#!/usr/bin/env python3
"""
Flask app for On the Clock - landing page and OAuth dashboard.
"""
import os
import secrets
import json
import psycopg2
import psycopg2.pool
from psycopg2.extras import RealDictCursor
from contextlib import contextmanager
import logging
import traceback
import threading
import asyncio
import concurrent.futures
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode
import requests
from flask import Flask, render_template, redirect, request, session, jsonify, url_for, make_response
from werkzeug.middleware.proxy_fix import ProxyFix
import stripe
from stripe import SignatureVerificationError

app = Flask(__name__)

# Import helper functions from bot.py for Stripe webhook handling
from bot import (
    check_bot_access,
    set_bot_access,
    set_retention_tier,
    purge_timeclock_data_only,
    create_secure_checkout_session,
    notify_server_owner_bot_access,
    get_active_employees_with_stats,
    create_adjustment_request,
    get_pending_adjustments,
    approve_adjustment,
    deny_adjustment,
    db as bot_db,
    bot
)

# Import and run database migrations on startup
from migrations import run_migrations

# Start Discord bot in background daemon thread
def start_discord_bot():
    """Start the Discord bot in a background daemon thread."""
    try:
        import asyncio
        from bot import run_bot_with_api
        app.logger.info("≡ƒñû Starting Discord bot in background thread...")
        asyncio.run(run_bot_with_api())
    except Exception as e:
        app.logger.error(f"Γ¥î Error starting Discord bot: {e}")
        import traceback
        traceback.print_exc()

# Start bot thread when running under Gunicorn (only in first worker)
if __name__ != '__main__':
    import os
    worker_id = os.environ.get('GUNICORN_WORKER_ID', '1')
    # Only start bot in first worker to avoid multiple instances
    if worker_id == '1' or 'GUNICORN_WORKER_ID' not in os.environ:
        # Run database migrations before starting bot
        run_migrations()
        
        bot_thread = threading.Thread(target=start_discord_bot, daemon=True)
        bot_thread.start()
        app.logger.info("Γ£à Discord bot thread started in worker")

# Configure logging to work with Gunicorn
if __name__ != '__main__':
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)
else:
    logging.basicConfig(level=logging.DEBUG)

# Custom Jinja2 filter for Discord permission checking
@app.template_filter('has_permission')
def has_permission(permissions, permission_flag):
    """Check if a permission integer has a specific flag using bitwise AND"""
    try:
        return int(permissions) & permission_flag != 0
    except (ValueError, TypeError):
        return False
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Fix for Replit reverse proxy - ensures correct scheme/host detection and client IP
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1, x_for=1)

# Database Configuration - PostgreSQL (shared with bot.py)
DATABASE_URL = os.getenv("DATABASE_URL")

# PostgreSQL connection pool for Flask app
app_db_pool = None

# Discord OAuth2 Configuration
DISCORD_CLIENT_ID = os.environ.get('DISCORD_CLIENT_ID')
DISCORD_CLIENT_SECRET = os.environ.get('DISCORD_CLIENT_SECRET')
DISCORD_API_BASE = 'https://discord.com/api/v10'
DISCORD_OAUTH_SCOPES = 'identify guilds'

# Stripe Configuration
STRIPE_SECRET_KEY = os.environ.get('STRIPE_SECRET_KEY')
STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET')
STRIPE_PRICE_IDS = {
    'bot_access': os.environ.get('STRIPE_PRICE_BOT_ACCESS'),
    'retention_7day': os.environ.get('STRIPE_PRICE_RETENTION_7DAY'),
    'retention_30day': os.environ.get('STRIPE_PRICE_RETENTION_30DAY')
}

# Initialize Stripe
if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

def get_redirect_uri():
    """Get redirect URI dynamically based on current request or environment"""
    # Use environment variable if set, otherwise compute from current request
    env_uri = os.environ.get('DISCORD_REDIRECT_URI')
    if env_uri:
        return env_uri
    # Fallback: compute from current request (forces HTTPS for production)
    return url_for('auth_callback', _external=True, _scheme='https')

# Database connection
def init_app_db_pool():
    """Initialize PostgreSQL connection pool for Flask app"""
    global app_db_pool
    if not DATABASE_URL:
        raise ValueError("DATABASE_URL environment variable is not set")
    app_db_pool = psycopg2.pool.ThreadedConnectionPool(
        minconn=1,
        maxconn=10,
        dsn=DATABASE_URL
    )
    app.logger.info("Γ£à PostgreSQL connection pool initialized for Flask")

class FlaskConnectionWrapper:
    """Wrapper to make psycopg2 connection behave like sqlite3 connection with Row factory"""
    def __init__(self, conn):
        self._conn = conn
        self._cursor = None
    
    def execute(self, query, params=None):
        """Execute a query and return a cursor (mimics sqlite3 behavior)"""
        # Use RealDictCursor for dict-like row access (like RealDictCursor)
        self._cursor = self._conn.cursor(cursor_factory=RealDictCursor)
        if params:
            self._cursor.execute(query, params)
        else:
            self._cursor.execute(query)
        return self._cursor
    
    def executemany(self, query, params_list):
        """Execute a query with multiple parameter sets"""
        self._cursor = self._conn.cursor(cursor_factory=RealDictCursor)
        self._cursor.executemany(query, params_list)
        return self._cursor
    
    def cursor(self):
        """Get a new cursor with dict-like rows"""
        return self._conn.cursor(cursor_factory=RealDictCursor)
    
    def commit(self):
        """Commit the transaction"""
        self._conn.commit()
    
    def rollback(self):
        """Rollback the transaction"""
        self._conn.rollback()

@contextmanager
def get_db():
    """Context manager for PostgreSQL database connections (Flask app)"""
    if app_db_pool is None:
        init_app_db_pool()
    
    conn = None
    max_retries = 2
    for attempt in range(max_retries):
        try:
            conn = app_db_pool.getconn()
            
            # Validate connection is alive by executing a simple query
            # This catches stale/closed SSL connections before they cause errors
            test_cursor = conn.cursor()
            test_cursor.execute("SELECT 1")
            test_cursor.close()
            
            # Connection is good, proceed
            break
        except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
            # Connection is stale/dead, close it and get a new one
            if conn:
                try:
                    conn.close()
                except:
                    pass
                app_db_pool.putconn(conn, close=True)  # Mark as bad
            
            if attempt < max_retries - 1:
                # Try again with a fresh connection
                continue
            else:
                # Last attempt failed, re-raise
                raise
    
    wrapper = FlaskConnectionWrapper(conn)
    try:
        yield wrapper
        # Auto-commit on successful exit
        conn.commit()
    except Exception as e:
        # Auto-rollback on exception
        conn.rollback()
        raise
    finally:
        # Always return connection to pool
        app_db_pool.putconn(conn)

def init_dashboard_tables():
    """Initialize database tables for OAuth and user sessions"""
    with get_db() as conn:
        # OAuth states table for CSRF protection
        conn.execute("""
            CREATE TABLE IF NOT EXISTS oauth_states (
                state TEXT PRIMARY KEY,
                expires_at TEXT NOT NULL
            )
        """)
        
        # User sessions table for logged-in users
        conn.execute("""
            CREATE TABLE IF NOT EXISTS user_sessions (
                session_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                username TEXT NOT NULL,
                discriminator TEXT,
                avatar TEXT,
                access_token TEXT NOT NULL,
                refresh_token TEXT,
                guilds_data TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (NOW()),
                expires_at TEXT NOT NULL,
                ip_address TEXT NOT NULL DEFAULT 'unknown'
            )
        """)
        
        # Migration: Add refresh_token column if it doesn't exist
        try:
            conn.execute("ALTER TABLE user_sessions ADD COLUMN refresh_token TEXT")
        except psycopg2.OperationalError:
            pass
        
        # Migration: Add created_at column if it doesn't exist
        try:
            conn.execute("ALTER TABLE user_sessions ADD COLUMN created_at TEXT NOT NULL DEFAULT (NOW())")
        except psycopg2.OperationalError:
            pass
        
        # Migration: Add ip_address column if it doesn't exist
        try:
            conn.execute("ALTER TABLE user_sessions ADD COLUMN ip_address TEXT NOT NULL DEFAULT 'unknown'")
        except psycopg2.OperationalError:
            pass
        
        # Clean up expired sessions and states
        conn.execute("DELETE FROM oauth_states WHERE expires_at < %s", 
                    (datetime.now(timezone.utc).isoformat(),))
        conn.execute("DELETE FROM user_sessions WHERE expires_at < %s", 
                    (datetime.now(timezone.utc).isoformat(),))

# Initialize tables when module is imported (for Gunicorn)
try:
    init_dashboard_tables()
except Exception as e:
    # Fallback to print if logger not available during import
    print(f"ΓÜá∩╕Å Dashboard initialization warning: {e}")

# OAuth Helper Functions
def create_oauth_state():
    """Generate and store OAuth state for CSRF protection"""
    state = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
    
    with get_db() as conn:
        conn.execute(
            "INSERT INTO oauth_states (state, expires_at) VALUES (%s, %s)",
            (state, expires_at.isoformat())
        )
    return state

def verify_oauth_state(state):
    """Verify OAuth state and delete it"""
    with get_db() as conn:
        cursor = conn.execute(
            "SELECT state FROM oauth_states WHERE state = %s AND expires_at > %s",
            (state, datetime.now(timezone.utc).isoformat())
        )
        result = cursor.fetchone()
        
        if result:
            conn.execute("DELETE FROM oauth_states WHERE state = %s", (state,))
            return True
    return False

def exchange_code_for_token(code, redirect_uri):
    """Exchange authorization code for access token"""
    data = {
        'client_id': DISCORD_CLIENT_ID,
        'client_secret': DISCORD_CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirect_uri
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    
    response = requests.post(f'{DISCORD_API_BASE}/oauth2/token', data=data, headers=headers)
    response.raise_for_status()
    return response.json()

def get_user_info(access_token):
    """Get Discord user information"""
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get(f'{DISCORD_API_BASE}/users/@me', headers=headers)
    response.raise_for_status()
    return response.json()

def get_user_guilds(access_token):
    """Get user's Discord guilds"""
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get(f'{DISCORD_API_BASE}/users/@me/guilds', headers=headers)
    response.raise_for_status()
    return response.json()

def create_user_session(user_data, access_token, refresh_token, guilds_data):
    """Create user session in database"""
    session_id = secrets.token_urlsafe(32)
    created_at = datetime.now(timezone.utc)
    expires_at = created_at + timedelta(hours=24)
    # Get real client IP from proxy headers (falls back to remote_addr)
    ip_address = request.access_route[0] if request.access_route else (request.remote_addr or 'unknown')
    
    with get_db() as conn:
        conn.execute("""
            INSERT INTO user_sessions 
            (session_id, user_id, username, discriminator, avatar, access_token, refresh_token, guilds_data, created_at, expires_at, ip_address)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            session_id,
            user_data['id'],
            user_data['username'],
            user_data.get('discriminator', '0'),
            user_data.get('avatar'),
            access_token,
            refresh_token,
            json.dumps(guilds_data),
            created_at.isoformat(),
            expires_at.isoformat(),
            ip_address
        ))
    return session_id

def get_user_session(session_id):
    """Get user session from database"""
    with get_db() as conn:
        cursor = conn.execute("""
            SELECT session_id, user_id, username, discriminator, avatar, access_token, guilds_data, expires_at
            FROM user_sessions 
            WHERE session_id = %s AND expires_at > %s
        """, (session_id, datetime.now(timezone.utc).isoformat()))
        row = cursor.fetchone()
        
        if row:
            return {
                'session_id': row['session_id'],
                'user_id': row['user_id'],
                'username': row['username'],
                'discriminator': row['discriminator'] or '0',
                'avatar': row['avatar'],
                'access_token': row['access_token'],
                'guilds': json.loads(row['guilds_data']) if row['guilds_data'] else [],
                'expires_at': row['expires_at']
            }
    return None

def delete_user_session(session_id):
    """Delete user session from database"""
    with get_db() as conn:
        conn.execute("DELETE FROM user_sessions WHERE session_id = %s", (session_id,))

def require_auth(f):
    """Decorator to require authentication"""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            session_id = session.get('session_id')
            if not session_id:
                app.logger.info("No session_id found, redirecting to login")
                return redirect('/auth/login')
            
            user_session = get_user_session(session_id)
            if not user_session:
                app.logger.warning(f"Invalid or expired session: {session_id[:8]}...")
                session.clear()
                return redirect('/auth/login')
            
            return f(user_session, *args, **kwargs)
        except Exception as e:
            app.logger.error(f"Authentication error: {str(e)}")
            app.logger.error(traceback.format_exc())
            session.clear()
            return redirect('/auth/login')
    return decorated_function

def require_api_auth(f):
    """Decorator to require authentication for API routes (returns JSON instead of redirect)"""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            session_id = session.get('session_id')
            if not session_id:
                return jsonify({'success': False, 'error': 'Unauthorized'}), 401
            
            user_session = get_user_session(session_id)
            if not user_session:
                session.clear()
                return jsonify({'success': False, 'error': 'Session expired'}), 401
            
            return f(user_session, *args, **kwargs)
        except Exception as e:
            app.logger.error(f"API authentication error: {str(e)}")
            app.logger.error(traceback.format_exc())
            return jsonify({'success': False, 'error': 'Authentication error'}), 500
    return decorated_function

def check_guild_paid_access(guild_id):
    """
    Check if a guild has paid bot access.
    Returns dict with: {'bot_invited': bool, 'bot_access_paid': bool}
    Performs fresh database lookup on every call (no caching).
    """
    try:
        with get_db() as conn:
            # Check if bot is in the guild (bot_guilds table)
            cursor = conn.execute("SELECT guild_id FROM bot_guilds WHERE guild_id = %s", (str(guild_id),))
            bot_invited = cursor.fetchone() is not None
            
            # Check if guild has paid bot access (server_subscriptions table)
            cursor = conn.execute(
                "SELECT bot_access_paid FROM server_subscriptions WHERE guild_id = %s",
                (int(guild_id),)
            )
            result = cursor.fetchone()
            bot_access_paid = bool(result['bot_access_paid']) if result else False
            
            return {
                'bot_invited': bot_invited,
                'bot_access_paid': bot_access_paid
            }
    except Exception as e:
        app.logger.error(f"Error checking guild {guild_id} paid access: {e}")
        # Fail closed - deny access on error
        return {
            'bot_invited': False,
            'bot_access_paid': False
        }

def check_user_admin_realtime(user_id, guild_id):
    """
    Check if user has admin permissions in guild via bot API (real-time check).
    This replaces cached OAuth session data with live guild membership/permissions.
    Returns dict with: {'is_member': bool, 'is_admin': bool, 'reason': str}
    Performs fresh lookup via bot's Discord cache on every call (no caching).
    """
    try:
        import requests
        
        bot_api_secret = os.getenv('BOT_API_SECRET')
        if not bot_api_secret:
            app.logger.error("BOT_API_SECRET not set - cannot verify admin status")
            # Fail closed - deny access if we can't verify
            return {'is_member': False, 'is_admin': False, 'reason': 'api_secret_missing'}
        
        # Call bot API to check admin status
        url = f'http://localhost:8081/api/guild/{guild_id}/user/{user_id}/check-admin'
        headers = {'Authorization': f'Bearer {bot_api_secret}'}
        
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                return {
                    'is_member': data.get('is_member', False),
                    'is_admin': data.get('is_admin', False),
                    'reason': data.get('reason', 'unknown')
                }
        
        app.logger.error(f"Bot API check failed for user {user_id} in guild {guild_id}: {response.status_code}")
        # Fail closed - deny access if bot API fails
        return {'is_member': False, 'is_admin': False, 'reason': 'bot_api_error'}
        
    except Exception as e:
        app.logger.error(f"Error checking user admin status (user {user_id}, guild {guild_id}): {e}")
        app.logger.error(traceback.format_exc())
        # Fail closed - deny access on error
        return {'is_member': False, 'is_admin': False, 'reason': 'check_error'}

def require_paid_access(f):
    """
    Decorator to require both authentication AND paid bot access for dashboard routes.
    Checks on every request (no caching) for real-time access control.
    
    Extracts guild_id from route parameters and validates:
    1. User is authenticated
    2. Bot is invited to the guild
    3. Guild has paid bot access
    4. User is admin in the guild
    
    Redirects to appropriate pages based on access state:
    - Not invited: /dashboard/invite
    - Invited but not paid: /dashboard/purchase
    - Paid but not admin: /dashboard/no-access
    """
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            # First check authentication
            session_id = session.get('session_id')
            if not session_id:
                app.logger.info("No session_id found, redirecting to login")
                return redirect('/auth/login')
            
            user_session = get_user_session(session_id)
            if not user_session:
                app.logger.warning(f"Invalid or expired session: {session_id[:8]}...")
                session.clear()
                return redirect('/auth/login')
            
            # Extract guild_id from route parameters
            guild_id = kwargs.get('guild_id')
            if not guild_id:
                # For routes without guild_id (like /dashboard), just require auth
                return f(user_session, *args, **kwargs)
            
            # Check bot access status (fresh DB lookup every time)
            access_status = check_guild_paid_access(guild_id)
            
            # Check if user is admin in this guild (real-time via bot API - ONLY source of truth)
            admin_status = check_user_admin_realtime(user_session['user_id'], guild_id)
            is_admin = admin_status.get('is_admin', False)
            is_member = admin_status.get('is_member', False)
            reason = admin_status.get('reason', 'unknown')
            
            # Log the check for debugging
            app.logger.info(f"Real-time admin check for user {user_session.get('username')} in guild {guild_id}: is_member={is_member}, is_admin={is_admin}, reason={reason}")
            
            # Fail closed on bot API errors
            if reason in ['api_secret_missing', 'bot_api_error', 'check_error']:
                app.logger.error(f"Bot API check failed for user {user_session.get('username')} in guild {guild_id}, denying access (fail closed)")
                session.clear()
                return redirect('/auth/login?error=api_check_failed')
            
            # Validate access requirements
            if not access_status['bot_invited']:
                app.logger.info(f"Bot not invited to guild {guild_id}, redirecting to invite page")
                return redirect(f'/dashboard/invite?guild_id={guild_id}')
            
            if not access_status['bot_access_paid']:
                app.logger.info(f"Guild {guild_id} does not have paid access, redirecting to purchase page")
                return redirect(f'/dashboard/purchase?guild_id={guild_id}')
            
            # Check guild membership (real-time from bot)
            if not is_member:
                app.logger.warning(f"User {user_session.get('username')} not member of guild {guild_id} (reason: {reason})")
                return redirect(f'/dashboard/no-access?guild_id={guild_id}')
            
            # Check admin permissions (real-time from bot)
            if not is_admin:
                app.logger.warning(f"User {user_session.get('username')} not admin in guild {guild_id} (reason: {reason})")
                return redirect(f'/dashboard/no-access?guild_id={guild_id}')
            
            # All checks passed - allow access
            return f(user_session, *args, **kwargs)
            
        except Exception as e:
            app.logger.error(f"Paid access check error: {str(e)}")
            app.logger.error(traceback.format_exc())
            session.clear()
            return redirect('/auth/login')
    return decorated_function

def require_paid_api_access(f):
    """
    API version of require_paid_access - returns JSON errors instead of redirects.
    """
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            # First check authentication
            session_id = session.get('session_id')
            if not session_id:
                return jsonify({'success': False, 'error': 'Unauthorized', 'code': 'NO_SESSION'}), 401
            
            user_session = get_user_session(session_id)
            if not user_session:
                session.clear()
                return jsonify({'success': False, 'error': 'Session expired', 'code': 'EXPIRED_SESSION'}), 401
            
            # Extract guild_id from route parameters
            guild_id = kwargs.get('guild_id')
            if not guild_id:
                return jsonify({'success': False, 'error': 'Missing guild_id', 'code': 'MISSING_GUILD'}), 400
            
            # Check bot access status (fresh DB lookup every time)
            access_status = check_guild_paid_access(guild_id)
            
            # Check if user is admin in this guild (real-time via bot API - ONLY source of truth)
            admin_status = check_user_admin_realtime(user_session['user_id'], guild_id)
            is_admin = admin_status.get('is_admin', False)
            is_member = admin_status.get('is_member', False)
            reason = admin_status.get('reason', 'unknown')
            
            # Log the check for debugging
            app.logger.info(f"Real-time admin check (API) for user {user_session.get('username')} in guild {guild_id}: is_member={is_member}, is_admin={is_admin}, reason={reason}")
            
            # Fail closed on bot API errors
            if reason in ['api_secret_missing', 'bot_api_error', 'check_error']:
                app.logger.error(f"Bot API check failed for user {user_session.get('username')} in guild {guild_id}, denying access (fail closed)")
                return jsonify({
                    'success': False,
                    'error': 'Access check failed',
                    'code': 'API_CHECK_FAILED'
                }), 500
            
            # Validate access requirements
            if not access_status['bot_invited']:
                return jsonify({
                    'success': False,
                    'error': 'Bot not invited to server',
                    'code': 'BOT_NOT_INVITED',
                    'redirect': f'/dashboard/invite?guild_id={guild_id}'
                }), 403
            
            if not access_status['bot_access_paid']:
                return jsonify({
                    'success': False,
                    'error': 'Server does not have paid bot access',
                    'code': 'NO_PAID_ACCESS',
                    'redirect': f'/dashboard/purchase?guild_id={guild_id}'
                }), 403
            
            # Check guild membership (real-time from bot)
            if not is_member:
                return jsonify({
                    'success': False,
                    'error': 'Not a member of this server',
                    'code': 'NOT_MEMBER',
                    'redirect': f'/dashboard/no-access?guild_id={guild_id}'
                }), 403
            
            # Check admin permissions (real-time from bot)
            if not is_admin:
                return jsonify({
                    'success': False,
                    'error': 'Admin access required',
                    'code': 'NOT_ADMIN',
                    'redirect': f'/dashboard/no-access?guild_id={guild_id}'
                }), 403
            
            # All checks passed - allow access
            return f(user_session, *args, **kwargs)
            
        except Exception as e:
            app.logger.error(f"API paid access check error: {str(e)}")
            app.logger.error(traceback.format_exc())
            return jsonify({'success': False, 'error': 'Access check error', 'code': 'CHECK_ERROR'}), 500
    return decorated_function

def get_bot_guild_ids():
    """Get list of guild IDs where the bot is present (as strings for OAuth comparison)"""
    try:
        with get_db() as conn:
            cursor = conn.execute("SELECT guild_id FROM bot_guilds")
            # Cast to string to match Discord OAuth guild IDs (which are strings)
            return set(str(row['guild_id']) for row in cursor.fetchall())
    except Exception as e:
        app.logger.error(f"Error fetching bot guild IDs: {e}")
        # Return empty set to avoid 500 errors if table missing or locked
        return set()

def user_has_admin_access(user_id, guild_id, user_guild):
    """
    Check if user has admin access to a guild.
    Returns True if user has:
    - Discord Owner permissions, OR
    - Discord Administrator permissions, OR
    - A custom admin role configured via bot slash commands, OR
    - The main admin role configured for the guild
    """
    # Check Discord owner permission
    if user_guild.get('owner', False):
        return True
    
    # Check Discord administrator permission (0x8 = ADMINISTRATOR)
    permissions = int(user_guild.get('permissions', '0'))
    if permissions & 0x8:  # Administrator permission
        return True
    
    # Check custom admin roles and main admin role from database
    # Note: We can't easily get user's role IDs from OAuth guilds endpoint
    # The guilds endpoint only gives us basic guild info and permissions
    # For now, we'll trust Discord permissions (owner/administrator)
    # Custom admin roles would require additional Discord API calls per guild
    
    # TODO: If needed, implement Discord API call to get member roles:
    # GET /guilds/{guild_id}/members/{user_id} with bot token
    # Then check against admin_roles and guild_settings.main_admin_role_id
    
    return False

def filter_user_guilds(user_session):
    """
    Filter user's guilds to show only those where:
    1. The user has admin access (owner, administrator, or custom admin role), AND
    2. EITHER the bot is present OR the server has paid/granted access
    
    This allows admins to see servers where access was manually granted even if bot hasn't joined yet.
    Also adds subscription information and bot presence flag to each guild.
    """
    all_guilds = user_session.get('guilds', [])
    bot_guild_ids = get_bot_guild_ids()
    filtered_guilds = []
    
    # Fetch all subscription data in one query for efficiency
    subscription_data = {}
    with get_db() as conn:
        cursor = conn.execute(
            "SELECT guild_id, bot_access_paid, retention_tier FROM server_subscriptions"
        )
        for row in cursor.fetchall():
            subscription_data[str(row['guild_id'])] = {
                'bot_access_paid': bool(row['bot_access_paid']),
                'retention_tier': row['retention_tier']
            }
    
    for guild in all_guilds:
        guild_id = guild.get('id')
        
        # Check if user has admin access first
        if not user_has_admin_access(user_session['user_id'], guild_id, guild):
            continue
        
        # Check bot presence and payment status
        bot_is_present = guild_id in bot_guild_ids
        sub_info = subscription_data.get(guild_id, {'bot_access_paid': False, 'retention_tier': 'none'})
        has_paid_access = sub_info['bot_access_paid']
        
        # Show guild if EITHER bot is present OR they have paid access
        # This allows admins to see their dashboard even if bot hasn't joined yet after manual grant
        if not bot_is_present and not has_paid_access:
            continue
        
        # Add subscription info and bot presence to guild
        guild['bot_access_paid'] = has_paid_access
        guild['retention_tier'] = sub_info['retention_tier']
        guild['bot_is_present'] = bot_is_present
        
        # Guild passes filters
        filtered_guilds.append(guild)
    
    return filtered_guilds

# Routes

@app.route("/webhook", methods=["POST"])
def stripe_webhook():
    """Handle Stripe webhook events"""
    payload = request.data
    sig_header = request.headers.get('stripe-signature')
    
    if not STRIPE_WEBHOOK_SECRET:
        app.logger.error("Γ¥î STRIPE_WEBHOOK_SECRET not configured")
        return jsonify({'error': 'Webhook secret not configured'}), 400
    
    if not sig_header:
        app.logger.error("Γ¥î Missing Stripe signature header")
        return jsonify({'error': 'Missing signature'}), 400
    
    try:
        # Verify webhook signature
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
        
        event_type = event.get('type')
        app.logger.info(f"≡ƒöö Processing Stripe webhook: {event_type}")
        
        # Handle different event types
        if event_type == 'checkout.session.completed':
            handle_checkout_completed(event['data']['object'])
        elif event_type == 'customer.subscription.updated':
            handle_subscription_change(event['data']['object'])
        elif event_type == 'customer.subscription.deleted':
            handle_subscription_cancellation(event['data']['object'])
        elif event_type == 'invoice.payment_failed':
            handle_payment_failure(event['data']['object'])
        else:
            app.logger.info(f"Γä╣∩╕Å Unhandled Stripe event type: {event_type}")
        
        return jsonify({'received': True}), 200
        
    except SignatureVerificationError as e:
        app.logger.error(f"Γ¥î Invalid webhook signature: {e}")
        return jsonify({'error': 'Invalid signature'}), 400
    except ValueError as e:
        app.logger.error(f"Γ¥î Invalid webhook payload: {e}")
        return jsonify({'error': 'Invalid payload'}), 400
    except Exception as e:
        app.logger.error(f"Γ¥î Error processing webhook: {e}")
        app.logger.error(traceback.format_exc())
        return jsonify({'error': 'Internal error'}), 500

def handle_checkout_completed(session):
    """Process a completed checkout session"""
    try:
        # Retrieve full session with line items to verify pricing
        full_session = stripe.checkout.Session.retrieve(
            session['id'],
            expand=['line_items']
        )
        
        # Extract price_id from session
        price_id = None
        if full_session.line_items and full_session.line_items.data:
            line_item = full_session.line_items.data[0]
            if line_item.price:
                price_id = line_item.price.id
        
        if not price_id:
            app.logger.error("Γ¥î No price ID found in checkout session")
            return
        
        # Match price_id against STRIPE_PRICE_IDS to determine product_type
        product_type = None
        for ptype, pid in STRIPE_PRICE_IDS.items():
            if pid == price_id:
                product_type = ptype
                break
        
        if not product_type:
            app.logger.error(f"Γ¥î Unknown price ID in checkout: {price_id}")
            return
        
        guild_id = session.get('metadata', {}).get('guild_id')
        
        if not guild_id:
            app.logger.error("Γ¥î No guild_id found in session metadata")
            return
        
        guild_id = int(guild_id)
        
        # Process based on product type
        if product_type == 'bot_access':
            # One-time bot access payment
            set_bot_access(guild_id, True)
            app.logger.info(f"Γ£à Bot access granted for server {guild_id}")
            
        elif product_type == 'retention_7day':
            # 7-day retention subscription
            if not check_bot_access(guild_id):
                app.logger.error(f"Γ¥î SECURITY: Retention purchase blocked - bot access not paid for server {guild_id}")
                return
            
            subscription_id = session.get('subscription')
            customer_id = session.get('customer')
            set_retention_tier(guild_id, '7day')
            
            # Store subscription_id and customer_id in database
            with bot_db() as conn:
                conn.execute("""
                    INSERT INTO server_subscriptions (guild_id, subscription_id, customer_id, status)
                    VALUES (%s, %s, %s, 'active')
                    ON CONFLICT(guild_id) DO UPDATE SET 
                        subscription_id = %s,
                        customer_id = %s,
                        status = 'active'
                """, (guild_id, subscription_id, customer_id, subscription_id, customer_id))
            
            app.logger.info(f"Γ£à 7-day retention granted for server {guild_id}")
            
        elif product_type == 'retention_30day':
            # 30-day retention subscription
            if not check_bot_access(guild_id):
                app.logger.error(f"Γ¥î SECURITY: Retention purchase blocked - bot access not paid for server {guild_id}")
                return
            
            subscription_id = session.get('subscription')
            customer_id = session.get('customer')
            set_retention_tier(guild_id, '30day')
            
            # Store subscription_id and customer_id in database
            with bot_db() as conn:
                conn.execute("""
                    INSERT INTO server_subscriptions (guild_id, subscription_id, customer_id, status)
                    VALUES (%s, %s, %s, 'active')
                    ON CONFLICT(guild_id) DO UPDATE SET 
                        subscription_id = %s,
                        customer_id = %s,
                        status = 'active'
                """, (guild_id, subscription_id, customer_id, subscription_id, customer_id))
            
            app.logger.info(f"Γ£à 30-day retention granted for server {guild_id}")
            
    except Exception as e:
        app.logger.error(f"Γ¥î Error processing checkout session: {e}")
        app.logger.error(traceback.format_exc())

def handle_subscription_change(subscription):
    """Handle subscription change events"""
    try:
        subscription_id = subscription.get('id')
        status = subscription.get('status')
        
        if not subscription_id:
            app.logger.error("Γ¥î No subscription ID in subscription change event")
            return
        
        with bot_db() as conn:
            conn.execute("""
                UPDATE server_subscriptions 
                SET status = %s
                WHERE subscription_id = %s
            """, (status, subscription_id))
        
        app.logger.info(f"Γ£à Subscription {subscription_id} status updated to {status}")
        
    except Exception as e:
        app.logger.error(f"Γ¥î Error processing subscription change: {e}")
        app.logger.error(traceback.format_exc())

def handle_subscription_cancellation(subscription):
    """Handle subscription cancellation events"""
    try:
        subscription_id = subscription.get('id')
        customer_id = subscription.get('customer')
        
        if not subscription_id:
            app.logger.error("Γ¥î No subscription ID in cancellation event")
            return
        
        with bot_db() as conn:
            cursor = conn.execute("""
                SELECT guild_id FROM server_subscriptions 
                WHERE subscription_id = %s OR customer_id = %s
            """, (subscription_id, customer_id))
            result = cursor.fetchone()
            
            if result:
                guild_id = result['guild_id']
                
                # Set retention tier to 'none'
                set_retention_tier(guild_id, 'none')
                
                # Update subscription status to canceled
                conn.execute("""
                    UPDATE server_subscriptions 
                    SET status = 'canceled', subscription_id = NULL
                    WHERE guild_id = %s
                """, (guild_id,))
                
                # Trigger immediate data deletion
                purge_timeclock_data_only(guild_id)
                
                app.logger.info(f"Γ£à Retention subscription canceled for server {guild_id}")
            else:
                app.logger.error(f"Γ¥î No guild found for subscription {subscription_id}")
                
    except Exception as e:
        app.logger.error(f"Γ¥î Error processing subscription cancellation: {e}")
        app.logger.error(traceback.format_exc())

def handle_payment_failure(invoice):
    """Handle payment failure events"""
    try:
        customer_id = invoice.get('customer')
        subscription_id = invoice.get('subscription')
        
        if not customer_id and not subscription_id:
            app.logger.error("Γ¥î No customer or subscription ID in payment failure event")
            return
        
        with bot_db() as conn:
            cursor = conn.execute("""
                SELECT guild_id FROM server_subscriptions 
                WHERE subscription_id = %s OR customer_id = %s
            """, (subscription_id, customer_id))
            result = cursor.fetchone()
            
            if result:
                guild_id = result['guild_id']
                
                # Update subscription status to past_due
                conn.execute("""
                    UPDATE server_subscriptions 
                    SET status = 'past_due'
                    WHERE guild_id = %s
                """, (guild_id,))
                
                app.logger.info(f"ΓÜá∩╕Å Payment failed: Guild {guild_id} marked as past_due")
            else:
                app.logger.error(f"Γ¥î No guild found for customer {customer_id}")
                
    except Exception as e:
        app.logger.error(f"Γ¥î Error processing payment failure: {e}")
        app.logger.error(traceback.format_exc())

@app.route("/")
def index():
    """Landing page with bot info, features, and upgrade links."""
    return render_template('landing.html')

@app.route("/dashboard/invite")
def dashboard_invite():
    """Page shown when user tries to access dashboard but bot is not invited to their server."""
    return render_template('dashboard_invite.html')

@app.route("/dashboard/purchase")
def dashboard_purchase():
    """Page shown when user tries to access dashboard but server doesn't have paid bot access."""
    return render_template('dashboard_purchase.html')

@app.route("/dashboard/no-access")
def dashboard_no_access():
    """Page shown when user tries to access dashboard but doesn't have admin permissions."""
    return render_template('dashboard_no_access.html')

@app.route("/auth/login")
def auth_login():
    """Redirect user to Discord OAuth"""
    state = create_oauth_state()
    redirect_uri = get_redirect_uri()
    
    params = {
        'client_id': DISCORD_CLIENT_ID,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': DISCORD_OAUTH_SCOPES,
        'state': state
    }
    
    auth_url = f'https://discord.com/oauth2/authorize?{urlencode(params)}'
    app.logger.info(f"OAuth login initiated - Redirect URI: {redirect_uri}")
    return redirect(auth_url)

@app.route("/auth/callback")
def auth_callback():
    """Handle Discord OAuth callback"""
    try:
        code = request.args.get('code')
        state = request.args.get('state')
        error = request.args.get('error')
        
        app.logger.info(f"OAuth callback received - code: {'present' if code else 'missing'}, state: {'present' if state else 'missing'}, error: {error}")
        
        if error:
            app.logger.error(f"OAuth error from Discord: {error}")
            return "<h1>Authentication Error</h1><p>Unable to authenticate with Discord. Please try again.</p><a href='/'>Return Home</a>", 400
        
        if not code or not state:
            app.logger.error("Missing code or state in OAuth callback")
            return "<h1>Authentication Error</h1><p>Invalid authentication request. Please try again.</p><a href='/'>Return Home</a>", 400
        
        if not verify_oauth_state(state):
            app.logger.error(f"Invalid OAuth state: {state[:8]}... (CSRF check failed)")
            return "<h1>Authentication Error</h1><p>Security validation failed. Please try again.</p><a href='/'>Return Home</a>", 400
        
        # Exchange code for token (use same redirect_uri as in authorization)
        redirect_uri = get_redirect_uri()
        app.logger.info(f"Exchanging code for token with redirect_uri: {redirect_uri}")
        token_data = exchange_code_for_token(code, redirect_uri)
        access_token = token_data['access_token']
        refresh_token = token_data.get('refresh_token')
        
        # Get user info
        app.logger.info("Fetching user info from Discord")
        user_data = get_user_info(access_token)
        app.logger.info(f"User authenticated: {user_data.get('username')}")
        
        # Get user's guilds
        app.logger.info("Fetching user guilds")
        guilds_data = get_user_guilds(access_token)
        app.logger.info(f"Found {len(guilds_data)} guilds")
        
        # Create session
        session_id = create_user_session(user_data, access_token, refresh_token, guilds_data)
        session['session_id'] = session_id
        app.logger.info(f"Session created: {session_id[:8]}...")
        
        # Check if this is a purchase flow
        if session.get('purchase_intent'):
            app.logger.info("Redirecting to server selection for purchase")
            return redirect('/purchase/select_server')
        
        return redirect('/dashboard')
        
    except Exception as e:
        app.logger.error(f"OAuth callback error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return "<h1>Authentication Error</h1><p>An error occurred during authentication. Please try again later.</p><a href='/'>Return Home</a>", 500

@app.route("/auth/logout")
def auth_logout():
    """Logout user"""
    session_id = session.get('session_id')
    if session_id:
        delete_user_session(session_id)
        app.logger.info("User session cleared")
    session.clear()
    return redirect('/')

@app.route("/dashboard")
@require_auth
def dashboard(user_session):
    """Protected dashboard showing user info and guilds where bot is present and user has admin access"""
    try:
        app.logger.info(f"Dashboard accessed by user: {user_session.get('username')}")
        
        # Filter guilds to show only where bot is present AND user has admin access
        filtered_guilds = filter_user_guilds(user_session)
        
        # Create a modified user session with filtered guilds
        dashboard_data = {
            **user_session,
            'guilds': filtered_guilds,
            'total_guilds': len(user_session.get('guilds', [])),
            'filtered_count': len(filtered_guilds)
        }
        
        app.logger.info(f"Showing {len(filtered_guilds)} of {len(user_session.get('guilds', []))} guilds")
        return render_template('dashboard.html', user=dashboard_data)
    except Exception as e:
        app.logger.error(f"Dashboard rendering error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return "<h1>Error</h1><p>Unable to load dashboard. Please try again later.</p><a href='/auth/logout'>Logout</a>", 500

def fetch_guild_name_from_discord(guild_id, db_conn=None):
    """
    Fetch guild name from Discord API and cache it in bot_guilds table.
    Returns guild name or None if not found/accessible.
    """
    bot_token = os.environ.get('DISCORD_TOKEN')
    if not bot_token:
        app.logger.error("DISCORD_TOKEN not found in environment")
        return None
    
    headers = {'Authorization': f'Bot {bot_token}'}
    try:
        # Fetch guild info from Discord API
        response = requests.get(
            f'{DISCORD_API_BASE}/guilds/{guild_id}',
            headers=headers,
            timeout=5
        )
        response.raise_for_status()
        guild_data = response.json()
        guild_name = guild_data.get('name', 'Unknown Server')
        
        # Cache in bot_guilds table for future use
        if db_conn:
            try:
                db_conn.execute("""
                    INSERT INTO bot_guilds (guild_id, guild_name) 
                    VALUES (%s, %s)
                    ON CONFLICT(guild_id) DO UPDATE SET guild_name = %s
                """, (str(guild_id), guild_name, guild_name))
                app.logger.info(f"Cached guild name for {guild_id}: {guild_name}")
            except Exception as db_error:
                app.logger.error(f"Failed to cache guild name: {db_error}")
        
        return guild_name
        
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 403:
            app.logger.warning(f"Bot lacks access to guild {guild_id} (403 Forbidden - bot likely not in server)")
        elif e.response.status_code == 404:
            app.logger.warning(f"Guild {guild_id} not found (404 - may have been deleted)")
        else:
            app.logger.error(f"HTTP error fetching guild {guild_id}: {e}")
        return None
    except Exception as e:
        app.logger.error(f"Error fetching guild {guild_id} from Discord: {e}")
        return None

@app.route("/owner")
@require_auth
def owner_dashboard(user_session):
    """Owner-only dashboard showing all servers, subscriptions, webhook events, and active sessions"""
    try:
        BOT_OWNER_ID = '107103438139056128'
        
        # Security check: Only allow bot owner
        if user_session['user_id'] != BOT_OWNER_ID:
            app.logger.warning(f"Unauthorized owner dashboard access attempt by user {user_session['user_id']}")
            return "<h1>403 Forbidden</h1><p>You do not have permission to access this page.</p><a href='/dashboard'>Return to Dashboard</a>", 403
        
        app.logger.info(f"Owner dashboard accessed by {user_session.get('username')}")
        
        # Get all servers with bot access
        with get_db() as conn:
            # Database reconciliation: Ensure all bot guilds have rows (non-destructive)
            try:
                # Insert placeholder rows for new guilds where bot is present but no row exists
                # Use ON CONFLICT DO NOTHING for PostgreSQL (equivalent to INSERT OR IGNORE)
                cursor = conn.execute("""
                    INSERT INTO server_subscriptions (guild_id, tier, bot_access_paid, retention_tier, status)
                    SELECT CAST(guild_id AS BIGINT), 'free', FALSE, 'none', 'free'
                    FROM bot_guilds
                    WHERE CAST(guild_id AS BIGINT) NOT IN (SELECT guild_id FROM server_subscriptions)
                    ON CONFLICT (guild_id) DO NOTHING
                """)
                inserted_count = cursor.rowcount
                if inserted_count > 0:
                    app.logger.info(f"Added {inserted_count} placeholder server_subscriptions rows for new guilds")
                
            except Exception as reconcile_error:
                app.logger.error(f"Database reconciliation error: {reconcile_error}")
                # Continue anyway - reconciliation failure shouldn't block dashboard
            # Get servers where bot is currently present
            # Only show servers that are in bot_guilds table (bot is actually there)
            cursor = conn.execute("""
                SELECT 
                    CAST(bg.guild_id AS BIGINT) as guild_id,
                    bg.guild_name,
                    COALESCE(ss.bot_access_paid, FALSE) as bot_access_paid,
                    COALESCE(ss.retention_tier, 'none') as retention_tier,
                    COALESCE(ss.status, 'free') as status,
                    ss.subscription_id,
                    ss.customer_id,
                    COUNT(DISTINCT s.id) as active_sessions,
                    TRUE as bot_is_present
                FROM bot_guilds bg
                LEFT JOIN server_subscriptions ss ON ss.guild_id = CAST(bg.guild_id AS BIGINT)
                LEFT JOIN sessions s ON CAST(bg.guild_id AS BIGINT) = s.guild_id AND s.clock_out IS NULL
                GROUP BY bg.guild_id, bg.guild_name, ss.bot_access_paid, ss.retention_tier, ss.status, ss.subscription_id, ss.customer_id
                ORDER BY guild_name
            """)
            servers = []
            for row in cursor.fetchall():
                guild_id = row['guild_id']
                guild_name = row['guild_name']
                bot_is_present = bool(row['bot_is_present'])
                
                servers.append({
                    'guild_id': guild_id,
                    'guild_name': guild_name or f'Unknown Server (ID: {guild_id})',
                    'bot_access': bool(row['bot_access_paid']),
                    'retention_tier': row['retention_tier'] if row['retention_tier'] != 'none' else None,
                    'status': row['status'],
                    'subscription_id': row['subscription_id'],
                    'customer_id': row['customer_id'],
                    'active_sessions': row['active_sessions'],
                    'bot_is_present': bot_is_present
                })
            
            # Get recent webhook events (last 100) - only for servers where bot is present
            cursor = conn.execute("""
                SELECT 
                    we.event_id,
                    we.event_type,
                    we.guild_id,
                    we.status,
                    we.timestamp,
                    we.details,
                    bg.guild_name
                FROM webhook_events we
                INNER JOIN bot_guilds bg ON bg.guild_id = CAST(we.guild_id AS TEXT)
                ORDER BY we.timestamp DESC
                LIMIT 100
            """)
            webhook_events = []
            for row in cursor.fetchall():
                # Safely parse JSON details with error handling
                details = {}
                if row['details']:
                    try:
                        details = json.loads(row['details'])
                    except (json.JSONDecodeError, TypeError) as e:
                        app.logger.warning(f"Failed to parse webhook event details: {e}")
                        details = {'error': 'Failed to parse details'}
                
                webhook_events.append({
                    'event_id': row['event_id'],
                    'event_type': row['event_type'],
                    'guild_id': row['guild_id'],
                    'status': row['status'],
                    'timestamp': row['timestamp'],
                    'details': details,
                    'guild_name': row['guild_name'] or 'Unknown'
                })
            
            # Get summary stats (counting from bot_guilds - source of truth)
            cursor = conn.execute("""
                SELECT 
                    COUNT(*) as total_servers,
                    SUM(CASE WHEN COALESCE(ss.bot_access_paid, FALSE) = TRUE THEN 1 ELSE 0 END) as paid_servers,
                    SUM(CASE WHEN ss.retention_tier = '7day' THEN 1 ELSE 0 END) as retention_7day_count,
                    SUM(CASE WHEN ss.retention_tier = '30day' THEN 1 ELSE 0 END) as retention_30day_count,
                    SUM(CASE WHEN ss.status = 'past_due' THEN 1 ELSE 0 END) as past_due_count
                FROM bot_guilds bg
                LEFT JOIN server_subscriptions ss ON ss.guild_id = CAST(bg.guild_id AS BIGINT)
            """)
            stats_row = cursor.fetchone()
            stats = {
                'total_servers': stats_row['total_servers'],
                'paid_servers': stats_row['paid_servers'],
                'retention_7day_count': stats_row['retention_7day_count'],
                'retention_30day_count': stats_row['retention_30day_count'],
                'past_due_count': stats_row['past_due_count']
            }
            
            # Get total active sessions across all servers
            cursor = conn.execute("""
                SELECT COUNT(*) as total_active_sessions
                FROM sessions 
                WHERE clock_out IS NULL
            """)
            stats['total_active_sessions'] = cursor.fetchone()['total_active_sessions']
        
        return render_template('owner_dashboard.html', 
                             user=user_session,
                             servers=servers,
                             webhook_events=webhook_events,
                             stats=stats)
    
    except Exception as e:
        app.logger.error(f"Owner dashboard error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return "<h1>Error</h1><p>Unable to load owner dashboard. Please try again later.</p><a href='/dashboard'>Return to Dashboard</a>", 500

@app.route("/api/owner/grant-access", methods=["POST"])
@require_api_auth
def api_owner_grant_access(user_session):
    """Owner-only API endpoint to manually grant bot access or retention tiers to servers"""
    try:
        BOT_OWNER_ID = '107103438139056128'
        
        # Security check: Only allow bot owner
        if user_session['user_id'] != BOT_OWNER_ID:
            app.logger.warning(f"Unauthorized grant access attempt by user {user_session['user_id']}")
            return jsonify({'success': False, 'error': 'Unauthorized - Owner access required'}), 403
        
        data = request.get_json()
        guild_id = data.get('guild_id')
        access_type = data.get('access_type')
        
        if not guild_id or not access_type:
            return jsonify({'success': False, 'error': 'Missing guild_id or access_type'}), 400
        
        if access_type not in ['bot_access', '7day', '30day']:
            return jsonify({'success': False, 'error': 'Invalid access_type. Must be bot_access, 7day, or 30day'}), 400
        
        app.logger.info(f"Owner {user_session.get('username')} granting {access_type} to guild {guild_id}")
        
        with get_db() as conn:
            # Check if server exists in server_subscriptions
            cursor = conn.execute("SELECT guild_id FROM server_subscriptions WHERE guild_id = %s", (guild_id,))
            server_exists = cursor.fetchone()
            
            if not server_exists:
                # Create server subscription entry if it doesn't exist
                conn.execute("""
                    INSERT INTO server_subscriptions (guild_id, tier, bot_access_paid, retention_tier, status)
                    VALUES (%s, 'free', FALSE, 'none', 'active')
                """, (guild_id,))
                app.logger.info(f"Created new server_subscriptions entry for guild {guild_id}")
            
            # Grant the appropriate access
            if access_type == 'bot_access':
                conn.execute("""
                    UPDATE server_subscriptions 
                    SET bot_access_paid = TRUE,
                        manually_granted = TRUE,
                        granted_by = %s,
                        granted_at = NOW()
                    WHERE guild_id = %s
                """, (user_session['user_id'], guild_id))
                app.logger.info(f"Γ£à Granted bot access to guild {guild_id}")
                
            elif access_type in ['7day', '30day']:
                # Ensure bot access is paid first
                cursor = conn.execute("SELECT bot_access_paid FROM server_subscriptions WHERE guild_id = %s", (guild_id,))
                bot_access = cursor.fetchone()
                
                if not bot_access or not bot_access['bot_access_paid']:
                    # Raise exception to trigger rollback via context manager
                    raise ValueError('Bot access must be granted before retention tiers. Grant bot access first.')
                
                conn.execute("""
                    UPDATE server_subscriptions 
                    SET retention_tier = %s,
                        manually_granted = TRUE,
                        granted_by = %s,
                        granted_at = NOW(),
                        status = 'active'
                    WHERE guild_id = %s
                """, (access_type, user_session['user_id'], guild_id))
                app.logger.info(f"Γ£à Granted {access_type} retention to guild {guild_id}")
            
            # Context manager handles commit automatically
            app.logger.info(f"Γ£à Transaction will be committed for guild {guild_id}")
            
            # Send notification to server owner if granting bot access
            if access_type == 'bot_access':
                app.logger.info(f"≡ƒôº Attempting to send welcome notification to server owner for guild {guild_id}")
                
                # Check bot availability with detailed logging
                if not bot:
                    app.logger.error(f"Γ¥î Bot instance is None - cannot send notification")
                    app.logger.error(f"   Bot may not have started yet. Check if Discord bot thread is running.")
                elif not hasattr(bot, 'loop'):
                    app.logger.error(f"Γ¥î Bot instance has no 'loop' attribute - bot may not be started yet")
                    app.logger.error(f"   Discord bot needs to connect before notifications can be sent.")
                elif not bot.loop:
                    app.logger.error(f"Γ¥î Bot loop is None - bot may not be fully connected")
                    app.logger.error(f"   Discord connection not established. Wait for bot to fully start.")
                elif not bot.is_ready():
                    app.logger.error(f"Γ¥î Bot is not ready - still connecting to Discord")
                    app.logger.error(f"   Bot status: connected but not ready. Notification will be skipped.")
                else:
                    app.logger.info(f"Γ£à Bot is ready and connected. Queueing notification...")
                    try:
                        # Queue the notification in the bot's event loop
                        future = asyncio.run_coroutine_threadsafe(
                            notify_server_owner_bot_access(int(guild_id), granted_by="manual"),
                            bot.loop
                        )
                        app.logger.info(f"Γ£à Welcome notification queued successfully for guild {guild_id}")
                        
                        # Wait for result (max 5 seconds) to catch errors
                        try:
                            result = future.result(timeout=5.0)
                            app.logger.info(f"Γ£à Welcome notification completed successfully for guild {guild_id}")
                        except concurrent.futures.TimeoutError:
                            app.logger.error(f"ΓÅ▒∩╕Å Welcome notification timed out after 5 seconds for guild {guild_id}")
                            app.logger.error(f"   Notification may still be processing. Check Discord bot logs for [NOTIFY] messages.")
                        except Exception as result_error:
                            app.logger.error(f"Γ¥î Welcome notification failed for guild {guild_id}")
                            app.logger.error(f"   Error type: {type(result_error).__name__}")
                            app.logger.error(f"   Error message: {str(result_error)}")
                            app.logger.error(f"   Full traceback:")
                            app.logger.error(traceback.format_exc())
                            
                    except Exception as notify_error:
                        app.logger.error(f"Γ¥î Failed to queue welcome notification for guild {guild_id}")
                        app.logger.error(f"   Error type: {type(notify_error).__name__}")
                        app.logger.error(f"   Error message: {str(notify_error)}")
                        app.logger.error(f"   Full traceback:")
                        app.logger.error(traceback.format_exc())
            
        return jsonify({
            'success': True,
            'message': f'Successfully granted {access_type} to server',
            'guild_id': guild_id,
            'access_type': access_type
        })
    
    except ValueError as ve:
        # Handle specific validation errors
        app.logger.warning(f"Validation error during grant: {str(ve)}")
        return jsonify({'success': False, 'error': str(ve)}), 400
    except Exception as e:
        app.logger.error(f"Grant access error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route("/api/owner/revoke-access", methods=["POST"])
@require_api_auth
def api_owner_revoke_access(user_session):
    """Owner-only API endpoint to manually revoke bot access or retention tiers from servers"""
    try:
        BOT_OWNER_ID = '107103438139056128'
        
        # Security check: Only allow bot owner
        if user_session['user_id'] != BOT_OWNER_ID:
            app.logger.warning(f"Unauthorized revoke access attempt by user {user_session['user_id']}")
            return jsonify({'success': False, 'error': 'Unauthorized - Owner access required'}), 403
        
        data = request.get_json()
        guild_id = data.get('guild_id')
        access_type = data.get('access_type')
        
        if not guild_id or not access_type:
            return jsonify({'success': False, 'error': 'Missing guild_id or access_type'}), 400
        
        if access_type not in ['bot_access', '7day', '30day']:
            return jsonify({'success': False, 'error': 'Invalid access_type. Must be bot_access, 7day, or 30day'}), 400
        
        app.logger.info(f"Owner {user_session.get('username')} revoking {access_type} from guild {guild_id}")
        
        with get_db() as conn:
            # Check if server exists in server_subscriptions
            cursor = conn.execute("SELECT guild_id, bot_access_paid, retention_tier FROM server_subscriptions WHERE guild_id = %s", (guild_id,))
            server = cursor.fetchone()
            
            if not server:
                app.logger.warning(f"Guild {guild_id} not found in server_subscriptions. Creating placeholder row.")
                # Auto-create placeholder row for this guild
                conn.execute("""
                    INSERT INTO server_subscriptions (guild_id, tier, bot_access_paid, retention_tier, status)
                    VALUES (%s, 'free', FALSE, 'none', 'free')
                """, (guild_id,))
                app.logger.info(f"Created placeholder server_subscriptions row for guild {guild_id}")
                # Re-fetch the server
                cursor = conn.execute("SELECT guild_id, bot_access_paid, retention_tier FROM server_subscriptions WHERE guild_id = %s", (guild_id,))
                server = cursor.fetchone()
            
            # Revoke the appropriate access
            if access_type == 'bot_access':
                # Revoke bot access and also clear retention tier
                # CRITICAL: Set tier to 'free' to prevent migration from re-enabling access
                conn.execute("""
                    UPDATE server_subscriptions 
                    SET bot_access_paid = FALSE,
                        tier = 'free',
                        retention_tier = 'none',
                        status = 'cancelled',
                        manually_granted = FALSE,
                        granted_by = NULL,
                        granted_at = NULL
                    WHERE guild_id = %s
                """, (guild_id,))
                app.logger.info(f"Γ¥î Revoked bot access from guild {guild_id} (tier set to 'free', retention cleared)")
                
            elif access_type in ['7day', '30day']:
                # Only revoke if this is the current retention tier
                if server['retention_tier'] == access_type:
                    conn.execute("""
                        UPDATE server_subscriptions 
                        SET retention_tier = 'none',
                            status = 'active'
                        WHERE guild_id = %s
                    """, (guild_id,))
                    app.logger.info(f"Γ¥î Revoked {access_type} retention from guild {guild_id}")
                else:
                    return jsonify({
                        'success': False, 
                        'error': f'Server does not have {access_type} retention active'
                    }), 400
            
            # Commit all changes
            app.logger.info(f"Γ£à Transaction committed successfully for guild {guild_id}")
            
            return jsonify({
                'success': True,
                'message': f'Successfully revoked {access_type} from server',
                'guild_id': guild_id,
                'access_type': access_type
            })
    
    except Exception as e:
        app.logger.error(f"Revoke access error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

def verify_guild_access(user_session, guild_id):
    """
    Verify user has access to a specific guild.
    Returns the guild object if user has access, None otherwise.
    """
    all_guilds = user_session.get('guilds', [])
    for guild in all_guilds:
        if guild.get('id') == guild_id:
            # Check if user has admin access to this guild
            if user_has_admin_access(user_session['user_id'], guild_id, guild):
                return guild
    return None

def get_guild_roles_from_bot(guild_id):
    """
    Fetch guild roles using Discord bot token.
    Returns list of roles, or None if error.
    Note: Members are fetched via separate API endpoint to avoid heavy initial page load.
    """
    bot_token = os.environ.get('DISCORD_TOKEN')
    if not bot_token:
        app.logger.error("DISCORD_TOKEN not found in environment")
        return None
    
    headers = {'Authorization': f'Bot {bot_token}'}
    try:
        # Fetch guild roles only (lighter initial load)
        roles_response = requests.get(
            f'{DISCORD_API_BASE}/guilds/{guild_id}/roles',
            headers=headers,
            timeout=5
        )
        roles_response.raise_for_status()
        roles = roles_response.json()
        
        return roles
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 403:
            app.logger.error(f"Bot lacks permissions to fetch roles for guild {guild_id}")
        elif e.response.status_code == 404:
            app.logger.error(f"Guild {guild_id} not found or bot not in guild")
        else:
            app.logger.error(f"HTTP error fetching guild roles: {str(e)}")
        return None
    except Exception as e:
        app.logger.error(f"Error fetching guild roles: {str(e)}")
        app.logger.error(traceback.format_exc())
        return None

def get_guild_settings(guild_id):
    """
    Fetch guild settings from database.
    Returns dict with admin_roles, employee_roles, emails, timezone, etc.
    """
    with get_db() as conn:
        # Get admin roles (convert to strings to match Discord API format)
        admin_cursor = conn.execute(
            "SELECT role_id FROM admin_roles WHERE guild_id = %s",
            (guild_id,)
        )
        admin_roles = [str(row['role_id']) for row in admin_cursor.fetchall()]
        
        # Get employee roles (convert to strings to match Discord API format)
        employee_cursor = conn.execute(
            "SELECT role_id FROM employee_roles WHERE guild_id = %s",
            (guild_id,)
        )
        employee_roles = [str(row['role_id']) for row in employee_cursor.fetchall()]
        app.logger.info(f"≡ƒôï Fetched {len(employee_roles)} employee roles for guild {guild_id}: {employee_roles}")
        
        # Get guild settings (timezone, recipient_user_id, work_day_end_time, etc.)
        settings_cursor = conn.execute(
            "SELECT timezone, recipient_user_id, name_display_mode, main_admin_role_id, work_day_end_time FROM guild_settings WHERE guild_id = %s",
            (guild_id,)
        )
        settings_row = settings_cursor.fetchone()
        
        # Get email settings
        try:
            email_settings_cursor = conn.execute(
                "SELECT auto_send_on_clockout, auto_email_before_delete FROM email_settings WHERE guild_id = %s",
                (guild_id,)
            )
            email_settings_row = email_settings_cursor.fetchone()
        except:
            email_settings_row = None
        
        # Get mobile restriction setting
        try:
            mobile_restriction_cursor = conn.execute(
                "SELECT restrict_mobile_clockin FROM server_subscriptions WHERE guild_id = %s",
                (int(guild_id),)
            )
            mobile_restriction_row = mobile_restriction_cursor.fetchone()
        except:
            mobile_restriction_row = None
        
        return {
            'admin_roles': admin_roles,
            'employee_roles': employee_roles,
            'timezone': (settings_row['timezone'] if settings_row else None) or 'America/New_York',
            'recipient_user_id': settings_row['recipient_user_id'] if settings_row else None,
            'name_display_mode': (settings_row['name_display_mode'] if settings_row else None) or 'username',
            'main_admin_role_id': settings_row['main_admin_role_id'] if settings_row else None,
            'work_day_end_time': (settings_row['work_day_end_time'] if settings_row else None) or '17:00',
            'auto_send_on_clockout': bool(email_settings_row['auto_send_on_clockout']) if email_settings_row else False,
            'auto_email_before_delete': bool(email_settings_row['auto_email_before_delete']) if email_settings_row else False,
            'restrict_mobile_clockin': bool(mobile_restriction_row['restrict_mobile_clockin']) if mobile_restriction_row else False,
            'emails': []  # TODO: Add email table and fetch emails
        }

@app.route("/upgrade/<guild_id>")
@require_auth
def upgrade_info(user_session, guild_id):
    """Show upgrade information page"""
    try:
        import html
        
        # Verify user has access to this guild
        guild = verify_guild_access(user_session, guild_id)
        if not guild:
            return "<h1>Access Denied</h1><p>You don't have admin access to this server.</p><a href='/dashboard'>Back to Dashboard</a>", 403
        
        # Get bot access and retention tier status
        from bot import check_bot_access, get_retention_tier
        has_bot_access = check_bot_access(int(guild_id))
        retention_tier = get_retention_tier(int(guild_id))
        
        # Escape guild name for XSS protection
        guild_name_safe = html.escape(guild['name'])
        
        # Simple upgrade instructions page
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Upgrade - {guild_name_safe}</title>
            <style>
                body {{
                    font-family: 'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif;
                    background: linear-gradient(135deg, #0A0F1F 0%, #151B2E 50%, #1E2750 100%);
                    color: #C9D1D9;
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                }}
                .upgrade-card {{
                    background: rgba(30, 35, 45, 0.8);
                    border: 2px solid rgba(212, 175, 55, 0.3);
                    border-radius: 16px;
                    padding: 40px;
                    max-width: 600px;
                    text-align: center;
                }}
                h1 {{ color: #D4AF37; margin-bottom: 20px; }}
                .instructions {{ margin: 30px 0; text-align: left; }}
                .command {{ 
                    background: rgba(16, 185, 129, 0.1); 
                    border: 2px solid rgba(16, 185, 129, 0.3);
                    padding: 15px;
                    border-radius: 8px;
                    font-family: monospace;
                    font-size: 18px;
                    color: #10B981;
                    margin: 20px 0;
                }}
                .back-btn {{
                    background: linear-gradient(135deg, #3B82F6, #2563EB);
                    color: white;
                    padding: 12px 24px;
                    border-radius: 8px;
                    text-decoration: none;
                    display: inline-block;
                    margin-top: 20px;
                }}
                .status {{ margin: 20px 0; padding: 15px; border-radius: 8px; }}
                .free {{ background: rgba(239, 68, 68, 0.1); border: 2px solid rgba(239, 68, 68, 0.3); }}
                .paid {{ background: rgba(16, 185, 129, 0.1); border: 2px solid rgba(16, 185, 129, 0.3); }}
            </style>
        </head>
        <body>
            <div class="upgrade-card">
                <h1>≡ƒÆ│ Upgrade Your Server</h1>
                
                <div class="status {'paid' if has_bot_access else 'free'}">
                    {'Γ£à Full Bot Access Active' if has_bot_access else '≡ƒöÆ Free Tier - Limited Features'}
                    <br>
                    {f"≡ƒôè {retention_tier.replace('day', '-Day').title()} Retention" if retention_tier != 'none' else 'ΓÜá∩╕Å 24-Hour Data Deletion'}
                </div>
                
                <div class="instructions">
                    <h3>≡ƒôï How to Upgrade:</h3>
                    <ol>
                        <li>Go to your Discord server: <strong>{guild_name_safe}</strong></li>
                        <li>Run this command in any channel:</li>
                    </ol>
                    <div class="command">/upgrade</div>
                    <p>The bot will show you available upgrade options with secure Stripe checkout links.</p>
                    
                    {'''
                    <h3 style="margin-top: 30px;">≡ƒÆí What You Get:</h3>
                    <ul style="text-align: left;">
                        <li><strong>$5 One-Time:</strong> Full bot access, real reports, dashboard unlocked</li>
                        <li><strong>$5/Month:</strong> 7-day data retention</li>
                        <li><strong>$10/Month:</strong> 30-day data retention</li>
                    </ul>
                    ''' if not has_bot_access else '''
                    <h3 style="margin-top: 30px;">≡ƒôü Add Data Retention:</h3>
                    <ul style="text-align: left;">
                        <li><strong>$5/Month:</strong> 7-day rolling retention</li>
                        <li><strong>$10/Month:</strong> 30-day rolling retention</li>
                    </ul>
                    '''}
                </div>
                
                <a href="/dashboard" class="back-btn">ΓåÉ Back to Dashboard</a>
            </div>
        </body>
        </html>
        """
    except Exception as e:
        app.logger.error(f"Upgrade info error: {str(e)}")
        return "<h1>Error</h1><p>Unable to load upgrade information.</p>", 500

@app.route("/purchase/<int:guild_id>")
def purchase_page(guild_id):
    """Public purchase page for $5 bot access - explains what it unlocks"""
    try:
        import html
        from bot import check_bot_access
        
        # Check if already has bot access
        has_bot_access = check_bot_access(guild_id)
        
        if has_bot_access:
            # Already purchased - redirect to upgrade page for retention options
            return f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta http-equiv="refresh" content="3;url=/upgrade/{guild_id}" />
                <title>Already Purchased</title>
                <style>
                    body {{
                        font-family: 'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif;
                        background: linear-gradient(135deg, #0A0F1F 0%, #151B2E 50%, #1E2750 100%);
                        color: #C9D1D9;
                        min-height: 100vh;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        text-align: center;
                        padding: 20px;
                    }}
                </style>
            </head>
            <body>
                <div>
                    <h1>Γ£à Bot Access Already Active!</h1>
                    <p>Redirecting to upgrade options...</p>
                </div>
            </body>
            </html>
            """
        
        # Show purchase information page
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Get Bot Access - On the Clock</title>
            <style>
                body {{
                    font-family: 'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif;
                    background: linear-gradient(135deg, #0A0F1F 0%, #151B2E 50%, #1E2750 100%);
                    color: #C9D1D9;
                    min-height: 100vh;
                    padding: 40px 20px;
                }}
                .container {{
                    max-width: 800px;
                    margin: 0 auto;
                }}
                .header {{
                    text-align: center;
                    margin-bottom: 50px;
                }}
                .header h1 {{
                    color: #D4AF37;
                    font-size: 2.5em;
                    margin-bottom: 10px;
                }}
                .price-tag {{
                    background: linear-gradient(135deg, #D4AF37, #F4C542);
                    color: #0A0F1F;
                    padding: 15px 30px;
                    border-radius: 12px;
                    display: inline-block;
                    font-size: 1.8em;
                    font-weight: bold;
                    margin: 20px 0;
                }}
                .features-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                    gap: 20px;
                    margin: 40px 0;
                }}
                .feature-card {{
                    background: rgba(30, 35, 45, 0.8);
                    border: 2px solid rgba(212, 175, 55, 0.3);
                    border-radius: 12px;
                    padding: 25px;
                }}
                .feature-card h3 {{
                    color: #D4AF37;
                    margin-bottom: 15px;
                }}
                .feature-card ul {{
                    list-style: none;
                    padding: 0;
                }}
                .feature-card li {{
                    padding: 8px 0;
                    display: flex;
                    align-items: center;
                }}
                .feature-card li::before {{
                    content: "Γ£à";
                    margin-right: 10px;
                }}
                .cta-section {{
                    background: rgba(59, 130, 246, 0.1);
                    border: 2px solid rgba(59, 130, 246, 0.3);
                    border-radius: 12px;
                    padding: 30px;
                    text-align: center;
                    margin: 40px 0;
                }}
                .command {{
                    background: rgba(16, 185, 129, 0.1);
                    border: 2px solid rgba(16, 185, 129, 0.3);
                    padding: 15px 25px;
                    border-radius: 8px;
                    font-family: monospace;
                    font-size: 1.4em;
                    color: #10B981;
                    margin: 20px auto;
                    display: inline-block;
                }}
                .comparison {{
                    background: rgba(30, 35, 45, 0.6);
                    border-radius: 12px;
                    padding: 30px;
                    margin: 40px 0;
                }}
                .comparison table {{
                    width: 100%;
                    border-collapse: collapse;
                }}
                .comparison th, .comparison td {{
                    padding: 15px;
                    text-align: left;
                    border-bottom: 1px solid rgba(212, 175, 55, 0.2);
                }}
                .comparison th {{
                    color: #D4AF37;
                    font-weight: 600;
                }}
                .yes {{ color: #10B981; }}
                .no {{ color: #EF4444; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>≡ƒöô Unlock Full Bot Access</h1>
                    <p style="font-size: 1.2em;">One-time payment to unlock all features</p>
                    <div class="price-tag">$5 One-Time</div>
                </div>

                <div class="features-grid">
                    <div class="feature-card">
                        <h3>≡ƒæÑ Full Team Access</h3>
                        <ul>
                            <li>Unlimited employees</li>
                            <li>Role-based access control</li>
                            <li>Admin management</li>
                            <li>Employee tracking</li>
                        </ul>
                    </div>

                    <div class="feature-card">
                        <h3>≡ƒôè Real Reports</h3>
                        <ul>
                            <li>CSV timesheet exports</li>
                            <li>Individual user reports</li>
                            <li>Team summaries</li>
                            <li>Email delivery</li>
                        </ul>
                    </div>

                    <div class="feature-card">
                        <h3>≡ƒÄ¢∩╕Å Dashboard Access</h3>
                        <ul>
                            <li>Web-based settings</li>
                            <li>Role management UI</li>
                            <li>Timezone controls</li>
                            <li>Email automation</li>
                        </ul>
                    </div>

                    <div class="feature-card">
                        <h3>ΓÜÖ∩╕Å All Commands</h3>
                        <ul>
                            <li>Clock in/out tracking</li>
                            <li>Time management</li>
                            <li>Admin tools</li>
                            <li>Settings control</li>
                        </ul>
                    </div>
                </div>

                <div class="comparison">
                    <h2 style="color: #D4AF37; text-align: center; margin-bottom: 25px;">Free vs Bot Access</h2>
                    <table>
                        <tr>
                            <th>Feature</th>
                            <th>Free Tier</th>
                            <th>Bot Access ($5)</th>
                        </tr>
                        <tr>
                            <td>Clock In/Out</td>
                            <td class="yes">Γ£à Basic</td>
                            <td class="yes">Γ£à Full Access</td>
                        </tr>
                        <tr>
                            <td>Team Reports</td>
                            <td class="no">Γ¥î Dummy Only</td>
                            <td class="yes">Γ£à Real CSV Reports</td>
                        </tr>
                        <tr>
                            <td>Dashboard</td>
                            <td class="no">Γ¥î Locked</td>
                            <td class="yes">Γ£à Full Access</td>
                        </tr>
                        <tr>
                            <td>Role Management</td>
                            <td class="no">Γ¥î Admin Only</td>
                            <td class="yes">Γ£à Full Control</td>
                        </tr>
                        <tr>
                            <td>Data Retention</td>
                            <td class="no">ΓÜá∩╕Å 24 Hours</td>
                            <td class="yes">ΓÜá∩╕Å 24 Hours*</td>
                        </tr>
                    </table>
                    <p style="margin-top: 20px; color: #9CA3AF; font-size: 0.9em;">
                        *Add retention subscriptions for 7-day ($5/mo) or 30-day ($10/mo) data storage
                    </p>
                </div>

                <div class="cta-section">
                    <h2 style="color: #D4AF37; margin-bottom: 20px;">How to Purchase</h2>
                    <p style="font-size: 1.1em; margin-bottom: 20px;">
                        Go to your Discord server and run this command:
                    </p>
                    <div class="command">/upgrade</div>
                    <p style="margin-top: 20px; color: #9CA3AF;">
                        The bot will provide a secure Stripe checkout link for the $5 bot access payment.
                    </p>
                </div>
            </div>
        </body>
        </html>
        """
    except Exception as e:
        app.logger.error(f"Purchase page error: {str(e)}")
        return "<h1>Error</h1><p>Unable to load purchase page.</p>", 500

# API Endpoints for Settings Management

def validate_role_in_guild(guild_id, role_id):
    """Validate that a role_id belongs to the specified guild"""
    try:
        roles = get_guild_roles_from_bot(guild_id)
        if not roles:
            return False
        return any(str(role['id']) == str(role_id) for role in roles)
    except Exception as e:
        app.logger.error(f"Error validating role: {str(e)}")
        return False

@app.route("/api/server/<guild_id>/admin-roles/add", methods=["POST"])
@require_paid_api_access
def api_add_admin_role(user_session, guild_id):
    """API endpoint to add an admin role - Proxies to bot API"""
    try:
        # Check for BOT_API_SECRET
        bot_api_secret = os.getenv('BOT_API_SECRET')
        if not bot_api_secret:
            app.logger.error("BOT_API_SECRET not configured")
            return jsonify({'success': False, 'error': 'Server configuration error - BOT_API_SECRET missing'}), 500
        
        # Verify user has access
        guild = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Get role_id from request
        data = request.get_json()
        if not data or 'role_id' not in data:
            return jsonify({'success': False, 'error': 'Missing role_id'}), 400
        
        role_id = str(data['role_id'])
        
        # Validate role belongs to guild
        if not validate_role_in_guild(guild_id, role_id):
            return jsonify({'success': False, 'error': 'Invalid role for this server'}), 400
        
        # Forward request to bot API (Bot as Boss)
        bot_api_url = f"http://localhost:8081/api/guild/{guild_id}/admin-roles/add"
        
        response = requests.post(
            bot_api_url,
            json={'role_id': role_id},
            headers={'Authorization': f'Bearer {bot_api_secret}'},
            timeout=5
        )
        
        if response.ok:
            app.logger.info(f"Added admin role {role_id} to guild {guild_id} by user {user_session.get('username')}")
            return jsonify(response.json())
        else:
            app.logger.error(f"Bot API error: {response.status_code} - {response.text}")
            return jsonify({'success': False, 'error': 'Bot API error'}), response.status_code
            
    except Exception as e:
        app.logger.error(f"Error adding admin role: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@app.route("/api/server/<guild_id>/admin-roles/remove", methods=["POST"])
@require_paid_api_access
def api_remove_admin_role(user_session, guild_id):
    """API endpoint to remove an admin role - Proxies to bot API"""
    try:
        # Check for BOT_API_SECRET
        bot_api_secret = os.getenv('BOT_API_SECRET')
        if not bot_api_secret:
            app.logger.error("BOT_API_SECRET not configured")
            return jsonify({'success': False, 'error': 'Server configuration error - BOT_API_SECRET missing'}), 500
        
        # Verify user has access
        guild = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Get role_id from request
        data = request.get_json()
        if not data or 'role_id' not in data:
            return jsonify({'success': False, 'error': 'Missing role_id'}), 400
        
        role_id = str(data['role_id'])
        
        # Forward request to bot API (Bot as Boss)
        bot_api_url = f"http://localhost:8081/api/guild/{guild_id}/admin-roles/remove"
        
        response = requests.post(
            bot_api_url,
            json={'role_id': role_id},
            headers={'Authorization': f'Bearer {bot_api_secret}'},
            timeout=5
        )
        
        if response.ok:
            app.logger.info(f"Removed admin role {role_id} from guild {guild_id} by user {user_session.get('username')}")
            return jsonify(response.json())
        else:
            app.logger.error(f"Bot API error: {response.status_code} - {response.text}")
            return jsonify({'success': False, 'error': 'Bot API error'}), response.status_code
            
    except Exception as e:
        app.logger.error(f"Error removing admin role: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@app.route("/api/server/<guild_id>/employee-roles/add", methods=["POST"])
@require_paid_api_access
def api_add_employee_role(user_session, guild_id):
    """API endpoint to add an employee role - Proxies to bot API"""
    try:
        # Check for BOT_API_SECRET
        bot_api_secret = os.getenv('BOT_API_SECRET')
        if not bot_api_secret:
            app.logger.error("BOT_API_SECRET not configured")
            return jsonify({'success': False, 'error': 'Server configuration error - BOT_API_SECRET missing'}), 500
        
        # Verify user has access
        guild = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Get role_id from request
        data = request.get_json()
        if not data or 'role_id' not in data:
            return jsonify({'success': False, 'error': 'Missing role_id'}), 400
        
        role_id = str(data['role_id'])
        
        # Validate role belongs to guild
        if not validate_role_in_guild(guild_id, role_id):
            return jsonify({'success': False, 'error': 'Invalid role for this server'}), 400
        
        # Forward request to bot API (Bot as Boss)
        bot_api_url = f"http://localhost:8081/api/guild/{guild_id}/employee-roles/add"
        
        app.logger.info(f"≡ƒöù Flask calling bot API: {bot_api_url} with role_id={role_id}")
        
        response = requests.post(
            bot_api_url,
            json={'role_id': role_id},
            headers={'Authorization': f'Bearer {bot_api_secret}'},
            timeout=5
        )
        
        app.logger.info(f"≡ƒöù Bot API response: status={response.status_code}, ok={response.ok}")
        
        if response.ok:
            app.logger.info(f"Added employee role {role_id} to guild {guild_id} by user {user_session.get('username')}")
            return jsonify(response.json())
        else:
            app.logger.error(f"Bot API error: {response.status_code} - {response.text}")
            return jsonify({'success': False, 'error': 'Bot API error'}), response.status_code
            
    except Exception as e:
        app.logger.error(f"Error adding employee role: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@app.route("/api/server/<guild_id>/employee-roles/remove", methods=["POST"])
@require_paid_api_access
def api_remove_employee_role(user_session, guild_id):
    """API endpoint to remove an employee role - Proxies to bot API"""
    try:
        # Check for BOT_API_SECRET
        bot_api_secret = os.getenv('BOT_API_SECRET')
        if not bot_api_secret:
            app.logger.error("BOT_API_SECRET not configured")
            return jsonify({'success': False, 'error': 'Server configuration error - BOT_API_SECRET missing'}), 500
        
        # Verify user has access
        guild = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Get role_id from request
        data = request.get_json()
        if not data or 'role_id' not in data:
            return jsonify({'success': False, 'error': 'Missing role_id'}), 400
        
        role_id = str(data['role_id'])
        
        # Forward request to bot API (Bot as Boss)
        bot_api_url = f"http://localhost:8081/api/guild/{guild_id}/employee-roles/remove"
        
        response = requests.post(
            bot_api_url,
            json={'role_id': role_id},
            headers={'Authorization': f'Bearer {bot_api_secret}'},
            timeout=5
        )
        
        if response.ok:
            app.logger.info(f"Removed employee role {role_id} from guild {guild_id} by user {user_session.get('username')}")
            return jsonify(response.json())
        else:
            app.logger.error(f"Bot API error: {response.status_code} - {response.text}")
            return jsonify({'success': False, 'error': 'Bot API error'}), response.status_code
            
    except Exception as e:
        app.logger.error(f"Error removing employee role: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@app.route("/api/server/<guild_id>/timezone", methods=["POST"])
@require_paid_api_access
def api_update_timezone(user_session, guild_id):
    """API endpoint to update timezone"""
    try:
        # Verify user has access
        guild = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Get timezone from request
        data = request.get_json()
        if not data or 'timezone' not in data:
            return jsonify({'success': False, 'error': 'Missing timezone'}), 400
        
        timezone_str = data['timezone']
        
        # Validate timezone
        try:
            from zoneinfo import ZoneInfo, available_timezones
            if timezone_str not in available_timezones():
                return jsonify({'success': False, 'error': 'Invalid timezone'}), 400
        except Exception as tz_error:
            app.logger.error(f"Timezone validation error: {str(tz_error)}")
            return jsonify({'success': False, 'error': 'Invalid timezone'}), 400
        
        # Update or insert guild settings
        with get_db() as conn:
            # Check if settings exist
            cursor = conn.execute("SELECT guild_id FROM guild_settings WHERE guild_id = %s", (guild_id,))
            exists = cursor.fetchone()
            
            if exists:
                conn.execute(
                    "UPDATE guild_settings SET timezone = %s WHERE guild_id = %s",
                    (timezone_str, guild_id)
                )
            else:
                conn.execute(
                    "INSERT INTO guild_settings (guild_id, timezone) VALUES (%s, %s)",
                    (guild_id, timezone_str)
                )
        
        app.logger.info(f"Updated timezone to {timezone_str} for guild {guild_id} by user {user_session.get('username')}")
        return jsonify({'success': True, 'message': 'Timezone updated successfully', 'timezone': timezone_str})
    except Exception as e:
        app.logger.error(f"Error updating timezone: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@app.route("/api/server/<guild_id>/email-settings", methods=["POST"])
@require_paid_api_access
def api_update_email_settings(user_session, guild_id):
    """API endpoint to update email settings"""
    try:
        # Verify user has access
        guild = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Get email settings from request
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Missing data'}), 400
        
        auto_send_on_clockout = bool(data.get('auto_send_on_clockout', False))
        auto_email_before_delete = bool(data.get('auto_email_before_delete', False))
        
        # Update or insert email settings
        with get_db() as conn:
            # Check if settings exist
            cursor = conn.execute("SELECT guild_id FROM email_settings WHERE guild_id = %s", (guild_id,))
            exists = cursor.fetchone()
            
            if exists:
                conn.execute(
                    """UPDATE email_settings 
                       SET auto_send_on_clockout = %s, auto_email_before_delete = %s 
                       WHERE guild_id = %s""",
                    (auto_send_on_clockout, auto_email_before_delete, guild_id)
                )
            else:
                conn.execute(
                    """INSERT INTO email_settings (guild_id, auto_send_on_clockout, auto_email_before_delete) 
                       VALUES (%s, %s, %s)""",
                    (guild_id, auto_send_on_clockout, auto_email_before_delete)
                )
            
            app.logger.info(f"Γ£à Email settings committed for guild {guild_id} by user {user_session.get('username')}")
            
            return jsonify({
                'success': True, 
                'message': 'Email settings updated successfully',
                'auto_send_on_clockout': auto_send_on_clockout,
                'auto_email_before_delete': auto_email_before_delete
            })
    except Exception as e:
        app.logger.error(f"Error updating email settings: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@app.route("/api/server/<guild_id>/work-day-time", methods=["POST"])
@require_paid_api_access
def api_update_work_day_time(user_session, guild_id):
    """API endpoint to update work day end time"""
    try:
        # Verify user has access
        guild = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Get work day end time from request
        data = request.get_json()
        if not data or 'work_day_end_time' not in data:
            return jsonify({'success': False, 'error': 'Missing work day end time'}), 400
        
        work_day_end_time = data['work_day_end_time']
        
        # Validate time format (HH:MM)
        import re
        if not re.match(r'^([01]%s[0-9]|2[0-3]):[0-5][0-9]$', work_day_end_time):
            return jsonify({'success': False, 'error': 'Invalid time format. Use HH:MM'}), 400
        
        # Update or insert guild settings
        with get_db() as conn:
            # Check if settings exist
            cursor = conn.execute("SELECT guild_id FROM guild_settings WHERE guild_id = %s", (guild_id,))
            exists = cursor.fetchone()
            
            if exists:
                conn.execute(
                    "UPDATE guild_settings SET work_day_end_time = %s WHERE guild_id = %s",
                    (work_day_end_time, guild_id)
                )
            else:
                # Insert with proper defaults for all columns
                conn.execute(
                    """INSERT INTO guild_settings (guild_id, timezone, name_display_mode, work_day_end_time) 
                       VALUES (%s, 'America/New_York', 'username', %s)""",
                    (guild_id, work_day_end_time)
                )
            
            app.logger.info(f"Γ£à Work day end time committed: {work_day_end_time} for guild {guild_id}")
            
            return jsonify({'success': True, 'message': 'Work day end time updated successfully', 'work_day_end_time': work_day_end_time})
    except Exception as e:
        app.logger.error(f"Error updating work day end time: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@app.route("/api/server/<guild_id>/mobile-restriction", methods=["POST"])
@require_paid_api_access
def api_update_mobile_restriction(user_session, guild_id):
    """API endpoint to update mobile device restriction setting"""
    try:
        app.logger.info(f"≡ƒöº Mobile restriction API called for guild {guild_id}")
        
        # Verify user has access
        guild = verify_guild_access(user_session, guild_id)
        if not guild:
            app.logger.warning(f"Γ¥î Access denied for guild {guild_id}")
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Get mobile restriction setting from request
        data = request.get_json()
        if data is None:
            app.logger.error(f"Γ¥î Missing data in request for guild {guild_id}")
            return jsonify({'success': False, 'error': 'Missing data'}), 400
        
        restrict_mobile = bool(data.get('restrict_mobile', False))
        app.logger.info(f"≡ƒô▒ Setting mobile restriction to {restrict_mobile} for guild {guild_id}")
        
        # Update or insert mobile restriction setting
        with get_db() as conn:
            # Ensure a record exists in server_subscriptions
            cursor = conn.execute("SELECT guild_id FROM server_subscriptions WHERE guild_id = %s", (int(guild_id),))
            exists = cursor.fetchone()
            
            if exists:
                app.logger.info(f"≡ƒöä Updating existing record for guild {guild_id}")
                conn.execute(
                    "UPDATE server_subscriptions SET restrict_mobile_clockin = %s WHERE guild_id = %s",
                    (restrict_mobile, int(guild_id))
                )
            else:
                app.logger.info(f"Γ₧ò Inserting new record for guild {guild_id}")
                # Insert new record with all required default values
                conn.execute(
                    """INSERT INTO server_subscriptions 
                       (guild_id, tier, bot_access_paid, retention_tier, restrict_mobile_clockin) 
                       VALUES (%s, 'free', FALSE, 'none', %s)""",
                    (int(guild_id), restrict_mobile)
                )
            
            # Verify the save
            verify_cursor = conn.execute(
                "SELECT restrict_mobile_clockin FROM server_subscriptions WHERE guild_id = %s",
                (int(guild_id),)
            )
            verify_result = verify_cursor.fetchone()
            if verify_result:
                app.logger.info(f"Γ£à Verified database value: {verify_result['restrict_mobile_clockin']} for guild {guild_id}")
            
            app.logger.info(f"Γ£à Mobile restriction setting committed: {restrict_mobile} for guild {guild_id}")
            
            return jsonify({
                'success': True, 
                'message': 'Mobile restriction setting updated successfully',
                'restrict_mobile': restrict_mobile
            })
    except Exception as e:
        app.logger.error(f"Γ¥î Error updating mobile restriction: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@app.route("/api/server/<guild_id>/email-recipients", methods=["GET"])
@require_paid_api_access
def api_get_email_recipients(user_session, guild_id):
    """API endpoint to fetch email recipients for a server"""
    try:
        # Verify user has access
        guild = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Fetch email recipients
        with get_db() as conn:
            cursor = conn.execute(
                """SELECT id, email_address, created_at 
                   FROM report_recipients 
                   WHERE guild_id = %s AND recipient_type = 'email'
                   ORDER BY created_at DESC""",
                (guild_id,)
            )
            recipients = cursor.fetchall()
            
        emails = [
            {
                'id': row['id'],
                'email': row['email_address'],
                'created_at': row['created_at']
            }
            for row in recipients
        ]
        
        return jsonify({'success': True, 'emails': emails})
    except Exception as e:
        app.logger.error(f"Error fetching email recipients: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@app.route("/api/server/<guild_id>/email-recipients/add", methods=["POST"])
@require_paid_api_access
def api_add_email_recipient(user_session, guild_id):
    """API endpoint to add an email recipient"""
    try:
        # Verify user has access
        guild = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Get email from request
        data = request.get_json()
        if not data or 'email' not in data:
            return jsonify({'success': False, 'error': 'Missing email address'}), 400
        
        email = data['email'].strip()
        
        # Basic email validation
        import re
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            return jsonify({'success': False, 'error': 'Invalid email address format'}), 400
        
        # Add to database
        with get_db() as conn:
            try:
                cursor = conn.execute(
                    """INSERT INTO report_recipients (guild_id, recipient_type, email_address) 
                       VALUES (%s, 'email', %s)""",
                    (guild_id, email)
                )
                recipient_id = cursor.lastrowid
                
                app.logger.info(f"Γ£à Email recipient committed: {email} for guild {guild_id}")
                
                return jsonify({'success': True, 'message': 'Email recipient added successfully', 'id': recipient_id, 'email': email})
            except psycopg2.IntegrityError:
                # Context manager handles rollback automatically
                return jsonify({'success': False, 'error': 'Email address already exists'}), 400
            except Exception as db_error:
                # Context manager handles rollback automatically
                app.logger.error(f"Database error adding email recipient: {db_error}")
                raise
    except Exception as e:
        app.logger.error(f"Error adding email recipient: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@app.route("/api/server/<guild_id>/email-recipients/remove", methods=["POST"])
@require_paid_api_access
def api_remove_email_recipient(user_session, guild_id):
    """API endpoint to remove an email recipient"""
    try:
        # Verify user has access
        guild = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Get email ID from request
        data = request.get_json()
        if not data or 'id' not in data:
            return jsonify({'success': False, 'error': 'Missing recipient ID'}), 400
        
        recipient_id = data['id']
        
        # Remove from database
        with get_db() as conn:
            cursor = conn.execute(
                """DELETE FROM report_recipients 
                   WHERE id = %s AND guild_id = %s AND recipient_type = 'email'""",
                (recipient_id, guild_id)
            )
            
            if cursor.rowcount == 0:
                return jsonify({'success': False, 'error': 'Recipient not found'}), 404
            
            app.logger.info(f"Γ£à Email recipient removed: {recipient_id} for guild {guild_id}")
            
            return jsonify({'success': True, 'message': 'Email recipient removed successfully'})
    except Exception as e:
        app.logger.error(f"Error removing email recipient: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@app.route("/api/server/<guild_id>/data", methods=["GET"])
@require_paid_api_access
def api_get_server_data(user_session, guild_id):
    """API endpoint to fetch server roles and settings for dashboard integration"""
    try:
        # Verify user has access
        guild = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Check if bot is present
        bot_guild_ids = get_bot_guild_ids()
        if guild_id not in bot_guild_ids:
            return jsonify({'success': False, 'error': 'Bot not present in this server'}), 404
        
        # Fetch guild roles
        roles = get_guild_roles_from_bot(guild_id)
        if not roles:
            return jsonify({'success': False, 'error': 'Could not fetch server roles'}), 500
        
        # Fetch current settings
        current_settings = get_guild_settings(guild_id)
        
        return jsonify({
            'success': True,
            'guild': guild,
            'roles': roles,
            'current_settings': current_settings
        })
    except Exception as e:
        app.logger.error(f"Error fetching server data: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@app.route("/api/server/<guild_id>/bans", methods=["GET"])
@require_paid_api_access
def api_get_bans(user_session, guild_id):
    """API endpoint to fetch all banned users for a server"""
    try:
        guild = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT user_id, banned_at, ban_expires_at, warning_count, reason 
                FROM banned_users 
                WHERE guild_id = %s
                ORDER BY banned_at DESC
            """, (guild_id,))
            
            bans = []
            for row in cursor.fetchall():
                bans.append({
                    'user_id': str(row['user_id']),
                    'banned_at': row['banned_at'],
                    'ban_expires_at': row['ban_expires_at'],
                    'warning_count': row['warning_count'],
                    'reason': row['reason']
                })
        
        return jsonify({'success': True, 'bans': bans})
    except Exception as e:
        app.logger.error(f"Error fetching bans: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@app.route("/api/server/<guild_id>/bans/unban", methods=["POST"])
@require_paid_api_access
def api_unban_user(user_session, guild_id):
    """API endpoint to unban a user"""
    try:
        guild = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        data = request.get_json()
        if not data or 'user_id' not in data:
            return jsonify({'success': False, 'error': 'Missing user_id'}), 400
        
        user_id = str(data['user_id'])
        
        with get_db() as conn:
            conn.execute(
                "DELETE FROM banned_users WHERE guild_id = %s AND user_id = %s",
                (guild_id, user_id)
            )
        
        app.logger.info(f"Unbanned user {user_id} from guild {guild_id} by {user_session.get('username')}")
        return jsonify({'success': True, 'message': 'User unbanned successfully'})
    except Exception as e:
        app.logger.error(f"Error unbanning user: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@app.route("/api/server/<guild_id>/bans/permanent", methods=["POST"])
@require_paid_api_access
def api_make_ban_permanent(user_session, guild_id):
    """API endpoint to make a ban permanent"""
    try:
        guild = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        data = request.get_json()
        if not data or 'user_id' not in data:
            return jsonify({'success': False, 'error': 'Missing user_id'}), 400
        
        user_id = str(data['user_id'])
        
        with get_db() as conn:
            conn.execute("""
                UPDATE banned_users 
                SET ban_expires_at = NULL, reason = 'permanent_ban'
                WHERE guild_id = %s AND user_id = %s
            """, (guild_id, user_id))
        
        app.logger.info(f"Made ban permanent for user {user_id} in guild {guild_id} by {user_session.get('username')}")
        return jsonify({'success': True, 'message': 'Ban made permanent'})
    except Exception as e:
        app.logger.error(f"Error making ban permanent: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@app.route("/purchase/<product_type>")
def purchase_init(product_type):
    """Initialize purchase flow - store intent and redirect to OAuth"""
    # Validate product type
    valid_products = ['bot_access', 'retention_7day', 'retention_30day']
    if product_type not in valid_products:
        return "<h1>Invalid Product</h1><p>Unknown product type.</p><a href='/'>Return Home</a>", 400
    
    # Store purchase intent in session
    session['purchase_intent'] = {
        'product_type': product_type,
        'initiated_at': datetime.now(timezone.utc).isoformat()
    }
    
    # Redirect to OAuth login
    state = create_oauth_state()
    redirect_uri = get_redirect_uri()
    
    params = {
        'client_id': DISCORD_CLIENT_ID,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': DISCORD_OAUTH_SCOPES,
        'state': state
    }
    
    auth_url = f'https://discord.com/oauth2/authorize?{urlencode(params)}'
    app.logger.info(f"Purchase flow initiated for {product_type}")
    return redirect(auth_url)

@app.route("/purchase/select_server")
@require_auth
def purchase_select_server(user_session):
    """Show server selection page after OAuth"""
    try:
        # Check for purchase intent
        purchase_intent = session.get('purchase_intent')
        if not purchase_intent:
            app.logger.warning("No purchase intent found in session")
            return redirect('/')
        
        product_type = purchase_intent.get('product_type')
        
        # Get bot guild IDs and user's guilds
        bot_guild_ids = get_bot_guild_ids()
        all_guilds = user_session.get('guilds', [])
        
        # Separate servers into with bot and without bot
        servers_with_bot = []
        servers_without_bot = []
        
        for guild in all_guilds:
            guild_id = guild.get('id')
            
            # Only include servers where user has admin access
            if not user_has_admin_access(user_session['user_id'], guild_id, guild):
                continue
            
            if guild_id in bot_guild_ids:
                servers_with_bot.append(guild)
            else:
                servers_without_bot.append(guild)
        
        # Bot invite URL
        bot_id = "1418446753379913809"
        permissions = "2048"
        invite_url = f"https://discord.com/api/oauth2/authorize?client_id={bot_id}&permissions={permissions}&scope=bot%20applications.commands"
        
        return render_template(
            'server_selection.html',
            product_type=product_type,
            servers_with_bot=servers_with_bot,
            servers_without_bot=servers_without_bot,
            invite_url=invite_url
        )
    except Exception as e:
        app.logger.error(f"Server selection error: {str(e)}")
        app.logger.error(traceback.format_exc())
        # Clear purchase intent on error
        session.pop('purchase_intent', None)
        return "<h1>Error</h1><p>Unable to load servers. Please try again.</p><a href='/'>Return Home</a>", 500

@app.route("/purchase/checkout")
@require_auth
def purchase_checkout(user_session):
    """Create Stripe checkout session - SECURITY: Verify admin access before proceeding"""
    try:
        # Check for purchase intent
        purchase_intent = session.get('purchase_intent')
        if not purchase_intent:
            app.logger.warning("No purchase intent found")
            return "<h1>Error</h1><p>Invalid purchase session.</p><a href='/'>Return Home</a>", 400
        
        product_type = purchase_intent.get('product_type')
        guild_id = request.args.get('guild_id')
        
        if not guild_id:
            return "<h1>Error</h1><p>No server selected.</p><a href='/purchase/select_server'>Go Back</a>", 400
        
        # CRITICAL SECURITY: Verify user has admin access to this guild
        all_guilds = user_session.get('guilds', [])
        authorized_guild = None
        
        for guild in all_guilds:
            if guild.get('id') == guild_id:
                # Check admin permissions
                if user_has_admin_access(user_session['user_id'], guild_id, guild):
                    authorized_guild = guild
                    break
        
        if not authorized_guild:
            app.logger.error(f"Unauthorized checkout attempt for guild {guild_id} by user {user_session.get('user_id')}")
            return "<h1>Access Denied</h1><p>You do not have admin permissions for this server.</p><a href='/purchase/select_server'>Go Back</a>", 403
        
        # SECURITY: Verify bot is present in the guild
        bot_guild_ids = get_bot_guild_ids()
        if guild_id not in bot_guild_ids:
            app.logger.error(f"Bot not present in guild {guild_id}")
            return "<h1>Error</h1><p>Bot must be added to the server before purchasing.</p><a href='/purchase/select_server'>Go Back</a>", 400
        
        # Create checkout session
        checkout_url = create_secure_checkout_session(
            guild_id=int(guild_id),
            product_type=product_type,
            guild_name=authorized_guild.get('name', '')
        )
        
        # Clear purchase intent after successful checkout creation
        session.pop('purchase_intent', None)
        
        app.logger.info(f"Checkout created for guild {guild_id}, product {product_type}, by user {user_session.get('username')}")
        return redirect(checkout_url)
        
    except ValueError as e:
        app.logger.error(f"Checkout error: {str(e)}")
        session.pop('purchase_intent', None)
        return f"<h1>Checkout Error</h1><p>{str(e)}</p><a href='/'>Return Home</a>", 400
    except Exception as e:
        app.logger.error(f"Checkout error: {str(e)}")
        app.logger.error(traceback.format_exc())
        session.pop('purchase_intent', None)
        return "<h1>Error</h1><p>Unable to create checkout session.</p><a href='/'>Return Home</a>", 500

@app.route("/success")
def purchase_success():
    """Purchase success page"""
    # Clear any remaining purchase intent
    session.pop('purchase_intent', None)
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Purchase Successful - On the Clock</title>
        <style>
            body {
                font-family: 'Inter', 'Segoe UI', system-ui, sans-serif;
                background: linear-gradient(135deg, #0A0F1F 0%, #151B2E 50%, #1E2750 100%);
                color: #C9D1D9;
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 2rem;
            }
            .container {
                max-width: 500px;
                text-align: center;
                background: rgba(30, 35, 45, 0.8);
                border: 2px solid #10B981;
                border-radius: 16px;
                padding: 3rem 2rem;
            }
            h1 {
                font-size: 2.5rem;
                color: #10B981;
                margin-bottom: 1rem;
            }
            p {
                font-size: 1.1rem;
                color: #8B949E;
                line-height: 1.6;
                margin-bottom: 2rem;
            }
            a {
                display: inline-block;
                background: linear-gradient(135deg, #D4AF37, #C19A2E);
                color: #0D1117;
                padding: 12px 28px;
                border-radius: 8px;
                font-weight: 600;
                text-decoration: none;
                transition: all 0.3s ease;
            }
            a:hover {
                transform: translateY(-2px);
                box-shadow: 0 6px 30px rgba(212, 175, 55, 0.5);
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Γ£à Purchase Successful!</h1>
            <p>Your payment has been processed. Your server's access has been automatically updated.</p>
            <p>You can now use all premium features in Discord!</p>
            <a href="/">Return to Home</a>
        </div>
    </body>
    </html>
    """

@app.route("/cancel")
def purchase_cancel():
    """Purchase cancelled page"""
    # Clear purchase intent
    session.pop('purchase_intent', None)
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Purchase Cancelled - On the Clock</title>
        <style>
            body {
                font-family: 'Inter', 'Segoe UI', system-ui, sans-serif;
                background: linear-gradient(135deg, #0A0F1F 0%, #151B2E 50%, #1E2750 100%);
                color: #C9D1D9;
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 2rem;
            }
            .container {
                max-width: 500px;
                text-align: center;
                background: rgba(30, 35, 45, 0.8);
                border: 2px solid rgba(239, 68, 68, 0.5);
                border-radius: 16px;
                padding: 3rem 2rem;
            }
            h1 {
                font-size: 2.5rem;
                color: #EF4444;
                margin-bottom: 1rem;
            }
            p {
                font-size: 1.1rem;
                color: #8B949E;
                line-height: 1.6;
                margin-bottom: 2rem;
            }
            a {
                display: inline-block;
                background: linear-gradient(135deg, #D4AF37, #C19A2E);
                color: #0D1117;
                padding: 12px 28px;
                border-radius: 8px;
                font-weight: 600;
                text-decoration: none;
                transition: all 0.3s ease;
                margin: 0.5rem;
            }
            a:hover {
                transform: translateY(-2px);
                box-shadow: 0 6px 30px rgba(212, 175, 55, 0.5);
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Γ¥î Purchase Cancelled</h1>
            <p>Your purchase was cancelled. No charges were made.</p>
            <p>You can try again anytime!</p>
            <a href="/">Return to Home</a>
            <a href="/purchase/bot_access">Try Again</a>
        </div>
    </body>
    </html>
    """

@app.route("/invite")
def invite():
    """Redirect to Discord bot invite link."""
    # Bot invite with essential permissions
    bot_id = "1418446753379913809"
    permissions = "2048"  # Slash commands permission
    invite_url = f"https://discord.com/api/oauth2/authorize?client_id={bot_id}&permissions={permissions}&scope=bot%20applications.commands"
    return f'<script>window.location.href="{invite_url}";</script><a href="{invite_url}">Click here if you are not redirected</a>'

@app.route("/favicon.ico")
def favicon():
    """Return empty favicon to prevent 404 errors."""
    from flask import Response
    return Response('', mimetype='image/x-icon')

@app.route("/api/guild/<guild_id>/employees/active")
@require_paid_api_access
def api_get_active_employees(user_session, guild_id):
    """
    Get active employees and their stats for the dashboard.
    """
    try:
        # Get timezone preference from query param or default
        timezone_name = request.args.get('timezone', 'America/New_York')
        
        employees = get_active_employees_with_stats(int(guild_id), timezone_name)
        
        # Enrich with avatar URLs (optional, if we had them in DB or could fetch from Discord)
        # For now, we'll rely on the frontend to handle avatars or basic placeholders
        # If we wanted real avatars, we'd need to fetch from Discord API or store them
        
        return jsonify({
            'success': True,
            'employees': employees
        })
    except Exception as e:
        app.logger.error(f"Error fetching active employees: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route("/api/guild/<guild_id>/adjustments", methods=["POST"])
@require_paid_api_access
def api_create_adjustment(user_session, guild_id):
    """
    Submit a new time adjustment request.
    """
    try:
        data = request.json
        if not data:
            return jsonify({'success': False, 'error': 'Missing request body'}), 400
            
        request_type = data.get('request_type')
        reason = data.get('reason')
        original_session_id = data.get('original_session_id')
        
        if not request_type or not reason:
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400
            
        # Validate request type
        if request_type not in ['modify_clockin', 'modify_clockout', 'add_session', 'delete_session']:
            return jsonify({'success': False, 'error': 'Invalid request type'}), 400
            
        # Prepare requested data
        requested_data = {
            'clock_in': data.get('requested_clock_in'),
            'clock_out': data.get('requested_clock_out')
        }
        
        request_id = create_adjustment_request(
            guild_id=int(guild_id),
            user_id=int(user_session['user_id']),
            request_type=request_type,
            original_session_id=original_session_id,
            requested_data=requested_data,
            reason=reason
        )
        
        if request_id:
            return jsonify({'success': True, 'request_id': request_id})
        else:
            return jsonify({'success': False, 'error': 'Failed to create request'}), 500
            
    except Exception as e:
        app.logger.error(f"Error creating adjustment: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/api/guild/<guild_id>/adjustments/pending")
@require_paid_api_access
def api_get_pending_adjustments(user_session, guild_id):
    """
    Get pending adjustment requests (Admin only).
    """
    try:
        # Verify admin access (already checked by decorator, but good to be explicit)
        # In a real app, we might want to restrict this further to specific roles
        
        requests = get_pending_adjustments(int(guild_id))
        
        # Convert datetime objects to ISO strings for JSON serialization
        serialized_requests = []
        for req in requests:
            req_dict = dict(req)
            # Handle datetime fields
            for key, value in req_dict.items():
                if isinstance(value, datetime):
                    req_dict[key] = value.isoformat()
            serialized_requests.append(req_dict)
            
        return jsonify({'success': True, 'requests': serialized_requests})
        
    except Exception as e:
        app.logger.error(f"Error fetching adjustments: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/api/guild/<guild_id>/adjustments/<request_id>/approve", methods=["POST"])
@require_paid_api_access
def api_approve_adjustment(user_session, guild_id, request_id):
    """
    Approve an adjustment request.
    """
    try:
        success, message = approve_adjustment(
            request_id=int(request_id),
            guild_id=int(guild_id),
            reviewer_user_id=int(user_session['user_id'])
        )
        
        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'error': message}), 400
            
    except Exception as e:
        app.logger.error(f"Error approving adjustment: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/api/guild/<guild_id>/adjustments/<request_id>/deny", methods=["POST"])
@require_paid_api_access
def api_deny_adjustment(user_session, guild_id, request_id):
    """
    Deny an adjustment request.
    """
    try:
        success, message = deny_adjustment(
            request_id=int(request_id),
            guild_id=int(guild_id),
            reviewer_user_id=int(user_session['user_id'])
        )
        
        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'error': message}), 400
            
    except Exception as e:
        app.logger.error(f"Error denying adjustment: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") != "production"
    
    print(f"🚀 Starting Landing Page Server...")
    print(f"🌍 Environment: {os.environ.get('FLASK_ENV', 'development')}")
    print(f"🔌 Port: {port}")
    print(f"🐛 Debug: {debug}")
    
    # Run Flask app
    app.run(host="0.0.0.0", port=port, debug=debug)
