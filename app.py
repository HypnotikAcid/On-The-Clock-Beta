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
        app.logger.info("🤖 Starting Discord bot in background thread...")
        asyncio.run(run_bot_with_api())
    except Exception as e:
        app.logger.error(f"❌ Error starting Discord bot: {e}")
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
        app.logger.info("✅ Discord bot thread started in worker")

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

# Environment configuration
DATABASE_URL = os.environ.get('DATABASE_URL')
DISCORD_CLIENT_ID = os.environ.get('DISCORD_CLIENT_ID')
DISCORD_CLIENT_SECRET = os.environ.get('DISCORD_CLIENT_SECRET')
DISCORD_API_BASE = 'https://discord.com/api/v10'
STRIPE_SECRET_KEY = os.environ.get('STRIPE_SECRET_KEY')
STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET')

# Database pool initialization
app_db_pool = None

app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

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
    app.logger.info("✅ PostgreSQL connection pool initialized for Flask")

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

def get_user_role_tier(guild_id, user_id):
    """
    Determine the user's role tier in a guild.
    Returns: 'owner', 'admin', 'employee', or 'none'
    """
    try:
        with get_db() as conn:
            # 1. Check if owner (highest tier)
            cursor = conn.execute("SELECT owner_id FROM guilds WHERE guild_id = %s", (str(guild_id),))
            guild_row = cursor.fetchone()
            if guild_row and str(guild_row['owner_id']) == str(user_id):
                return 'owner'
            
            # 2. Check if admin (via session/Discord permissions)
            # We need to check the user's session for this guild's permissions
            # This is a bit complex since we don't have the session object here directly
            # But we can check if they are in the employees table as an admin? 
            # No, employees table doesn't store admin status directly usually.
            # Let's rely on the check_user_admin_realtime for admin status
            
            admin_status = check_user_admin_realtime(user_id, guild_id)
            if admin_status.get('is_admin'):
                return 'admin'
                
            # 3. Check if employee
            cursor = conn.execute(
                "SELECT 1 FROM employees WHERE guild_id = %s AND user_id = %s AND is_active = TRUE", 
                (str(guild_id), str(user_id))
            )
            if cursor.fetchone():
                return 'employee'
                
            return 'none'
    except Exception as e:
        app.logger.error(f"Error checking role tier: {e}")
        return 'none'

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
    print(f"⚠️ Dashboard initialization warning: {e}")

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

def require_server_access(f):
    """
    Decorator to require authentication AND server access (admin OR employee).
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
                return jsonify({'success': False, 'error': 'Missing guild_id'}), 400
            
            # Check bot access status (fresh DB lookup every time)
            access_status = check_guild_paid_access(guild_id)
            
            if not access_status['bot_invited']:
                return jsonify({'success': False, 'error': 'Bot not invited', 'code': 'BOT_NOT_INVITED'}), 403
            
            if not access_status['bot_access_paid']:
                return jsonify({'success': False, 'error': 'Server subscription required', 'code': 'PAYMENT_REQUIRED'}), 403

            # Check role tier
            role_tier = get_user_role_tier(guild_id, user_session['user_id'])
            
            if role_tier == 'none':
                return jsonify({'success': False, 'error': 'Access denied', 'code': 'NO_ACCESS'}), 403
            
            return f(user_session, *args, **kwargs)
            
        except Exception as e:
            app.logger.error(f"Server access check error: {str(e)}")
            app.logger.error(traceback.format_exc())
            return jsonify({'success': False, 'error': 'Access check error', 'code': 'CHECK_ERROR'}), 500
    return decorated_function

@app.route("/api/guild/<guild_id>/adjustments", methods=["POST"])
@require_server_access
def api_create_adjustment(user_session, guild_id):
    try:
        data = request.get_json()
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

def get_user_adjustments(guild_id, user_id):
    """
    Get all adjustment requests for a specific user.
    """
    try:
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT * FROM time_adjustment_requests 
                WHERE guild_id = %s AND user_id = %s
                ORDER BY created_at DESC
            """, (str(guild_id), int(user_id)))
            return cursor.fetchall()
    except Exception as e:
        app.logger.error(f"Error fetching user adjustments: {e}")
        return []

@app.route("/api/guild/<guild_id>/adjustments/history")
@require_server_access
def api_get_user_adjustment_history(user_session, guild_id):
    """
    Get adjustment history for the current user.
    """
    try:
        user_id = user_session['user_id']
        requests = get_user_adjustments(guild_id, user_id)
        
        # Serialize
        serialized_requests = []
        for req in requests:
            req_dict = dict(req)
            for key, value in req_dict.items():
                if isinstance(value, datetime):
                    req_dict[key] = value.isoformat()
            serialized_requests.append(req_dict)
            
        return jsonify({'success': True, 'requests': serialized_requests})
    except Exception as e:
        app.logger.error(f"Error fetching adjustment history: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/api/server/<guild_id>/data", methods=["GET"])
@require_server_access
def api_get_server_data(user_session, guild_id):
    try:
        # Get user role tier
        user_tier = get_user_role_tier(guild_id, user_session['user_id'])
        
        # Get guild data from bot
        guild = bot.get_guild(int(guild_id))
        if not guild:
            return jsonify({'success': False, 'error': 'Guild not found'}), 404
            
        # Get roles
        roles_data = []
        for role in guild.roles:
            roles_data.append({
                'id': str(role.id),
                'name': role.name,
                'color': role.color.value
            })
            
        # Get settings from DB
        with get_db() as conn:
            # Get timezone
            cursor = conn.execute("SELECT setting_value FROM guild_settings WHERE guild_id = %s AND setting_key = 'timezone'", (guild_id,))
            row = cursor.fetchone()
            timezone = row['setting_value'] if row else 'America/New_York'
            
            # Get admin roles
            cursor = conn.execute("SELECT role_id FROM admin_roles WHERE guild_id = %s", (guild_id,))
            admin_roles = [str(row['role_id']) for row in cursor.fetchall()]
            
            # Get employee roles
            cursor = conn.execute("SELECT role_id FROM employee_roles WHERE guild_id = %s", (guild_id,))
            employee_roles = [str(row['role_id']) for row in cursor.fetchall()]
            
            # Get work day end time
            cursor = conn.execute("SELECT setting_value FROM guild_settings WHERE guild_id = %s AND setting_key = 'work_day_end_time'", (guild_id,))
            row = cursor.fetchone()
            work_day_end_time = row['setting_value'] if row else '17:00'
            
            # Get mobile restriction
            cursor = conn.execute("SELECT setting_value FROM guild_settings WHERE guild_id = %s AND setting_key = 'restrict_mobile_clockin'", (guild_id,))
            row = cursor.fetchone()
            restrict_mobile = row['setting_value'] == 'true' if row else False

        current_settings = {
            'timezone': timezone,
            'admin_roles': admin_roles,
            'employee_roles': employee_roles,
            'work_day_end_time': work_day_end_time,
            'restrict_mobile_clockin': restrict_mobile
        }
        
        guild_data = {
            'id': str(guild.id),
            'name': guild.name,
            'icon': str(guild.icon.url) if guild.icon else None,
            'member_count': guild.member_count
        }
        
        return jsonify({
            'success': True,
            'guild': guild_data,
            'roles': roles_data,
            'user_role_tier': user_tier,
            'current_settings': current_settings
        })
        
    except Exception as e:
        app.logger.error(f"Error fetching server data: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") != "production"
    
    print(f"🌐 Starting Landing Page Server...")
    print(f"🔧 Environment: {os.environ.get('FLASK_ENV', 'development')}")
    print(f"🌐 Port: {port}")
    print(f"🐛 Debug: {debug}")
    
    # Run Flask app
    app.run(host="0.0.0.0", port=port, debug=debug)