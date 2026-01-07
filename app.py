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
from urllib.parse import urlencode, urlparse
import requests
import hashlib
import time as time_module
from flask import Flask, render_template, redirect, request, session, jsonify, url_for, make_response
from werkzeug.middleware.proxy_fix import ProxyFix
import stripe
from stripe import SignatureVerificationError

app = Flask(__name__)

# Health check endpoint - responds immediately without waiting for bot
# This MUST be defined early, before any slow initialization
@app.route('/health')
def health_check():
    """Quick health check for deployment - responds before bot is ready."""
    return jsonify({
        'status': 'healthy',
        'service': 'on-the-clock',
        'timestamp': datetime.now(timezone.utc).isoformat()
    }), 200

# Track bot initialization status
bot_status = {
    'initialized': False,
    'error': None,
    'started_at': None
}

# Version and Changelog
__version__ = "1.5.0"

# Customer-facing update notes (latest first, max 3 shown on dashboard)
CHANGELOG = [
    {
        "version": "1.5.0",
        "date": "2025-11-27",
        "title": "Employee Detail View",
        "description": "Click any employee card to view their complete profile with weekly timecard visualization and recent time adjustment requests.",
        "icon": "📊",
        "customer_benefit": "Faster access to employee information without navigating multiple pages"
    },
    {
        "version": "1.4.0",
        "date": "2025-11-26",
        "title": "Time Adjustment Requests",
        "description": "Employees can now request time adjustments for missed clock-ins/outs. Admins can approve or deny requests with one click.",
        "icon": "⏳",
        "customer_benefit": "Simplified time correction process - no more manual data entry"
    },
    {
        "version": "1.3.0",
        "date": "2025-11-25",
        "title": "Role-Based Access Control",
        "description": "Configure custom admin and employee roles. Control who can access admin features and use time tracking.",
        "icon": "👥",
        "customer_benefit": "Better security and delegation - assign managers without giving full admin access"
    }
]

# LAZY IMPORTS: Bot module imports are deferred to allow fast Flask startup
# This enables the /health endpoint to respond immediately before bot is loaded
_bot_module = None
_bot_functions = {}

def _get_bot_module():
    """Lazy import of bot module - only loads when first needed."""
    global _bot_module
    if _bot_module is None:
        print("[LAZY] Loading bot module...")
        import bot as _bot_module
        print("[LAZY] Bot module loaded")
    return _bot_module

def _get_bot_func(name):
    """Get a function from the bot module with lazy loading."""
    if name not in _bot_functions:
        _bot_functions[name] = getattr(_get_bot_module(), name)
    return _bot_functions[name]

# Wrapper functions for lazy bot imports
def check_bot_access(*args, **kwargs):
    return _get_bot_func('check_bot_access')(*args, **kwargs)

def set_bot_access(*args, **kwargs):
    return _get_bot_func('set_bot_access')(*args, **kwargs)

def set_retention_tier(*args, **kwargs):
    return _get_bot_func('set_retention_tier')(*args, **kwargs)

def purge_timeclock_data_only(*args, **kwargs):
    return _get_bot_func('purge_timeclock_data_only')(*args, **kwargs)

def create_secure_checkout_session(*args, **kwargs):
    return _get_bot_func('create_secure_checkout_session')(*args, **kwargs)

def notify_server_owner_bot_access(*args, **kwargs):
    return _get_bot_func('notify_server_owner_bot_access')(*args, **kwargs)

def get_active_employees_with_stats(*args, **kwargs):
    return _get_bot_func('get_active_employees_with_stats')(*args, **kwargs)

def create_adjustment_request(*args, **kwargs):
    return _get_bot_func('create_adjustment_request')(*args, **kwargs)

def get_pending_adjustments(*args, **kwargs):
    return _get_bot_func('get_pending_adjustments')(*args, **kwargs)

def get_user_adjustment_history(*args, **kwargs):
    return _get_bot_func('get_user_adjustment_history')(*args, **kwargs)

def approve_adjustment(*args, **kwargs):
    return _get_bot_func('approve_adjustment')(*args, **kwargs)

def deny_adjustment(*args, **kwargs):
    return _get_bot_func('deny_adjustment')(*args, **kwargs)

def bot_db():
    """Lazy access to bot database context manager - returns the callable that produces the context manager."""
    return _get_bot_func('db')()

# Flask-side database functions that use get_db() for production compatibility
# These are used by webhook handlers and dashboard to write to the correct database
def flask_check_bot_access(guild_id: int) -> bool:
    """Check if a server has paid for bot access using Flask's database connection."""
    with get_db() as conn:
        cursor = conn.execute(
            "SELECT bot_access_paid FROM server_subscriptions WHERE guild_id = %s",
            (guild_id,)
        )
        result = cursor.fetchone()
        if not result:
            return False
        return bool(result['bot_access_paid'])

def flask_set_bot_access(guild_id: int, paid: bool, source: str = 'stripe'):
    """Update bot_access_paid status using Flask's database connection.
    
    Args:
        guild_id: The Discord guild ID
        paid: Whether bot access is paid
        source: The source of the grant ('stripe' for payments, 'granted' for manual)
    """
    with get_db() as conn:
        conn.execute("""
            INSERT INTO server_subscriptions (guild_id, bot_access_paid, status, grant_source)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT(guild_id) DO UPDATE SET 
                bot_access_paid = %s,
                status = EXCLUDED.status,
                grant_source = EXCLUDED.grant_source
        """, (guild_id, paid, 'active' if paid else 'free', source if paid else None, paid))

def flask_set_retention_tier(guild_id: int, tier: str, source: str = 'stripe'):
    """Update retention tier using Flask's database connection.
    
    Args:
        guild_id: The Discord guild ID
        tier: The retention tier ('none', '7day', '30day')
        source: The source of the grant ('stripe' for payments, 'granted' for manual)
    """
    valid_tiers = ('none', '7day', '30day')
    if tier not in valid_tiers:
        raise ValueError(f"Invalid retention tier: {tier}. Must be one of {valid_tiers}")
    
    with get_db() as conn:
        conn.execute("""
            INSERT INTO server_subscriptions (guild_id, retention_tier, grant_source)
            VALUES (%s, %s, %s)
            ON CONFLICT(guild_id) DO UPDATE SET 
                retention_tier = %s,
                grant_source = COALESCE(server_subscriptions.grant_source, %s)
        """, (guild_id, tier, source if tier != 'none' else None, tier, source if tier != 'none' else None))

# Lazy access to Discord bot instance - use get_bot() for property access
def get_bot():
    """Lazy access to Discord bot instance."""
    return _get_bot_module().bot

# Create a bot proxy that lazily loads the real bot
class _BotProxy:
    """Proxy object that lazily loads the bot module's bot instance."""
    def __getattr__(self, name):
        return getattr(_get_bot_module().bot, name)
    
    def __bool__(self):
        try:
            return bool(_get_bot_module().bot)
        except:
            return False

bot = _BotProxy()

# These modules are lightweight and can be imported at startup
# Import and run database migrations on startup (deferred to Gunicorn init)
# from migrations import run_migrations  # Moved to Gunicorn init block

# Import entitlements system for consistent access checking
from entitlements import Entitlements, UserTier, UserRole

# Start Discord bot in background daemon thread
def start_discord_bot():
    """Start the Discord bot in a background daemon thread with robust error handling."""
    global bot_status
    bot_status['started_at'] = datetime.now(timezone.utc).isoformat()
    
    try:
        import asyncio
        print("[STARTUP] Discord bot thread starting...")
        print("[STARTUP] Importing bot module...")
        from bot import run_bot_with_api
        print("[STARTUP] Bot module imported successfully")
        print("[STARTUP] Starting Discord bot event loop...")
        bot_status['initialized'] = True
        asyncio.run(run_bot_with_api())
    except ImportError as e:
        error_msg = f"Failed to import bot module: {e}"
        print(f"[ERROR] {error_msg}")
        bot_status['error'] = error_msg
        import traceback
        traceback.print_exc()
    except Exception as e:
        error_msg = f"Discord bot error: {e}"
        print(f"[ERROR] {error_msg}")
        bot_status['error'] = error_msg
        import traceback
        traceback.print_exc()
        # Don't re-raise - let Flask continue serving even if bot fails

# Start bot thread when running under Gunicorn (only in first worker)
if __name__ != '__main__':
    import os
    print("[STARTUP] Flask app initializing under Gunicorn...")
    print(f"[STARTUP] Health check endpoint ready at /health")
    
    worker_id = os.environ.get('GUNICORN_WORKER_ID', '1')
    # Only start bot in first worker to avoid multiple instances
    if worker_id == '1' or 'GUNICORN_WORKER_ID' not in os.environ:
        print("[STARTUP] Running database migrations...")
        try:
            from migrations import run_migrations
            run_migrations()
            print("[STARTUP] Database migrations complete")
        except Exception as e:
            print(f"[WARNING] Migration error (non-fatal): {e}")
        
        print("[STARTUP] Starting Discord bot thread (non-blocking)...")
        bot_thread = threading.Thread(target=start_discord_bot, daemon=True)
        bot_thread.start()
        print("[STARTUP] Discord bot thread started - Flask ready to serve requests")

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
DISCORD_CLIENT_ID = os.getenv('DISCORD_CLIENT_ID', '1418446753379913809')
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

# Bot API Configuration
BOT_API_BASE_URL = os.getenv('BOT_API_BASE_URL', 'http://localhost:8081')

def validate_bot_api_url(url):
    """
    Validate that a URL is safe for server-side requests (SSRF prevention).
    Returns True if valid, False otherwise.
    """
    try:
        parsed = urlparse(url)
        
        # Ensure scheme is http or https
        if parsed.scheme not in ('http', 'https'):
            return False
        
        # Ensure hostname exists
        if not parsed.hostname:
            return False
        
        # In production, block requests to localhost/private IPs
        # Allow localhost only in development
        hostname = parsed.hostname.lower()
        is_local = hostname in ('localhost', '127.0.0.1', '0.0.0.0', '::1')
        
        # Block private IP ranges in production
        if os.environ.get('FLASK_ENV') == 'production' and is_local:
            return False
        
        # Additional check: URL must start with the configured base
        # (protects against path traversal in base URL)
        if not url.startswith(BOT_API_BASE_URL):
            return False
            
        return True
    except Exception:
        return False

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
    app.logger.info("[OK] PostgreSQL connection pool initialized for Flask")

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
        
        # Purchase history table for tracking all purchases
        conn.execute("""
            CREATE TABLE IF NOT EXISTS purchase_history (
                id SERIAL PRIMARY KEY NOT NULL,
                guild_id BIGINT NOT NULL,
                guild_name VARCHAR(255),
                customer_email VARCHAR(255),
                customer_id VARCHAR(255),
                product_type VARCHAR(50) NOT NULL,
                amount_cents INTEGER,
                currency VARCHAR(10) DEFAULT 'usd',
                stripe_session_id VARCHAR(255),
                purchased_at TIMESTAMP DEFAULT NOW()
            )
        """)
        
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
    print(f"[WARN] Dashboard initialization warning: {e}")

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
            # Use string for comparison if the DB stores it that way, or ensure types match
            cursor = conn.execute(
                "SELECT bot_access_paid, status FROM server_subscriptions WHERE CAST(guild_id AS TEXT) = %s",
                (str(guild_id),)
            )
            result = cursor.fetchone()
            
            # A server is considered paid if bot_access_paid is True OR status is 'active'
            bot_access_paid = False
            if result:
                is_paid_flag = bool(result.get('bot_access_paid'))
                is_active_status = result.get('status') == 'active'
                bot_access_paid = is_paid_flag or is_active_status
            
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
        url = f'{BOT_API_BASE_URL}/api/guild/{guild_id}/user/{user_id}/check-admin'
        
        # Validate URL to prevent SSRF
        if not validate_bot_api_url(url):
            app.logger.error(f"SSRF protection: Invalid bot API URL rejected")
            return {'is_member': False, 'is_admin': False, 'reason': 'invalid_url'}
        
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
    """Get list of guild IDs where the bot is currently present (as strings for OAuth comparison)"""
    try:
        with get_db() as conn:
            cursor = conn.execute("SELECT guild_id FROM bot_guilds WHERE is_present = TRUE OR is_present IS NULL")
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
        
        # Add subscription info, bot presence, and access level to guild
        guild['bot_access_paid'] = has_paid_access
        guild['retention_tier'] = sub_info['retention_tier']
        guild['bot_is_present'] = bot_is_present
        guild['access_level'] = 'admin'
        
        # Guild passes filters
        filtered_guilds.append(guild)
    
    return filtered_guilds

def get_employee_guilds(user_id):
    """
    Get guilds where user has an active employee profile.
    Cross-references with bot_guilds to ensure bot is present.
    Returns list of guilds with format matching OAuth guild structure.
    """
    employee_guilds = []
    
    try:
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT 
                    ep.guild_id,
                    bg.guild_name,
                    COALESCE(ss.bot_access_paid, FALSE) as bot_access_paid,
                    COALESCE(ss.retention_tier, 'none') as retention_tier
                FROM employee_profiles ep
                JOIN bot_guilds bg ON bg.guild_id = CAST(ep.guild_id AS TEXT)
                LEFT JOIN server_subscriptions ss ON ss.guild_id = ep.guild_id
                WHERE ep.user_id = %s AND ep.is_active = TRUE
                AND (bg.is_present = TRUE OR bg.is_present IS NULL)
            """, (int(user_id),))
            
            for row in cursor.fetchall():
                employee_guilds.append({
                    'id': str(row['guild_id']),
                    'name': row['guild_name'],
                    'icon': None,
                    'access_level': 'employee',
                    'bot_access_paid': bool(row['bot_access_paid']),
                    'retention_tier': row['retention_tier'] or 'none',
                    'bot_is_present': True
                })
    except Exception as e:
        app.logger.error(f"Error fetching employee guilds for user {user_id}: {e}")
        app.logger.error(traceback.format_exc())
    
    return employee_guilds

def get_all_user_guilds(user_session):
    """
    Get all guilds where user has access (admin or employee).
    Deduplicates: if user is admin on a guild, don't include it as employee-only.
    
    Returns dict with:
    - 'admin_guilds': guilds where user has admin access
    - 'employee_guilds': guilds where user is employee-only (not admin)
    """
    user_id = user_session.get('user_id')
    
    admin_guilds = filter_user_guilds(user_session)
    admin_guild_ids = set(g['id'] for g in admin_guilds)
    
    all_employee_guilds = get_employee_guilds(user_id)
    employee_only_guilds = [
        g for g in all_employee_guilds 
        if g['id'] not in admin_guild_ids
    ]
    
    return {
        'admin_guilds': admin_guilds,
        'employee_guilds': employee_only_guilds
    }

# Routes

def log_purchase_and_notify(guild_id, guild_name, customer_email, customer_id, product_type, amount_cents, stripe_session_id):
    """Log purchase to history table and send email notification to owner"""
    try:
        # Log to purchase_history table (using Flask's get_db for production)
        with get_db() as conn:
            conn.execute("""
                INSERT INTO purchase_history 
                (guild_id, guild_name, customer_email, customer_id, product_type, amount_cents, stripe_session_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (guild_id, guild_name, customer_email, customer_id, product_type, amount_cents, stripe_session_id))
        
        app.logger.info(f"[OK] Purchase logged: {product_type} for guild {guild_id}")
        
        # Send email notification to owner
        owner_email = os.getenv('OWNER_EMAIL')
        if owner_email:
            from email_utils import send_email
            import asyncio
            
            product_display = {
                'bot_access': 'Bot Access ($5)',
                'retention_7day': '7-Day Retention ($5/mo)',
                'retention_30day': '30-Day Retention ($5/mo)'
            }.get(product_type, product_type)
            
            amount_display = f"${amount_cents / 100:.2f}" if amount_cents else "N/A"
            
            subject = f"New Purchase: {product_display}"
            text_content = f"""
New Purchase Notification

Product: {product_display}
Amount: {amount_display}

Server Details:
- Guild ID: {guild_id}
- Guild Name: {guild_name}

Customer Details:
- Email: {customer_email or 'N/A'}
- Stripe Customer ID: {customer_id or 'N/A'}

Stripe Session: {stripe_session_id}

This purchase has been automatically processed and the customer should now have access.

---
On the Clock Bot - Purchase Notification
"""
            
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            
            loop.run_until_complete(send_email(
                to=[owner_email],
                subject=subject,
                text=text_content
            ))
            app.logger.info(f"[OK] Purchase notification email sent to owner for guild {guild_id}")
        else:
            app.logger.warning("[WARN] OWNER_EMAIL not configured - skipping purchase notification")
            
    except Exception as e:
        app.logger.error(f"[ERROR] Failed to log purchase or send notification: {e}")
        app.logger.error(traceback.format_exc())

@app.route("/webhook", methods=["POST"])
def stripe_webhook():
    """Handle Stripe webhook events"""
    payload = request.data
    sig_header = request.headers.get('stripe-signature')
    
    if not STRIPE_WEBHOOK_SECRET:
        app.logger.error("[ERROR] STRIPE_WEBHOOK_SECRET not configured")
        return jsonify({'error': 'Webhook secret not configured'}), 400
    
    if not sig_header:
        app.logger.error("[ERROR] Missing Stripe signature header")
        return jsonify({'error': 'Missing signature'}), 400
    
    try:
        # Verify webhook signature
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
        
        event_type = event.get('type')
        app.logger.info(f"≡ƒoo Processing Stripe webhook: {event_type}")
        
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
            app.logger.info(f"[INFO] Unhandled Stripe event type: {event_type}")
        
        return jsonify({'received': True}), 200
        
    except SignatureVerificationError as e:
        app.logger.error(f"[ERROR] Invalid webhook signature: {e}")
        return jsonify({'error': 'Invalid signature'}), 400
    except ValueError as e:
        app.logger.error(f"[ERROR] Invalid webhook payload: {e}")
        return jsonify({'error': 'Invalid payload'}), 400
    except Exception as e:
        app.logger.error(f"[ERROR] Error processing webhook: {e}")
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
        amount_cents = None
        if full_session.line_items and full_session.line_items.data:
            line_item = full_session.line_items.data[0]
            if line_item.price:
                price_id = line_item.price.id
            amount_cents = line_item.amount_total if hasattr(line_item, 'amount_total') else None
        
        if not price_id:
            app.logger.error("[ERROR] No price ID found in checkout session")
            return
        
        # Match price_id against STRIPE_PRICE_IDS to determine product_type
        product_type = None
        for ptype, pid in STRIPE_PRICE_IDS.items():
            if pid == price_id:
                product_type = ptype
                break
        
        if not product_type:
            app.logger.error(f"[ERROR] Unknown price ID in checkout: {price_id}")
            return
        
        guild_id = session.get('metadata', {}).get('guild_id')
        guild_name = session.get('metadata', {}).get('guild_name', 'Unknown Server')
        
        if not guild_id:
            app.logger.error("[ERROR] No guild_id found in session metadata")
            return
        
        guild_id = int(guild_id)
        
        # Extract customer details
        customer_email = None
        customer_id = session.get('customer')
        if full_session.customer_details:
            customer_email = full_session.customer_details.get('email')
        
        # Log purchase to history and send owner notification
        log_purchase_and_notify(
            guild_id=guild_id,
            guild_name=guild_name,
            customer_email=customer_email,
            customer_id=customer_id,
            product_type=product_type,
            amount_cents=amount_cents,
            stripe_session_id=session['id']
        )
        
        # Process based on product type (using Flask-side functions for production DB)
        if product_type == 'bot_access':
            # One-time bot access payment
            flask_set_bot_access(guild_id, True)
            app.logger.info(f"[OK] Bot access granted for server {guild_id}")
            
        elif product_type == 'retention_7day':
            # 7-day retention subscription
            if not flask_check_bot_access(guild_id):
                app.logger.error(f"[ERROR] SECURITY: Retention purchase blocked - bot access not paid for server {guild_id}")
                return
            
            subscription_id = session.get('subscription')
            customer_id = session.get('customer')
            flask_set_retention_tier(guild_id, '7day')
            
            # Store subscription_id and customer_id in database (using Flask's get_db)
            with get_db() as conn:
                conn.execute("""
                    INSERT INTO server_subscriptions (guild_id, subscription_id, customer_id, status)
                    VALUES (%s, %s, %s, 'active')
                    ON CONFLICT(guild_id) DO UPDATE SET 
                        subscription_id = %s,
                        customer_id = %s,
                        status = 'active'
                """, (guild_id, subscription_id, customer_id, subscription_id, customer_id))
            
            app.logger.info(f"[OK] 7-day retention granted for server {guild_id}")
            
        elif product_type == 'retention_30day':
            # 30-day retention subscription
            if not flask_check_bot_access(guild_id):
                app.logger.error(f"[ERROR] SECURITY: Retention purchase blocked - bot access not paid for server {guild_id}")
                return
            
            subscription_id = session.get('subscription')
            customer_id = session.get('customer')
            flask_set_retention_tier(guild_id, '30day')
            
            # Store subscription_id and customer_id in database (using Flask's get_db)
            with get_db() as conn:
                conn.execute("""
                    INSERT INTO server_subscriptions (guild_id, subscription_id, customer_id, status)
                    VALUES (%s, %s, %s, 'active')
                    ON CONFLICT(guild_id) DO UPDATE SET 
                        subscription_id = %s,
                        customer_id = %s,
                        status = 'active'
                """, (guild_id, subscription_id, customer_id, subscription_id, customer_id))
            
            app.logger.info(f"[OK] 30-day retention granted for server {guild_id}")
            
    except Exception as e:
        app.logger.error(f"[ERROR] Error processing checkout session: {e}")
        app.logger.error(traceback.format_exc())

def handle_subscription_change(subscription):
    """Handle subscription change events"""
    try:
        subscription_id = subscription.get('id')
        status = subscription.get('status')
        
        if not subscription_id:
            app.logger.error("[ERROR] No subscription ID in subscription change event")
            return
        
        # Using Flask's get_db for production database
        with get_db() as conn:
            conn.execute("""
                UPDATE server_subscriptions 
                SET status = %s
                WHERE subscription_id = %s
            """, (status, subscription_id))
        
        app.logger.info(f"[OK] Subscription {subscription_id} status updated to {status}")
        
    except Exception as e:
        app.logger.error(f"[ERROR] Error processing subscription change: {e}")
        app.logger.error(traceback.format_exc())

def handle_subscription_cancellation(subscription):
    """Handle subscription cancellation events"""
    try:
        subscription_id = subscription.get('id')
        customer_id = subscription.get('customer')
        
        if not subscription_id:
            app.logger.error("[ERROR] No subscription ID in cancellation event")
            return
        
        # Using Flask's get_db for production database
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT guild_id FROM server_subscriptions 
                WHERE subscription_id = %s OR customer_id = %s
            """, (subscription_id, customer_id))
            result = cursor.fetchone()
            
            if result:
                guild_id = result['guild_id']
                
                # Set retention tier to 'none' using Flask-side function
                flask_set_retention_tier(guild_id, 'none')
                
                # Update subscription status to canceled
                conn.execute("""
                    UPDATE server_subscriptions 
                    SET status = 'canceled', subscription_id = NULL
                    WHERE guild_id = %s
                """, (guild_id,))
                
                # Trigger immediate data deletion (this still uses bot function)
                purge_timeclock_data_only(guild_id)
                
                app.logger.info(f"[OK] Retention subscription canceled for server {guild_id}")
            else:
                app.logger.error(f"[ERROR] No guild found for subscription {subscription_id}")
                
    except Exception as e:
        app.logger.error(f"[ERROR] Error processing subscription cancellation: {e}")
        app.logger.error(traceback.format_exc())

def handle_payment_failure(invoice):
    """Handle payment failure events"""
    try:
        customer_id = invoice.get('customer')
        subscription_id = invoice.get('subscription')
        
        if not customer_id and not subscription_id:
            app.logger.error("[ERROR] No customer or subscription ID in payment failure event")
            return
        
        # Using Flask's get_db for production database
        with get_db() as conn:
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
                
                app.logger.info(f"[WARN] Payment failed: Guild {guild_id} marked as past_due")
            else:
                app.logger.error(f"[ERROR] No guild found for customer {customer_id}")
                
    except Exception as e:
        app.logger.error(f"[ERROR] Error processing payment failure: {e}")
        app.logger.error(traceback.format_exc())

@app.route('/deeplink/<page>')
def handle_deeplink(page):
    """Handle signed deep-links from Discord buttons"""
    guild_id = request.args.get('guild')
    user_id = request.args.get('user')
    timestamp = request.args.get('t')
    signature = request.args.get('sig')
    
    # Verify signature
    secret = os.environ.get('SESSION_SECRET', 'fallback-secret')
    data = f"{guild_id}:{user_id}:{page}:{timestamp}"
    expected_sig = hashlib.sha256(f"{data}:{secret}".encode()).hexdigest()[:16]
    
    if signature != expected_sig:
        return redirect('/auth/login?error=invalid_link')
    
    # Check timestamp (valid for 24 hours)
    try:
        if not timestamp or int(time_module.time()) - int(timestamp) > 86400:
            return redirect(url_for('auth_login', error='link_expired'))
    except (ValueError, TypeError):
        return redirect(url_for('auth_login', error='invalid_link'))
    
    # Store intent in session and redirect to auth
    session['deeplink_guild'] = guild_id
    session['deeplink_page'] = page
    
    # Redirect to appropriate dashboard page (using url_for for proper URL encoding)
    if page == 'adjustments':
        return redirect(url_for('dashboard', guild=guild_id, tab='adjustments'))
    elif page == 'profile':
        return redirect(url_for('dashboard', guild=guild_id, tab='employees', user=user_id))
    else:
        return redirect(url_for('dashboard', guild=guild_id))


@app.route("/")
def index():
    """Landing page with bot info, features, and upgrade links."""
    return render_template('landing.html')

@app.route("/dashboard/invite")
def dashboard_invite():
    """Page shown when user tries to access dashboard but bot is not invited to their server."""
    discord_client_id = os.getenv("DISCORD_CLIENT_ID", "1418446753379913809")
    invite_url = f"https://discord.com/oauth2/authorize?client_id={discord_client_id}&permissions=8&scope=bot%20applications.commands"
    return render_template('dashboard_invite.html', invite_url=invite_url)

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
    """Protected dashboard showing user info and guilds where user has admin or employee access"""
    try:
        app.logger.info(f"Dashboard accessed by user: {user_session.get('username')}")
        
        # Get all guilds where user has access (admin or employee)
        all_guilds = get_all_user_guilds(user_session)
        admin_guilds = all_guilds['admin_guilds']
        employee_guilds = all_guilds['employee_guilds']
        
        # Create a modified user session with both admin and employee guilds
        dashboard_data = {
            **user_session,
            'guilds': admin_guilds,  # Maintain backward compatibility
            'admin_guilds': admin_guilds,
            'employee_guilds': employee_guilds,
            'total_guilds': len(user_session.get('guilds', [])),
            'filtered_count': len(admin_guilds) + len(employee_guilds)
        }
        
        app.logger.info(f"Showing {len(admin_guilds)} admin guilds and {len(employee_guilds)} employee-only guilds")
        return render_template('dashboard.html', 
                             user=dashboard_data, 
                             version=__version__, 
                             recent_updates=CHANGELOG[:3])  # Top 3 most recent updates
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
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        
        # Security check: Only allow bot owner
        if user_session['user_id'] != bot_owner_id:
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
            # Get all servers from bot_guilds (including archived paid servers where bot left)
            # Also fetch email recipients for bundling with server info
            cursor = conn.execute("""
                SELECT 
                    CAST(bg.guild_id AS BIGINT) as guild_id,
                    bg.guild_name,
                    COALESCE(ss.bot_access_paid, FALSE) as bot_access_paid,
                    COALESCE(ss.retention_tier, 'none') as retention_tier,
                    COALESCE(ss.status, 'free') as status,
                    ss.subscription_id,
                    ss.customer_id,
                    COALESCE(ss.manually_granted, FALSE) as manually_granted,
                    ss.granted_by,
                    ss.granted_at,
                    ss.grant_source,
                    COUNT(DISTINCT s.id) as active_sessions,
                    COALESCE(bg.is_present, TRUE) as bot_is_present,
                    bg.left_at
                FROM bot_guilds bg
                LEFT JOIN server_subscriptions ss ON ss.guild_id = CAST(bg.guild_id AS BIGINT)
                LEFT JOIN sessions s ON CAST(bg.guild_id AS BIGINT) = s.guild_id AND s.clock_out IS NULL
                GROUP BY bg.guild_id, bg.guild_name, ss.bot_access_paid, ss.retention_tier, ss.status, ss.subscription_id, ss.customer_id, ss.manually_granted, ss.granted_by, ss.granted_at, ss.grant_source, bg.is_present, bg.left_at
                ORDER BY COALESCE(bg.is_present, TRUE) DESC, guild_name
            """)
            servers = []
            for row in cursor.fetchall():
                guild_id = row['guild_id']
                guild_name = row['guild_name']
                bot_is_present = bool(row['bot_is_present'])
                left_at = row.get('left_at')
                
                # Use grant_source column directly (stripe, granted, or None)
                grant_source = row.get('grant_source')
                
                servers.append({
                    'guild_id': guild_id,
                    'guild_name': guild_name or f'Unknown Server (ID: {guild_id})',
                    'bot_access': bool(row['bot_access_paid']),
                    'retention_tier': row['retention_tier'] if row['retention_tier'] != 'none' else None,
                    'status': row['status'],
                    'subscription_id': row['subscription_id'],
                    'customer_id': row['customer_id'],
                    'manually_granted': bool(row['manually_granted']),
                    'granted_by': row['granted_by'],
                    'granted_at': row['granted_at'].isoformat() if row.get('granted_at') else None,
                    'grant_source': grant_source,
                    'active_sessions': row['active_sessions'],
                    'bot_is_present': bot_is_present,
                    'left_at': left_at.isoformat() if left_at else None,
                    'email_recipients': [],  # Will be populated below
                    'webhook_events': []  # Will be populated below
                })
            
            # Get email recipients per guild
            cursor = conn.execute("""
                SELECT guild_id, email 
                FROM email_recipients 
                ORDER BY guild_id
            """)
            email_recipients_by_guild = {}
            for row in cursor.fetchall():
                gid = row['guild_id']
                if gid not in email_recipients_by_guild:
                    email_recipients_by_guild[gid] = []
                email_recipients_by_guild[gid].append(row['email'])
            
            # Get webhook events per guild (last 10 per guild)
            cursor = conn.execute("""
                SELECT we.guild_id, we.event_type, we.status, we.timestamp, we.details
                FROM webhook_events we
                ORDER BY we.guild_id, we.timestamp DESC
            """)
            webhooks_by_guild = {}
            for row in cursor.fetchall():
                gid = str(row['guild_id'])
                if gid not in webhooks_by_guild:
                    webhooks_by_guild[gid] = []
                if len(webhooks_by_guild[gid]) < 10:  # Limit to 10 per guild
                    details = {}
                    if row['details']:
                        try:
                            details = json.loads(row['details'])
                        except:
                            details = {}
                    webhooks_by_guild[gid].append({
                        'event_type': row['event_type'],
                        'status': row['status'],
                        'timestamp': row['timestamp'],
                        'details': details
                    })
            
            # Attach email recipients and webhooks to each server
            for server in servers:
                gid = str(server['guild_id'])
                server['email_recipients'] = email_recipients_by_guild.get(int(gid), [])
                server['webhook_events'] = webhooks_by_guild.get(gid, [])
            
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
                    SUM(CASE WHEN ss.status = 'past_due' THEN 1 ELSE 0 END) as past_due_count,
                    SUM(CASE WHEN COALESCE(bg.is_present, TRUE) = TRUE THEN 1 ELSE 0 END) as active_servers,
                    SUM(CASE WHEN COALESCE(bg.is_present, TRUE) = FALSE THEN 1 ELSE 0 END) as inactive_servers,
                    SUM(CASE WHEN COALESCE(bg.is_present, TRUE) = FALSE AND COALESCE(ss.bot_access_paid, FALSE) = FALSE THEN 1 ELSE 0 END) as departed_unpaid_servers
                FROM bot_guilds bg
                LEFT JOIN server_subscriptions ss ON ss.guild_id = CAST(bg.guild_id AS BIGINT)
            """)
            stats_row = cursor.fetchone()
            stats = {
                'total_servers': stats_row['total_servers'],
                'paid_servers': stats_row['paid_servers'],
                'retention_7day_count': stats_row['retention_7day_count'],
                'retention_30day_count': stats_row['retention_30day_count'],
                'past_due_count': stats_row['past_due_count'],
                'active_servers': stats_row['active_servers'],
                'inactive_servers': stats_row['inactive_servers'],
                'departed_unpaid_servers': stats_row['departed_unpaid_servers'] or 0
            }
            
            # Get total active sessions across all servers
            cursor = conn.execute("""
                SELECT COUNT(*) as total_active_sessions
                FROM sessions 
                WHERE clock_out IS NULL
            """)
            stats['total_active_sessions'] = cursor.fetchone()['total_active_sessions']
            
            # Get purchase history (last 100 purchases)
            cursor = conn.execute("""
                SELECT 
                    id,
                    guild_id,
                    guild_name,
                    customer_email,
                    product_type,
                    amount_cents,
                    purchased_at
                FROM purchase_history
                ORDER BY purchased_at DESC
                LIMIT 100
            """)
            purchase_history = []
            for row in cursor.fetchall():
                purchase_history.append({
                    'id': row['id'],
                    'guild_id': row['guild_id'],
                    'guild_name': row['guild_name'] or 'Unknown',
                    'customer_email': row['customer_email'] or 'N/A',
                    'product_type': row['product_type'],
                    'amount_cents': row['amount_cents'],
                    'purchased_at': row['purchased_at']
                })
        
        return render_template('owner_dashboard.html', 
                             user=user_session,
                             servers=servers,
                             webhook_events=webhook_events,
                             purchase_history=purchase_history,
                             stats=stats)
    
    except Exception as e:
        app.logger.error(f"Owner dashboard error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return "<h1>Error</h1><p>Unable to load owner dashboard. Please try again later.</p><a href='/dashboard'>Return to Dashboard</a>", 500

@app.route("/api/owner/manual-grant", methods=["POST"])
@require_api_auth
def api_owner_manual_grant(user_session):
    """Owner-only API endpoint to manually grant access with specific source attribution"""
    try:
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        if user_session['user_id'] != bot_owner_id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
            
        data = request.get_json()
        guild_id = data.get('guild_id')
        source = data.get('source', 'owner') # 'stripe' or 'owner'
        
        if not guild_id or not guild_id.isdigit():
            return jsonify({'success': False, 'error': 'Invalid guild_id'}), 400
            
        db_source = 'Stripe' if source == 'stripe' else 'Granted'
        
        with get_db() as conn:
            conn.execute("""
                INSERT INTO server_subscriptions (guild_id, tier, bot_access_paid, retention_tier, status, manually_granted, granted_by, granted_at, grant_source)
                VALUES (%s, 'premium', TRUE, '30day', 'active', TRUE, %s, NOW(), %s)
                ON CONFLICT (guild_id) DO UPDATE SET
                    tier = 'premium',
                    bot_access_paid = TRUE,
                    retention_tier = '30day',
                    status = 'active',
                    manually_granted = TRUE,
                    granted_by = %s,
                    granted_at = NOW(),
                    grant_source = %s
            """, (int(guild_id), user_session['user_id'], db_source, user_session['user_id'], db_source))
            
        app.logger.info(f"Owner {user_session.get('username')} manually granted access to {guild_id} as {db_source}")
        return jsonify({'success': True, 'message': f'Premium access granted to {guild_id} (Source: {db_source})'})
        
    except Exception as e:
        app.logger.error(f"Manual grant error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/debug")
@require_auth
def debug_console(user_session):
    """Owner-only debug console for security testing"""
    try:
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        
        if user_session['user_id'] != bot_owner_id:
            app.logger.warning(f"Unauthorized debug console access attempt by user {user_session['user_id']}")
            return "<h1>403 Forbidden</h1><p>You do not have permission to access this page.</p><a href='/dashboard'>Return to Dashboard</a>", 403
        
        app.logger.info(f"Debug console accessed by owner {user_session.get('username')}")
        return render_template('debug.html', user=user_session)
    
    except Exception as e:
        app.logger.error(f"Debug console error: {str(e)}")
        return "<h1>Error</h1><p>Unable to load debug console.</p><a href='/dashboard'>Return to Dashboard</a>", 500

@app.route("/debug/run-test", methods=["POST"])
@require_api_auth
def debug_run_test(user_session):
    """Owner-only API endpoint to run security tests"""
    try:
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        
        if user_session['user_id'] != bot_owner_id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        data = request.get_json()
        test_type = data.get('test_type')
        guild_id = data.get('guild_id', '')
        role_id = data.get('role_id', '')
        
        app.logger.info(f"Debug test '{test_type}' initiated by owner")
        
        if test_type == 'valid_guild':
            if not guild_id or not guild_id.isdigit():
                return jsonify({
                    'success': False,
                    'message': 'Please enter a valid numeric guild ID first',
                    'details': 'Guild ID must be a numeric Discord snowflake ID'
                })
            
            result = _test_guild_id_validation(guild_id, role_id, user_session)
            return jsonify(result)
        
        elif test_type == 'path_traversal':
            malicious_id = f"{guild_id}/../admin" if guild_id else "123/../admin"
            result = _test_guild_id_validation(malicious_id, role_id, user_session, expect_block=True)
            return jsonify(result)
        
        elif test_type == 'encoded_traversal':
            malicious_id = f"{guild_id}%2F..%2Fadmin" if guild_id else "123%2F..%2Fadmin"
            result = _test_guild_id_validation(malicious_id, role_id, user_session, expect_block=True)
            return jsonify(result)
        
        elif test_type == 'special_chars':
            malicious_id = f"{guild_id}@evil.com#fragment" if guild_id else "123@evil.com#fragment"
            result = _test_guild_id_validation(malicious_id, role_id, user_session, expect_block=True)
            return jsonify(result)
        
        elif test_type == 'empty_guild':
            result = _test_guild_id_validation('', role_id, user_session, expect_block=True)
            return jsonify(result)
        
        elif test_type == 'non_numeric':
            result = _test_guild_id_validation('abcdefgh', role_id, user_session, expect_block=True)
            return jsonify(result)
        
        elif test_type == 'bot_api_health':
            try:
                bot_api_secret = os.getenv('BOT_API_SECRET')
                if not bot_api_secret:
                    return jsonify({
                        'success': False,
                        'message': 'BOT_API_SECRET not configured',
                        'details': 'The bot API secret is not set in environment variables'
                    })
                
                response = requests.get(
                    'http://localhost:8081/health',
                    headers={'Authorization': f'Bearer {bot_api_secret}'},
                    timeout=5
                )
                
                if response.ok:
                    return jsonify({
                        'success': True,
                        'message': 'Bot API is healthy and responding',
                        'details': f'Status: {response.status_code}, Response: {response.text[:200]}'
                    })
                else:
                    return jsonify({
                        'success': False,
                        'message': f'Bot API returned status {response.status_code}',
                        'details': response.text[:500]
                    })
            except requests.exceptions.ConnectionError:
                return jsonify({
                    'success': False,
                    'message': 'Cannot connect to Bot API at localhost:8081',
                    'details': 'The bot API server may not be running'
                })
            except Exception as e:
                return jsonify({
                    'success': False,
                    'message': f'Bot API health check failed: {str(e)}',
                    'details': traceback.format_exc()
                })
        
        elif test_type == 'db_connection':
            try:
                with get_db() as conn:
                    cursor = conn.execute("SELECT COUNT(*) as count FROM server_subscriptions")
                    row = cursor.fetchone()
                    return jsonify({
                        'success': True,
                        'message': 'Database connection successful',
                        'details': f'Query executed successfully. Server subscriptions count: {row["count"]}'
                    })
            except Exception as e:
                return jsonify({
                    'success': False,
                    'message': f'Database connection failed: {str(e)}',
                    'details': traceback.format_exc()
                })
        
        elif test_type == 'session_check':
            return jsonify({
                'success': True,
                'message': 'Session is valid and authenticated',
                'details': {
                    'user_id': user_session.get('user_id'),
                    'username': user_session.get('username'),
                    'is_owner': user_session['user_id'] == bot_owner_id,
                    'guilds_count': len(user_session.get('guilds', []))
                }
            })
        
        elif test_type == 'invalid_role_id':
            result = _test_role_id_validation(guild_id, user_session)
            return jsonify(result)
        
        else:
            return jsonify({
                'success': False,
                'message': f'Unknown test type: {test_type}'
            })
    
    except Exception as e:
        app.logger.error(f"Debug test error: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Test execution error: {str(e)}',
            'details': traceback.format_exc()
        })

def _test_guild_id_validation(guild_id, role_id, user_session, expect_block=False):
    """Helper function to test guild_id validation (SSRF protection)"""
    test_url = f"/api/server/{guild_id}/admin-roles/add"
    
    is_numeric = guild_id.isdigit() if guild_id else False
    
    if not is_numeric:
        if expect_block:
            return {
                'success': True,
                'blocked': True,
                'expected_failure': True,
                'message': f'SSRF PROTECTION ACTIVE: Guild ID "{guild_id}" correctly rejected',
                'details': {
                    'tested_value': guild_id,
                    'is_numeric': False,
                    'validation_result': 'BLOCKED',
                    'reason': 'isdigit() check returned False - malicious input prevented'
                }
            }
        else:
            return {
                'success': False,
                'message': f'Guild ID "{guild_id}" is not numeric',
                'details': 'Please use a valid numeric Discord guild ID'
            }
    
    guild, _ = verify_guild_access(user_session, guild_id)
    if not guild:
        return {
            'success': False,
            'blocked': False,
            'message': f'You do not have admin access to guild {guild_id}',
            'details': {
                'tested_value': guild_id,
                'is_numeric': True,
                'validation_result': 'PASSED format check',
                'access_check': 'FAILED - no admin access'
            }
        }
    
    if expect_block:
        return {
            'success': False,
            'blocked': False,
            'message': f'WARNING: Guild ID "{guild_id}" was NOT blocked!',
            'details': {
                'tested_value': guild_id,
                'is_numeric': True,
                'expected': 'BLOCK',
                'actual': 'ALLOWED',
                'security_concern': 'This input should have been rejected'
            }
        }
    
    return {
        'success': True,
        'blocked': False,
        'message': f'Guild ID "{guild_id}" passed validation and access checks',
        'details': {
            'tested_value': guild_id,
            'is_numeric': True,
            'validation_result': 'PASSED',
            'access_check': 'PASSED',
            'guild_name': guild.get('name', 'Unknown'),
            'role_id_provided': bool(role_id)
        }
    }

def _test_role_id_validation(guild_id, user_session):
    """Helper function to test role_id validation in remove endpoints"""
    fake_role_id = "999999999999999999"
    
    if not guild_id:
        return {
            'success': False,
            'message': 'Please enter a valid Guild ID first to test role validation',
            'details': 'A real guild ID is needed to test role validation against the guild\'s actual roles'
        }
    
    if not guild_id.isdigit():
        return {
            'success': False,
            'message': f'Guild ID "{guild_id}" is not numeric',
            'details': 'Please use a valid numeric Discord guild ID'
        }
    
    guild, _ = verify_guild_access(user_session, guild_id)
    if not guild:
        return {
            'success': False,
            'message': f'You do not have admin access to guild {guild_id}',
            'details': 'Enter a guild ID where you have admin permissions'
        }
    
    is_valid_role = validate_role_in_guild(guild_id, fake_role_id)
    
    if not is_valid_role:
        return {
            'success': True,
            'blocked': True,
            'expected_failure': True,
            'message': f'ROLE VALIDATION ACTIVE: Fake role ID "{fake_role_id}" correctly rejected',
            'details': {
                'tested_guild': guild_id,
                'guild_name': guild.get('name', 'Unknown'),
                'tested_role_id': fake_role_id,
                'validation_result': 'BLOCKED',
                'reason': 'validate_role_in_guild() returned False - invalid role prevented from being forwarded'
            }
        }
    else:
        return {
            'success': False,
            'blocked': False,
            'message': f'WARNING: Fake role ID "{fake_role_id}" was NOT blocked!',
            'details': {
                'tested_guild': guild_id,
                'tested_role_id': fake_role_id,
                'expected': 'BLOCK',
                'actual': 'ALLOWED',
                'security_concern': 'This role ID should have been rejected as invalid for this guild'
            }
        }

@app.route("/api/owner/grant-access", methods=["POST"])
@require_api_auth
def api_owner_grant_access(user_session):
    """Owner-only API endpoint to manually grant bot access or retention tiers to servers"""
    try:
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        
        # Security check: Only allow bot owner
        if user_session['user_id'] != bot_owner_id:
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
                        granted_at = NOW(),
                        grant_source = 'granted'
                    WHERE guild_id = %s
                """, (user_session['user_id'], guild_id))
                app.logger.info(f"[OK] Granted bot access to guild {guild_id}")
                
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
                        status = 'active',
                        grant_source = 'granted'
                    WHERE guild_id = %s
                """, (access_type, user_session['user_id'], guild_id))
                app.logger.info(f"[OK] Granted {access_type} retention to guild {guild_id}")
            
            # Context manager handles commit automatically
            app.logger.info(f"[OK] Transaction will be committed for guild {guild_id}")
            
            # Send notification to server owner if granting bot access
            if access_type == 'bot_access':
                app.logger.info(f"≡ƒôº Attempting to send welcome notification to server owner for guild {guild_id}")
                
                # Check bot availability with detailed logging
                if not bot:
                    app.logger.error(f"[ERROR] Bot instance is None - cannot send notification")
                    app.logger.error(f"   Bot may not have started yet. Check if Discord bot thread is running.")
                elif not hasattr(bot, 'loop'):
                    app.logger.error(f"[ERROR] Bot instance has no 'loop' attribute - bot may not be started yet")
                    app.logger.error(f"   Discord bot needs to connect before notifications can be sent.")
                elif not bot.loop:
                    app.logger.error(f"[ERROR] Bot loop is None - bot may not be fully connected")
                    app.logger.error(f"   Discord connection not established. Wait for bot to fully start.")
                elif not bot.is_ready():
                    app.logger.error(f"[ERROR] Bot is not ready - still connecting to Discord")
                    app.logger.error(f"   Bot status: connected but not ready. Notification will be skipped.")
                else:
                    app.logger.info(f"[OK] Bot is ready and connected. Queueing notification...")
                    try:
                        # Queue the notification in the bot's event loop
                        future = asyncio.run_coroutine_threadsafe(
                            notify_server_owner_bot_access(int(guild_id), granted_by="manual"),
                            bot.loop
                        )
                        app.logger.info(f"[OK] Welcome notification queued successfully for guild {guild_id}")
                        
                        # Wait for result (max 5 seconds) to catch errors
                        try:
                            result = future.result(timeout=5.0)
                            app.logger.info(f"[OK] Welcome notification completed successfully for guild {guild_id}")
                        except concurrent.futures.TimeoutError:
                            app.logger.error(f"ΓÅ▒∩╕Å Welcome notification timed out after 5 seconds for guild {guild_id}")
                            app.logger.error(f"   Notification may still be processing. Check Discord bot logs for [NOTIFY] messages.")
                        except Exception as result_error:
                            app.logger.error(f"[ERROR] Welcome notification failed for guild {guild_id}")
                            app.logger.error(f"   Error type: {type(result_error).__name__}")
                            app.logger.error(f"   Error message: {str(result_error)}")
                            app.logger.error(f"   Full traceback:")
                            app.logger.error(traceback.format_exc())
                            
                    except Exception as notify_error:
                        app.logger.error(f"[ERROR] Failed to queue welcome notification for guild {guild_id}")
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
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        
        # Security check: Only allow bot owner
        if user_session['user_id'] != bot_owner_id:
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
                app.logger.info(f"[ERROR] Revoked bot access from guild {guild_id} (tier set to 'free', retention cleared)")
                
            elif access_type in ['7day', '30day']:
                # Only revoke if this is the current retention tier
                if server['retention_tier'] == access_type:
                    conn.execute("""
                        UPDATE server_subscriptions 
                        SET retention_tier = 'none',
                            status = 'active'
                        WHERE guild_id = %s
                    """, (guild_id,))
                    app.logger.info(f"[ERROR] Revoked {access_type} retention from guild {guild_id}")
                else:
                    return jsonify({
                        'success': False, 
                        'error': f'Server does not have {access_type} retention active'
                    }), 400
            
            # Commit all changes
            app.logger.info(f"[OK] Transaction committed successfully for guild {guild_id}")
            
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

@app.route("/api/owner/broadcast", methods=["POST"])
@require_api_auth
def api_owner_broadcast(user_session):
    """Owner-only API endpoint to broadcast messages to all servers"""
    try:
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        
        # Security check: Only allow bot owner
        if user_session['user_id'] != bot_owner_id:
            app.logger.warning(f"Unauthorized broadcast attempt by user {user_session['user_id']}")
            return jsonify({'success': False, 'error': 'Unauthorized - Owner access required'}), 403
        
        data = request.get_json()
        title = data.get('title', '').strip()
        message = data.get('message', '').strip()
        target = data.get('target', 'all')  # 'all', 'paid', or 'free'
        
        if not title or not message:
            return jsonify({'success': False, 'error': 'Title and message are required'}), 400
        
        if len(title) > 100:
            return jsonify({'success': False, 'error': 'Title must be 100 characters or less'}), 400
            
        if len(message) > 2000:
            return jsonify({'success': False, 'error': 'Message must be 2000 characters or less'}), 400
        
        if target not in ['all', 'paid', 'free']:
            return jsonify({'success': False, 'error': 'Invalid target. Must be all, paid, or free'}), 400
        
        app.logger.info(f"Owner {user_session.get('username')} initiating broadcast to {target} servers")
        app.logger.info(f"Broadcast title: {title}")
        
        # Get target guild IDs based on filter (using Flask's get_db for production)
        # Note: bot_guilds.guild_id is TEXT, server_subscriptions.guild_id is BIGINT - must cast for JOIN
        with get_db() as conn:
            if target == 'all':
                cursor = conn.execute("""
                    SELECT DISTINCT guild_id FROM bot_guilds WHERE is_present = TRUE
                """)
            elif target == 'paid':
                cursor = conn.execute("""
                    SELECT bg.guild_id FROM bot_guilds bg
                    JOIN server_subscriptions ss ON CAST(bg.guild_id AS BIGINT) = ss.guild_id
                    WHERE bg.is_present = TRUE AND ss.bot_access_paid = TRUE
                """)
            else:  # free
                cursor = conn.execute("""
                    SELECT bg.guild_id FROM bot_guilds bg
                    LEFT JOIN server_subscriptions ss ON CAST(bg.guild_id AS BIGINT) = ss.guild_id
                    WHERE bg.is_present = TRUE AND (ss.bot_access_paid IS NULL OR ss.bot_access_paid = FALSE)
                """)
            
            guild_rows = cursor.fetchall()
            guild_ids = [row['guild_id'] for row in guild_rows]
        
        if not guild_ids:
            return jsonify({'success': False, 'error': 'No servers found matching the target filter'}), 400
        
        app.logger.info(f"Broadcasting to {len(guild_ids)} servers")
        
        # Send broadcast via bot's internal HTTP API (more reliable than cross-thread async)
        try:
            import requests
            bot_api_port = os.getenv("BOT_API_PORT", "8081")
            bot_api_secret = os.getenv("BOT_API_SECRET", "")
            
            # If no secret configured, try to get it from the bot module
            if not bot_api_secret:
                try:
                    bot_api_secret = _get_bot_module().BOT_API_SECRET
                except:
                    pass
            
            response = requests.post(
                f"http://127.0.0.1:{bot_api_port}/api/broadcast",
                json={
                    'guild_ids': guild_ids,
                    'title': title,
                    'message': message
                },
                headers={
                    'Authorization': f'Bearer {bot_api_secret}',
                    'Content-Type': 'application/json'
                },
                timeout=300  # 5 minute timeout for broadcasts
            )
            
            result = response.json()
            
            sent_count = result.get('sent_count', 0)
            failed_count = result.get('failed_count', 0)
            
            app.logger.info(f"Broadcast complete: {sent_count} sent, {failed_count} failed")
            
            if not result.get('success', True) and sent_count == 0:
                return jsonify({
                    'success': False,
                    'error': result.get('error', f'Failed to send to all {failed_count} servers'),
                    'sent_count': sent_count,
                    'failed_count': failed_count
                }), 500
            elif failed_count > 0:
                return jsonify({
                    'success': True,
                    'partial': True,
                    'message': f'Broadcast partially complete',
                    'sent_count': sent_count,
                    'failed_count': failed_count
                })
            else:
                return jsonify({
                    'success': True,
                    'message': f'Broadcast sent successfully',
                    'sent_count': sent_count,
                    'failed_count': 0
                })
                
        except requests.exceptions.Timeout:
            app.logger.error("Broadcast timed out after 300 seconds")
            return jsonify({'success': False, 'error': 'Broadcast timed out'}), 504
        except requests.exceptions.ConnectionError:
            app.logger.error("Could not connect to bot API")
            return jsonify({'success': False, 'error': 'Bot is not ready. Please try again later.'}), 503
        except Exception as broadcast_error:
            app.logger.error(f"Broadcast execution error: {str(broadcast_error)}")
            app.logger.error(traceback.format_exc())
            return jsonify({'success': False, 'error': f'Broadcast failed: {str(broadcast_error)}'}), 500
    
    except Exception as e:
        app.logger.error(f"Outer Broadcast error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route("/api/owner/email-logs", methods=["GET"])
@require_api_auth
def api_owner_email_logs(user_session):
    """Owner-only API endpoint to view persistent email logs"""
    try:
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        
        if user_session['user_id'] != bot_owner_id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        from pathlib import Path
        import json
        
        log_file = Path("data/email_logs/email_audit.log")
        
        if not log_file.exists():
            return jsonify({
                'success': True,
                'logs': [],
                'message': 'No email logs found yet'
            })
        
        # Read last 100 lines
        lines = log_file.read_text().strip().split('\n')
        recent_lines = lines[-100:] if len(lines) > 100 else lines
        
        logs = []
        for line in recent_lines:
            if line.strip():
                try:
                    logs.append(json.loads(line))
                except json.JSONDecodeError:
                    logs.append({"raw": line})
        
        # Reverse so newest first
        logs.reverse()
        
        return jsonify({
            'success': True,
            'logs': logs,
            'total_entries': len(lines)
        })
        
    except Exception as e:
        app.logger.error(f"Email logs API error: {str(e)}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route("/api/owner/trigger-deletion-check", methods=["POST"])
@require_api_auth
def api_owner_trigger_deletion_check(user_session):
    """Owner-only API endpoint to manually trigger deletion warning check"""
    try:
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        
        if user_session['user_id'] != bot_owner_id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        data = request.get_json() or {}
        guild_id = data.get('guild_id')
        
        app.logger.info(f"Owner triggered deletion warning check" + (f" for guild {guild_id}" if guild_id else " for all guilds"))
        
        import asyncio
        from scheduler import send_deletion_warnings
        
        if bot and bot.loop and bot.loop.is_running():
            # Use bot's event loop if available
            future = asyncio.run_coroutine_threadsafe(
                send_deletion_warnings(),
                bot.loop
            )
            try:
                future.result(timeout=30.0)
            except concurrent.futures.TimeoutError:
                return jsonify({'success': False, 'error': 'Check timed out'}), 500
        else:
            # Fallback: run in a new event loop if bot isn't ready
            app.logger.info("Bot loop not available, running in standalone event loop")
            try:
                asyncio.run(send_deletion_warnings())
            except Exception as async_error:
                app.logger.error(f"Standalone async execution failed: {async_error}")
                return jsonify({'success': False, 'error': f'Async execution failed: {str(async_error)}'}), 500
        
        return jsonify({
            'success': True,
            'message': 'Deletion warning check triggered. Check email logs for results.'
        })
        
    except Exception as e:
        app.logger.error(f"Trigger deletion check error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route("/api/owner/bulk-upgrade-paid", methods=["POST"])
@require_api_auth
def api_owner_bulk_upgrade_paid(user_session):
    """Owner-only API endpoint to upgrade all paid servers to 7-day retention"""
    try:
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        
        if user_session['user_id'] != bot_owner_id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        app.logger.info(f"Owner initiating bulk upgrade of paid servers to 7-day retention")
        
        with get_db() as conn:
            # Find all paid servers that don't have 7day or 30day retention
            cursor = conn.execute("""
                SELECT guild_id, retention_tier, subscription_id, customer_id, manually_granted
                FROM server_subscriptions
                WHERE bot_access_paid = TRUE 
                AND (retention_tier IS NULL OR retention_tier = 'none' OR retention_tier = '')
            """)
            servers_to_upgrade = cursor.fetchall()
            
            if not servers_to_upgrade:
                return jsonify({
                    'success': True,
                    'message': 'No servers need upgrading - all paid servers already have retention',
                    'upgraded_count': 0
                })
            
            # Upgrade each server to 7-day retention using parameterized queries
            upgraded_count = 0
            upgraded_guilds = []
            for server in servers_to_upgrade:
                guild_id = server['guild_id']
                # Validate guild_id is a proper integer to be extra safe
                try:
                    guild_id = int(guild_id)
                except (ValueError, TypeError):
                    app.logger.warning(f"Skipping invalid guild_id: {guild_id}")
                    continue
                
                cursor = conn.execute("""
                    UPDATE server_subscriptions 
                    SET retention_tier = '7day', 
                        tier = 'basic',
                        status = 'active'
                    WHERE guild_id = %s
                """, (guild_id,))
                if cursor.rowcount > 0:
                    upgraded_count += 1
                    upgraded_guilds.append(str(guild_id))
            
            app.logger.info(f"Bulk upgraded {upgraded_count} servers to 7-day retention: {upgraded_guilds}")
            
            return jsonify({
                'success': True,
                'message': f'Successfully upgraded {upgraded_count} paid servers to 7-day retention',
                'upgraded_count': upgraded_count,
                'upgraded_guilds': upgraded_guilds
            })
            
    except Exception as e:
        app.logger.error(f"Bulk upgrade error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route("/api/owner/purge-email-recipient", methods=["POST"])
@require_api_auth
def api_owner_purge_email_recipient(user_session):
    """Owner-only API endpoint to remove a specific email recipient from any guild"""
    try:
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        
        if user_session['user_id'] != bot_owner_id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        data = request.get_json() or {}
        guild_id = data.get('guild_id')
        email = data.get('email')
        
        if not guild_id or not email:
            return jsonify({'success': False, 'error': 'Missing guild_id or email'}), 400
        
        email = email.lower().strip()
        
        app.logger.info(f"Owner purging email recipient: {email} from guild {guild_id}")
        
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT id, email_address FROM report_recipients WHERE guild_id = %s AND email_address = %s",
                (guild_id, email)
            )
            existing = cursor.fetchone()
            
            if not existing:
                return jsonify({
                    'success': False, 
                    'error': f'Email {email} not found for guild {guild_id}',
                    'checked_guild': guild_id,
                    'checked_email': email
                }), 404
            
            cursor = conn.execute(
                "DELETE FROM report_recipients WHERE guild_id = %s AND email_address = %s",
                (guild_id, email)
            )
            deleted_count = cursor.rowcount
            
            app.logger.info(f"[OK] Purged {deleted_count} email recipient(s): {email} from guild {guild_id}")
            
            from email_utils import log_email_to_file
            log_email_to_file(
                event_type="owner_purge_recipient",
                recipients=[email],
                subject=f"Purged from guild {guild_id}",
                context={
                    "guild_id": str(guild_id),
                    "deleted_count": deleted_count,
                    "action": "owner_manual_purge"
                }
            )
        
        return jsonify({
            'success': True,
            'message': f'Successfully removed {email} from guild {guild_id}',
            'deleted_count': deleted_count
        })
        
    except Exception as e:
        app.logger.error(f"Purge email recipient error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route("/api/owner/list-all-email-recipients", methods=["GET"])
@require_api_auth
def api_owner_list_all_email_recipients(user_session):
    """Owner-only API endpoint to list ALL email recipients across ALL guilds"""
    try:
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        
        if user_session['user_id'] != bot_owner_id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT 
                    rr.id,
                    rr.guild_id,
                    bg.guild_name,
                    rr.email_address,
                    rr.recipient_type,
                    rr.created_at
                FROM report_recipients rr
                LEFT JOIN bot_guilds bg ON CAST(rr.guild_id AS TEXT) = bg.guild_id
                WHERE rr.recipient_type = 'email'
                ORDER BY rr.guild_id, rr.created_at
            """)
            recipients = cursor.fetchall()
        
        result = []
        for row in recipients:
            result.append({
                'id': row['id'],
                'guild_id': str(row['guild_id']),
                'guild_name': row['guild_name'] or f"Unknown Guild {row['guild_id']}",
                'email': row['email_address'],
                'created_at': row['created_at'].isoformat() if row['created_at'] else None
            })
        
        return jsonify({
            'success': True,
            'recipients': result,
            'total': len(result)
        })
        
    except Exception as e:
        app.logger.error(f"List email recipients error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route("/api/owner/audit-email-settings", methods=["POST"])
@require_api_auth
def api_owner_audit_email_settings(user_session):
    """Owner-only API endpoint to audit and fix guilds with email settings enabled but no recipients"""
    try:
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        
        if user_session['user_id'] != bot_owner_id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        app.logger.info("Owner initiating email settings audit")
        
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT es.guild_id, es.auto_send_on_clockout, es.auto_email_before_delete,
                       bg.guild_name,
                       (SELECT COUNT(*) FROM report_recipients rr 
                        WHERE rr.guild_id = es.guild_id AND rr.recipient_type = 'email') as recipient_count
                FROM email_settings es
                LEFT JOIN bot_guilds bg ON CAST(es.guild_id AS TEXT) = bg.guild_id
                WHERE (es.auto_send_on_clockout = TRUE OR es.auto_email_before_delete = TRUE)
            """)
            guilds_with_settings = cursor.fetchall()
            
            orphaned_guilds = []
            fixed_guilds = []
            
            for guild in guilds_with_settings:
                if guild['recipient_count'] == 0:
                    orphaned_guilds.append({
                        'guild_id': str(guild['guild_id']),
                        'guild_name': guild['guild_name'] or f"Unknown Guild {guild['guild_id']}",
                        'auto_send_on_clockout': guild['auto_send_on_clockout'],
                        'auto_email_before_delete': guild['auto_email_before_delete']
                    })
                    
                    conn.execute("""
                        UPDATE email_settings 
                        SET auto_send_on_clockout = FALSE, auto_email_before_delete = FALSE 
                        WHERE guild_id = %s
                    """, (guild['guild_id'],))
                    fixed_guilds.append(str(guild['guild_id']))
            
            app.logger.info(f"Email settings audit complete: Found {len(orphaned_guilds)} orphaned guilds, fixed {len(fixed_guilds)}")
        
        return jsonify({
            'success': True,
            'message': f'Audit complete. Found and fixed {len(fixed_guilds)} guilds with email settings but no recipients.',
            'orphaned_guilds': orphaned_guilds,
            'fixed_count': len(fixed_guilds)
        })
        
    except Exception as e:
        app.logger.error(f"Email settings audit error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route("/api/owner/employee-list/<guild_id>", methods=["GET"])
@require_api_auth
def api_owner_employee_list(user_session, guild_id):
    """Owner-only API endpoint to get employee list for a server"""
    try:
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        
        if user_session['user_id'] != bot_owner_id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT 
                    ep.user_id,
                    ep.first_name,
                    ep.last_name,
                    ep.full_name,
                    ep.display_name,
                    ep.company_role,
                    ep.role_tier,
                    ep.is_active,
                    COALESCE(SUM(
                        CASE WHEN s.clock_out IS NOT NULL 
                        THEN EXTRACT(EPOCH FROM (s.clock_out - s.clock_in))/3600 
                        ELSE 0 END
                    ), 0) as total_hours,
                    COUNT(s.id) as session_count,
                    EXISTS(SELECT 1 FROM sessions s2 WHERE s2.guild_id = ep.guild_id AND s2.user_id = ep.user_id AND s2.clock_out IS NULL) as is_clocked_in
                FROM employee_profiles ep
                LEFT JOIN sessions s ON s.guild_id = ep.guild_id AND s.user_id = ep.user_id
                WHERE ep.guild_id = %s
                GROUP BY ep.user_id, ep.first_name, ep.last_name, ep.full_name, ep.display_name, ep.company_role, ep.role_tier, ep.is_active, ep.guild_id
                ORDER BY ep.display_name, ep.user_id
            """, (int(guild_id),))
            employees = cursor.fetchall()
        
        result = []
        for emp in employees:
            name = emp['display_name'] or emp['full_name'] or f"{emp['first_name'] or ''} {emp['last_name'] or ''}".strip() or f"User {emp['user_id']}"
            result.append({
                'user_id': str(emp['user_id']),
                'display_name': name,
                'role': emp['company_role'] or emp['role_tier'] or 'Employee',
                'is_active': emp['is_active'],
                'total_hours': round(float(emp['total_hours']), 2),
                'session_count': emp['session_count'],
                'is_clocked_in': emp['is_clocked_in']
            })
        
        return jsonify({
            'success': True,
            'employees': result,
            'total': len(result)
        })
        
    except Exception as e:
        app.logger.error(f"Employee list error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route("/api/owner/time-report/<guild_id>", methods=["GET"])
@require_api_auth
def api_owner_time_report(user_session, guild_id):
    """Owner-only API endpoint to download time report CSV for a server"""
    try:
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        
        if user_session['user_id'] != bot_owner_id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        if not start_date or not end_date:
            return jsonify({'success': False, 'error': 'start_date and end_date required'}), 400
        
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT bg.guild_name FROM bot_guilds WHERE guild_id = %s
            """, (str(guild_id),))
            guild_row = cursor.fetchone()
            guild_name = guild_row['guild_name'] if guild_row else f"Server {guild_id}"
            
            cursor = conn.execute("""
                SELECT 
                    s.user_id,
                    ep.display_name,
                    ep.full_name,
                    ep.first_name,
                    ep.last_name,
                    s.clock_in,
                    s.clock_out,
                    CASE 
                        WHEN s.clock_out IS NOT NULL 
                        THEN EXTRACT(EPOCH FROM (s.clock_out - s.clock_in))/3600 
                        ELSE NULL 
                    END as hours_worked
                FROM sessions s
                LEFT JOIN employee_profiles ep ON s.guild_id = ep.guild_id AND s.user_id = ep.user_id
                WHERE s.guild_id = %s
                  AND s.clock_in >= %s::date
                  AND s.clock_in < (%s::date + interval '1 day')
                ORDER BY s.clock_in
            """, (int(guild_id), start_date, end_date))
            sessions = cursor.fetchall()
        
        import io
        import csv
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        writer.writerow(['Employee ID', 'Employee Name', 'Clock In', 'Clock Out', 'Hours Worked'])
        
        total_hours = 0
        for session in sessions:
            name = session['display_name'] or session['full_name'] or f"{session['first_name'] or ''} {session['last_name'] or ''}".strip() or f"User {session['user_id']}"
            clock_in = session['clock_in'].strftime('%Y-%m-%d %H:%M:%S') if session['clock_in'] else ''
            clock_out = session['clock_out'].strftime('%Y-%m-%d %H:%M:%S') if session['clock_out'] else 'Still clocked in'
            hours = round(float(session['hours_worked']), 2) if session['hours_worked'] else 'N/A'
            if session['hours_worked']:
                total_hours += float(session['hours_worked'])
            
            writer.writerow([str(session['user_id']), name, clock_in, clock_out, hours])
        
        writer.writerow([])
        writer.writerow(['', '', '', 'Total Hours:', round(total_hours, 2)])
        writer.writerow(['', '', '', 'Report Period:', f'{start_date} to {end_date}'])
        writer.writerow(['', '', '', 'Server:', guild_name])
        
        output.seek(0)
        
        from flask import Response
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={
                'Content-Disposition': f'attachment; filename=time_report_{guild_id}_{start_date}_to_{end_date}.csv'
            }
        )
        
    except Exception as e:
        app.logger.error(f"Time report error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

def verify_guild_access(user_session, guild_id, allow_employee=False):
    """
    Verify user has access to a specific guild.
    Returns tuple (guild_object, access_level) if user has access, (None, None) otherwise.
    
    Args:
        user_session: Current user session
        guild_id: Guild ID to check
        allow_employee: If True, also checks employee_profiles for employee access
    
    Returns:
        (guild_dict, access_level) or (None, None)
        access_level is 'admin' or 'employee'
    """
    all_guilds = user_session.get('guilds', [])
    
    # First check admin access (from OAuth guilds)
    for guild in all_guilds:
        if guild.get('id') == guild_id:
            if user_has_admin_access(user_session['user_id'], guild_id, guild):
                return (guild, 'admin')
    
    # If allow_employee and no admin access, check employee_profiles
    if allow_employee:
        user_id = user_session.get('user_id')
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT ep.guild_id, bg.guild_name
                FROM employee_profiles ep
                JOIN bot_guilds bg ON bg.guild_id = CAST(ep.guild_id AS TEXT)
                WHERE ep.user_id = %s 
                  AND ep.guild_id = %s 
                  AND ep.is_active = TRUE
            """, (user_id, int(guild_id)))
            
            employee_guild = cursor.fetchone()
            if employee_guild:
                # Return a guild-like dict with employee access
                return ({
                    'id': guild_id,
                    'name': employee_guild['guild_name'],
                    'owner': False,
                    'permissions': '0'
                }, 'employee')
    
    return (None, None)

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

def get_guild_text_channels(guild_id):
    """
    Fetch guild text channels using Discord bot token.
    Returns list of text channels (id, name), or empty list if error.
    """
    bot_token = os.environ.get('DISCORD_TOKEN')
    if not bot_token:
        app.logger.error("DISCORD_TOKEN not found in environment")
        return []
    
    headers = {'Authorization': f'Bot {bot_token}'}
    try:
        channels_response = requests.get(
            f'{DISCORD_API_BASE}/guilds/{guild_id}/channels',
            headers=headers,
            timeout=5
        )
        channels_response.raise_for_status()
        channels = channels_response.json()
        
        # Filter to text channels only (type 0) and return simplified list
        text_channels = [
            {'id': str(ch['id']), 'name': ch['name']}
            for ch in channels 
            if ch.get('type') == 0  # 0 = text channel
        ]
        return sorted(text_channels, key=lambda x: x['name'])
    except Exception as e:
        app.logger.error(f"Error fetching guild channels: {str(e)}")
        return []

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
        
        # Get guild settings (timezone, recipient_user_id, work_day_end_time, broadcast_channel_id, etc.)
        settings_cursor = conn.execute(
            "SELECT timezone, recipient_user_id, name_display_mode, main_admin_role_id, work_day_end_time, broadcast_channel_id FROM guild_settings WHERE guild_id = %s",
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
        
        # Get subscription info including mobile restriction, bot_access, and retention tier
        try:
            subscription_cursor = conn.execute(
                "SELECT restrict_mobile_clockin, bot_access_paid, retention_tier, status FROM server_subscriptions WHERE guild_id = %s",
                (int(guild_id),)
            )
            subscription_row = subscription_cursor.fetchone()
        except:
            subscription_row = None
        
        # Calculate tier using entitlements helper
        has_bot_access = (bool(subscription_row['bot_access_paid']) if subscription_row else False) or (subscription_row.get('status') == 'active' if subscription_row else False)
        retention_tier = subscription_row['retention_tier'] if subscription_row else 'none'
        guild_tier = Entitlements.get_guild_tier(has_bot_access, retention_tier or 'none')
        
        # Get email recipient count for fail-safe validation
        try:
            recipient_count_cursor = conn.execute(
                "SELECT COUNT(*) as count FROM report_recipients WHERE guild_id = %s AND recipient_type = 'email'",
                (guild_id,)
            )
            email_recipient_count = recipient_count_cursor.fetchone()['count']
        except:
            email_recipient_count = 0
        
        return {
            'admin_roles': admin_roles,
            'employee_roles': employee_roles,
            'timezone': (settings_row['timezone'] if settings_row else None) or 'America/New_York',
            'recipient_user_id': settings_row['recipient_user_id'] if settings_row else None,
            'name_display_mode': (settings_row['name_display_mode'] if settings_row else None) or 'username',
            'main_admin_role_id': settings_row['main_admin_role_id'] if settings_row else None,
            'work_day_end_time': (settings_row['work_day_end_time'] if settings_row else None) or '17:00',
            'broadcast_channel_id': str(settings_row['broadcast_channel_id']) if settings_row and settings_row['broadcast_channel_id'] else None,
            'auto_send_on_clockout': bool(email_settings_row['auto_send_on_clockout']) if email_settings_row else False,
            'auto_email_before_delete': bool(email_settings_row['auto_email_before_delete']) if email_settings_row else False,
            'restrict_mobile_clockin': bool(subscription_row['restrict_mobile_clockin']) if subscription_row else False,
            'email_recipient_count': email_recipient_count,
            'emails': [],
            'tier': guild_tier.value,
            'bot_access_paid': has_bot_access,
            'retention_tier': retention_tier,
            'retention_days': Entitlements.get_retention_days(guild_tier)
        }

@app.route("/server/<guild_id>/adjustments/review")
@require_paid_access
def server_adjustments_review(user_session, guild_id):
    """Admin page for reviewing time adjustment requests"""
    try:
        # Get guild name from user's guilds
        guild_name = "Server"
        for g in user_session.get('guilds', []):
            if str(g.get('id')) == str(guild_id):
                guild_name = g.get('name', 'Server')
                break
        
        return render_template(
            'server_adjustments_review.html',
            guild_id=guild_id,
            guild_name=guild_name
        )
    except Exception as e:
        app.logger.error(f"Error loading adjustments review: {e}")
        return render_template('error.html', error="Failed to load review page"), 500

@app.route("/upgrade/<guild_id>")
@require_auth
def upgrade_info(user_session, guild_id):
    """Show upgrade information page"""
    try:
        import html
        
        # Verify user has access to this guild
        guild, _ = verify_guild_access(user_session, guild_id)
        if not guild:
            return "<h1>Access Denied</h1><p>You don't have admin access to this server.</p><a href='/dashboard'>Back to Dashboard</a>", 403
        
        # Get bot access and retention tier status (using Flask-side function for production)
        has_bot_access = flask_check_bot_access(int(guild_id))
        # get_retention_tier is read-only so can use bot module
        from bot import get_retention_tier
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
                    {'[OK] Full Bot Access Active' if has_bot_access else '≡ƒoÆ Free Tier - Limited Features'}
                    <br>
                    {f"≡ƒôè {retention_tier.replace('day', '-Day').title()} Retention" if retention_tier != 'none' else '[WARN] 24-Hour Data Deletion'}
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
                        <li><strong>Dashboard Premium ($5 One-Time):</strong> Full bot access, real reports, dashboard unlocked, 7-day data retention</li>
                        <li><strong>Pro Retention ($5/Month Add-On):</strong> Extend to 30-day data retention</li>
                    </ul>
                    ''' if not has_bot_access else '''
                    <h3 style="margin-top: 30px;">≡ƒôu Add Data Retention:</h3>
                    <ul style="text-align: left;">
                        <li><strong>Pro Retention ($5/Month):</strong> 30-day rolling retention</li>
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
        
        # Check if already has bot access (using Flask-side function for production)
        has_bot_access = flask_check_bot_access(guild_id)
        
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
                    <h1>[OK] Bot Access Already Active!</h1>
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
                    content: "[OK]";
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
                    <h1>≡ƒoô Unlock Full Bot Access</h1>
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
                            <td class="yes">[OK] Basic</td>
                            <td class="yes">[OK] Full Access</td>
                        </tr>
                        <tr>
                            <td>Team Reports</td>
                            <td class="no">[ERROR] Dummy Only</td>
                            <td class="yes">[OK] Real CSV Reports</td>
                        </tr>
                        <tr>
                            <td>Dashboard</td>
                            <td class="no">[ERROR] Locked</td>
                            <td class="yes">[OK] Full Access</td>
                        </tr>
                        <tr>
                            <td>Role Management</td>
                            <td class="no">[ERROR] Admin Only</td>
                            <td class="yes">[OK] Full Control</td>
                        </tr>
                        <tr>
                            <td>Data Retention</td>
                            <td class="no">[WARN] 24 Hours</td>
                            <td class="yes">[WARN] 24 Hours*</td>
                        </tr>
                    </table>
                    <p style="margin-top: 20px; color: #9CA3AF; font-size: 0.9em;">
                        *Dashboard Premium includes 7-day retention. Add Pro Retention ($5/mo) for 30-day storage.
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
        
        # Validate guild_id format to prevent SSRF
        if not guild_id.isdigit() or len(guild_id) > 20:
            return jsonify({'success': False, 'error': 'Invalid guild ID format'}), 400
        
        # Verify user has access
        guild, _ = verify_guild_access(user_session, guild_id)
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
        # Using constant base URL with validated guild_id (digits only, max 20 chars)
        bot_api_url = f"{BOT_API_BASE_URL}/api/guild/{guild_id}/admin-roles/add"
        
        # Validate URL to prevent SSRF
        if not validate_bot_api_url(bot_api_url):
            app.logger.error(f"SSRF protection: Invalid bot API URL rejected")
            return jsonify({'success': False, 'error': 'Invalid request'}), 400
        
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
        
        # Validate guild_id format to prevent SSRF
        if not guild_id.isdigit() or len(guild_id) > 20:
            return jsonify({'success': False, 'error': 'Invalid guild ID format'}), 400
        
        # Verify user has access
        guild, _ = verify_guild_access(user_session, guild_id)
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
        # Using constant base URL with validated guild_id (digits only, max 20 chars)
        bot_api_url = f"{BOT_API_BASE_URL}/api/guild/{guild_id}/admin-roles/remove"
        
        # Validate URL to prevent SSRF
        if not validate_bot_api_url(bot_api_url):
            app.logger.error(f"SSRF protection: Invalid bot API URL rejected")
            return jsonify({'success': False, 'error': 'Invalid request'}), 400
        
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
        
        # Validate guild_id format to prevent SSRF
        if not guild_id.isdigit() or len(guild_id) > 20:
            return jsonify({'success': False, 'error': 'Invalid guild ID format'}), 400
        
        # Verify user has access
        guild, _ = verify_guild_access(user_session, guild_id)
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
        # Using constant base URL with validated guild_id (digits only, max 20 chars)
        bot_api_url = f"{BOT_API_BASE_URL}/api/guild/{guild_id}/employee-roles/add"
        
        # Validate URL to prevent SSRF
        if not validate_bot_api_url(bot_api_url):
            app.logger.error(f"SSRF protection: Invalid bot API URL rejected")
            return jsonify({'success': False, 'error': 'Invalid request'}), 400
        
        app.logger.info(f"≡ƒou Flask calling bot API: {bot_api_url} with role_id={role_id}")
        
        response = requests.post(
            bot_api_url,
            json={'role_id': role_id},
            headers={'Authorization': f'Bearer {bot_api_secret}'},
            timeout=5
        )
        
        app.logger.info(f"≡ƒou Bot API response: status={response.status_code}, ok={response.ok}")
        
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
        
        # Validate guild_id format to prevent SSRF
        if not guild_id.isdigit() or len(guild_id) > 20:
            return jsonify({'success': False, 'error': 'Invalid guild ID format'}), 400
        
        # Verify user has access
        guild, _ = verify_guild_access(user_session, guild_id)
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
        # Using constant base URL with validated guild_id (digits only, max 20 chars)
        bot_api_url = f"{BOT_API_BASE_URL}/api/guild/{guild_id}/employee-roles/remove"
        
        # Validate URL to prevent SSRF
        if not validate_bot_api_url(bot_api_url):
            app.logger.error(f"SSRF protection: Invalid bot API URL rejected")
            return jsonify({'success': False, 'error': 'Invalid request'}), 400
        
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
        guild, _ = verify_guild_access(user_session, guild_id)
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

@app.route("/api/server/<guild_id>/broadcast-channel", methods=["POST"])
@require_paid_api_access
def api_update_broadcast_channel(user_session, guild_id):
    """API endpoint to update broadcast channel setting"""
    try:
        # Verify user has access
        guild, _ = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Get channel_id from request
        data = request.get_json()
        if data is None:
            return jsonify({'success': False, 'error': 'Missing data'}), 400
        
        channel_id = data.get('channel_id')
        
        # Validate channel_id format (should be null or a numeric string)
        if channel_id is not None:
            if not isinstance(channel_id, str) or not channel_id.isdigit():
                return jsonify({'success': False, 'error': 'Invalid channel ID'}), 400
            channel_id = int(channel_id)
        
        # Update or insert guild settings
        with get_db() as conn:
            cursor = conn.execute("SELECT guild_id FROM guild_settings WHERE guild_id = %s", (guild_id,))
            exists = cursor.fetchone()
            
            if exists:
                conn.execute(
                    "UPDATE guild_settings SET broadcast_channel_id = %s WHERE guild_id = %s",
                    (channel_id, guild_id)
                )
            else:
                conn.execute(
                    "INSERT INTO guild_settings (guild_id, broadcast_channel_id) VALUES (%s, %s)",
                    (guild_id, channel_id)
                )
        
        app.logger.info(f"Updated broadcast channel to {channel_id} for guild {guild_id} by user {user_session.get('username')}")
        return jsonify({'success': True, 'message': 'Broadcast channel updated successfully'})
    except Exception as e:
        app.logger.error(f"Error updating broadcast channel: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@app.route("/api/server/<guild_id>/email-settings", methods=["POST"])
@require_paid_api_access
def api_update_email_settings(user_session, guild_id):
    """API endpoint to update email settings"""
    try:
        # Verify user has access
        guild, _ = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Get email settings from request
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Missing data'}), 400
        
        auto_send_on_clockout = bool(data.get('auto_send_on_clockout', False))
        auto_email_before_delete = bool(data.get('auto_email_before_delete', False))
        
        # FAIL-SAFE: Check if any email recipients are configured before enabling email features
        if auto_send_on_clockout or auto_email_before_delete:
            with get_db() as conn:
                cursor = conn.execute(
                    "SELECT COUNT(*) as count FROM report_recipients WHERE guild_id = %s AND recipient_type = 'email'",
                    (guild_id,)
                )
                recipient_count = cursor.fetchone()['count']
                
                if recipient_count == 0:
                    return jsonify({
                        'success': False, 
                        'error': 'Please add at least one email recipient before enabling email automation features.',
                        'requires_recipients': True
                    }), 400
        
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
            
            app.logger.info(f"[OK] Email settings committed for guild {guild_id} by user {user_session.get('username')}")
            
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
        guild, _ = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Get work day end time from request
        data = request.get_json()
        if not data or 'work_day_end_time' not in data:
            return jsonify({'success': False, 'error': 'Missing work day end time'}), 400
        
        work_day_end_time = data['work_day_end_time']
        
        # Validate time format (HH:MM)
        import re
        if not re.match(r'^([01][0-9]|2[0-3]):[0-5][0-9]$', work_day_end_time):
            return jsonify({'success': False, 'error': 'Invalid time format. Use HH:MM'}), 400
        
        # FAIL-SAFE: Check if any email recipients are configured (work day end time triggers email reports)
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT COUNT(*) as count FROM report_recipients WHERE guild_id = %s AND recipient_type = 'email'",
                (guild_id,)
            )
            recipient_count = cursor.fetchone()['count']
            
            if recipient_count == 0:
                return jsonify({
                    'success': False, 
                    'error': 'Please add at least one email recipient before setting work day end time for automated reports.',
                    'requires_recipients': True
                }), 400
        
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
            
            app.logger.info(f"[OK] Work day end time committed: {work_day_end_time} for guild {guild_id}")
            
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
        app.logger.info(f"≡ƒoº Mobile restriction API called for guild {guild_id}")
        
        # Verify user has access
        guild, _ = verify_guild_access(user_session, guild_id)
        if not guild:
            app.logger.warning(f"[ERROR] Access denied for guild {guild_id}")
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Get mobile restriction setting from request
        data = request.get_json()
        if data is None:
            app.logger.error(f"[ERROR] Missing data in request for guild {guild_id}")
            return jsonify({'success': False, 'error': 'Missing data'}), 400
        
        restrict_mobile = bool(data.get('restrict_mobile', False))
        app.logger.info(f"≡ƒô▒ Setting mobile restriction to {restrict_mobile} for guild {guild_id}")
        
        # Update or insert mobile restriction setting
        with get_db() as conn:
            # Ensure a record exists in server_subscriptions
            cursor = conn.execute("SELECT guild_id FROM server_subscriptions WHERE guild_id = %s", (int(guild_id),))
            exists = cursor.fetchone()
            
            if exists:
                app.logger.info(f"≡ƒoa Updating existing record for guild {guild_id}")
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
                app.logger.info(f"[OK] Verified database value: {verify_result['restrict_mobile_clockin']} for guild {guild_id}")
            
            app.logger.info(f"[OK] Mobile restriction setting committed: {restrict_mobile} for guild {guild_id}")
            
            return jsonify({
                'success': True, 
                'message': 'Mobile restriction setting updated successfully',
                'restrict_mobile': restrict_mobile
            })
    except Exception as e:
        app.logger.error(f"[ERROR] Error updating mobile restriction: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@app.route("/api/server/<guild_id>/email-recipients", methods=["GET"])
@require_paid_api_access
def api_get_email_recipients(user_session, guild_id):
    """API endpoint to fetch email recipients for a server"""
    try:
        # Verify user has access
        guild, _ = verify_guild_access(user_session, guild_id)
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
        guild, _ = verify_guild_access(user_session, guild_id)
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
                
                app.logger.info(f"[OK] Email recipient committed: {email} for guild {guild_id}")
                
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
        guild, _ = verify_guild_access(user_session, guild_id)
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
            
            app.logger.info(f"[OK] Email recipient removed: {recipient_id} for guild {guild_id}")
            
            # FAIL-SAFE: Check remaining recipients and auto-disable email settings if none left
            remaining_cursor = conn.execute(
                "SELECT COUNT(*) as count FROM report_recipients WHERE guild_id = %s AND recipient_type = 'email'",
                (guild_id,)
            )
            remaining_count = remaining_cursor.fetchone()['count']
            
            email_settings_disabled = False
            if remaining_count == 0:
                # Auto-disable all email-dependent settings
                conn.execute(
                    "UPDATE email_settings SET auto_send_on_clockout = FALSE, auto_email_before_delete = FALSE WHERE guild_id = %s",
                    (guild_id,)
                )
                conn.execute(
                    "UPDATE guild_settings SET work_day_end_time = NULL WHERE guild_id = %s",
                    (guild_id,)
                )
                email_settings_disabled = True
                app.logger.info(f"[OK] Auto-disabled email settings for guild {guild_id} (no recipients remaining)")
            
            return jsonify({
                'success': True, 
                'message': 'Email recipient removed successfully',
                'remaining_count': remaining_count,
                'email_settings_disabled': email_settings_disabled
            })
    except Exception as e:
        app.logger.error(f"Error removing email recipient: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@app.route("/api/server/<guild_id>/data", methods=["GET"])
@require_api_auth  # Changed from require_paid_api_access to allow employees
def api_get_server_data(user_session, guild_id):
    """API endpoint to fetch server roles and settings for dashboard integration"""
    try:
        # Verify user has access (admin OR employee)
        guild, access_level = verify_guild_access(user_session, guild_id, allow_employee=True)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Check if bot is present
        bot_guild_ids = get_bot_guild_ids()
        if guild_id not in bot_guild_ids:
            return jsonify({'success': False, 'error': 'Bot not present in this server'}), 404
        
        # Determine user_role_tier based on access_level and Discord permissions
        if access_level == 'employee':
            user_role_tier = 'employee'
        elif guild.get('owner', False):
            user_role_tier = 'owner'
        else:
            permissions = int(guild.get('permissions', '0'))
            if permissions & 0x8:
                user_role_tier = 'admin'
            else:
                user_role_tier = 'employee'
        
        # For employees, only return limited data
        if access_level == 'employee':
            return jsonify({
                'success': True,
                'guild': guild,
                'roles': [],  # Employees don't need role list
                'text_channels': [],  # Employees don't need channel list
                'current_settings': {
                    'timezone': get_guild_settings(guild_id).get('timezone', 'America/New_York')
                },
                'current_user_id': user_session.get('user_id'),
                'user_role_tier': user_role_tier,
                'access_level': access_level
            })
        
        # For admins, return full data
        roles = get_guild_roles_from_bot(guild_id)
        if not roles:
            return jsonify({'success': False, 'error': 'Could not fetch server roles'}), 500
        
        current_settings = get_guild_settings(guild_id)
        text_channels = get_guild_text_channels(guild_id)
        
        return jsonify({
            'success': True,
            'guild': guild,
            'roles': roles,
            'text_channels': text_channels,
            'current_settings': current_settings,
            'current_user_id': user_session.get('user_id'),
            'user_role_tier': user_role_tier,
            'access_level': access_level
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
        guild, _ = verify_guild_access(user_session, guild_id)
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
        guild, _ = verify_guild_access(user_session, guild_id)
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
        guild, _ = verify_guild_access(user_session, guild_id)
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
        discord_client_id = os.getenv("DISCORD_CLIENT_ID", "1418446753379913809")
        permissions = "2048"
        invite_url = f"https://discord.com/api/oauth2/authorize?client_id={discord_client_id}&permissions={permissions}&scope=bot%20applications.commands"
        
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
            <h1>[OK] Purchase Successful!</h1>
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
            <h1>[ERROR] Purchase Cancelled</h1>
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
    discord_client_id = os.getenv("DISCORD_CLIENT_ID", "1418446753379913809")
    permissions = "2048"  # Slash commands permission
    invite_url = f"https://discord.com/api/oauth2/authorize?client_id={discord_client_id}&permissions={permissions}&scope=bot%20applications.commands"
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

@app.route("/api/guild/<guild_id>/on-the-clock")
@require_paid_api_access
def api_get_on_the_clock(user_session, guild_id):
    """
    Get currently clocked-in coworkers for employee view.
    Employees can only see who is on the clock, not detailed stats.
    """
    try:
        # Verify user has access to this guild (admin or employee)
        guild, access_level = verify_guild_access(user_session, guild_id, allow_employee=True)
        if not guild:
            app.logger.warning(f"On-the-clock access denied for user {user_session.get('user_id')} to guild {guild_id}")
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        timezone_name = request.args.get('timezone', 'America/New_York')
        employees = get_active_employees_with_stats(int(guild_id), timezone_name)
        
        # For employee view, only return basic info about clocked-in coworkers
        coworkers = []
        for emp in employees:
            if emp.get('is_clocked_in'):
                coworkers.append({
                    'user_id': emp['user_id'],
                    'display_name': emp.get('display_name') or emp.get('full_name') or 'Unknown',
                    'is_clocked_in': True
                })
        
        return jsonify({
            'success': True,
            'coworkers': coworkers
        })
    except Exception as e:
        app.logger.error(f"Error fetching on-the-clock: {e}")
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
            # Notify admins via Discord (async)
            from bot import notify_admins_of_adjustment, bot
            if bot and bot.loop:
                asyncio.run_coroutine_threadsafe(
                    notify_admins_of_adjustment(int(guild_id), request_id),
                    bot.loop
                )
            
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

@app.route("/api/guild/<guild_id>/adjustments/submit-day", methods=["POST"])
@require_api_auth
def api_submit_day_adjustment(user_session, guild_id):
    """
    Submit adjustment request(s) for a specific day from the calendar popup.
    Accepts multiple session changes in one request.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        session_date = data.get('session_date')
        reason = data.get('reason', '').strip()
        changes = data.get('changes', [])
        
        if not session_date:
            return jsonify({'success': False, 'error': 'Session date is required'}), 400
        if not reason:
            return jsonify({'success': False, 'error': 'Reason is required'}), 400
        if not changes or len(changes) == 0:
            return jsonify({'success': False, 'error': 'No changes provided'}), 400
        
        user_id = int(user_session['user_id'])
        guild_id_int = int(guild_id)
        
        # Check guild has paid access
        access_status = check_guild_paid_access(guild_id)
        if not access_status['bot_invited'] or not access_status['bot_access_paid']:
            return jsonify({'success': False, 'error': 'Server does not have paid access'}), 403
        
        created_requests = []
        invalid_sessions = []
        
        with get_db() as conn:
            # First, validate all sessions belong to the user
            for change in changes:
                session_id = change.get('session_id')
                if not session_id:
                    return jsonify({'success': False, 'error': 'Invalid session data - missing session_id'}), 400
                
                cursor = conn.execute("""
                    SELECT id, clock_in, clock_out, duration_seconds
                    FROM sessions
                    WHERE id = %s AND guild_id = %s AND user_id = %s
                """, (session_id, guild_id_int, user_id))
                
                if not cursor.fetchone():
                    invalid_sessions.append(session_id)
            
            # Reject if any sessions are invalid (not owned by user)
            if invalid_sessions:
                return jsonify({
                    'success': False, 
                    'error': 'Access denied - one or more sessions do not belong to you'
                }), 403
            
            # Now process each valid change
            for change in changes:
                session_id = change.get('session_id')
                new_clock_in = change.get('new_clock_in')
                new_clock_out = change.get('new_clock_out')
                original_clock_in = change.get('original_clock_in')
                original_clock_out = change.get('original_clock_out')
                
                # Get original session data (we know it exists and belongs to user)
                cursor = conn.execute("""
                    SELECT id, clock_in, clock_out, duration_seconds
                    FROM sessions
                    WHERE id = %s AND guild_id = %s AND user_id = %s
                """, (session_id, guild_id_int, user_id))
                
                original_session = cursor.fetchone()
                
                # Parse new times and combine with session date
                import pytz
                from datetime import datetime as dt
                
                # Get guild timezone
                cursor = conn.execute(
                    "SELECT timezone FROM guild_settings WHERE guild_id = %s",
                    (guild_id_int,)
                )
                tz_row = cursor.fetchone()
                guild_tz_str = tz_row['timezone'] if tz_row else 'America/New_York'
                guild_tz = pytz.timezone(guild_tz_str)
                
                # Parse new clock in/out times
                requested_clock_in = None
                requested_clock_out = None
                
                if new_clock_in:
                    try:
                        date_parts = session_date.split('-')
                        time_parts = new_clock_in.split(':')
                        local_dt = dt(int(date_parts[0]), int(date_parts[1]), int(date_parts[2]),
                                     int(time_parts[0]), int(time_parts[1]))
                        requested_clock_in = guild_tz.localize(local_dt).astimezone(pytz.utc)
                    except Exception as e:
                        app.logger.error(f"Error parsing clock_in time: {e}")
                
                if new_clock_out:
                    try:
                        date_parts = session_date.split('-')
                        time_parts = new_clock_out.split(':')
                        local_dt = dt(int(date_parts[0]), int(date_parts[1]), int(date_parts[2]),
                                     int(time_parts[0]), int(time_parts[1]))
                        requested_clock_out = guild_tz.localize(local_dt).astimezone(pytz.utc)
                    except Exception as e:
                        app.logger.error(f"Error parsing clock_out time: {e}")
                
                # Calculate new duration if both times are set
                calculated_duration = None
                if requested_clock_in and requested_clock_out:
                    calculated_duration = int((requested_clock_out - requested_clock_in).total_seconds())
                
                # Create the adjustment request
                cursor = conn.execute("""
                    INSERT INTO time_adjustment_requests (
                        guild_id, user_id, request_type, original_session_id,
                        original_clock_in, original_clock_out, original_duration,
                        requested_clock_in, requested_clock_out, reason,
                        session_date, calculated_duration, status
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'pending')
                    RETURNING id
                """, (
                    guild_id_int, user_id, 'modify_session', session_id,
                    original_session['clock_in'], original_session['clock_out'], 
                    original_session['duration_seconds'],
                    requested_clock_in, requested_clock_out, reason,
                    session_date, calculated_duration
                ))
                
                new_request_id = cursor.fetchone()['id']
                created_requests.append(new_request_id)
                
                app.logger.info(f"[OK] Created adjustment request {new_request_id} for session {session_id} by user {user_id}")
        
        if created_requests:
            return jsonify({
                'success': True, 
                'message': f'Created {len(created_requests)} adjustment request(s)',
                'request_ids': created_requests
            })
        else:
            return jsonify({'success': False, 'error': 'No valid changes to submit'}), 400
            
    except Exception as e:
        app.logger.error(f"Error submitting day adjustment: {e}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/api/guild/<guild_id>/adjustments/history")
@require_api_auth
def api_get_adjustment_history(user_session, guild_id):
    """
    Get adjustment request history for the current user.
    Returns all requests (pending, approved, denied) for audit trail.
    """
    try:
        user_id = int(user_session['user_id'])
        requests = get_user_adjustment_history(int(guild_id), user_id)
        
        serialized_requests = []
        for req in requests:
            req_dict = dict(req)
            for key, value in req_dict.items():
                if isinstance(value, datetime):
                    req_dict[key] = value.isoformat()
            serialized_requests.append(req_dict)
            
        return jsonify({'success': True, 'history': serialized_requests})
        
    except Exception as e:
        app.logger.error(f"Error fetching adjustment history: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/api/guild/<guild_id>/adjustments/admin-calendar")
@require_api_auth
def api_get_admin_calendar_adjustments(user_session, guild_id):
    """
    Get pending adjustment requests grouped by date for admin calendar view.
    Returns data for the entire guild (all employees) for the specified month.
    
    Query params:
        year: Target year (required, e.g. 2025)
        month: Target month 1-12 (required, e.g. 11)
    
    Access control:
    - Admin only (verified via check_user_admin_realtime)
    """
    try:
        import calendar as cal_module
        from collections import defaultdict
        
        # Input validation
        if not guild_id.isdigit() or len(guild_id) > 20:
            return jsonify({'success': False, 'error': 'Invalid guild ID format'}), 400
        
        # Check guild has paid access
        access_status = check_guild_paid_access(guild_id)
        if not access_status['bot_invited'] or not access_status['bot_access_paid']:
            return jsonify({'success': False, 'error': 'Server does not have paid access'}), 403
        
        # Verify admin access
        admin_status = check_user_admin_realtime(user_session['user_id'], guild_id)
        if not admin_status.get('is_admin', False):
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        
        # Get and validate query parameters
        year_str = request.args.get('year')
        month_str = request.args.get('month')
        
        if not year_str or not month_str:
            return jsonify({'success': False, 'error': 'Missing required parameters: year and month'}), 400
        
        try:
            year = int(year_str)
            month = int(month_str)
        except ValueError:
            return jsonify({'success': False, 'error': 'Invalid year or month format'}), 400
        
        if not (1 <= month <= 12):
            return jsonify({'success': False, 'error': 'Month must be 1-12'}), 400
        if not (2020 <= year <= 2100):
            return jsonify({'success': False, 'error': 'Invalid year'}), 400
        
        # Calculate date range for the month
        first_day = datetime(year, month, 1, tzinfo=timezone.utc)
        last_day_num = cal_module.monthrange(year, month)[1]
        last_day = datetime(year, month, last_day_num, 23, 59, 59, tzinfo=timezone.utc)
        
        # Query pending adjustment requests for the guild in the date range
        # Use session_date if available, otherwise fall back to created_at date
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT r.id, r.guild_id, r.user_id, r.request_type, r.reason,
                       r.original_session_id, r.original_clock_in, r.original_clock_out,
                       r.requested_clock_in, r.requested_clock_out,
                       r.session_date, r.created_at, r.status,
                       COALESCE(r.session_date, DATE(r.created_at)) as effective_date,
                       COALESCE(p.display_name, p.full_name, CAST(r.user_id AS TEXT)) as user_name,
                       p.avatar_url
                FROM time_adjustment_requests r
                LEFT JOIN employee_profiles p ON r.user_id = p.user_id AND r.guild_id = p.guild_id
                WHERE r.guild_id = %s 
                  AND r.status = 'pending'
                  AND COALESCE(r.session_date, DATE(r.created_at)) >= %s
                  AND COALESCE(r.session_date, DATE(r.created_at)) <= %s
                ORDER BY COALESCE(r.session_date, DATE(r.created_at)), r.created_at
            """, (int(guild_id), first_day.date(), last_day.date()))
            
            rows = cursor.fetchall()
        
        # Group requests by date
        days_dict = defaultdict(list)
        total_pending = 0
        
        for row in rows:
            row_dict = dict(row)
            effective_date = row_dict.get('effective_date')
            
            if effective_date:
                date_str = effective_date.isoformat() if hasattr(effective_date, 'isoformat') else str(effective_date)
            else:
                continue
            
            # Build request object
            request_obj = {
                'id': row_dict['id'],
                'user_id': str(row_dict['user_id']),
                'user_name': row_dict.get('user_name') or str(row_dict['user_id']),
                'request_type': row_dict['request_type'],
                'reason': row_dict.get('reason'),
                'original_clock_in': row_dict['original_clock_in'].isoformat() if row_dict.get('original_clock_in') else None,
                'original_clock_out': row_dict['original_clock_out'].isoformat() if row_dict.get('original_clock_out') else None,
                'requested_clock_in': row_dict['requested_clock_in'].isoformat() if row_dict.get('requested_clock_in') else None,
                'requested_clock_out': row_dict['requested_clock_out'].isoformat() if row_dict.get('requested_clock_out') else None,
                'created_at': row_dict['created_at'].isoformat() if row_dict.get('created_at') else None,
                'status': row_dict['status']
            }
            
            days_dict[date_str].append(request_obj)
            total_pending += 1
        
        # Build days array
        days = []
        for date_str, requests_list in sorted(days_dict.items()):
            days.append({
                'date': date_str,
                'pending_count': len(requests_list),
                'requests': requests_list
            })
        
        return jsonify({
            'success': True,
            'data': {
                'year': year,
                'month': month,
                'days': days,
                'total_pending': total_pending
            }
        })
        
    except Exception as e:
        app.logger.error(f"Error fetching admin calendar adjustments: {e}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/api/guild/<guild_id>/adjustments/resolved")
@require_api_auth
def api_get_resolved_adjustments(user_session, guild_id):
    """
    Get resolved (approved/denied) adjustment requests for the entire guild.
    Returns the last 50 resolved requests, most recently resolved first.
    
    Access control:
    - Admin only (verified via check_user_admin_realtime)
    """
    try:
        if not guild_id.isdigit() or len(guild_id) > 20:
            return jsonify({'success': False, 'error': 'Invalid guild ID format'}), 400
        
        access_status = check_guild_paid_access(guild_id)
        if not access_status['bot_invited'] or not access_status['bot_access_paid']:
            return jsonify({'success': False, 'error': 'Server does not have paid access'}), 403
        
        admin_status = check_user_admin_realtime(user_session['user_id'], guild_id)
        if not admin_status.get('is_admin', False):
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT r.id, r.user_id, r.request_type, r.reason, r.status,
                       r.reviewed_at, r.reviewed_by, r.created_at,
                       COALESCE(p.display_name, p.full_name, CONCAT(p.first_name, ' ', p.last_name)) as display_name
                FROM time_adjustment_requests r
                LEFT JOIN employee_profiles p ON r.user_id = p.user_id AND r.guild_id = p.guild_id
                WHERE r.guild_id = %s AND r.status IN ('approved', 'denied')
                ORDER BY r.reviewed_at DESC NULLS LAST
                LIMIT 50
            """, (int(guild_id),))
            
            rows = cursor.fetchall()
        
        requests_list = []
        for row in rows:
            row_dict = dict(row)
            requests_list.append({
                'id': row_dict['id'],
                'user_id': str(row_dict['user_id']),
                'display_name': row_dict.get('display_name') or str(row_dict['user_id']),
                'request_type': row_dict['request_type'],
                'reason': row_dict.get('reason'),
                'status': row_dict['status'],
                'reviewed_at': row_dict['reviewed_at'].isoformat() if row_dict.get('reviewed_at') else None,
                'reviewed_by': str(row_dict['reviewed_by']) if row_dict.get('reviewed_by') else None,
                'created_at': row_dict['created_at'].isoformat() if row_dict.get('created_at') else None
            })
        
        return jsonify({
            'success': True,
            'requests': requests_list
        })
        
    except Exception as e:
        app.logger.error(f"Error fetching resolved adjustments: {e}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/api/guild/<guild_id>/employee/<user_id>/monthly-timecard")
@require_api_auth
def api_get_monthly_timecard(user_session, guild_id, user_id):
    """
    Get monthly timecard data for calendar view.
    Returns sessions grouped by date with daily totals.
    
    Access control:
    - Employees can view their OWN calendar
    - Admins can view any employee's calendar
    
    Query params:
        year: Target year (default: current year)
        month: Target month 1-12 (default: current month)
        timezone: Guild timezone (default: fetch from guild settings)
    """
    try:
        # Input validation
        if not guild_id.isdigit() or len(guild_id) > 20:
            return jsonify({'success': False, 'error': 'Invalid guild ID format'}), 400
        if not user_id.isdigit() or len(user_id) > 20:
            return jsonify({'success': False, 'error': 'Invalid user ID format'}), 400
        
        # Check guild has paid access
        access_status = check_guild_paid_access(guild_id)
        if not access_status['bot_invited'] or not access_status['bot_access_paid']:
            return jsonify({'success': False, 'error': 'Server does not have paid access'}), 403
        
        # Authorization: allow if viewing own data OR if admin
        current_user_id = str(user_session.get('user_id', ''))
        is_own_data = current_user_id == str(user_id)
        
        if not is_own_data:
            # Check if user is admin to view others' data
            admin_status = check_user_admin_realtime(user_session['user_id'], guild_id)
            if not admin_status.get('is_admin', False):
                return jsonify({'success': False, 'error': 'Access denied - you can only view your own calendar'}), 403
        
        # Get query parameters
        now = datetime.now(timezone.utc)
        year = int(request.args.get('year', now.year))
        month = int(request.args.get('month', now.month))
        
        # Validate month/year
        if not (1 <= month <= 12):
            return jsonify({'success': False, 'error': 'Month must be 1-12'}), 400
        if not (2020 <= year <= 2100):
            return jsonify({'success': False, 'error': 'Invalid year'}), 400
        
        # Get guild timezone
        guild_tz_str = request.args.get('timezone')
        if not guild_tz_str:
            with get_db() as conn:
                cursor = conn.execute(
                    "SELECT timezone FROM guild_settings WHERE guild_id = %s",
                    (int(guild_id),)
                )
                row = cursor.fetchone()
                guild_tz_str = row['timezone'] if row else 'America/New_York'
        
        # Calculate date range for the month
        import calendar
        from datetime import datetime as dt
        import pytz
        
        guild_tz = pytz.timezone(guild_tz_str)
        first_day = dt(year, month, 1, 0, 0, 0)
        last_day_num = calendar.monthrange(year, month)[1]
        last_day = dt(year, month, last_day_num, 23, 59, 59)
        
        # Convert to UTC for database query (sessions stored in UTC)
        first_day_utc = guild_tz.localize(first_day).astimezone(pytz.utc)
        last_day_utc = guild_tz.localize(last_day).astimezone(pytz.utc)
        
        # Query sessions for the month
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT 
                    id,
                    clock_in,
                    clock_out,
                    duration_seconds,
                    DATE(clock_in AT TIME ZONE 'UTC' AT TIME ZONE %s) as work_date
                FROM sessions
                WHERE guild_id = %s
                  AND user_id = %s
                  AND clock_in >= %s
                  AND clock_in <= %s
                ORDER BY clock_in ASC
            """, (guild_tz_str, int(guild_id), int(user_id), first_day_utc, last_day_utc))
            
            sessions = cursor.fetchall()
        
        # Group sessions by date
        sessions_by_date = {}
        for session in sessions:
            date_key = session['work_date'].isoformat()
            
            if date_key not in sessions_by_date:
                sessions_by_date[date_key] = {
                    'date': date_key,
                    'sessions': [],
                    'total_seconds': 0,
                    'total_hours': 0
                }
            
            # Convert timestamps to guild timezone for display
            clock_in_local = session['clock_in'].replace(tzinfo=pytz.utc).astimezone(guild_tz) if session['clock_in'] else None
            clock_out_local = session['clock_out'].replace(tzinfo=pytz.utc).astimezone(guild_tz) if session['clock_out'] else None
            
            session_data = {
                'id': session['id'],
                'clock_in': clock_in_local.isoformat() if clock_in_local else None,
                'clock_out': clock_out_local.isoformat() if clock_out_local else None,
                'duration_seconds': session['duration_seconds'] or 0
            }
            
            sessions_by_date[date_key]['sessions'].append(session_data)
            if session['duration_seconds']:
                sessions_by_date[date_key]['total_seconds'] += session['duration_seconds']
        
        # Calculate total hours for each date
        for date_key in sessions_by_date:
            total_seconds = sessions_by_date[date_key]['total_seconds']
            sessions_by_date[date_key]['total_hours'] = round(total_seconds / 3600, 2)
        
        # Fetch adjustment requests for this month to show status on calendar
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT 
                    id,
                    session_date,
                    original_session_id,
                    request_type,
                    status,
                    requested_clock_in,
                    requested_clock_out,
                    reason,
                    reviewed_by,
                    reviewed_at,
                    created_at
                FROM time_adjustment_requests
                WHERE guild_id = %s
                  AND user_id = %s
                  AND (
                      session_date >= %s AND session_date <= %s
                      OR (session_date IS NULL AND created_at >= %s AND created_at <= %s)
                  )
                ORDER BY created_at DESC
            """, (int(guild_id), int(user_id), 
                  f"{year}-{month:02d}-01", f"{year}-{month:02d}-{last_day_num}",
                  first_day_utc, last_day_utc))
            
            adjustments = cursor.fetchall()
        
        # Map adjustments to their dates
        adjustments_by_date = {}
        for adj in adjustments:
            if adj['session_date']:
                adj_date_key = adj['session_date'].isoformat()
            elif adj['requested_clock_in']:
                # Use requested_clock_in date if session_date not set
                adj_in_local = adj['requested_clock_in'].replace(tzinfo=pytz.utc).astimezone(guild_tz)
                adj_date_key = adj_in_local.strftime('%Y-%m-%d')
            else:
                continue
                
            if adj_date_key not in adjustments_by_date:
                adjustments_by_date[adj_date_key] = []
            
            adjustments_by_date[adj_date_key].append({
                'id': adj['id'],
                'request_type': adj['request_type'],
                'status': adj['status'],
                'reason': adj['reason'],
                'requested_clock_in': adj['requested_clock_in'].isoformat() if adj['requested_clock_in'] else None,
                'requested_clock_out': adj['requested_clock_out'].isoformat() if adj['requested_clock_out'] else None,
                'reviewed_by': str(adj['reviewed_by']) if adj['reviewed_by'] else None,
                'reviewed_at': adj['reviewed_at'].isoformat() if adj['reviewed_at'] else None,
                'created_at': adj['created_at'].isoformat() if adj['created_at'] else None
            })
        
        # Merge adjustments into session data and calculate day status
        for date_key in sessions_by_date:
            day_data = sessions_by_date[date_key]
            day_adjustments = adjustments_by_date.get(date_key, [])
            day_data['adjustments'] = day_adjustments
            
            # Determine overall status for the day
            # Priority: pending > approved/denied (show most relevant)
            if any(adj['status'] == 'pending' for adj in day_adjustments):
                day_data['adjustment_status'] = 'pending'
            elif any(adj['status'] == 'approved' for adj in day_adjustments):
                day_data['adjustment_status'] = 'approved'
            elif any(adj['status'] == 'denied' for adj in day_adjustments):
                day_data['adjustment_status'] = 'denied'
            else:
                day_data['adjustment_status'] = None
        
        # Convert to list sorted by date
        calendar_data = sorted(sessions_by_date.values(), key=lambda x: x['date'])
        
        return jsonify({
            'success': True,
            'data': {
                'year': year,
                'month': month,
                'timezone': guild_tz_str,
                'days': calendar_data
            }
        })
        
    except ValueError as e:
        app.logger.error(f"Invalid parameter in monthly timecard request: {e}")
        return jsonify({'success': False, 'error': 'Invalid parameters'}), 400
    except Exception as e:
        app.logger.error(f"Error fetching monthly timecard: {e}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Failed to fetch timecard data'}), 500

@app.route("/api/guild/<guild_id>/clock-out", methods=["POST"])
@require_api_auth
def api_clock_out(user_session, guild_id):
    """
    Clock out the current user from their active session.
    
    Validates that the user has an active session (clock_out IS NULL)
    and updates it with the current time as clock_out.
    """
    try:
        if not guild_id.isdigit() or len(guild_id) > 20:
            return jsonify({'success': False, 'error': 'Invalid guild ID'}), 400
        
        guild_id_int = int(guild_id)
        user_id = int(user_session['user_id'])
        
        access_status = check_guild_paid_access(guild_id)
        if not access_status['bot_invited'] or not access_status['bot_access_paid']:
            return jsonify({'success': False, 'error': 'Server does not have paid access'}), 403
        
        with get_db() as conn:
            if conn is None:
                app.logger.error("Database connection failed in api_clock_out")
                return jsonify({'success': False, 'error': 'Database connection error'}), 500
                
            cursor = conn.execute("""
                SELECT id, clock_in, clock_out
                FROM sessions
                WHERE guild_id = %s AND user_id = %s AND clock_out IS NULL
                ORDER BY clock_in DESC
                LIMIT 1
            """, (guild_id_int, user_id))
            
            active_session = cursor.fetchone()
            
            if not active_session:
                return jsonify({'success': False, 'error': 'No active session found'}), 404
            
            session_id = active_session['id']
            clock_in = active_session['clock_in']
            clock_out_time = datetime.now(timezone.utc)
            
            if clock_in.tzinfo is None:
                clock_in = clock_in.replace(tzinfo=timezone.utc)
            
            duration_seconds = int((clock_out_time - clock_in).total_seconds())
            
            conn.execute("""
                UPDATE sessions
                SET clock_out = %s, duration_seconds = %s
                WHERE id = %s
            """, (clock_out_time, duration_seconds, session_id))
        
        return jsonify({
            'success': True,
            'message': 'Successfully clocked out',
            'session': {
                'id': session_id,
                'clock_in': clock_in.isoformat(),
                'clock_out': clock_out_time.isoformat(),
                'duration_seconds': duration_seconds
            }
        })
        
    except Exception as e:
        app.logger.error(f"Error clocking out: {e}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Failed to clock out'}), 500

@app.route("/api/guild/<guild_id>/employees/<user_id>/clock-out", methods=["POST"])
@require_paid_api_access
def api_admin_clock_out_employee(user_session, guild_id, user_id):
    """
    Admin endpoint to clock out a specific employee.
    
    This allows admins to manually clock out employees from the dashboard.
    Validates that the target user has an active session (clock_out IS NULL)
    and updates it with the current time as clock_out.
    """
    try:
        if not guild_id.isdigit() or len(guild_id) > 20:
            return jsonify({'success': False, 'error': 'Invalid guild ID'}), 400
        
        if not user_id.isdigit() or len(user_id) > 20:
            return jsonify({'success': False, 'error': 'Invalid user ID'}), 400
        
        guild_id_int = int(guild_id)
        user_id_int = int(user_id)
        
        access_status = check_guild_paid_access(guild_id)
        if not access_status['bot_invited'] or not access_status['bot_access_paid']:
            return jsonify({'success': False, 'error': 'Server does not have paid access'}), 403
        
        # CRITICAL: Verify the caller has admin access to this guild
        admin_status = check_user_admin_realtime(user_session['user_id'], guild_id)
        if not admin_status.get('is_admin', False):
            app.logger.warning(f"Non-admin user {user_session.get('user_id')} attempted to clock out user {user_id} in guild {guild_id}")
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        
        with get_db() as conn:
            if conn is None:
                app.logger.error("Database connection failed in api_admin_clock_out_employee")
                return jsonify({'success': False, 'error': 'Database connection error'}), 500
                
            cursor = conn.execute("""
                SELECT id, clock_in, clock_out
                FROM sessions
                WHERE guild_id = %s AND user_id = %s AND clock_out IS NULL
                ORDER BY clock_in DESC
                LIMIT 1
            """, (guild_id_int, user_id_int))
            
            active_session = cursor.fetchone()
            
            if not active_session:
                return jsonify({'success': False, 'error': 'No active session found for this employee'}), 404
            
            session_id = active_session['id']
            clock_in = active_session['clock_in']
            clock_out_time = datetime.now(timezone.utc)
            
            if clock_in.tzinfo is None:
                clock_in = clock_in.replace(tzinfo=timezone.utc)
            
            duration_seconds = int((clock_out_time - clock_in).total_seconds())
            
            conn.execute("""
                UPDATE sessions
                SET clock_out = %s, duration_seconds = %s
                WHERE id = %s
            """, (clock_out_time, duration_seconds, session_id))
        
        app.logger.info(f"Admin {user_session.get('username')} clocked out user {user_id} in guild {guild_id}")
        
        return jsonify({
            'success': True,
            'message': 'Employee successfully clocked out',
            'session': {
                'id': session_id,
                'clock_in': clock_in.isoformat(),
                'clock_out': clock_out_time.isoformat(),
                'duration_seconds': duration_seconds
            }
        })
        
    except Exception as e:
        app.logger.error(f"Error in admin clock out: {e}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Failed to clock out employee'}), 500

# Employee Detail View API Endpoints
@app.route("/api/guild/<guild_id>/employee/<user_id>/detail")
@require_paid_api_access
def api_get_employee_detail(user_session, guild_id, user_id):
    """
    Get comprehensive employee detail including profile, status, and statistics.
    """
    try:
        from bot import get_active_employees_with_stats
        
        # Get employee data with stats
        timezone_name = request.args.get('timezone', 'America/New_York')
        employees = get_active_employees_with_stats(int(guild_id), timezone_name)
        
        # Find the specific employee
        employee = None
        for emp in employees:
            if str(emp.get('user_id')) == str(user_id):
                employee = emp
                break
        
        # If not in active list, get from database (using Flask's get_db)
        if not employee:
            with get_db() as conn:
                cursor = conn.execute("""
                    SELECT user_id, username, display_name
                    FROM employee_profiles
                    WHERE guild_id = %s AND user_id = %s
                """, (int(guild_id), user_id))
                profile = cursor.fetchone()
                
                if profile:
                    employee = {
                        'user_id': profile['user_id'],
                        'username': profile['username'],
                        'display_name': profile['display_name'],
                        'status': 'clocked_out',
                        'hours_today': 0,
                        'hours_week': 0,
                        'hours_month': 0
                    }
        
        if not employee:
            return jsonify({'success': False, 'error': 'Employee not found'}), 404
        
        # Get total sessions count (using Flask's get_db)
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT COUNT(*) as total_sessions
                FROM sessions
                WHERE guild_id = %s AND user_id = %s
            """, (int(guild_id), user_id))
            result = cursor.fetchone()
            employee['total_sessions'] = result['total_sessions'] if result else 0
        
        return jsonify({'success': True, 'employee': employee})
        
    except Exception as e:
        app.logger.error(f"Error fetching employee detail: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/api/guild/<guild_id>/employee/<user_id>/timecard")
@require_paid_api_access
def api_get_employee_timecard(user_session, guild_id, user_id):
    """
    Get weekly timecard for an employee showing daily clock in/out times.
    """
    try:
        from datetime import date, timedelta
        
        # Get week start (default to current week's Monday)
        week_param = request.args.get('week')
        if week_param:
            week_start = datetime.fromisoformat(week_param).date()
        else:
            today = date.today()
            week_start = today - timedelta(days=today.weekday())
        
        timezone_name = request.args.get('timezone', 'America/New_York')
        
        # Get sessions for the week (using Flask's get_db)
        week_end = week_start + timedelta(days=7)
        
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT clock_in, clock_out, duration_seconds
                FROM sessions
                WHERE guild_id = %s AND user_id = %s
                AND clock_in::date >= %s AND clock_in::date < %s
                ORDER BY clock_in ASC
            """, (int(guild_id), user_id, week_start, week_end))
            sessions = cursor.fetchall()
        
        # Build 7-day structure
        days = []
        week_total_seconds = 0
        day_names = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        
        for i in range(7):
            current_date = week_start + timedelta(days=i)
            day_sessions = [s for s in sessions if s['clock_in'].date() == current_date]
            
            if day_sessions:
                # Use first session of the day
                session = day_sessions[0]
                day_data = {
                    'date': current_date.isoformat(),
                    'day_name': day_names[i],
                    'clock_in': session['clock_in'].isoformat() if session['clock_in'] else None,
                    'clock_out': session['clock_out'].isoformat() if session['clock_out'] else None,
                    'duration_hours': round(session['duration_seconds'] / 3600, 2) if session['duration_seconds'] else 0,
                    'status': 'complete' if session['clock_out'] else 'in_progress'
                }
                week_total_seconds += session['duration_seconds'] or 0
            else:
                day_data = {
                    'date': current_date.isoformat(),
                    'day_name': day_names[i],
                    'clock_in': None,
                    'clock_out': None,
                    'duration_hours': 0,
                    'status': 'absent'
                }
            
            days.append(day_data)
        
        return jsonify({
            'success': True,
            'week_start': week_start.isoformat(),
            'days': days,
            'week_total_hours': round(week_total_seconds / 3600, 2)
        })
        
    except Exception as e:
        app.logger.error(f"Error fetching employee timecard: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/api/guild/<guild_id>/employee/<user_id>/adjustments/recent")
@require_paid_api_access
def api_get_employee_recent_adjustments(user_session, guild_id, user_id):
    """
    Get top 3 most recent adjustment requests for an employee.
    """
    try:
        # Using Flask's get_db for production database
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT id, request_type, status, created_at, reason,
                       original_clock_in, original_clock_out,
                       requested_clock_in, requested_clock_out,
                       reviewed_by, reviewed_at
                FROM time_adjustment_requests
                WHERE guild_id = %s AND user_id = %s
                ORDER BY created_at DESC
                LIMIT 3
            """, (int(guild_id), user_id))
            requests = cursor.fetchall()
        
        serialized_requests = []
        for req in requests:
            req_dict = dict(req)
            for key, value in req_dict.items():
                if isinstance(value, datetime):
                    req_dict[key] = value.isoformat()
            serialized_requests.append(req_dict)
        
        return jsonify({'success': True, 'requests': serialized_requests})
        
    except Exception as e:
        app.logger.error(f"Error fetching recent adjustments: {e}")
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
