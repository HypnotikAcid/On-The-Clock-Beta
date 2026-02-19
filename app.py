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
import pytz
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
def get_current_version():
    try:
        with open('version.json', 'r') as f:
            return json.load(f).get('version', '1.0.0')
    except Exception:
        return "1.0.0"

__version__ = get_current_version()

# Customer-facing update notes (latest first, max 3 shown on dashboard)
# Demo server configuration - grant admin access to all demo server visitors
DEMO_SERVER_ID = '1419894879894507661'

# Demo server allowed role IDs (security: prevent public users from assigning dangerous roles)
DEMO_ALLOWED_ADMIN_ROLES = {'1465149753510596628'}  # Demo Admin role
DEMO_ALLOWED_EMPLOYEE_ROLES = {'1465150374968033340'}  # Demo Employee role

def is_demo_server(guild_id) -> bool:
    """
    Check if guild is the demo server.
    Handles both int and string guild IDs for type safety.

    Args:
        guild_id: Guild ID as int or string

    Returns:
        True if this is the demo server (1419894879894507661)
    """
    return str(guild_id) == DEMO_SERVER_ID

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

def get_employees_for_calendar(*args, **kwargs):
    return _get_bot_func('get_employees_for_calendar')(*args, **kwargs)

def create_adjustment_request(*args, **kwargs):
    return _get_bot_func('create_adjustment_request')(*args, **kwargs)

def get_pending_adjustments(*args, **kwargs):
    return _get_bot_func('get_pending_adjustments')(*args, **kwargs)

def get_user_adjustment_history(*args, **kwargs):
    return _get_bot_func('get_user_adjustment_history')(*args, **kwargs)

def get_all_adjustment_history(*args, **kwargs):
    return _get_bot_func('get_all_adjustment_history')(*args, **kwargs)

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

# Deferred database initialization (runs in background after Flask binds)
def deferred_db_init():
    """Run database migrations and table init in background thread."""
    try:
        print("[STARTUP] Running database migrations...")
        from migrations import run_migrations
        run_migrations()
        print("[STARTUP] Database migrations complete")
    except Exception as e:
        print(f"[WARNING] Migration error (non-fatal): {e}")
    
    try:
        print("[STARTUP] Initializing dashboard tables...")
        init_dashboard_tables()
        print("[STARTUP] Dashboard tables initialized")
    except Exception as e:
        print(f"[WARNING] Dashboard initialization warning: {e}")

# Start bot thread when running under Gunicorn (only in first worker)
if __name__ != '__main__':
    import os
    print("[STARTUP] Flask app initializing under Gunicorn...")
    print(f"[STARTUP] Health check endpoint ready at /health")
    
    worker_id = os.environ.get('GUNICORN_WORKER_ID', '1')
    # Only start bot in first worker to avoid multiple instances
    if worker_id == '1' or 'GUNICORN_WORKER_ID' not in os.environ:
        print("[STARTUP] Deferring database initialization to background thread...")
        db_init_thread = threading.Thread(target=deferred_db_init, daemon=True)
        db_init_thread.start()
        
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
_session_secret = os.environ.get('SESSION_SECRET') or os.environ.get('SECRET_KEY')
if not _session_secret:
    print("[WARNING] Neither SESSION_SECRET nor SECRET_KEY is set - using random key (sessions will reset on restart)")
    _session_secret = secrets.token_hex(32)
app.secret_key = _session_secret
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Fix for Replit reverse proxy - ensures correct scheme/host detection and client IP
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1, x_for=1)  # type: ignore[method-assign]

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
    'premium': os.environ.get('STRIPE_PRICE_PREMIUM'),
    'pro': os.environ.get('STRIPE_PRICE_PRO'),
}
STRIPE_PRICE_IDS_LEGACY = {
    'bot_access': os.environ.get('STRIPE_PRICE_BOT_ACCESS'),
    'retention_7day': os.environ.get('STRIPE_PRICE_RETENTION_7DAY'),
    'retention_30day': os.environ.get('STRIPE_PRICE_RETENTION_30DAY'),
}

# Bot API Configuration
BOT_API_BASE_URL = os.getenv('BOT_API_BASE_URL', 'http://localhost:8081')

def _parse_stickers(value):
    """Parse selected_stickers from database - handles both JSON string and list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        try:
            import json
            parsed = json.loads(value)
            return parsed if isinstance(parsed, list) else []
        except (json.JSONDecodeError, TypeError):
            return []
    return []

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
        conn.execute("""
            CREATE TABLE IF NOT EXISTS oauth_states (
                state TEXT PRIMARY KEY,
                expires_at TEXT NOT NULL,
                metadata TEXT
            )
        """)
        conn.execute("""
            ALTER TABLE oauth_states ADD COLUMN IF NOT EXISTS metadata TEXT
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

# Dashboard tables are initialized in the Gunicorn startup block (deferred)
# This allows the Flask app to bind to port 5000 immediately without blocking on DB

# OAuth Helper Functions
def create_oauth_state(metadata=None):
    """Generate and store OAuth state for CSRF protection.
    Optionally stores metadata (e.g. purchase_intent) that survives cross-domain redirects."""
    state = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
    metadata_json = json.dumps(metadata) if metadata else None
    
    with get_db() as conn:
        conn.execute(
            "INSERT INTO oauth_states (state, expires_at, metadata) VALUES (%s, %s, %s)",
            (state, expires_at.isoformat(), metadata_json)
        )
    return state

def verify_oauth_state(state):
    """Verify OAuth state and delete it. Returns (True, metadata_dict) or (False, None)."""
    with get_db() as conn:
        cursor = conn.execute(
            "SELECT state, metadata FROM oauth_states WHERE state = %s AND expires_at > %s",
            (state, datetime.now(timezone.utc).isoformat())
        )
        result = cursor.fetchone()
        
        if result:
            conn.execute("DELETE FROM oauth_states WHERE state = %s", (state,))
            metadata = None
            if result['metadata']:
                try:
                    metadata = json.loads(result['metadata'])
                except (json.JSONDecodeError, TypeError):
                    pass
            return True, metadata
    return False, None

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
    # Demo server override: Grant admin access to all users for demo exploration
    if is_demo_server(guild_id):
        return {'is_member': True, 'is_admin': True, 'reason': 'demo_server'}
    
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

def get_flask_guild_access(guild_id):
    """Check guild tier, trial status, and exemption for dashboard routes"""
    from entitlements import Entitlements, UserTier
    try:
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT ss.bot_access_paid, ss.retention_tier, ss.grandfathered,
                       gs.trial_start_date
                FROM server_subscriptions ss
                LEFT JOIN guild_settings gs ON ss.guild_id = gs.guild_id
                WHERE ss.guild_id = %s
            """, (int(guild_id),))
            row = cursor.fetchone()
            if not row:
                return {'tier': 'free', 'trial_active': False, 'days_remaining': 0, 'is_exempt': False}
            grandfathered = row.get('grandfathered', False) or False
            tier = Entitlements.get_guild_tier(
                row.get('bot_access_paid', False),
                row.get('retention_tier', 'none'),
                grandfathered
            )
            trial_start = row.get('trial_start_date')
            # Check for owner grants
            grant_cursor = conn.execute("""
                SELECT COUNT(*) as cnt FROM server_subscriptions
                WHERE guild_id = %s AND (grandfathered = true OR bot_access_paid = true)
            """, (int(guild_id),))
            grant_row = grant_cursor.fetchone()
            owner_granted = (grant_row and grant_row['cnt'] > 0) or False
            is_exempt = Entitlements.is_server_exempt(int(guild_id), grandfathered, owner_granted)
            return {
                'tier': tier.value,
                'trial_active': Entitlements.is_trial_active(trial_start),
                'days_remaining': Entitlements.get_trial_days_remaining(trial_start),
                'is_exempt': is_exempt
            }
    except Exception as e:
        app.logger.error(f"Error checking guild access: {e}")
        return {'tier': 'free', 'trial_active': False, 'days_remaining': 0, 'is_exempt': False}

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

    return False

def require_kiosk_access(f):
    """
    Decorator for kiosk routes.
    - Demo server (1419894879894507661): Always allow (for public preview)
    - Production servers: Require Pro tier
    """
    from functools import wraps

    @wraps(f)
    def decorated_function(*args, **kwargs):
        guild_id = kwargs.get('guild_id')
        if not guild_id:
            return jsonify({
                'success': False,
                'error': 'Missing guild_id'
            }), 400

        # Demo server override - allow free exploration
        if is_demo_server(guild_id):
            app.logger.debug(f"Demo server kiosk access granted for guild {guild_id}")
            return f(*args, **kwargs)

        # For production servers, check Pro tier
        try:
            with get_db() as conn:
                cursor = conn.execute("""
                    SELECT bot_access_paid, retention_tier, grandfathered
                    FROM server_subscriptions
                    WHERE guild_id = %s
                """, (int(guild_id),))
                result = cursor.fetchone()

                if not result:
                    return jsonify({
                        'success': False,
                        'error': 'Server not found. Please invite the bot first.',
                        'code': 'NO_SUBSCRIPTION'
                    }), 404

                # Get tier using entitlements
                from entitlements import Entitlements, UserTier
                tier = Entitlements.get_guild_tier(
                    bot_access_paid=result['bot_access_paid'],
                    retention_tier=result['retention_tier'],
                    grandfathered=result.get('grandfathered', False)
                )

                # Check if tier allows kiosk (Pro tier required)
                if tier != UserTier.PRO:
                    return jsonify({
                        'success': False,
                        'error': 'Kiosk mode requires Pro tier subscription',
                        'code': 'PRO_REQUIRED',
                        'current_tier': tier.value,
                        'required_tier': 'pro',
                        'upgrade_url': f'https://ontheclock.app/dashboard/purchase?guild_id={guild_id}'
                    }), 403

                # Pro tier confirmed - proceed
                return f(*args, **kwargs)

        except Exception as e:
            app.logger.error(f"Error checking kiosk access for guild {guild_id}: {e}")
            return jsonify({
                'success': False,
                'error': 'Unable to verify kiosk access'
            }), 500

    return decorated_function

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
                JOIN bot_guilds bg ON CAST(bg.guild_id AS BIGINT) = ep.guild_id
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
                'premium': 'Premium ($8/mo)',
                'pro': 'Pro ($15/mo)',
                'bot_access': 'Bot Access (Legacy)',
                'retention_7day': '7-Day Retention (Legacy)',
                'retention_30day': '30-Day Retention (Legacy)'
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
Time Warden Bot - Purchase Notification
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
        elif event_type == 'customer.subscription.created':
            handle_subscription_change(event['data']['object'])
        elif event_type == 'customer.subscription.updated':
            handle_subscription_change(event['data']['object'])
        elif event_type == 'customer.subscription.deleted':
            handle_subscription_cancellation(event['data']['object'])
        elif event_type == 'invoice.payment_succeeded':
            app.logger.info(f"[OK] Invoice payment succeeded: {event['data']['object'].get('id')}")
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
    """Process a completed checkout session - handles new subscription model"""
    try:
        full_session = stripe.checkout.Session.retrieve(
            session['id'],
            expand=['line_items']
        )
        
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
        
        product_type = None
        all_price_ids = {**STRIPE_PRICE_IDS, **STRIPE_PRICE_IDS_LEGACY}
        for ptype, pid in all_price_ids.items():
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
        subscription_id = session.get('subscription')
        customer_id = session.get('customer')
        
        customer_email = None
        if full_session.customer_details:
            customer_email = full_session.customer_details.get('email')
        
        log_purchase_and_notify(
            guild_id=guild_id,
            guild_name=guild_name,
            customer_email=customer_email,
            customer_id=customer_id,
            product_type=product_type,
            amount_cents=amount_cents,
            stripe_session_id=session['id']
        )
        
        if product_type in ('premium', 'bot_access'):
            flask_set_bot_access(guild_id, True)
            with get_db() as conn:
                conn.execute("""
                    INSERT INTO server_subscriptions (guild_id, subscription_id, customer_id, status, bot_access_paid, tier)
                    VALUES (%s, %s, %s, 'active', TRUE, 'premium')
                    ON CONFLICT(guild_id) DO UPDATE SET 
                        subscription_id = COALESCE(%s, server_subscriptions.subscription_id),
                        customer_id = COALESCE(%s, server_subscriptions.customer_id),
                        status = 'active',
                        bot_access_paid = TRUE,
                        tier = 'premium'
                """, (guild_id, subscription_id, customer_id, subscription_id, customer_id))
            app.logger.info(f"[OK] Premium subscription activated for server {guild_id}")
            
        elif product_type == 'pro':
            flask_set_bot_access(guild_id, True)
            flask_set_retention_tier(guild_id, '30day')
            with get_db() as conn:
                conn.execute("""
                    INSERT INTO server_subscriptions (guild_id, subscription_id, customer_id, status, bot_access_paid, retention_tier, tier)
                    VALUES (%s, %s, %s, 'active', TRUE, '30day', 'pro')
                    ON CONFLICT(guild_id) DO UPDATE SET 
                        subscription_id = COALESCE(%s, server_subscriptions.subscription_id),
                        customer_id = COALESCE(%s, server_subscriptions.customer_id),
                        status = 'active',
                        bot_access_paid = TRUE,
                        retention_tier = '30day',
                        tier = 'pro'
                """, (guild_id, subscription_id, customer_id, subscription_id, customer_id))
            app.logger.info(f"[OK] Pro subscription activated for server {guild_id}")
        
        elif product_type in ('retention_7day', 'retention_30day'):
            retention_val = '7day' if product_type == 'retention_7day' else '30day'
            flask_set_retention_tier(guild_id, retention_val)
            with get_db() as conn:
                conn.execute("""
                    INSERT INTO server_subscriptions (guild_id, subscription_id, customer_id, status, bot_access_paid, retention_tier)
                    VALUES (%s, %s, %s, 'active', TRUE, %s)
                    ON CONFLICT(guild_id) DO UPDATE SET 
                        subscription_id = COALESCE(%s, server_subscriptions.subscription_id),
                        customer_id = COALESCE(%s, server_subscriptions.customer_id),
                        status = 'active',
                        bot_access_paid = TRUE,
                        retention_tier = %s
                """, (guild_id, subscription_id, customer_id, retention_val, subscription_id, customer_id, retention_val))
            app.logger.info(f"[OK] Legacy {retention_val} retention granted for server {guild_id}")
        
        trial_applied = session.get('metadata', {}).get('trial_applied')
        if trial_applied == 'true':
            try:
                with get_db() as conn:
                    conn.execute("""
                        INSERT INTO trial_usage (guild_id, granted_by, grant_type)
                        VALUES (%s, %s, 'checkout')
                        ON CONFLICT (guild_id) DO NOTHING
                    """, (guild_id, customer_id or 'stripe'))
                app.logger.info(f"[OK] Trial usage recorded for server {guild_id} via checkout")
            except Exception as trial_error:
                app.logger.warning(f"Could not record trial usage: {trial_error}")
            
    except Exception as e:
        app.logger.error(f"[ERROR] Error processing checkout session: {e}")
        app.logger.error(traceback.format_exc())

def handle_subscription_change(subscription):
    """Handle subscription create/update events - status changes, plan changes"""
    try:
        subscription_id = subscription.get('id')
        status = subscription.get('status')
        
        if not subscription_id:
            app.logger.error("[ERROR] No subscription ID in subscription change event")
            return
        
        guild_id = None
        metadata = subscription.get('metadata', {})
        if metadata.get('guild_id'):
            guild_id = int(metadata['guild_id'])
        
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT guild_id FROM server_subscriptions WHERE subscription_id = %s",
                (subscription_id,)
            )
            result = cursor.fetchone()
            
            if result:
                guild_id = result['guild_id']
            elif guild_id:
                conn.execute("""
                    INSERT INTO server_subscriptions (guild_id, subscription_id, customer_id, status, bot_access_paid)
                    VALUES (%s, %s, %s, %s, TRUE)
                    ON CONFLICT(guild_id) DO UPDATE SET
                        subscription_id = %s,
                        status = %s,
                        bot_access_paid = TRUE
                """, (guild_id, subscription_id, subscription.get('customer'), status, subscription_id, status))
                app.logger.info(f"[OK] Created subscription record for server {guild_id} from lifecycle event")
            else:
                app.logger.warning(f"[WARN] No server found for subscription {subscription_id} and no metadata")
                return
            
            conn.execute("""
                UPDATE server_subscriptions 
                SET status = %s
                WHERE subscription_id = %s
            """, (status, subscription_id))
            
            if status in ('active', 'trialing'):
                flask_set_bot_access(guild_id, True)
                app.logger.info(f"[OK] Subscription {subscription_id} active for server {guild_id}")
            elif status in ('past_due', 'unpaid'):
                app.logger.warning(f"[WARN] Subscription {subscription_id} is {status} for server {guild_id}")
            elif status == 'canceled':
                flask_set_bot_access(guild_id, False)
                app.logger.info(f"[OK] Subscription canceled, access revoked for server {guild_id}")
        
    except Exception as e:
        app.logger.error(f"[ERROR] Error processing subscription change: {e}")
        app.logger.error(traceback.format_exc())

def handle_subscription_cancellation(subscription):
    """Handle subscription deletion/cancellation events"""
    try:
        subscription_id = subscription.get('id')
        customer_id = subscription.get('customer')
        
        if not subscription_id:
            app.logger.error("[ERROR] No subscription ID in cancellation event")
            return
        
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT guild_id FROM server_subscriptions 
                WHERE subscription_id = %s OR customer_id = %s
            """, (subscription_id, customer_id))
            result = cursor.fetchone()
            
            if result:
                guild_id = result['guild_id']
                
                flask_set_bot_access(guild_id, False)
                flask_set_retention_tier(guild_id, 'none')
                
                conn.execute("""
                    UPDATE server_subscriptions 
                    SET status = 'canceled', subscription_id = NULL, bot_access_paid = FALSE
                    WHERE guild_id = %s
                """, (guild_id,))
                
                app.logger.info(f"[OK] Subscription canceled for server {guild_id}, access revoked")
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
    try:
        with open('public_roadmap.json', 'r') as f:
            version_info = json.load(f)
    except Exception:
        version_info = {
            "version": "1.0.0",
            "recent_updates": ["Initial release"],
            "roadmap": ["Mobile improvements", "Shift scheduling"]
        }
    return render_template('landing.html', version_info=version_info)

@app.route("/dashboard/invite")
def dashboard_invite():
    """Page shown when user tries to access dashboard but bot is not invited to their server."""
    discord_client_id = os.getenv("DISCORD_CLIENT_ID", "1418446753379913809")
    invite_url = f"https://discord.com/oauth2/authorize?client_id={discord_client_id}&permissions=8&scope=bot%20applications.commands"
    return render_template('dashboard_invite.html', invite_url=invite_url)

@app.route("/dashboard/purchase")
def dashboard_purchase():
    """Page shown when user tries to access dashboard but server doesn't have paid bot access."""
    guild_id = request.args.get('guild_id')
    access = get_flask_guild_access(guild_id) if guild_id else None
    return render_template('dashboard_purchase.html', guild_id=guild_id, access=access)

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
        
        state_valid, state_metadata = verify_oauth_state(state)
        if not state_valid:
            app.logger.error(f"Invalid OAuth state: {state[:8]}... (CSRF check failed)")
            return "<h1>Authentication Error</h1><p>Security validation failed. Please try again.</p><a href='/'>Return Home</a>", 400
        
        redirect_uri = get_redirect_uri()
        app.logger.info(f"Exchanging code for token with redirect_uri: {redirect_uri}")
        token_data = exchange_code_for_token(code, redirect_uri)
        access_token = token_data['access_token']
        refresh_token = token_data.get('refresh_token')
        
        app.logger.info("Fetching user info from Discord")
        user_data = get_user_info(access_token)
        app.logger.info(f"User authenticated: {user_data.get('username')}")
        
        app.logger.info("Fetching user guilds")
        guilds_data = get_user_guilds(access_token)
        app.logger.info(f"Found {len(guilds_data)} guilds")
        
        session_id = create_user_session(user_data, access_token, refresh_token, guilds_data)
        session['session_id'] = session_id
        app.logger.info(f"Session created: {session_id[:8]}...")
        
        purchase_intent = (state_metadata or {}).get('purchase_intent') or session.get('purchase_intent')
        if purchase_intent:
            session['purchase_intent'] = purchase_intent
            app.logger.info(f"Purchase flow detected via state metadata, redirecting to server selection for: {purchase_intent.get('product_type')}")
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

        # Check if user is bot owner
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        is_bot_owner = str(user_session.get('user_id')) == str(bot_owner_id)

        # Create a modified user session with both admin and employee guilds
        dashboard_data = {
            **user_session,
            'guilds': admin_guilds,  # Maintain backward compatibility
            'admin_guilds': admin_guilds,
            'employee_guilds': employee_guilds,
            'total_guilds': len(user_session.get('guilds', [])),
            'filtered_count': len(admin_guilds) + len(employee_guilds),
            'is_bot_owner': is_bot_owner
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


def get_server_page_context(user_session, guild_id, active_page):
    """
    Helper to build common context for server-specific dashboard pages.
    Returns (context_dict, error_response) - error_response is None if successful.
    """
    guild, access_level = verify_guild_access(user_session, guild_id, allow_employee=True)
    if not guild:
        return None, redirect('/dashboard')


    is_demo_server_flag = is_demo_server(guild_id)
    view_as_employee = False
    last_demo_reset = None

    if is_demo_server_flag:
        view_as_employee = request.args.get('view_as') == 'employee' or session.get('demo_view_as_employee', False)
        if request.args.get('view_as') == 'employee':
            session['demo_view_as_employee'] = True
            view_as_employee = True
        elif request.args.get('view_as') == 'admin':
            session['demo_view_as_employee'] = False
            view_as_employee = False
        
        if view_as_employee and access_level == 'admin':
            access_level = 'employee'
    
    user_id = user_session.get('user_id')
    is_also_employee = False
    pending_adjustments = 0
    show_tz_reminder = False
    server_settings = {}
    
    with get_db() as conn:
        if access_level == 'admin':
            cursor = conn.execute("""
                SELECT COUNT(*) as count FROM time_adjustment_requests 
                WHERE guild_id = %s AND status = 'pending'
            """, (int(guild_id),))
            result = cursor.fetchone()
            pending_adjustments = result['count'] if result else 0
            
            cursor = conn.execute("""
                SELECT 1 FROM employee_profiles 
                WHERE guild_id = %s AND user_id = %s AND is_active = TRUE
            """, (int(guild_id), user_id))
            is_also_employee = cursor.fetchone() is not None
            
            cursor = conn.execute("""
                SELECT timezone FROM guild_settings WHERE guild_id = %s
            """, (int(guild_id),))
            tz_row = cursor.fetchone()
            show_tz_reminder = not tz_row or not tz_row.get('timezone')
        
        cursor = conn.execute("""
            SELECT bot_access_paid, retention_tier, tier, COALESCE(grandfathered, FALSE) as grandfathered
            FROM server_subscriptions WHERE guild_id = %s
        """, (int(guild_id),))
        sub_row = cursor.fetchone()
        if sub_row:
            server_settings = {
                'bot_access_paid': sub_row.get('bot_access_paid', False),
                'retention_tier': sub_row.get('retention_tier', 'none'),
                'tier': sub_row.get('tier', 'free'),
                'grandfathered': bool(sub_row.get('grandfathered', False))
            }
        
        # Get demo reset info if this is the demo server
        if is_demo_server_flag:
            cursor = conn.execute("""
                SELECT last_demo_reset FROM guild_settings WHERE guild_id = %s
            """, (int(guild_id),))
            demo_row = cursor.fetchone()
            if demo_row and demo_row.get('last_demo_reset'):
                last_demo_reset = demo_row['last_demo_reset']
    
    context = {
        'user': user_session,
        'server': {
            'id': guild_id,
            'name': guild.get('name', 'Unknown Server'),
            'icon': guild.get('icon')
        },
        'user_role': access_level,
        'is_also_employee': is_also_employee,
        'active_page': active_page,
        'pending_adjustments': pending_adjustments,
        'show_tz_reminder': show_tz_reminder,
        'server_settings': server_settings,
        'is_demo_server': is_demo_server_flag,
        'view_as_employee': view_as_employee,
        'last_demo_reset': last_demo_reset
    }
    
    return context, None


def check_premium_access(context, feature_name='advanced_settings'):
    """
    Check if the server has premium access for a given feature.
    Returns None if access granted, or a redirect/template response if denied.
    """
    server_settings = context.get('server_settings', {})
    bot_access_paid = server_settings.get('bot_access_paid', False)
    retention_tier = server_settings.get('retention_tier', 'none')
    tier = server_settings.get('tier', 'free')
    
    is_grandfathered = tier == 'grandfathered' or server_settings.get('grandfathered', False)
    guild_tier = Entitlements.get_guild_tier(bot_access_paid, retention_tier, is_grandfathered)
    user_role = UserRole.ADMIN if context['user_role'] == 'admin' else UserRole.EMPLOYEE
    
    if not Entitlements.can_access_feature(guild_tier, user_role, feature_name):
        gate_context = context.copy()
        gate_context['premium_required'] = True
        gate_context['premium_feature'] = feature_name
        gate_context['locked_message'] = Entitlements.get_locked_message(feature_name)
        return render_template('dashboard_pages/premium_required.html', **gate_context)
    
    return None


def check_premium_api_access(guild_id, feature_name='advanced_settings'):
    """
    Check if a server has premium access for API endpoints.
    Returns None if access granted, or a JSON error response if denied.
    For use in API routes that don't have the full page context.
    """
    try:
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT bot_access_paid, retention_tier, tier, COALESCE(grandfathered, FALSE) as grandfathered
                FROM server_subscriptions WHERE guild_id = %s
            """, (int(guild_id),))
            sub_row = cursor.fetchone()
            
            if not sub_row:
                return jsonify({'success': False, 'error': 'Premium feature - please upgrade', 'premium_required': True}), 403
            
            bot_access_paid = sub_row.get('bot_access_paid', False)
            retention_tier = sub_row.get('retention_tier', 'none')
            tier = sub_row.get('tier', 'free')
            is_grandfathered = tier == 'grandfathered' or bool(sub_row.get('grandfathered', False))
            
            guild_tier = Entitlements.get_guild_tier(bot_access_paid, retention_tier, is_grandfathered)
            
            if not Entitlements.can_access_feature(guild_tier, UserRole.ADMIN, feature_name):
                locked_msg = Entitlements.get_locked_message(feature_name)
                return jsonify({
                    'success': False, 
                    'error': locked_msg['message'],
                    'premium_required': True,
                    'upgrade_price': locked_msg['beta_price']
                }), 403
            
            return None
    except Exception as e:
        logging.error(f"Premium API check error: {e}")
        return jsonify({'success': False, 'error': 'Premium feature - please upgrade', 'premium_required': True}), 403


@app.route("/setup-wizard")
@require_auth
def setup_wizard(user_session):
    """Guided setup wizard for first-time server admins"""
    guild_id = request.args.get('guild_id')

    # Validate guild_id parameter
    if not guild_id or not guild_id.isdigit() or len(guild_id) > 20:
        return redirect('/dashboard')

    # Verify user has admin access to this guild
    context, error = get_server_page_context(user_session, guild_id, 'setup-wizard')
    if error:
        return error

    # Only admins can access setup wizard
    if context['user_role'] != 'admin':
        return redirect(f'/dashboard/server/{guild_id}')

    # Render setup wizard with guild context
    return render_template('setup_wizard.html',
                          guild_id=guild_id,
                          guild_name=context.get('guild_name', 'Unknown Server'),
                          user_session=user_session)


@app.route("/templates/setup_wizard_steps/<step_file>")
@require_auth
def setup_wizard_step(user_session, step_file):
    """Serve setup wizard step HTML files for AJAX loading"""
    # Validate step file name (only allow step1.html through step5.html)
    if not step_file.startswith('step') or not step_file.endswith('.html'):
        return "Invalid step file", 404

    # Extract step number and validate range
    try:
        step_num = int(step_file.replace('step', '').replace('.html', ''))
        if step_num < 1 or step_num > 5:
            return "Invalid step number", 404
    except ValueError:
        return "Invalid step file", 404

    # Render the step template
    return render_template(f'setup_wizard_steps/{step_file}')


@app.route("/dashboard/server/<guild_id>")
@require_auth
def dashboard_server_overview(user_session, guild_id):
    """Server overview page"""
    if not guild_id.isdigit() or len(guild_id) > 20:
        return redirect('/dashboard')
    
    context, error = get_server_page_context(user_session, guild_id, 'overview')
    if error:
        return error
    
    return render_template('dashboard_pages/server_overview.html', **context)


@app.route("/dashboard/server/<guild_id>/admin-roles")
@require_auth
def dashboard_admin_roles(user_session, guild_id):
    """Admin roles management page"""
    if not guild_id.isdigit() or len(guild_id) > 20:
        return redirect('/dashboard')
    
    context, error = get_server_page_context(user_session, guild_id, 'admin-roles')
    if error:
        return error
    
    if context['user_role'] != 'admin':
        return redirect(f'/dashboard/server/{guild_id}')
    
    return render_template('dashboard_pages/admin_roles.html', **context)


@app.route("/dashboard/server/<guild_id>/employee-roles")
@require_auth
def dashboard_employee_roles(user_session, guild_id):
    """Employee roles management page"""
    if not guild_id.isdigit() or len(guild_id) > 20:
        return redirect('/dashboard')
    
    context, error = get_server_page_context(user_session, guild_id, 'employee-roles')
    if error:
        return error
    
    if context['user_role'] != 'admin':
        return redirect(f'/dashboard/server/{guild_id}')
    
    return render_template('dashboard_pages/employee_roles.html', **context)


@app.route("/dashboard/server/<guild_id>/email")
@require_auth
def dashboard_email_settings(user_session, guild_id):
    """Email settings page"""
    if not guild_id.isdigit() or len(guild_id) > 20:
        return redirect('/dashboard')
    
    context, error = get_server_page_context(user_session, guild_id, 'email')
    if error:
        return error
    
    if context['user_role'] != 'admin':
        return redirect(f'/dashboard/server/{guild_id}')
    
    premium_block = check_premium_access(context, 'email_automation')
    if premium_block:
        return premium_block
    
    return render_template('dashboard_pages/email_settings.html', **context)


@app.route("/dashboard/server/<guild_id>/timezone")
@require_auth
def dashboard_timezone_settings(user_session, guild_id):
    """Timezone settings page"""
    if not guild_id.isdigit() or len(guild_id) > 20:
        return redirect('/dashboard')
    
    context, error = get_server_page_context(user_session, guild_id, 'timezone')
    if error:
        return error
    
    if context['user_role'] != 'admin':
        return redirect(f'/dashboard/server/{guild_id}')
    
    return render_template('dashboard_pages/timezone_settings.html', **context)


@app.route("/dashboard/server/<guild_id>/employees")
@require_auth
def dashboard_employees(user_session, guild_id):
    """Employee status page"""
    if not guild_id.isdigit() or len(guild_id) > 20:
        return redirect('/dashboard')
    
    context, error = get_server_page_context(user_session, guild_id, 'employees')
    if error:
        return error
    
    if context['user_role'] != 'admin':
        return redirect(f'/dashboard/server/{guild_id}')
    
    premium_block = check_premium_access(context, 'employee_profiles_extended')
    if premium_block:
        return premium_block
    
    return render_template('dashboard_pages/employees.html', **context)


@app.route("/dashboard/server/<guild_id>/clock")
@require_auth
def dashboard_on_the_clock(user_session, guild_id):
    """On the clock page for employees (admins can also view for monitoring)"""
    if not guild_id.isdigit() or len(guild_id) > 20:
        return redirect('/dashboard')
    
    context, error = get_server_page_context(user_session, guild_id, 'clock')
    if error:
        return error
    
    return render_template('dashboard_pages/on_the_clock.html', **context)


@app.route("/dashboard/server/<guild_id>/adjustments")
@require_auth
def dashboard_adjustments(user_session, guild_id):
    """Time adjustments page"""
    if not guild_id.isdigit() or len(guild_id) > 20:
        return redirect('/dashboard')
    
    context, error = get_server_page_context(user_session, guild_id, 'adjustments')
    if error:
        return error
    
    premium_block = check_premium_access(context, 'time_adjustments')
    if premium_block:
        return premium_block
    
    return render_template('dashboard_pages/adjustments.html', **context)


@app.route("/dashboard/server/<guild_id>/calendar")
@require_auth
def dashboard_admin_calendar(user_session, guild_id):
    """Admin calendar page"""
    if not guild_id.isdigit() or len(guild_id) > 20:
        return redirect('/dashboard')
    
    context, error = get_server_page_context(user_session, guild_id, 'calendar')
    if error:
        return error
    
    if context['user_role'] != 'admin':
        return redirect(f'/dashboard/server/{guild_id}')
    
    premium_block = check_premium_access(context, 'advanced_settings')
    if premium_block:
        return premium_block
    
    return render_template('dashboard_pages/admin_calendar.html', **context)


@app.route("/dashboard/server/<guild_id>/bans")
@require_auth
def dashboard_ban_management(user_session, guild_id):
    """Ban management page"""
    if not guild_id.isdigit() or len(guild_id) > 20:
        return redirect('/dashboard')
    
    context, error = get_server_page_context(user_session, guild_id, 'bans')
    if error:
        return error
    
    if context['user_role'] != 'admin':
        return redirect(f'/dashboard/server/{guild_id}')
    
    premium_block = check_premium_access(context, 'ban_management')
    if premium_block:
        return premium_block
    
    return render_template('dashboard_pages/ban_management.html', **context)


@app.route("/dashboard/server/<guild_id>/beta")
@require_auth
def dashboard_beta_settings(user_session, guild_id):
    """Beta settings page (admin only)"""
    if not guild_id.isdigit() or len(guild_id) > 20:
        return redirect('/dashboard')
    
    context, error = get_server_page_context(user_session, guild_id, 'beta')
    if error:
        return error
    
    # Fetch beta settings
    with get_db() as conn:
        cursor = conn.execute("SELECT beta_enabled, allow_kiosk_customization FROM guild_settings WHERE guild_id = %s", (guild_id,))
        settings = cursor.fetchone()
        
    beta_enabled = settings['beta_enabled'] if settings else False
    allow_kiosk_customization = settings['allow_kiosk_customization'] if settings else True

    context['beta_enabled'] = beta_enabled
    context['allow_kiosk_customization'] = allow_kiosk_customization
    
    if context['user_role'] != 'admin':
        return redirect(f'/dashboard/server/{guild_id}')
    
    return render_template('dashboard_pages/beta_settings.html', **context)


@app.route("/dashboard/server/<guild_id>/profile/<user_id>")
@require_auth
def dashboard_employee_profile(user_session, guild_id, user_id):
    """Employee profile page - viewable by the employee or admins"""
    access = get_flask_guild_access(guild_id)
    if not access['is_exempt'] and access['tier'] == 'free' and not access['trial_active']:
        return redirect(f'/dashboard/purchase?guild_id={guild_id}')

    if not guild_id.isdigit() or len(guild_id) > 20:
        return redirect('/dashboard')
    if not user_id.isdigit() or len(user_id) > 20:
        return redirect(f'/dashboard/server/{guild_id}')
    
    context, error = get_server_page_context(user_session, guild_id, 'profile')
    if error:
        return error
    
    # Allow access if: user is viewing their own profile OR user is admin
    viewer_user_id = user_session.get('user_id')
    if context['user_role'] != 'admin' and str(viewer_user_id) != str(user_id):
        return redirect(f'/dashboard/server/{guild_id}')
    
    # Add profile user_id to context for the template
    context['profile_user_id'] = user_id
    context['is_own_profile'] = str(viewer_user_id) == str(user_id)
    context['employee_id'] = user_id # Compatibility for employee_profile.html
    
    return render_template('dashboard_pages/employee_profile.html', **context)


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
                    COALESCE(ss.grandfathered, FALSE) as grandfathered,
                    COUNT(DISTINCT s.session_id) as active_sessions,
                    COALESCE(bg.is_present, TRUE) as bot_is_present,
                    bg.left_at
                FROM bot_guilds bg
                LEFT JOIN server_subscriptions ss ON ss.guild_id = CAST(bg.guild_id AS BIGINT)
                LEFT JOIN timeclock_sessions s ON CAST(bg.guild_id AS BIGINT) = s.guild_id AND s.clock_out_time IS NULL
                GROUP BY bg.guild_id, bg.guild_name, ss.bot_access_paid, ss.retention_tier, ss.status, ss.subscription_id, ss.customer_id, ss.manually_granted, ss.granted_by, ss.granted_at, ss.grant_source, ss.grandfathered, bg.is_present, bg.left_at
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
                    'grandfathered': bool(row.get('grandfathered', False)),
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
                    SUM(CASE WHEN COALESCE(ss.grandfathered, FALSE) = TRUE THEN 1 ELSE 0 END) as grandfathered_count,
                    SUM(CASE WHEN ss.retention_tier = '7day' THEN 1 ELSE 0 END) as retention_7day_count,
                    SUM(CASE WHEN ss.retention_tier = '30day' THEN 1 ELSE 0 END) as retention_30day_count,
                    SUM(CASE WHEN ss.retention_tier = 'pro' THEN 1 ELSE 0 END) as pro_count,
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
                'grandfathered_count': stats_row['grandfathered_count'] or 0,
                'retention_7day_count': stats_row['retention_7day_count'],
                'retention_30day_count': stats_row['retention_30day_count'],
                'pro_count': stats_row['pro_count'] or 0,
                'past_due_count': stats_row['past_due_count'],
                'active_servers': stats_row['active_servers'],
                'inactive_servers': stats_row['inactive_servers'],
                'departed_unpaid_servers': stats_row['departed_unpaid_servers'] or 0
            }
            
            # Get total active sessions across all servers (using timeclock_sessions)
            cursor = conn.execute("""
                SELECT COUNT(*) as total_active_sessions
                FROM timeclock_sessions 
                WHERE clock_out_time IS NULL
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

@app.route("/owner/paid")
@require_auth
def owner_dashboard_paid(user_session):
    """Owner-only dashboard showing only paid servers"""
    try:
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        
        if user_session['user_id'] != bot_owner_id:
            app.logger.warning(f"Unauthorized owner dashboard access attempt by user {user_session['user_id']}")
            return "<h1>403 Forbidden</h1><p>You do not have permission to access this page.</p><a href='/dashboard'>Return to Dashboard</a>", 403
        
        app.logger.info(f"Owner paid servers dashboard accessed by {user_session.get('username')}")
        
        with get_db() as conn:
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
                    COUNT(DISTINCT s.session_id) as active_sessions,
                    COALESCE(bg.is_present, TRUE) as bot_is_present,
                    bg.left_at
                FROM bot_guilds bg
                LEFT JOIN server_subscriptions ss ON ss.guild_id = CAST(bg.guild_id AS BIGINT)
                LEFT JOIN timeclock_sessions s ON CAST(bg.guild_id AS BIGINT) = s.guild_id AND s.clock_out_time IS NULL
                WHERE ss.bot_access_paid = TRUE
                GROUP BY bg.guild_id, bg.guild_name, ss.bot_access_paid, ss.retention_tier, ss.status, ss.subscription_id, ss.customer_id, ss.manually_granted, ss.granted_by, ss.granted_at, ss.grant_source, bg.is_present, bg.left_at
                ORDER BY COALESCE(bg.is_present, TRUE) DESC, guild_name
            """)
            servers = []
            for row in cursor.fetchall():
                servers.append({
                    'guild_id': row['guild_id'],
                    'guild_name': row['guild_name'] or f'Unknown Server (ID: {row["guild_id"]})',
                    'bot_access': bool(row['bot_access_paid']),
                    'retention_tier': row['retention_tier'] if row['retention_tier'] != 'none' else None,
                    'status': row['status'],
                    'subscription_id': row['subscription_id'],
                    'customer_id': row['customer_id'],
                    'manually_granted': bool(row['manually_granted']),
                    'granted_by': row['granted_by'],
                    'granted_at': row['granted_at'].isoformat() if row.get('granted_at') else None,
                    'grant_source': row.get('grant_source'),
                    'active_sessions': row['active_sessions'],
                    'bot_is_present': bool(row['bot_is_present']),
                    'left_at': row['left_at'].isoformat() if row.get('left_at') else None,
                    'email_recipients': [],
                    'webhook_events': []
                })
            
            stats = {
                'total_servers': len(servers),
                'paid_servers': len(servers),
                'retention_7day_count': sum(1 for s in servers if s['retention_tier'] == '7day'),
                'retention_30day_count': sum(1 for s in servers if s['retention_tier'] == '30day'),
                'past_due_count': sum(1 for s in servers if s['status'] == 'past_due'),
                'active_servers': sum(1 for s in servers if s['bot_is_present']),
                'inactive_servers': sum(1 for s in servers if not s['bot_is_present']),
                'total_active_sessions': sum(s['active_sessions'] for s in servers),
                'departed_unpaid_servers': 0
            }
        
        return render_template('owner_dashboard.html', 
                             user=user_session,
                             servers=servers,
                             webhook_events=[],
                             purchase_history=[],
                             stats=stats,
                             filter_mode='paid')
    
    except Exception as e:
        app.logger.error(f"Owner paid dashboard error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return "<h1>Error</h1><p>Unable to load owner dashboard. Please try again later.</p>", 500

@app.route("/owner/unpaid")
@require_auth
def owner_dashboard_unpaid(user_session):
    """Owner-only dashboard showing only unpaid servers (bot installed but not paid)"""
    try:
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        
        if user_session['user_id'] != bot_owner_id:
            app.logger.warning(f"Unauthorized owner dashboard access attempt by user {user_session['user_id']}")
            return "<h1>403 Forbidden</h1><p>You do not have permission to access this page.</p><a href='/dashboard'>Return to Dashboard</a>", 403
        
        app.logger.info(f"Owner unpaid servers dashboard accessed by {user_session.get('username')}")
        
        with get_db() as conn:
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
                    COUNT(DISTINCT s.session_id) as active_sessions,
                    COALESCE(bg.is_present, TRUE) as bot_is_present,
                    bg.left_at
                FROM bot_guilds bg
                LEFT JOIN server_subscriptions ss ON ss.guild_id = CAST(bg.guild_id AS BIGINT)
                LEFT JOIN timeclock_sessions s ON CAST(bg.guild_id AS BIGINT) = s.guild_id AND s.clock_out_time IS NULL
                WHERE COALESCE(ss.bot_access_paid, FALSE) = FALSE AND COALESCE(bg.is_present, TRUE) = TRUE
                GROUP BY bg.guild_id, bg.guild_name, ss.bot_access_paid, ss.retention_tier, ss.status, ss.subscription_id, ss.customer_id, ss.manually_granted, ss.granted_by, ss.granted_at, ss.grant_source, bg.is_present, bg.left_at
                ORDER BY guild_name
            """)
            servers = []
            for row in cursor.fetchall():
                servers.append({
                    'guild_id': row['guild_id'],
                    'guild_name': row['guild_name'] or f'Unknown Server (ID: {row["guild_id"]})',
                    'bot_access': bool(row['bot_access_paid']),
                    'retention_tier': row['retention_tier'] if row['retention_tier'] != 'none' else None,
                    'status': row['status'],
                    'subscription_id': row['subscription_id'],
                    'customer_id': row['customer_id'],
                    'manually_granted': bool(row['manually_granted']),
                    'granted_by': row['granted_by'],
                    'granted_at': row['granted_at'].isoformat() if row.get('granted_at') else None,
                    'grant_source': row.get('grant_source'),
                    'active_sessions': row['active_sessions'],
                    'bot_is_present': bool(row['bot_is_present']),
                    'left_at': row['left_at'].isoformat() if row.get('left_at') else None,
                    'email_recipients': [],
                    'webhook_events': []
                })
            
            stats = {
                'total_servers': len(servers),
                'paid_servers': 0,
                'retention_7day_count': 0,
                'retention_30day_count': 0,
                'past_due_count': 0,
                'active_servers': len(servers),
                'inactive_servers': 0,
                'total_active_sessions': sum(s['active_sessions'] for s in servers),
                'departed_unpaid_servers': 0
            }
        
        return render_template('owner_dashboard.html', 
                             user=user_session,
                             servers=servers,
                             webhook_events=[],
                             purchase_history=[],
                             stats=stats,
                             filter_mode='unpaid')
    
    except Exception as e:
        app.logger.error(f"Owner unpaid dashboard error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return "<h1>Error</h1><p>Unable to load owner dashboard. Please try again later.</p>", 500

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


@app.route("/debug/health/bot")
@require_auth
def debug_health_bot(user_session):
    """Check Discord bot health"""
    bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
    if user_session['user_id'] != bot_owner_id:
        return jsonify({'healthy': False, 'error': 'Unauthorized'}), 403
    
    try:
        bot_api_secret = os.getenv('BOT_API_SECRET')
        if not bot_api_secret:
            return jsonify({'healthy': False, 'error': 'BOT_API_SECRET not configured'})
        
        response = requests.get(
            'http://localhost:8081/health',
            headers={'Authorization': f'Bearer {bot_api_secret}'},
            timeout=5
        )
        
        if response.ok:
            return jsonify({'healthy': True, 'message': 'Bot connected and healthy'})
        else:
            return jsonify({'healthy': False, 'error': f'Bot API returned {response.status_code}'})
    except requests.exceptions.ConnectionError:
        return jsonify({'healthy': False, 'error': 'Bot API not responding'})
    except Exception as e:
        return jsonify({'healthy': False, 'error': str(e)})


@app.route("/debug/health/db")
@require_auth
def debug_health_db(user_session):
    """Check database health"""
    bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
    if user_session['user_id'] != bot_owner_id:
        return jsonify({'healthy': False, 'error': 'Unauthorized'}), 403
    
    try:
        with get_db() as conn:
            cursor = conn.execute("SELECT COUNT(*) as count FROM server_subscriptions")
            row = cursor.fetchone()
            return jsonify({'healthy': True, 'message': f'{row["count"]} servers tracked'})
    except Exception as e:
        return jsonify({'healthy': False, 'error': str(e)})


@app.route("/debug/health/stripe")
@require_auth
def debug_health_stripe(user_session):
    """Check Stripe configuration"""
    bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
    if user_session['user_id'] != bot_owner_id:
        return jsonify({'healthy': False, 'error': 'Unauthorized'}), 403
    
    try:
        import stripe
        stripe_key = os.getenv('STRIPE_SECRET_KEY')
        webhook_secret = os.getenv('STRIPE_WEBHOOK_SECRET')
        
        if not stripe_key:
            return jsonify({'healthy': False, 'error': 'STRIPE_SECRET_KEY not set'})
        
        if not webhook_secret:
            return jsonify({'healthy': False, 'error': 'Webhook secret missing'})
        
        stripe.api_key = stripe_key
        stripe.Account.retrieve()
        return jsonify({'healthy': True, 'message': 'Stripe configured and connected'})
    except Exception as e:
        return jsonify({'healthy': False, 'error': str(e)})


@app.route("/debug/health/email")
@require_auth
def debug_health_email(user_session):
    """Check email service configuration"""
    bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
    if user_session['user_id'] != bot_owner_id:
        return jsonify({'healthy': False, 'error': 'Unauthorized'}), 403
    
    try:
        from email_utils import send_email
        return jsonify({'healthy': True, 'message': 'Email service available'})
    except ImportError:
        return jsonify({'healthy': False, 'error': 'email_utils module not found'})
    except Exception as e:
        return jsonify({'healthy': False, 'error': str(e)})


@app.route("/debug/api-test/<test_id>")
@require_auth
def debug_api_test(user_session, test_id):
    """Run specific API tests"""
    bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
    if user_session['user_id'] != bot_owner_id:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    try:
        if test_id == 'bot-api':
            bot_api_secret = os.getenv('BOT_API_SECRET')
            if not bot_api_secret:
                return jsonify({'success': False, 'error': 'No API secret configured'})
            response = requests.get(
                'http://localhost:8081/health',
                headers={'Authorization': f'Bearer {bot_api_secret}'},
                timeout=5
            )
            return jsonify({'success': response.ok, 'message': f'Status {response.status_code}'})
        
        elif test_id == 'db':
            with get_db() as conn:
                cursor = conn.execute("SELECT 1 as test")
                cursor.fetchone()
                return jsonify({'success': True, 'message': 'Query executed successfully'})
        
        elif test_id == 'session':
            return jsonify({
                'success': True, 
                'message': f'Logged in as {user_session.get("username")}'
            })
        
        elif test_id == 'stripe':
            import stripe
            stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
            if not stripe.api_key:
                return jsonify({'success': False, 'error': 'No Stripe key'})
            stripe.Account.retrieve()
            return jsonify({'success': True, 'message': 'Stripe API accessible'})
        
        elif test_id == 'email':
            from email_utils import send_email
            return jsonify({'success': True, 'message': 'Email module loaded'})
        
        else:
            return jsonify({'success': False, 'error': f'Unknown test: {test_id}'})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route("/debug/version-info")
@require_auth
def debug_version_info(user_session):
    """Get version information from version.json and public_roadmap.json"""
    bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
    if user_session['user_id'] != bot_owner_id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        internal_version = 'Unknown'
        public_version = 'Unknown'
        updated = 'Unknown'
        
        try:
            with open('version.json', 'r') as f:
                version_data = json.load(f)
                internal_version = version_data.get('version', 'Unknown')
                updated = version_data.get('last_updated', 'Unknown')
        except:
            pass
        
        try:
            with open('public_roadmap.json', 'r') as f:
                roadmap_data = json.load(f)
                public_version = roadmap_data.get('current_version', 'Unknown')
        except:
            pass
        
        return jsonify({
            'internal': internal_version,
            'public': public_version,
            'updated': updated
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route("/debug/checklist")
@require_auth
def debug_checklist(user_session):
    """Run full pre-publish checklist"""
    bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
    if user_session['user_id'] != bot_owner_id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    checks = {}
    
    try:
        bot_api_secret = os.getenv('BOT_API_SECRET')
        if bot_api_secret:
            response = requests.get(
                'http://localhost:8081/health',
                headers={'Authorization': f'Bearer {bot_api_secret}'},
                timeout=5
            )
            if response.ok:
                checks['bot-connected'] = {'status': 'pass', 'name': 'Discord Bot', 'detail': 'Connected and responding'}
            else:
                checks['bot-connected'] = {'status': 'fail', 'name': 'Discord Bot', 'detail': f'API returned {response.status_code}'}
        else:
            checks['bot-connected'] = {'status': 'fail', 'name': 'Discord Bot', 'detail': 'BOT_API_SECRET not configured'}
    except:
        checks['bot-connected'] = {'status': 'fail', 'name': 'Discord Bot', 'detail': 'Cannot connect to bot API'}
    
    try:
        bot_api_secret = os.getenv('BOT_API_SECRET')
        if bot_api_secret:
            response = requests.get(
                'http://localhost:8081/commands',
                headers={'Authorization': f'Bearer {bot_api_secret}'},
                timeout=5
            )
            if response.ok:
                data = response.json()
                cmd_count = data.get('count', 0)
                checks['commands-synced'] = {'status': 'pass', 'name': 'Slash Commands', 'detail': f'{cmd_count} commands synced'}
            else:
                checks['commands-synced'] = {'status': 'warn', 'name': 'Slash Commands', 'detail': 'Could not verify command count'}
        else:
            checks['commands-synced'] = {'status': 'warn', 'name': 'Slash Commands', 'detail': 'Cannot check without API secret'}
    except:
        checks['commands-synced'] = {'status': 'warn', 'name': 'Slash Commands', 'detail': 'Command endpoint not available'}
    
    try:
        with get_db() as conn:
            cursor = conn.execute("SELECT 1 as test")
            cursor.fetchone()
            checks['db-connected'] = {'status': 'pass', 'name': 'Database', 'detail': 'PostgreSQL connected'}
    except Exception as e:
        checks['db-connected'] = {'status': 'fail', 'name': 'Database', 'detail': str(e)}
    
    checks['migrations-current'] = {'status': 'pass', 'name': 'Migrations', 'detail': 'Auto-applied on startup'}
    
    stripe_key = os.getenv('STRIPE_SECRET_KEY')
    if stripe_key and stripe_key.startswith('sk_'):
        checks['stripe-configured'] = {'status': 'pass', 'name': 'Stripe API', 'detail': 'Secret key configured'}
    else:
        checks['stripe-configured'] = {'status': 'fail', 'name': 'Stripe API', 'detail': 'Invalid or missing key'}
    
    webhook_secret = os.getenv('STRIPE_WEBHOOK_SECRET')
    if webhook_secret and webhook_secret.startswith('whsec_'):
        checks['webhook-secret'] = {'status': 'pass', 'name': 'Webhook Secret', 'detail': 'Properly configured'}
    else:
        checks['webhook-secret'] = {'status': 'fail', 'name': 'Webhook Secret', 'detail': 'Invalid or missing'}
    
    try:
        from email_utils import send_email
        checks['email-service'] = {'status': 'pass', 'name': 'Email Service', 'detail': 'Module available'}
    except:
        checks['email-service'] = {'status': 'fail', 'name': 'Email Service', 'detail': 'email_utils not found'}
    
    try:
        from entitlements import Entitlements
        checks['entitlements'] = {'status': 'pass', 'name': 'Entitlements', 'detail': 'Premium gates active'}
    except:
        checks['entitlements'] = {'status': 'fail', 'name': 'Entitlements', 'detail': 'Module not loaded'}
    
    try:
        with open('version.json', 'r') as f:
            version_data = json.load(f)
            version = version_data.get('version', 'Unknown')
            checks['version-updated'] = {'status': 'pass', 'name': 'Version', 'detail': f'v{version}'}
    except:
        checks['version-updated'] = {'status': 'warn', 'name': 'Version', 'detail': 'version.json not found'}
    
    try:
        with open('version.json', 'r') as f:
            version_data = json.load(f)
        with open('public_roadmap.json', 'r') as f:
            roadmap_data = json.load(f)
        
        internal_v = version_data.get('version', '')
        public_v = roadmap_data.get('current_version', '')
        
        if internal_v == public_v:
            checks['roadmap-synced'] = {'status': 'pass', 'name': 'Roadmap Sync', 'detail': f'Both at v{internal_v}'}
        else:
            checks['roadmap-synced'] = {'status': 'warn', 'name': 'Roadmap Sync', 'detail': f'Internal {internal_v} vs Public {public_v}'}
    except:
        checks['roadmap-synced'] = {'status': 'warn', 'name': 'Roadmap Sync', 'detail': 'Could not compare versions'}
    
    return jsonify({'checks': checks})


def seed_demo_data_internal():
    """Internal function to seed demo data for the demo server."""
    from datetime import datetime, timedelta, timezone
    import random
    
    demo_guild_id = 1419894879894507661
    demo_employees = [
        {'user_id': 100000000000000001, 'display_name': 'Alex Manager', 'full_name': 'Alex Thompson', 'first_name': 'Alex', 'last_name': 'Thompson', 'email': 'alex.demo@ontheclock.app', 'position': 'Store Manager', 'department': 'Management', 'company_role': 'Manager', 'bio': 'Demo manager account - 5 years with the company', 'role_tier': 'admin'},
        {'user_id': 100000000000000002, 'display_name': 'Jordan Sales', 'full_name': 'Jordan Rivera', 'first_name': 'Jordan', 'last_name': 'Rivera', 'email': 'jordan.demo@ontheclock.app', 'position': 'Sales Associate', 'department': 'Sales', 'company_role': 'Employee', 'bio': 'Top performer in sales department', 'role_tier': 'employee'},
        {'user_id': 100000000000000003, 'display_name': 'Casey Support', 'full_name': 'Casey Williams', 'first_name': 'Casey', 'last_name': 'Williams', 'email': 'casey.demo@ontheclock.app', 'position': 'Customer Support', 'department': 'Support', 'company_role': 'Employee', 'bio': 'Friendly face of customer service', 'role_tier': 'employee'},
        {'user_id': 100000000000000004, 'display_name': 'Sam Warehouse', 'full_name': 'Sam Johnson', 'first_name': 'Sam', 'last_name': 'Johnson', 'email': 'sam.demo@ontheclock.app', 'position': 'Warehouse Lead', 'department': 'Warehouse', 'company_role': 'Employee', 'bio': 'Keeps the warehouse running smoothly', 'role_tier': 'employee'},
        {'user_id': 100000000000000005, 'display_name': 'Taylor Intern', 'full_name': 'Taylor Chen', 'first_name': 'Taylor', 'last_name': 'Chen', 'email': 'taylor.demo@ontheclock.app', 'position': 'Marketing Intern', 'department': 'Marketing', 'company_role': 'Intern', 'bio': 'Learning the ropes of digital marketing', 'role_tier': 'employee'}
    ]
    
    try:
        with get_db() as conn:
            now = datetime.now(timezone.utc)
            
            # 1. Seed Employees
            for emp in demo_employees:
                conn.execute("""
                    INSERT INTO employee_profiles (guild_id, user_id, display_name, full_name, first_name, last_name, email, position, department, company_role, bio, role_tier, is_active, profile_setup_completed, hire_date)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, TRUE, TRUE, %s)
                    ON CONFLICT (guild_id, user_id) DO UPDATE SET 
                        display_name = EXCLUDED.display_name, 
                        full_name = EXCLUDED.full_name, 
                        first_name = EXCLUDED.first_name, 
                        last_name = EXCLUDED.last_name, 
                        email = EXCLUDED.email, 
                        position = EXCLUDED.position, 
                        department = EXCLUDED.department, 
                        company_role = EXCLUDED.company_role, 
                        bio = EXCLUDED.bio, 
                        role_tier = EXCLUDED.role_tier, 
                        is_active = TRUE, 
                        profile_setup_completed = TRUE
                """, (demo_guild_id, emp['user_id'], emp['display_name'], emp['full_name'], emp['first_name'], emp['last_name'], emp['email'], emp['position'], emp['department'], emp['company_role'], emp['bio'], emp['role_tier'], now - timedelta(days=random.randint(30, 365))))
            
            # 2. Clear and Seed Sessions
            demo_user_ids = [e['user_id'] for e in demo_employees]
            conn.execute("DELETE FROM timeclock_sessions WHERE guild_id = %s AND user_id = ANY(%s)", (demo_guild_id, demo_user_ids))
            
            for emp_id in demo_user_ids:
                work_days = random.randint(15, 25)
                for day_offset in range(30, 0, -1):
                    if random.random() > (work_days / 30.0):
                        continue
                    work_date = now - timedelta(days=day_offset)
                    if work_date.weekday() >= 5 and random.random() > 0.2:
                        continue
                    start_hour = random.randint(7, 10)
                    start_minute = random.choice([0, 15, 30, 45])
                    clock_in = work_date.replace(hour=start_hour, minute=start_minute, second=0, microsecond=0)
                    shift_length = random.uniform(4, 9)
                    clock_out = clock_in + timedelta(hours=shift_length)
                    conn.execute("INSERT INTO timeclock_sessions (guild_id, user_id, clock_in_time, clock_out_time) VALUES (%s, %s, %s, %s)", (demo_guild_id, emp_id, clock_in.isoformat(), clock_out.isoformat()))
            
            # 3. Add one active session
            active_emp = random.choice(demo_employees[1:])
            today_start = now.replace(hour=random.randint(7, 10), minute=random.choice([0, 15, 30]), second=0, microsecond=0)
            conn.execute("INSERT INTO timeclock_sessions (guild_id, user_id, clock_in_time, clock_out_time) VALUES (%s, %s, %s, NULL)", (demo_guild_id, active_emp['user_id'], today_start.isoformat()))
            
            # 4. Clear and Seed Adjustment Requests
            conn.execute("DELETE FROM time_adjustment_requests WHERE guild_id = %s AND user_id = ANY(%s)", (demo_guild_id, demo_user_ids))
            request_scenarios = [
                {'employee_idx': 1, 'request_type': 'add_session', 'reason': 'Forgot to clock in - morning meeting', 'status': 'pending', 'days_ago': 2},
                {'employee_idx': 2, 'request_type': 'modify_clockout', 'reason': 'System logged me out early', 'status': 'pending', 'days_ago': 1},
                {'employee_idx': 3, 'request_type': 'add_session', 'reason': 'Worked from home', 'status': 'approved', 'days_ago': 5},
                {'employee_idx': 4, 'request_type': 'modify_clockin', 'reason': 'Arrived early to help', 'status': 'denied', 'days_ago': 7}
            ]
            for scenario in request_scenarios:
                emp = demo_employees[scenario['employee_idx']]
                request_date = now - timedelta(days=scenario['days_ago'])
                req_in = request_date.replace(hour=9, minute=0, second=0, microsecond=0)
                req_out = request_date.replace(hour=17, minute=0, second=0, microsecond=0)
                rev_by = demo_employees[0]['user_id'] if scenario['status'] != 'pending' else None
                rev_at = now - timedelta(days=scenario['days_ago'] - 1) if scenario['status'] != 'pending' else None
                conn.execute("INSERT INTO time_adjustment_requests (guild_id, user_id, request_type, reason, status, requested_clock_in, requested_clock_out, reviewed_by, reviewed_at, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", (demo_guild_id, emp['user_id'], scenario['request_type'], scenario['reason'], scenario['status'], req_in.isoformat(), req_out.isoformat(), rev_by, rev_at.isoformat() if rev_at else None, request_date.isoformat()))
            
            # 5. Track last reset
            conn.execute("""
                INSERT INTO guild_settings (guild_id, name, last_demo_reset)
                VALUES (%s, %s, %s)
                ON CONFLICT (guild_id) DO UPDATE SET last_demo_reset = EXCLUDED.last_demo_reset
            """, (demo_guild_id, "On The Clock Demo", now.isoformat()))
            
            conn.commit()
            return True
    except Exception as e:
        print(f"Error seeding demo data: {e}")
        return False

@app.route("/debug/seed-demo-data", methods=["POST"])
@require_auth
def debug_seed_demo_data(user_session):
    """Owner-only endpoint to manually seed demo data."""
    bot_owner_id = str(os.getenv("BOT_OWNER_ID", "107103438139056128"))
    if str(user_session['user_id']) != bot_owner_id:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    success = seed_demo_data_internal()
    if success:
        return jsonify({'success': True, 'message': 'Demo data seeded successfully'}), 200
    else:
        return jsonify({'success': False, 'error': 'Seeding failed'}), 500


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
        grant_source = data.get('source', 'granted').lower()
        
        if not guild_id or not access_type:
            return jsonify({'success': False, 'error': 'Missing guild_id or access_type'}), 400
        
        if access_type not in ['bot_access', '7day', '30day', 'premium', 'pro']:
            return jsonify({'success': False, 'error': 'Invalid access_type. Must be premium, pro, bot_access, 7day, or 30day'}), 400
        
        # Map new tier names to database values
        original_type = access_type
        if access_type == 'premium':
            access_type = '30day'  # Premium = 30-day retention + bot_access
        
        if grant_source not in ['granted', 'stripe']:
            grant_source = 'granted'
        
        app.logger.info(f"Owner {user_session.get('username')} granting {original_type} (mapped to {access_type}, source={grant_source}) to guild {guild_id}")
        
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
                        grant_source = %s
                    WHERE guild_id = %s
                """, (user_session['user_id'], grant_source, guild_id))
                app.logger.info(f"[OK] Granted bot access (source={grant_source}) to guild {guild_id}")
                
            elif access_type in ['7day', '30day', 'pro']:
                # For premium/pro, also grant bot_access automatically
                conn.execute("""
                    UPDATE server_subscriptions 
                    SET retention_tier = %s,
                        bot_access_paid = TRUE,
                        manually_granted = TRUE,
                        granted_by = %s,
                        granted_at = NOW(),
                        status = 'active',
                        grant_source = %s
                    WHERE guild_id = %s
                """, (access_type, user_session['user_id'], grant_source, guild_id))
                app.logger.info(f"[OK] Granted {original_type} tier (retention={access_type}, source={grant_source}) to guild {guild_id}")
            
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

@app.route("/api/owner/server-index", methods=["GET"])
@require_api_auth
def api_owner_server_index(user_session):
    """Owner-only API endpoint to get lightweight server list for dropdown selection"""
    try:
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        
        if user_session['user_id'] != bot_owner_id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        search = request.args.get('search', '').strip().lower()
        
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT 
                    CAST(bg.guild_id AS BIGINT) as guild_id,
                    bg.guild_name,
                    COALESCE(ss.bot_access_paid, FALSE) as bot_access_paid,
                    COALESCE(ss.retention_tier, 'none') as retention_tier,
                    COALESCE(ss.manually_granted, FALSE) as manually_granted,
                    ss.grant_source,
                    COALESCE(bg.is_present, TRUE) as is_present,
                    bg.left_at
                FROM bot_guilds bg
                LEFT JOIN server_subscriptions ss ON ss.guild_id = CAST(bg.guild_id AS BIGINT)
                ORDER BY COALESCE(bg.is_present, TRUE) DESC, bg.guild_name
            """)
            
            active_servers = []
            historical_servers = []
            
            for row in cursor.fetchall():
                guild_id = str(row['guild_id'])
                guild_name = row['guild_name'] or f'Unknown ({guild_id})'
                is_present = bool(row['is_present'])
                
                # Apply search filter
                if search and search not in guild_name.lower() and search not in guild_id:
                    continue
                
                server_data = {
                    'guild_id': guild_id,
                    'name': guild_name,
                    'bot_access': bool(row['bot_access_paid']),
                    'retention': row['retention_tier'] if row['retention_tier'] != 'none' else None,
                    'granted': bool(row['manually_granted']),
                    'source': row['grant_source'],
                    'left_at': row['left_at'].strftime('%Y-%m-%d') if row.get('left_at') else None
                }
                
                if is_present:
                    active_servers.append(server_data)
                else:
                    historical_servers.append(server_data)
            
            return jsonify({
                'success': True,
                'active': active_servers,
                'historical': historical_servers
            })
    
    except Exception as e:
        app.logger.error(f"Server index error: {str(e)}")
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
        
        if access_type not in ['bot_access', '7day', '30day', 'pro', 'all']:
            return jsonify({'success': False, 'error': 'Invalid access_type. Must be bot_access, 7day, 30day, pro, or all'}), 400
        
        app.logger.info(f"Owner {user_session.get('username')} revoking {access_type} from guild {guild_id}")
        
        with get_db() as conn:
            # Check if server exists in server_subscriptions
            cursor = conn.execute("SELECT guild_id, bot_access_paid, retention_tier, grandfathered FROM server_subscriptions WHERE guild_id = %s", (guild_id,))
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
            
            # Protect grandfathered servers from revocation (but allow upgrades)
            if server.get('grandfathered') and access_type in ['all', 'bot_access']:
                app.logger.warning(f"Attempted to revoke core access from grandfathered server {guild_id}")
                return jsonify({
                    'success': False, 
                    'error': 'Cannot revoke core access from grandfathered servers. These are legacy $5 lifetime users with permanent Premium access.'
                }), 400
            
            # Revoke the appropriate access
            if access_type == 'all':
                # Revoke all access (bot access + retention tier)
                conn.execute("""
                    UPDATE server_subscriptions 
                    SET bot_access_paid = FALSE,
                        tier = 'free',
                        retention_tier = 'none',
                        status = 'cancelled',
                        manually_granted = FALSE,
                        granted_by = NULL,
                        granted_at = NULL,
                        grant_source = NULL
                    WHERE guild_id = %s
                """, (guild_id,))
                app.logger.info(f"[REVOKE] Revoked ALL access from guild {guild_id}")
                
            elif access_type == 'bot_access':
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
                app.logger.info(f"[REVOKE] Revoked bot access from guild {guild_id} (tier set to 'free', retention cleared)")
                
            elif access_type in ['7day', '30day', 'pro']:
                # Only revoke if this is the current retention tier
                if server['retention_tier'] == access_type:
                    conn.execute("""
                        UPDATE server_subscriptions 
                        SET retention_tier = 'none',
                            status = 'active'
                        WHERE guild_id = %s
                    """, (guild_id,))
                    app.logger.info(f"[REVOKE] Revoked {access_type} retention from guild {guild_id}")
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

@app.route("/api/owner/trial/grant", methods=["POST"])
@require_api_auth
def api_owner_trial_grant(user_session):
    """Owner-only API to manually grant trial usage to a server"""
    try:
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        
        if user_session['user_id'] != bot_owner_id:
            return jsonify({'success': False, 'error': 'Unauthorized - Owner access required'}), 403
        
        data = request.get_json()
        guild_id = data.get('guild_id', '').strip()
        
        if not guild_id:
            return jsonify({'success': False, 'error': 'Guild ID is required'}), 400
        
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT * FROM trial_usage WHERE guild_id = %s",
                (guild_id,)
            )
            existing = cursor.fetchone()
            
            if existing:
                return jsonify({
                    'success': False, 
                    'error': f'Trial already used on {existing["used_at"].strftime("%Y-%m-%d %H:%M")} ({existing["grant_type"]})'
                }), 400
            
            conn.execute("""
                INSERT INTO trial_usage (guild_id, granted_by, grant_type)
                VALUES (%s, %s, 'owner_grant')
            """, (guild_id, user_session['user_id']))
            
            app.logger.info(f"Trial granted to guild {guild_id} by owner {user_session.get('username')}")
            
            return jsonify({
                'success': True,
                'message': f'Trial marked as used for server {guild_id}. They will not see the $5 discount at checkout.'
            })
    
    except Exception as e:
        app.logger.error(f"Trial grant error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route("/api/owner/trial/status/<guild_id>", methods=["GET"])
@require_api_auth
def api_owner_trial_status(user_session, guild_id):
    """Owner-only API to check trial status for a server"""
    try:
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        
        if user_session['user_id'] != bot_owner_id:
            return jsonify({'success': False, 'error': 'Unauthorized - Owner access required'}), 403
        
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT * FROM trial_usage WHERE guild_id = %s",
                (guild_id,)
            )
            trial = cursor.fetchone()
            
            if trial:
                return jsonify({
                    'success': True,
                    'trial_used': True,
                    'used_at': trial['used_at'].strftime('%Y-%m-%d %H:%M'),
                    'grant_type': trial['grant_type'],
                    'stripe_coupon_id': trial.get('stripe_coupon_id'),
                    'granted_by': trial.get('granted_by')
                })
            else:
                return jsonify({
                    'success': True,
                    'trial_used': False,
                    'message': 'Trial available'
                })
    
    except Exception as e:
        app.logger.error(f"Trial status check error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route("/api/owner/trial/reset", methods=["POST"])
@require_api_auth
def api_owner_trial_reset(user_session):
    """Owner-only API to reset trial usage for a server (allow re-use)"""
    try:
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        
        if user_session['user_id'] != bot_owner_id:
            return jsonify({'success': False, 'error': 'Unauthorized - Owner access required'}), 403
        
        data = request.get_json()
        guild_id = data.get('guild_id', '').strip()
        
        if not guild_id:
            return jsonify({'success': False, 'error': 'Guild ID is required'}), 400
        
        with get_db() as conn:
            cursor = conn.execute(
                "DELETE FROM trial_usage WHERE guild_id = %s RETURNING id",
                (guild_id,)
            )
            deleted = cursor.fetchone()
            
            if deleted:
                app.logger.info(f"Trial reset for guild {guild_id} by owner {user_session.get('username')}")
                return jsonify({
                    'success': True,
                    'message': f'Trial reset for server {guild_id}. They can now use the $5 first-month discount.'
                })
            else:
                return jsonify({
                    'success': True,
                    'message': 'No trial record found - server already has trial available.'
                })
    
    except Exception as e:
        app.logger.error(f"Trial reset error: {str(e)}")
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
                        CASE WHEN s.clock_out_time IS NOT NULL 
                        THEN EXTRACT(EPOCH FROM (s.clock_out_time - s.clock_in_time))/3600 
                        ELSE 0 END
                    ), 0) as total_hours,
                    COUNT(s.session_id) as session_count,
                    EXISTS(SELECT 1 FROM timeclock_sessions s2 WHERE s2.guild_id = ep.guild_id::text AND s2.user_id = ep.user_id::text AND s2.clock_out_time IS NULL) as is_clocked_in
                FROM employee_profiles ep
                LEFT JOIN timeclock_sessions s ON s.guild_id = ep.guild_id::text AND s.user_id = ep.user_id::text
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
                    s.clock_in_time as clock_in,
                    s.clock_out_time as clock_out,
                    CASE 
                        WHEN s.clock_out_time IS NOT NULL 
                        THEN EXTRACT(EPOCH FROM (s.clock_out_time - s.clock_in_time))/3600 
                        ELSE NULL 
                    END as hours_worked
                FROM timeclock_sessions s
                LEFT JOIN employee_profiles ep ON s.guild_id = ep.guild_id::text AND s.user_id = ep.user_id::text
                WHERE s.guild_id = %s
                  AND s.clock_in_time >= %s::date
                  AND s.clock_in_time < (%s::date + interval '1 day')
                ORDER BY s.clock_in_time
            """, (str(guild_id), start_date, end_date))
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
    
    # Demo server override: Grant admin access to all users for demo exploration
    if is_demo_server(guild_id):
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT guild_name FROM bot_guilds WHERE guild_id = %s",
                (DEMO_SERVER_ID,)
            )
            row = cursor.fetchone()
            guild_name = row['guild_name'] if row else 'On The Clock Demo'
        return ({
            'id': guild_id,
            'name': guild_name,
            'owner': False,
            'permissions': '0'
        }, 'admin')
    
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
    """Purchase page for a specific guild - redirects to new Premium subscription flow"""
    try:
        has_bot_access = flask_check_bot_access(guild_id)
        
        if has_bot_access:
            return redirect(f'/dashboard/{guild_id}')
        
        return redirect('/dashboard/purchase?guild_id=' + str(guild_id))
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

        # DEMO SERVER SECURITY: Restrict to safe role subset
        if is_demo_server(guild_id):
            if role_id not in DEMO_ALLOWED_ADMIN_ROLES:
                app.logger.warning(f"Demo server security: Blocked attempt to add non-whitelisted admin role {role_id}")
                return jsonify({
                    'success': False,
                    'error': 'Demo Mode: You can only map the designated Demo Admin role for security.'
                }), 403

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

        # DEMO SERVER SECURITY: Restrict to safe role subset
        if is_demo_server(guild_id):
            if role_id not in DEMO_ALLOWED_ADMIN_ROLES:
                app.logger.warning(f"Demo server security: Blocked attempt to remove non-whitelisted admin role {role_id}")
                return jsonify({
                    'success': False,
                    'error': 'Demo Mode: You can only manage the designated Demo Admin role for security.'
                }), 403

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

        # DEMO SERVER SECURITY: Restrict to safe role subset
        if is_demo_server(guild_id):
            if role_id not in DEMO_ALLOWED_EMPLOYEE_ROLES:
                app.logger.warning(f"Demo server security: Blocked attempt to add non-whitelisted employee role {role_id}")
                return jsonify({
                    'success': False,
                    'error': 'Demo Mode: You can only map the designated Demo Employee role for security.'
                }), 403

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

        # DEMO SERVER SECURITY: Restrict to safe role subset
        if is_demo_server(guild_id):
            if role_id not in DEMO_ALLOWED_EMPLOYEE_ROLES:
                app.logger.warning(f"Demo server security: Blocked attempt to remove non-whitelisted employee role {role_id}")
                return jsonify({
                    'success': False,
                    'error': 'Demo Mode: You can only manage the designated Demo Employee role for security.'
                }), 403

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

@app.route("/api/server/<guild_id>/email-settings-status", methods=["GET"])
@require_paid_api_access
def api_get_email_settings_status(user_session, guild_id):
    """API endpoint to fetch email settings status for a server"""
    try:
        # Verify user has access
        guild, _ = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Fetch email settings
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT auto_send_on_clockout, auto_email_before_delete FROM email_settings WHERE guild_id = %s",
                (guild_id,)
            )
            settings = cursor.fetchone()
            
        if settings:
            return jsonify({
                'success': True,
                'auto_send_on_clockout': settings['auto_send_on_clockout'],
                'auto_email_before_delete': settings['auto_email_before_delete']
            })
        else:
            return jsonify({
                'success': True,
                'auto_send_on_clockout': True, # Default
                'auto_email_before_delete': True # Default
            })
    except Exception as e:
        app.logger.error(f"Error fetching email settings status: {str(e)}")
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

@app.route("/api/server/<guild_id>/kiosk-customization", methods=["POST"])
@require_paid_api_access
def api_update_kiosk_customization(user_session, guild_id):
    """API endpoint to update kiosk button customization setting"""
    try:
        guild, _ = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        data = request.get_json()
        if not data or 'allow_kiosk_customization' not in data:
            return jsonify({'success': False, 'error': 'Missing setting'}), 400
        
        allow_customization = bool(data['allow_kiosk_customization'])
        
        with get_db() as conn:
            conn.execute("""
                INSERT INTO guild_settings (guild_id, allow_kiosk_customization)
                VALUES (%s, %s)
                ON CONFLICT (guild_id) DO UPDATE SET allow_kiosk_customization = EXCLUDED.allow_kiosk_customization
            """, (guild_id, allow_customization))
            
            app.logger.info(f"[OK] Kiosk customization setting committed: {allow_customization} for guild {guild_id}")
            
            return jsonify({'success': True, 'allow_kiosk_customization': allow_customization})
    except Exception as e:
        app.logger.error(f"Error updating kiosk customization: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error'}), 500

@app.route("/api/server/<guild_id>/email-recipients", methods=["GET"])
@require_paid_api_access
def api_get_email_recipients(user_session, guild_id):
    """API endpoint to fetch email recipients for a server"""
    try:
        guild, _ = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        with get_db() as conn:
            cursor = conn.execute(
                """SELECT id, email_address, created_at, 
                          COALESCE(verification_status, 'verified') as verification_status, 
                          verified_at
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
                'created_at': row['created_at'],
                'verification_status': row['verification_status'],
                'verified_at': row.get('verified_at')
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
    """API endpoint to add an email recipient with verification"""
    try:
        guild, _ = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        data = request.get_json()
        if not data or 'email' not in data:
            return jsonify({'success': False, 'error': 'Missing email address'}), 400
        
        email = data['email'].strip().lower()
        
        import re
        import secrets
        import hashlib
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            return jsonify({'success': False, 'error': 'Invalid email address format'}), 400
        
        verification_code = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
        code_hash = hashlib.sha256(verification_code.encode()).hexdigest()
        
        with get_db() as conn:
            try:
                cursor = conn.execute(
                    """INSERT INTO report_recipients (guild_id, recipient_type, email_address, verification_status, verification_code_hash, verification_code_sent_at) 
                       VALUES (%s, 'email', %s, 'pending', %s, NOW())
                       RETURNING id""",
                    (guild_id, email, code_hash)
                )
                result = cursor.fetchone()
                recipient_id = result['id'] if result else None
                
                conn.execute("""
                    INSERT INTO email_settings (guild_id, auto_send_on_clockout, auto_email_before_delete)
                    VALUES (%s, TRUE, TRUE)
                    ON CONFLICT (guild_id) DO NOTHING
                """, (guild_id,))
                
                app.logger.info(f"[OK] Email recipient added (pending verification): {email} for guild {guild_id}")
                
            except psycopg2.IntegrityError:
                return jsonify({'success': False, 'error': 'Email address already exists'}), 400
            except Exception as db_error:
                app.logger.error(f"Database error adding email recipient: {db_error}")
                raise
        
        try:
            from email_utils import send_email
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            subject = "Verify your email for Time Warden"
            text_content = f"""Hello!

You've added this email to receive notifications from Time Warden.

Your verification code is: {verification_code}

Enter this code in the dashboard to verify your email address.

If you didn't request this, you can safely ignore this email.

- Time Warden Bot"""
            
            result = loop.run_until_complete(send_email(to=[email], subject=subject, text=text_content))
            loop.close()
            
            if result.get('success'):
                app.logger.info(f"[OK] Verification email sent to {email}")
            else:
                app.logger.warning(f"Failed to send verification email to {email}: {result.get('error')}")
        except Exception as email_error:
            app.logger.error(f"Error sending verification email: {email_error}")
        
        return jsonify({
            'success': True, 
            'message': 'Email added! Check your inbox for a verification code.', 
            'id': recipient_id, 
            'email': email,
            'verification_status': 'pending'
        })
    except Exception as e:
        app.logger.error(f"Error adding email recipient: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@app.route("/api/server/<guild_id>/email-recipients/verify", methods=["POST"])
@require_paid_api_access
def api_verify_email_recipient(user_session, guild_id):
    """API endpoint to verify an email recipient with a code"""
    try:
        import hashlib
        
        guild, _ = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        data = request.get_json()
        if not data or 'id' not in data or 'code' not in data:
            return jsonify({'success': False, 'error': 'Missing recipient ID or verification code'}), 400
        
        recipient_id = int(data['id'])
        code = data['code'].strip()
        
        if not code.isdigit() or len(code) != 6:
            return jsonify({'success': False, 'error': 'Invalid code format. Enter the 6-digit code from your email.'}), 400
        
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        
        with get_db() as conn:
            cursor = conn.execute(
                """SELECT id, verification_code_hash, verification_status, verification_attempts, verification_code_sent_at
                   FROM report_recipients 
                   WHERE id = %s AND guild_id = %s AND recipient_type = 'email'""",
                (recipient_id, guild_id)
            )
            recipient = cursor.fetchone()
            
            if not recipient:
                return jsonify({'success': False, 'error': 'Recipient not found'}), 404
            
            if recipient['verification_status'] == 'verified':
                return jsonify({'success': True, 'message': 'Email already verified'})
            
            attempts = recipient['verification_attempts'] or 0
            if attempts >= 5:
                return jsonify({'success': False, 'error': 'Too many failed attempts. Please resend the verification code.'}), 429
            
            if recipient['verification_code_sent_at']:
                from datetime import datetime, timedelta
                import pytz
                code_sent_at = recipient['verification_code_sent_at']
                if code_sent_at.tzinfo is None:
                    code_sent_at = pytz.UTC.localize(code_sent_at)
                if datetime.now(pytz.UTC) - code_sent_at > timedelta(hours=24):
                    return jsonify({'success': False, 'error': 'Verification code expired. Please resend the code.'}), 400
            
            if recipient['verification_code_hash'] != code_hash:
                new_attempts = attempts + 1
                conn.execute(
                    "UPDATE report_recipients SET verification_attempts = %s WHERE id = %s",
                    (new_attempts, recipient_id)
                )
                remaining = max(0, 5 - new_attempts)
                return jsonify({'success': False, 'error': f'Incorrect code. {remaining} attempts remaining.'}), 400
            
            conn.execute(
                """UPDATE report_recipients 
                   SET verification_status = 'verified', verified_at = NOW(), verification_code_hash = NULL, verification_attempts = 0
                   WHERE id = %s""",
                (recipient_id,)
            )
            
            app.logger.info(f"[OK] Email verified for recipient {recipient_id} in guild {guild_id}")
            
        return jsonify({'success': True, 'message': 'Email verified successfully!'})
    except Exception as e:
        app.logger.error(f"Error verifying email: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@app.route("/api/server/<guild_id>/email-recipients/resend", methods=["POST"])
@require_paid_api_access
def api_resend_verification(user_session, guild_id):
    """API endpoint to resend verification code"""
    try:
        import secrets
        import hashlib
        
        guild, _ = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        data = request.get_json()
        if not data or 'id' not in data:
            return jsonify({'success': False, 'error': 'Missing recipient ID'}), 400
        
        recipient_id = int(data['id'])
        
        with get_db() as conn:
            cursor = conn.execute(
                """SELECT id, email_address, verification_status, verification_code_sent_at
                   FROM report_recipients 
                   WHERE id = %s AND guild_id = %s AND recipient_type = 'email'""",
                (recipient_id, guild_id)
            )
            recipient = cursor.fetchone()
            
            if not recipient:
                return jsonify({'success': False, 'error': 'Recipient not found'}), 404
            
            if recipient['verification_status'] == 'verified':
                return jsonify({'success': True, 'message': 'Email already verified'})
            
            if recipient['verification_code_sent_at']:
                from datetime import datetime, timedelta
                import pytz
                code_sent_at = recipient['verification_code_sent_at']
                if code_sent_at.tzinfo is None:
                    code_sent_at = pytz.UTC.localize(code_sent_at)
                if datetime.now(pytz.UTC) - code_sent_at < timedelta(minutes=1):
                    return jsonify({'success': False, 'error': 'Please wait 1 minute before requesting a new code.'}), 429
            
            verification_code = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
            code_hash = hashlib.sha256(verification_code.encode()).hexdigest()
            
            conn.execute(
                """UPDATE report_recipients 
                   SET verification_code_hash = %s, verification_code_sent_at = NOW(), verification_attempts = 0
                   WHERE id = %s""",
                (code_hash, recipient_id)
            )
            
            email = recipient['email_address']
        
        try:
            from email_utils import send_email
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            subject = "Your new verification code for Time Warden"
            text_content = f"""Hello!

Here's your new verification code: {verification_code}

Enter this code in the dashboard to verify your email address.

- Time Warden Bot"""
            
            result = loop.run_until_complete(send_email(to=[email], subject=subject, text=text_content))
            loop.close()
            
            if result.get('success'):
                app.logger.info(f"[OK] Verification code resent to {email}")
            else:
                app.logger.warning(f"Failed to resend verification email to {email}: {result.get('error')}")
                return jsonify({'success': False, 'error': 'Failed to send email. Please try again.'}), 500
        except Exception as email_error:
            app.logger.error(f"Error resending verification email: {email_error}")
            return jsonify({'success': False, 'error': 'Failed to send email'}), 500
        
        return jsonify({'success': True, 'message': 'New verification code sent!'})
    except Exception as e:
        app.logger.error(f"Error resending verification: {str(e)}")
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

@app.route("/api/server/<guild_id>/test-email", methods=["POST"])
@require_paid_api_access
def api_send_test_email(user_session, guild_id):
    """Send a test email to verify email setup is working"""
    try:
        guild, _ = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT email_address FROM report_recipients WHERE guild_id = %s AND recipient_type = 'email'",
                (guild_id,)
            )
            recipients = [row['email_address'] for row in cursor.fetchall()]
        
        if not recipients:
            return jsonify({'success': False, 'error': 'No email recipients configured. Add at least one email address first.'}), 400
        
        guild_name = guild.get('name', f'Server {guild_id}')
        
        from email_utils import send_email, log_email_to_file
        import asyncio
        
        subject = f"Test Email - {guild_name}"
        text_content = f"""Test Email from Time Warden

This is a test email to confirm your email setup is working correctly.

Server: {guild_name}
Recipients: {', '.join(recipients)}

If you received this email, your daily report emails are configured correctly!

---
Time Warden Discord Bot
https://time-warden.com
"""
        
        log_email_to_file(
            event_type="test_email_attempt",
            recipients=recipients,
            subject=subject,
            context={"guild_id": str(guild_id), "guild_name": guild_name, "source": "dashboard_test"}
        )
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(send_email(to=recipients, subject=subject, text=text_content))
        finally:
            loop.close()
        
        log_email_to_file(
            event_type="test_email_sent",
            recipients=recipients,
            subject=subject,
            context={"guild_id": str(guild_id), "result": str(result)},
            success=True
        )
        
        app.logger.info(f"[OK] Test email sent to {recipients} for guild {guild_id}")
        
        return jsonify({
            'success': True,
            'message': f'Test email sent to {len(recipients)} recipient(s)',
            'recipients': recipients
        })
        
    except Exception as e:
        app.logger.error(f"Error sending test email: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': f'Failed to send test email: {str(e)}'}), 500

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


@app.route("/api/server/<guild_id>/settings", methods=["GET"])
@require_api_auth
def api_get_server_settings(user_session, guild_id):
    """API endpoint to fetch server settings for dashboard pages"""
    access = get_flask_guild_access(guild_id)
    if not access['is_exempt'] and access['tier'] == 'free' and not access['trial_active']:
        return jsonify({
            'success': False,
            'error': 'Your free trial has expired. Upgrade to Premium to continue.',
            'code': 'TRIAL_EXPIRED',
            'upgrade_url': f'/dashboard/purchase?guild_id={guild_id}',
            'trial_expired': True
        }), 403
    try:
        guild, access_level = verify_guild_access(user_session, guild_id, allow_employee=True)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        settings = get_guild_settings(guild_id)
        
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT bot_access_paid, retention_tier, tier 
                FROM server_subscriptions WHERE guild_id = %s
            """, (int(guild_id),))
            sub_row = cursor.fetchone()
            if sub_row:
                settings['bot_access_paid'] = sub_row.get('bot_access_paid', False)
                settings['retention_tier'] = sub_row.get('retention_tier', 'none')
                settings['tier'] = sub_row.get('tier', 'free')
        
        settings['trial_info'] = {
            'is_trial': access['tier'] == 'free',
            'trial_active': access['trial_active'],
            'days_remaining': access['days_remaining'],
            'is_exempt': access['is_exempt']
        }
        
        return jsonify({'success': True, 'settings': settings})
    except Exception as e:
        app.logger.error(f"Error fetching server settings: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error'}), 500


@app.route("/api/server/<guild_id>/employees", methods=["GET"])
@require_api_auth
def api_get_server_employees(user_session, guild_id):
    """API endpoint to fetch employees for dashboard pages (admin only)"""
    access = get_flask_guild_access(guild_id)
    if not access['is_exempt'] and access['tier'] == 'free' and not access['trial_active']:
        return jsonify({
            'success': False,
            'error': 'Your free trial has expired. Upgrade to Premium to continue.',
            'code': 'TRIAL_EXPIRED',
            'upgrade_url': f'/dashboard/purchase?guild_id={guild_id}',
            'trial_expired': True
        }), 403
    try:
        guild, access_level = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Get guild timezone for accurate week calculation
        guild_settings = get_guild_settings(guild_id)
        guild_tz = guild_settings.get('timezone') or 'America/Chicago'
        
        employees = []
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT ep.user_id, ep.full_name, ep.display_name,
                       ep.is_active, ep.avatar_url, ep.welcome_dm_sent, 
                       ep.first_clock_used, ep.first_clock_at, ep.email,
                       (SELECT COUNT(*) > 0 FROM timeclock_sessions ts 
                        WHERE ts.user_id = ep.user_id AND ts.guild_id = ep.guild_id 
                        AND ts.clock_out_time IS NULL) as is_clocked_in,
                       (SELECT clock_in_time FROM timeclock_sessions ts 
                        WHERE ts.user_id = ep.user_id AND ts.guild_id = ep.guild_id 
                        AND ts.clock_out_time IS NULL ORDER BY clock_in_time DESC LIMIT 1) as current_session_start,
                       (SELECT COALESCE(SUM(EXTRACT(EPOCH FROM (COALESCE(clock_out_time, NOW()) - clock_in_time))), 0)
                        FROM timeclock_sessions ts 
                        WHERE ts.user_id = ep.user_id AND ts.guild_id = ep.guild_id
                        AND clock_in_time >= date_trunc('week', NOW() AT TIME ZONE %s)) / 60.0 as weekly_minutes,
                       (SELECT COUNT(*) FROM time_adjustment_requests tar
                        WHERE tar.user_id = ep.user_id AND tar.guild_id = ep.guild_id
                        AND tar.status = 'pending') as pending_adjustments,
                       (SELECT token FROM employee_profile_tokens ept
                        WHERE ept.user_id = ep.user_id AND ept.guild_id = ep.guild_id
                        AND ept.expires_at > NOW() LIMIT 1) IS NOT NULL as has_kiosk_pin
                FROM employee_profiles ep
                WHERE ep.guild_id = %s AND ep.is_active = TRUE
                ORDER BY COALESCE(ep.display_name, ep.full_name)
            """, (guild_tz, int(guild_id),))
            
            for row in cursor.fetchall():
                current_session_duration = None
                if row['is_clocked_in'] and row.get('current_session_start'):
                    duration_seconds = (datetime.now(pytz.UTC) - row['current_session_start'].replace(tzinfo=pytz.UTC)).total_seconds()
                    current_session_duration = int(duration_seconds / 60)
                
                employees.append({
                    'user_id': str(row['user_id']),
                    'username': row['full_name'] or '',
                    'display_name': row['display_name'] or row['full_name'] or 'Unknown',
                    'is_active': row['is_active'],
                    'is_clocked_in': row['is_clocked_in'],
                    'avatar_url': row['avatar_url'],
                    'current_session_duration': current_session_duration,
                    'weekly_minutes': round(row.get('weekly_minutes') or 0, 1),
                    'pending_adjustments': row.get('pending_adjustments') or 0,
                    'has_kiosk_pin': row.get('has_kiosk_pin') or False,
                    'welcome_dm_sent': row.get('welcome_dm_sent') or False,
                    'first_clock_used': row.get('first_clock_used') or False,
                    'has_email': bool(row.get('email'))
                })
        
        return jsonify({'success': True, 'employees': employees})
    except Exception as e:
        app.logger.error(f"Error fetching employees: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error'}), 500


@app.route("/api/server/<guild_id>/employees/sync", methods=["POST"])
@require_api_auth
def api_sync_server_employees(user_session, guild_id):
    """API endpoint to sync employees from Discord roles into employee_profiles (admin only)"""
    access = get_flask_guild_access(guild_id)
    if not access['is_exempt'] and access['tier'] == 'free' and not access['trial_active']:
        return jsonify({
            'success': False,
            'error': 'Your free trial has expired. Upgrade to Premium to continue.',
            'code': 'TRIAL_EXPIRED',
            'upgrade_url': f'/dashboard/purchase?guild_id={guild_id}',
            'trial_expired': True
        }), 403
    try:
        guild, access_level = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Call bot API to sync employees
        bot_api_url = f"http://127.0.0.1:8081/api/guild/{guild_id}/employees/sync"
        bot_api_secret = os.environ.get('BOT_API_SECRET')
        
        if not bot_api_secret:
            bot_module = _get_bot_module()
            if bot_module:
                bot_api_secret = getattr(bot_module, 'BOT_API_SECRET', None)
        
        if not bot_api_secret:
            return jsonify({'success': False, 'error': 'Bot API not configured'}), 500
        
        import requests
        response = requests.post(
            bot_api_url,
            headers={'Authorization': f'Bearer {bot_api_secret}'},
            json={},
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            return jsonify({
                'success': True,
                'message': data.get('message', 'Employees synced'),
                'synced_count': data.get('synced_count', 0)
            })
        else:
            return jsonify({'success': False, 'error': 'Failed to sync employees'}), 500
            
    except Exception as e:
        app.logger.error(f"Error syncing employees: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error'}), 500


@app.route("/api/server/<guild_id>/employees/send-onboarding", methods=["POST"])
@require_api_auth
def api_send_employee_onboarding(user_session, guild_id):
    """API endpoint to send onboarding DMs to all employees (admin only, premium only)"""
    access = get_flask_guild_access(guild_id)
    if not access['is_exempt'] and access['tier'] == 'free' and not access['trial_active']:
        return jsonify({
            'success': False,
            'error': 'Your free trial has expired. Upgrade to Premium to continue.',
            'code': 'TRIAL_EXPIRED',
            'upgrade_url': f'/dashboard/purchase?guild_id={guild_id}',
            'trial_expired': True
        }), 403
    try:
        guild, access_level = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        if access_level != 'admin':
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        
        # Check premium access
        guild_settings = get_guild_settings(guild_id)
        if not guild_settings.get('has_bot_access'):
            return jsonify({'success': False, 'error': 'Premium feature - please upgrade'}), 403
        
        # Call bot API to send onboarding DMs
        bot_api_url = f"http://127.0.0.1:8081/api/guild/{guild_id}/employees/send-onboarding"
        bot_api_secret = os.environ.get('BOT_API_SECRET')
        
        if not bot_api_secret:
            bot_module = _get_bot_module()
            if bot_module:
                bot_api_secret = getattr(bot_module, 'BOT_API_SECRET', None)
        
        if not bot_api_secret:
            return jsonify({'success': False, 'error': 'Bot API not configured'}), 500
        
        import requests
        response = requests.post(
            bot_api_url,
            headers={'Authorization': f'Bearer {bot_api_secret}'},
            json={},
            timeout=60
        )
        
        if response.status_code == 200:
            data = response.json()
            return jsonify({
                'success': True,
                'message': data.get('message', 'Onboarding sent'),
                'sent_count': data.get('sent_count', 0)
            })
        else:
            error_data = response.json() if response.content else {}
            return jsonify({'success': False, 'error': error_data.get('error', 'Failed to send onboarding')}), 500
            
    except Exception as e:
        app.logger.error(f"Error sending onboarding: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error'}), 500


@app.route("/api/server/<guild_id>/employee/<user_id>/profile", methods=["GET"])
@require_api_auth
def api_get_employee_profile(user_session, guild_id, user_id):
    """API endpoint to fetch employee profile with stats"""
    access = get_flask_guild_access(guild_id)
    if not access['is_exempt'] and access['tier'] == 'free' and not access['trial_active']:
        return jsonify({
            'success': False,
            'error': 'Your free trial has expired. Upgrade to Premium to continue.',
            'code': 'TRIAL_EXPIRED',
            'upgrade_url': f'/dashboard/purchase?guild_id={guild_id}',
            'trial_expired': True
        }), 403
    try:
        guild, access_level = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Allow access if: user is viewing their own profile OR user is admin
        viewer_user_id = user_session.get('user_id')
        is_admin = access_level == 'admin'
        is_own_profile = str(viewer_user_id) == str(user_id)
        
        if not is_admin and not is_own_profile:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Get guild timezone
        guild_settings = get_guild_settings(guild_id)
        guild_tz = guild_settings.get('timezone') or 'America/Chicago'
        
        with get_db() as conn:
            # Get employee profile info
            cursor = conn.execute("""
                SELECT ep.user_id, ep.full_name, ep.display_name, ep.avatar_url,
                       ep.email, ep.hire_date, ep.position, ep.department, ep.company_role,
                       ep.first_clock_at, ep.bio, ep.is_active,
                       ep.profile_setup_completed, ep.welcome_dm_sent, ep.first_clock_used,
                       ep.phone, ep.avatar_choice, ep.profile_background, ep.catchphrase,
                       ep.selected_stickers, ep.accent_color
                FROM employee_profiles ep
                WHERE ep.guild_id = %s AND ep.user_id = %s
            """, (int(guild_id), int(user_id)))
            profile_row = cursor.fetchone()
            app.logger.debug(f"Profile fetched for user {user_id}: {profile_row is not None}")

            if not profile_row:
                return jsonify({'success': False, 'error': 'Employee not found'}), 404

            app.logger.debug(f"Calculating stats for user {user_id}")
            # Calculate stats from timeclock_sessions
            stats_cursor = conn.execute("""
                SELECT 
                    COUNT(*) as total_sessions,
                    COALESCE(SUM(EXTRACT(EPOCH FROM (COALESCE(clock_out_time, NOW()) - clock_in_time))), 0) / 3600.0 as total_hours,
                    COALESCE(MAX(EXTRACT(EPOCH FROM (clock_out_time - clock_in_time))), 0) / 3600.0 as longest_shift_hours,
                    MIN(clock_in_time) as first_session,
                    MAX(clock_in_time) as last_session
                FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s AND clock_out_time IS NOT NULL
            """, (int(guild_id), int(user_id)))
            stats_row = stats_cursor.fetchone()

            # Safety check: ensure stats_row is not None
            if not stats_row:
                app.logger.warning(f"No stats_row returned for user {user_id} in guild {guild_id}")
                # Create default stats row
                stats_row = {
                    'total_sessions': 0,
                    'total_hours': 0,
                    'longest_shift_hours': 0,
                    'first_session': None,
                    'last_session': None
                }

            # Calculate this week's hours
            week_cursor = conn.execute("""
                SELECT COALESCE(SUM(EXTRACT(EPOCH FROM (COALESCE(clock_out_time, NOW()) - clock_in_time))), 0) / 3600.0 as weekly_hours
                FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s
                AND clock_in_time >= date_trunc('week', NOW() AT TIME ZONE %s)
            """, (int(guild_id), int(user_id), guild_tz))
            week_row = week_cursor.fetchone()

            # Safety check: ensure week_row is not None
            if not week_row:
                app.logger.warning(f"No week_row returned for user {user_id} in guild {guild_id}")
                week_row = {'weekly_hours': 0}

            app.logger.debug(f"Calculating weekly hours for user {user_id}")

            # Calculate average weekly hours (total hours / weeks since first clock)
            first_clock = profile_row.get('first_clock_at') or stats_row.get('first_session')
            avg_weekly = 0
            if first_clock and stats_row.get('total_hours'):
                try:
                    # Ensure first_clock is a datetime object
                    if isinstance(first_clock, datetime):
                        naive_first_clock = first_clock.replace(tzinfo=None) if first_clock.tzinfo else first_clock
                        weeks_active = max(1, (datetime.now() - naive_first_clock).days / 7)
                        avg_weekly = round(stats_row['total_hours'] / weeks_active, 1)
                    else:
                        app.logger.warning(f"first_clock is not datetime: {type(first_clock)}")
                except Exception as e:
                    app.logger.error(f"Error calculating avg_weekly: {e}")
                    avg_weekly = 0
            
            # Calculate average daily hours
            avg_daily = 0
            if stats_row.get('total_sessions') and stats_row['total_sessions'] > 0:
                avg_daily = round(stats_row['total_hours'] / stats_row['total_sessions'], 1)
            
            # Calculate tenure
            app.logger.debug(f"Calculating tenure for user {user_id}")
            hire_date = profile_row.get('hire_date')
            tenure_text = "Not set"
            if hire_date:
                try:
                    if isinstance(hire_date, datetime):
                        hire_with_tz = hire_date.replace(tzinfo=pytz.UTC) if hire_date.tzinfo is None else hire_date
                        days = (datetime.now(pytz.UTC) - hire_with_tz).days
                        if days < 30:
                            tenure_text = f"{days} days"
                        elif days < 365:
                            months = days // 30
                            tenure_text = f"{months} month{'s' if months > 1 else ''}"
                        else:
                            years = days // 365
                            months = (days % 365) // 30
                            tenure_text = f"{years} year{'s' if years > 1 else ''}"
                            if months > 0:
                                tenure_text += f", {months} mo"
                    else:
                        app.logger.warning(f"hire_date is not datetime: {type(hire_date)}")
                except Exception as e:
                    app.logger.error(f"Error calculating tenure: {e}")
                    tenure_text = "Error calculating tenure"

            app.logger.debug(f"Checking clock status for user {user_id}")
            # Check if currently clocked in
            clock_cursor = conn.execute("""
                SELECT clock_in_time FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s AND clock_out_time IS NULL
                ORDER BY clock_in_time DESC LIMIT 1
            """, (int(guild_id), int(user_id)))
            clock_row = clock_cursor.fetchone()
            is_clocked_in = clock_row is not None

            app.logger.debug(f"Checking tier for guild {guild_id}")
            # Check server subscription tier for premium customization access using Entitlements
            tier_cursor = conn.execute("""
                SELECT bot_access_paid, COALESCE(retention_tier, 'none') as retention_tier,
                       COALESCE(grandfathered, FALSE) as grandfathered
                FROM server_subscriptions WHERE guild_id = %s
            """, (int(guild_id),))
            tier_row = tier_cursor.fetchone()
            if tier_row:
                guild_tier = Entitlements.get_guild_tier(
                    bool(tier_row['bot_access_paid']),
                    tier_row['retention_tier'],
                    bool(tier_row['grandfathered'])
                )
            else:
                guild_tier = UserTier.FREE
            # Customization available for Premium, Pro, and Grandfathered tiers
            has_premium_customization = guild_tier in [UserTier.PREMIUM, UserTier.PRO, UserTier.GRANDFATHERED]

            app.logger.debug(f"Building profile response for user {user_id}")
            profile_data = {
                'user_id': str(profile_row['user_id']),
                'display_name': profile_row['display_name'] or profile_row['full_name'] or 'Unknown',
                'full_name': profile_row['full_name'] or '',
                'avatar_url': profile_row['avatar_url'],
                'email': profile_row['email'] if is_own_profile or is_admin else None,
                'phone': profile_row.get('phone') if is_own_profile or is_admin else None,
                'hire_date': profile_row['hire_date'].isoformat() if profile_row.get('hire_date') else None,
                'position': profile_row['position'] or '',
                'department': profile_row['department'] or '',
                'company_role': profile_row['company_role'] or '',
                'bio': profile_row['bio'] or '',
                'is_active': profile_row['is_active'],
                'is_clocked_in': is_clocked_in,
                'tenure_text': tenure_text,
                'avatar_choice': profile_row.get('avatar_choice') or 'random',
                'profile_background': profile_row.get('profile_background') or 'default',
                'accent_color': profile_row.get('accent_color') or 'cyan',
                'catchphrase': profile_row.get('catchphrase') or '',
                'selected_stickers': _parse_stickers(profile_row.get('selected_stickers')),
                'stats': {
                    'total_hours': round(stats_row.get('total_hours') or 0, 1),
                    'total_sessions': stats_row.get('total_sessions') or 0,
                    'weekly_hours': round(week_row.get('weekly_hours') or 0, 1),
                    'avg_weekly_hours': avg_weekly,
                    'avg_daily_hours': avg_daily,
                    'longest_shift_hours': round(stats_row.get('longest_shift_hours') or 0, 1),
                    'first_session': stats_row.get('first_session').isoformat() if stats_row.get('first_session') else None,
                    'last_session': stats_row.get('last_session').isoformat() if stats_row.get('last_session') else None
                }
            }
            
            return jsonify({
                'success': True, 
                'profile': profile_data, 
                'is_own_profile': is_own_profile,
                'has_premium_customization': has_premium_customization,
                'guild_tier': guild_tier.value if guild_tier else 'free'
            })
    except Exception as e:
        app.logger.error(f"Error fetching employee profile for guild {guild_id}, user {user_id}")
        app.logger.error(f"Exception type: {type(e).__name__}")
        app.logger.error(f"Exception message: {str(e)}")
        app.logger.error(f"Full traceback:\n{traceback.format_exc()}")
        return jsonify({'success': False, 'error': 'Server error'}), 500


@app.route("/api/server/<guild_id>/employee/<user_id>/profile", methods=["POST"])
@require_api_auth
def api_update_employee_profile(user_session, guild_id, user_id):
    """API endpoint to update employee's own profile (email, etc.)"""
    access = get_flask_guild_access(guild_id)
    if not access['is_exempt'] and access['tier'] == 'free' and not access['trial_active']:
        return jsonify({
            'success': False,
            'error': 'Your free trial has expired. Upgrade to Premium to continue.',
            'code': 'TRIAL_EXPIRED',
            'upgrade_url': f'/dashboard/purchase?guild_id={guild_id}',
            'trial_expired': True
        }), 403
    try:
        guild, access_level = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Only allow updating own profile (or admin can update any)
        viewer_user_id = user_session.get('user_id')
        is_admin = access_level == 'admin'
        is_own_profile = str(viewer_user_id) == str(user_id)
        
        if not is_admin and not is_own_profile:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        # Check server subscription tier for premium customization access using Entitlements
        with get_db() as conn:
            tier_cursor = conn.execute("""
                SELECT bot_access_paid, COALESCE(retention_tier, 'none') as retention_tier, 
                       COALESCE(grandfathered, FALSE) as grandfathered
                FROM server_subscriptions WHERE guild_id = %s
            """, (int(guild_id),))
            tier_row = tier_cursor.fetchone()
            if tier_row:
                guild_tier = Entitlements.get_guild_tier(
                    bool(tier_row['bot_access_paid']),
                    tier_row['retention_tier'],
                    bool(tier_row['grandfathered'])
                )
            else:
                guild_tier = UserTier.FREE
            # Customization available for Premium, Pro, and Grandfathered tiers
            has_premium_customization = guild_tier in [UserTier.PREMIUM, UserTier.PRO, UserTier.GRANDFATHERED]
        
        # Basic fields available to all tiers (text-based info)
        allowed_fields = ['email', 'phone', 'catchphrase']
        
        # Premium customization fields only for Premium/Pro tiers
        premium_fields = ['avatar_choice', 'profile_background', 'accent_color', 'selected_stickers']
        
        # Check if trying to update premium fields without proper tier
        for field in premium_fields:
            if field in data and not has_premium_customization:
                return jsonify({
                    'success': False, 
                    'error': 'Profile customization requires Premium tier. Upgrade to unlock custom avatars, backgrounds, and stickers.',
                    'upgrade_required': True
                }), 403
        
        # Add premium fields if server has Premium/Pro tier
        if has_premium_customization:
            allowed_fields.extend(premium_fields)
        
        if is_admin:
            allowed_fields.extend(['hire_date', 'position', 'department', 'company_role'])
        
        updates = []
        params = []
        
        for field in allowed_fields:
            if field in data:
                value = data[field]
                if field == 'email' and value:
                    # Basic email validation
                    import re
                    if not re.match(r'^[^@]+@[^@]+\.[^@]+$', value):
                        return jsonify({'success': False, 'error': 'Invalid email format'}), 400
                if field == 'phone' and value:
                    # Basic phone validation (allow digits, spaces, dashes, parentheses, plus)
                    import re
                    cleaned = re.sub(r'[^\d]', '', value)
                    if len(cleaned) < 7 or len(cleaned) > 15:
                        return jsonify({'success': False, 'error': 'Invalid phone number'}), 400
                if field == 'avatar_choice' and value:
                    # Validate avatar choice against allowed list
                    allowed_avatars = ['discord', 'random', 'superhero', 'ninja', 'pirate', 'astronaut',
                                       'wizard', 'unicorn', 'dinosaur', 'robot', 'skater', 'beach',
                                       'pumpkin', 'vampire', 'ghost', 'santa', 'snowman', 'cupid', 
                                       'leprechaun', 'bunny']
                    if value not in allowed_avatars:
                        return jsonify({'success': False, 'error': 'Invalid avatar choice'}), 400
                if field == 'profile_background' and value:
                    allowed_backgrounds = ['default', 'sunset', 'ocean', 'forest', 'fire', 'midnight',
                                           'candy', 'aurora', 'cosmic', 'golden', 'mint', 'cherry']
                    if value not in allowed_backgrounds:
                        return jsonify({'success': False, 'error': 'Invalid background choice'}), 400
                if field == 'accent_color' and value:
                    allowed_accents = ['cyan', 'magenta', 'gold', 'green', 'blue', 'red', 'purple', 'teal']
                    if value not in allowed_accents:
                        return jsonify({'success': False, 'error': 'Invalid accent color'}), 400
                if field == 'catchphrase' and value:
                    if len(value) > 50:
                        return jsonify({'success': False, 'error': 'Catchphrase too long (max 50 characters)'}), 400
                if field == 'selected_stickers':
                    # Validate stickers
                    allowed_stickers = ['star', 'coffee', 'fire', 'heart', 'lightning', 
                                        'rainbow', 'pizza', 'music', 'diamond', 'crown']
                    if not isinstance(value, list):
                        value = []
                    if len(value) > 5:
                        return jsonify({'success': False, 'error': 'Maximum 5 stickers allowed'}), 400
                    value = [s for s in value if s in allowed_stickers]
                    # Convert to JSON for storage
                    import json
                    value = json.dumps(value)
                updates.append(f"{field} = %s")
                params.append(value if value else None)
        
        if not updates:
            return jsonify({'success': False, 'error': 'No valid fields to update'}), 400
        
        params.extend([int(guild_id), int(user_id)])
        
        with get_db() as conn:
            conn.execute(f"""
                UPDATE employee_profiles 
                SET {', '.join(updates)}, updated_at = NOW()
                WHERE guild_id = %s AND user_id = %s
            """, params)
        
        return jsonify({'success': True, 'message': 'Profile updated'})
    except Exception as e:
        app.logger.error(f"Error updating employee profile: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error'}), 500


@app.route("/api/server/<guild_id>/roles", methods=["GET"])
@require_api_auth
def api_get_server_roles(user_session, guild_id):
    """API endpoint to fetch roles for dashboard pages"""
    try:
        guild, access_level = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        all_roles = get_guild_roles_from_bot(guild_id) or []
        
        admin_roles = []
        employee_roles = []
        
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT role_id FROM admin_roles WHERE guild_id = %s
            """, (str(guild_id),))
            admin_role_ids = [str(row['role_id']) for row in cursor.fetchall()]
            
            cursor = conn.execute("""
                SELECT role_id FROM employee_roles WHERE guild_id = %s
            """, (str(guild_id),))
            employee_role_ids = [str(row['role_id']) for row in cursor.fetchall()]
        
        for role in all_roles:
            role_id = str(role.get('id'))
            if role_id in admin_role_ids:
                admin_roles.append(role)
            if role_id in employee_role_ids:
                employee_roles.append(role)
        
        return jsonify({
            'success': True,
            'all_roles': all_roles,
            'admin_roles': admin_roles,
            'employee_roles': employee_roles
        })
    except Exception as e:
        app.logger.error(f"Error fetching roles: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error'}), 500


@app.route("/api/server/<guild_id>/channels", methods=["GET"])
@require_api_auth
def api_get_server_channels(user_session, guild_id):
    """API endpoint to fetch text channels for dashboard pages"""
    try:
        guild, access_level = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        channels = get_guild_text_channels(guild_id) or []
        
        return jsonify({'success': True, 'channels': channels})
    except Exception as e:
        app.logger.error(f"Error fetching channels: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error'}), 500


@app.route("/api/server/<guild_id>/employee/<user_id>/entries", methods=["GET"])
@require_api_auth
def api_get_employee_entries(user_session, guild_id, user_id):
    """API endpoint to fetch time entries for an employee (for calendar view)"""
    try:
        guild, access_level = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        start_date = request.args.get('start', '')
        end_date = request.args.get('end', '')
        
        with get_db() as conn:
            query = """
                SELECT session_id, user_id, clock_in_time, clock_out_time,
                       EXTRACT(EPOCH FROM (clock_out_time - clock_in_time)) as duration_seconds
                FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s
            """
            params = [str(guild_id), str(user_id)]
            
            if start_date:
                query += " AND clock_in_time >= %s"
                params.append(start_date)
            if end_date:
                query += " AND clock_in_time <= %s"
                params.append(end_date + ' 23:59:59')
            
            query += " ORDER BY clock_in_time DESC"
            
            cursor = conn.execute(query, params)
            
            entries = []
            for row in cursor.fetchall():
                duration = row['duration_seconds']
                entries.append({
                    'id': row['session_id'],
                    'user_id': str(row['user_id']),
                    'clock_in_time': row['clock_in_time'].isoformat() if row['clock_in_time'] else None,
                    'clock_out_time': row['clock_out_time'].isoformat() if row['clock_out_time'] else None,
                    'duration_seconds': float(duration) if duration else 0
                })
        
        return jsonify({'success': True, 'entries': entries})
    except Exception as e:
        app.logger.error(f"Error fetching employee entries: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error'}), 500


@app.route("/api/server/<guild_id>/employee/<user_id>/status", methods=["GET"])
@require_api_auth
def api_get_employee_status(user_session, guild_id, user_id):
    """API endpoint to fetch current clock status and hours for an employee"""
    try:
        guild, access_level = verify_guild_access(user_session, guild_id, allow_employee=True)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Employees can only view their own status
        if access_level == 'employee' and str(user_session.get('user_id')) != str(user_id):
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        with get_db() as conn:
            # Check if currently clocked in
            cursor = conn.execute("""
                SELECT session_id, clock_in_time FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s AND clock_out_time IS NULL
                ORDER BY clock_in_time DESC LIMIT 1
            """, (str(guild_id), str(user_id)))
            current_session = cursor.fetchone()
            
            is_clocked_in = current_session is not None
            current_session_start = current_session['clock_in_time'].isoformat() if current_session else None
            
            # Get hours today (calculate duration from timestamps, convert to minutes)
            cursor = conn.execute("""
                SELECT COALESCE(SUM(EXTRACT(EPOCH FROM (clock_out_time - clock_in_time)) / 60), 0) as total
                FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s
                AND DATE(clock_in_time) = CURRENT_DATE
                AND clock_out_time IS NOT NULL
            """, (str(guild_id), str(user_id)))
            hours_today = cursor.fetchone()['total'] or 0

            # Get hours this week (convert to minutes)
            cursor = conn.execute("""
                SELECT COALESCE(SUM(EXTRACT(EPOCH FROM (clock_out_time - clock_in_time)) / 60), 0) as total
                FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s
                AND clock_in_time >= DATE_TRUNC('week', CURRENT_DATE)
                AND clock_out_time IS NOT NULL
            """, (str(guild_id), str(user_id)))
            hours_week = cursor.fetchone()['total'] or 0

            # Get hours this month (convert to minutes)
            cursor = conn.execute("""
                SELECT COALESCE(SUM(EXTRACT(EPOCH FROM (clock_out_time - clock_in_time)) / 60), 0) as total
                FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s
                AND clock_in_time >= DATE_TRUNC('month', CURRENT_DATE)
                AND clock_out_time IS NOT NULL
            """, (str(guild_id), str(user_id)))
            hours_month = cursor.fetchone()['total'] or 0
        
        return jsonify({
            'success': True,
            'is_clocked_in': is_clocked_in,
            'current_session_start': current_session_start,
            'hours_today': hours_today,
            'hours_this_week': hours_week,
            'hours_this_month': hours_month
        })
    except Exception as e:
        app.logger.error(f"Error fetching employee status: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error'}), 500


@app.route("/api/server/<guild_id>/employee/<user_id>/sessions", methods=["GET"])
@require_api_auth
def api_get_employee_sessions(user_session, guild_id, user_id):
    """API endpoint to fetch recent sessions for an employee"""
    try:
        guild, access_level = verify_guild_access(user_session, guild_id, allow_employee=True)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Employees can only view their own sessions
        if access_level == 'employee' and str(user_session.get('user_id')) != str(user_id):
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        try:
            limit = int(request.args.get('limit', 10))
            if limit < 1: limit = 1
            limit = min(limit, 50)
        except (ValueError, TypeError):
            limit = 10
        
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT session_id, clock_in_time, clock_out_time,
                       EXTRACT(EPOCH FROM (clock_out_time - clock_in_time)) as duration_seconds
                FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s
                ORDER BY clock_in_time DESC
                LIMIT %s
            """, (str(guild_id), str(user_id), limit))
            
            sessions = []
            for row in cursor.fetchall():
                duration_seconds = float(row['duration_seconds']) if row['duration_seconds'] else 0
                duration_minutes = int(duration_seconds // 60) if duration_seconds else 0
                sessions.append({
                    'id': row['session_id'],
                    'clock_in_time': row['clock_in_time'].isoformat() if row['clock_in_time'] else None,
                    'clock_out_time': row['clock_out_time'].isoformat() if row['clock_out_time'] else None,
                    'duration_minutes': duration_minutes
                })
        
        return jsonify({'success': True, 'sessions': sessions})
    except Exception as e:
        app.logger.error(f"Error fetching employee sessions: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error'}), 500


@app.route("/api/server/<guild_id>/entries/<entry_id>", methods=["PUT"])
@require_api_auth
def api_update_entry(user_session, guild_id, entry_id):
    """API endpoint to update a time entry (admin only)"""
    try:
        guild, access_level = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        data = request.get_json()
        clock_in = data.get('clock_in_time')
        clock_out = data.get('clock_out_time')
        admin_notes = data.get('admin_notes', '')
        
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT session_id, user_id FROM timeclock_sessions 
                WHERE session_id = %s AND guild_id = %s
            """, (int(entry_id), str(guild_id)))
            entry = cursor.fetchone()
            
            if not entry:
                return jsonify({'success': False, 'error': 'Entry not found'}), 404
            
            conn.execute("""
                UPDATE timeclock_sessions 
                SET clock_in_time = %s, clock_out_time = %s
                WHERE session_id = %s AND guild_id = %s
            """, (clock_in, clock_out, int(entry_id), str(guild_id)))
        
        return jsonify({'success': True})
    except Exception as e:
        app.logger.error(f"Error updating entry: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error'}), 500


@app.route("/api/server/<guild_id>/entries/<entry_id>", methods=["DELETE"])
@require_api_auth
def api_delete_entry(user_session, guild_id, entry_id):
    """API endpoint to delete a time entry (admin only)"""
    try:
        guild, access_level = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        with get_db() as conn:
            cursor = conn.execute("""
                DELETE FROM timeclock_sessions 
                WHERE session_id = %s AND guild_id = %s
                RETURNING session_id
            """, (int(entry_id), str(guild_id)))
            deleted = cursor.fetchone()
            
            if not deleted:
                return jsonify({'success': False, 'error': 'Entry not found'}), 404
        
        return jsonify({'success': True})
    except Exception as e:
        app.logger.error(f"Error deleting entry: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error'}), 500


@app.route("/api/server/<guild_id>/calendar/monthly-summary", methods=["GET"])
@require_api_auth
def api_get_monthly_summary(user_session, guild_id):
    """
    Admin Calendar API: Get guild-wide daily summary for a month.
    Returns shift counts and total hours per day for all employees.
    """
    access = get_flask_guild_access(guild_id)
    if not access['is_exempt'] and access['tier'] == 'free' and not access['trial_active']:
        return jsonify({
            'success': False,
            'error': 'Your free trial has expired. Upgrade to Premium to continue.',
            'code': 'TRIAL_EXPIRED',
            'upgrade_url': f'/dashboard/purchase?guild_id={guild_id}',
            'trial_expired': True
        }), 403
    try:
        guild, access_level = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        year = request.args.get('year', type=int)
        month = request.args.get('month', type=int)
        
        if not year or not month:
            from datetime import date
            today = date.today()
            year = year or today.year
            month = month or today.month
        
        from datetime import datetime
        from calendar import monthrange
        
        _, last_day = monthrange(year, month)
        start_date = f"{year}-{month:02d}-01"
        end_date = f"{year}-{month:02d}-{last_day}"
        
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT 
                    DATE(clock_in_time) as work_date,
                    COUNT(DISTINCT user_id) as employee_count,
                    COUNT(*) as session_count,
                    COALESCE(SUM(EXTRACT(EPOCH FROM (COALESCE(clock_out_time, NOW()) - clock_in_time))), 0) as total_seconds
                FROM timeclock_sessions
                WHERE guild_id = %s 
                  AND clock_in_time >= %s
                  AND clock_in_time < %s::date + interval '1 day'
                GROUP BY DATE(clock_in_time)
                ORDER BY work_date
            """, (str(guild_id), start_date, end_date))
            
            days = {}
            for row in cursor.fetchall():
                date_str = row['work_date'].strftime('%Y-%m-%d')
                days[date_str] = {
                    'date': date_str,
                    'employee_count': row['employee_count'],
                    'session_count': row['session_count'],
                    'total_hours': round(row['total_seconds'] / 3600, 2)
                }
        
        return jsonify({
            'success': True,
            'year': year,
            'month': month,
            'days': days
        })
    except Exception as e:
        app.logger.error(f"Error fetching monthly summary: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error'}), 500


@app.route("/api/server/<guild_id>/calendar/day-detail", methods=["GET"])
@require_api_auth
def api_get_day_detail(user_session, guild_id):
    """
    Admin Calendar API: Get all employees and their sessions for a specific day.
    Returns employee info with their clock in/out times.
    """
    access = get_flask_guild_access(guild_id)
    if not access['is_exempt'] and access['tier'] == 'free' and not access['trial_active']:
        return jsonify({
            'success': False,
            'error': 'Your free trial has expired. Upgrade to Premium to continue.',
            'code': 'TRIAL_EXPIRED',
            'upgrade_url': f'/dashboard/purchase?guild_id={guild_id}',
            'trial_expired': True
        }), 403
    try:
        guild, access_level = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        date_str = request.args.get('date')
        if not date_str:
            return jsonify({'success': False, 'error': 'Missing date parameter'}), 400
        
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT 
                    s.session_id,
                    s.user_id,
                    s.clock_in_time,
                    s.clock_out_time,
                    EXTRACT(EPOCH FROM (COALESCE(s.clock_out_time, NOW()) - s.clock_in_time)) as duration_seconds,
                    ep.display_name,
                    ep.username,
                    ep.avatar_url,
                    ep.position
                FROM timeclock_sessions s
                LEFT JOIN employee_profiles ep ON s.guild_id::text = ep.guild_id::text AND s.user_id::text = ep.user_id::text
                WHERE s.guild_id = %s 
                  AND DATE(s.clock_in_time) = %s
                ORDER BY s.clock_in_time ASC
            """, (str(guild_id), date_str))
            
            sessions = []
            for row in cursor.fetchall():
                duration = row['duration_seconds']
                sessions.append({
                    'session_id': row['session_id'],
                    'user_id': str(row['user_id']),
                    'clock_in_time': row['clock_in_time'].isoformat() if row['clock_in_time'] else None,
                    'clock_out_time': row['clock_out_time'].isoformat() if row['clock_out_time'] else None,
                    'duration_seconds': float(duration) if duration else 0,
                    'display_name': row['display_name'] or row['username'] or 'Unknown',
                    'username': row['username'],
                    'avatar_url': row['avatar_url'],
                    'position': row['position']
                })
        
        return jsonify({
            'success': True,
            'date': date_str,
            'sessions': sessions
        })
    except Exception as e:
        import traceback
        app.logger.error(f"Error fetching day detail for guild {guild_id}, date {request.args.get('date')}: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'success': False, 'error': 'Server error'}), 500


@app.route("/api/server/<guild_id>/sessions/admin-create", methods=["POST"])
@require_api_auth
def api_admin_create_session(user_session, guild_id):
    """
    Admin API: Create a new session for an employee (admin logged them in/out).
    Used when employee forgot to clock in/out and admin is fixing it.
    """
    try:
        guild, access_level = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        data = request.get_json()
        user_id = data.get('user_id')
        clock_in = data.get('clock_in_time')
        clock_out = data.get('clock_out_time')
        
        if not user_id or not clock_in:
            return jsonify({'success': False, 'error': 'Missing user_id or clock_in_time'}), 400
        
        with get_db() as conn:
            cursor = conn.execute("""
                INSERT INTO timeclock_sessions (guild_id, user_id, clock_in_time, clock_out_time)
                VALUES (%s, %s, %s, %s)
                RETURNING session_id
            """, (str(guild_id), str(user_id), clock_in, clock_out))
            new_session = cursor.fetchone()
        
        app.logger.info(f"Admin {user_session.get('username')} created session for user {user_id} in guild {guild_id}")
        
        return jsonify({
            'success': True,
            'session_id': new_session['session_id']
        })
    except Exception as e:
        app.logger.error(f"Error creating admin session: {str(e)}")
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
    """Initialize purchase flow - store intent and redirect to OAuth or server selection"""
    valid_products = ['premium', 'pro', 'bot_access', 'retention_7day', 'retention_30day']
    if product_type not in valid_products:
        return "<h1>Invalid Product</h1><p>Unknown product type.</p><a href='/'>Return Home</a>", 400
    
    purchase_data = {
        'product_type': product_type,
        'initiated_at': datetime.now(timezone.utc).isoformat()
    }
    session['purchase_intent'] = purchase_data
    
    session_id = session.get('session_id')
    if session_id:
        user_session = get_user_session(session_id)
        if user_session:
            app.logger.info(f"Purchase flow: user already logged in, skipping OAuth for {product_type}")
            return redirect('/purchase/select_server')
    
    state = create_oauth_state(metadata={'purchase_intent': purchase_data})
    redirect_uri = get_redirect_uri()
    
    params = {
        'client_id': DISCORD_CLIENT_ID,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': DISCORD_OAUTH_SCOPES,
        'state': state
    }
    
    auth_url = f'https://discord.com/oauth2/authorize?{urlencode(params)}'
    app.logger.info(f"Purchase flow initiated for {product_type} (intent stored in OAuth state)")
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
        
        apply_trial = False
        if product_type in ['premium', 'pro']:
            try:
                with get_db() as conn:
                    cursor = conn.execute(
                        "SELECT id FROM trial_usage WHERE guild_id = %s",
                        (int(guild_id),)
                    )
                    if not cursor.fetchone():
                        apply_trial = True
                        app.logger.info(f"Guild {guild_id} eligible for first-month-free trial")
            except Exception as e:
                app.logger.warning(f"Could not check trial eligibility: {e}")
        
        # Create checkout session
        checkout_url = create_secure_checkout_session(
            guild_id=int(guild_id),
            product_type=product_type,
            guild_name=authorized_guild.get('name', ''),
            apply_trial_coupon=apply_trial
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
        <title>Purchase Successful - Time Warden</title>
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
        <title>Purchase Cancelled - Time Warden</title>
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

@app.route("/api/guild/<guild_id>/employees/calendar-list")
@require_paid_api_access
def api_get_employees_for_calendar(user_session, guild_id):
    """
    Get all employees for the admin calendar dropdown.
    Returns employees from profiles and sessions tables.
    """
    try:
        employees = get_employees_for_calendar(int(guild_id))
        
        return jsonify({
            'success': True,
            'employees': employees
        })
    except Exception as e:
        app.logger.error(f"Error fetching employees for calendar: {e}")
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
            
            # Queue email notification to verified recipients (non-blocking)
            from email_utils import queue_adjustment_notification_email
            queue_adjustment_notification_email(
                int(guild_id),
                request_id,
                int(user_session['user_id']),
                request_type,
                reason
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
                    SELECT session_id, clock_in_time, clock_out_time,
                           EXTRACT(EPOCH FROM (clock_out_time - clock_in_time)) as duration_seconds
                    FROM timeclock_sessions
                    WHERE session_id = %s AND guild_id = %s AND user_id = %s
                """, (session_id, str(guild_id), str(user_id)))
                
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
                    SELECT session_id, clock_in_time as clock_in, clock_out_time as clock_out,
                           EXTRACT(EPOCH FROM (clock_out_time - clock_in_time)) as duration_seconds
                    FROM timeclock_sessions
                    WHERE session_id = %s AND guild_id = %s AND user_id = %s
                """, (session_id, str(guild_id), str(user_id)))
                
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
    Get adjustment request history.
    For employees: returns their own requests.
    For admins: returns all requests (or filtered by user_id param).
    Returns all requests (pending, approved, denied) for audit trail.
    """
    try:
        viewer_user_id = int(user_session['user_id'])
        
        # Check if user is admin
        admin_status = check_user_admin_realtime(viewer_user_id, guild_id)
        is_admin = admin_status.get('is_admin', False)
        
        # Determine which user's requests to fetch
        requested_user_id = request.args.get('user_id')
        if requested_user_id:
            target_user_id = int(requested_user_id)
        else:
            target_user_id = viewer_user_id
        
        # Non-admins can only see their own requests
        if not is_admin and target_user_id != viewer_user_id:
            target_user_id = viewer_user_id
        
        if is_admin and not requested_user_id:
            # Admin viewing all - get all history
            adjustment_requests = get_all_adjustment_history(int(guild_id))
        else:
            # Get specific user's history
            adjustment_requests = get_user_adjustment_history(int(guild_id), target_user_id)
        
        serialized_requests = []
        for req in adjustment_requests:
            req_dict = dict(req)
            for key, value in req_dict.items():
                if isinstance(value, datetime):
                    req_dict[key] = value.isoformat()
            serialized_requests.append(req_dict)
            
        return jsonify({'success': True, 'requests': serialized_requests, 'history': serialized_requests})
        
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


@app.route("/api/guild/<guild_id>/admin/master-calendar")
@require_api_auth
def api_get_admin_master_calendar(user_session, guild_id):
    """
    Get aggregated calendar data for all employees (admin only).
    Returns sessions grouped by date with employee breakdown per day.
    
    Query params:
        year: Target year (default: current year)
        month: Target month 1-12 (default: current month)
    """
    try:
        import calendar as cal_module
        import pytz
        
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
        
        # Get query parameters
        now = datetime.now(timezone.utc)
        year = int(request.args.get('year', now.year))
        month = int(request.args.get('month', now.month))
        
        if not (1 <= month <= 12):
            return jsonify({'success': False, 'error': 'Month must be 1-12'}), 400
        if not (2020 <= year <= 2100):
            return jsonify({'success': False, 'error': 'Invalid year'}), 400
        
        # Get guild timezone
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT timezone FROM guild_settings WHERE guild_id = %s",
                (int(guild_id),)
            )
            row = cursor.fetchone()
            guild_tz_str = row['timezone'] if row else 'America/New_York'
        
        guild_tz = pytz.timezone(guild_tz_str)
        first_day = datetime(year, month, 1, 0, 0, 0)
        last_day_num = cal_module.monthrange(year, month)[1]
        last_day = datetime(year, month, last_day_num, 23, 59, 59)
        
        # Convert to UTC for database query
        first_day_utc = guild_tz.localize(first_day).astimezone(pytz.utc)
        last_day_utc = guild_tz.localize(last_day).astimezone(pytz.utc)
        
        # Query all sessions for the month with employee info (using timeclock_sessions)
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT 
                    s.session_id as id,
                    s.user_id,
                    s.clock_in_time as clock_in,
                    s.clock_out_time as clock_out,
                    EXTRACT(EPOCH FROM (s.clock_out_time - s.clock_in_time)) as duration_seconds,
                    DATE(s.clock_in_time AT TIME ZONE 'UTC' AT TIME ZONE %s) as work_date,
                    COALESCE(p.display_name, p.full_name, s.user_id) as employee_name
                FROM timeclock_sessions s
                LEFT JOIN employee_profiles p ON s.user_id = p.user_id::text AND s.guild_id = p.guild_id::text
                WHERE s.guild_id = %s
                  AND s.clock_in_time >= %s
                  AND s.clock_in_time <= %s
                ORDER BY s.clock_in_time ASC
            """, (guild_tz_str, str(guild_id), first_day_utc, last_day_utc))
            
            sessions = cursor.fetchall()
            
            # Also get list of all employees for dropdown
            cursor = conn.execute("""
                SELECT user_id, 
                       COALESCE(display_name, full_name, CAST(user_id AS TEXT)) as name
                FROM employee_profiles 
                WHERE guild_id = %s
                ORDER BY COALESCE(display_name, full_name, CAST(user_id AS TEXT))
            """, (int(guild_id),))
            employees = [{'user_id': str(r['user_id']), 'name': r['name']} for r in cursor.fetchall()]
        
        # Group sessions by date
        days_data = {}
        for session in sessions:
            date_key = session['work_date'].isoformat()
            
            if date_key not in days_data:
                days_data[date_key] = {
                    'date': date_key,
                    'employees': {},
                    'total_sessions': 0,
                    'total_hours': 0
                }
            
            user_id = str(session['user_id'])
            if user_id not in days_data[date_key]['employees']:
                days_data[date_key]['employees'][user_id] = {
                    'user_id': user_id,
                    'name': session['employee_name'],
                    'sessions': [],
                    'total_seconds': 0
                }
            
            # Convert timestamps to guild timezone
            clock_in_local = session['clock_in'].replace(tzinfo=pytz.utc).astimezone(guild_tz)
            clock_out_local = session['clock_out'].replace(tzinfo=pytz.utc).astimezone(guild_tz) if session['clock_out'] else None
            
            session_data = {
                'id': session['id'],
                'clock_in': clock_in_local.isoformat(),
                'clock_out': clock_out_local.isoformat() if clock_out_local else None,
                'duration_seconds': session['duration_seconds'] or 0
            }
            
            days_data[date_key]['employees'][user_id]['sessions'].append(session_data)
            days_data[date_key]['employees'][user_id]['total_seconds'] += session['duration_seconds'] or 0
            days_data[date_key]['total_sessions'] += 1
            days_data[date_key]['total_hours'] += (session['duration_seconds'] or 0) / 3600
        
        # Convert employees dict to list for each day
        days_list = []
        for date_key in sorted(days_data.keys()):
            day = days_data[date_key]
            day['employees'] = list(day['employees'].values())
            day['employee_count'] = len(day['employees'])
            day['total_hours'] = round(day['total_hours'], 2)
            days_list.append(day)
        
        return jsonify({
            'success': True,
            'data': {
                'year': year,
                'month': month,
                'timezone': guild_tz_str,
                'days': days_list,
                'employees': employees
            }
        })
        
    except Exception as e:
        app.logger.error(f"Error fetching admin master calendar: {e}")
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
        
        # Query sessions for the month (using timeclock_sessions)
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT 
                    session_id as id,
                    clock_in_time as clock_in,
                    clock_out_time as clock_out,
                    EXTRACT(EPOCH FROM (clock_out_time - clock_in_time)) as duration_seconds,
                    DATE(clock_in_time AT TIME ZONE 'UTC' AT TIME ZONE %s) as work_date
                FROM timeclock_sessions
                WHERE guild_id = %s
                  AND user_id = %s
                  AND clock_in_time >= %s
                  AND clock_in_time <= %s
                ORDER BY clock_in_time ASC
            """, (guild_tz_str, str(guild_id), str(user_id), first_day_utc, last_day_utc))
            
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
                SELECT session_id, clock_in_time, clock_out_time
                FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s AND clock_out_time IS NULL
                ORDER BY clock_in_time DESC
                LIMIT 1
            """, (str(guild_id), str(user_id)))
            
            active_session = cursor.fetchone()
            
            if not active_session:
                return jsonify({'success': False, 'error': 'No active session found'}), 404
            
            session_id = active_session['session_id']
            clock_in = active_session['clock_in_time']
            clock_out_time = datetime.now(timezone.utc)
            
            if clock_in.tzinfo is None:
                clock_in = clock_in.replace(tzinfo=timezone.utc)
            
            duration_seconds = int((clock_out_time - clock_in).total_seconds())
            
            conn.execute("""
                UPDATE timeclock_sessions
                SET clock_out_time = %s
                WHERE session_id = %s
            """, (clock_out_time, session_id))
        
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

@app.route("/api/guild/<guild_id>/admin/edit-session", methods=["POST"])
@require_api_auth
def api_admin_edit_session(user_session, guild_id):
    """
    Admin endpoint to directly edit a session's clock in/out times.
    Creates an audit log entry for the change.
    """
    try:
        if not guild_id.isdigit() or len(guild_id) > 20:
            return jsonify({'success': False, 'error': 'Invalid guild ID'}), 400
        
        # Check guild has paid access
        access_status = check_guild_paid_access(guild_id)
        if not access_status['bot_invited'] or not access_status['bot_access_paid']:
            return jsonify({'success': False, 'error': 'Server does not have paid access'}), 403
        
        # Verify admin access
        admin_status = check_user_admin_realtime(user_session['user_id'], guild_id)
        if not admin_status.get('is_admin', False):
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        
        data = request.get_json()
        session_id = data.get('session_id')
        new_clock_in = data.get('clock_in')
        new_clock_out = data.get('clock_out')
        reason = data.get('reason', 'Admin adjustment')
        
        if not session_id:
            return jsonify({'success': False, 'error': 'Session ID required'}), 400
        
        import pytz
        
        with get_db() as conn:
            # Get original session (using timeclock_sessions)
            cursor = conn.execute("""
                SELECT session_id, user_id, clock_in_time, clock_out_time,
                       EXTRACT(EPOCH FROM (clock_out_time - clock_in_time)) as duration_seconds
                FROM timeclock_sessions
                WHERE session_id = %s AND guild_id = %s
            """, (session_id, str(guild_id)))
            
            session = cursor.fetchone()
            if not session:
                return jsonify({'success': False, 'error': 'Session not found'}), 404
            
            # Parse new times
            updates = {}
            if new_clock_in:
                updates['clock_in_time'] = datetime.fromisoformat(new_clock_in.replace('Z', '+00:00'))
            if new_clock_out:
                updates['clock_out_time'] = datetime.fromisoformat(new_clock_out.replace('Z', '+00:00'))
            
            if not updates:
                return jsonify({'success': False, 'error': 'No changes provided'}), 400
            
            # Calculate new duration if both times are set
            final_clock_in = updates.get('clock_in_time', session['clock_in_time'])
            final_clock_out = updates.get('clock_out_time', session['clock_out_time'])
            
            if final_clock_in and final_clock_out:
                if final_clock_in.tzinfo is None:
                    final_clock_in = final_clock_in.replace(tzinfo=timezone.utc)
                if final_clock_out.tzinfo is None:
                    final_clock_out = final_clock_out.replace(tzinfo=timezone.utc)
                
                # Validate clock_out is after clock_in
                if final_clock_out <= final_clock_in:
                    return jsonify({'success': False, 'error': 'Clock out must be after clock in'}), 400
                
                new_duration = int((final_clock_out - final_clock_in).total_seconds())
                
                # Sanity check - max 24 hours per session
                if new_duration > 86400:
                    return jsonify({'success': False, 'error': 'Session duration cannot exceed 24 hours'}), 400
            else:
                new_duration = session['duration_seconds'] or 0
            
            # Update session (timeclock_sessions)
            conn.execute("""
                UPDATE timeclock_sessions
                SET clock_in_time = COALESCE(%s, clock_in_time),
                    clock_out_time = COALESCE(%s, clock_out_time)
                WHERE session_id = %s
            """, (updates.get('clock_in_time'), updates.get('clock_out_time'), session_id))
            
            # Log the change using JSONB details column (table schema: id, request_id, action, actor_id, timestamp, details)
            def safe_isoformat(val):
                """Safely convert datetime to ISO string, handling None and already-string values"""
                if val is None:
                    return None
                if isinstance(val, str):
                    return val
                if hasattr(val, 'isoformat'):
                    return val.isoformat()
                return str(val)
            
            audit_details = {
                'action_type': 'admin_edit',
                'guild_id': str(guild_id),
                'user_id': session['user_id'],
                'session_id': session_id,
                'old_clock_in': safe_isoformat(session['clock_in_time']),
                'old_clock_out': safe_isoformat(session['clock_out_time']),
                'new_clock_in': safe_isoformat(updates.get('clock_in_time')),
                'new_clock_out': safe_isoformat(updates.get('clock_out_time')),
                'reason': reason
            }
            conn.execute("""
                INSERT INTO adjustment_audit_log 
                (action, actor_id, details)
                VALUES (%s, %s, %s)
            """, ('admin_edit', int(user_session['user_id']), json.dumps(audit_details)))
        
        app.logger.info(f"Admin {user_session.get('username')} edited session {session_id} in guild {guild_id}")
        
        return jsonify({
            'success': True,
            'message': 'Session updated successfully',
            'session_id': session_id
        })
        
    except Exception as e:
        app.logger.error(f"Error editing session: {e}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': str(e)}), 500


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
                SELECT session_id, clock_in_time, clock_out_time
                FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s AND clock_out_time IS NULL
                ORDER BY clock_in_time DESC
                LIMIT 1
            """, (str(guild_id), str(user_id)))
            
            active_session = cursor.fetchone()
            
            if not active_session:
                return jsonify({'success': False, 'error': 'No active session found for this employee'}), 404
            
            session_id = active_session['session_id']
            clock_in = active_session['clock_in_time']
            clock_out_time = datetime.now(timezone.utc)
            
            if clock_in.tzinfo is None:
                clock_in = clock_in.replace(tzinfo=timezone.utc)
            
            duration_seconds = int((clock_out_time - clock_in).total_seconds())
            
            conn.execute("""
                UPDATE timeclock_sessions
                SET clock_out_time = %s
                WHERE session_id = %s
            """, (clock_out_time, session_id))
        
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


@app.route("/api/server/<guild_id>/employee/<user_id>/reset-pin", methods=["POST"])
@require_paid_api_access
def api_reset_employee_pin(user_session, guild_id, user_id):
    """Reset/regenerate an employee's kiosk PIN token"""
    try:
        guild, access_level = verify_guild_access(user_session, guild_id)
        if not guild or access_level != 'admin':
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        
        with get_db() as conn:
            conn.execute("""
                DELETE FROM employee_profile_tokens 
                WHERE guild_id = %s AND user_id = %s
            """, (int(guild_id), int(user_id)))
            
            conn.execute("""
                INSERT INTO employee_profile_tokens (guild_id, user_id, delivery_method, expires_at)
                VALUES (%s, %s, 'ephemeral', NOW() + INTERVAL '30 days')
            """, (int(guild_id), int(user_id)))
        
        app.logger.info(f"Admin {user_session.get('username')} reset PIN for user {user_id} in guild {guild_id}")
        return jsonify({'success': True, 'message': 'Kiosk PIN has been reset'})
        
    except Exception as e:
        app.logger.error(f"Error resetting PIN: {e}")
        return jsonify({'success': False, 'error': 'Failed to reset PIN'}), 500


@app.route("/api/server/<guild_id>/employee/<user_id>/rerun-onboarding", methods=["POST"])
@require_paid_api_access
def api_rerun_employee_onboarding(user_session, guild_id, user_id):
    """Reset onboarding flags and trigger welcome DM for an employee"""
    try:
        guild, access_level = verify_guild_access(user_session, guild_id)
        if not guild or access_level != 'admin':
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        
        with get_db() as conn:
            cursor = conn.execute("""
                UPDATE employee_profiles 
                SET welcome_dm_sent = FALSE, first_clock_used = FALSE
                WHERE guild_id = %s AND user_id = %s
                RETURNING display_name, full_name
            """, (int(guild_id), int(user_id)))
            row = cursor.fetchone()
            
            if not row:
                return jsonify({'success': False, 'error': 'Employee not found'}), 404
        
        try:
            from bot import trigger_welcome_dm
            result = trigger_welcome_dm(int(guild_id), int(user_id))
            if result.get('success'):
                app.logger.info(f"Admin {user_session.get('username')} reran onboarding for user {user_id} in guild {guild_id}")
                return jsonify({'success': True, 'message': 'Welcome DM sent successfully'})
            else:
                return jsonify({'success': True, 'message': 'Onboarding flags reset (DM may not have sent - user may have DMs disabled)'})
        except Exception as dm_error:
            app.logger.warning(f"DM failed during rerun onboarding: {dm_error}")
            return jsonify({'success': True, 'message': 'Onboarding flags reset (DM could not be sent)'})
        
    except Exception as e:
        app.logger.error(f"Error rerunning onboarding: {e}")
        return jsonify({'success': False, 'error': 'Failed to rerun onboarding'}), 500


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
        
        # Get total sessions count (using timeclock_sessions)
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT COUNT(*) as total_sessions
                FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s
            """, (str(guild_id), str(user_id)))
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
                SELECT clock_in_time as clock_in, clock_out_time as clock_out, 
                       EXTRACT(EPOCH FROM (clock_out_time - clock_in_time)) as duration_seconds
                FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s
                AND clock_in_time::date >= %s AND clock_in_time::date < %s
                ORDER BY clock_in_time ASC
            """, (str(guild_id), str(user_id), week_start, week_end))
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

# ============================================
# KIOSK CONTROL CENTER ROUTES
# ============================================

@app.route("/kiosk/<guild_id>")
@require_kiosk_access
def kiosk_page(guild_id):
    """Render the kiosk control center for a specific guild"""
    return render_template("kiosk.html", guild_id=guild_id)

@app.route("/api/kiosk/<guild_id>/employees")
@require_kiosk_access
def api_kiosk_employees(guild_id):
    """Get all employees for the kiosk display optimized with CTE"""
    try:
        with get_db() as conn:
            # Check if kiosk customization is enabled for this guild
            settings_cursor = conn.execute("""
                SELECT COALESCE(allow_kiosk_customization, false) as allow_kiosk_customization
                FROM guild_settings WHERE guild_id = %s
            """, (int(guild_id),))
            settings_row = settings_cursor.fetchone()
            allow_kiosk_customization = settings_row['allow_kiosk_customization'] if settings_row else False
            
            # Using CTE (Common Table Expression) to optimize subqueries
            # This allows us to calculate counts for all employees in one pass 
            # rather than running a subquery per row, which scales much better.
            cursor = conn.execute("""
                WITH pending_counts AS (
                    SELECT user_id::text, COUNT(*) as count 
                    FROM time_adjustment_requests 
                    WHERE guild_id = %s AND status = 'pending'
                    GROUP BY user_id
                ),
                missing_punch_counts AS (
                    SELECT user_id::text, COUNT(*) as count
                    FROM timeclock_sessions
                    WHERE guild_id = %s 
                    AND clock_out_time IS NULL
                    AND clock_in_time < NOW() - INTERVAL '8 hours'
                    AND DATE(clock_in_time) > CURRENT_DATE - INTERVAL '7 days'
                    GROUP BY user_id
                )
                SELECT ep.user_id, ep.display_name, ep.first_name, ep.last_name, ep.avatar_url,
                       ep.position, ep.department, ep.email, ep.timesheet_email, ep.accent_color, ep.profile_background,
                       ep.catchphrase, ep.selected_stickers,
                       EXISTS(SELECT 1 FROM employee_pins WHERE guild_id = %s AND user_id = ep.user_id) as has_pin,
                       EXISTS(SELECT 1 FROM timeclock_sessions WHERE guild_id = %s AND user_id::text = ep.user_id::text AND clock_out_time IS NULL) as is_clocked_in,
                       COALESCE(pc.count, 0) as pending_requests,
                       COALESCE(mpc.count, 0) as missing_punches
                FROM employee_profiles ep
                LEFT JOIN pending_counts pc ON pc.user_id = ep.user_id::text
                LEFT JOIN missing_punch_counts mpc ON mpc.user_id = ep.user_id::text
                WHERE ep.guild_id = %s AND ep.is_active = TRUE
                ORDER BY COALESCE(ep.display_name, ep.first_name, ep.user_id::text)
            """, (str(guild_id), str(guild_id), int(guild_id), str(guild_id), int(guild_id)))
            employees = cursor.fetchall()
        
        employee_list = []
        for emp in employees:
            display_name = emp['display_name'] or f"{emp['first_name'] or ''} {emp['last_name'] or ''}".strip() or f"User {emp['user_id']}"
            has_email = bool(emp.get('timesheet_email') or emp.get('email'))
            pending_requests = emp.get('pending_requests', 0)
            missing_punches = emp.get('missing_punches', 0)
            has_alerts = not has_email or pending_requests > 0 or missing_punches > 0
            
            employee_list.append({
                'user_id': str(emp['user_id']),
                'display_name': display_name,
                'avatar_url': emp['avatar_url'],
                'position': emp['position'],
                'has_pin': emp['has_pin'],
                'is_clocked_in': emp['is_clocked_in'],
                'has_email': has_email,
                'has_alerts': has_alerts,
                'pending_requests': pending_requests,
                'missing_punches': missing_punches,
                'accent_color': emp.get('accent_color') or 'cyan',
                'profile_background': emp.get('profile_background') or 'default',
                'catchphrase': emp.get('catchphrase') or '',
                'selected_stickers': _parse_stickers(emp.get('selected_stickers'))
            })
        
        return jsonify({
            'success': True, 
            'employees': employee_list,
            'allow_kiosk_customization': allow_kiosk_customization
        })
    except Exception as e:
        app.logger.error(f"Error fetching kiosk employees: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/api/kiosk/<guild_id>/pin/create", methods=["POST"])
@require_kiosk_access
def api_kiosk_create_pin(guild_id):
    """Create a PIN for an employee"""
    try:
        import hashlib
        data = request.get_json()
        user_id = data.get('user_id')
        pin = data.get('pin')

        if not user_id or not pin or len(pin) != 4 or not pin.isdigit():
            return jsonify({'success': False, 'error': 'Invalid PIN format'}), 400

        # Demo server protection - fake success, no DB write
        if is_demo_server(guild_id):
            app.logger.info(f"Demo server: Blocking PIN creation for guild {guild_id}")
            return jsonify({
                'success': True,
                'message': 'PIN created successfully',
                'demo_note': 'In live server: PIN would be saved to database'
            }), 200
        
        # Hash the PIN
        pin_hash = hashlib.sha256(f"{guild_id}:{user_id}:{pin}".encode()).hexdigest()
        
        with get_db() as conn:
            conn.execute("""
                INSERT INTO employee_pins (guild_id, user_id, pin_hash)
                VALUES (%s, %s, %s)
                ON CONFLICT (guild_id, user_id) 
                DO UPDATE SET pin_hash = EXCLUDED.pin_hash, updated_at = NOW()
            """, (str(guild_id), str(user_id), pin_hash))
        
        app.logger.info(f"PIN created for user {user_id} in guild {guild_id}")
        return jsonify({'success': True})
    except Exception as e:
        app.logger.error(f"Error creating PIN: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/api/kiosk/<guild_id>/pin/verify", methods=["POST"])
@require_kiosk_access
def api_kiosk_verify_pin(guild_id):
    """Verify an employee's PIN"""
    try:
        import hashlib
        data = request.get_json()
        user_id = data.get('user_id')
        pin = data.get('pin')
        
        if not user_id or not pin:
            return jsonify({'success': False, 'error': 'Missing credentials'}), 400
        
        # Hash the PIN to compare
        pin_hash = hashlib.sha256(f"{guild_id}:{user_id}:{pin}".encode()).hexdigest()
        
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT pin_hash FROM employee_pins
                WHERE guild_id = %s AND user_id = %s
            """, (str(guild_id), str(user_id)))
            result = cursor.fetchone()
        
        if not result or result['pin_hash'] != pin_hash:
            return jsonify({'success': False, 'error': 'Incorrect PIN'}), 401
        
        return jsonify({'success': True})
    except Exception as e:
        app.logger.error(f"Error verifying PIN: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/api/kiosk/<guild_id>/employee/<user_id>/info")
@require_kiosk_access
def api_kiosk_employee_info(guild_id, user_id):
    """Get employee info for the kiosk action screen"""
    try:
        from datetime import timedelta
        
        with get_db() as conn:
            # Get employee profile including customization
            cursor = conn.execute("""
                SELECT display_name, first_name, last_name, avatar_url, position, department, 
                       email, timesheet_email, accent_color, profile_background, catchphrase, selected_stickers
                FROM employee_profiles
                WHERE guild_id = %s AND user_id = %s
            """, (str(guild_id), str(user_id)))
            profile = cursor.fetchone()
            
            # Check if kiosk customization is allowed for this guild (use COALESCE for safety)
            cursor = conn.execute("""
                SELECT COALESCE(allow_kiosk_customization, false) as allow_kiosk_customization 
                FROM guild_settings WHERE guild_id = %s
            """, (str(guild_id),))
            guild_settings = cursor.fetchone()
            allow_customization = guild_settings['allow_kiosk_customization'] if guild_settings else False
            
            # Prefer timesheet_email over regular email
            employee_email = None
            if profile:
                employee_email = profile.get('timesheet_email') or profile.get('email')
            
            # Check if clocked in (using timeclock_sessions)
            cursor = conn.execute("""
                SELECT clock_in_time FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s AND clock_out_time IS NULL
                ORDER BY clock_in_time DESC LIMIT 1
            """, (str(guild_id), str(user_id)))
            active_session = cursor.fetchone()
            
            # Get today's hours (using timeclock_sessions)
            today = datetime.now().date()
            cursor = conn.execute("""
                SELECT COALESCE(SUM(EXTRACT(EPOCH FROM (clock_out_time - clock_in_time))), 0) as total
                FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s 
                AND DATE(clock_in_time) = %s AND clock_out_time IS NOT NULL
            """, (str(guild_id), str(user_id), today))
            today_result = cursor.fetchone()
            today_minutes = float(today_result['total'] or 0) / 60
            
            # Add current session time if clocked in
            if active_session:
                clock_in_time = active_session['clock_in_time']
                if clock_in_time.tzinfo:
                    elapsed = (datetime.now(clock_in_time.tzinfo) - clock_in_time).total_seconds()
                else:
                    elapsed = (datetime.now() - clock_in_time).total_seconds()
                today_minutes += elapsed / 60
            
            # Get week's hours (Monday to Sunday)
            week_start = today - timedelta(days=today.weekday())
            cursor = conn.execute("""
                SELECT COALESCE(SUM(EXTRACT(EPOCH FROM (clock_out_time - clock_in_time))), 0) as total
                FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s 
                AND DATE(clock_in_time) >= %s AND clock_out_time IS NOT NULL
            """, (str(guild_id), str(user_id), week_start))
            week_result = cursor.fetchone()
            week_minutes = float(week_result['total'] or 0) / 60 + (today_minutes if active_session else 0)
            
            # Get last punch
            cursor = conn.execute("""
                SELECT clock_in_time, clock_out_time FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s
                ORDER BY COALESCE(clock_out_time, clock_in_time) DESC LIMIT 1
            """, (str(guild_id), str(user_id)))
            last_session = cursor.fetchone()
            
            last_punch = None
            if last_session:
                if last_session['clock_out_time']:
                    last_punch = f"Clocked out {last_session['clock_out_time'].strftime('%I:%M %p on %b %d')}"
                else:
                    last_punch = f"Clocked in at {last_session['clock_in_time'].strftime('%I:%M %p')}"
            
            # Get pending time adjustment requests for this employee
            cursor = conn.execute("""
                SELECT id, request_type, created_at FROM time_adjustment_requests
                WHERE guild_id = %s AND user_id = %s AND status = 'pending'
                ORDER BY created_at DESC LIMIT 5
            """, (str(guild_id), str(user_id)))
            pending_requests = cursor.fetchall()
            
            # Get recently resolved requests (last 7 days)
            cursor = conn.execute("""
                SELECT id, request_type, status, reviewed_at FROM time_adjustment_requests
                WHERE guild_id = %s AND user_id = %s AND status IN ('approved', 'denied')
                AND reviewed_at > NOW() - INTERVAL '7 days'
                ORDER BY reviewed_at DESC LIMIT 5
            """, (str(guild_id), str(user_id)))
            resolved_requests = cursor.fetchall()
            
            # Check for missing punches (sessions from last 7 days without clock_out)
            cursor = conn.execute("""
                SELECT session_id, clock_in_time FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s 
                AND clock_out_time IS NULL
                AND clock_in_time < NOW() - INTERVAL '8 hours'
                AND DATE(clock_in_time) > CURRENT_DATE - INTERVAL '7 days'
                ORDER BY clock_in_time DESC
            """, (str(guild_id), str(user_id)))
            missing_punches = cursor.fetchall()
        
        # Build notifications list
        notifications = []
        
        # Missing punches
        for mp in missing_punches:
            clock_in_dt = mp['clock_in_time']
            notifications.append({
                'type': 'alert',
                'icon': '⚠️',
                'text': f"Missing clock-out from {clock_in_dt.strftime('%b %d at %I:%M %p')}"
            })
        
        # Pending requests
        for pr in pending_requests:
            req_type = pr['request_type'] or 'adjustment'
            notifications.append({
                'type': 'pending',
                'icon': '⏳',
                'text': f"Time {req_type} request pending review"
            })
        
        # Resolved requests
        for rr in resolved_requests:
            req_type = rr['request_type'] or 'adjustment'
            status = rr['status']
            if status == 'approved':
                notifications.append({
                    'type': 'approved',
                    'icon': '✅',
                    'text': f"Time {req_type} request was approved"
                })
            else:
                notifications.append({
                    'type': 'denied',
                    'icon': '❌',
                    'text': f"Time {req_type} request was denied"
                })
        
        # Determine if there are important alerts (missing punches, pending requests, or missing email)
        has_alerts = len(missing_punches) > 0 or len(pending_requests) > 0 or not employee_email
        
        # Build customization data (only if allowed by guild)
        customization = {}
        if allow_customization and profile:
            customization = {
                'accent_color': profile.get('accent_color') or 'cyan',
                'profile_background': profile.get('profile_background') or 'default',
                'catchphrase': profile.get('catchphrase') or '',
                'selected_stickers': _parse_stickers(profile.get('selected_stickers'))
            }
        
        return jsonify({
            'success': True,
            'avatar_url': profile['avatar_url'] if profile else None,
            'position': profile['position'] if profile else None,
            'email': employee_email,
            'is_clocked_in': active_session is not None,
            'today_hours': float(today_minutes),
            'week_hours': float(week_minutes),
            'last_punch': last_punch,
            'notifications': notifications,
            'has_alerts': has_alerts,
            'pending_requests_count': len(pending_requests),
            'missing_punches_count': len(missing_punches),
            'allow_customization': allow_customization,
            'customization': customization
        })
    except Exception as e:
        app.logger.error(f"Error fetching kiosk employee info: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Rate limiting cache for forgot-PIN requests
# Format: {key: last_request_time} where key can be guild:user, guild, or ip
_forgot_pin_rate_limit: dict[str, float] = {}
_forgot_pin_guild_limit: dict[str, float] = {}  # Per-guild limit (max 10 requests per 10 minutes per guild)
_forgot_pin_ip_limit: dict[str, float] = {}  # Per-IP limit (max 5 requests per 10 minutes per IP)

def _clean_old_rate_limits():
    """Clean up expired rate limit entries to prevent memory bloat"""
    current_time = time_module.time()
    cutoff = current_time - 1800  # 30 minutes
    for cache in [_forgot_pin_rate_limit, _forgot_pin_guild_limit, _forgot_pin_ip_limit]:
        expired_keys = [k for k, v in cache.items() if v < cutoff]
        for k in expired_keys:
            del cache[k]

@app.route("/api/kiosk/<guild_id>/forgot-pin", methods=["POST"])
@require_kiosk_access
def api_kiosk_forgot_pin(guild_id):
    """Handle forgot PIN request - logs the request and can notify admin
    
    Security measures:
    - Per-user rate limit: 1 request per 5 minutes
    - Per-guild rate limit: 10 requests per 10 minutes
    - Per-IP rate limit: 5 requests per 10 minutes
    - Employee validation (no enumeration leaks)
    """
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        display_name = data.get('display_name', 'Unknown')
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        
        if not user_id:
            return jsonify({'success': False, 'error': 'Missing user ID'}), 400
        
        current_time = time_module.time()
        
        # Clean old entries occasionally
        if len(_forgot_pin_rate_limit) > 1000:
            _clean_old_rate_limits()
        
        # Per-IP rate limit: Max 5 requests per 10 minutes
        ip_key = f"ip:{client_ip}"
        ip_requests = _forgot_pin_ip_limit.get(ip_key, [])
        ip_requests = [t for t in ip_requests if current_time - t < 600]
        if len(ip_requests) >= 5:
            app.logger.warning(f"IP rate limited forgot PIN request from {client_ip}")
            return jsonify({'success': True, 'message': 'Too many requests. Please try again later.'})
        
        # Per-guild rate limit: Max 10 requests per 10 minutes
        guild_key = f"guild:{guild_id}"
        guild_requests = _forgot_pin_guild_limit.get(guild_key, [])
        guild_requests = [t for t in guild_requests if current_time - t < 600]
        if len(guild_requests) >= 10:
            app.logger.warning(f"Guild rate limited forgot PIN request for guild {guild_id}")
            return jsonify({'success': True, 'message': 'Too many requests for this server. Please try again later.'})
        
        # Per-user rate limit: 1 request per 5 minutes
        user_key = f"{guild_id}:{user_id}"
        last_request = _forgot_pin_rate_limit.get(user_key, 0)
        if current_time - last_request < 300:
            remaining = int(300 - (current_time - last_request))
            app.logger.warning(f"User rate limited forgot PIN request for {user_id} in guild {guild_id}")
            return jsonify({'success': True, 'message': f'Request already submitted. Please wait {remaining // 60} minutes.'})
        
        # Validate user exists as an employee in this guild (security: prevent enumeration attacks)
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT user_id FROM employee_profiles
                WHERE guild_id = %s AND user_id = %s
            """, (str(guild_id), str(user_id)))
            if not cursor.fetchone():
                # Don't reveal whether user exists - return generic success
                app.logger.warning(f"Forgot PIN request for non-existent user {user_id} in guild {guild_id}")
                return jsonify({'success': True, 'message': 'If this employee exists, admin has been notified'})
        
        # Update all rate limits
        _forgot_pin_rate_limit[user_key] = current_time
        _forgot_pin_ip_limit[ip_key] = ip_requests + [current_time]
        _forgot_pin_guild_limit[guild_key] = guild_requests + [current_time]
        
        # Log the forgot PIN request
        app.logger.info(f"FORGOT PIN REQUEST: User {display_name} (ID: {user_id}) in guild {guild_id} requested PIN reset")

        # Demo server protection - no emails in demo mode
        if is_demo_server(guild_id):
            app.logger.info(f"Demo server: Blocking forgot PIN email for guild {guild_id}")
            return jsonify({
                'success': True,
                'message': 'PIN reset request sent to admins'
            }), 200

        # Try to send notification email to verified report recipients
        try:
            with get_db() as conn:
                recipients_cursor = conn.execute(
                    """SELECT email_address FROM report_recipients 
                       WHERE guild_id = %s AND recipient_type = 'email' 
                       AND verification_status = 'verified'""",
                    (str(guild_id),)
                )
                recipients = [row['email_address'] for row in recipients_cursor.fetchall()]
                
                if recipients:
                    import asyncio
                    from email_utils import send_email
                    
                    subject = f"PIN Reset Request - {display_name}"
                    text_content = f"""An employee has requested a PIN reset.

Employee: {display_name}
User ID: {user_id}

Please assist this employee in resetting their kiosk PIN.

- Time Warden Bot"""
                    
                    def send_notification():
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        try:
                            loop.run_until_complete(send_email(to=recipients, subject=subject, text=text_content))
                        finally:
                            loop.close()
                    
                    import threading
                    thread = threading.Thread(target=send_notification, daemon=True)
                    thread.start()
        except Exception as email_err:
            app.logger.warning(f"Failed to send forgot PIN notification email: {email_err}")
        
        return jsonify({'success': True, 'message': 'Admin has been notified'})
    except Exception as e:
        app.logger.error(f"Error handling forgot PIN request: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/api/kiosk/<guild_id>/clock", methods=["POST"])
@require_kiosk_access
def api_kiosk_clock(guild_id):
    """Handle clock in/out from kiosk - uses timeclock_sessions for dashboard sync"""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        action = data.get('action')  # 'in' or 'out'

        if not user_id or action not in ['in', 'out']:
            return jsonify({'success': False, 'error': 'Invalid request'}), 400

        # Demo server protection - fake success, no DB write
        if is_demo_server(guild_id):
            from datetime import timezone
            app.logger.info(f"Demo server: Blocking clock {action} for guild {guild_id}")
            return jsonify({
                'success': True,
                'message': f'Clocked {action} successfully',
                'demo_note': f'In live server: Employee would be clocked {action} with timestamp saved to database',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'action': action
            }), 200
        
        now = datetime.now()
        
        with get_db() as conn:
            if action == 'in':
                # Check not already clocked in (using timeclock_sessions)
                cursor = conn.execute("""
                    SELECT session_id FROM timeclock_sessions
                    WHERE guild_id = %s AND user_id = %s AND clock_out_time IS NULL
                """, (str(guild_id), str(user_id)))
                if cursor.fetchone():
                    return jsonify({'success': False, 'error': 'Already clocked in'}), 400
                
                # Create new session in timeclock_sessions
                conn.execute("""
                    INSERT INTO timeclock_sessions (guild_id, user_id, clock_in_time)
                    VALUES (%s, %s, %s)
                """, (str(guild_id), str(user_id), now))
                
                app.logger.info(f"Kiosk clock IN: user {user_id} in guild {guild_id}")
                
            else:  # action == 'out'
                # Find active session in timeclock_sessions
                cursor = conn.execute("""
                    SELECT session_id, clock_in_time FROM timeclock_sessions
                    WHERE guild_id = %s AND user_id = %s AND clock_out_time IS NULL
                    ORDER BY clock_in_time DESC LIMIT 1
                """, (str(guild_id), str(user_id)))
                session = cursor.fetchone()
                
                if not session:
                    return jsonify({'success': False, 'error': 'Not clocked in'}), 400
                
                # Update session with clock out time
                conn.execute("""
                    UPDATE timeclock_sessions 
                    SET clock_out_time = %s
                    WHERE session_id = %s
                """, (now, session['session_id']))
                
                app.logger.info(f"Kiosk clock OUT: user {user_id} in guild {guild_id}")
                
                # Return session_id for email functionality
                return jsonify({'success': True, 'action': action, 'session_id': session['session_id']})
        
        return jsonify({'success': True, 'action': action})
    except Exception as e:
        app.logger.error(f"Error with kiosk clock action: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/api/kiosk/<guild_id>/employee/<user_id>/email", methods=["GET", "POST"])
@require_kiosk_access
def api_kiosk_employee_email(guild_id, user_id):
    """Get or save email for kiosk employee"""
    if request.method == "POST":
        # Save email
        try:
            data = request.get_json()
            email = data.get('email', '').strip()

            if not email:
                return jsonify({'success': False, 'error': 'Email is required'}), 400

            # Basic email validation
            import re
            if not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email):
                return jsonify({'success': False, 'error': 'Invalid email format'}), 400

            # Demo server protection - fake success, no DB write
            if is_demo_server(guild_id):
                app.logger.info(f"Demo server: Blocking email update for guild {guild_id}")
                return jsonify({
                    'success': True,
                    'message': 'Email address updated successfully',
                    'demo_note': f'In live server: Email {email} would be saved to employee profile',
                    'email': email
                }), 200
            
            with get_db() as conn:
                # Update both email and timesheet_email for consistency
                conn.execute("""
                    UPDATE employee_profiles 
                    SET email = %s, timesheet_email = %s
                    WHERE guild_id = %s AND user_id = %s
                """, (email, email, str(guild_id), str(user_id)))
            
            app.logger.info(f"Email updated for user {user_id} in guild {guild_id}")
            return jsonify({'success': True, 'email': email})
        except Exception as e:
            app.logger.error(f"Error saving employee email: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    # GET - retrieve email
    try:
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT email, timesheet_email FROM employee_profiles
                WHERE guild_id = %s AND user_id = %s
            """, (str(guild_id), str(user_id)))
            profile = cursor.fetchone()
            
            if profile:
                # Prefer timesheet_email if set, otherwise use regular email
                email = profile.get('timesheet_email') or profile.get('email')
                return jsonify({'success': True, 'email': email})
            
            return jsonify({'success': True, 'email': None})
    except Exception as e:
        app.logger.error(f"Error fetching employee email: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/api/kiosk/<guild_id>/send-shift-email", methods=["POST"])
@require_kiosk_access
def api_kiosk_send_shift_email(guild_id):
    """Send shift summary email to employee after clock-out"""
    try:
        from email_utils import ReplitMailSender
        import asyncio
        import pytz
        
        data = request.get_json()
        if not data:
            app.logger.error("No JSON data received in shift email request")
            return jsonify({'success': False, 'error': 'Invalid request data'}), 400
        user_id = data.get('user_id')
        email = data.get('email')
        session_id = data.get('session_id')
        
        if not user_id or not email:
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400

        # Demo server protection - no emails in demo mode
        if is_demo_server(guild_id):
            app.logger.info(f"Demo server: Blocking shift email for guild {guild_id}")
            return jsonify({
                'success': True,
                'message': 'Shift summary email sent successfully'
            }), 200

        with get_db() as conn:
            # Get guild info
            cursor = conn.execute("""
                SELECT guild_name FROM bot_guilds WHERE guild_id = %s
            """, (str(guild_id),))
            guild_row = cursor.fetchone()
            guild_name = guild_row['guild_name'] if guild_row else 'Unknown Server'
            
            # Get guild timezone
            cursor = conn.execute("""
                SELECT timezone FROM guild_settings WHERE guild_id = %s
            """, (str(guild_id),))
            tz_row = cursor.fetchone()
            guild_tz_str = tz_row['timezone'] if tz_row else 'America/New_York'
            guild_tz = pytz.timezone(guild_tz_str)
            
            # Get employee name
            cursor = conn.execute("""
                SELECT display_name, first_name FROM employee_profiles
                WHERE guild_id = %s AND user_id = %s
            """, (str(guild_id), str(user_id)))
            emp_row = cursor.fetchone()
            emp_name = emp_row['first_name'] or emp_row['display_name'] if emp_row else 'Employee'
            
            # Get the session details
            if session_id:
                cursor = conn.execute("""
                    SELECT clock_in_time, clock_out_time FROM timeclock_sessions
                    WHERE session_id = %s
                """, (session_id,))
            else:
                # Fallback: get most recent completed session
                cursor = conn.execute("""
                    SELECT clock_in_time, clock_out_time FROM timeclock_sessions
                    WHERE guild_id = %s AND user_id = %s AND clock_out_time IS NOT NULL
                    ORDER BY clock_out_time DESC LIMIT 1
                """, (str(guild_id), str(user_id)))
            
            session = cursor.fetchone()
            
            if not session:
                return jsonify({'success': False, 'error': 'No session found'}), 400
            
            clock_in = session['clock_in_time']
            clock_out = session['clock_out_time']
            
            # Convert to guild timezone for display
            if clock_in.tzinfo is None:
                clock_in = pytz.utc.localize(clock_in)
            if clock_out.tzinfo is None:
                clock_out = pytz.utc.localize(clock_out)
            
            clock_in_local = clock_in.astimezone(guild_tz)
            clock_out_local = clock_out.astimezone(guild_tz)
            
            # Calculate duration
            duration = clock_out - clock_in
            hours = int(duration.total_seconds() // 3600)
            minutes = int((duration.total_seconds() % 3600) // 60)
            duration_str = f"{hours}h {minutes}m" if hours > 0 else f"{minutes}m"
            
            # Save email for future use
            cursor = conn.execute("""
                SELECT id FROM employee_profiles WHERE guild_id = %s AND user_id = %s
            """, (str(guild_id), str(user_id)))
            if cursor.fetchone():
                conn.execute("""
                    UPDATE employee_profiles SET timesheet_email = %s
                    WHERE guild_id = %s AND user_id = %s
                """, (email, str(guild_id), str(user_id)))
        
        # Build email content
        subject = f"Shift Summary - {clock_out_local.strftime('%B %d, %Y')}"
        
        html_content = f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #1a1f2e; color: #c9d1d9; padding: 30px; border-radius: 12px;">
            <div style="text-align: center; margin-bottom: 30px;">
                <h1 style="color: #D4AF37; margin: 0;">Time Warden</h1>
                <p style="color: #8b949e; margin: 5px 0 0 0;">{guild_name}</p>
            </div>
            
            <h2 style="color: #c9d1d9; border-bottom: 1px solid #30363d; padding-bottom: 10px;">Shift Summary</h2>
            
            <p>Hello {emp_name},</p>
            <p>Here is your shift summary for today:</p>
            
            <div style="background: rgba(212, 175, 55, 0.1); border: 1px solid rgba(212, 175, 55, 0.3); border-radius: 8px; padding: 20px; margin: 20px 0;">
                <table style="width: 100%; border-collapse: collapse;">
                    <tr>
                        <td style="padding: 8px 0; color: #8b949e;">Date:</td>
                        <td style="padding: 8px 0; text-align: right; font-weight: bold;">{clock_in_local.strftime('%A, %B %d, %Y')}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px 0; color: #8b949e;">Clock In:</td>
                        <td style="padding: 8px 0; text-align: right; font-weight: bold;">{clock_in_local.strftime('%I:%M %p')}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px 0; color: #8b949e;">Clock Out:</td>
                        <td style="padding: 8px 0; text-align: right; font-weight: bold;">{clock_out_local.strftime('%I:%M %p')}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px 0; color: #8b949e; border-top: 1px solid #30363d;">Total Time:</td>
                        <td style="padding: 8px 0; text-align: right; font-weight: bold; color: #D4AF37; border-top: 1px solid #30363d;">{duration_str}</td>
                    </tr>
                </table>
            </div>
            
            <p style="color: #8b949e; font-size: 12px; text-align: center; margin-top: 30px;">
                This is an automated message from Time Warden. Please do not reply to this email.
            </p>
        </div>
        """
        
        text_content = f"""
Shift Summary - {guild_name}

Hello {emp_name},

Here is your shift summary for today:

Date: {clock_in_local.strftime('%A, %B %d, %Y')}
Clock In: {clock_in_local.strftime('%I:%M %p')}
Clock Out: {clock_out_local.strftime('%I:%M %p')}
Total Time: {duration_str}

This is an automated message from Time Warden.
        """
        
        # Send email
        mail_sender = ReplitMailSender()
        
        # Run async send in sync context
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(
                mail_sender.send_email(
                    to=email,
                    subject=subject,
                    html=html_content,
                    text=text_content
                )
            )
            app.logger.info(f"Shift summary email sent to {email} for user {user_id}")
            return jsonify({'success': True})
        except ValueError as val_err:
            # Missing auth token or invalid email
            app.logger.error(f"Email validation error: {val_err}")
            return jsonify({
                'success': False,
                'error': 'Email service not configured. Please contact support.',
                'code': 'EMAIL_CONFIG_ERROR'
            }), 500
        except asyncio.TimeoutError:
            app.logger.error("Email send timeout")
            return jsonify({
                'success': False,
                'error': 'Email service timeout. Please try again.',
                'code': 'EMAIL_TIMEOUT'
            }), 500
        except Exception as email_err:
            app.logger.error(f"Failed to send shift email: {email_err}")
            return jsonify({
                'success': False,
                'error': 'Failed to send email. Please check email address.',
                'code': 'EMAIL_SEND_FAILED'
            }), 500
        finally:
            loop.close()
            
    except Exception as e:
        app.logger.error(f"Error sending shift email: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/api/server/<guild_id>/kiosk-mode", methods=["GET"])
@require_paid_api_access
def api_get_kiosk_mode(user_session, guild_id):
    """Get kiosk mode setting for a server"""
    try:
        guild, _ = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT kiosk_mode_only FROM server_subscriptions WHERE guild_id = %s
            """, (int(guild_id),))
            result = cursor.fetchone()
        
        return jsonify({
            'success': True,
            'kiosk_mode_only': bool(result.get('kiosk_mode_only', False)) if result else False
        })
    except Exception as e:
        app.logger.error(f"Error fetching kiosk mode: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/api/server/<guild_id>/kiosk-mode", methods=["POST"])
@require_paid_api_access
def api_set_kiosk_mode(user_session, guild_id):
    """Set kiosk mode setting for a server"""
    try:
        guild, _ = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        data = request.get_json()
        kiosk_mode_only = bool(data.get('kiosk_mode_only', False))
        
        with get_db() as conn:
            cursor = conn.execute("SELECT guild_id FROM server_subscriptions WHERE guild_id = %s", (int(guild_id),))
            if cursor.fetchone():
                conn.execute("""
                    UPDATE server_subscriptions SET kiosk_mode_only = %s WHERE guild_id = %s
                """, (kiosk_mode_only, int(guild_id)))
            else:
                conn.execute("""
                    INSERT INTO server_subscriptions (guild_id, kiosk_mode_only) VALUES (%s, %s)
                """, (int(guild_id), kiosk_mode_only))
        
        app.logger.info(f"Kiosk mode set to {kiosk_mode_only} for guild {guild_id}")
        return jsonify({'success': True, 'kiosk_mode_only': kiosk_mode_only})
    except Exception as e:
        app.logger.error(f"Error setting kiosk mode: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/api/kiosk/<guild_id>/employee/<user_id>/today-sessions")
@require_kiosk_access
def api_kiosk_today_sessions(guild_id, user_id):
    """Get today's sessions for a kiosk employee - used for time adjustment modal"""
    try:
        from datetime import datetime, timezone
        import pytz
        
        with get_db() as conn:
            # Get guild timezone
            cursor = conn.execute(
                "SELECT timezone FROM guild_settings WHERE guild_id = %s",
                (int(guild_id),)
            )
            tz_row = cursor.fetchone()
            guild_tz_str = tz_row['timezone'] if tz_row else 'America/New_York'
            guild_tz = pytz.timezone(guild_tz_str)
            
            # Calculate today's date range in guild timezone
            now_utc = datetime.now(timezone.utc)
            now_local = now_utc.astimezone(guild_tz)
            today_start = now_local.replace(hour=0, minute=0, second=0, microsecond=0)
            today_end = now_local.replace(hour=23, minute=59, second=59, microsecond=999999)
            
            # Convert to UTC for query
            today_start_utc = today_start.astimezone(timezone.utc)
            today_end_utc = today_end.astimezone(timezone.utc)
            
            # Get today's sessions
            cursor = conn.execute("""
                SELECT session_id, clock_in_time, clock_out_time,
                       EXTRACT(EPOCH FROM (COALESCE(clock_out_time, NOW()) - clock_in_time)) as duration_seconds
                FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s
                AND clock_in_time >= %s AND clock_in_time <= %s
                ORDER BY clock_in_time ASC
            """, (str(guild_id), str(user_id), today_start_utc, today_end_utc))
            
            sessions = []
            total_seconds = 0
            is_clocked_in = False
            
            for row in cursor.fetchall():
                clock_in_utc = row['clock_in_time']
                clock_out_utc = row['clock_out_time']
                
                # Convert to local time
                if clock_in_utc:
                    if clock_in_utc.tzinfo is None:
                        clock_in_utc = clock_in_utc.replace(tzinfo=timezone.utc)
                    clock_in_local = clock_in_utc.astimezone(guild_tz)
                else:
                    clock_in_local = None
                
                if clock_out_utc:
                    if clock_out_utc.tzinfo is None:
                        clock_out_utc = clock_out_utc.replace(tzinfo=timezone.utc)
                    clock_out_local = clock_out_utc.astimezone(guild_tz)
                else:
                    clock_out_local = None
                    is_clocked_in = True  # No clock out means currently clocked in
                
                duration = row['duration_seconds'] or 0
                total_seconds += duration
                
                sessions.append({
                    'session_id': row['session_id'],
                    'clock_in': clock_in_local.strftime('%H:%M') if clock_in_local else None,
                    'clock_in_iso': clock_in_utc.isoformat() if clock_in_utc else None,
                    'clock_out': clock_out_local.strftime('%H:%M') if clock_out_local else None,
                    'clock_out_iso': clock_out_utc.isoformat() if clock_out_utc else None,
                    'duration_minutes': int(duration / 60),
                    'is_active': clock_out_utc is None
                })
            
            return jsonify({
                'success': True,
                'sessions': sessions,
                'is_clocked_in': is_clocked_in,
                'today_total_minutes': int(total_seconds / 60),
                'date': now_local.strftime('%Y-%m-%d'),
                'timezone': guild_tz_str
            })
            
    except Exception as e:
        app.logger.error(f"Error fetching kiosk today sessions: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route("/api/kiosk/<guild_id>/adjustment", methods=["POST"])
@require_kiosk_access
def api_kiosk_submit_adjustment(guild_id):
    """
    Submit a time adjustment request from the kiosk.
    Populates all required metadata fields for admin review compatibility.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400

        user_id = data.get('user_id')
        reason = data.get('reason', '').strip()
        changes = data.get('changes', [])

        if not user_id:
            return jsonify({'success': False, 'error': 'User ID is required'}), 400
        if not reason:
            return jsonify({'success': False, 'error': 'Please provide a reason for the adjustment'}), 400
        if not changes or len(changes) == 0:
            return jsonify({'success': False, 'error': 'No changes provided'}), 400

        # Demo server protection - fake success, no DB write
        if is_demo_server(guild_id):
            app.logger.info(f"Demo server: Blocking adjustment submission for guild {guild_id}")
            return jsonify({
                'success': True,
                'message': 'Time adjustment request submitted',
                'demo_note': 'In live server: Request would be submitted to admin for approval',
                'request_id': 'DEMO-001'
            }), 200
        
        user_id = int(user_id)
        guild_id_int = int(guild_id)
        
        from datetime import datetime, timezone
        import pytz
        
        created_requests = []
        
        with get_db() as conn:
            # Get guild timezone
            cursor = conn.execute(
                "SELECT timezone FROM guild_settings WHERE guild_id = %s",
                (guild_id_int,)
            )
            tz_row = cursor.fetchone()
            guild_tz_str = tz_row['timezone'] if tz_row else 'America/New_York'
            guild_tz = pytz.timezone(guild_tz_str)
            
            # Get today's date in proper format
            now_local = datetime.now(timezone.utc).astimezone(guild_tz)
            session_date_str = now_local.strftime('%Y-%m-%d')
            session_date = now_local.date()  # For DATE column
            
            for change in changes:
                session_id = change.get('session_id')
                new_clock_in = change.get('new_clock_in')
                new_clock_out = change.get('new_clock_out')
                is_new = change.get('is_new', False)
                
                # For new sessions
                if is_new:
                    if not new_clock_in or not new_clock_out:
                        continue  # Skip incomplete new sessions
                    
                    # Validate times - clock_out must be after clock_in
                    try:
                        date_parts = session_date_str.split('-')
                        in_parts = new_clock_in.split(':')
                        out_parts = new_clock_out.split(':')
                        
                        in_local = datetime(int(date_parts[0]), int(date_parts[1]), int(date_parts[2]),
                                           int(in_parts[0]), int(in_parts[1]))
                        out_local = datetime(int(date_parts[0]), int(date_parts[1]), int(date_parts[2]),
                                            int(out_parts[0]), int(out_parts[1]))
                        
                        # Validate clock_out is after clock_in
                        if out_local <= in_local:
                            app.logger.warning(f"Invalid time range: clock_out {out_local} <= clock_in {in_local}")
                            continue
                        
                        requested_clock_in = guild_tz.localize(in_local).astimezone(pytz.utc)
                        requested_clock_out = guild_tz.localize(out_local).astimezone(pytz.utc)
                        
                        # Check for overlapping sessions (handle NULL clock_out for active sessions)
                        cursor = conn.execute("""
                            SELECT session_id FROM timeclock_sessions
                            WHERE guild_id = %s AND user_id = %s
                            AND NOT (COALESCE(clock_out_time, NOW()) <= %s OR clock_in_time >= %s)
                        """, (str(guild_id), str(user_id), requested_clock_in, requested_clock_out))
                        
                        if cursor.fetchone():
                            app.logger.warning(f"Overlapping session detected for new entry")
                            continue  # Skip overlapping sessions
                        
                        # Calculate duration for new session
                        calculated_duration = int((requested_clock_out - requested_clock_in).total_seconds())
                        
                        # Insert adjustment request for new session with all metadata
                        cursor = conn.execute("""
                            INSERT INTO time_adjustment_requests 
                            (guild_id, user_id, request_type, original_session_id,
                             requested_clock_in, requested_clock_out, reason, status, source,
                             session_date, calculated_duration)
                            VALUES (%s, %s, 'add_session', NULL, %s, %s, %s, 'pending', 'kiosk', %s, %s)
                            RETURNING id
                        """, (guild_id_int, user_id, requested_clock_in, requested_clock_out, 
                              reason, session_date, calculated_duration))
                        
                        result = cursor.fetchone()
                        if result:
                            created_requests.append(result['id'])
                            
                    except Exception as e:
                        app.logger.error(f"Error parsing new session times: {e}")
                        continue
                        
                else:
                    # Modifying existing session
                    if not session_id:
                        continue
                    
                    # Verify session belongs to user and get original data
                    cursor = conn.execute("""
                        SELECT session_id, clock_in_time, clock_out_time,
                               EXTRACT(EPOCH FROM (clock_out_time - clock_in_time))::integer as original_duration
                        FROM timeclock_sessions
                        WHERE session_id = %s AND guild_id = %s AND user_id = %s
                    """, (session_id, str(guild_id), str(user_id)))
                    
                    original = cursor.fetchone()
                    if not original:
                        continue  # Skip invalid sessions
                    
                    # Parse new times
                    requested_clock_in = None
                    requested_clock_out = None
                    clock_in_changed = False
                    clock_out_changed = False
                    
                    if new_clock_in:
                        try:
                            date_parts = session_date_str.split('-')
                            time_parts = new_clock_in.split(':')
                            local_dt = datetime(int(date_parts[0]), int(date_parts[1]), int(date_parts[2]),
                                               int(time_parts[0]), int(time_parts[1]))
                            requested_clock_in = guild_tz.localize(local_dt).astimezone(pytz.utc)
                            clock_in_changed = True
                        except Exception as e:
                            app.logger.error(f"Error parsing clock_in: {e}")
                    
                    if new_clock_out:
                        try:
                            date_parts = session_date_str.split('-')
                            time_parts = new_clock_out.split(':')
                            local_dt = datetime(int(date_parts[0]), int(date_parts[1]), int(date_parts[2]),
                                               int(time_parts[0]), int(time_parts[1]))
                            requested_clock_out = guild_tz.localize(local_dt).astimezone(pytz.utc)
                            clock_out_changed = True
                        except Exception as e:
                            app.logger.error(f"Error parsing clock_out: {e}")
                    
                    if not (clock_in_changed or clock_out_changed):
                        continue  # No actual changes
                    
                    # Determine request type based on what changed
                    if clock_in_changed and clock_out_changed:
                        request_type = 'modify_session'
                    elif clock_in_changed:
                        request_type = 'modify_clockin'
                    else:
                        request_type = 'modify_clockout'
                    
                    # Calculate new duration if both times are available
                    calculated_duration = None
                    final_clock_in = requested_clock_in if clock_in_changed else original['clock_in_time']
                    final_clock_out = requested_clock_out if clock_out_changed else original['clock_out_time']
                    
                    if final_clock_in and final_clock_out:
                        # Ensure both have timezone info
                        if final_clock_in.tzinfo is None:
                            final_clock_in = final_clock_in.replace(tzinfo=timezone.utc)
                        if final_clock_out.tzinfo is None:
                            final_clock_out = final_clock_out.replace(tzinfo=timezone.utc)
                        
                        # Check for overlapping sessions (exclude the session being modified)
                        cursor = conn.execute("""
                            SELECT session_id FROM timeclock_sessions
                            WHERE guild_id = %s AND user_id = %s AND session_id != %s
                            AND NOT (COALESCE(clock_out_time, NOW()) <= %s OR clock_in_time >= %s)
                        """, (str(guild_id), str(user_id), session_id, final_clock_in, final_clock_out))
                        
                        if cursor.fetchone():
                            app.logger.warning(f"Overlapping session detected for modification of session {session_id}")
                            continue  # Skip overlapping modifications
                        
                        calculated_duration = int((final_clock_out - final_clock_in).total_seconds())
                    
                    # Insert adjustment request with all metadata
                    cursor = conn.execute("""
                        INSERT INTO time_adjustment_requests 
                        (guild_id, user_id, request_type, original_session_id,
                         original_clock_in, original_clock_out, original_duration,
                         requested_clock_in, requested_clock_out, reason, status, source,
                         session_date, calculated_duration)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'pending', 'kiosk', %s, %s)
                        RETURNING id
                    """, (guild_id_int, user_id, request_type, session_id,
                          original['clock_in_time'], original['clock_out_time'], 
                          original['original_duration'],
                          requested_clock_in, requested_clock_out, reason,
                          session_date, calculated_duration))
                    
                    result = cursor.fetchone()
                    if result:
                        created_requests.append(result['id'])
        
        if created_requests:
            app.logger.info(f"Kiosk adjustment requests created: {created_requests} for user {user_id} in guild {guild_id}")
            return jsonify({
                'success': True,
                'message': 'Adjustment request submitted for admin review',
                'request_ids': created_requests
            })
        else:
            return jsonify({
                'success': False,
                'error': 'No valid changes to submit'
            }), 400
            
    except Exception as e:
        app.logger.error(f"Error submitting kiosk adjustment: {e}")
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
