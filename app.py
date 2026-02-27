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

# Register Blueprints
from web.routes.auth import auth_bp
app.register_blueprint(auth_bp)
from web.utils.billing import billing_bp, create_secure_checkout_session
app.register_blueprint(billing_bp)

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

def sanitize_csv_string(value) -> str:
    """
    Prevents CSV Macro Injection (Formula Injection) in Excel/Sheets.
    If a string starts with =, +, -, @, \t, or \r, it prepends a single quote.
    """
    if value is None:
        return ""
    val_str = str(value)
    if val_str and val_str[0] in ('=', '+', '-', '@', '\t', '\r'):
        return f"'{val_str}"
    return val_str

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
# Ensure persistent sessions by requiring a static SECRET_KEY
_session_secret = os.environ.get('SECRET_KEY') or os.environ.get('SESSION_SECRET')
if not _session_secret:
    print("[CRITICAL] SECRET_KEY is not set in environment. Generating fallback key.")
    print("         Sessions will invalidate if the server restarts. PLEASE add SECRET_KEY to .env!")
    _session_secret = secrets.token_hex(32)

app.secret_key = _session_secret
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Security Middleware: Prevent Clickjacking via iframes
@app.after_request
def apply_security_headers(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

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
from web.utils.db import init_app_db_pool, app_db_pool, FlaskConnectionWrapper, get_db
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
from web.utils.auth import (
    create_oauth_state, verify_oauth_state, exchange_code_for_token,
    get_user_info, get_user_guilds, create_user_session, get_user_session,
    delete_user_session, require_auth, require_api_auth, require_server_owner,
    rate_limit_check, check_guild_paid_access, check_user_admin_realtime,
    get_flask_guild_access, require_paid_access, require_paid_api_access,
    get_bot_guild_ids, user_has_admin_access, require_kiosk_access,
    require_kiosk_session, filter_user_guilds, get_employee_guilds,
    get_all_user_guilds
)

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

@app.route("/upgrade")
def upgrade_vanity():
    """Vanity URL for bot commands pointing to server upgrade flow"""
    return redirect(url_for('purchase_init', product_type='premium'))

@app.route("/")
def index():
    """Landing page with bot info, features, and upgrade links."""
    user_session = get_user_session(request.cookies.get('session_id'))
    if is_v2_ui_enabled_for_user(user_session):
        pass  # return render_template("v2/landing.html") when V2 files exist
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
            
            # Phase 6: Dynamic MRR & 7-Day Growth Calculation
            # Calculate total estimated Monthly Recurring Revenue based on subscription tiers
            mrr_premium = (stats['paid_servers'] - stats['pro_count'] - stats['grandfathered_count']) * 8
            mrr_pro = stats['pro_count'] * 15
            stats['estimated_mrr'] = mrr_premium + mrr_pro
            
            # Calculate 7-Day Server Growth
            seven_days_ago = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
            cursor = conn.execute("""
                SELECT COUNT(*) as growth
                FROM bot_guilds
                WHERE joined_at >= %s
            """, (seven_days_ago,))
            growth_row = cursor.fetchone()
            stats['seven_day_growth'] = growth_row['growth'] if growth_row and 'growth' in growth_row else 0
            
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
            cursor = conn.execute("SELECT flag_name, is_enabled FROM global_feature_flags")
            feature_flags = {row['flag_name']: row['is_enabled'] for row in cursor.fetchall()}
        
        return render_template('owner_dashboard.html', 
                             user=user_session,
                             servers=servers,
                             webhook_events=webhook_events,
                             purchase_history=purchase_history,
                             stats=stats,
                             feature_flags=feature_flags)
    
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
            cursor = conn.execute("SELECT flag_name, is_enabled FROM global_feature_flags")
            feature_flags = {row['flag_name']: row['is_enabled'] for row in cursor.fetchall()}
        
        return render_template('owner_dashboard.html', 
                             user=user_session,
                             servers=servers,
                             webhook_events=[],
                             purchase_history=[],
                             stats=stats,
                             filter_mode='paid',
                             feature_flags=feature_flags)
    
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
            cursor = conn.execute("SELECT flag_name, is_enabled FROM global_feature_flags")
            feature_flags = {row['flag_name']: row['is_enabled'] for row in cursor.fetchall()}
        
        return render_template('owner_dashboard.html', 
                             user=user_session,
                             servers=servers,
                             webhook_events=[],
                             purchase_history=[],
                             stats=stats,
                             filter_mode='unpaid',
                             feature_flags=feature_flags)
    
    except Exception as e:
        app.logger.error(f"Owner unpaid dashboard error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return "<h1>Error</h1><p>Unable to load owner dashboard. Please try again later.</p>", 500


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
        access_level is 'owner', 'admin' or 'employee'
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
        if guild.get('id') == str(guild_id) or guild.get('id') == guild_id:
            if user_has_admin_access(user_session['user_id'], guild_id, guild):
                if guild.get('owner', False):
                    return (guild, 'owner')
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
            """, (str(user_id), int(guild_id)))
            
            employee_guild = cursor.fetchone()
            if employee_guild:
                # Return a guild-like dict with employee access
                return ({
                    'id': str(guild_id),
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
                "SELECT auto_send_on_clockout, auto_email_before_delete, subject_line, reply_to_address, cc_addresses FROM email_settings WHERE guild_id = %s",
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
            'subject_line': email_settings_row['subject_line'] if email_settings_row else None,
            'reply_to_address': email_settings_row['reply_to_address'] if email_settings_row else None,
            'cc_addresses': email_settings_row['cc_addresses'] if email_settings_row else None,
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
@require_server_owner
def purchase_checkout(user_session):
    """Create Stripe checkout session - SECURITY: Verify owner access before proceeding"""
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

@app.route("/docs")
@app.route("/wiki")
@app.route("/docs/<page>")
@app.route("/wiki/<page>")
def docs_hub(page="getting-started"):
    """Standalone Wiki/Documentation route lacking auth bounds."""
    # The valid pages
    valid_pages = [
        "getting-started",
        "employee-workflows",
        "exports-payroll",
        "pricing"
    ]
    if page not in valid_pages:
        page = "getting-started"
        
    return render_template("wiki.html", active_page=page)

# ==========================================
# Application Entry Point
# ============================================

def is_v2_ui_enabled_for_user(user_session):
    """Check if the V2 UI feature flag is enabled AND the user is the owner."""
    if not user_session:
        return False
        
    # 1. Verify user is the bot owner
    bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
    if str(user_session.get('user_id', '')) != bot_owner_id:
        return False

    # 2. Check if the global flag is turned on
    try:
        with get_db() as conn:
            cursor = conn.execute("SELECT is_enabled FROM global_feature_flags WHERE flag_name = 'v2_ui'")
            row = cursor.fetchone()
            return row['is_enabled'] if row else False
    except Exception as e:
        app.logger.error(f"Error checking v2_ui flag: {e}")
        return False

# ============================================
# PUBLIC ROUTES
# ============================================

# ============================================
# API ENDPOINTS & ROUTES
# ============================================

@app.route("/api/owner/feature-flags/toggle", methods=["POST"])
@require_auth
def api_toggle_feature_flag(user_session):
    # Verify owner (must be bot owner ID from env)
    bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
    if str(user_session.get('user_id', '')) != bot_owner_id:
         return jsonify({'success': False, 'error': 'Unauthorized - Bot owner access required'}), 403

    data = request.get_json()
    flag_name = data.get('flag_name')
    is_enabled = bool(data.get('is_enabled', False))

    if flag_name != 'v2_ui':
        return jsonify({'success': False, 'error': 'Invalid flag'}), 400

    try:
        with get_db() as conn:
            conn.execute("""
                UPDATE global_feature_flags 
                SET is_enabled = %s, updated_at = NOW(), updated_by = %s
                WHERE flag_name = %s
            """, (is_enabled, user_session['user_id'], flag_name))
            
            # If the row doesn't exist for some reason, insert it
            if conn.rowcount == 0:
                 conn.execute("""
                    INSERT INTO global_feature_flags (flag_name, is_enabled, updated_by)
                    VALUES (%s, %s, %s)
                """, (flag_name, is_enabled, user_session['user_id']))

        app.logger.info(f"Owner {user_session['user_id']} set flag {flag_name} to {is_enabled}")
        return jsonify({'success': True, 'flag_name': flag_name, 'is_enabled': is_enabled})
    except Exception as e:
        app.logger.error(f"Error toggling flag: {e}")
        return jsonify({'success': False, 'error': 'Database error'}), 500

        return jsonify({'success': False, 'error': str(e)}), 500


# Register heavily-dependent Blueprints after all helper methods are loaded
from web.routes.dashboard import dashboard_bp
from web.routes.api_kiosk import kiosk_bp
from web.routes.api_owner import api_owner_bp
from web.routes.api_server import api_server_bp
from web.routes.api_guild import api_guild_bp
app.register_blueprint(dashboard_bp)
app.register_blueprint(kiosk_bp)
app.register_blueprint(api_owner_bp)
app.register_blueprint(api_server_bp)
app.register_blueprint(api_guild_bp)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") != "production"
    
    print(f"🚀 Starting Landing Page Server...")
    print(f"🌍 Environment: {os.environ.get('FLASK_ENV', 'development')}")
    print(f"🔌 Port: {port}")
    print(f"🐛 Debug: {debug}")
    
    # Run Flask app
    app.run(host="0.0.0.0", port=port, debug=debug)
