#!/usr/bin/env python3
"""
Flask app for On the Clock - landing page and OAuth dashboard.
"""
import os
import secrets
import json
import sqlite3
import logging
import traceback
import threading
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode
import requests
from flask import Flask, render_template, redirect, request, session, jsonify, url_for, make_response
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)

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
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Fix for Replit reverse proxy - ensures correct scheme/host detection and client IP
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1, x_for=1)

# Database Configuration - MUST match bot.py for proper synchronization
DB_PATH = os.getenv("TIMECLOCK_DB", "timeclock.db")

# Discord OAuth2 Configuration
DISCORD_CLIENT_ID = os.environ.get('DISCORD_CLIENT_ID')
DISCORD_CLIENT_SECRET = os.environ.get('DISCORD_CLIENT_SECRET')
DISCORD_API_BASE = 'https://discord.com/api/v10'
DISCORD_OAUTH_SCOPES = 'identify guilds'

def get_redirect_uri():
    """Get redirect URI dynamically based on current request or environment"""
    # Use environment variable if set, otherwise compute from current request
    env_uri = os.environ.get('DISCORD_REDIRECT_URI')
    if env_uri:
        return env_uri
    # Fallback: compute from current request (forces HTTPS for production)
    return url_for('auth_callback', _external=True, _scheme='https')

# Database connection
def get_db():
    """
    Get database connection with same PRAGMA settings as bot.py
    for proper synchronization between Discord bot and web dashboard
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA synchronous = NORMAL")
    return conn

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
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                expires_at TEXT NOT NULL,
                ip_address TEXT NOT NULL DEFAULT 'unknown'
            )
        """)
        
        # Migration: Add refresh_token column if it doesn't exist
        try:
            conn.execute("ALTER TABLE user_sessions ADD COLUMN refresh_token TEXT")
        except sqlite3.OperationalError:
            pass
        
        # Migration: Add created_at column if it doesn't exist
        try:
            conn.execute("ALTER TABLE user_sessions ADD COLUMN created_at TEXT NOT NULL DEFAULT (datetime('now'))")
        except sqlite3.OperationalError:
            pass
        
        # Migration: Add ip_address column if it doesn't exist
        try:
            conn.execute("ALTER TABLE user_sessions ADD COLUMN ip_address TEXT NOT NULL DEFAULT 'unknown'")
        except sqlite3.OperationalError:
            pass
        
        # Clean up expired sessions and states
        conn.execute("DELETE FROM oauth_states WHERE expires_at < ?", 
                    (datetime.now(timezone.utc).isoformat(),))
        conn.execute("DELETE FROM user_sessions WHERE expires_at < ?", 
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
            "INSERT INTO oauth_states (state, expires_at) VALUES (?, ?)",
            (state, expires_at.isoformat())
        )
    return state

def verify_oauth_state(state):
    """Verify OAuth state and delete it"""
    with get_db() as conn:
        cursor = conn.execute(
            "SELECT state FROM oauth_states WHERE state = ? AND expires_at > ?",
            (state, datetime.now(timezone.utc).isoformat())
        )
        result = cursor.fetchone()
        
        if result:
            conn.execute("DELETE FROM oauth_states WHERE state = ?", (state,))
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
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            WHERE session_id = ? AND expires_at > ?
        """, (session_id, datetime.now(timezone.utc).isoformat()))
        row = cursor.fetchone()
        
        if row:
            return {
                'session_id': row[0],
                'user_id': row[1],
                'username': row[2],
                'discriminator': row[3] or '0',
                'avatar': row[4],
                'access_token': row[5],
                'guilds': json.loads(row[6]) if row[6] else [],
                'expires_at': row[7]
            }
    return None

def delete_user_session(session_id):
    """Delete user session from database"""
    with get_db() as conn:
        conn.execute("DELETE FROM user_sessions WHERE session_id = ?", (session_id,))

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

def get_bot_guild_ids():
    """Get list of guild IDs where the bot is present (as strings for OAuth comparison)"""
    try:
        with get_db() as conn:
            cursor = conn.execute("SELECT guild_id FROM bot_guilds")
            # Cast to string to match Discord OAuth guild IDs (which are strings)
            return set(str(row[0]) for row in cursor.fetchall())
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
    1. The bot is present (in bot_guilds table), AND
    2. The user has admin access (owner, administrator, or custom admin role)
    """
    all_guilds = user_session.get('guilds', [])
    bot_guild_ids = get_bot_guild_ids()
    filtered_guilds = []
    
    for guild in all_guilds:
        guild_id = guild.get('id')
        
        # Check if bot is in this guild
        if guild_id not in bot_guild_ids:
            continue
        
        # Check if user has admin access
        if not user_has_admin_access(user_session['user_id'], guild_id, guild):
            continue
        
        # Guild passes both filters
        filtered_guilds.append(guild)
    
    return filtered_guilds

# Routes
@app.route("/")
def index():
    """Landing page with bot info, features, and upgrade links."""
    return render_template('landing.html')

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
            "SELECT role_id FROM admin_roles WHERE guild_id = ?",
            (guild_id,)
        )
        admin_roles = [str(row[0]) for row in admin_cursor.fetchall()]
        
        # Get employee roles (convert to strings to match Discord API format)
        employee_cursor = conn.execute(
            "SELECT role_id FROM employee_roles WHERE guild_id = ?",
            (guild_id,)
        )
        employee_roles = [str(row[0]) for row in employee_cursor.fetchall()]
        
        # Get guild settings (timezone, recipient_user_id, etc.)
        settings_cursor = conn.execute(
            "SELECT timezone, recipient_user_id, name_display_mode, main_admin_role_id FROM guild_settings WHERE guild_id = ?",
            (guild_id,)
        )
        settings_row = settings_cursor.fetchone()
        
        # Get email settings - check if email_settings table exists
        try:
            email_settings_cursor = conn.execute(
                "SELECT auto_send_on_clockout, auto_email_before_delete, work_day_end_time FROM email_settings WHERE guild_id = ?",
                (guild_id,)
            )
            email_settings_row = email_settings_cursor.fetchone()
        except:
            email_settings_row = None
        
        return {
            'admin_roles': admin_roles,
            'employee_roles': employee_roles,
            'timezone': (settings_row[0] if settings_row else None) or 'America/New_York',
            'recipient_user_id': settings_row[1] if settings_row else None,
            'name_display_mode': (settings_row[2] if settings_row else None) or 'username',
            'main_admin_role_id': settings_row[3] if settings_row and len(settings_row) > 3 else None,
            'work_day_end_time': (email_settings_row[2] if email_settings_row and len(email_settings_row) > 2 else None) or '17:00',
            'auto_send_on_clockout': bool(email_settings_row[0]) if email_settings_row else False,
            'auto_email_before_delete': bool(email_settings_row[1]) if email_settings_row else False,
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
                <h1>💳 Upgrade Your Server</h1>
                
                <div class="status {'paid' if has_bot_access else 'free'}">
                    {'✅ Full Bot Access Active' if has_bot_access else '🔒 Free Tier - Limited Features'}
                    <br>
                    {f"📊 {retention_tier.replace('day', '-Day').title()} Retention" if retention_tier != 'none' else '⚠️ 24-Hour Data Deletion'}
                </div>
                
                <div class="instructions">
                    <h3>📋 How to Upgrade:</h3>
                    <ol>
                        <li>Go to your Discord server: <strong>{guild_name_safe}</strong></li>
                        <li>Run this command in any channel:</li>
                    </ol>
                    <div class="command">/upgrade</div>
                    <p>The bot will show you available upgrade options with secure Stripe checkout links.</p>
                    
                    {'''
                    <h3 style="margin-top: 30px;">💡 What You Get:</h3>
                    <ul style="text-align: left;">
                        <li><strong>$5 One-Time:</strong> Full bot access, real reports, dashboard unlocked</li>
                        <li><strong>$5/Month:</strong> 7-day data retention</li>
                        <li><strong>$10/Month:</strong> 30-day data retention</li>
                    </ul>
                    ''' if not has_bot_access else '''
                    <h3 style="margin-top: 30px;">📁 Add Data Retention:</h3>
                    <ul style="text-align: left;">
                        <li><strong>$5/Month:</strong> 7-day rolling retention</li>
                        <li><strong>$10/Month:</strong> 30-day rolling retention</li>
                    </ul>
                    '''}
                </div>
                
                <a href="/server/{guild_id}/settings" class="back-btn">← Back to Dashboard</a>
            </div>
        </body>
        </html>
        """
    except Exception as e:
        app.logger.error(f"Upgrade info error: {str(e)}")
        return "<h1>Error</h1><p>Unable to load upgrade information.</p>", 500

@app.route("/purchase/<guild_id>")
def purchase_page(guild_id):
    """Public purchase page for $5 bot access - explains what it unlocks"""
    try:
        import html
        from bot import check_bot_access
        
        # Check if already has bot access
        has_bot_access = check_bot_access(int(guild_id))
        
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
                    <h1>✅ Bot Access Already Active!</h1>
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
                    content: "✅";
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
                    <h1>🔓 Unlock Full Bot Access</h1>
                    <p style="font-size: 1.2em;">One-time payment to unlock all features</p>
                    <div class="price-tag">$5 One-Time</div>
                </div>

                <div class="features-grid">
                    <div class="feature-card">
                        <h3>👥 Full Team Access</h3>
                        <ul>
                            <li>Unlimited employees</li>
                            <li>Role-based access control</li>
                            <li>Admin management</li>
                            <li>Employee tracking</li>
                        </ul>
                    </div>

                    <div class="feature-card">
                        <h3>📊 Real Reports</h3>
                        <ul>
                            <li>CSV timesheet exports</li>
                            <li>Individual user reports</li>
                            <li>Team summaries</li>
                            <li>Email delivery</li>
                        </ul>
                    </div>

                    <div class="feature-card">
                        <h3>🎛️ Dashboard Access</h3>
                        <ul>
                            <li>Web-based settings</li>
                            <li>Role management UI</li>
                            <li>Timezone controls</li>
                            <li>Email automation</li>
                        </ul>
                    </div>

                    <div class="feature-card">
                        <h3>⚙️ All Commands</h3>
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
                            <td class="yes">✅ Basic</td>
                            <td class="yes">✅ Full Access</td>
                        </tr>
                        <tr>
                            <td>Team Reports</td>
                            <td class="no">❌ Dummy Only</td>
                            <td class="yes">✅ Real CSV Reports</td>
                        </tr>
                        <tr>
                            <td>Dashboard</td>
                            <td class="no">❌ Locked</td>
                            <td class="yes">✅ Full Access</td>
                        </tr>
                        <tr>
                            <td>Role Management</td>
                            <td class="no">❌ Admin Only</td>
                            <td class="yes">✅ Full Control</td>
                        </tr>
                        <tr>
                            <td>Data Retention</td>
                            <td class="no">⚠️ 24 Hours</td>
                            <td class="yes">⚠️ 24 Hours*</td>
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

@app.route("/server/<guild_id>/settings")
@require_auth
def server_settings(user_session, guild_id):
    """Server-specific settings page with admin/employee management, email, and timezone"""
    try:
        app.logger.info(f"Server settings accessed for guild {guild_id} by user {user_session.get('username')}")
        
        # Check if bot is present in this guild first (before expensive Discord API calls)
        bot_guild_ids = get_bot_guild_ids()
        if guild_id not in bot_guild_ids:
            app.logger.warning(f"Bot not present in guild {guild_id}")
            return "<h1>Bot Not Present</h1><p>The On the Clock bot is not in this server. Please invite the bot first.</p><a href='/dashboard'>Back to Dashboard</a>", 404
        
        # Verify user has access to this guild
        guild = verify_guild_access(user_session, guild_id)
        if not guild:
            app.logger.warning(f"User {user_session.get('username')} unauthorized for guild {guild_id}")
            return "<h1>Access Denied</h1><p>You don't have admin access to this server.</p><a href='/dashboard'>Back to Dashboard</a>", 403
        
        # Fetch guild roles from Discord (members loaded via API later)
        roles = get_guild_roles_from_bot(guild_id)
        if not roles:
            app.logger.error(f"Failed to fetch roles for guild {guild_id}")
            # Render page with error state but show existing settings
            current_settings = get_guild_settings(guild_id)
            return render_template('server_settings.html', 
                                   user=user_session, 
                                   guild=guild, 
                                   guild_id=guild_id, 
                                   roles=[],
                                   current_settings=current_settings,
                                   error="Could not fetch server roles. Please check bot permissions and try again."), 200
        
        # Fetch current settings from database
        try:
            current_settings = get_guild_settings(guild_id)
        except Exception as e:
            app.logger.error(f"Error fetching guild settings: {str(e)}")
            # Use defaults if database error
            current_settings = {
                'admin_roles': [],
                'employee_roles': [],
                'timezone': 'America/New_York',
                'recipient_user_id': None,
                'name_display_mode': 'username',
                'main_admin_role_id': None,
                'emails': []
            }
        
        # Get bot access and retention tier status (NEW MONETIZATION MODEL)
        from bot import check_bot_access, get_retention_tier
        has_bot_access = check_bot_access(int(guild_id))
        retention_tier = get_retention_tier(int(guild_id))
        
        # Prepare data for template
        template_data = {
            'user': user_session,
            'guild': guild,
            'guild_id': guild_id,
            'roles': roles,
            'current_settings': current_settings,
            'has_bot_access': has_bot_access,
            'retention_tier': retention_tier
        }
        
        # Add cache-busting headers to ensure users see latest changes
        response = make_response(render_template('server_settings.html', **template_data))
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    except Exception as e:
        app.logger.error(f"Server settings error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return "<h1>Error</h1><p>Unable to load server settings. Please try again later.</p><a href='/dashboard'>Back to Dashboard</a>", 500

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
@require_api_auth
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
@require_api_auth
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
@require_api_auth
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
        
        response = requests.post(
            bot_api_url,
            json={'role_id': role_id},
            headers={'Authorization': f'Bearer {bot_api_secret}'},
            timeout=5
        )
        
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
@require_api_auth
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
@require_api_auth
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
            cursor = conn.execute("SELECT guild_id FROM guild_settings WHERE guild_id = ?", (guild_id,))
            exists = cursor.fetchone()
            
            if exists:
                conn.execute(
                    "UPDATE guild_settings SET timezone = ? WHERE guild_id = ?",
                    (timezone_str, guild_id)
                )
            else:
                conn.execute(
                    "INSERT INTO guild_settings (guild_id, timezone) VALUES (?, ?)",
                    (guild_id, timezone_str)
                )
        
        app.logger.info(f"Updated timezone to {timezone_str} for guild {guild_id} by user {user_session.get('username')}")
        return jsonify({'success': True, 'message': 'Timezone updated successfully', 'timezone': timezone_str})
    except Exception as e:
        app.logger.error(f"Error updating timezone: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@app.route("/api/server/<guild_id>/email-settings", methods=["POST"])
@require_api_auth
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
            cursor = conn.execute("SELECT guild_id FROM email_settings WHERE guild_id = ?", (guild_id,))
            exists = cursor.fetchone()
            
            if exists:
                conn.execute(
                    """UPDATE email_settings 
                       SET auto_send_on_clockout = ?, auto_email_before_delete = ? 
                       WHERE guild_id = ?""",
                    (auto_send_on_clockout, auto_email_before_delete, guild_id)
                )
            else:
                conn.execute(
                    """INSERT INTO email_settings (guild_id, auto_send_on_clockout, auto_email_before_delete) 
                       VALUES (?, ?, ?)""",
                    (guild_id, auto_send_on_clockout, auto_email_before_delete)
                )
        
        app.logger.info(f"Updated email settings for guild {guild_id} by user {user_session.get('username')}")
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
@require_api_auth
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
        if not re.match(r'^([01]?[0-9]|2[0-3]):[0-5][0-9]$', work_day_end_time):
            return jsonify({'success': False, 'error': 'Invalid time format. Use HH:MM'}), 400
        
        # Update or insert guild settings
        with get_db() as conn:
            # Check if settings exist
            cursor = conn.execute("SELECT guild_id FROM guild_settings WHERE guild_id = ?", (guild_id,))
            exists = cursor.fetchone()
            
            if exists:
                conn.execute(
                    "UPDATE guild_settings SET work_day_end_time = ? WHERE guild_id = ?",
                    (work_day_end_time, guild_id)
                )
            else:
                # Insert with proper defaults for all columns
                conn.execute(
                    """INSERT INTO guild_settings (guild_id, timezone, name_display_mode, work_day_end_time) 
                       VALUES (?, 'America/New_York', 'username', ?)""",
                    (guild_id, work_day_end_time)
                )
        
        app.logger.info(f"Updated work day end time to {work_day_end_time} for guild {guild_id} by user {user_session.get('username')}")
        return jsonify({'success': True, 'message': 'Work day end time updated successfully', 'work_day_end_time': work_day_end_time})
    except Exception as e:
        app.logger.error(f"Error updating work day end time: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@app.route("/api/server/<guild_id>/email-recipients", methods=["GET"])
@require_api_auth
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
                   WHERE guild_id = ? AND recipient_type = 'email'
                   ORDER BY created_at DESC""",
                (guild_id,)
            )
            recipients = cursor.fetchall()
            
        emails = [
            {
                'id': row[0],
                'email': row[1],
                'created_at': row[2]
            }
            for row in recipients
        ]
        
        return jsonify({'success': True, 'emails': emails})
    except Exception as e:
        app.logger.error(f"Error fetching email recipients: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@app.route("/api/server/<guild_id>/email-recipients/add", methods=["POST"])
@require_api_auth
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
                       VALUES (?, 'email', ?)""",
                    (guild_id, email)
                )
                recipient_id = cursor.lastrowid
            except sqlite3.IntegrityError:
                return jsonify({'success': False, 'error': 'Email address already exists'}), 400
        
        app.logger.info(f"Added email recipient {email} for guild {guild_id} by user {user_session.get('username')}")
        return jsonify({'success': True, 'message': 'Email recipient added successfully', 'id': recipient_id, 'email': email})
    except Exception as e:
        app.logger.error(f"Error adding email recipient: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@app.route("/api/server/<guild_id>/email-recipients/remove", methods=["POST"])
@require_api_auth
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
                   WHERE id = ? AND guild_id = ? AND recipient_type = 'email'""",
                (recipient_id, guild_id)
            )
            
            if cursor.rowcount == 0:
                return jsonify({'success': False, 'error': 'Recipient not found'}), 404
        
        app.logger.info(f"Removed email recipient {recipient_id} for guild {guild_id} by user {user_session.get('username')}")
        return jsonify({'success': True, 'message': 'Email recipient removed successfully'})
    except Exception as e:
        app.logger.error(f"Error removing email recipient: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@app.route("/api/server/<guild_id>/data", methods=["GET"])
@require_api_auth
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

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") != "production"
    
    print(f"🌐 Starting Landing Page Server...")
    print(f"🔧 Environment: {os.environ.get('FLASK_ENV', 'development')}")
    print(f"🌐 Port: {port}")
    print(f"🐛 Debug: {debug}")
    
    # Run Flask app
    app.run(host="0.0.0.0", port=port, debug=debug)