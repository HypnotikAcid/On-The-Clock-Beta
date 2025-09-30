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
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode
import requests
from flask import Flask, render_template, redirect, request, session, jsonify, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)

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
    conn = sqlite3.connect('timeclock.db')
    conn.row_factory = sqlite3.Row
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

def get_bot_guild_ids():
    """Get list of guild IDs where the bot is present"""
    with get_db() as conn:
        cursor = conn.execute("SELECT guild_id FROM bot_guilds")
        return set(row[0] for row in cursor.fetchall())

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