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
        # Get admin roles
        admin_cursor = conn.execute(
            "SELECT role_id FROM admin_roles WHERE guild_id = ?",
            (guild_id,)
        )
        admin_roles = [row[0] for row in admin_cursor.fetchall()]
        
        # Get employee roles
        employee_cursor = conn.execute(
            "SELECT role_id FROM employee_roles WHERE guild_id = ?",
            (guild_id,)
        )
        employee_roles = [row[0] for row in employee_cursor.fetchall()]
        
        # Get guild settings (timezone, recipient_user_id, etc.)
        settings_cursor = conn.execute(
            "SELECT timezone, recipient_user_id, name_display_mode FROM guild_settings WHERE guild_id = ?",
            (guild_id,)
        )
        settings_row = settings_cursor.fetchone()
        
        # Get main admin role
        main_admin_cursor = conn.execute(
            "SELECT main_admin_role_id FROM guild_settings WHERE guild_id = ?",
            (guild_id,)
        )
        main_admin_row = main_admin_cursor.fetchone()
        main_admin_role_id = main_admin_row[0] if main_admin_row and main_admin_row[0] else None
        
        return {
            'admin_roles': admin_roles,
            'employee_roles': employee_roles,
            'timezone': settings_row[0] if settings_row else 'America/New_York',
            'recipient_user_id': settings_row[1] if settings_row else None,
            'name_display_mode': settings_row[2] if settings_row else 'username',
            'main_admin_role_id': main_admin_role_id,
            'emails': []  # TODO: Add email table and fetch emails
        }

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
        
        # Prepare data for template
        template_data = {
            'user': user_session,
            'guild': guild,
            'guild_id': guild_id,
            'roles': roles,
            'current_settings': current_settings
        }
        
        return render_template('server_settings.html', **template_data)
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
    """API endpoint to add an admin role"""
    try:
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
        
        # Add role to database
        with get_db() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO admin_roles (guild_id, role_id) VALUES (?, ?)",
                (guild_id, role_id)
            )
        
        app.logger.info(f"Added admin role {role_id} to guild {guild_id} by user {user_session.get('username')}")
        return jsonify({'success': True, 'message': 'Admin role added successfully', 'role_id': role_id})
    except Exception as e:
        app.logger.error(f"Error adding admin role: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@app.route("/api/server/<guild_id>/admin-roles/remove", methods=["POST"])
@require_api_auth
def api_remove_admin_role(user_session, guild_id):
    """API endpoint to remove an admin role"""
    try:
        # Verify user has access
        guild = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Get role_id from request
        data = request.get_json()
        if not data or 'role_id' not in data:
            return jsonify({'success': False, 'error': 'Missing role_id'}), 400
        
        role_id = str(data['role_id'])
        
        # Remove role from database
        with get_db() as conn:
            conn.execute(
                "DELETE FROM admin_roles WHERE guild_id = ? AND role_id = ?",
                (guild_id, role_id)
            )
        
        app.logger.info(f"Removed admin role {role_id} from guild {guild_id} by user {user_session.get('username')}")
        return jsonify({'success': True, 'message': 'Admin role removed successfully', 'role_id': role_id})
    except Exception as e:
        app.logger.error(f"Error removing admin role: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@app.route("/api/server/<guild_id>/employee-roles/add", methods=["POST"])
@require_api_auth
def api_add_employee_role(user_session, guild_id):
    """API endpoint to add an employee role"""
    try:
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
        
        # Add role to database
        with get_db() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO employee_roles (guild_id, role_id) VALUES (?, ?)",
                (guild_id, role_id)
            )
        
        app.logger.info(f"Added employee role {role_id} to guild {guild_id} by user {user_session.get('username')}")
        return jsonify({'success': True, 'message': 'Employee role added successfully', 'role_id': role_id})
    except Exception as e:
        app.logger.error(f"Error adding employee role: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@app.route("/api/server/<guild_id>/employee-roles/remove", methods=["POST"])
@require_api_auth
def api_remove_employee_role(user_session, guild_id):
    """API endpoint to remove an employee role"""
    try:
        # Verify user has access
        guild = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Get role_id from request
        data = request.get_json()
        if not data or 'role_id' not in data:
            return jsonify({'success': False, 'error': 'Missing role_id'}), 400
        
        role_id = str(data['role_id'])
        
        # Remove role from database
        with get_db() as conn:
            conn.execute(
                "DELETE FROM employee_roles WHERE guild_id = ? AND role_id = ?",
                (guild_id, role_id)
            )
        
        app.logger.info(f"Removed employee role {role_id} from guild {guild_id} by user {user_session.get('username')}")
        return jsonify({'success': True, 'message': 'Employee role removed successfully', 'role_id': role_id})
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