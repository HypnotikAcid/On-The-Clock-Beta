import os
import sqlite3
import json
from datetime import datetime, timedelta
from flask import Flask, redirect, url_for, render_template, session, request, jsonify, make_response
from flask_session import Session
from werkzeug.middleware.proxy_fix import ProxyFix
import requests

app = Flask(__name__)

# Critical: Add ProxyFix for Replit's reverse proxy environment
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# Security configuration - use environment variable for production consistency
app.secret_key = os.environ.get('SECRET_KEY') or 'dev-fallback-key-change-in-production'

# Session configuration for production - corrected for HTTPS with ProxyFix  
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('REPLIT_ENVIRONMENT') == 'production'  # True for HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  
app.config['SESSION_COOKIE_DOMAIN'] = None
app.config['SESSION_COOKIE_PATH'] = '/'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)  # 24 hour sessions

# Session storage - using filesystem sessions (proven reliable approach)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = './flask_session'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True

# Initialize Flask-Session for proper server-side storage
Session(app)

# Create session directory if it doesn't exist
import os
os.makedirs('./flask_session', exist_ok=True)

print("✅ Server-side session storage configured - filesystem-based for security and reliability")

# Discord OAuth2 configuration
app.config["DISCORD_CLIENT_ID"] = os.environ.get("DISCORD_CLIENT_ID")
app.config["DISCORD_CLIENT_SECRET"] = os.environ.get("DISCORD_CLIENT_SECRET")

# Dynamic redirect URI based on environment
def get_base_url():
    """Get the base URL for the current environment."""
    if os.environ.get("REPLIT_ENVIRONMENT") == "production":
        # Production domain - always HTTPS
        return "https://on-the-clock.replit.app"
    else:
        # Development/preview domain - always HTTPS on Replit
        domains = os.environ.get("REPLIT_DOMAINS", "").split(",")
        if domains and domains[0]:
            return f"https://{domains[0].strip()}"
        return "http://localhost:5000"  # Local fallback only

# Set redirect URI dynamically - ensure HTTPS in production
redirect_uri = os.environ.get("DISCORD_REDIRECT_URI") or f"{get_base_url()}/callback"
# Force HTTPS in production to fix OAuth insecure_transport error
if os.environ.get("REPLIT_ENVIRONMENT") == "production" and redirect_uri.startswith("http://"):
    redirect_uri = redirect_uri.replace("http://", "https://")

app.config["DISCORD_REDIRECT_URI"] = redirect_uri
app.config["DISCORD_BOT_TOKEN"] = os.environ.get("DISCORD_TOKEN")

# Discord API configuration for direct OAuth implementation
DISCORD_API_BASE = "https://discord.com/api"
DISCORD_CDN_BASE = "https://cdn.discordapp.com"

# Direct Discord OAuth2 Implementation (Proven Pattern)
def exchange_code_for_token(code):
    """Exchange authorization code for access token using Discord API."""
    token_data = {
        'client_id': app.config['DISCORD_CLIENT_ID'],
        'client_secret': app.config['DISCORD_CLIENT_SECRET'],
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': app.config['DISCORD_REDIRECT_URI']
    }
    
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    
    response = requests.post(f'{DISCORD_API_BASE}/oauth2/token', 
                           data=token_data, headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"❌ Token exchange failed: {response.status_code} - {response.text}")
        return None

def get_discord_user(access_token):
    """Get Discord user info using access token."""
    headers = {'Authorization': f'Bearer {access_token}'}
    
    response = requests.get(f'{DISCORD_API_BASE}/users/@me', headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"❌ User fetch failed: {response.status_code} - {response.text}")
        return None

def get_discord_guilds(access_token):
    """Get user's Discord guilds using access token."""
    headers = {'Authorization': f'Bearer {access_token}'}
    
    response = requests.get(f'{DISCORD_API_BASE}/users/@me/guilds', headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"❌ Guilds fetch failed: {response.status_code} - {response.text}")
        return []

def store_user_session_data(user_id, access_token, guilds_data, user_data=None):
    """Store sensitive session data server-side in database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create user_sessions table if it doesn't exist FIRST
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_sessions (
            user_id TEXT PRIMARY KEY,
            access_token TEXT,
            guilds_data TEXT,
            expires_at TIMESTAMP DEFAULT (datetime('now', '+24 hours'))
        )
    """)
    
    # Check if user_data column exists, add if missing (robust migration)
    try:
        cursor.execute("PRAGMA table_info(user_sessions)")
        columns = [row[1] for row in cursor.fetchall()]
        
        if 'user_data' not in columns:
            print("🔧 Adding user_data column to user_sessions table...")
            cursor.execute("ALTER TABLE user_sessions ADD COLUMN user_data TEXT")
            print("✅ Database migration completed")
    except Exception as e:
        print(f"⚠️ Database migration error (likely already migrated): {e}")
    
    # Store session data (replace if exists)
    cursor.execute("""
        INSERT OR REPLACE INTO user_sessions (user_id, access_token, guilds_data, user_data, expires_at)
        VALUES (?, ?, ?, ?, datetime('now', '+24 hours'))
    """, (user_id, access_token, json.dumps(guilds_data), json.dumps(user_data) if user_data else None))
    
    conn.commit()
    conn.close()
    print(f"✅ Stored session data server-side for user {user_id}")

def get_user_session_data(user_id):
    """Get user's session data from server-side storage."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Resilient query - handle missing user_data column gracefully
    try:
        cursor.execute("""
            SELECT access_token, guilds_data, user_data FROM user_sessions 
            WHERE user_id = ? AND expires_at > datetime('now')
        """, (user_id,))
    except Exception:
        # Fallback for legacy schema without user_data
        cursor.execute("""
            SELECT access_token, guilds_data FROM user_sessions 
            WHERE user_id = ? AND expires_at > datetime('now')
        """, (user_id,))
    
    result = cursor.fetchone()
    conn.close()
    
    if result:
        # Always return consistent dict format
        return {
            'access_token': result[0] if result[0] else None,
            'guilds_data': json.loads(result[1]) if result[1] else [],
            'user_data': json.loads(result[2]) if len(result) >= 3 and result[2] else None
        }
    
    return {'access_token': None, 'guilds_data': [], 'user_data': None}

def get_user_guilds_cached(user_id):
    """Get user's guilds from server-side cache."""
    result = get_user_session_data(user_id)
    return result.get('guilds_data', [])

def store_finalize_token(token, user_id):
    """Store one-time finalize token with short expiry for security."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create finalize_tokens table if it doesn't exist
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS finalize_tokens (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            expires_at TIMESTAMP DEFAULT (datetime('now', '+5 minutes'))
        )
    """)
    
    # Clean up expired tokens
    cursor.execute("DELETE FROM finalize_tokens WHERE expires_at < datetime('now')")
    
    # Store new token with 5-minute expiry
    cursor.execute("""
        INSERT INTO finalize_tokens (token, user_id, expires_at)
        VALUES (?, ?, datetime('now', '+5 minutes'))
    """, (token, user_id))
    
    conn.commit()
    conn.close()
    print(f"✅ Stored finalize token for user {user_id}")

def verify_and_consume_finalize_token(token):
    """Verify and consume one-time finalize token, return user_id or None."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if token exists and is not expired
    cursor.execute("""
        SELECT user_id FROM finalize_tokens 
        WHERE token = ? AND expires_at > datetime('now')
    """, (token,))
    
    result = cursor.fetchone()
    
    if result:
        user_id = result[0]
        # Consume token (delete it immediately for security)
        cursor.execute("DELETE FROM finalize_tokens WHERE token = ?", (token,))
        conn.commit()
        conn.close()
        print(f"✅ Consumed finalize token for user {user_id}")
        return user_id
    else:
        conn.close()
        print("❌ Invalid or expired finalize token")
        return None

# Discord API cache
discord_cache = {}
CACHE_DURATION = 300  # 5 minutes

def get_bot_headers():
    """Get headers for Discord bot API requests."""
    return {
        "Authorization": f"Bot {app.config['DISCORD_BOT_TOKEN']}",
        "Content-Type": "application/json"
    }

def get_cached_or_fetch(cache_key, fetch_function, duration=CACHE_DURATION):
    """Get data from cache or fetch it if expired."""
    now = datetime.now()
    
    if cache_key in discord_cache:
        cached_data, timestamp = discord_cache[cache_key]
        if now - timestamp < timedelta(seconds=duration):
            return cached_data
    
    # Fetch fresh data
    data = fetch_function()
    discord_cache[cache_key] = (data, now)
    return data

def get_db_connection():
    """Get database connection."""
    conn = sqlite3.connect('timeclock.db')
    conn.row_factory = sqlite3.Row
    return conn

def login_required(f):
    """Decorator to require login for routes."""
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('auth_login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

@app.errorhandler(500)
def internal_error(error):
    """Handle internal server errors gracefully."""
    print(f"❌ Internal server error: {error}")
    return render_template("dashboard.html", error="Something went wrong. Please try again later."), 500

@app.errorhandler(404)
def not_found(error):
    """Handle page not found errors."""
    return render_template("dashboard.html", error="Page not found."), 404

@app.errorhandler(Exception)
def handle_exception(e):
    """Handle unexpected exceptions."""
    print(f"❌ Unexpected error: {e}")
    # Return a generic error page for production
    if os.environ.get('FLASK_ENV', 'development') == 'production':
        return render_template("dashboard.html", error="An unexpected error occurred. Please try again."), 500
    else:
        # In development, let Flask show the full traceback
        raise e

@app.route("/")
def index():
    """Homepage with login option."""
    return render_template("dashboard.html")

@app.route("/auth/login")
def auth_login():
    """Initiate Discord OAuth login with CSRF protection."""
    import secrets
    
    # Generate CSRF state token for security
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state
    
    # Properly encode OAuth URL parameters for security
    from urllib.parse import urlencode
    
    params = {
        'client_id': app.config['DISCORD_CLIENT_ID'],
        'redirect_uri': app.config['DISCORD_REDIRECT_URI'],
        'response_type': 'code',
        'scope': 'identify guilds',  # Removed email scope as suggested
        'state': state
    }
    discord_login_url = f"https://discord.com/api/oauth2/authorize?{urlencode(params)}"
    return redirect(discord_login_url)

@app.route("/callback")
def callback():
    """Handle OAuth callback from Discord with CSRF protection."""
    code = request.args.get('code')
    state = request.args.get('state')
    
    # Verify CSRF state token
    if not state or state != session.get('oauth_state'):
        print("❌ Invalid or missing OAuth state - CSRF protection triggered")
        session.clear()  # Clear potentially compromised session
        return redirect(url_for("index"))
    
    # Clear the state token
    session.pop('oauth_state', None)
    
    if not code:
        print("❌ No authorization code received from Discord")
        return redirect(url_for("index"))
    
    # Exchange code for access token
    token_info = exchange_code_for_token(code)
    if not token_info:
        print("❌ Failed to exchange code for access token")
        return redirect(url_for("index"))
    
    access_token = token_info['access_token']
    
    # Get user info
    user_data = get_discord_user(access_token)
    if not user_data:
        print("❌ Failed to fetch Discord user information")
        return redirect(url_for("index"))
    
    # Get user's guilds
    guilds_data = get_discord_guilds(access_token)
    
    # Store minimal user data in session (secure approach)
    user_id = user_data['id']
    
    # Store user session data server-side first (including user_data for finalize)
    store_user_session_data(user_id, access_token, guilds_data, user_data)
    
    # Generate secure one-time finalize token (CSRF protection)
    import secrets
    finalize_token = secrets.token_urlsafe(32)
    store_finalize_token(finalize_token, user_id)
    
    # Force session ID regeneration by clearing session and creating new response
    session.clear()  # Clear old session data
    
    # Create response that forces new session cookie and redirect to finalize
    response = make_response(redirect(url_for('auth_finalize', token=finalize_token)))
    
    # Properly delete old session cookie using Flask configuration
    cookie_name = app.config.get('SESSION_COOKIE_NAME', getattr(app, 'session_cookie_name', 'session'))
    cookie_domain = app.config.get('SESSION_COOKIE_DOMAIN')
    cookie_path = app.config.get('SESSION_COOKIE_PATH', '/')
    
    response.delete_cookie(cookie_name, path=cookie_path, domain=cookie_domain)
    
    print(f"✅ User data stored server-side: {user_data['username']} - redirecting to finalize with secure token")
    return response

@app.route("/dashboard")
@login_required
def dashboard():
    """Main dashboard page."""
    try:
        user_data = session.get('user')
        if not user_data:
            return redirect(url_for('auth_login'))
            
        # Get guilds from secure server-side storage  
        guilds_data = get_user_guilds_cached(user_data['id'])
        
        # Filter guilds where user has admin permissions (direct API approach)
        admin_guilds = []
        for guild in guilds_data:
            # Check if user has admin permissions (0x8 = ADMINISTRATOR)
            if guild.get('permissions', 0) & 0x8:
                admin_guilds.append(guild)
        
        return render_template("dashboard.html", 
                             user=user_data, 
                             guilds=admin_guilds, 
                             authenticated=True)
    except Exception as e:
        print(f"❌ Dashboard error: {e}")
        return f"Dashboard Error: {str(e)}", 500

@app.route("/api/user")
@login_required
def api_user():
    """Get current user data."""
    try:
        user_data = session.get('user')
        if not user_data:
            return jsonify({"error": "User not authenticated"}), 401
            
        # Get guilds from secure server-side storage
        guilds_data = get_user_guilds_cached(user_data['id'])
        print(f"✅ API user request: {user_data['username']} with {len(guilds_data)} guilds from server-side storage")
        
        # Filter to admin guilds only (0x8 = ADMINISTRATOR permission)
        admin_guilds = [
            {
                "id": str(guild["id"]),
                "name": guild["name"],
                "icon": f"https://cdn.discordapp.com/icons/{guild['id']}/{guild['icon']}.png" if guild.get('icon') else None,
                "permissions": guild.get("permissions", 0)
            }
            for guild in guilds_data if guild.get("permissions", 0) & 0x8  # ADMINISTRATOR permission
        ]
        
        return jsonify({
            "id": user_data["id"],
            "username": user_data["username"],
            "discriminator": user_data.get("discriminator", "0000"),
            "avatar_url": f"https://cdn.discordapp.com/avatars/{user_data['id']}/{user_data['avatar']}.png" if user_data.get('avatar') else None,
            "email": user_data.get("email"),
            "guilds": admin_guilds
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/guild/<guild_id>")
@login_required
def api_guild_info(guild_id):
    """Get guild information and statistics."""
    try:
        # Verify user has access to this guild from server-side storage
        user_data = session.get('user')
        if not user_data:
            return jsonify({"error": "User not authenticated"}), 401
            
        guilds_data = get_user_guilds_cached(user_data['id'])
        guild = next((g for g in guilds_data if str(g["id"]) == guild_id and g.get("permissions", 0) & 0x8), None)
        
        if not guild:
            return jsonify({"error": "Guild not found or no admin access"}), 403
        
        # Get guild stats from database
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get total sessions
        cursor.execute("SELECT COUNT(*) FROM time_sessions WHERE guild_id = ?", (guild_id,))
        total_sessions = cursor.fetchone()[0]
        
        # Get active users (users with sessions in last 30 days)
        cursor.execute("""
            SELECT COUNT(DISTINCT user_id) FROM time_sessions 
            WHERE guild_id = ? AND start_time > datetime('now', '-30 days')
        """, (guild_id,))
        active_users = cursor.fetchone()[0]
        
        # Get subscription info
        cursor.execute("SELECT tier, expires_at FROM server_subscriptions WHERE guild_id = ?", (guild_id,))
        subscription = cursor.fetchone()
        
        tier = subscription[0] if subscription else "free"
        expires_at = subscription[1] if subscription else None
        
        conn.close()
        
        return jsonify({
            "id": str(guild["id"]),
            "name": guild["name"],
            "icon": f"https://cdn.discordapp.com/icons/{guild['id']}/{guild['icon']}.png" if guild.get('icon') else None,
            "total_sessions": total_sessions,
            "active_users": active_users,
            "tier": tier,
            "expires_at": expires_at
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/guild/<guild_id>/roles")
@login_required
def api_guild_roles(guild_id):
    """Get guild roles using bot token."""
    try:
        # Verify user has access
        user_data = session.get('user')
        if not user_data:
            return jsonify({"error": "User not authenticated"}), 401
        guilds_data = get_user_guilds_cached(user_data['id'])
        guild = next((g for g in guilds_data if str(g["id"]) == guild_id and g.get("permissions", 0) & 0x8), None)
        
        if not guild:
            return jsonify({"error": "Guild not found or no admin access"}), 403
        
        def fetch_roles():
            """Fetch roles from Discord API."""
            response = requests.get(
                f"https://discord.com/api/v10/guilds/{guild_id}/roles",
                headers=get_bot_headers()
            )
            
            if response.status_code == 200:
                roles = response.json()
                # Filter out @everyone and sort by position
                return [
                    {
                        "id": role["id"],
                        "name": role["name"],
                        "color": role["color"],
                        "position": role["position"],
                        "permissions": role["permissions"]
                    }
                    for role in roles
                    if role["name"] != "@everyone"
                ]
            else:
                return []
        
        # Get cached or fresh data
        cache_key = f"roles_{guild_id}"
        roles = get_cached_or_fetch(cache_key, fetch_roles)
        
        return jsonify({"roles": roles})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/guild/<guild_id>/members")
@login_required  
def api_guild_members(guild_id):
    """Get guild members using bot token with fallback for missing privileged intents."""
    try:
        # Verify user has access
        user_data = session.get('user')
        if not user_data:
            return jsonify({"error": "User not authenticated"}), 401
        guilds_data = get_user_guilds_cached(user_data['id'])
        guild = next((g for g in guilds_data if str(g["id"]) == guild_id and g.get("permissions", 0) & 0x8), None)
        
        if not guild:
            return jsonify({"error": "Guild not found or no admin access"}), 403
        
        def fetch_members():
            """Fetch members from Discord API with error handling."""
            try:
                response = requests.get(
                    f"https://discord.com/api/v10/guilds/{guild_id}/members",
                    headers=get_bot_headers(),
                    params={"limit": 50}  # Smaller limit for testing
                )
                
                if response.status_code == 403:
                    # Members intent not enabled - return placeholder data
                    print(f"⚠️ Members API returned 403 for guild {guild_id} - likely missing Server Members Intent")
                    return [
                        {
                            "id": "placeholder_1",
                            "username": "Member_1",
                            "discriminator": "0000",
                            "display_name": "Sample Member 1",
                            "avatar_url": None
                        },
                        {
                            "id": "placeholder_2", 
                            "username": "Member_2",
                            "discriminator": "0000",
                            "display_name": "Sample Member 2",
                            "avatar_url": None
                        }
                    ]
                
                if response.status_code != 200:
                    print(f"⚠️ Members API returned {response.status_code} for guild {guild_id}")
                    return []
                
                batch = response.json()
                members = []
                
                for member in batch:
                    user = member.get("user", {})
                    members.append({
                        "id": user.get("id"),
                        "username": user.get("username"),
                        "discriminator": user.get("discriminator", "0"),
                        "display_name": member.get("nick") or user.get("global_name") or user.get("username"),
                        "avatar_url": f"https://cdn.discordapp.com/avatars/{user.get('id')}/{user.get('avatar')}.png" if user.get('avatar') else None
                    })
                
                print(f"✅ Successfully fetched {len(members)} members for guild {guild_id}")
                return members
                
            except Exception as e:
                print(f"❌ Error fetching members for guild {guild_id}: {e}")
                return []
        
        # Get cached or fresh data
        cache_key = f"members_{guild_id}"
        members = get_cached_or_fetch(cache_key, fetch_members)
        
        return jsonify({
            "members": members,
            "note": "Limited member data due to Discord API restrictions" if len(members) <= 2 else None
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/guild/<guild_id>/settings", methods=["GET"])
@login_required
def api_guild_settings_get(guild_id):
    """Get guild settings."""
    try:
        # Verify user has access
        user_data = session.get('user')
        if not user_data:
            return jsonify({"error": "User not authenticated"}), 401
        guilds_data = get_user_guilds_cached(user_data['id'])
        guild = next((g for g in guilds_data if str(g["id"]) == guild_id and g.get("permissions", 0) & 0x8), None)
        
        if not guild:
            return jsonify({"error": "Guild not found or no admin access"}), 403
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get guild settings
        cursor.execute("SELECT * FROM guild_settings WHERE guild_id = ?", (guild_id,))
        settings = cursor.fetchone()
        
        # Get recipients
        cursor.execute("SELECT * FROM report_recipients WHERE guild_id = ?", (guild_id,))
        recipients = cursor.fetchall()
        
        conn.close()
        
        # Format response
        result = {
            "timezone": settings["timezone"] if settings else "UTC",
            "name_display": settings["name_display"] if settings else "username",
            "admin_roles": json.loads(settings["admin_roles"]) if settings and settings["admin_roles"] else [],
            "employee_roles": json.loads(settings["employee_roles"]) if settings and settings["employee_roles"] else [],
            "recipients": [
                {
                    "id": r["id"],
                    "type": r["type"],
                    "discord_user_id": r["discord_user_id"],
                    "email": r["email"]
                }
                for r in recipients
            ]
        }
        
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/guild/<guild_id>/settings", methods=["POST"])
@login_required
def api_guild_settings_post(guild_id):
    """Save guild settings."""
    try:
        # Verify user has access
        user_data = session.get('user')
        if not user_data:
            return jsonify({"error": "User not authenticated"}), 401
        guilds_data = get_user_guilds_cached(user_data['id'])
        guild = next((g for g in guilds_data if str(g["id"]) == guild_id and g.get("permissions", 0) & 0x8), None)
        
        if not guild:
            return jsonify({"error": "Guild not found or no admin access"}), 403
        
        data = request.get_json()
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Update guild settings
        cursor.execute("""
            INSERT OR REPLACE INTO guild_settings 
            (guild_id, timezone, name_display, admin_roles, employee_roles)
            VALUES (?, ?, ?, ?, ?)
        """, (
            guild_id,
            data.get("timezone", "UTC"),
            data.get("name_display", "username"),
            json.dumps(data.get("admin_roles", [])),
            json.dumps(data.get("employee_roles", []))
        ))
        
        # Clear existing recipients
        cursor.execute("DELETE FROM report_recipients WHERE guild_id = ?", (guild_id,))
        
        # Add new recipients
        for recipient in data.get("recipients", []):
            cursor.execute("""
                INSERT INTO report_recipients (guild_id, type, discord_user_id, email)
                VALUES (?, ?, ?, ?)
            """, (
                guild_id,
                recipient.get("type"),
                recipient.get("discord_user_id"),
                recipient.get("email")
            ))
        
        conn.commit()
        conn.close()
        
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/auth/finalize")
def auth_finalize():
    """Finalize authentication with new session ID using secure one-time token."""
    token = request.args.get('token')
    if not token:
        print("❌ Missing finalize token")
        return redirect(url_for("index"))
    
    # Verify and consume one-time token
    user_id = verify_and_consume_finalize_token(token)
    if not user_id:
        print("❌ Invalid or expired finalize token")
        return redirect(url_for("index"))
    
    # Retrieve user data from server-side storage
    cached_data = get_user_session_data(user_id)
    if not cached_data:
        print("❌ No cached user data found during finalize")
        return redirect(url_for("index"))
    
    user_data = cached_data.get('user_data')
    if not user_data:
        print("❌ Invalid cached user data during finalize")
        return redirect(url_for("index"))
    
    # Set user session data in new session with new SID
    session['user'] = {
        'id': user_data['id'],
        'username': user_data['username'],
        'discriminator': user_data.get('discriminator', '0000'),
        'avatar': user_data.get('avatar'),
        'email': user_data.get('email')
    }
    session.permanent = True
    session.modified = True  # Ensure Flask issues new session cookie
    
    print(f"✅ Authentication finalized with new SID for: {user_data['username']}")
    return redirect(url_for('dashboard'))

@app.route("/logout")
def logout():
    """Logout with comprehensive session cleanup."""
    user_data = session.get('user')
    if user_data:
        # Clear server-side session data
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM user_sessions WHERE user_id = ?", (user_data['id'],))
        conn.commit()
        conn.close()
        print(f"✅ Cleared server-side session data for user {user_data['id']}")
    
    # Clear client session and rotate session ID for security
    session.clear()
    print("✅ User logged out - all session data cleared")
    
    # Create response that properly deletes session cookie
    response = make_response(redirect(url_for("index")))
    
    # Use Flask's session cookie configuration for proper deletion
    cookie_name = app.config.get('SESSION_COOKIE_NAME', getattr(app, 'session_cookie_name', 'session'))
    cookie_domain = app.config.get('SESSION_COOKIE_DOMAIN')
    cookie_path = app.config.get('SESSION_COOKIE_PATH', '/')
    
    response.delete_cookie(cookie_name, path=cookie_path, domain=cookie_domain)
    
    print("✅ Session cookie properly deleted with all attributes")
    return response

if __name__ == "__main__":
    print("🚀 Starting Flask Dashboard Server...")
    print(f"📍 Base URL: {get_base_url()}")
    print(f"🔄 Redirect URI: {app.config['DISCORD_REDIRECT_URI']}")
    
    # Production-ready configuration
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV', 'development') == 'development'
    
    print(f"🔧 Environment: {os.environ.get('FLASK_ENV', 'development')}")
    print(f"🌐 Port: {port}")
    print(f"🐛 Debug: {debug}")
    
    # Run Flask app
    app.run(host="0.0.0.0", port=port, debug=debug)