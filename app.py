import os
import sqlite3
import json
from datetime import datetime, timedelta
from flask import Flask, redirect, url_for, render_template, session, request, jsonify
from flask_discord import DiscordOAuth2Session, requires_authorization, Unauthorized
import requests

app = Flask(__name__)

# Security configuration
app.secret_key = os.urandom(24)  # Secure random secret key

# Discord OAuth2 configuration
app.config["DISCORD_CLIENT_ID"] = os.environ.get("DISCORD_CLIENT_ID")
app.config["DISCORD_CLIENT_SECRET"] = os.environ.get("DISCORD_CLIENT_SECRET")

# Dynamic redirect URI based on environment
def get_base_url():
    """Get the base URL for the current environment."""
    if os.environ.get("REPLIT_ENVIRONMENT") == "production":
        # Production domain
        return "https://on-the-clock.replit.app"
    else:
        # Development/preview domain
        domains = os.environ.get("REPLIT_DOMAINS", "").split(",")
        if domains and domains[0]:
            return f"https://{domains[0].strip()}"
        return "http://localhost:5000"  # Local fallback

app.config["DISCORD_REDIRECT_URI"] = f"{get_base_url()}/callback"
app.config["DISCORD_BOT_TOKEN"] = os.environ.get("DISCORD_TOKEN")

# Initialize Discord OAuth session
discord = DiscordOAuth2Session(app)

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

@app.errorhandler(Unauthorized)
def redirect_unauthorized(e):
    """Redirect unauthorized users to login."""
    return redirect(url_for("login"))

@app.route("/")
def index():
    """Homepage with login option."""
    return render_template("dashboard.html")

@app.route("/login/")
def login():
    """Initiate Discord OAuth login."""
    return discord.create_session(scope=["identify", "email", "guilds"])

@app.route("/callback/")
def callback():
    """Handle OAuth callback from Discord."""
    try:
        discord.callback()
        return redirect(url_for("dashboard"))
    except Exception as e:
        return f"OAuth Error: {str(e)}", 400

@app.route("/dashboard/")
@requires_authorization
def dashboard():
    """Main dashboard page."""
    try:
        user = discord.fetch_user()
        guilds = discord.fetch_guilds()
        
        # Filter guilds where the bot is present
        bot_guilds = []
        for guild in guilds:
            # Check if user has admin permissions
            if guild.permissions.administrator:
                bot_guilds.append(guild)
        
        return render_template("dashboard.html", user=user, guilds=bot_guilds, authenticated=True)
    except Exception as e:
        return f"Dashboard Error: {str(e)}", 500

@app.route("/api/user")
@requires_authorization
def api_user():
    """Get current user data."""
    try:
        user = discord.fetch_user()
        guilds = discord.fetch_guilds()
        
        # Filter to admin guilds only
        admin_guilds = [
            {
                "id": str(guild.id),
                "name": guild.name,
                "icon": guild.icon_url if guild.icon_url else None,
                "owner": guild.owner,
                "permissions": guild.permissions.administrator
            }
            for guild in guilds if guild.permissions.administrator
        ]
        
        return jsonify({
            "id": str(user.id),
            "username": user.name,
            "discriminator": user.discriminator,
            "avatar_url": user.avatar_url,
            "email": user.email,
            "guilds": admin_guilds
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/guild/<guild_id>")
@requires_authorization
def api_guild_info(guild_id):
    """Get guild information and statistics."""
    try:
        # Verify user has access to this guild
        guilds = discord.fetch_guilds()
        guild = next((g for g in guilds if str(g.id) == guild_id and g.permissions.administrator), None)
        
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
            "id": str(guild.id),
            "name": guild.name,
            "icon": guild.icon_url,
            "total_sessions": total_sessions,
            "active_users": active_users,
            "tier": tier,
            "expires_at": expires_at
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/guild/<guild_id>/roles")
@requires_authorization
def api_guild_roles(guild_id):
    """Get guild roles using bot token."""
    try:
        # Verify user has access
        guilds = discord.fetch_guilds()
        guild = next((g for g in guilds if str(g.id) == guild_id and g.permissions.administrator), None)
        
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
@requires_authorization  
def api_guild_members(guild_id):
    """Get guild members using bot token."""
    try:
        # Verify user has access
        guilds = discord.fetch_guilds()
        guild = next((g for g in guilds if str(g.id) == guild_id and g.permissions.administrator), None)
        
        if not guild:
            return jsonify({"error": "Guild not found or no admin access"}), 403
        
        def fetch_members():
            """Fetch members from Discord API."""
            members = []
            params = {"limit": 1000}
            
            while True:
                response = requests.get(
                    f"https://discord.com/api/v10/guilds/{guild_id}/members",
                    headers=get_bot_headers(),
                    params=params
                )
                
                if response.status_code != 200:
                    break
                
                batch = response.json()
                if not batch:
                    break
                
                for member in batch:
                    user = member.get("user", {})
                    members.append({
                        "id": user.get("id"),
                        "username": user.get("username"),
                        "discriminator": user.get("discriminator", "0"),
                        "display_name": member.get("nick") or user.get("global_name") or user.get("username"),
                        "avatar_url": f"https://cdn.discordapp.com/avatars/{user.get('id')}/{user.get('avatar')}.png" if user.get('avatar') else None
                    })
                
                # Set up pagination for next batch
                if len(batch) < 1000:
                    break
                params["after"] = batch[-1]["user"]["id"]
            
            return members[:50]  # Limit to first 50 for performance
        
        # Get cached or fresh data
        cache_key = f"members_{guild_id}"
        members = get_cached_or_fetch(cache_key, fetch_members)
        
        return jsonify({"members": members})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/guild/<guild_id>/settings", methods=["GET"])
@requires_authorization
def api_guild_settings_get(guild_id):
    """Get guild settings."""
    try:
        # Verify user has access
        guilds = discord.fetch_guilds()
        guild = next((g for g in guilds if str(g.id) == guild_id and g.permissions.administrator), None)
        
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
@requires_authorization
def api_guild_settings_post(guild_id):
    """Save guild settings."""
    try:
        # Verify user has access
        guilds = discord.fetch_guilds()
        guild = next((g for g in guilds if str(g.id) == guild_id and g.permissions.administrator), None)
        
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

@app.route("/logout/")
def logout():
    """Logout and revoke Discord session."""
    discord.revoke()
    return redirect(url_for("index"))

if __name__ == "__main__":
    print("🚀 Starting Flask Dashboard Server...")
    print(f"📍 Base URL: {get_base_url()}")
    print(f"🔄 Redirect URI: {app.config['DISCORD_REDIRECT_URI']}")
    
    # Run Flask app
    app.run(host="0.0.0.0", port=3000, debug=True)