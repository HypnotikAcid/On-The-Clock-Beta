import os
import sqlite3
import csv
import io
import threading
from datetime import datetime, timezone
from typing import Optional
from http.server import HTTPServer, BaseHTTPRequestHandler

import discord
from discord import app_commands
from discord.ext import commands

# --- Config / Secrets ---
TOKEN = os.getenv("DISCORD_TOKEN")            # required
DB_PATH = os.getenv("TIMECLOCK_DB", "timeclock.db")
GUILD_ID = os.getenv("GUILD_ID")              # optional but makes commands appear instantly (guild sync)
DEFAULT_TZ = "America/New_York"
HTTP_PORT = int(os.getenv("PORT", "5000"))     # Health check server port

# --- Health Check HTTP Server ---
class HealthCheckHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            # Serve HTML dashboard page at root
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
            self.send_header('Pragma', 'no-cache')
            self.send_header('Expires', '0')
            self.end_headers()
            html_content = self.get_dashboard_html()
            self.wfile.write(html_content.encode())
        elif self.path == "/health":
            # Keep JSON health check for deployment
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            response = {
                "status": "healthy",
                "service": "discord-bot",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            self.wfile.write(str(response).encode())
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_HEAD(self):
        if self.path == "/" or self.path == "/health":
            self.send_response(200)
            if self.path == "/":
                self.send_header('Content-type', 'text/html')
            else:
                self.send_header('Content-type', 'application/json')
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()
    
    def get_dashboard_html(self):
        # Get bot status info
        bot_status = "🟢 Online" if bot.is_ready() else "🔴 Offline"
        guild_count = len(bot.guilds) if bot.is_ready() else "Loading..."
        
        # Get bot's client ID for invite URL
        bot_id = bot.user.id if bot.is_ready() and bot.user else "1418446753379913809"
        invite_url = f"https://discord.com/api/oauth2/authorize?client_id={bot_id}&permissions=2048&scope=bot%20applications.commands"
        
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>On the Clock - Discord Timeclock Bot</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #e0e6ed;
        }}
        .container {{
            background: #2c2f36;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.4);
            border: 1px solid #3e4147;
            padding: 40px;
            max-width: 800px;
            width: 90%;
            text-align: center;
        }}
        .header {{
            margin-bottom: 30px;
        }}
        .bot-title {{
            font-size: 2.5em;
            font-weight: bold;
            color: #5865F2;
            margin-bottom: 10px;
        }}
        .bot-subtitle {{
            font-size: 1.2em;
            color: #b9bbbe;
            margin-bottom: 20px;
        }}
        .status-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        .status-card {{
            background: #36393f;
            border-radius: 15px;
            padding: 20px;
            border-left: 4px solid #5865F2;
            border: 1px solid #42464d;
        }}
        .status-title {{
            font-weight: bold;
            color: #dcddde;
            margin-bottom: 5px;
        }}
        .status-value {{
            font-size: 1.5em;
            color: #5865F2;
        }}
        .features {{
            margin: 30px 0;
            text-align: left;
        }}
        .features h3 {{
            color: #ffffff;
            margin-bottom: 15px;
            text-align: center;
        }}
        .feature-list {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 15px;
        }}
        .feature-item {{
            background: #36393f;
            padding: 15px;
            border-radius: 10px;
            border-left: 3px solid #28a745;
            border: 1px solid #42464d;
            color: #dcddde;
        }}
        .add-bot-section {{
            margin: 40px 0 20px 0;
            text-align: center;
        }}
        .add-bot-btn {{
            background: #5865F2;
            color: white;
            padding: 15px 30px;
            border: none;
            border-radius: 10px;
            font-size: 1.2em;
            font-weight: bold;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            margin: 10px 0;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(88, 101, 242, 0.3);
        }}
        .add-bot-btn:hover {{
            background: #4752C4;
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(88, 101, 242, 0.4);
        }}
        .add-bot-note {{
            color: #b9bbbe;
            font-size: 0.9em;
            margin-top: 10px;
        }}
        .beta-disclaimer {{
            background: #3e2723;
            border: 2px solid #ff6b35;
            border-radius: 10px;
            padding: 20px;
            margin: 30px 0;
            color: #ffccbc;
        }}
        .beta-disclaimer h3 {{
            color: #ff6b35;
            margin-bottom: 15px;
        }}
        .beta-disclaimer ul {{
            margin: 15px 0;
            padding-left: 20px;
        }}
        .beta-disclaimer li {{
            margin: 8px 0;
        }}
        .pricing-info {{
            background: #2c2f36;
            border: 1px solid #42464d;
            border-radius: 10px;
            padding: 25px;
            margin: 30px 0;
        }}
        .pricing-info h3 {{
            color: #f39c12;
            margin-bottom: 20px;
            text-align: center;
        }}
        .pricing-tier {{
            background: #36393f;
            border-left: 4px solid #f39c12;
            padding: 15px;
            margin: 15px 0;
            border-radius: 5px;
        }}
        .footer {{
            margin-top: 30px;
            color: #b9bbbe;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1 class="bot-title">⏰ On the Clock</h1>
            <p class="bot-subtitle">Professional Discord Timeclock Bot</p>
        </div>
        
        <div class="status-grid">
            <div class="status-card">
                <div class="status-title">Bot Status</div>
                <div class="status-value">{bot_status}</div>
            </div>
            <div class="status-card">
                <div class="status-title">Active Servers</div>
                <div class="status-value">{guild_count}</div>
            </div>
            <div class="status-card">
                <div class="status-title">Last Updated</div>
                <div class="status-value">{datetime.now().astimezone(__import__('zoneinfo').ZoneInfo('America/New_York')).strftime('%H:%M %Z')}</div>
            </div>
        </div>
        
        <div class="features">
            <h3>🚀 Features</h3>
            <div class="feature-list">
                <div class="feature-item">
                    <strong>⏱️ Clock In/Out</strong><br>
                    Easy-to-use buttons for time tracking
                </div>
                <div class="feature-item">
                    <strong>📊 Time Reports</strong><br>
                    Generate CSV reports for payroll
                </div>
                <div class="feature-item">
                    <strong>🌍 Timezone Support</strong><br>
                    Customizable timezone settings per server
                </div>
                <div class="feature-item">
                    <strong>🔒 Role Permissions</strong><br>
                    Control who can view time information
                </div>
                <div class="feature-item">
                    <strong>📱 Direct Messages</strong><br>
                    Automatic notifications to managers
                </div>
                <div class="feature-item">
                    <strong>💾 Persistent Data</strong><br>
                    Reliable SQLite database storage
                </div>
            </div>
        </div>
        
        <div class="add-bot-section">
            <a href="{invite_url}" target="_blank" class="add-bot-btn">
                🤖 Add to Your Discord Server
            </a>
            <p class="add-bot-note">Requires administrator permissions to set up</p>
        </div>
        
        <div class="beta-disclaimer">
            <h3>⚠️ Beta Software Notice</h3>
            <p><strong>This application is in beta testing.</strong> By using this service, you acknowledge:</p>
            <ul>
                <li>🔧 Features may not work as expected and bugs may occur</li>
                <li>⏰ Service downtime and maintenance may happen without notice</li>
                <li>💾 Data loss is possible and backups are not guaranteed</li>
                <li>🚫 This service may be discontinued at any time without notice</li>
                <li>📜 No warranty or guarantee of service availability is provided</li>
            </ul>
            <p><strong>Use at your own risk.</strong> This bot is provided "as-is" without any warranties.</p>
        </div>
        
        <div class="pricing-info">
            <h3>💰 Subscription Plans</h3>
            <div class="pricing-tier">
                <strong>Basic - $5/month</strong><br>
                Clock In/Out • Individual Time Info • Basic Tracking
            </div>
            <div class="pricing-tier">
                <strong>Pro - $10/month</strong><br>
                Everything in Basic • CSV Reports • Multiple Managers • Advanced Features
            </div>
        </div>
        
        <div class="footer">
            <p>Built for businesses and teams who need reliable time tracking in Discord</p>
            <p>Questions? Contact your server administrator</p>
        </div>
    </div>
</body>
</html>
        """
    
    def log_message(self, format, *args):
        # Suppress default HTTP server logs to avoid cluttering Discord bot logs
        pass

def start_health_server():
    """Start the health check HTTP server in a separate thread"""
    httpd = HTTPServer(('0.0.0.0', HTTP_PORT), HealthCheckHandler)
    print(f"🔧 Health check server starting on http://0.0.0.0:{HTTP_PORT}")
    httpd.serve_forever()

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    with db() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS guild_settings (
            guild_id INTEGER PRIMARY KEY,
            recipient_user_id INTEGER,
            button_channel_id INTEGER,
            button_message_id INTEGER,
            timezone TEXT DEFAULT 'America/New_York'
        )
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS authorized_roles (
            guild_id INTEGER,
            role_id INTEGER,
            PRIMARY KEY (guild_id, role_id)
        )
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            guild_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            clock_in TEXT NOT NULL,     -- ISO UTC
            clock_out TEXT,             -- ISO UTC
            duration_seconds INTEGER
        )
        """)

def get_guild_setting(guild_id: int, key: str, default=None):
    # Map of allowed keys to their SQL column queries
    column_queries = {
        'recipient_user_id': "SELECT recipient_user_id FROM guild_settings WHERE guild_id=?",
        'button_channel_id': "SELECT button_channel_id FROM guild_settings WHERE guild_id=?",
        'button_message_id': "SELECT button_message_id FROM guild_settings WHERE guild_id=?",
        'timezone': "SELECT timezone FROM guild_settings WHERE guild_id=?"
    }
    
    if key not in column_queries:
        raise ValueError(f"Invalid column name: {key}")
    
    with db() as conn:
        cur = conn.execute(column_queries[key], (guild_id,))
        row = cur.fetchone()
        return row[0] if row and row[0] is not None else default

def set_guild_setting(guild_id: int, key: str, value):
    # Map of allowed keys to their SQL update queries
    update_queries = {
        'recipient_user_id': "UPDATE guild_settings SET recipient_user_id=? WHERE guild_id=?",
        'button_channel_id': "UPDATE guild_settings SET button_channel_id=? WHERE guild_id=?",
        'button_message_id': "UPDATE guild_settings SET button_message_id=? WHERE guild_id=?",
        'timezone': "UPDATE guild_settings SET timezone=? WHERE guild_id=?"
    }
    
    if key not in update_queries:
        raise ValueError(f"Invalid column name: {key}")
    
    with db() as conn:
        conn.execute("INSERT OR IGNORE INTO guild_settings(guild_id) VALUES (?)", (guild_id,))
        conn.execute(update_queries[key], (value, guild_id))

def get_active_session(guild_id: int, user_id: int):
    with db() as conn:
        cur = conn.execute("""
            SELECT id, clock_in FROM sessions
            WHERE guild_id=? AND user_id=? AND clock_out IS NULL
            ORDER BY id DESC LIMIT 1
        """, (guild_id, user_id))
        return cur.fetchone()

def start_session(guild_id: int, user_id: int, clock_in_iso: str):
    with db() as conn:
        conn.execute("""
            INSERT INTO sessions (guild_id, user_id, clock_in)
            VALUES (?, ?, ?)
        """, (guild_id, user_id, clock_in_iso))

def close_session(session_id: int, clock_out_iso: str, duration_s: int):
    with db() as conn:
        conn.execute("""
            UPDATE sessions SET clock_out=?, duration_seconds=? WHERE id=?
        """, (clock_out_iso, duration_s, session_id))

def get_sessions_report(guild_id: int, user_id: Optional[int], start_utc: str, end_utc: str):
    """Get sessions for report generation within date range (UTC boundaries)."""
    with db() as conn:
        if user_id is not None:
            # Report for specific user
            cur = conn.execute("""
                SELECT user_id, clock_in, clock_out, duration_seconds
                FROM sessions
                WHERE guild_id=? AND user_id=? 
                AND clock_out IS NOT NULL
                AND clock_in < ?
                AND clock_out >= ?
                ORDER BY clock_in
            """, (guild_id, user_id, end_utc, start_utc))
        else:
            # Report for all users
            cur = conn.execute("""
                SELECT user_id, clock_in, clock_out, duration_seconds
                FROM sessions
                WHERE guild_id=? 
                AND clock_out IS NOT NULL
                AND clock_in < ?
                AND clock_out >= ?
                ORDER BY user_id, clock_in
            """, (guild_id, end_utc, start_utc))
        return cur.fetchall()

def add_authorized_role(guild_id: int, role_id: int):
    """Add a role as authorized for Info button access."""
    with db() as conn:
        conn.execute("INSERT OR IGNORE INTO authorized_roles (guild_id, role_id) VALUES (?, ?)", 
                     (guild_id, role_id))

def remove_authorized_role(guild_id: int, role_id: int):
    """Remove a role from authorized Info button access."""
    with db() as conn:
        conn.execute("DELETE FROM authorized_roles WHERE guild_id=? AND role_id=?", 
                     (guild_id, role_id))

def get_authorized_roles(guild_id: int):
    """Get all authorized role IDs for a guild."""
    with db() as conn:
        cur = conn.execute("SELECT role_id FROM authorized_roles WHERE guild_id=?", (guild_id,))
        return [row[0] for row in cur.fetchall()]

def user_has_authorized_role(guild_id: int, user_roles):
    """Check if user has any authorized role."""
    authorized_roles = get_authorized_roles(guild_id)
    user_role_ids = [role.id for role in user_roles]
    return any(role_id in authorized_roles for role_id in user_role_ids)

def get_user_hours_info(guild_id: int, user_id: int, guild_tz_name: str = "America/New_York"):
    """Get current session, daily, and weekly hours for a user."""
    from zoneinfo import ZoneInfo
    
    try:
        guild_tz = ZoneInfo(guild_tz_name)
    except Exception:
        guild_tz = timezone.utc
    
    now = datetime.now(timezone.utc)
    
    # Current session time
    active_session = get_active_session(guild_id, user_id)
    current_session_seconds = 0
    if active_session:
        session_id, clock_in_iso = active_session
        start_dt = datetime.fromisoformat(clock_in_iso)
        current_session_seconds = int((now - start_dt).total_seconds())
    
    # Get start of today and start of week in guild timezone
    now_local = now.astimezone(guild_tz)
    today_start = datetime.combine(now_local.date(), datetime.min.time()).replace(tzinfo=guild_tz)
    
    # Calculate start of week (Monday)
    days_since_monday = now_local.weekday()
    from datetime import timedelta
    week_start = today_start - timedelta(days=days_since_monday)
    
    # Convert to UTC for database queries
    today_start_utc = today_start.astimezone(timezone.utc).isoformat()
    week_start_utc = week_start.astimezone(timezone.utc).isoformat()
    now_utc = now.isoformat()
    
    with db() as conn:
        # Daily hours (sessions that overlap with today)
        daily_cur = conn.execute("""
            SELECT clock_in, clock_out FROM sessions
            WHERE guild_id=? AND user_id=? AND clock_out IS NOT NULL
            AND clock_in < ? AND clock_out >= ?
        """, (guild_id, user_id, now_utc, today_start_utc))
        daily_sessions = daily_cur.fetchall()
        
        daily_seconds = 0
        for clock_in_iso, clock_out_iso in daily_sessions:
            clock_in_dt = datetime.fromisoformat(clock_in_iso)
            clock_out_dt = datetime.fromisoformat(clock_out_iso)
            today_start_dt = datetime.fromisoformat(today_start_utc)
            
            # Calculate overlap with today
            overlap_start = max(clock_in_dt, today_start_dt)
            overlap_end = min(clock_out_dt, now)
            
            if overlap_end > overlap_start:
                daily_seconds += int((overlap_end - overlap_start).total_seconds())
        
        # Weekly hours (sessions that overlap with this week)
        weekly_cur = conn.execute("""
            SELECT clock_in, clock_out FROM sessions
            WHERE guild_id=? AND user_id=? AND clock_out IS NOT NULL
            AND clock_in < ? AND clock_out >= ?
        """, (guild_id, user_id, now_utc, week_start_utc))
        weekly_sessions = weekly_cur.fetchall()
        
        weekly_seconds = 0
        for clock_in_iso, clock_out_iso in weekly_sessions:
            clock_in_dt = datetime.fromisoformat(clock_in_iso)
            clock_out_dt = datetime.fromisoformat(clock_out_iso)
            week_start_dt = datetime.fromisoformat(week_start_utc)
            
            # Calculate overlap with this week
            overlap_start = max(clock_in_dt, week_start_dt)
            overlap_end = min(clock_out_dt, now)
            
            if overlap_end > overlap_start:
                weekly_seconds += int((overlap_end - overlap_start).total_seconds())
    
    return current_session_seconds, daily_seconds, weekly_seconds

async def generate_csv_report(bot, sessions_data, guild_tz="America/New_York"):
    """Generate organized CSV content from sessions data with usernames."""
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Group sessions by user
    user_sessions = {}
    for user_id, clock_in_iso, clock_out_iso, duration_seconds in sessions_data:
        if user_id not in user_sessions:
            user_sessions[user_id] = []
        user_sessions[user_id].append((clock_in_iso, clock_out_iso, duration_seconds))
    
    # Generate organized format for each user
    for user_id, sessions in user_sessions.items():
        # Fetch Discord user to get username
        try:
            discord_user = await bot.fetch_user(user_id)
            user_display_name = discord_user.name
        except:
            user_display_name = f"User-{user_id}"  # Fallback if user not found
        
        # Calculate date range for this user
        all_dates = []
        for clock_in_iso, _, _ in sessions:
            clock_in_dt = datetime.fromisoformat(clock_in_iso)
            date_formatted = fmt(clock_in_dt, guild_tz).split()[0]
            all_dates.append(date_formatted)
        
        date_range = f"{min(all_dates)} to {max(all_dates)}" if len(set(all_dates)) > 1 else min(all_dates)
        
        # Employee header with username
        writer.writerow([f"Employee: {user_display_name} - Shift Report ({date_range})"])
        writer.writerow([])  # Empty row
        
        # Process each session for this user
        for clock_in_iso, clock_out_iso, duration_seconds in sessions:
            # Parse timestamps
            clock_in_dt = datetime.fromisoformat(clock_in_iso)
            clock_out_dt = datetime.fromisoformat(clock_out_iso)
            
            # Format day and times
            day_of_week = clock_in_dt.strftime("%A")  # Full day name
            date_str = fmt(clock_in_dt, guild_tz).split()[0]
            in_time = fmt(clock_in_dt, guild_tz).split()[1:3]  # Time and timezone
            out_time = fmt(clock_out_dt, guild_tz).split()[1:3]
            
            # Duration in decimal hours
            total_hours = round(duration_seconds / 3600, 2)
            
            # Write shift details
            writer.writerow([f"{day_of_week} ({date_str}):"])
            writer.writerow([f"IN - {' '.join(in_time)}"])
            writer.writerow([f"OUT - {' '.join(out_time)}"])
            writer.writerow([f"{total_hours} total hours"])
            writer.writerow([])  # Empty row between shifts
        
        # Add separator between employees
        writer.writerow(["=" * 50])
        writer.writerow([])
    
    return output.getvalue()

async def generate_individual_csv_report(bot, user_id, sessions, guild_tz="America/New_York"):
    """Generate CSV for a single user."""
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Fetch Discord user to get username
    try:
        discord_user = await bot.fetch_user(user_id)
        user_display_name = discord_user.name
    except:
        user_display_name = f"User-{user_id}"  # Fallback if user not found
    
    # Calculate date range for this user
    all_dates = []
    for clock_in_iso, _, _ in sessions:
        clock_in_dt = datetime.fromisoformat(clock_in_iso)
        date_formatted = fmt(clock_in_dt, guild_tz).split()[0]
        all_dates.append(date_formatted)
    
    date_range = f"{min(all_dates)} to {max(all_dates)}" if len(set(all_dates)) > 1 else min(all_dates)
    
    # Employee header with username
    writer.writerow([f"Employee: {user_display_name} - Shift Report ({date_range})"])
    writer.writerow([])  # Empty row
    
    # Process each session for this user
    for clock_in_iso, clock_out_iso, duration_seconds in sessions:
        # Parse timestamps
        clock_in_dt = datetime.fromisoformat(clock_in_iso)
        clock_out_dt = datetime.fromisoformat(clock_out_iso)
        
        # Format day and times
        day_of_week = clock_in_dt.strftime("%A")  # Full day name
        date_str = fmt(clock_in_dt, guild_tz).split()[0]
        in_time = fmt(clock_in_dt, guild_tz).split()[1:3]  # Time and timezone
        out_time = fmt(clock_out_dt, guild_tz).split()[1:3]
        
        # Duration in decimal hours
        total_hours = round(duration_seconds / 3600, 2)
        
        # Write shift details
        writer.writerow([f"{day_of_week} ({date_str}):"])
        writer.writerow([f"IN - {' '.join(in_time)}"])
        writer.writerow([f"OUT - {' '.join(out_time)}"])
        writer.writerow([f"{total_hours} total hours"])
        writer.writerow([])  # Empty row between shifts
    
    return output.getvalue(), user_display_name

# --- Time helpers ---
def now_utc():
    return datetime.now(timezone.utc)

def fmt(dt: datetime, tz_name: Optional[str]) -> str:
    try:
        from zoneinfo import ZoneInfo
        tz = ZoneInfo(tz_name) if tz_name else ZoneInfo("America/New_York")
    except Exception:
        tz = timezone.utc
    return dt.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S %Z")

def human_duration(seconds: int) -> str:
    h = seconds // 3600
    m = (seconds % 3600) // 60
    s = seconds % 60
    parts = []
    if h: parts.append(f"{h}h")
    if m: parts.append(f"{m}m")
    if s or not parts: parts.append(f"{s}s")
    return " ".join(parts)

# --- Discord bot ---
intents = discord.Intents.default()
bot = commands.Bot(command_prefix="!", intents=intents)
tree = bot.tree

class TimeClockView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)  # persistent view

    @discord.ui.button(label="Clock In", style=discord.ButtonStyle.success, custom_id="timeclock:in")
    async def clock_in(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.guild is None:
            await interaction.response.send_message("Use this in a server.", ephemeral=True)
            return
        guild_id = interaction.guild.id
        user_id = interaction.user.id
        if get_active_session(guild_id, user_id):
            await interaction.response.send_message("You're already clocked in.", ephemeral=True)
            return
        start_session(guild_id, user_id, now_utc().isoformat())
        await interaction.response.send_message("✅ Clocked in. Have a great shift!", ephemeral=True)

    @discord.ui.button(label="Clock Out", style=discord.ButtonStyle.danger, custom_id="timeclock:out")
    async def clock_out(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.guild is None:
            await interaction.response.send_message("Use this in a server.", ephemeral=True)
            return
        guild_id = interaction.guild.id
        user_id = interaction.user.id
        active = get_active_session(guild_id, user_id)
        if not active:
            await interaction.response.send_message("You don't have an active session.", ephemeral=True)
            return

        session_id, clock_in_iso = active
        start_dt = datetime.fromisoformat(clock_in_iso)
        end_dt = now_utc()
        elapsed = int((end_dt - start_dt).total_seconds())
        close_session(session_id, end_dt.isoformat(), elapsed)

        tz_name = get_guild_setting(guild_id, "timezone", DEFAULT_TZ)
        await interaction.response.send_message(
            f"🔚 Clocked out.\n**In:** {fmt(start_dt, tz_name)}\n**Out:** {fmt(end_dt, tz_name)}\n**Total:** {human_duration(elapsed)}",
            ephemeral=True
        )

        # DM the designated manager
        recipient_id = get_guild_setting(guild_id, "recipient_user_id")
        if recipient_id:
            try:
                manager = await bot.fetch_user(recipient_id)
                embed = discord.Embed(
                    title="Timeclock Entry",
                    description=f"**Employee:** {interaction.user.mention} (`{interaction.user.id}`)",
                    color=discord.Color.blurple(),
                    timestamp=end_dt
                )
                embed.add_field(name="Clock In", value=fmt(start_dt, tz_name), inline=True)
                embed.add_field(name="Clock Out", value=fmt(end_dt, tz_name), inline=True)
                embed.add_field(name="Total", value=human_duration(elapsed), inline=False)
                embed.set_footer(text=f"Guild: {interaction.guild.name} • ID: {guild_id}")
                await manager.send(embed=embed)
            except discord.Forbidden:
                try:
                    await interaction.followup.send(
                        "⚠️ Could not DM the designated manager (their DMs may be off).",
                        ephemeral=True
                    )
                except Exception:
                    pass

    @discord.ui.button(label="Info", style=discord.ButtonStyle.primary, custom_id="timeclock:info")
    async def show_info(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.guild is None:
            await interaction.response.send_message("Use this in a server.", ephemeral=True)
            return
        
        guild_id = interaction.guild.id
        user_id = interaction.user.id
        
        # Check if user has authorized role
        if not user_has_authorized_role(guild_id, interaction.user.roles):
            await interaction.response.send_message("❌ You don't have permission to view time info.", ephemeral=True)
            return
        
        tz_name = get_guild_setting(guild_id, "timezone", DEFAULT_TZ)
        current_session_seconds, daily_seconds, weekly_seconds = get_user_hours_info(guild_id, user_id, tz_name)
        
        embed = discord.Embed(
            title="⏰ Your Time Information",
            color=discord.Color.blue()
        )
        
        if current_session_seconds > 0:
            embed.add_field(
                name="Current Session", 
                value=human_duration(current_session_seconds), 
                inline=True
            )
        else:
            embed.add_field(
                name="Current Session", 
                value="Not clocked in", 
                inline=True
            )
        
        embed.add_field(
            name="Today's Total", 
            value=human_duration(daily_seconds), 
            inline=True
        )
        embed.add_field(
            name="This Week's Total", 
            value=human_duration(weekly_seconds), 
            inline=True
        )
        
        await interaction.response.send_message(embed=embed, ephemeral=True)

    @discord.ui.button(label="Reports", style=discord.ButtonStyle.success, custom_id="timeclock:reports")
    async def generate_reports(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.guild is None:
            await interaction.response.send_message("Use this in a server.", ephemeral=True)
            return
        
        # Check if user has administrator permissions
        if not interaction.user.guild_permissions.administrator:
            await interaction.response.send_message("❌ You need administrator permissions to generate reports.", ephemeral=True)
            return
        
        await interaction.response.defer(ephemeral=True)
        
        guild_id = interaction.guild.id
        guild_tz_name = get_guild_setting(guild_id, "timezone", DEFAULT_TZ)
        
        # Generate report for last 30 days automatically
        from zoneinfo import ZoneInfo
        from datetime import timedelta
        try:
            guild_tz = ZoneInfo(guild_tz_name)
        except Exception:
            guild_tz = timezone.utc
            guild_tz_name = "UTC"
        
        # Calculate date range (last 30 days)
        end_date = datetime.now(guild_tz)
        start_date = end_date - timedelta(days=30)
        
        start_boundary = datetime.combine(start_date.date(), datetime.min.time()).replace(tzinfo=guild_tz)
        end_boundary = datetime.combine(end_date.date(), datetime.max.time()).replace(tzinfo=guild_tz)
        
        start_utc = start_boundary.astimezone(timezone.utc).isoformat()
        end_utc = end_boundary.astimezone(timezone.utc).isoformat()
        
        # Get all user sessions
        sessions_data = get_sessions_report(guild_id, None, start_utc, end_utc)
        
        if not sessions_data:
            await interaction.followup.send(
                "📭 No completed timesheet entries found for the last 30 days",
                ephemeral=True
            )
            return
        
        # Group sessions by user
        user_sessions = {}
        for user_id, clock_in_iso, clock_out_iso, duration_seconds in sessions_data:
            if user_id not in user_sessions:
                user_sessions[user_id] = []
            user_sessions[user_id].append((clock_in_iso, clock_out_iso, duration_seconds))
        
        # Generate separate CSV files for each user
        files = []
        total_users = len(user_sessions)
        total_entries = len(sessions_data)
        
        for user_id, sessions in user_sessions.items():
            csv_content, user_display_name = await generate_individual_csv_report(bot, user_id, sessions, guild_tz_name)
            
            start_date_str = start_date.strftime("%Y-%m-%d")
            end_date_str = end_date.strftime("%Y-%m-%d")
            filename = f"timesheet_report_{start_date_str}_to_{end_date_str}_{user_display_name}.csv"
            
            file = discord.File(
                io.BytesIO(csv_content.encode('utf-8')), 
                filename=filename
            )
            files.append(file)
        
        # Send all files
        await interaction.followup.send(
            f"📊 Generated individual timesheet reports for **{total_users} users**\n"
            f"📅 **Period:** Last 30 days ({start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')})\n"
            f"📝 **Total Entries:** {total_entries} completed shifts\n"
            f"🕐 **Timezone:** {guild_tz_name}\n\n"
            f"📁 **Files:** One CSV per employee",
            files=files,
            ephemeral=True
        )

@bot.event
async def on_ready():
    bot.add_view(TimeClockView())  # keep buttons alive across restarts
    
    # Debug: Check what commands are in the tree
    commands = tree.get_commands()
    print(f"📋 Commands in tree: {len(commands)}")
    for cmd in commands:
        print(f"   - {cmd.name}: {cmd.description}")
    
    # Try syncing commands with better error handling
    synced_count = 0
    sync_location = "nowhere"
    
    try:
        if GUILD_ID:
            # Try guild-specific sync first
            try:
                guild_obj = discord.Object(id=int(GUILD_ID))
                synced = await tree.sync(guild=guild_obj)
                synced_count = len(synced)
                sync_location = f"guild {GUILD_ID}"
                print(f"✅ Synced {synced_count} commands to guild {GUILD_ID}")
                
                # If guild sync fails, try global
                if synced_count == 0:
                    print("🔄 Guild sync returned 0 commands, trying global sync...")
                    synced = await tree.sync()
                    synced_count = len(synced)
                    sync_location = "globally (after guild failed)"
                    print(f"✅ Global sync: {synced_count} commands")
                    
            except Exception as guild_error:
                print(f"❌ Guild sync failed: {guild_error}")
                print("🔄 Trying global sync as fallback...")
                # Fallback to global sync
                synced = await tree.sync()
                synced_count = len(synced)
                sync_location = "globally"
                print(f"✅ Synced {synced_count} commands globally (fallback)")
        else:
            # No guild ID provided, sync globally
            synced = await tree.sync()
            synced_count = len(synced)
            sync_location = "globally"
            print(f"✅ Synced {synced_count} global commands")
            
    except Exception as e:
        print(f"❌ All command sync attempts failed: {e}")
        synced_count = 0
    
    print(f"🎯 Final result: {synced_count} commands synced {sync_location}")
    print(f"🤖 Logged in as {bot.user} ({bot.user.id})")

@tree.command(name="setup_timeclock", description="Post a persistent Clock In/Clock Out message")
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def setup_timeclock(interaction: discord.Interaction, channel: Optional[discord.TextChannel] = None):
    ch = channel or interaction.channel
    if ch is None:
        await interaction.response.send_message("No channel resolved.", ephemeral=True)
        return
    view = TimeClockView()
    msg = await ch.send("**Time Clock** — Click a button to record your time.\n(Only you see confirmations.)", view=view)
    set_guild_setting(interaction.guild_id, "button_channel_id", ch.id)
    set_guild_setting(interaction.guild_id, "button_message_id", msg.id)
    await interaction.response.send_message(f"✅ Posted timeclock in {ch.mention}.", ephemeral=True)

@tree.command(name="set_recipient", description="Set who receives private time entries (DMs)")
@app_commands.describe(user="Manager/admin who should receive time entries via DM")
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def set_recipient(interaction: discord.Interaction, user: discord.User):
    set_guild_setting(interaction.guild_id, "recipient_user_id", user.id)
    await interaction.response.send_message(f"✅ Set recipient to {user.mention}.", ephemeral=True)

@tree.command(name="set_timezone", description="Set display timezone (e.g., America/New_York)")
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def set_timezone(interaction: discord.Interaction, tz: str):
    set_guild_setting(interaction.guild_id, "timezone", tz)
    await interaction.response.send_message(f"✅ Timezone set to `{tz}` (display only).", ephemeral=True)

@tree.command(name="add_info_role", description="Add a role that can use the Info button")
@app_commands.describe(role="Role to authorize for Info button access")
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def add_info_role(interaction: discord.Interaction, role: discord.Role):
    add_authorized_role(interaction.guild_id, role.id)
    await interaction.response.send_message(f"✅ Added {role.mention} to authorized roles for Info button access.", ephemeral=True)

@tree.command(name="remove_info_role", description="Remove a role's access to the Info button")
@app_commands.describe(role="Role to remove from Info button access")
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def remove_info_role(interaction: discord.Interaction, role: discord.Role):
    remove_authorized_role(interaction.guild_id, role.id)
    await interaction.response.send_message(f"✅ Removed {role.mention} from authorized roles for Info button access.", ephemeral=True)

@tree.command(name="list_info_roles", description="List all roles authorized for Info button access")
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def list_info_roles(interaction: discord.Interaction):
    authorized_role_ids = get_authorized_roles(interaction.guild_id)
    
    if not authorized_role_ids:
        await interaction.response.send_message("ℹ️ No roles are currently authorized for Info button access.", ephemeral=True)
        return
    
    role_mentions = []
    for role_id in authorized_role_ids:
        role = interaction.guild.get_role(role_id)
        if role:
            role_mentions.append(role.mention)
        else:
            role_mentions.append(f"<Deleted Role ID: {role_id}>")
    
    embed = discord.Embed(
        title="🔑 Authorized Roles for Info Button",
        description="\n".join(role_mentions),
        color=discord.Color.blue()
    )
    
    await interaction.response.send_message(embed=embed, ephemeral=True)

@tree.command(name="help", description="List all available slash commands")
@app_commands.guild_only()
async def help_command(interaction: discord.Interaction):
    embed = discord.Embed(
        title="🤖 Bot Commands Help",
        description="Here are all the available slash commands:",
        color=discord.Color.green()
    )
    
    # General Commands
    embed.add_field(
        name="📋 General Commands",
        value=(
            "`/help` - Show this help message\n"
            "`/report <user> <start_date> <end_date>` - Generate timesheet report for a user"
        ),
        inline=False
    )
    
    # Admin Commands
    embed.add_field(
        name="⚙️ Administrator Commands",
        value=(
            "`/setup_timeclock [channel]` - Post the time clock buttons\n"
            "`/set_recipient <user>` - Set who gets DM notifications\n"
            "`/set_timezone <timezone>` - Set display timezone (e.g., America/New_York)"
        ),
        inline=False
    )
    
    # Role Management Commands
    embed.add_field(
        name="🔑 Role Management Commands",
        value=(
            "`/add_info_role <role>` - Allow a role to use the Info button\n"
            "`/remove_info_role <role>` - Remove Info button access from a role\n"
            "`/list_info_roles` - Show all roles with Info button access"
        ),
        inline=False
    )
    
    # Button Information
    embed.add_field(
        name="🔘 Time Clock Buttons",
        value=(
            "🟢 **Clock In** - Start tracking your time\n"
            "🔴 **Clock Out** - Stop tracking and log your shift\n"
            "🔵 **Info** - View your hours (requires authorized role)\n"
            "🟢 **Reports** - Generate all user reports (admin only)"
        ),
        inline=False
    )
    
    embed.set_footer(text="💡 Tip: Use the time clock buttons for quick access to common features!")
    
    await interaction.response.send_message(embed=embed, ephemeral=True)

@tree.command(name="report", description="Generate CSV timesheet report for individual user")
@app_commands.describe(
    user="Select user to generate report for",
    start_date="Start date (YYYY-MM-DD format)",
    end_date="End date (YYYY-MM-DD format)"
)
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def generate_report(
    interaction: discord.Interaction, 
    user: discord.Member,
    start_date: str,
    end_date: str
):
    await interaction.response.defer(ephemeral=True)
    
    try:
        # Validate date format and order
        start_dt = datetime.strptime(start_date, "%Y-%m-%d")
        end_dt = datetime.strptime(end_date, "%Y-%m-%d")
        
        if start_dt > end_dt:
            await interaction.followup.send(
                "❌ Start date must be before or equal to end date", 
                ephemeral=True
            )
            return
            
    except ValueError:
        await interaction.followup.send(
            "❌ Invalid date format. Please use YYYY-MM-DD (e.g., 2024-01-15)", 
            ephemeral=True
        )
        return
    
    # Get guild timezone
    guild_tz_name = get_guild_setting(interaction.guild_id, "timezone", DEFAULT_TZ)
    
    # Convert date range to UTC boundaries for proper filtering
    try:
        from zoneinfo import ZoneInfo
        guild_tz = ZoneInfo(guild_tz_name)
    except Exception:
        guild_tz = timezone.utc
        guild_tz_name = "UTC"  # Use actual UTC if timezone is invalid
    
    # Create start and end boundaries in guild timezone, then convert to UTC
    start_boundary = datetime.combine(start_dt.date(), datetime.min.time()).replace(tzinfo=guild_tz)
    end_boundary = datetime.combine(end_dt.date(), datetime.max.time()).replace(tzinfo=guild_tz)
    
    start_utc = start_boundary.astimezone(timezone.utc).isoformat()
    end_utc = end_boundary.astimezone(timezone.utc).isoformat()
    
    # Generate report for specific user
    user_id = user.id
    sessions_data = get_sessions_report(interaction.guild_id, user_id, start_utc, end_utc)
    
    if not sessions_data:
        await interaction.followup.send(
            f"📭 No completed timesheet entries found for **{user.name}** between {start_date} and {end_date}",
            ephemeral=True
        )
        return
    
    # Generate single CSV
    csv_content = await generate_csv_report(bot, sessions_data, guild_tz_name)
    
    # Create file using Discord username (not display name)
    filename = f"timesheet_report_{start_date}_to_{end_date}_{user.name}.csv"
    
    file = discord.File(
        io.BytesIO(csv_content.encode('utf-8')), 
        filename=filename
    )
    
    # Send file
    total_entries = len(sessions_data)
    
    await interaction.followup.send(
        f"📊 Generated timesheet report for **{user.name}**\n"
        f"📅 **Period:** {start_date} to {end_date}\n"
        f"📝 **Entries:** {total_entries} completed shifts\n"
        f"🕐 **Timezone:** {guild_tz_name}",
        file=file,
        ephemeral=True
    )

if __name__ == "__main__":
    init_db()
    if not TOKEN:
        raise SystemExit("Set DISCORD_TOKEN in your environment.")
    
    # Start health check server in a separate thread
    health_thread = threading.Thread(target=start_health_server, daemon=True)
    health_thread.start()
    print(f"✅ Health check server thread started")
    
    # Start Discord bot (this will block)
    print(f"🤖 Starting Discord bot...")
    bot.run(TOKEN)
