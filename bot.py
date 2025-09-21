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
DEFAULT_TZ = "UTC"
HTTP_PORT = int(os.getenv("PORT", "5000"))     # Health check server port

# --- Health Check HTTP Server ---
class HealthCheckHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/" or self.path == "/health":
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
            self.send_header('Content-type', 'application/json')
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()
    
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
            timezone TEXT DEFAULT 'UTC'
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
    with db() as conn:
        cur = conn.execute(f"SELECT {key} FROM guild_settings WHERE guild_id=?", (guild_id,))
        row = cur.fetchone()
        return row[0] if row and row[0] is not None else default

def set_guild_setting(guild_id: int, key: str, value):
    with db() as conn:
        conn.execute("INSERT OR IGNORE INTO guild_settings(guild_id) VALUES (?)", (guild_id,))
        conn.execute(f"UPDATE guild_settings SET {key}=? WHERE guild_id=?", (value, guild_id))

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

async def generate_csv_report(bot, sessions_data, guild_tz="UTC"):
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
        # Fetch Discord user to get display name
        try:
            discord_user = await bot.fetch_user(user_id)
            user_display_name = discord_user.display_name or discord_user.name
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

async def generate_individual_csv_report(bot, user_id, sessions, guild_tz="UTC"):
    """Generate CSV for a single user."""
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Fetch Discord user to get display name
    try:
        discord_user = await bot.fetch_user(user_id)
        user_display_name = discord_user.display_name or discord_user.name
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
        tz = ZoneInfo(tz_name) if tz_name else ZoneInfo("UTC")
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

@tree.command(name="report", description="Generate CSV timesheet reports")
@app_commands.describe(
    report_type="Select report type",
    start_date="Start date (YYYY-MM-DD format)",
    end_date="End date (YYYY-MM-DD format)",
    user="User to generate report for (required when report_type is 'user')"
)
@app_commands.choices(report_type=[
    app_commands.Choice(name="Individual User Report", value="user"),
    app_commands.Choice(name="All Users (Separate Files)", value="all")
])
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def generate_report(
    interaction: discord.Interaction, 
    report_type: app_commands.Choice[str],
    start_date: str,
    end_date: str,
    user: Optional[discord.User] = None
):
    await interaction.response.defer(ephemeral=True)
    
    # Validate user parameter based on report type
    if report_type.value == "user" and user is None:
        await interaction.followup.send(
            "❌ You must specify a user when generating an individual user report", 
            ephemeral=True
        )
        return
    
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
    
    if report_type.value == "user":
        # Generate report for specific user
        user_id = user.id
        sessions_data = get_sessions_report(interaction.guild_id, user_id, start_utc, end_utc)
        
        if not sessions_data:
            await interaction.followup.send(
                f"📭 No completed timesheet entries found for {user.mention} between {start_date} and {end_date}",
                ephemeral=True
            )
            return
        
        # Generate single CSV
        csv_content = await generate_csv_report(bot, sessions_data, guild_tz_name)
        
        # Create file
        filename = f"timesheet_report_{start_date}_to_{end_date}_{user.display_name}.csv"
        
        file = discord.File(
            io.BytesIO(csv_content.encode('utf-8')), 
            filename=filename
        )
        
        # Send file
        total_entries = len(sessions_data)
        
        await interaction.followup.send(
            f"📊 Generated timesheet report for **{user.display_name}**\n"
            f"📅 **Period:** {start_date} to {end_date}\n"
            f"📝 **Entries:** {total_entries} completed shifts\n"
            f"🕐 **Timezone:** {guild_tz_name}",
            file=file,
            ephemeral=True
        )
        
    else:  # report_type.value == "all"
        # Generate separate reports for all users
        sessions_data = get_sessions_report(interaction.guild_id, None, start_utc, end_utc)
        
        if not sessions_data:
            await interaction.followup.send(
                f"📭 No completed timesheet entries found for any users between {start_date} and {end_date}",
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
            
            # Create file for this user
            filename = f"timesheet_report_{start_date}_to_{end_date}_{user_display_name}.csv"
            
            file = discord.File(
                io.BytesIO(csv_content.encode('utf-8')), 
                filename=filename
            )
            files.append(file)
        
        # Send all files
        await interaction.followup.send(
            f"📊 Generated individual timesheet reports for **{total_users} users**\n"
            f"📅 **Period:** {start_date} to {end_date}\n"
            f"📝 **Total Entries:** {total_entries} completed shifts\n"
            f"🕐 **Timezone:** {guild_tz_name}\n\n"
            f"📁 **Files:** One CSV per employee",
            files=files,
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
