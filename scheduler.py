import asyncio
import logging
import sqlite3
import os
from datetime import datetime, timezone, timedelta
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
import pytz
from contextlib import contextmanager

from email_utils import send_timeclock_report_email

# Database connection
DB_PATH = os.getenv("TIMECLOCK_DB", "timeclock.db")

@contextmanager
def db():
    """Context manager for database operations"""
    conn = sqlite3.connect(DB_PATH, isolation_level=None, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
    finally:
        conn.close()

def get_retention_tier(guild_id: int) -> str:
    """Get the retention tier for a guild"""
    with db() as conn:
        cursor = conn.execute(
            "SELECT tier FROM server_subscriptions WHERE guild_id = ?",
            (guild_id,)
        )
        row = cursor.fetchone()
        return row[0] if row else 'free'

logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler()

async def send_work_day_end_reports():
    """Send automated work day end reports to all guilds with configured settings"""
    logger.info("🕐 Running scheduled work day end reports...")
    
    with db() as conn:
        cursor = conn.execute("""
            SELECT 
                gs.guild_id, 
                gs.work_day_end_time,
                gs.timezone,
                es.auto_send_on_clockout
            FROM guild_settings gs
            JOIN email_settings es ON gs.guild_id = es.guild_id
            WHERE gs.work_day_end_time IS NOT NULL
        """)
        guilds_with_settings = cursor.fetchall()
    
    current_time = datetime.now(timezone.utc)
    
    for guild_id, work_day_end_time, tz_name, auto_send in guilds_with_settings:
        if not work_day_end_time:
            continue
        
        try:
            retention_tier = get_retention_tier(guild_id)
            if retention_tier == 'free':
                logger.info(f"Skipping work day end report for free tier guild {guild_id}")
                continue
            
            guild_tz = pytz.timezone(tz_name or 'America/New_York')
            current_local = current_time.astimezone(guild_tz)
            
            config_hour, config_minute = map(int, work_day_end_time.split(':'))
            
            if current_local.hour == config_hour and current_local.minute == config_minute:
                await send_daily_report_for_guild(guild_id)
                
        except Exception as e:
            logger.error(f"Error processing work day end report for guild {guild_id}: {e}")

async def send_daily_report_for_guild(guild_id: int):
    """Generate and send daily report for a specific guild"""
    try:
        with db() as conn:
            cursor = conn.execute(
                "SELECT name FROM bot_guilds WHERE guild_id = ?",
                (str(guild_id),)
            )
            guild_row = cursor.fetchone()
            guild_name = guild_row[0] if guild_row else f"Guild {guild_id}"
            
            cursor = conn.execute(
                "SELECT timezone FROM guild_settings WHERE guild_id = ?",
                (guild_id,)
            )
            tz_row = cursor.fetchone()
            tz_name = tz_row[0] if tz_row else 'America/New_York'
            
            guild_tz = pytz.timezone(tz_name)
            now_local = datetime.now(timezone.utc).astimezone(guild_tz)
            
            start_of_day = now_local.replace(hour=0, minute=0, second=0, microsecond=0)
            end_of_day = now_local.replace(hour=23, minute=59, second=59, microsecond=999999)
            
            start_utc = start_of_day.astimezone(timezone.utc).isoformat()
            end_utc = end_of_day.astimezone(timezone.utc).isoformat()
            
            cursor = conn.execute("""
                SELECT user_id, clock_in, clock_out, duration_seconds
                FROM sessions
                WHERE guild_id = ? 
                AND clock_out IS NOT NULL
                AND clock_in >= ?
                AND clock_out <= ?
                ORDER BY user_id, clock_in
            """, (guild_id, start_utc, end_utc))
            
            sessions = cursor.fetchall()
            
            if not sessions:
                logger.info(f"No sessions to report for guild {guild_id} today")
                return
            
            csv_lines = ["User ID,Clock In,Clock Out,Duration (hours)"]
            for user_id, clock_in, clock_out, duration_seconds in sessions:
                duration_hours = round(duration_seconds / 3600, 2)
                csv_lines.append(f"{user_id},{clock_in},{clock_out},{duration_hours}")
            
            csv_content = "\n".join(csv_lines)
            
            cursor = conn.execute(
                "SELECT email_address FROM report_recipients WHERE guild_id = ? AND recipient_type = 'email'",
                (guild_id,)
            )
            recipients = [row[0] for row in cursor.fetchall()]
            
            if recipients:
                report_period = f"{start_of_day.strftime('%Y-%m-%d')}"
                await send_timeclock_report_email(
                    to=recipients,
                    guild_name=guild_name,
                    csv_content=csv_content,
                    report_period=report_period
                )
                logger.info(f"✅ Daily report sent for guild {guild_id} to {len(recipients)} recipients")
            
    except Exception as e:
        logger.error(f"Error sending daily report for guild {guild_id}: {e}")

async def send_deletion_warnings():
    """Send warning emails before data deletion based on retention tier"""
    logger.info("⚠️ Running deletion warning check...")
    
    with db() as conn:
        cursor = conn.execute("""
            SELECT 
                gs.guild_id,
                es.auto_email_before_delete
            FROM guild_settings gs
            JOIN email_settings es ON gs.guild_id = es.guild_id
            WHERE es.auto_email_before_delete = 1
        """)
        guilds_with_warnings = cursor.fetchall()
    
    for guild_id, _ in guilds_with_warnings:
        try:
            retention_tier = get_retention_tier(guild_id)
            
            days_to_keep = {
                'free': 1,
                'basic': 7,
                'pro': 30
            }.get(retention_tier, 1)
            
            cutoff_time = datetime.now(timezone.utc) - timedelta(days=days_to_keep)
            warning_time = cutoff_time + timedelta(hours=1)
            
            with db() as conn:
                cursor = conn.execute("""
                    SELECT COUNT(*) FROM sessions
                    WHERE guild_id = ?
                    AND clock_out IS NOT NULL
                    AND clock_out < ?
                    AND clock_out >= ?
                """, (guild_id, warning_time.isoformat(), cutoff_time.isoformat()))
                
                count = cursor.fetchone()[0]
                
                if count > 0:
                    await send_deletion_warning_email(guild_id, count, days_to_keep)
                    
        except Exception as e:
            logger.error(f"Error checking deletion warnings for guild {guild_id}: {e}")

async def send_deletion_warning_email(guild_id: int, session_count: int, days_to_keep: int):
    """Send warning email about upcoming data deletion"""
    try:
        with db() as conn:
            cursor = conn.execute(
                "SELECT name FROM bot_guilds WHERE guild_id = ?",
                (str(guild_id),)
            )
            guild_row = cursor.fetchone()
            guild_name = guild_row[0] if guild_row else f"Guild {guild_id}"
            
            cursor = conn.execute(
                "SELECT email_address FROM report_recipients WHERE guild_id = ? AND recipient_type = 'email'",
                (guild_id,)
            )
            recipients = [row[0] for row in cursor.fetchall()]
            
            if not recipients:
                return
            
            from email_utils import send_email
            
            subject = f"⚠️ Data Deletion Warning - {guild_name}"
            text_content = f"""
Data Deletion Warning

Server: {guild_name}
Retention Period: {days_to_keep} days

{session_count} timeclock session(s) will be automatically deleted soon as they have exceeded your {days_to_keep}-day retention period.

To preserve this data:
- Generate reports now using the /report command
- Upgrade to a higher tier for longer retention (Basic: 7 days, Pro: 30 days)

This is an automated reminder from On the Clock Discord Bot.
"""
            
            await send_email(
                to=recipients,
                subject=subject,
                text=text_content
            )
            
            logger.info(f"✅ Deletion warning sent for guild {guild_id} ({session_count} sessions)")
            
    except Exception as e:
        logger.error(f"Error sending deletion warning email for guild {guild_id}: {e}")

def start_scheduler():
    """Initialize and start the scheduler"""
    scheduler.add_job(
        send_work_day_end_reports,
        trigger=CronTrigger(minute='*'),
        id='work_day_end_reports',
        name='Send work day end reports',
        replace_existing=True
    )
    
    scheduler.add_job(
        send_deletion_warnings,
        trigger=CronTrigger(hour='*'),
        id='deletion_warnings',
        name='Send deletion warning emails',
        replace_existing=True
    )
    
    scheduler.start()
    logger.info("✅ Email scheduler started successfully")

def stop_scheduler():
    """Stop the scheduler"""
    scheduler.shutdown()
    logger.info("🛑 Email scheduler stopped")
