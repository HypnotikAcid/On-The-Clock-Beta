import asyncio
import logging
import psycopg2
import psycopg2.pool
from psycopg2.extras import RealDictCursor
import os
from datetime import datetime, timezone, timedelta
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
import pytz
from contextlib import contextmanager

from email_utils import send_timeclock_report_email, process_outbox_emails
from entitlements import Entitlements, UserTier

# PostgreSQL connection pool
DATABASE_URL = os.getenv("DATABASE_URL")
db_pool = None

# Discord bot reference (set by start_scheduler)
discord_bot = None

# Track guilds that have been warned in the current 24h cycle to prevent spam
# Format: {guild_id: last_warning_timestamp}
predeletion_warning_tracker: dict[int, float] = {}

# Track guilds that have received email warnings to prevent hourly spam
# Format: {guild_id: last_email_warning_timestamp}
email_warning_tracker: dict[int, float] = {}

def init_db_pool():
    """Initialize PostgreSQL connection pool"""
    global db_pool
    if db_pool is None and DATABASE_URL:
        db_pool = psycopg2.pool.ThreadedConnectionPool(
            minconn=1,
            maxconn=5,
            dsn=DATABASE_URL,
            cursor_factory=RealDictCursor
        )
    return db_pool is not None

@contextmanager
def db():
    """Context manager for database operations with connection pool and cursor"""
    if db_pool is None:
        init_db_pool()
    
    conn = db_pool.getconn()
    cursor = conn.cursor()
    try:
        yield cursor
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise
    finally:
        cursor.close()
        db_pool.putconn(conn)

def get_guild_tier_for_scheduler(guild_id: int) -> UserTier:
    """
    Get guild tier using Entitlements.get_guild_tier().
    This is the standardized way to check tier per CLAUDE.md rules.
    Returns: UserTier enum (FREE, GRANDFATHERED, PREMIUM, PRO)
    """
    with db() as cursor:
        cursor.execute(
            """SELECT bot_access_paid, retention_tier,
                      COALESCE(grandfathered, FALSE) as grandfathered
               FROM server_subscriptions WHERE guild_id = %s""",
            (guild_id,)
        )
        row = cursor.fetchone()
        if not row:
            return UserTier.FREE

        bot_access_paid = bool(row.get('bot_access_paid', False))
        retention_tier = row.get('retention_tier') or 'none'
        grandfathered = bool(row.get('grandfathered', False))

        return Entitlements.get_guild_tier(bot_access_paid, retention_tier, grandfathered)

logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler()

async def send_work_day_end_reports():
    """Send automated work day end reports to all guilds with email recipients configured.
    
    Uses LEFT JOIN to include guilds without explicit email_settings row,
    and defaults to midnight (23:59) if no work_day_end_time is set.
    """
    logger.info("🕐 Running scheduled work day end reports...")
    
    with db() as cursor:
        cursor.execute("""
            SELECT 
                rr.guild_id,
                COALESCE(gs.work_day_end_time, '23:59') as work_day_end_time,
                COALESCE(gs.timezone, 'America/New_York') as timezone,
                COALESCE(es.auto_send_on_clockout, TRUE) as auto_send_on_clockout
            FROM (SELECT DISTINCT guild_id FROM report_recipients WHERE recipient_type = 'email') rr
            LEFT JOIN guild_settings gs ON rr.guild_id = gs.guild_id
            LEFT JOIN email_settings es ON rr.guild_id = es.guild_id
        """)
        guilds_with_recipients = cursor.fetchall()
    
    current_time = datetime.now(timezone.utc)
    processed_count = 0
    skipped_count = 0
    
    for row in guilds_with_recipients:
        guild_id = row['guild_id']
        work_day_end_time = row['work_day_end_time']
        tz_name = row['timezone']
        auto_send = row['auto_send_on_clockout']
        
        try:
            if not auto_send:
                logger.debug(f"   Guild {guild_id}: skipped (auto_send_on_clockout disabled)")
                skipped_count += 1
                continue

            tier = get_guild_tier_for_scheduler(guild_id)
            if tier == UserTier.FREE:
                logger.debug(f"   Guild {guild_id}: skipped (free tier - no reports)")
                skipped_count += 1
                continue
            
            guild_tz = pytz.timezone(tz_name or 'America/New_York')
            current_local = current_time.astimezone(guild_tz)
            
            config_hour, config_minute = map(int, work_day_end_time.split(':'))
            
            if current_local.hour == config_hour and current_local.minute == config_minute:
                logger.info(f"   Guild {guild_id}: sending daily report (time match {work_day_end_time})")
                await send_daily_report_for_guild(guild_id)
                processed_count += 1
                
        except Exception as e:
            logger.error(f"Error processing work day end report for guild {guild_id}: {e}")
    
    if processed_count > 0 or skipped_count > 0:
        logger.info(f"🕐 Work day reports: {processed_count} sent, {skipped_count} skipped")

async def send_daily_report_for_guild(guild_id: int):
    """Generate and send daily report for a specific guild"""
    try:
        with db() as cursor:
            cursor.execute(
                "SELECT guild_name FROM bot_guilds WHERE guild_id = %s",
                (str(guild_id),)
            )
            guild_row = cursor.fetchone()
            guild_name = guild_row['guild_name'] if guild_row else f"Guild {guild_id}"
            
            cursor.execute(
                "SELECT timezone FROM guild_settings WHERE guild_id = %s",
                (guild_id,)
            )
            tz_row = cursor.fetchone()
            tz_name = tz_row['timezone'] if tz_row else 'America/New_York'
            
            guild_tz = pytz.timezone(tz_name)
            now_local = datetime.now(timezone.utc).astimezone(guild_tz)
            
            start_of_day = now_local.replace(hour=0, minute=0, second=0, microsecond=0)
            end_of_day = now_local.replace(hour=23, minute=59, second=59, microsecond=999999)
            
            start_utc = start_of_day.astimezone(timezone.utc).isoformat()
            end_utc = end_of_day.astimezone(timezone.utc).isoformat()
            
            cursor.execute("""
                SELECT ts.user_id, ts.clock_in_time as clock_in, ts.clock_out_time as clock_out,
                       EXTRACT(EPOCH FROM (ts.clock_out_time - ts.clock_in_time))::integer as duration_seconds,
                       COALESCE(ep.display_name, ep.full_name) as display_name
                FROM timeclock_sessions ts
                LEFT JOIN employee_profiles ep ON ts.guild_id::text = ep.guild_id AND ts.user_id = ep.user_id
                WHERE ts.guild_id = %s 
                AND ts.clock_out_time IS NOT NULL
                AND ts.clock_in_time >= %s
                AND ts.clock_out_time <= %s
                ORDER BY ts.user_id, ts.clock_in_time
            """, (guild_id, start_utc, end_utc))
            
            sessions = cursor.fetchall()
            
            if not sessions:
                logger.info(f"No sessions to report for guild {guild_id} today")
                return
            
            csv_lines = ["User ID,Display Name,Clock In,Clock Out,Duration (hours)"]
            for row in sessions:
                user_id = row['user_id']
                display_name = row['display_name']
                
                if not display_name and discord_bot:
                    try:
                        discord_user = await discord_bot.fetch_user(int(user_id))
                        display_name = discord_user.display_name or discord_user.name
                    except Exception:
                        display_name = f"User {user_id}"
                elif not display_name:
                    display_name = f"User {user_id}"
                
                display_name = display_name.replace(',', ' ')
                clock_in = row['clock_in']
                clock_out = row['clock_out']
                duration_seconds = row['duration_seconds']
                duration_hours = round(duration_seconds / 3600, 2)
                csv_lines.append(f"{user_id},{display_name},{clock_in},{clock_out},{duration_hours}")
            
            csv_content = "\n".join(csv_lines)
            
            cursor.execute(
                "SELECT email_address FROM report_recipients WHERE guild_id = %s AND recipient_type = 'email'",
                (guild_id,)
            )
            recipients = [row['email_address'] for row in cursor.fetchall()]
            
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
    global email_warning_tracker
    
    logger.info("⚠️ Running deletion warning check...")
    
    current_time = datetime.now(timezone.utc)
    
    with db() as cursor:
        cursor.execute("""
            SELECT 
                gs.guild_id,
                es.auto_email_before_delete
            FROM guild_settings gs
            JOIN email_settings es ON gs.guild_id = es.guild_id
            LEFT JOIN server_subscriptions ss ON gs.guild_id = ss.guild_id
            WHERE es.auto_email_before_delete = TRUE
              AND (ss.bot_access_paid = FALSE OR ss.bot_access_paid IS NULL)
              AND (ss.status != 'active' OR ss.status IS NULL)
        """)
        guilds_with_warnings = cursor.fetchall()
    
    sent_count = 0
    skipped_count = 0
    
    for row in guilds_with_warnings:
        guild_id = row['guild_id']
        try:
            # Check if we already warned this guild recently (within 20 hours)
            last_warning = email_warning_tracker.get(guild_id)
            if last_warning:
                hours_since_warning = (current_time - last_warning).total_seconds() / 3600
                if hours_since_warning < 20:
                    skipped_count += 1
                    continue

            tier = get_guild_tier_for_scheduler(guild_id)
            days_to_keep = Entitlements.get_retention_days(tier)
            
            cutoff_time = datetime.now(timezone.utc) - timedelta(days=days_to_keep)
            warning_time = cutoff_time + timedelta(hours=1)
            
            with db() as cursor:
                cursor.execute("""
                    SELECT COUNT(*) as count FROM timeclock_sessions
                    WHERE guild_id = %s
                    AND clock_out_time IS NOT NULL
                    AND clock_out_time < %s
                    AND clock_out_time >= %s
                """, (guild_id, warning_time.isoformat(), cutoff_time.isoformat()))
                
                count = cursor.fetchone()['count']
                
                if count > 0:
                    await send_deletion_warning_email(guild_id, count, days_to_keep)
                    email_warning_tracker[guild_id] = current_time
                    sent_count += 1
                    
        except Exception as e:
            logger.error(f"Error checking deletion warnings for guild {guild_id}: {e}")
    
    # Clean up old tracker entries (older than 24 hours)
    old_entries = [gid for gid, ts in email_warning_tracker.items() 
                   if (current_time - ts).total_seconds() / 3600 > 24]
    for gid in old_entries:
        del email_warning_tracker[gid]
    
    if sent_count > 0 or skipped_count > 0:
        logger.info(f"⚠️ Deletion email warnings: {sent_count} sent, {skipped_count} skipped (already warned)")

async def send_deletion_warning_email(guild_id: int, session_count: int, days_to_keep: int):
    """Send warning email about upcoming data deletion"""
    logger.info(f"📧 DELETION WARNING EMAIL - Starting for guild {guild_id}")
    try:
        with db() as cursor:
            cursor.execute(
                "SELECT guild_name FROM bot_guilds WHERE guild_id = %s",
                (str(guild_id),)
            )
            guild_row = cursor.fetchone()
            guild_name = guild_row['guild_name'] if guild_row else f"Guild {guild_id}"
            logger.info(f"   Guild name: {guild_name}")
            
            # Log the exact query being used
            logger.info(f"   Querying recipients for guild_id={guild_id} (type: {type(guild_id).__name__})")
            cursor.execute(
                "SELECT email_address FROM report_recipients WHERE guild_id = %s AND recipient_type = 'email'",
                (guild_id,)
            )
            raw_results = cursor.fetchall()
            recipients = [row['email_address'] for row in raw_results]
            
            # Log exactly what was found
            logger.info(f"   Database query returned {len(raw_results)} rows")
            logger.info(f"   Recipients found: {recipients}")
            
            if not recipients:
                logger.info(f"   No recipients configured - skipping email for guild {guild_id}")
                return
            
            from email_utils import send_email, log_email_to_file
            
            # Log to persistent file with full context BEFORE sending
            log_email_to_file(
                event_type="deletion_warning_attempt",
                recipients=recipients,
                subject=f"⚠️ Data Deletion Warning - {guild_name}",
                context={
                    "guild_id": str(guild_id),
                    "guild_name": guild_name,
                    "session_count": session_count,
                    "days_to_keep": days_to_keep,
                    "source": "scheduler.send_deletion_warning_email"
                }
            )
            
            logger.info(f"   Sending deletion warning to: {recipients}")
            subject = f"⚠️ Data Deletion Warning - {guild_name}"
            
            text_content = f"""
Data Deletion Warning

Server: {guild_name}
Retention Period: {days_to_keep} days

{session_count} timeclock session(s) will be automatically deleted soon as they have exceeded your {days_to_keep}-day retention period.

To preserve this data:
- Generate reports now using the /report command
- Upgrade to Dashboard Premium ($5 one-time) for 7-day retention
- Add Pro Retention ($5/month) for 30-day retention

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


async def send_predeletion_dm_warnings():
    """Send DM warnings to free tier server owners before data deletion"""
    global predeletion_warning_tracker
    
    if discord_bot is None:
        logger.warning("⚠️ Discord bot not available for pre-deletion DM warnings")
        return
    
    logger.info("📧 Running pre-deletion DM warning check...")
    
    try:
        import discord
        
        current_time = datetime.now(timezone.utc)
        
        with db() as cursor:
            cursor.execute("""
                SELECT DISTINCT s.guild_id, bg.guild_name
                FROM timeclock_sessions s
                JOIN bot_guilds bg ON CAST(s.guild_id AS TEXT) = bg.guild_id
                LEFT JOIN server_subscriptions ss ON s.guild_id = ss.guild_id
                WHERE COALESCE(ss.tier, 'free') = 'free'
                AND s.clock_in_time < NOW() - INTERVAL '20 hours'
                AND s.clock_in_time > NOW() - INTERVAL '24 hours'
            """)
            guilds_to_warn = cursor.fetchall()
        
        warned_count = 0
        skipped_count = 0
        
        for row in guilds_to_warn:
            guild_id = row['guild_id']
            guild_name = row['guild_name']
            
            last_warning = predeletion_warning_tracker.get(guild_id)
            if last_warning:
                hours_since_warning = (current_time - last_warning).total_seconds() / 3600
                if hours_since_warning < 20:
                    skipped_count += 1
                    continue
            
            guild = discord_bot.get_guild(int(guild_id))
            if guild and guild.owner:
                try:
                    embed = discord.Embed(
                        title="⚠️ Data Deletion Warning",
                        description=f"Time entries for **{guild_name}** will be automatically deleted in ~4 hours.",
                        color=0xFFAA00
                    )
                    embed.add_field(
                        name="💎 Upgrade to Keep Your Data",
                        value="Get Dashboard Premium for **$5 one-time** (7-day retention) or add Pro Retention for **$5/month** (30-day)!",
                        inline=False
                    )
                    embed.add_field(
                        name="How to Upgrade",
                        value="Use `/upgrade` in your server or visit the dashboard.",
                        inline=False
                    )
                    embed.set_footer(text="On the Clock • Free tier has 24-hour data retention")
                    
                    await guild.owner.send(embed=embed)
                    
                    predeletion_warning_tracker[guild_id] = current_time
                    warned_count += 1
                    logger.info(f"📧 Sent pre-deletion warning to owner of {guild_name}")
                    
                except discord.Forbidden:
                    logger.info(f"   Could not DM owner of {guild_name} (DMs disabled)")
                except Exception as e:
                    logger.error(f"   Error sending warning to {guild_name}: {e}")
        
        old_entries = [gid for gid, ts in predeletion_warning_tracker.items() 
                       if (current_time - ts).total_seconds() / 3600 > 24]
        for gid in old_entries:
            del predeletion_warning_tracker[gid]
        
        if warned_count > 0 or skipped_count > 0:
            logger.info(f"📧 Pre-deletion warnings: {warned_count} sent, {skipped_count} skipped (already warned)")
            
    except Exception as e:
        logger.error(f"❌ Pre-deletion DM warning job failed: {e}")


async def process_email_outbox():
    """
    Process pending emails from the outbox.
    This runs every 30 seconds to pick up queued emails and send them with retry logic.
    """
    try:
        stats = await process_outbox_emails(batch_size=10)
        
        if stats['processed'] > 0:
            logger.info(
                f"📬 Email outbox processed: "
                f"{stats['sent']} sent, "
                f"{stats['retried']} scheduled for retry, "
                f"{stats['failed']} failed permanently"
            )
    except Exception as e:
        logger.error(f"❌ Email outbox processing failed: {e}")

async def reset_demo_data_job():
    """Job to reset demo server data by calling the internal seeding function."""
    logger.info("🔄 Running scheduled demo data reset...")
    try:
        from app import seed_demo_data_internal
        success = seed_demo_data_internal()
        if success:
            logger.info("✅ Demo data reset successfully")
        else:
            logger.error("❌ Demo data reset failed")
    except Exception as e:
        logger.error(f"❌ Error during demo data reset job: {e}")


def start_scheduler(bot=None):
    """Initialize and start the scheduler
    
    Args:
        bot: Discord bot instance (optional, needed for DM warnings)
    """
    global discord_bot
    discord_bot = bot
    
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
    
    scheduler.add_job(
        send_predeletion_dm_warnings,
        trigger=CronTrigger(hour='*'),
        id='predeletion_dm_warnings',
        name='Send pre-deletion DM warnings to free tier owners',
        replace_existing=True
    )
    
    scheduler.add_job(
        process_email_outbox,
        trigger=CronTrigger(second='*/30'),  # Every 30 seconds
        id='process_email_outbox',
        name='Process pending emails from outbox',
        replace_existing=True
    )
    
    # Scheduled job to reset demo server data every 24 hours
    scheduler.add_job(
        reset_demo_data_job,
        trigger=CronTrigger(hour=0, minute=0),  # Every day at midnight
        id='reset_demo_data',
        name='Auto-reset demo server data',
        replace_existing=True
    )
    
    scheduler.start()
    logger.info("✅ Email scheduler started successfully")
    logger.info("✅ Email outbox processor running every 30 seconds")
    if discord_bot:
        logger.info("✅ Pre-deletion DM warnings enabled (bot connected)")

def stop_scheduler():
    """Stop the scheduler"""
    scheduler.shutdown()
    logger.info("🛑 Email scheduler stopped")
