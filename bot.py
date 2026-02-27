import os
import psycopg2
import psycopg2.pool
from psycopg2.extras import RealDictCursor
from contextlib import contextmanager
import csv
import io
import zipfile
import json
import threading
import time
import asyncio
import secrets
import base64
import requests
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, List
from urllib.parse import parse_qs, urlparse, parse_qsl
import stripe
from stripe import StripeError, SignatureVerificationError

import discord
from discord import app_commands
from discord.ext import commands

# Import aiohttp for bot HTTP API server
from aiohttp import web
import hashlib
import hmac

# Import email functionality for report delivery
from email_utils import send_timeclock_report_email, queue_shift_report_email, process_outbox_emails
# Import migrations
from migrations import run_migrations
from scheduler import start_scheduler, stop_scheduler
# Import entitlements for tier checking
from entitlements import Entitlements, UserTier

# --- Config / Secrets ---
TOKEN = os.getenv("DISCORD_TOKEN")            # required
DATABASE_URL = os.getenv("DATABASE_URL")      # PostgreSQL connection string
GUILD_ID = os.getenv("GUILD_ID")              # optional but makes commands appear instantly (guild sync)
DEFAULT_TZ = "America/New_York"

# PostgreSQL connection pool for better performance
db_pool = None

# --- Bot Owner Configuration ---
BOT_OWNER_ID = int(os.getenv("BOT_OWNER_ID", "107103438139056128"))  # Discord user ID for super admin access

# --- Demo Server Configuration ---
DEMO_SERVER_ID = 1419894879894507661  # "On The Clock" demo server
DEMO_EMPLOYEE_ROLE_ID = 1465150374968033340  # "Demo Employee" role for auto-assignment
DEMO_ADMIN_ROLE_ID = 1465149753510596628  # "Demo Admin" role for simulating admin access

# --- Discord Application Configuration ---
DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID", "1418446753379913809")  # Discord application client ID

# --- Discord Data Caching ---
# Simple in-memory cache for Discord API data to reduce rate limiting
from typing import Any
DISCORD_CACHE: dict[str, dict[Any, Any]] = {
    "guild_roles": {},    # guild_id -> {timestamp, data}
    "guild_members": {},  # guild_id -> {timestamp, data}
}
CACHE_DURATION = 300  # 5 minutes cache duration

def get_cached_discord_data(cache_type: str, guild_id: int):
    """
    Get cached Discord data if still valid.
    Returns None if cache miss or expired.
    """
    cache = DISCORD_CACHE.get(cache_type, {})
    entry = cache.get(guild_id)
    
    if entry:
        timestamp = entry.get('timestamp', 0)
        if time.time() - timestamp < CACHE_DURATION:
            return entry.get('data')
    return None

def set_cached_discord_data(cache_type: str, guild_id: int, data):
    """
    Store Discord data in cache with current timestamp.
    """
    if cache_type not in DISCORD_CACHE:
        DISCORD_CACHE[cache_type] = {}
    
    DISCORD_CACHE[cache_type][guild_id] = {
        'timestamp': time.time(),
        'data': data
    }

# --- OAuth and Session Functions (for bot's HTTP server) ---
# Note: These duplicate some functionality from app.py but are needed
# for the bot's internal HTTP server to avoid circular imports

# DISCORD_CLIENT_ID already defined above with fallback
DISCORD_CLIENT_SECRET = os.environ.get('DISCORD_CLIENT_SECRET')
DISCORD_API_BASE = 'https://discord.com/api/v10'
DISCORD_OAUTH_SCOPES = 'identify guilds'
DISCORD_REDIRECT_URI = os.environ.get('DISCORD_REDIRECT_URI', '')

def create_oauth_session(state: str, ip_address: str, expiry_minutes: int = 15) -> bool:
    """
    Create OAuth state in database for CSRF protection.
    Returns True on success, False on failure.
    """
    try:
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=expiry_minutes)
        with db() as conn:
            conn.execute(
                "INSERT INTO oauth_states (state, expires_at) VALUES (%s, %s)",
                (state, expires_at.isoformat())
            )
        return True
    except Exception as e:
        print(f"Error creating OAuth session: {e}")
        return False

def get_discord_oauth_url(state: str) -> str:
    """
    Generate Discord OAuth2 authorization URL.
    """
    from urllib.parse import urlencode
    
    params = {
        'client_id': DISCORD_CLIENT_ID,
        'redirect_uri': DISCORD_REDIRECT_URI,
        'response_type': 'code',
        'scope': DISCORD_OAUTH_SCOPES,
        'state': state
    }
    
    return f'https://discord.com/oauth2/authorize?{urlencode(params)}'

def get_user_session(session_id: str) -> Optional[Dict]:
    """
    Get user session from database.
    Returns session dict or None if not found/expired.
    """
    try:
        with db() as conn:
            cursor = conn.execute("""
                SELECT session_id, user_id, username, discriminator, avatar, 
                       access_token, guilds_data, expires_at
                FROM user_sessions 
                WHERE session_id = %s AND expires_at > %s
            """, (session_id, datetime.now(timezone.utc).isoformat()))
            row = cursor.fetchone()
            
            if row:
                return {
                    'session_id': row['session_id'],
                    'user_id': row['user_id'],
                    'username': row['username'],
                    'discriminator': row['discriminator'] or '0',
                    'avatar': row['avatar'],
                    'access_token': row['access_token'],
                    'guilds': json.loads(row['guilds_data']) if row['guilds_data'] else [],
                    'expires_at': row['expires_at']
                }
    except Exception as e:
        print(f"Error getting user session: {e}")
    return None

def delete_user_session(session_id: str) -> bool:
    """
    Delete user session from database.
    Returns True on success.
    """
    try:
        with db() as conn:
            conn.execute("DELETE FROM user_sessions WHERE session_id = %s", (session_id,))
        return True
    except Exception as e:
        print(f"Error deleting user session: {e}")
        return False

def get_discord_guild_member(access_token: str, guild_id: int) -> Optional[Dict]:
    """
    Fetch guild member data from Discord API using OAuth token.
    Returns member data dict or None on failure.
    """
    try:
        headers = {'Authorization': f'Bearer {access_token}'}
        response = requests.get(
            f'{DISCORD_API_BASE}/users/@me/guilds/{guild_id}/member',
            headers=headers
        )
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 403:
            print(f"No permission to access member data for guild {guild_id}")
        else:
            print(f"Failed to fetch guild member: {response.status_code}")
    except Exception as e:
        print(f"Error fetching guild member: {e}")
    return None

# --- Rate Limiting / Spam Detection ---
# Track user interactions to prevent spam/abuse
RATE_LIMIT_WINDOW = 30  # 30 seconds
RATE_LIMIT_MAX_REQUESTS = 5  # Max 5 requests per window per button
user_interaction_timestamps: dict[tuple[int, int, str], list[float]] = {}  # {(guild_id, user_id, button_name): [timestamp1, timestamp2, ...]}

# --- Stripe Configuration ---
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")
STRIPE_PRICE_IDS = {
    'premium': os.getenv('STRIPE_PRICE_PREMIUM'),
    'pro': os.getenv('STRIPE_PRICE_PRO'),
}
STRIPE_PRICE_IDS_LEGACY = {
    'bot_access': os.getenv('STRIPE_PRICE_BOT_ACCESS'),
    'retention_7day': os.getenv('STRIPE_PRICE_RETENTION_7DAY'),
    'retention_30day': os.getenv('STRIPE_PRICE_RETENTION_30DAY'),
}

# Session storage - now using database for persistence instead of in-memory dictionaries

# Guild-based locks to prevent race conditions in setup operations
guild_setup_locks: Dict[int, asyncio.Lock] = {}

def get_guild_lock(guild_id: int) -> asyncio.Lock:
    """Get or create an asyncio lock for a specific guild"""
    if guild_id not in guild_setup_locks:
        guild_setup_locks[guild_id] = asyncio.Lock()
    return guild_setup_locks[guild_id]

# --- Proper Interaction Response Helper ---
async def robust_defer(interaction: discord.Interaction, ephemeral: bool = True) -> bool:
    """
    Robust interaction defer with proper error handling.
    
    Args:
        interaction: The Discord interaction to defer
        ephemeral: Whether the response should be ephemeral
    
    Returns:
        bool: True if defer was successful, False if interaction was already acknowledged
    """
    if interaction.response.is_done():
        print(f"⚠️ Interaction already acknowledged for guild {interaction.guild_id if interaction.guild else 'Unknown'}")
        return False
    
    try:
        await interaction.response.defer(ephemeral=ephemeral)
        return True
    except discord.errors.NotFound:
        print(f"❌ Interaction expired for guild {interaction.guild_id if interaction.guild else 'Unknown'}")
        return False
    except discord.errors.HTTPException as e:
        if "already been acknowledged" in str(e):
            print(f"⚠️ Interaction already acknowledged for guild {interaction.guild_id if interaction.guild else 'Unknown'}")
            return False
        print(f"❌ HTTP error during defer: {e}")
        return False

async def send_reply(interaction: discord.Interaction, content: Optional[str] = None, ephemeral: bool = True, **kwargs):
    """
    Proper helper function to handle Discord interaction responses.
    Uses followup if interaction is already responded to, otherwise uses initial response.
    
    Args:
        interaction: The Discord interaction to respond to
        content: Optional text content for the response (can be None if using embed= or other kwargs)
        ephemeral: Whether the response should be ephemeral (visible only to the user)
        **kwargs: Additional parameters like embed, view, etc.
    
    Returns:
        The sent message object
    """
    # Handle None content by only passing content if it's not None
    send_kwargs = {'ephemeral': ephemeral, **kwargs}
    if content is not None:
        send_kwargs['content'] = content
    
    if interaction.response.is_done():
        return await interaction.followup.send(**send_kwargs)
    else:
        await interaction.response.send_message(**send_kwargs)
        return await interaction.original_response()

# Get domain for Stripe redirects
def get_domain() -> str:
    # Check if we're in production mode
    if os.getenv('REPLIT_ENVIRONMENT') == 'production':
        # In production, use the published domain
        return 'time-warden.com'
    else:
        # In development, use the dev domain
        domains = os.getenv('REPLIT_DOMAINS', '')
        return domains.split(',')[0] if domains else 'localhost:5000'


def generate_dashboard_deeplink(guild_id: int, user_id: int, page: str, secret: str | None = None) -> str:
    """Generate a signed deep-link URL for dashboard navigation"""
    if secret is None:
        secret = os.getenv('SESSION_SECRET', 'fallback-secret')
    
    # Create timestamp and signature
    timestamp = int(time.time())
    data = f"{guild_id}:{user_id}:{page}:{timestamp}"
    signature = hashlib.sha256(f"{data}:{secret}".encode()).hexdigest()[:16]
    
    # Build URL
    base_url = "https://time-warden.com"
    return f"{base_url}/deeplink/{page}?guild={guild_id}&user={user_id}&t={timestamp}&sig={signature}"


def create_secure_checkout_session(guild_id: int, product_type: str, guild_name: str = "", apply_trial_coupon: bool = False) -> str:
    """Create a secure Stripe checkout session for subscription products.
    
    Args:
        guild_id: Discord guild/server ID
        product_type: One of 'premium', 'pro'
        guild_name: Optional guild name for confirmation messages
        apply_trial_coupon: If True, applies the first-month free coupon.
    
    Returns:
        Checkout session URL
    
    Raises:
        ValueError: If Stripe is not configured, product_type is invalid, or checkout fails
    """
    if not stripe.api_key:
        raise ValueError("STRIPE_SECRET_KEY not configured")
    
    if product_type not in STRIPE_PRICE_IDS:
        raise ValueError(f"Invalid product_type: {product_type}. Must be one of: {', '.join(STRIPE_PRICE_IDS.keys())}")
    
    price_id = STRIPE_PRICE_IDS[product_type]
    if not price_id:
        raise ValueError(f"Stripe price ID not configured for {product_type}")
    
    domain = get_domain()
    
    try:
        metadata = {
            'guild_id': str(guild_id),
            'product_type': product_type
        }
        
        if guild_name:
            metadata['guild_name'] = guild_name
        
        session_params = {
            'line_items': [{
                'price': price_id,
                'quantity': 1,
            }],
            'mode': 'subscription',
            'success_url': f'https://{domain}/success?session_id={{CHECKOUT_SESSION_ID}}',
            'cancel_url': f'https://{domain}/cancel',
            'metadata': metadata,
            'subscription_data': {
                'metadata': metadata,
            },
        }
        
        import logging
        logger = logging.getLogger('gunicorn.error')
        
        if apply_trial_coupon:
            coupon_id = os.getenv('STRIPE_COUPON_FIRST_MONTH', 'sfaexZAF')
            try:
                coupon = stripe.Coupon.retrieve(coupon_id)
                if coupon.valid:
                    session_params['discounts'] = [{'coupon': coupon_id}]
                    metadata['trial_applied'] = 'true'
                    logger.info(f"[STRIPE] Coupon {coupon_id} validated and applied")
                else:
                    logger.warning(f"[STRIPE] Coupon {coupon_id} is no longer valid, skipping")
            except StripeError as ce:
                logger.warning(f"[STRIPE] Coupon {coupon_id} retrieval failed: {ce}, skipping coupon")
        
        logger.info(f"[STRIPE] Creating checkout session for guild {guild_id}, product {product_type}, trial={apply_trial_coupon}")
        logger.info(f"[STRIPE] Session params keys: {list(session_params.keys())}")
        logger.info(f"[STRIPE] API key set: {bool(stripe.api_key)}, key prefix: {stripe.api_key[:8] if stripe.api_key else 'NONE'}...")
        
        stripe.max_network_retries = 1
        checkout_session = stripe.checkout.Session.create(**session_params)  # type: ignore[arg-type]
        logger.info(f"[STRIPE] Checkout session created: {checkout_session.id}")
        
        return checkout_session.url or ""
        
    except StripeError as e:
        import logging
        logging.getLogger('gunicorn.error').error(f"[STRIPE] Stripe API error: {e}")
        raise ValueError(f"Stripe error: {str(e)}")
    except Exception as e:
        import logging
        logging.getLogger('gunicorn.error').error(f"[STRIPE] Checkout creation failed: {e}")
        raise ValueError(f"Checkout creation failed: {str(e)}")


_db_pool_initialized = False

def init_db_pool():
    """Initialize PostgreSQL connection pool"""
    global db_pool, _db_pool_initialized
    if _db_pool_initialized and db_pool is not None:
        return
    if not DATABASE_URL:
        raise ValueError("DATABASE_URL environment variable is not set")
    db_pool = psycopg2.pool.ThreadedConnectionPool(
        minconn=1,
        maxconn=10,
        dsn=DATABASE_URL
    )
    _db_pool_initialized = True
    print("✅ PostgreSQL connection pool initialized")
    
    # Run migrations on startup (guarded internally)
    run_migrations()

class ConnectionWrapper:
    """Wrapper to make psycopg2 connection behave like sqlite3 connection"""
    def __init__(self, conn):
        self._conn = conn
        self._cursor = None
    
    def execute(self, query, params=None):
        """Execute a query and return a cursor (mimics sqlite3 behavior)"""
        self._cursor = self._conn.cursor(cursor_factory=RealDictCursor)
        if params:
            self._cursor.execute(query, params)
        else:
            self._cursor.execute(query)
        return self._cursor
    
    def executemany(self, query, params_list):
        """Execute a query with multiple parameter sets"""
        self._cursor = self._conn.cursor(cursor_factory=RealDictCursor)
        self._cursor.executemany(query, params_list)
        return self._cursor
    
    def cursor(self):
        """Get a new cursor with RealDictCursor"""
        return self._conn.cursor(cursor_factory=RealDictCursor)
    
    def commit(self):
        """Commit the transaction"""
        self._conn.commit()
    
    def rollback(self):
        """Rollback the transaction"""
        self._conn.rollback()

@contextmanager
def db():
    """Context manager for PostgreSQL database connections"""
    if db_pool is None:
        init_db_pool()
    
    conn = db_pool.getconn()
    wrapper = ConnectionWrapper(conn)
    try:
        yield wrapper
        # Auto-commit on successful exit
        conn.commit()
    except Exception as e:
        # Auto-rollback on exception
        conn.rollback()
        raise
    finally:
        # Always return connection to pool
        db_pool.putconn(conn)

def init_db():
    """PostgreSQL schema already exists - no initialization needed"""
    print("✅ Using existing PostgreSQL schema (tables already created during migration)")
    pass

def get_guild_tier_string(guild_id: int) -> str:
    """
    Get guild tier as a string using Entitlements.get_guild_tier().
    This is the standardized way to check tier per CLAUDE.md rules.
    Returns: "free", "grandfathered", "premium", or "pro"
    """
    with db() as conn:
        cursor = conn.execute(
            """SELECT bot_access_paid, retention_tier, tier,
                      COALESCE(grandfathered, FALSE) as grandfathered
               FROM server_subscriptions WHERE guild_id = %s""",
            (guild_id,)
        )
        result = cursor.fetchone()
        if not result:
            # No subscription record = free tier
            return UserTier.FREE.value

        bot_access_paid = bool(result.get('bot_access_paid', False))
        retention_tier = result.get('retention_tier') or 'none'
        grandfathered = bool(result.get('grandfathered', False))

        tier_enum = Entitlements.get_guild_tier(bot_access_paid, retention_tier, grandfathered)
        return tier_enum.value

def get_guild_access_info(guild_id: int) -> dict:
    """Get complete access info for a guild including tier and trial status"""
    tier = get_guild_tier_string(guild_id)
    with db() as conn:
        cursor = conn.execute("SELECT trial_start_date FROM guild_settings WHERE guild_id = %s", (guild_id,))
        gs_row = cursor.fetchone()
        trial_start_date = gs_row['trial_start_date'] if gs_row else None

        cursor = conn.execute("SELECT grandfathered, grant_source FROM server_subscriptions WHERE guild_id = %s", (guild_id,))
        ss_row = cursor.fetchone()
        grandfathered = ss_row['grandfathered'] if ss_row else False
        owner_granted = ss_row['grant_source'] == 'granted' if ss_row else False

    trial_active = Entitlements.is_trial_active(trial_start_date)
    days_remaining = Entitlements.get_trial_days_remaining(trial_start_date)
    is_exempt = Entitlements.is_server_exempt(guild_id, grandfathered, owner_granted)

    return {
        'tier': tier,
        'trial_active': trial_active,
        'days_remaining': days_remaining,
        'is_exempt': is_exempt
    }


def set_server_tier(guild_id: int, tier: str, subscription_id: Optional[str] = None, customer_id: Optional[str] = None):
    """Set subscription tier for a server"""
    with db() as conn:
        if subscription_id and customer_id:
            # Full subscription with customer info
            conn.execute("""
                INSERT INTO server_subscriptions 
                (guild_id, tier, subscription_id, expires_at, status, customer_id) 
                VALUES (%s, %s, %s, NULL, 'active', %s)
                ON CONFLICT (guild_id) DO UPDATE 
                SET tier = EXCLUDED.tier, subscription_id = EXCLUDED.subscription_id, 
                    status = EXCLUDED.status, customer_id = EXCLUDED.customer_id
            """, (guild_id, tier, subscription_id, customer_id))
        elif subscription_id:
            # Subscription without customer (legacy)
            conn.execute("""
                INSERT INTO server_subscriptions 
                (guild_id, tier, subscription_id, expires_at, status) 
                VALUES (%s, %s, %s, NULL, 'active')
                ON CONFLICT (guild_id) DO UPDATE 
                SET tier = EXCLUDED.tier, subscription_id = EXCLUDED.subscription_id, status = EXCLUDED.status
            """, (guild_id, tier, subscription_id))
        else:
            # Free tier or manual assignment
            conn.execute("""
                INSERT INTO server_subscriptions 
                (guild_id, tier, expires_at, status) 
                VALUES (%s, %s, NULL, 'active')
                ON CONFLICT (guild_id) DO UPDATE 
                SET tier = EXCLUDED.tier, status = EXCLUDED.status
            """, (guild_id, tier))

def is_user_banned(guild_id: int, user_id: int) -> bool:
    """Check if a user is currently banned (checks if ban expired)"""
    with db() as conn:
        cursor = conn.execute(
            """SELECT ban_expires_at FROM banned_users 
               WHERE guild_id = %s AND user_id = %s""",
            (guild_id, user_id)
        )
        result = cursor.fetchone()
        if not result:
            return False
        
        ban_expires_at = result['ban_expires_at']
        if not ban_expires_at:
            # No expiration = permanent ban (shouldn't happen with new system)
            return True
        
        # Check if ban has expired
        from datetime import datetime, timezone
        expiry = safe_parse_timestamp(ban_expires_at)
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > expiry:
            # Ban expired, remove it
            conn.execute(
                "DELETE FROM banned_users WHERE guild_id = %s AND user_id = %s",
                (guild_id, user_id)
            )
            return False
        
        return True

def get_user_warning_count(guild_id: int, user_id: int) -> int:
    """Get the number of warnings a user has received"""
    with db() as conn:
        cursor = conn.execute(
            "SELECT warning_count FROM banned_users WHERE guild_id = %s AND user_id = %s",
            (guild_id, user_id)
        )
        result = cursor.fetchone()
        return result['warning_count'] if result else 0

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

async def dispatch_webhook_event(guild_id: int, user_id: int, event_type: str, event_data: dict = None):
    """
    Dispatch internal events to a Discord channel configured in the server's settings.
    Used to bridge Kiosk button presses to Discord channels in real-time.
    
    Args:
        guild_id: Discord Server ID
        user_id: Employee's Discord ID
        event_type: 'clock_in', 'clock_out', 'time_adjustment', etc.
        event_data: Additional context dictionary (timestamp, duration, etc.)
    """
    try:
        with db() as conn:
            cursor = conn.execute(
                "SELECT discord_log_channel_id FROM guild_settings WHERE guild_id = %s",
                (str(guild_id),)
            )
            settings = cursor.fetchone()
            
        if not settings or not settings.get('discord_log_channel_id'):
            return  # No logging channel configured
            
        channel_id = int(settings['discord_log_channel_id'])
        guild = bot.get_guild(guild_id)
        if not guild:
            return  
            
        channel = guild.get_channel(channel_id)
        if not channel:
            return
            
        member = guild.get_member(user_id)
        user_mention = member.mention if member else f"<@{user_id}>"
        
        # Build embed based on event type
        embed = discord.Embed(timestamp=discord.utils.utcnow())
        
        if event_type == 'clock_in':
            embed.title = "🟢 Clock In via Kiosk"
            embed.color = discord.Color.green()
            embed.description = f"{user_mention} has started their shift."
        elif event_type == 'clock_out':
            embed.title = "🔴 Clock Out via Kiosk"
            embed.color = discord.Color.red()
            embed.description = f"{user_mention} has ended their shift."
            if event_data and 'duration_minutes' in event_data:
                mins = event_data['duration_minutes']
                hours = mins / 60
                embed.add_field(name="Duration", value=f"{hours:.2f} hours ({mins:.0f} mins)")
        elif event_type == 'time_adjustment_approved':
            embed.title = "✅ Time Adjustment Approved"
            embed.color = discord.Color.green()
            embed.description = f"The time adjustment request for {user_mention} has been approved."
        elif event_type == 'time_adjustment_denied':
            embed.title = "❌ Time Adjustment Denied"
            embed.color = discord.Color.red()
            embed.description = f"The time adjustment request for {user_mention} was denied by an admin."
        elif event_type == 'employee_removed':
            embed.title = "🗑️ Employee Removed"
            embed.color = discord.Color.orange()
            embed.description = f"{user_mention} has been manually removed from the Time Warden dashboard by an admin."
        else:
            embed.title = f"🔔 Event: {event_type}"
            embed.color = discord.Color.blue()
            embed.description = f"User: {user_mention}"
            
        await channel.send(embed=embed)
        
    except Exception as e:
        print(f"❌ Failed to dispatch webhook event for {guild_id}: {e}")

async def mutate_employee_roles(guild_id: int, user_id: int, action: str):
    """
    MATHEMATICALLY swap Active/Inactive roles during clocked states.
    Fetches the `role_id_clocked_in` and `role_id_clocked_out` from guild_settings.
    Includes explicit error handling for missing permissions or deleted roles.
    
    Args:
        guild_id: The Discord Server ID
        user_id: The Employee's Discord ID
        action: 'in' to grant clocked_in role and strip clocked_out role.
                'out' to grant clocked_out role and strip clocked_in role.
    """
    try:
        with db() as conn:
            cursor = conn.execute("""
                SELECT enable_role_sync, role_id_clocked_in, role_id_clocked_out 
                FROM guild_settings WHERE guild_id = %s
            """, (str(guild_id),))
            settings = cursor.fetchone()
            
        if not settings or not settings.get('enable_role_sync'):
            return  # Role syncing is disabled for this server
            
        role_in_id = settings.get('role_id_clocked_in')
        role_out_id = settings.get('role_id_clocked_out')
        
        if not role_in_id and not role_out_id:
            return  # No roles configured
            
        guild = bot.get_guild(int(guild_id))
        if not guild:
            # Bot might be restarting or not fully loaded
            return
            
        member = guild.get_member(int(user_id))
        if not member:
            return  # User left the server
            
        # Determine roles to add and remove based on the action
        roles_to_add_ids = []
        roles_to_remove_ids = []
        
        if action == 'in':
            if role_in_id: roles_to_add_ids.append(role_in_id)
            if role_out_id: roles_to_remove_ids.append(role_out_id)
        elif action == 'out':
            if role_out_id: roles_to_add_ids.append(role_out_id)
            if role_in_id: roles_to_remove_ids.append(role_in_id)
            
        # Resolve objects safely
        roles_to_add = [guild.get_role(int(rid)) for rid in roles_to_add_ids if guild.get_role(int(rid))]
        roles_to_remove = [guild.get_role(int(rid)) for rid in roles_to_remove_ids if guild.get_role(int(rid))]
        
        # Execute mutations
        if roles_to_remove:
            try:
                await member.remove_roles(*roles_to_remove, reason=f"TimeWarden: Auto-sync on clock {action}")
            except discord.Forbidden:
                print(f"❌ Missing Permissions to remove role in {guild_id}")
            except discord.HTTPException as he:
                print(f"❌ Discord API error removing role in {guild_id}: {he}")
                
        if roles_to_add:
            try:
                await member.add_roles(*roles_to_add, reason=f"TimeWarden: Auto-sync on clock {action}")
            except discord.Forbidden:
                print(f"❌ Missing Permissions to add role in {guild_id}")
            except discord.HTTPException as he:
                print(f"❌ Discord API error adding role in {guild_id}: {he}")
                
    except Exception as e:
        print(f"Error mutating roles for user {user_id} in {guild_id}: {e}")

def issue_warning(guild_id: int, user_id: int):
    """Issue a warning to a user (first offense)"""
    with db() as conn:
        conn.execute(
            """INSERT INTO banned_users (guild_id, user_id, warning_count, reason) 
               VALUES (%s, %s, 1, 'spam_warning')
               ON CONFLICT(guild_id, user_id) 
               DO UPDATE SET warning_count = warning_count + 1""",
            (guild_id, user_id)
        )
    print(f"⚠️ Warning issued to user {user_id} in guild {guild_id}")

def ban_user_24h(guild_id: int, user_id: int, reason: str = "rate_limit_exceeded"):
    """Ban a user for 24 hours"""
    from datetime import datetime, timezone, timedelta
    
    ban_expires = datetime.now(timezone.utc) + timedelta(hours=24)
    
    with db() as conn:
        # Get current warning count for this user
        cursor = conn.execute(
            "SELECT warning_count FROM banned_users WHERE guild_id = %s AND user_id = %s",
            (guild_id, user_id)
        )
        result = cursor.fetchone()
        current_warnings = result['warning_count'] if result else 0
        
        # Insert or update ban record
        conn.execute(
            """INSERT INTO banned_users 
               (guild_id, user_id, banned_at, ban_expires_at, warning_count, reason) 
               VALUES (%s, %s, NOW(), %s, %s, %s)
               ON CONFLICT (guild_id, user_id) DO UPDATE 
               SET banned_at = NOW(), ban_expires_at = EXCLUDED.ban_expires_at, 
                   warning_count = EXCLUDED.warning_count, reason = EXCLUDED.reason""",
            (guild_id, user_id, ban_expires.isoformat(), current_warnings, reason)
        )
        
        # Log to server ban tracking
        conn.execute(
            "INSERT INTO server_ban_log (guild_id, user_id) VALUES (%s, %s)",
            (guild_id, user_id)
        )
    
    print(f"🚫 24-hour ban issued to user {user_id} in guild {guild_id} - Expires: {ban_expires.isoformat()}")

def check_server_abuse(guild_id: int) -> bool:
    """Check if server has excessive bans (5+ in last hour) = abuse"""
    from datetime import datetime, timezone, timedelta
    
    one_hour_ago = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    
    with db() as conn:
        cursor = conn.execute(
            """SELECT COUNT(*) as count FROM server_ban_log 
               WHERE guild_id = %s AND banned_at >= %s""",
            (guild_id, one_hour_ago)
        )
        result = cursor.fetchone()
        ban_count = result['count'] if result else 0
    
    return ban_count >= 5

def check_rate_limit(guild_id: int, user_id: int, button_name: str = "unknown") -> tuple[bool, int, str]:
    """
    Check if user has exceeded rate limits for a specific button.
    Returns (is_allowed, requests_in_window, action_taken)
    
    Rate limit: 5 requests per 30 seconds PER BUTTON
    - First violation: Warning
    - Second violation: 24-hour ban
    
    NOTE: Ban check fails-closed (blocks on error) for security
          Rate limiting fails-open (allows on error) for availability
    """
    # CRITICAL: Ban check fails-closed to prevent banned users bypassing bans
    try:
        if is_user_banned(guild_id, user_id):
            return (False, 999, "banned")
    except Exception as e:
        # FAIL-CLOSED for security: If ban check fails, treat as banned
        print(f"❌ Ban check failed for user {user_id} in guild {guild_id}: {e}")
        print(f"   Blocking request (fail-closed security policy)")
        return (False, 999, "banned")
    
    # Rate limiting logic - fails-open for availability
    try:
        current_time = time.time()
        key = (guild_id, user_id, button_name)
        
        # Initialize if not exists
        if key not in user_interaction_timestamps:
            user_interaction_timestamps[key] = []
        
        # Remove timestamps older than the rate limit window
        cutoff_time = current_time - RATE_LIMIT_WINDOW
        user_interaction_timestamps[key] = [
            ts for ts in user_interaction_timestamps[key] 
            if ts > cutoff_time
        ]
        
        # Count requests in current window
        requests_in_window = len(user_interaction_timestamps[key])
        
        # Check if limit exceeded
        if requests_in_window >= RATE_LIMIT_MAX_REQUESTS:
            try:
                # Get warning count to determine action
                warning_count = get_user_warning_count(guild_id, user_id)
                
                if warning_count == 0:
                    # FIRST OFFENSE: Issue warning
                    try:
                        issue_warning(guild_id, user_id)
                        print(f"⚠️ SPAM WARNING: User {user_id} in guild {guild_id} exceeded rate limit ({requests_in_window} requests in {RATE_LIMIT_WINDOW}s) - WARNING ISSUED")
                        return (False, requests_in_window, "warning")
                    except Exception as e:
                        print(f"❌ Failed to issue warning for user {user_id} in guild {guild_id}: {e}")
                        # Still block the request even if warning fails
                        return (False, requests_in_window, "warning")
                else:
                    # SECOND OFFENSE: 24-hour ban
                    try:
                        ban_user_24h(guild_id, user_id, reason="rate_limit_exceeded")
                        print(f"🚫 SPAM BAN: User {user_id} in guild {guild_id} exceeded rate limit again - 24 HOUR BAN")
                        
                        # Check if this server is abusing the bot (too many bans)
                        try:
                            if check_server_abuse(guild_id):
                                print(f"🚨 SERVER ABUSE DETECTED: Guild {guild_id} has 5+ bans in 1 hour - BOT WILL LEAVE")
                                return (False, requests_in_window, "server_abuse")
                        except Exception as e:
                            print(f"❌ Server abuse check failed for guild {guild_id}: {e}")
                        
                        return (False, requests_in_window, "banned")
                    except Exception as e:
                        print(f"❌ Failed to ban user {user_id} in guild {guild_id}: {e}")
                        # Still block the request even if ban fails
                        return (False, requests_in_window, "banned")
            except Exception as e:
                print(f"❌ Warning count check failed for user {user_id} in guild {guild_id}: {e}")
                # Block the rate-limited request even if warning check fails
                return (False, requests_in_window, "warning")
        
        # Add current timestamp
        user_interaction_timestamps[key].append(current_time)
        
        return (True, requests_in_window + 1, "allowed")
    
    except Exception as e:
        # FAIL-OPEN: If rate limiting logic fails, allow the request to proceed
        # This prevents database errors from breaking all button interactions
        # But bans are still enforced (checked above with fail-closed)
        print(f"❌ Rate limit logic failed for user {user_id} in guild {guild_id}: {e}")
        print(f"   Allowing request to proceed (fail-open availability policy)")
        return (True, 0, "allowed")

async def handle_rate_limit_response(interaction: discord.Interaction, action: str) -> bool:
    """
    Handle rate limit response messages and server abuse.
    Returns True if should leave server (abuse detected), False otherwise.
    """
    try:
        if action == "warning":
            await interaction.followup.send(
                "⚠️ **Spam Detection Warning**\n\n"
                "You're clicking the same button too quickly (5+ clicks in 30 seconds).\n"
                "Please slow down.\n\n"
                "**⛔ Next violation will result in a 24-hour ban.**",
                ephemeral=True
            )
        elif action == "server_abuse":
            # Bot will leave server
            await interaction.followup.send(
                "🚨 **Server Abuse Detected**\n\n"
                "This server has excessive spam activity. The bot is leaving this server.",
                ephemeral=True
            )
            if interaction.guild:
                try:
                    await interaction.guild.leave()
                    print(f"🚨 Bot left guild {interaction.guild.id} due to abuse (5+ bans in 1 hour)")
                except Exception as e:
                    print(f"❌ Failed to leave guild {interaction.guild.id}: {e}")
            return True
        else:  # banned
            await interaction.followup.send(
                "🚫 **24-Hour Ban**\n\n"
                "Your access to this bot has been temporarily suspended due to spam/abuse.\n"
                "You exceeded the rate limit (5 requests per 30 seconds on the same button) after receiving a warning.\n\n"
                "**Ban Duration:** 24 hours\n"
                "**Contact:** Server administrator for assistance",
                ephemeral=True
            )
    except Exception as e:
        # If sending rate limit message fails, log it but don't break the flow
        print(f"❌ Failed to send rate limit response: {e}")
    
    return False

def check_bot_access(guild_id: int) -> bool:
    """
    Check if a server has paid for bot access.
    Returns True if bot_access_paid=1, False otherwise.
    Handles missing records gracefully (returns False for free tier).
    """
    with db() as conn:
        cursor = conn.execute(
            "SELECT bot_access_paid FROM server_subscriptions WHERE guild_id = %s",
            (guild_id,)
        )
        result = cursor.fetchone()
        if not result:
            return False  # No record = free tier = no bot access
        
        return bool(result['bot_access_paid'])

def get_retention_tier(guild_id: int) -> str:
    """
    Get data retention tier for a server.
    Returns 'none', '7day', or '30day'.
    Defaults to 'none' if no record exists or value is NULL/invalid.
    """
    valid_tiers = {'none', '7day', '30day'}
    
    with db() as conn:
        cursor = conn.execute(
            "SELECT retention_tier FROM server_subscriptions WHERE guild_id = %s",
            (guild_id,)
        )
        result = cursor.fetchone()
        if not result:
            return 'none'  # Default to no retention
        
        tier = result['retention_tier'] or 'none'  # Normalize NULL to 'none'
        
        # Validate tier is in allowed set, default to 'none' if invalid
        if tier not in valid_tiers:
            return 'none'
        
        return tier

def is_mobile_restricted(guild_id: int) -> bool:
    """
    Check if mobile device clock-in/out is restricted for a server.
    Returns True if restriction is enabled, False otherwise.
    Defaults to False (mobile allowed) if no record exists.
    """
    with db() as conn:
        cursor = conn.execute(
            "SELECT restrict_mobile_clockin FROM server_subscriptions WHERE guild_id = %s",
            (guild_id,)
        )
        result = cursor.fetchone()
        if not result:
            return False  # Default to allowing mobile
        
        return bool(result['restrict_mobile_clockin'])

def is_kiosk_mode_only(guild_id: int) -> bool:
    """Check if the server has enabled Kiosk-Only Mode"""
    try:
        # Use async DB connection pool
        return bot.loop.run_until_complete(_check_kiosk_mode(guild_id))
    except Exception as e:
        logger.error(f"Error checking kiosk_only_mode for guild {guild_id}: {e}")
        return False

async def _check_kiosk_mode(guild_id: int) -> bool:
    try:
        async with db() as conn:
            row = await conn.fetchrow(
                "SELECT kiosk_only_mode FROM guild_settings WHERE guild_id = $1",
                guild_id
            )
            return bool(row.get('kiosk_only_mode', False)) if row else False
    except Exception as e:
        logger.error(f"Error checking kiosk_only_mode for guild {guild_id}: {e}")
        return False

async def notify_server_owner_bot_access(guild_id: int, granted_by: str = "purchase"):
    """
    Send a welcome message to the server when bot access is granted.
    Posts in system channel or first available text channel with @owner mention.
    
    Args:
        guild_id: The Discord guild ID
        granted_by: Either "purchase" (Stripe) or "manual" (bot owner grant)
    """
    import logging
    logger = logging.getLogger('bot.notify')
    
    try:
        logger.info(f"📧 [NOTIFY] Starting notification for guild {guild_id}, granted_by={granted_by}")
        
        guild = bot.get_guild(guild_id)
        if not guild:
            logger.error(f"❌ [NOTIFY] Guild {guild_id} not found in bot cache")
            return
        
        logger.info(f"✅ [NOTIFY] Guild found: {guild.name} (ID: {guild_id})")
        
        # Get owner ID (always available)
        owner_id = guild.owner_id
        if not owner_id:
            logger.error(f"❌ [NOTIFY] Guild {guild_id} has no owner_id (impossible - all Discord servers must have an owner)")
            return
        
        logger.info(f"📍 [NOTIFY] Guild owner ID: {owner_id}")
        
        # Try to get the owner member object (may not be cached after restart)
        owner: discord.Member | discord.User | None = guild.get_member(owner_id)

        if not owner:
            logger.warning(f"⚠️ [NOTIFY] Owner member not in cache, attempting to fetch...")
            try:
                # Fetch the user object (not a full member, but has basic info)
                owner = await bot.fetch_user(owner_id)
                if owner:
                    logger.info(f"✅ [NOTIFY] Fetched owner user object: {owner.name} (ID: {owner.id})")
            except Exception as e:
                logger.warning(f"⚠️ [NOTIFY] Could not fetch owner user {owner_id}: {e}")
                logger.info(f"📤 [NOTIFY] Will send notification without owner mention")
                owner = None
        else:
            logger.info(f"✅ [NOTIFY] Owner found in cache: {owner.name} (ID: {owner.id})")
        
        # Create a fancy embed
        embed = discord.Embed(
            title="🎉 Bot Access Activated!",
            description=f"**{guild.name}** now has full access to On the Clock!",
            color=discord.Color.green(),
            timestamp=datetime.now(timezone.utc)
        )
        
        if granted_by == "purchase":
            embed.add_field(
                name="✅ Payment Confirmed",
                value="Thank you for your purchase! Your server is now activated.",
                inline=False
            )
        else:
            embed.add_field(
                name="✅ Access Granted",
                value="Your server has been granted full bot access + dashboard usage by the bot owner.",
                inline=False
            )
        
        embed.add_field(
            name="🚀 What's Next?",
            value=(
                "• Use `/setup` to view setup instructions\n"
                "• Use `/clock` to open the timeclock interface\n"
                "• Use `/help` to see all available commands\n"
                "• Configure roles and settings in the dashboard"
            ),
            inline=False
        )
        
        # Get the dashboard URL dynamically
        dashboard_url = os.getenv("REPLIT_DEV_DOMAIN", "time-warden.com")
        if not dashboard_url.startswith("http"):
            dashboard_url = f"https://{dashboard_url}"
        
        embed.add_field(
            name="📊 Dashboard Access",
            value=f"Visit your [server dashboard]({dashboard_url}/dashboard) to:\n• Add admin and employee roles\n• Configure email notifications\n• Set timezone and schedule\n• View time tracking reports",
            inline=False
        )
        
        embed.add_field(
            name="💾 Data Retention",
            value="With full access, your timeclock data is stored securely. Add the Pro Retention add-on for extended 7-day or 30-day data storage.",
            inline=False
        )
        
        embed.set_footer(text=f"Server ID: {guild_id}")
        embed.set_thumbnail(url=guild.icon.url if guild.icon else None)
        
        # Find a channel to post in - check permissions before selecting
        target_channel = None
        
        # Build list of candidate channels: system channel first, then all text channels
        candidate_channels = []
        if guild.system_channel:
            logger.info(f"📍 [NOTIFY] System channel found: {guild.system_channel.name} (ID: {guild.system_channel.id})")
            candidate_channels.append(guild.system_channel)
        
        candidate_channels.extend(guild.text_channels)
        
        # Find first channel where bot has required permissions
        logger.info(f"📍 [NOTIFY] Searching {len(candidate_channels)} channels for suitable target...")
        for channel in candidate_channels:
            permissions = channel.permissions_for(guild.me)
            if permissions.send_messages and permissions.embed_links:
                logger.info(f"✅ [NOTIFY] Found suitable channel: #{channel.name} (ID: {channel.id})")
                logger.info(f"   Permissions: send_messages={permissions.send_messages}, embed_links={permissions.embed_links}")
                target_channel = channel
                break
            else:
                logger.warning(f"⚠️ [NOTIFY] Skipping #{channel.name}: send_messages={permissions.send_messages}, embed_links={permissions.embed_links}")
        
        if not target_channel:
            logger.error(f"❌ [NOTIFY] No accessible text channels found in guild {guild_id}")
            logger.error(f"   Bot needs 'Send Messages' and 'Embed Links' permissions in at least one channel")
            return
        
        # Send message with @owner mention (if available)
        logger.info(f"📤 [NOTIFY] Sending message to #{target_channel.name}...")
        try:
            # Include owner mention if we successfully fetched the owner
            if owner:
                await target_channel.send(
                    content=f"{owner.mention} 👋",
                    embed=embed
                )
                logger.info(f"✅ [NOTIFY] Successfully sent bot access notification to #{target_channel.name} in {guild.name} (ID: {guild_id})")
            else:
                # Send without mention if owner couldn't be fetched
                await target_channel.send(embed=embed)
                logger.info(f"✅ [NOTIFY] Successfully sent bot access notification (no mention) to #{target_channel.name} in {guild.name} (ID: {guild_id})")
        except discord.Forbidden:
            logger.error(f"❌ [NOTIFY] Permission denied when sending to #{target_channel.name} (permissions may have changed)")
            logger.error(f"   Bot needs 'Send Messages' and 'Embed Links' permissions in {guild.name}")
            raise
        
    except discord.Forbidden:
        logger.error(f"❌ [NOTIFY] Missing permissions to post in guild {guild_id}")
    except Exception as e:
        logger.error(f"❌ [NOTIFY] Error notifying guild {guild_id}: {e}")
        import traceback
        logger.error(traceback.format_exc())

def set_bot_access(guild_id: int, paid: bool):
    """
    Update bot_access_paid status for a server.
    Creates record with default values if doesn't exist.
    Used when processing bot access payments.
    """
    with db() as conn:
        conn.execute("""
            INSERT INTO server_subscriptions (guild_id, bot_access_paid, status)
            VALUES (%s, %s, %s)
            ON CONFLICT(guild_id) DO UPDATE SET 
                bot_access_paid = %s,
                status = EXCLUDED.status
        """, (guild_id, paid, 'active' if paid else 'free', paid))

def set_retention_tier(guild_id: int, tier: str):
    """
    Update retention tier for a server.
    Validates tier is in ('none', '7day', '30day').
    Raises ValueError if invalid tier.
    """
    valid_tiers = ('none', '7day', '30day')
    if tier not in valid_tiers:
        raise ValueError(f"Invalid retention tier: {tier}. Must be one of {valid_tiers}")
    
    with db() as conn:
        conn.execute("""
            INSERT INTO server_subscriptions (guild_id, retention_tier)
            VALUES (%s, %s)
            ON CONFLICT(guild_id) DO UPDATE SET retention_tier = %s
        """, (guild_id, tier, tier))

def check_tier_access(guild_id: int, required_tier: str) -> bool:
    """Check if server has access to features requiring a specific tier"""
    tier_hierarchy = {'free': 0, 'basic': 1, 'pro': 2}
    current_tier = get_guild_tier_string(guild_id)
    return tier_hierarchy.get(current_tier, 0) >= tier_hierarchy.get(required_tier, 0)

def is_server_admin(user: discord.Member) -> bool:
    """Check if user is server administrator (for free tier restrictions)"""
    return user.guild_permissions.administrator

# --- Data Retention Management ---
def get_retention_days(guild_id: int) -> int:
    """
    Get data retention days for a server based on bot_access_paid and retention tier.
    
    NEW PRICING MODEL:
    - bot_access_paid = false AND no subscription → 1 day (24 hours)
    - bot_access_paid = true AND no subscription → 7 days
    - Active subscription (30day tier) → 30 days
    
    The 7-day subscription tier is retired; 7-day retention is now granted
    automatically with bot_access_paid = true.
    """
    has_bot_access = check_bot_access(guild_id)
    tier = get_retention_tier(guild_id)
    
    # 30-day subscription active
    if tier == '30day':
        return 30
    
    # Legacy 7-day subscription (treat same as 30-day for backwards compat)
    if tier == '7day':
        return 7
    
    # Bot access paid but no subscription = 7 days
    if has_bot_access:
        return 7
    
    # Free tier = 1 day (24 hours)
    return 1

def cleanup_old_sessions(guild_id: Optional[int] = None) -> int:
    """Clean up old session data based on retention policy. Returns count of deleted records."""
    deleted_count = 0
    max_retries = 3
    
    for attempt in range(max_retries):
        try:
            with db() as conn:
                
                if guild_id:
                    # Clean up specific guild - only delete COMPLETED sessions older than retention period
                    retention_days = get_retention_days(guild_id)
                    cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)
                    
                    cursor = conn.execute("""
                        DELETE FROM timeclock_sessions 
                        WHERE guild_id = %s AND clock_out_time IS NOT NULL AND clock_out_time < %s
                    """, (guild_id, cutoff_date.isoformat()))
                    deleted_count = cursor.rowcount
                else:
                    # Clean up all guilds based on their individual retention policies
                    guilds_cursor = conn.execute("SELECT DISTINCT guild_id FROM timeclock_sessions")
                    guild_ids = [row['guild_id'] for row in guilds_cursor.fetchall()]
                    
                    for guild_id in guild_ids:
                        if guild_id is None:
                            continue  # Skip invalid guild IDs
                        retention_days = get_retention_days(guild_id)
                        cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)
                        
                        cursor = conn.execute("""
                            DELETE FROM timeclock_sessions 
                            WHERE guild_id = %s AND clock_out_time IS NOT NULL AND clock_out_time < %s
                        """, (guild_id, cutoff_date.isoformat()))
                        deleted_count += cursor.rowcount
                
                # Optimize database after cleanup (only if we deleted something)
                if deleted_count > 0:
                    # Skip VACUUM in background cleanup to avoid long locks
                    pass
                    
            # Success - exit retry loop
            break
            
        except psycopg2.OperationalError as e:
            if "database is locked" in str(e) and attempt < max_retries - 1:
                print(f"🔄 Database locked, retrying cleanup attempt {attempt + 1}/{max_retries}")
                time.sleep(2 ** attempt)  # Exponential backoff: 1s, 2s, 4s
                continue
            else:
                raise
    
    return deleted_count

def cleanup_user_sessions(guild_id: int, user_id: int) -> int:
    """Delete all timeclock sessions for a specific user in a guild. Returns count of deleted records."""
    deleted_count = 0
    max_retries = 3
    
    for attempt in range(max_retries):
        try:
            with db() as conn:
                # Delete all sessions for the specific user in this guild
                cursor = conn.execute("""
                    DELETE FROM timeclock_sessions 
                    WHERE guild_id = %s AND user_id = %s
                """, (guild_id, user_id))
                deleted_count = cursor.rowcount
                
                # Optimize database after cleanup (only if we deleted something)
                if deleted_count > 0:
                    # Skip VACUUM for PostgreSQL to avoid long locks
                    pass
                    
            # Success - exit retry loop
            break
            
        except psycopg2.OperationalError as e:
            if "database is locked" in str(e) and attempt < max_retries - 1:
                print(f"🔄 Database locked, retrying user cleanup attempt {attempt + 1}/{max_retries}")
                time.sleep(2 ** attempt)  # Exponential backoff: 1s, 2s, 4s
                continue
            else:
                raise
    
    return deleted_count

def get_guild_setting(guild_id: int, key: str, default=None):
    # Map of allowed keys to their SQL column queries
    column_queries = {
        'recipient_user_id': "SELECT recipient_user_id FROM guild_settings WHERE guild_id=%s",
        'timezone': "SELECT timezone FROM guild_settings WHERE guild_id=%s",
        'name_display_mode': "SELECT name_display_mode FROM guild_settings WHERE guild_id=%s",
        'main_admin_role_id': "SELECT main_admin_role_id FROM guild_settings WHERE guild_id=%s",
        'broadcast_channel_id': "SELECT broadcast_channel_id FROM guild_settings WHERE guild_id=%s"
    }
    
    if key not in column_queries:
        raise ValueError(f"Invalid column name: {key}")
    
    with db() as conn:
        cur = conn.execute(column_queries[key], (guild_id,))
        row = cur.fetchone()
        return row[key] if row and row[key] is not None else default

def get_active_employees_with_stats(guild_id: int, timezone_name: str = "America/New_York"):
    """
    Get ALL employees (clocked in and out) with their stats and recent activity.
    Returns: List[Dict] with user_id, username, display_name, avatar_url,
             is_clocked_in, clock_in, clock_out, hours_today, hours_week, hours_month
    """
    from zoneinfo import ZoneInfo
    try:
        tz = ZoneInfo(timezone_name)
    except Exception:
        tz = ZoneInfo('UTC')

    now_utc = datetime.now(timezone.utc)
    now_local = now_utc.astimezone(tz)
    
    # Calculate start of day, week, month in LOCAL time, then convert to UTC
    today_start_local = now_local.replace(hour=0, minute=0, second=0, microsecond=0)
    today_start_utc = today_start_local.astimezone(timezone.utc)
    
    # Start of week (Monday)
    week_start_local = today_start_local - timedelta(days=today_start_local.weekday())
    week_start_utc = week_start_local.astimezone(timezone.utc)
    
    # Start of month
    month_start_local = today_start_local.replace(day=1)
    month_start_utc = month_start_local.astimezone(timezone.utc)

    employees = []
    
    with db() as conn:
        # Get all unique employees who have sessions in this guild
        # Join with employee_profiles table to get user data and privacy settings
        cursor = conn.execute("""
            SELECT DISTINCT s.user_id, u.display_name, u.full_name, u.avatar_url,
                   u.show_last_seen, u.show_discord_status
            FROM timeclock_sessions s
            LEFT JOIN employee_profiles u ON s.user_id = u.user_id AND s.guild_id = u.guild_id
            WHERE s.guild_id = %s
            ORDER BY s.user_id
        """, (guild_id,))
        all_employees = cursor.fetchall()
        
        for emp in all_employees:
            user_id = emp['user_id']
            
            # Check if currently clocked in
            cursor = conn.execute("""
                SELECT clock_in_time as clock_in 
                FROM timeclock_sessions 
                WHERE guild_id = %s AND user_id = %s AND clock_out_time IS NULL
                LIMIT 1
            """, (guild_id, user_id))
            active_session = cursor.fetchone()
            
            # Get most recent completed session for clock out time
            cursor = conn.execute("""
                SELECT clock_out_time as clock_out
                FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s AND clock_out_time IS NOT NULL
                ORDER BY clock_out_time DESC
                LIMIT 1
            """, (guild_id, user_id))
            last_completed = cursor.fetchone()
            
            is_clocked_in = active_session is not None
            clock_in = active_session['clock_in'] if active_session else None
            clock_out = last_completed['clock_out'] if last_completed else None
            
            # Calculate historical hours
            
            # Hours Today
            cursor = conn.execute("""
                SELECT SUM(EXTRACT(EPOCH FROM (clock_out_time - clock_in_time))::integer) as total
                FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s 
                AND clock_out_time IS NOT NULL
                AND clock_in_time >= %s
            """, (guild_id, user_id, today_start_utc.isoformat()))
            result = cursor.fetchone()
            hours_today = result['total'] if result and result['total'] else 0
            
            # Add current session duration to today's total if clocked in
            if is_clocked_in:
                current_duration = int((now_utc - safe_parse_timestamp(clock_in)).total_seconds())
                hours_today += current_duration
            else:
                current_duration = 0

            # Hours Week
            cursor = conn.execute("""
                SELECT SUM(EXTRACT(EPOCH FROM (clock_out_time - clock_in_time))::integer) as total
                FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s 
                AND clock_out_time IS NOT NULL
                AND clock_in_time >= %s
            """, (guild_id, user_id, week_start_utc.isoformat()))
            result = cursor.fetchone()
            hours_week = result['total'] if result and result['total'] else 0
            hours_week += current_duration

            # Hours Month
            cursor = conn.execute("""
                SELECT SUM(EXTRACT(EPOCH FROM (clock_out_time - clock_in_time))::integer) as total
                FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s 
                AND clock_out_time IS NOT NULL
                AND clock_in_time >= %s
            """, (guild_id, user_id, month_start_utc.isoformat()))
            result = cursor.fetchone()
            hours_month = result['total'] if result and result['total'] else 0
            hours_month += current_duration
            
            # Default privacy settings to True if no employee record exists
            show_status = emp['show_discord_status'] if emp['show_discord_status'] is not None else True
            show_last_seen = emp['show_last_seen'] if emp['show_last_seen'] is not None else True
            
            employees.append({
                'user_id': str(user_id),
                'username': emp['display_name'] or emp['full_name'] or f"User {user_id}",
                'display_name': emp['display_name'] or emp['full_name'],
                'avatar_url': emp['avatar_url'],
                'is_clocked_in': is_clocked_in,
                'clock_in': clock_in if clock_in else None,
                'clock_out': clock_out if clock_out else None,
                'hours_today': hours_today,
                'hours_week': hours_week,
                'hours_month': hours_month,
                'privacy_show_status': show_status,
                'privacy_show_last_seen': show_last_seen
            })
            
    return employees

def get_employees_for_calendar(guild_id: int):
    """
    Get all employees for the admin calendar dropdown.
    Combines employees from:
    1. employee_profiles table (anyone who has interacted)
    2. sessions table (anyone who has clocked in)
    Returns unique list of user_id with display names.
    """
    employees = []
    seen_users = set()
    
    with db() as conn:
        # First, get employees from employee_profiles for this guild
        cursor = conn.execute("""
            SELECT DISTINCT user_id, display_name, full_name
            FROM employee_profiles
            WHERE guild_id = %s
            ORDER BY COALESCE(display_name, full_name, user_id::text)
        """, (guild_id,))
        
        for row in cursor.fetchall():
            user_id = str(row['user_id'])
            if user_id not in seen_users:
                seen_users.add(user_id)
                employees.append({
                    'user_id': user_id,
                    'display_name': row['display_name'] or row['full_name'] or f"User {user_id}"
                })
        
        # Also get any users with sessions who might not be in employee_profiles
        cursor = conn.execute("""
            SELECT DISTINCT s.user_id, p.display_name, p.full_name
            FROM timeclock_sessions s
            LEFT JOIN employee_profiles p ON s.user_id = p.user_id AND s.guild_id = p.guild_id
            WHERE s.guild_id = %s
            ORDER BY COALESCE(p.display_name, p.full_name, s.user_id::text)
        """, (guild_id,))
        
        for row in cursor.fetchall():
            user_id = str(row['user_id'])
            if user_id not in seen_users:
                seen_users.add(user_id)
                employees.append({
                    'user_id': user_id,
                    'display_name': row['display_name'] or row['full_name'] or f"User {user_id}"
                })
    
    return employees

def create_adjustment_request(guild_id: int, user_id: int, request_type: str, 
                              original_session_id: Optional[int], 
                              requested_data: Dict, reason: str) -> Optional[int]:
    """
    Create a new adjustment request.
    requested_data should contain: requested_clock_in, requested_clock_out (ISO strings or datetimes)
    Returns: request_id or None if failed
    """
    try:
        # Negative Time Guard: Ensure clock_in is strictly before clock_out
        req_in = requested_data.get('clock_in')
        req_out = requested_data.get('clock_out')
        if req_in and req_out:
            dt_in = safe_parse_timestamp(req_in)
            dt_out = safe_parse_timestamp(req_out)
            if dt_out <= dt_in:
                print("⚠️ Blocked Negative Time Adjustment: clock_out <= clock_in")
                return None
                
        with db() as conn:
            # If modifying existing session, get original data for audit trail
            original_clock_in = None
            original_clock_out = None
            original_duration = None
            
            if original_session_id:
                cursor = conn.execute("""
                    SELECT clock_in_time as clock_in, clock_out_time as clock_out, 
                           EXTRACT(EPOCH FROM (clock_out_time - clock_in_time))::integer as duration_seconds 
                    FROM timeclock_sessions WHERE session_id = %s AND guild_id = %s
                """, (original_session_id, guild_id))
                row = cursor.fetchone()
                if row:
                    original_clock_in = row['clock_in']
                    original_clock_out = row['clock_out']
                    original_duration = row['duration_seconds']
            
            cursor = conn.execute("""
                INSERT INTO time_adjustment_requests 
                (guild_id, user_id, request_type, original_session_id, 
                 original_clock_in, original_clock_out, original_duration,
                 requested_clock_in, requested_clock_out, reason, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'pending')
                RETURNING id
            """, (
                guild_id, user_id, request_type, original_session_id,
                original_clock_in, original_clock_out, original_duration,
                requested_data.get('clock_in'), requested_data.get('clock_out'),
                reason
            ))
            
            request_id = cursor.fetchone()['id']
            return request_id
            
    except Exception as e:
        print(f"Error creating adjustment request: {e}")
        return None

def get_pending_adjustments(guild_id: int):
    """
    Get all pending adjustment requests for a guild.
    Returns: List[Dict] with request details enriched with user info
    """
    with db() as conn:
        cursor = conn.execute("""
            SELECT r.*, 
                   u.display_name, u.full_name, u.avatar_url
            FROM time_adjustment_requests r
            LEFT JOIN employee_profiles u ON r.user_id = u.user_id AND r.guild_id = u.guild_id
            WHERE r.guild_id = %s AND r.status = 'pending'
            ORDER BY r.created_at DESC
        """, (guild_id,))
        return cursor.fetchall()

def approve_adjustment(request_id: int, guild_id: int, reviewer_user_id: int):
    """
    Approve an adjustment request and apply changes to sessions table.
    Uses PostgreSQL transaction for atomicity.
    Returns: (success: bool, message: str)
    """
    try:
        with db() as conn:
            # Get request details with FOR UPDATE to block concurrent approvals
            cursor = conn.execute("""
                SELECT * FROM time_adjustment_requests 
                WHERE id = %s AND guild_id = %s AND status = 'pending'
                FOR UPDATE
            """, (request_id, guild_id))
            request = cursor.fetchone()
            
            if not request:
                return False, "Request not found or already processed"
            
            req_type = request['request_type']
            user_id = request['user_id']
            
            # Apply changes based on type
            if req_type == 'add_session':
                # Calculate duration
                clock_in = safe_parse_timestamp(request['requested_clock_in'])
                clock_out = safe_parse_timestamp(request['requested_clock_out'])
                duration = int((clock_out - clock_in).total_seconds())
                
                conn.execute("""
                    INSERT INTO timeclock_sessions (guild_id, user_id, clock_in_time, clock_out_time)
                    VALUES (%s, %s, %s, %s)
                """, (guild_id, user_id, request['requested_clock_in'], request['requested_clock_out']))
                
            elif req_type in ['modify_clockin', 'modify_clockout']:
                session_id = request['original_session_id']
                if not session_id:
                    return False, "Original session ID missing"
                
                # Update session
                updates = []
                params = []
                
                if request['requested_clock_in']:
                    updates.append("clock_in_time = %s")
                    params.append(request['requested_clock_in'])
                    
                if request['requested_clock_out']:
                    updates.append("clock_out_time = %s")
                    params.append(request['requested_clock_out'])
                
                # Fetch current state to verify session exists
                cursor = conn.execute("SELECT clock_in_time as clock_in, clock_out_time as clock_out FROM timeclock_sessions WHERE session_id = %s", (session_id,))
                current = cursor.fetchone()
                
                if not current:
                    return False, "Original session not found"
                
                params.append(session_id)
                
                query = "UPDATE timeclock_sessions SET " + ', '.join(updates) + " WHERE session_id = %s"
                conn.execute(query, tuple(params))
                
            elif req_type == 'delete_session':
                session_id = request['original_session_id']
                conn.execute("DELETE FROM timeclock_sessions WHERE session_id = %s", (session_id,))
            
            # Mark request as approved
            conn.execute("""
                UPDATE time_adjustment_requests 
                SET status = 'approved', reviewed_by = %s, reviewed_at = NOW()
                WHERE id = %s
            """, (reviewer_user_id, request_id))
            
            # Fire Webhook Notification to log channel
            import asyncio
            asyncio.run_coroutine_threadsafe(
                dispatch_webhook_event(
                    guild_id=guild_id,
                    user_id=user_id,
                    event_type='time_adjustment_approved',
                    event_data={'request_id': request_id}
                ),
                bot.loop
            )

            return True, "Adjustment approved and applied"
            
    except Exception as e:
        print(f"Error approving adjustment: {e}")
        return False, str(e)

def deny_adjustment(request_id: int, guild_id: int, reviewer_user_id: int):
    """Update request status to 'denied'"""
    try:
        with db() as conn:
            cursor = conn.execute("""
                UPDATE time_adjustment_requests 
                SET status = 'denied', reviewed_by = %s, reviewed_at = NOW()
                WHERE id = %s AND guild_id = %s AND status = 'pending'
                RETURNING user_id
            """, (reviewer_user_id, request_id, guild_id))
            
            row = cursor.fetchone()
            if row:
                user_id = row['user_id']
                # Fire Webhook Notification to log channel
                import asyncio
                asyncio.run_coroutine_threadsafe(
                    dispatch_webhook_event(
                        guild_id=guild_id,
                        user_id=user_id,
                        event_type='time_adjustment_denied',
                        event_data={'request_id': request_id}
                    ),
                    bot.loop
                )
                return True, "Request denied"
            return False, "Request not found or already processed"
    except Exception as e:
        return False, str(e)

def get_user_adjustment_history(guild_id: int, user_id: int, limit: int = 50):
    """
    Get adjustment request history for a specific user.
    Returns all requests (pending, approved, denied) for audit trail.
    """
    with db() as conn:
        cursor = conn.execute("""
            SELECT r.id, r.request_type, r.status, r.reason,
                   r.original_clock_in, r.original_clock_out,
                   r.requested_clock_in, r.requested_clock_out,
                   r.created_at, r.reviewed_at, r.reviewed_by,
                   ep.display_name
            FROM time_adjustment_requests r
            LEFT JOIN employee_profiles ep ON ep.guild_id = r.guild_id AND ep.user_id = r.user_id
            WHERE r.guild_id = %s AND r.user_id = %s
            ORDER BY r.created_at DESC
            LIMIT %s
        """, (guild_id, user_id, limit))
        return cursor.fetchall()

def get_all_adjustment_history(guild_id: int, limit: int = 100):
    """
    Get all adjustment request history for a guild (admin view).
    Returns all requests from all users (pending, approved, denied).
    """
    with db() as conn:
        cursor = conn.execute("""
            SELECT r.id, r.user_id, r.request_type, r.status, r.reason,
                   r.original_clock_in, r.original_clock_out,
                   r.requested_clock_in, r.requested_clock_out,
                   r.created_at, r.reviewed_at, r.reviewed_by,
                   ep.display_name, r.session_date as request_date
            FROM time_adjustment_requests r
            LEFT JOIN employee_profiles ep ON ep.guild_id = r.guild_id AND ep.user_id = r.user_id
            WHERE r.guild_id = %s
            ORDER BY r.created_at DESC
            LIMIT %s
        """, (guild_id, limit))
        return cursor.fetchall()

# --- Report Recipients Management ---

def add_report_recipient(guild_id: int, recipient_type: str, recipient_id: Optional[str] = None, email_address: Optional[str] = None):
    """Add a report recipient for a guild.
    
    Also ensures email_settings row exists with auto_send_on_clockout=True
    so that scheduled reports will actually be sent.
    """
    if recipient_type not in ['discord', 'email']:
        raise ValueError("recipient_type must be 'discord' or 'email'")
    
    if recipient_type == 'discord' and not recipient_id:
        raise ValueError("recipient_id is required for discord type")
    
    if recipient_type == 'email' and not email_address:
        raise ValueError("email_address is required for email type")
    
    try:
        with db() as conn:
            conn.execute("""
                INSERT INTO report_recipients (guild_id, recipient_type, recipient_id, email_address)
                VALUES (%s, %s, %s, %s)
            """, (guild_id, recipient_type, recipient_id, email_address))
            
            conn.execute("""
                INSERT INTO email_settings (guild_id, auto_send_on_clockout, auto_email_before_delete)
                VALUES (%s, TRUE, TRUE)
                ON CONFLICT (guild_id) DO NOTHING
            """, (guild_id,))
            
            return True
    except psycopg2.IntegrityError:
        return False

def remove_report_recipient(guild_id: int, recipient_type: str, recipient_id: Optional[str] = None, email_address: Optional[str] = None):
    """Remove a report recipient for a guild"""
    with db() as conn:
        if recipient_type == 'discord':
            conn.execute("""
                DELETE FROM report_recipients 
                WHERE guild_id = %s AND recipient_type = %s AND recipient_id = %s
            """, (guild_id, recipient_type, recipient_id))
        else:  # email
            conn.execute("""
                DELETE FROM report_recipients 
                WHERE guild_id = %s AND recipient_type = %s AND email_address = %s
            """, (guild_id, recipient_type, email_address))

def get_report_recipients(guild_id: int, recipient_type: Optional[str] = None):
    """Get all report recipients for a guild, optionally filtered by type"""
    with db() as conn:
        if recipient_type:
            cursor = conn.execute("""
                SELECT id, recipient_type, recipient_id, email_address, created_at
                FROM report_recipients 
                WHERE guild_id = %s AND recipient_type = %s
                ORDER BY created_at ASC
            """, (guild_id, recipient_type))
        else:
            cursor = conn.execute("""
                SELECT id, recipient_type, recipient_id, email_address, created_at
                FROM report_recipients 
                WHERE guild_id = %s
                ORDER BY recipient_type, created_at ASC
            """, (guild_id,))
        
        return cursor.fetchall()

async def send_timeclock_notifications(guild_id: int, interaction: discord.Interaction, start_dt: datetime, end_dt: datetime, elapsed: int, tz_name: str):
    """Send timeclock notifications to Discord recipients (DMs) and optionally to email recipients"""
    # Check if auto-send on clock-out is enabled
    with db() as conn:
        cursor = conn.execute(
            "SELECT auto_send_on_clockout FROM email_settings WHERE guild_id = %s",
            (guild_id,)
        )
        settings_row = cursor.fetchone()
        auto_send_enabled = bool(settings_row['auto_send_on_clockout']) if settings_row else False
    
    # Get Discord recipients for DM notifications
    discord_recipients = get_report_recipients(guild_id, recipient_type='discord')
    
    # Also check for legacy single recipient
    legacy_recipient_id = get_guild_setting(guild_id, "recipient_user_id")
    
    # Prepare the notification embed for Discord
    embed = discord.Embed(
        title="Timeclock Entry",
        description=f"**Employee:** {interaction.user.mention} (`{interaction.user.id}`)",
        color=discord.Color.blurple(),
        timestamp=end_dt
    )
    embed.add_field(name="Clock In", value=fmt(start_dt, tz_name), inline=True)
    embed.add_field(name="Clock Out", value=fmt(end_dt, tz_name), inline=True)
    embed.add_field(name="Total", value=human_duration(elapsed), inline=False)
    guild_name = interaction.guild.name if interaction.guild else "Unknown Server"
    embed.set_footer(text=f"Guild: {guild_name} • ID: {guild_id}")
    
    notification_sent = False
    errors = []
    
    # Send Discord DMs to Discord recipients
    for recipient_row in discord_recipients:
        recipient_id = recipient_row['id']
        recipient_type = recipient_row['recipient_type']
        discord_user_id = recipient_row['recipient_id']
        email_address = recipient_row['email_address']
        created_at = recipient_row['created_at']
        
        if recipient_type == 'discord' and discord_user_id:
            try:
                user = await bot.fetch_user(int(discord_user_id))
                await user.send(embed=embed)
                notification_sent = True
            except discord.Forbidden:
                errors.append(f"Discord user {discord_user_id} has DMs disabled")
            except discord.NotFound:
                errors.append(f"Discord user {discord_user_id} not found")
            except Exception as e:
                errors.append(f"Failed to notify Discord user {discord_user_id}: {str(e)}")
    
    # Fallback to legacy recipient if no new recipients configured
    if not discord_recipients and legacy_recipient_id:
        try:
            manager = await bot.fetch_user(legacy_recipient_id)
            await manager.send(embed=embed)
            notification_sent = True
        except discord.Forbidden:
            errors.append("Legacy recipient has DMs disabled")
        except discord.NotFound:
            errors.append("Legacy recipient not found")
        except Exception as e:
            errors.append(f"Failed to notify legacy recipient: {str(e)}")
    
    # Queue emails to email recipients if auto-send is enabled (using outbox for reliability)
    if auto_send_enabled:
        email_recipients = get_report_recipients(guild_id, recipient_type='email')
        if email_recipients:
            try:
                user_name = get_user_display_name(interaction.user, guild_id)  # type: ignore[arg-type]
                
                # Create CSV for single clock-out entry
                duration_hours = round(elapsed / 3600, 2)
                fallback_name = interaction.user.display_name or interaction.user.name
                safe_user_name = (user_name or fallback_name).replace(',', ' ')
                csv_content = f"User ID,Display Name,Clock In,Clock Out,Duration (hours)\n{interaction.user.id},{safe_user_name},{start_dt.isoformat()},{end_dt.isoformat()},{duration_hours}"
                
                # Only get verified email addresses
                email_addresses = [row['email_address'] for row in email_recipients 
                                   if row['email_address'] and row.get('verification_status') == 'verified']
                
                if email_addresses:
                    report_period = f"Clock-out at {fmt(end_dt, tz_name)} - {user_name}"
                    # Queue email to outbox for reliable delivery with retry
                    outbox_id = queue_shift_report_email(
                        guild_id=guild_id,
                        guild_name=guild_name,
                        recipients=email_addresses,
                        csv_content=csv_content,
                        report_period=report_period,
                        user_name=user_name
                    )
                    notification_sent = True
                    print(f"📬 Clock-out email queued #{outbox_id} for {len(email_addresses)} recipient(s)")
            except Exception as e:
                errors.append(f"Failed to queue clock-out email: {str(e)}")
                print(f"❌ Clock-out email queue failed: {str(e)}")
    
    # Report any errors to the user
    if errors and not notification_sent:
        try:
            await interaction.followup.send(
                "⚠️ Could not send notifications to any recipients:\n" + "\n".join(f"• {error}" for error in errors[:3]),
                ephemeral=True
            )
        except Exception:
            pass
    elif errors:
        try:
            await interaction.followup.send(
                f"⚠️ Some notifications failed:\n" + "\n".join(f"• {error}" for error in errors[:3]),
                ephemeral=True
            )
        except Exception:
            pass

def set_guild_setting(guild_id: int, key: str, value):
    # Map of allowed keys to their SQL update queries
    update_queries = {
        'recipient_user_id': "UPDATE guild_settings SET recipient_user_id=%s WHERE guild_id=%s",
        'timezone': "UPDATE guild_settings SET timezone=%s WHERE guild_id=%s",
        'name_display_mode': "UPDATE guild_settings SET name_display_mode=%s WHERE guild_id=%s",
        'main_admin_role_id': "UPDATE guild_settings SET main_admin_role_id=%s WHERE guild_id=%s",
        'broadcast_channel_id': "UPDATE guild_settings SET broadcast_channel_id=%s WHERE guild_id=%s"
    }
    
    if key not in update_queries:
        raise ValueError(f"Invalid column name: {key}")
    
    with db() as conn:
        conn.execute("INSERT INTO guild_settings(guild_id) VALUES (%s) ON CONFLICT (guild_id) DO NOTHING", (guild_id,))
        conn.execute(update_queries[key], (value, guild_id))

def get_guild_settings(guild_id: int) -> dict:
    """Fetch guild settings from database. Returns dict with all guild_settings columns."""
    with db() as conn:
        cursor = conn.execute(
            "SELECT * FROM guild_settings WHERE guild_id = %s",
            (guild_id,)
        )
        row = cursor.fetchone()
        return dict(row) if row else {}

def get_user_display_name(user: discord.Member, guild_id: int) -> str:
    """Get user display name based on guild preference: 'username' or 'nickname' or 'custom_name'"""
    # 1. Phase 1: Check for custom report name if the server format is set to custom
    csv_name_format = get_guild_setting(guild_id, "csv_name_format", "standard")
    
    if csv_name_format == "custom_name":
        try:
            with db() as conn:
                cur = conn.execute("SELECT custom_report_name FROM employee_profiles WHERE user_id=%s AND guild_id=%s", (user.id, guild_id))
                row = cur.fetchone()
                if row and row['custom_report_name']:
                    return row['custom_report_name']
        except Exception:
            pass # Fallback to standard logic if DB fails

    # 2. Fallback to standard Discord modes
    display_mode = get_guild_setting(guild_id, "name_display_mode", "username")
    
    if display_mode == "nickname" and hasattr(user, 'display_name'):
        return user.display_name
    else:
        return user.name

def get_active_session(guild_id: int, user_id: int):
    with db() as conn:
        cur = conn.execute("""
            SELECT session_id as id, clock_in_time as clock_in FROM timeclock_sessions
            WHERE guild_id=%s AND user_id=%s AND clock_out_time IS NULL
            ORDER BY session_id DESC LIMIT 1
        """, (guild_id, user_id))
        return cur.fetchone()

def start_session(guild_id: int, user_id: int, clock_in_iso: str):
    with db() as conn:
        conn.execute("""
            INSERT INTO timeclock_sessions (guild_id, user_id, clock_in_time)
            VALUES (%s, %s, %s)
        """, (guild_id, user_id, clock_in_iso))

def close_session(session_id: int, clock_out_iso: str, duration_s: int):
    with db() as conn:
        conn.execute("""
            UPDATE timeclock_sessions SET clock_out_time=%s WHERE session_id=%s
        """, (clock_out_iso, session_id))

def get_sessions_report(guild_id: int, user_id: Optional[int], start_utc: str, end_utc: str):
    """Get sessions for report generation within date range (UTC boundaries)."""
    with db() as conn:
        if user_id is not None:
            # Report for specific user
            cur = conn.execute("""
                SELECT user_id, clock_in_time as clock_in, clock_out_time as clock_out,
                       EXTRACT(EPOCH FROM (clock_out_time - clock_in_time))::integer as duration_seconds
                FROM timeclock_sessions
                WHERE guild_id=%s AND user_id=%s 
                AND clock_out_time IS NOT NULL
                AND clock_in_time < %s
                AND clock_out_time >= %s
                ORDER BY clock_in_time
            """, (guild_id, user_id, end_utc, start_utc))
        else:
            # Report for all users
            cur = conn.execute("""
                SELECT user_id, clock_in_time as clock_in, clock_out_time as clock_out,
                       EXTRACT(EPOCH FROM (clock_out_time - clock_in_time))::integer as duration_seconds
                FROM timeclock_sessions
                WHERE guild_id=%s 
                AND clock_out_time IS NOT NULL
                AND clock_in_time < %s
                AND clock_out_time >= %s
                ORDER BY user_id, clock_in_time
            """, (guild_id, end_utc, start_utc))
        return cur.fetchall()



def add_admin_role(guild_id: int, role_id: int):
    """Add a role as admin for Reports/Upgrade button access."""
    with db() as conn:
        # Convert IDs to strings for database storage (Discord snowflakes)
        conn.execute("INSERT INTO admin_roles (guild_id, role_id) VALUES (%s, %s) ON CONFLICT (guild_id, role_id) DO NOTHING", 
                     (str(guild_id), str(role_id)))

def remove_admin_role(guild_id: int, role_id: int):
    """Remove a role from admin Reports/Upgrade button access."""
    with db() as conn:
        # Convert IDs to strings for database storage (Discord snowflakes)
        conn.execute("DELETE FROM admin_roles WHERE guild_id=%s AND role_id=%s", 
                     (str(guild_id), str(role_id)))

def get_admin_roles(guild_id: int):
    """Get all admin role IDs for a guild. Returns integers for Discord.py compatibility."""
    with db() as conn:
        cur = conn.execute("SELECT role_id FROM admin_roles WHERE guild_id=%s", (str(guild_id),))
        # Convert back to int for Discord.py (role.id is an int)
        return [int(row['role_id']) for row in cur.fetchall()]

def user_has_admin_access(user: discord.Member):
    """Check if user has admin access (Discord admin OR custom admin role OR main admin role)."""
    # Check Discord administrator permission first
    if user.guild_permissions.administrator:
        return True
    
    user_role_ids = [role.id for role in user.roles]
    
    # Check main admin role (primary designated admin role)
    main_admin_role_id = get_guild_setting(user.guild.id, "main_admin_role_id")
    if main_admin_role_id:
        # Convert to int for comparison with Discord.py role IDs
        try:
            if int(main_admin_role_id) in user_role_ids:
                return True
        except (ValueError, TypeError):
            pass
    
    # Check custom admin roles (additional admin roles) - already returns ints
    admin_roles = get_admin_roles(user.guild.id)
    return any(role_id in user_role_ids for role_id in admin_roles)

def add_employee_role(guild_id: int, role_id: int):
    """Add a role that can use timeclock functions."""
    with db() as conn:
        # Convert IDs to strings for database storage (Discord snowflakes)
        cursor = conn.execute("INSERT INTO employee_roles (guild_id, role_id) VALUES (%s, %s) ON CONFLICT (guild_id, role_id) DO NOTHING", 
                     (str(guild_id), str(role_id)))
        if cursor.rowcount > 0:
            print(f"✅ Added employee role {role_id} to guild {guild_id}")
        else:
            print(f"ℹ️ Employee role {role_id} already exists for guild {guild_id}")

def remove_employee_role(guild_id: int, role_id: int):
    """Remove a role from timeclock functions access."""
    with db() as conn:
        # Convert IDs to strings for database storage (Discord snowflakes)
        cursor = conn.execute("DELETE FROM employee_roles WHERE guild_id=%s AND role_id=%s", 
                     (str(guild_id), str(role_id)))
        if cursor.rowcount > 0:
            print(f"✅ Removed employee role {role_id} from guild {guild_id}")
        else:
            print(f"⚠️ Employee role {role_id} not found for guild {guild_id}")

def get_employee_roles(guild_id: int):
    """Get all clock role IDs for a guild. Returns integers for Discord.py compatibility."""
    with db() as conn:
        cur = conn.execute("SELECT role_id FROM employee_roles WHERE guild_id=%s", (str(guild_id),))
        # Convert back to int for Discord.py (role.id is an int)
        return [int(row['role_id']) for row in cur.fetchall()]

def user_has_clock_access(user: discord.Member, server_tier: str):
    """Check if user can access clock buttons based on server tier and roles."""
    guild_id = user.guild.id
    
    # All tiers: check clock roles OR admin access
    # If no clock roles are configured, default to admin-only
    employee_roles = get_employee_roles(guild_id)
    if not employee_roles:
        return user_has_admin_access(user)
    
    # Check if user has any of the configured clock roles
    user_role_ids = [role.id for role in user.roles]
    has_clock_role = any(role_id in user_role_ids for role_id in employee_roles)
    
    # Allow access if user has clock role OR admin access
    return has_clock_role or user_has_admin_access(user)


def get_user_hours_info(guild_id: int, user_id: int, guild_tz_name: str = "America/New_York"):
    """Get current session, daily, and weekly hours for a user."""
    from zoneinfo import ZoneInfo

    try:
        guild_tz = ZoneInfo(guild_tz_name)
    except Exception:
        guild_tz = ZoneInfo('UTC')
    
    now = datetime.now(timezone.utc)
    
    # Current session time
    active_session = get_active_session(guild_id, user_id)
    current_session_seconds = 0
    if active_session:
        session_id = active_session['id']
        clock_in_iso = active_session['clock_in']
        start_dt = safe_parse_timestamp(clock_in_iso)
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
            SELECT clock_in_time as clock_in, clock_out_time as clock_out FROM timeclock_sessions
            WHERE guild_id=%s AND user_id=%s AND clock_out_time IS NOT NULL
            AND clock_in_time < %s AND clock_out_time >= %s
        """, (guild_id, user_id, now_utc, today_start_utc))
        daily_sessions = daily_cur.fetchall()
        
        daily_seconds = 0
        for session in daily_sessions:
            clock_in_dt = safe_parse_timestamp(session['clock_in'])
            clock_out_dt = safe_parse_timestamp(session['clock_out'])
            today_start_dt = datetime.fromisoformat(today_start_utc)
            
            # Calculate overlap with today
            overlap_start = max(clock_in_dt, today_start_dt)
            overlap_end = min(clock_out_dt, now)
            
            if overlap_end > overlap_start:
                daily_seconds += int((overlap_end - overlap_start).total_seconds())
        
        # Weekly hours (sessions that overlap with this week)
        weekly_cur = conn.execute("""
            SELECT clock_in_time as clock_in, clock_out_time as clock_out FROM timeclock_sessions
            WHERE guild_id=%s AND user_id=%s AND clock_out_time IS NOT NULL
            AND clock_in_time < %s AND clock_out_time >= %s
        """, (guild_id, user_id, now_utc, week_start_utc))
        weekly_sessions = weekly_cur.fetchall()
        
        weekly_seconds = 0
        for session in weekly_sessions:
            clock_in_dt = safe_parse_timestamp(session['clock_in'])
            clock_out_dt = safe_parse_timestamp(session['clock_out'])
            week_start_dt = datetime.fromisoformat(week_start_utc)
            
            # Calculate overlap with this week
            overlap_start = max(clock_in_dt, week_start_dt)
            overlap_end = min(clock_out_dt, now)
            
            if overlap_end > overlap_start:
                weekly_seconds += int((overlap_end - overlap_start).total_seconds())
    
    return current_session_seconds, daily_seconds, weekly_seconds

async def fetch_formatted_employee_name(bot, guild_id, user_id):
    """
    Fetch the appropriately formatted name for a user based on the guild's report_name_format setting.
    This replaces raw Discord User IDs with clean, customizable names on exports.
    """
    with db() as conn:
        # Get formatting preference
        cursor = conn.execute("SELECT report_name_format FROM guild_settings WHERE guild_id = %s", (guild_id,))
        row = cursor.fetchone()
        name_format = row['report_name_format'] if row and row.get('report_name_format') else 'full_name'
        
        # Get profile data
        cursor = conn.execute("SELECT full_name, display_name FROM employee_profiles WHERE guild_id = %s AND user_id = %s", (guild_id, user_id))
        emp_row = cursor.fetchone()
        
    db_full_name = emp_row['full_name'] if emp_row and emp_row.get('full_name') else None
    db_display_name = emp_row['display_name'] if emp_row and emp_row.get('display_name') else None
    
    # Format 1: Raw ID
    if name_format == 'user_id_only':
        return str(user_id)
        
    # Format 2: Strict Discord Username (@txclone)
    if name_format == 'discord_username':
        try:
            discord_user = bot.get_user(user_id) or await bot.fetch_user(user_id)
            return discord_user.name
        except:
            return db_display_name or f"User-{user_id}"
            
    # Format 3: Discord Server Nickname
    if name_format == 'discord_nickname_or_username':
        try:
            guild = bot.get_guild(guild_id)
            if guild:
                member = guild.get_member(user_id) or await guild.fetch_member(user_id)
                return member.display_name
        except:
            pass # fallback below
        return db_display_name or f"User-{user_id}"
        
    # Format 4: Full Name (Default)
    if name_format == 'full_name':
        if db_full_name:
            return db_full_name
            
    # Absolute Fallback (if they chose full_name but never typed it, or if all else failed)
    return db_display_name or f"User-{user_id}"

async def generate_csv_report(bot, sessions_data, guild_id, guild_tz="America/New_York"):
    """Generate organized CSV content from sessions data with usernames."""
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Group sessions by user
    user_sessions = {}
    for session_row in sessions_data:
        user_id = session_row['user_id']
        clock_in = safe_parse_timestamp(session_row['clock_in'])
        clock_out = safe_parse_timestamp(session_row['clock_out'])
        duration_seconds = session_row['duration_seconds']
        if user_id not in user_sessions:
            user_sessions[user_id] = []
        user_sessions[user_id].append((clock_in, clock_out, duration_seconds))
    
    # Generate organized format for each user
    for user_id, sessions in user_sessions.items():
        # Fetch formatted name based on Guild Settings preference
        user_display_name = await fetch_formatted_employee_name(bot, guild_id, user_id)
        
        # Calculate date range for this user
        all_dates = []
        for clock_in, _, _ in sessions:
            date_formatted = fmt(clock_in, guild_tz).split()[0]
            all_dates.append(date_formatted)
        
        date_range = f"{min(all_dates)} to {max(all_dates)}" if len(set(all_dates)) > 1 else min(all_dates)
        
        # Employee header with username
        sanitized_name = sanitize_csv_string(user_display_name)
        writer.writerow([f"Employee: {sanitized_name} - Shift Report ({date_range})"])
        writer.writerow([])  # Empty row
        
        # Process each session for this user
        for clock_in, clock_out, duration_seconds in sessions:
            # Format day and times
            day_of_week = clock_in.strftime("%A")  # Full day name
            date_str = fmt(clock_in, guild_tz).split()[0]
            in_time = fmt(clock_in, guild_tz).split()[1:3]  # Time and timezone
            out_time = fmt(clock_out, guild_tz).split()[1:3]
            
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

async def generate_individual_csv_report(bot, user_id, sessions, guild_id, guild_tz="America/New_York"):
    """Generate CSV for a single user."""
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Fetch formatted name based on Guild Settings preference
    user_display_name = await fetch_formatted_employee_name(bot, guild_id, user_id)
    
    # Calculate date range for this user
    all_dates = []
    for clock_in, _, _ in sessions:
        date_formatted = fmt(clock_in, guild_tz).split()[0]
        all_dates.append(date_formatted)
    
    date_range = f"{min(all_dates)} to {max(all_dates)}" if len(set(all_dates)) > 1 else min(all_dates)
    
    # Employee header with username
    sanitized_name = sanitize_csv_string(user_display_name)
    writer.writerow([f"Employee: {sanitized_name} - Shift Report ({date_range})"])
    writer.writerow([])  # Empty row
    
    # Process each session for this user
    for clock_in, clock_out, duration_seconds in sessions:
        # Format day and times
        day_of_week = clock_in.strftime("%A")  # Full day name
        date_str = fmt(clock_in, guild_tz).split()[0]
        in_time = fmt(clock_in, guild_tz).split()[1:3]  # Time and timezone
        out_time = fmt(clock_out, guild_tz).split()[1:3]
        
        # Duration in decimal hours
        total_hours = round(duration_seconds / 3600, 2)
        
        # Write shift details
        writer.writerow([f"{day_of_week} ({date_str}):"])
        writer.writerow([f"IN - {' '.join(in_time)}"])
        writer.writerow([f"OUT - {' '.join(out_time)}"])
        writer.writerow([f"{total_hours} total hours"])
        writer.writerow([])  # Empty row between shifts
    
    return output.getvalue(), user_display_name

async def generate_payroll_csv_report(bot, sessions_data, guild_id, guild_tz="America/New_York"):
    """Generate Quickbooks/Gusto compatible Payroll CSV."""
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Standard Payroll Headers
    writer.writerow(["Employee Name", "Date", "Regular Hours", "Overtime Hours", "Total Hours", "Notes"])
    
    # Group sessions by user and date
    user_daily_totals = {}
    for session_row in sessions_data:
        user_id = session_row['user_id']
        clock_in = safe_parse_timestamp(session_row['clock_in'])
        duration_seconds = session_row['duration_seconds']
        
        date_formatted = fmt(clock_in, guild_tz).split()[0]
        
        if user_id not in user_daily_totals:
            user_daily_totals[user_id] = {}
            
        if date_formatted not in user_daily_totals[user_id]:
            user_daily_totals[user_id][date_formatted] = 0
            
        user_daily_totals[user_id][date_formatted] += duration_seconds
        
    for user_id, daily_data in user_daily_totals.items():
        # Fetch formatted name based on Guild Settings preference
        user_display_name = await fetch_formatted_employee_name(bot, guild_id, user_id)
            
        for date_str, total_seconds in sorted(daily_data.items()):
            total_hours = round(total_seconds / 3600, 2)
            
            # Simple Overtime calculation (over 8 hours a day)
            regular_hours = min(8.0, total_hours)
            overtime_hours = max(0.0, total_hours - 8.0)
            
            writer.writerow([
                sanitize_csv_string(user_display_name),
                date_str,
                f"{regular_hours:.2f}",
                f"{overtime_hours:.2f}",
                f"{total_hours:.2f}",
                ""
            ])
            
    return output.getvalue()


async def generate_pdf_report(bot, sessions_data, guild_id, guild_tz="America/New_York"):
    """Generate a branded PDF Report using ReportLab."""
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    
    output = io.BytesIO()
    doc = SimpleDocTemplate(output, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    
    styles = getSampleStyleSheet()
    title_style = styles['Heading1']
    title_style.alignment = 1 # Center
    
    # Check if a custom guild name is configured, else fallback to Discord API name
    guild_settings = get_guild_settings(guild_id)
    guild_name = guild_settings.get('custom_guild_name')
    if not guild_name:
        guild = bot.get_guild(guild_id)
        guild_name = guild.name if guild else f"Server {guild_id}"
        
    elements = []
    
    # Title
    elements.append(Paragraph(f"<b>{guild_name}</b>", title_style))
    elements.append(Paragraph("Official Timesheet Report", styles['Heading3']))
    elements.append(Spacer(1, 20))
    
    # Group sessions by user
    user_sessions = {}
    for session_row in sessions_data:
        user_id = session_row['user_id']
        clock_in = safe_parse_timestamp(session_row['clock_in'])
        clock_out = safe_parse_timestamp(session_row['clock_out'])
        duration_seconds = session_row['duration_seconds']
        if user_id not in user_sessions:
            user_sessions[user_id] = []
        user_sessions[user_id].append((clock_in, clock_out, duration_seconds))
        
    for user_id, sessions in user_sessions.items():
        # Fetch formatted name based on Guild Settings preference
        user_display_name = await fetch_formatted_employee_name(bot, guild_id, user_id)
            
        elements.append(Paragraph(f"<b>Employee: {user_display_name}</b>", styles['Heading4']))
        elements.append(Spacer(1, 5))
        
        table_data = [["Date", "Clock In", "Clock Out", "Hours"]]
        
        total_hours_for_user = 0.0
        
        for clock_in, clock_out, duration_seconds in sessions:
            date_str = fmt(clock_in, guild_tz).split()[0]
            in_time = " ".join(fmt(clock_in, guild_tz).split()[1:3])
            out_time = " ".join(fmt(clock_out, guild_tz).split()[1:3])
            
            hours = round(duration_seconds / 3600, 2)
            total_hours_for_user += hours
            
            table_data.append([date_str, in_time, out_time, f"{hours:.2f}h"])
            
        # Add summary row
        table_data.append(["", "", "Total:", f"<b>{total_hours_for_user:.2f}h</b>"])
            
        t = Table(table_data, colWidths=[100, 150, 150, 80])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#D4AF37')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.black),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0,0), (-1,-1), 1, colors.lightgrey),
            # Bold the total row
            ('FONTNAME', (0,-1), (-1,-1), 'Helvetica-Bold')
        ]))
        
        elements.append(t)
        elements.append(Spacer(1, 30))
        
    doc.build(elements)
    
    return output.getvalue()


# --- Time helpers ---
def now_utc():
    return datetime.now(timezone.utc)

def safe_parse_timestamp(value):
    """Safely parse a timestamp value from database - handles both datetime objects and ISO strings
    Always returns timezone-aware datetime in UTC to prevent naive/aware subtraction errors"""
    if isinstance(value, datetime):
        parsed_dt = value
    elif isinstance(value, str):
        parsed_dt = datetime.fromisoformat(value)
    else:
        raise ValueError(f"Cannot parse timestamp from type {type(value)}: {value}")
    
    # Ensure timezone awareness - if naive, assume UTC
    if parsed_dt.tzinfo is None:
        parsed_dt = parsed_dt.replace(tzinfo=timezone.utc)
    
    return parsed_dt

def fmt(dt: datetime, tz_name: Optional[str]) -> str:
    try:
        from zoneinfo import ZoneInfo
        tz = ZoneInfo(tz_name) if tz_name else ZoneInfo("America/New_York")
    except Exception:
        tz = ZoneInfo('UTC')
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

def format_duration_hhmmss(seconds: int) -> str:
    """Format seconds into HH:MM:SS format"""
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = int(seconds % 60)
    return f"{h:02d}:{m:02d}:{s:02d}"

def purge_timeclock_data_only(guild_id: int):
    """Standalone function to purge only timeclock sessions data, preserving subscription and core settings"""
    try:
        with db() as conn:
            # Set timeout for database operations
                        # Delete all sessions data only
            sessions_cursor = conn.execute("DELETE FROM timeclock_sessions WHERE guild_id = %s", (guild_id,))
            sessions_deleted = sessions_cursor.rowcount
            
            print(f"🗑️ Timeclock data purged for Guild {guild_id}: {sessions_deleted} sessions deleted (subscription preserved)")
            
    except Exception as e:
        print(f"❌ Error purging timeclock data for {guild_id}: {e}")
        raise e  # Re-raise so the error can be caught by the calling function

def format_shift_duration(seconds: int) -> str:
    """Format seconds into clean 'X hrs Y mins' format"""
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = int(seconds % 60)
    
    if h > 0:
        return f"{h} hr{'s' if h != 1 else ''} {m} min{'s' if m != 1 else ''}"
    elif m > 0:
        return f"{m} min{'s' if m != 1 else ''} {s} sec{'s' if s != 1 else ''}"
    else:
        return f"{s} second{'s' if s != 1 else ''}"

def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent path traversal and ensure safe file names"""
    import re
    
    # Remove path separators and other unsafe characters
    filename = re.sub(r'[/\\:*?"<>|]', '_', filename)
    
    # Replace multiple underscores with single underscore
    filename = re.sub(r'_+', '_', filename)
    
    # Remove leading/trailing whitespace and underscores
    filename = filename.strip(' _')
    
    # Limit length to 50 characters
    if len(filename) > 50:
        filename = filename[:47] + '...'
    
    # Ensure we don't end up with empty filename
    if not filename or filename.isspace():
        filename = "user"
    
    return filename

# --- Employee Management Helpers ---
def ensure_employee_profile(guild_id: int, user_id: int, username: str, display_name: str, avatar_url: str | None) -> bool:
    """
    Ensure an employee profile exists. If not, create a default one.
    Returns True if a new profile was created, False if it already existed.
    """
    with db() as conn:
        # Check if profile exists
        cursor = conn.execute(
            "SELECT 1 FROM employee_profiles WHERE guild_id = %s AND user_id = %s",
            (guild_id, user_id)
        )
        if cursor.fetchone():
            return False
            
        # PHASE 2: Free Tier App-Wide 3-User Hard-Cap (Lazy initialization block)
        server_tier = get_guild_tier_string(guild_id)
        if server_tier == 'free':
            cursor = conn.execute("SELECT COUNT(*) as count FROM employee_profiles WHERE guild_id = %s AND is_active = TRUE", (guild_id,))
            active_count = cursor.fetchone()['count']
            if active_count >= 3:
                print(f"🔒 Lazy profile creation blocked for {username} in guild {guild_id}: Free tier limit (3) reached.")
                return False # Do not create the profile
            
        # Create default profile
        conn.execute("""
            INSERT INTO employee_profiles 
            (guild_id, user_id, full_name, display_name, avatar_url, 
             position, department, hire_date, is_active, 
             show_last_seen, show_discord_status, profile_setup_completed)
            VALUES (%s, %s, %s, %s, %s, 'Employee', 'General', NOW(), TRUE, TRUE, TRUE, FALSE)
        """, (guild_id, user_id, username, display_name, avatar_url))
        print(f"👤 Created default employee profile for {username} ({user_id}) in guild {guild_id}")
        return True

def generate_profile_setup_token(guild_id: int, user_id: int) -> str:
    """Generate a secure token for profile setup."""
    import uuid
    token = str(uuid.uuid4())
    from datetime import timedelta
    expires_at = datetime.now(timezone.utc) + timedelta(days=30)
    
    with db() as conn:
        conn.execute("""
            INSERT INTO employee_profile_tokens 
            (token, guild_id, user_id, created_at, expires_at, is_used, delivery_method)
            VALUES (%s, %s, %s, NOW(), %s, FALSE, 'dm')
        """, (token, guild_id, user_id, expires_at))
        
    return token

def archive_employee(guild_id: int, user_id: int, reason: str = "left_server"):
    """Archive an employee profile."""
    with db() as conn:
        # Get current profile data
        cursor = conn.execute(
            "SELECT * FROM employee_profiles WHERE guild_id = %s AND user_id = %s",
            (guild_id, user_id)
        )
        profile = cursor.fetchone()
        
        if not profile:
            return
            
        # Create archive record
        conn.execute("""
            INSERT INTO employee_archive
            (guild_id, user_id, original_profile_data, archived_at, termination_reason)
            VALUES (%s, %s, %s, NOW(), %s)
            ON CONFLICT (guild_id, user_id) DO UPDATE
            SET original_profile_data = EXCLUDED.original_profile_data,
                archived_at = NOW(),
                termination_reason = EXCLUDED.termination_reason,
                reactivated_at = NULL
        """, (guild_id, user_id, json.dumps(profile, default=str), reason))
        
        # Mark profile as inactive
        conn.execute("""
            UPDATE employee_profiles 
            SET is_active = FALSE 
            WHERE guild_id = %s AND user_id = %s
        """, (guild_id, user_id))
        
        print(f"📦 Archived employee {user_id} in guild {guild_id} (Reason: {reason})")

def reactivate_employee(guild_id: int, user_id: int):
    """Reactivate an archived employee profile."""
    with db() as conn:
        # Check if archived
        cursor = conn.execute(
            "SELECT 1 FROM employee_archive WHERE guild_id = %s AND user_id = %s",
            (guild_id, user_id)
        )
        if not cursor.fetchone():
            return
            
        # Reactivate profile
        conn.execute("""
            UPDATE employee_profiles 
            SET is_active = TRUE 
            WHERE guild_id = %s AND user_id = %s
        """, (guild_id, user_id))
        
        # Update archive record
        conn.execute("""
            UPDATE employee_archive
            SET reactivated_at = NOW()
            WHERE guild_id = %s AND user_id = %s
        """, (guild_id, user_id))
        
        print(f"♻️ Reactivated employee {user_id} in guild {guild_id}")

# Debounce cache for presence updates
presence_update_cache: dict[tuple[int, int], float] = {}

def update_employee_presence(guild_id: int, user_id: int, status: str):
    """Update employee's last seen status with debounce."""
    key = (guild_id, user_id)
    now = time.time()

    # Debounce: Only update every 5 minutes per user
    if key in presence_update_cache and now - presence_update_cache[key] < 300:
        return

    presence_update_cache[key] = now
    
    try:
        with db() as conn:
            conn.execute("""
                UPDATE employee_profiles 
                SET last_seen_discord = NOW(), 
                    discord_status = %s
                WHERE guild_id = %s AND user_id = %s AND is_active = TRUE
            """, (status, guild_id, user_id))
    except Exception as e:
        print(f"Error updating presence for {user_id}: {e}")

# --- Discord bot ---
intents = discord.Intents.default()
intents.presences = True  # Required for is_on_mobile() to work
intents.members = True    # Also required for is_on_mobile() to work properly
# Note: members and presences intents require privileged intent in Discord Developer Portal
# Make sure these are enabled in the Discord Developer Portal settings
bot = commands.Bot(command_prefix="!", intents=intents)
tree = bot.tree

# Register persistent views at startup to handle interactions after bot restart
async def setup_hook():
    """Setup hook to register persistent views when bot starts"""
    print("🔧 Registering persistent views...")
    
    # Register TimeClockView with ALL button callbacks defined
    # This ensures buttons work after bot reboots (2025 Discord best practices)
    # All 7 buttons are registered here so Discord can match interactions to callbacks
    bot.add_view(TimeClockView())
    print("✅ TimeClockView registered with all 7 persistent buttons")
    
    # Register SetupInstructionsView for welcome messages
    bot.add_view(SetupInstructionsView())
    print("✅ SetupInstructionsView registered")
    
    # Register TimeclockHubView for bulletproof button persistence
    # Uses stable "tc:" prefixed custom_ids for maximum reliability
    bot.add_view(TimeclockHubView())
    print("✅ TimeclockHubView registered with bulletproof persistence")

    # Register DemoRoleSwitcherView for demo server role switching
    bot.add_view(DemoRoleSwitcherView())
    print("✅ DemoRoleSwitcherView registered for demo server")

    print("✅ Persistent view setup complete - ephemeral interface mode")

bot.setup_hook = setup_hook  # type: ignore[method-assign]

@bot.event
async def on_member_remove(member):
    """Handle member leaving - archive employee profile"""
    try:
        # Check if they were an employee (had profile)
        archive_employee(member.guild.id, member.id, reason="left_server")
    except Exception as e:
        print(f"Error in on_member_remove for {member.id}: {e}")

@bot.event
async def on_member_update(before, after):
    """Handle member updates - check for role changes to reactivate and send welcome DM"""
    if before.roles == after.roles:
        return
        
    try:
        guild_id = after.guild.id
        employee_roles = get_employee_roles(guild_id)
        
        # Check if they gained an employee role
        had_role = any(r.id in employee_roles for r in before.roles)
        has_role = any(r.id in employee_roles for r in after.roles)
        
        if not had_role and has_role:
            # Employee role added - reactivate if archived
            reactivate_employee(guild_id, after.id)
            
            # Ensure profile exists (creates new if needed)
            is_new_employee = ensure_employee_profile(
                guild_id, after.id, 
                after.name, after.display_name, 
                str(after.avatar.url) if after.avatar else str(after.default_avatar.url)
            )
            
            # Skip demo server - it has its own on_member_join welcome handler
            if guild_id == DEMO_SERVER_ID:
                print(f"Skipping standard welcome DM for demo server member: {after}")
                return
            
            # Check if welcome DM was already sent (for existing profiles)
            should_send_dm = is_new_employee
            if not is_new_employee:
                with db() as conn:
                    cursor = conn.execute(
                        "SELECT welcome_dm_sent FROM employee_profiles WHERE guild_id = %s AND user_id = %s",
                        (guild_id, after.id)
                    )
                    row = cursor.fetchone()
                    should_send_dm = not (row and row.get('welcome_dm_sent', False))
            
            # Send welcome DM to new employees
            if should_send_dm:
                await send_employee_welcome_dm(after, after.guild)
                print(f"New employee role assigned: {after} in {after.guild.name}")
            
    except Exception as e:
        print(f"Error in on_member_update for {after.id}: {e}")

@bot.event
async def on_presence_update(before, after):
    """Track employee activity"""
    try:
        if after.bot:
            return
            
        status_map = {
            discord.Status.online: 'online',
            discord.Status.idle: 'idle',
            discord.Status.dnd: 'dnd',
            discord.Status.offline: 'offline'
        }
        
        status = status_map.get(after.status, 'offline')
        update_employee_presence(after.guild.id, after.id, status)
        
    except Exception as e:
        # Fail silently to avoid log spam
        pass

class TimeClockView(discord.ui.View):
    """
    Persistent timeclock view following 2025 Discord best practices.
    
    All buttons are defined using @discord.ui.button decorators with unique custom_id values.
    This ensures buttons work correctly after bot reboots - Discord can match button clicks
    to the registered view callbacks even when the bot restarts.
    
    Tier-specific logic is handled in the callback functions, not by conditionally
    showing/hiding buttons. This is required for proper persistence.
    """
    def __init__(self):
        super().__init__(timeout=None)  # REQUIRED for persistence
    
    # Row 0: Core timeclock buttons
    @discord.ui.button(
        label="Clock In",
        style=discord.ButtonStyle.success,
        custom_id="timeclock:clock_in",
        row=0
    )
    async def clock_in_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Clock in button callback"""
        await self.clock_in(interaction)
    
    @discord.ui.button(
        label="Clock Out",
        style=discord.ButtonStyle.danger,
        custom_id="timeclock:clock_out",
        row=0
    )
    async def clock_out_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Clock out button callback"""
        await self.clock_out(interaction)
    
    @discord.ui.button(
        label="Help",
        style=discord.ButtonStyle.primary,
        custom_id="timeclock:help",
        row=0
    )
    async def help_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Help button callback"""
        await self.show_help(interaction)
    
    @discord.ui.button(
        label="On the Clock",
        style=discord.ButtonStyle.secondary,
        custom_id="timeclock:onclock",
        row=0
    )
    async def onclock_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """On the clock button callback"""
        await self.on_the_clock(interaction)
    
    # Row 1: Dashboard and conditional buttons (Reports/Upgrade)
    @discord.ui.button(
        label="Dashboard",
        style=discord.ButtonStyle.primary,
        custom_id="timeclock:dashboard",
        emoji="📊",
        row=1
    )
    async def dashboard_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Dashboard button callback"""
        await self.show_dashboard(interaction)
    
    @discord.ui.button(
        label="Reports",
        style=discord.ButtonStyle.success,
        custom_id="timeclock:reports",
        row=1
    )
    async def reports_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Reports button callback - handles tier check internally"""
        await self.generate_reports(interaction)
    
    @discord.ui.button(
        label="Upgrade",
        style=discord.ButtonStyle.secondary,
        custom_id="timeclock:upgrade",
        emoji="🚀",
        row=1
    )
    async def upgrade_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Upgrade button callback"""
        await self.show_upgrade(interaction)

    async def on_the_clock(self, interaction: discord.Interaction):
        """Show all currently clocked in users with their times"""
        # Robust defer with proper fallback
        defer_success = await robust_defer(interaction, ephemeral=True)
        if not defer_success and not interaction.response.is_done():
            # If defer failed and interaction isn't done, we can't proceed
            return
        
        if interaction.guild is None:
            await interaction.followup.send("Use this in a server.", ephemeral=True)
            return
            
        guild_id = interaction.guild.id
        user_id = interaction.user.id
        
        # RATE LIMITING: Check for spam/abuse
        is_allowed, request_count, action = check_rate_limit(guild_id, user_id, "on_the_clock")
        if not is_allowed:
            await handle_rate_limit_response(interaction, action)
            return

        # Check clock access permissions
        server_tier = get_guild_tier_string(guild_id)
        # Type guard: ensure we have a Member for guild-specific functions
        if not isinstance(interaction.user, discord.Member):
            await interaction.followup.send(
                "❌ Unable to verify access permissions. Please try again.",
                ephemeral=True
            )
            return
        
        if not user_has_clock_access(interaction.user, server_tier):
            await interaction.followup.send(
                "🔒 **Access Restricted**\n"
                "You need an employee role to use the timeclock.\n"
                "Ask an administrator to add your role with `/add_employee_role @yourrole`",
                ephemeral=True
            )
            return
        
        try:
            # Get all currently clocked in users
            with db() as conn:
                cursor = conn.execute("""
                    SELECT user_id, clock_in_time as clock_in 
                    FROM timeclock_sessions 
                    WHERE guild_id = %s AND clock_out_time IS NULL
                    ORDER BY clock_in_time ASC
                """, (guild_id,))
                active_sessions = cursor.fetchall()
            
            if not active_sessions:
                embed = discord.Embed(
                    title="⏰ On the Clock",
                    description="No one is currently clocked in.",
                    color=discord.Color.gold()
                )
                await interaction.followup.send(embed=embed, ephemeral=True)
                return
            
            # Get timezone setting
            tz_name = get_guild_setting(guild_id, "timezone", DEFAULT_TZ)
            
            try:
                from zoneinfo import ZoneInfo
                guild_tz = ZoneInfo(tz_name or DEFAULT_TZ)
            except (ImportError, Exception):
                # If timezone or ZoneInfo import fails, fallback to EST instead of UTC
                try:
                    from zoneinfo import ZoneInfo
                    guild_tz = ZoneInfo(DEFAULT_TZ)
                    tz_name = "America/New_York (EST)"
                except ImportError:
                    # ZoneInfo not available, use UTC
                    guild_tz = ZoneInfo('UTC')
                    tz_name = "UTC"
            
            embed = discord.Embed(
                title="🕒 Team Currently On the Clock",
                description=f"📊 **{len(active_sessions)} active team member{'s' if len(active_sessions) != 1 else ''}**",
                color=discord.Color.blurple()
            )
            
            now_utc = datetime.now(timezone.utc)
            
            # Sort users by clock in time for organized display
            sorted_sessions = sorted(active_sessions, key=lambda x: x['clock_in'])
            
            user_details = []
            for i, session in enumerate(sorted_sessions, 1):
                user_id = session['user_id']
                clock_in_iso = session['clock_in']
                try:
                    # Get user with proper Discord nickname
                    user = interaction.guild.get_member(user_id)
                    if user:
                        # Always use Discord nickname (display_name) which includes server nick
                        display_name = user.display_name
                        user_mention = user.mention
                    else:
                        # Fallback to trying to get user from cache
                        try:
                            user = await interaction.client.fetch_user(user_id)
                            display_name = user.display_name if hasattr(user, 'display_name') else user.name
                            user_mention = f"<@{user_id}>"
                        except:
                            display_name = f"Unknown User"
                            user_mention = f"<@{user_id}>"
                    
                    # Parse clock in time
                    clock_in_utc = safe_parse_timestamp(clock_in_iso)
                    if clock_in_utc.tzinfo is None:
                        clock_in_utc = clock_in_utc.replace(tzinfo=timezone.utc)
                    clock_in_local = clock_in_utc.astimezone(guild_tz)
                    
                    # Calculate total time for today in this timezone
                    local_date = clock_in_local.date()
                    day_start = datetime.combine(local_date, datetime.min.time()).replace(tzinfo=guild_tz)
                    day_end = datetime.combine(local_date, datetime.max.time()).replace(tzinfo=guild_tz)
                    
                    # Get all sessions for today
                    day_start_utc = day_start.astimezone(timezone.utc).isoformat()
                    day_end_utc = day_end.astimezone(timezone.utc).isoformat()
                    
                    with db() as conn:
                        cursor = conn.execute("""
                            SELECT clock_in_time as clock_in, clock_out_time as clock_out 
                            FROM timeclock_sessions 
                            WHERE guild_id = %s AND user_id = %s 
                            AND clock_in_time >= %s AND clock_in_time <= %s
                        """, (guild_id, user_id, day_start_utc, day_end_utc))
                        day_sessions = cursor.fetchall()
                    
                    # Calculate total day seconds
                    total_day_seconds = 0
                    for day_session in day_sessions:
                        session_in = safe_parse_timestamp(day_session['clock_in'])
                        session_out_raw = day_session['clock_out']
                        if session_out_raw:  # Completed session
                            session_out = safe_parse_timestamp(session_out_raw)
                            if session_in.tzinfo is None:
                                session_in = session_in.replace(tzinfo=timezone.utc)
                            if session_out.tzinfo is None:
                                session_out = session_out.replace(tzinfo=timezone.utc)
                            total_day_seconds += (session_out - session_in).total_seconds()
                        else:  # Current active session
                            if session_in.tzinfo is None:
                                session_in = session_in.replace(tzinfo=timezone.utc)
                            total_day_seconds += (now_utc - session_in).total_seconds()
                    
                    # Current shift time
                    shift_seconds = (now_utc - clock_in_utc).total_seconds()
                    
                    # Format times
                    clock_in_time = clock_in_local.strftime("%I:%M %p")
                    total_day_time = format_duration_hhmmss(int(total_day_seconds))
                    shift_time = format_shift_duration(int(shift_seconds))
                    
                    # Create fancy formatted entry
                    user_entry = (
                        f"**#{i}** {user_mention} • **{display_name}**\n"
                        f"🟢 **Clocked In:** {clock_in_time}\n"
                        f"📅 **Today's Total:** {total_day_time}\n"
                        f"⏱️ **Current Shift:** {shift_time}\n"
                        f"{'─' * 35}"
                    )
                    user_details.append(user_entry)
                    
                except Exception as e:
                    print(f"Error processing user {user_id}: {e}")
                    # Fallback with better formatting even for errors
                    user_entry = (
                        f"**#{i}** <@{user_id}> • **Unknown User**\n"
                        f"❌ **Error loading time data**\n"
                        f"{'─' * 35}"
                    )
                    user_details.append(user_entry)
            
            # Add users to embed with nice organization
            if len(user_details) <= 3:
                # If 3 or fewer users, show them all in one field
                embed.add_field(
                    name="👥 Active Team Members",
                    value="\n".join(user_details),
                    inline=False
                )
            else:
                # If more than 3 users, split into multiple fields for better organization
                mid_point = len(user_details) // 2
                
                embed.add_field(
                    name="👥 Active Team Members (Part 1)",
                    value="\n".join(user_details[:mid_point]),
                    inline=True
                )
                
                embed.add_field(
                    name="👥 Active Team Members (Part 2)", 
                    value="\n".join(user_details[mid_point:]),
                    inline=True
                )
            
            embed.add_field(
                name="Timezone",
                value=tz_name,
                inline=True
            )
            
            await interaction.followup.send(embed=embed, ephemeral=True)
            
        except Exception as e:
            await interaction.followup.send(
                "❌ Error retrieving active users. Please try again.", 
                ephemeral=True
            )
            print(f"Error in on_the_clock: {e}")

    async def clock_in(self, interaction: discord.Interaction):
        """Handle clock in button interaction with robust error handling"""
        # Robust defer with proper fallback
        defer_success = await robust_defer(interaction, ephemeral=True)
        if not defer_success and not interaction.response.is_done():
            # If defer failed and interaction isn't done, we can't proceed
            return
        
        try:
            if interaction.guild is None:
                await interaction.followup.send("Use this in a server.", ephemeral=True)
                return
                
            guild_id = interaction.guild.id
            user_id = interaction.user.id
            
            # RATE LIMITING: Check for spam/abuse
            is_allowed, request_count, action = check_rate_limit(guild_id, user_id, "clock_in")
            if not is_allowed:
                await handle_rate_limit_response(interaction, action)
                return

            # Check clock access permissions
            server_tier = get_guild_tier_string(guild_id)
            # Type guard: ensure we have a Member for guild-specific functions
            if not isinstance(interaction.user, discord.Member):
                await interaction.followup.send(
                    "❌ Unable to verify access permissions. Please try again.",
                    ephemeral=True
                )
                return
            
            if not user_has_clock_access(interaction.user, server_tier):
                await interaction.followup.send(
                    "🔒 **Access Restricted**\n"
                    "You need an employee role to use the timeclock.\n"
                    "Ask an administrator to add your role with `/add_employee_role @yourrole`",
                    ephemeral=True
                )
                return
            
            # Check mobile device restriction
            if is_mobile_restricted(guild_id) and interaction.user.is_on_mobile():
                await interaction.followup.send(
                    "📱 **Mobile Clock-In Restricted**\n"
                    "Your server administrator has disabled mobile/tablet clock-ins.\n"
                    "Please use a desktop or web browser to clock in.",
                    ephemeral=True
                )
                return
            
            # Check kiosk mode restriction
            if is_kiosk_mode_only(guild_id):
                await interaction.followup.send(
                    "📱 **Kiosk Mode Only**\n"
                    "Your server administrator has enabled Kiosk Mode.\n"
                    "Please use the in-store kiosk tablet to clock in.",
                    ephemeral=True
                )
                return
            
            if get_active_session(guild_id, user_id):
                await interaction.followup.send("You're already clocked in.", ephemeral=True)
                return
                
            start_session(guild_id, user_id, now_utc().isoformat())
            
            # --- Profile Setup Logic ---
            profile_message_sent = False
            try:
                avatar_url = str(interaction.user.avatar.url) if interaction.user.avatar else str(interaction.user.default_avatar.url)
                ensure_employee_profile(
                    guild_id, user_id, 
                    interaction.user.name, interaction.user.display_name, 
                    avatar_url
                )
                
                with db() as conn:
                    cursor = conn.execute(
                        "SELECT profile_sent_on_first_clockin, profile_setup_completed FROM employee_profiles WHERE guild_id = %s AND user_id = %s",
                        (guild_id, user_id)
                    )
                    row = cursor.fetchone()
                    
                    if row and not row['profile_sent_on_first_clockin'] and not row['profile_setup_completed']:
                        token = generate_profile_setup_token(guild_id, user_id)
                        domain = get_domain()
                        protocol = "https" if "replit.app" in domain else "http"
                        setup_url = f"{protocol}://{domain}/setup-profile/{token}"
                        
                        await interaction.followup.send(
                            f"✅ **Clocked In!**\n\n"
                            f"👋 **Welcome to the team!**\n"
                            f"Please take a moment to set up your employee profile:\n"
                            f"👉 [**Complete Your Profile**]({setup_url})\n"
                            f"*(This link expires in 30 days)*", 
                            ephemeral=True
                        )
                        profile_message_sent = True
                        
                        conn.execute(
                            "UPDATE employee_profiles SET profile_sent_on_first_clockin = TRUE WHERE guild_id = %s AND user_id = %s",
                            (guild_id, user_id)
                        )
            except Exception as e:
                print(f"Error in profile setup logic: {e}")
            
            if not profile_message_sent:
                await interaction.followup.send("✅ Clocked in. Have a great shift!", ephemeral=True)
            
        except (discord.NotFound, discord.errors.NotFound):
            # Interaction expired or was deleted - silently handle this
            print(f"⚠️ Clock in interaction expired/not found for user {interaction.user.id}")
        except discord.errors.InteractionResponded:
            # Interaction was already responded to - try followup
            try:
                await interaction.followup.send("❌ Button interaction error. Please try again.", ephemeral=True)
            except Exception as e:
                print(f"⚠️ Failed to send followup after InteractionResponded: {e}")
        except Exception as e:
            # General error handling
            print(f"❌ Error in clock_in callback: {e}")
            try:
                if not interaction.response.is_done():
                    await interaction.response.send_message("❌ An error occurred. Please try again.", ephemeral=True)
                else:
                    await interaction.followup.send("❌ An error occurred. Please try again.", ephemeral=True)
            except Exception:
                # If we can't even send an error message, just log it
                print(f"❌ Failed to send error message for clock_in: {e}")

    async def clock_out(self, interaction: discord.Interaction):
        """Handle clock out button interaction with robust error handling"""
        # Robust defer with proper fallback
        defer_success = await robust_defer(interaction, ephemeral=True)
        if not defer_success and not interaction.response.is_done():
            # If defer failed and interaction isn't done, we can't proceed
            return
        
        try:
            if interaction.guild is None:
                await interaction.followup.send("Use this in a server.", ephemeral=True)
                return
                
            guild_id = interaction.guild.id
            user_id = interaction.user.id
            
            # RATE LIMITING: Check for spam/abuse
            is_allowed, request_count, action = check_rate_limit(guild_id, user_id, "clock_out")
            if not is_allowed:
                await handle_rate_limit_response(interaction, action)
                return

            # Check clock access permissions
            server_tier = get_guild_tier_string(guild_id)
            # Type guard: ensure we have a Member for guild-specific functions
            if not isinstance(interaction.user, discord.Member):
                await interaction.followup.send(
                    "❌ Unable to verify access permissions. Please try again.",
                    ephemeral=True
                )
                return
            
            if not user_has_clock_access(interaction.user, server_tier):
                await interaction.followup.send(
                    "🔒 **Access Restricted**\n"
                    "You need an employee role to use the timeclock.\n"
                    "Ask an administrator to add your role with `/add_employee_role @yourrole`",
                    ephemeral=True
                )
                return
            
            # Check mobile device restriction
            if is_mobile_restricted(guild_id) and interaction.user.is_on_mobile():
                await interaction.followup.send(
                    "📱 **Mobile Clock-Out Restricted**\n"
                    "Your server administrator has disabled mobile/tablet clock-outs.\n"
                    "Please use a desktop or web browser to clock out.",
                    ephemeral=True
                )
                return
            
            # Check kiosk mode restriction
            if is_kiosk_mode_only(guild_id):
                await interaction.followup.send(
                    "📱 **Kiosk Mode Only**\n"
                    "Your server administrator has enabled Kiosk Mode.\n"
                    "Please use the in-store kiosk tablet to clock out.",
                    ephemeral=True
                )
                return
            
            active = get_active_session(guild_id, user_id)
            if not active:
                await interaction.followup.send("You don't have an active session.", ephemeral=True)
                return

            session_id = active['id']
            clock_in_iso = active['clock_in']
            start_dt = safe_parse_timestamp(clock_in_iso)
            end_dt = now_utc()
            elapsed = int((end_dt - start_dt).total_seconds())
            close_session(session_id, end_dt.isoformat(), elapsed)

            tz_name = get_guild_setting(guild_id, "timezone", DEFAULT_TZ) or DEFAULT_TZ
            out_msg = f"🔚 Clocked out.\n**In:** {fmt(start_dt, tz_name)}\n**Out:** {fmt(end_dt, tz_name)}\n**Total:** {human_duration(elapsed)}"
            
            # Phase 5: The Review & Feedback Funnel (10% Micro-Prompt)
            import random
            if random.random() < 0.10:
                out_msg += "\n\n*Having a good shift? ⭐ [Leave us a 5-star review on top.gg!](https://top.gg/bot/1418446753379913809#reviews)*"
                
            await interaction.followup.send(out_msg, ephemeral=True)

            # Send notifications to all configured recipients
            await send_timeclock_notifications(guild_id, interaction, start_dt, end_dt, elapsed, tz_name)
                        
        except (discord.NotFound, discord.errors.NotFound):
            # Interaction expired or was deleted - silently handle this
            print(f"⚠️ Clock out interaction expired/not found for user {interaction.user.id}")
        except discord.errors.InteractionResponded:
            # Interaction was already responded to - try followup
            try:
                await interaction.followup.send("❌ Button interaction error. Please try again.", ephemeral=True)
            except Exception as e:
                print(f"⚠️ Failed to send followup after InteractionResponded: {e}")
        except Exception as e:
            # General error handling
            print(f"❌ Error in clock_out callback: {e}")
            try:
                if not interaction.response.is_done():
                    await interaction.response.send_message("❌ An error occurred. Please try again.", ephemeral=True)
                else:
                    await interaction.followup.send("❌ An error occurred. Please try again.", ephemeral=True)
            except Exception:
                # If we can't even send an error message, just log it
                print(f"❌ Failed to send error message for clock_out: {e}")

    async def show_help(self, interaction: discord.Interaction):
        """Show help commands instead of user time info with robust error handling"""
        await send_reply(interaction, "Please use the `/help` command to see a full list of commands.", ephemeral=True)

    async def generate_reports(self, interaction: discord.Interaction):
        # Robust defer with proper fallback
        defer_success = await robust_defer(interaction, ephemeral=True)
        if not defer_success and not interaction.response.is_done():
            # If defer failed and interaction isn't done, we can't proceed
            return
            
        try:
            
            if interaction.guild is None:
                await interaction.followup.send("Use this in a server.", ephemeral=True)
                return
            
            guild_id = interaction.guild.id
            user_id = interaction.user.id
            
            # RATE LIMITING: Check for spam/abuse
            is_allowed, request_count, action = check_rate_limit(guild_id, user_id, "reports")
            if not is_allowed:
                await handle_rate_limit_response(interaction, action)
                return
            
            # Check if user has admin access (Discord admin OR custom admin role)
            # Type guard: ensure we have a Member for guild-specific functions
            if not isinstance(interaction.user, discord.Member):
                await interaction.followup.send(
                    "❌ Unable to verify admin permissions. Please try again.",
                    ephemeral=True
                )
                return
            
            if not user_has_admin_access(interaction.user):
                await interaction.followup.send(
                    "❌ **Access Denied - Admin Role Required**\n\n"
                    "You need administrator permissions or an admin role to generate reports.\n\n"
                    "**To get access:**\n"
                    "• Ask your server administrator to grant you admin role access\n"
                    "• They can use: `/add_admin_role @yourrole` to give your role admin access\n"
                    "• Or ask them to add you to an existing admin role\n\n"
                    "💡 Contact your server admin for help with role management.",
                    ephemeral=True
                )
                return
            
            access = get_guild_access_info(guild_id)

            if not access['is_exempt'] and access['tier'] == 'free':
                if not access['trial_active']:
                    embed = discord.Embed(
                        title="⏰ Free Trial Expired",
                        description="Your 30-day free trial has ended.\nUpgrade to Premium to generate reports!",
                        color=discord.Color.red()
                    )
                    embed.add_field(name="💎 Premium", value="$8/month (first month FREE!)\n✅ Full team clock in/out\n✅ Dashboard & reports\n✅ 30-day data retention", inline=False)
                    embed.add_field(name="⬆️ Upgrade", value="Use `/upgrade` or visit your dashboard to subscribe!", inline=False)
                    await interaction.followup.send(embed=embed, ephemeral=True)
                    return
                else:
                    # Free tier with active trial: show sample data with trial countdown
                    fake_csv = "Date,Clock In,Clock Out,Duration\n2024-01-01,09:00,17:00,8.0 hours\nThis is sample data from your free trial."
                    filename = f"sample_report_last_30_days.csv"
                    file = discord.File(io.BytesIO(fake_csv.encode('utf-8')), filename=filename)
                    days = access['days_remaining']
                    await interaction.followup.send(
                        f"📊 **Free Trial Sample Report**\n"
                        f"🎯 This is sample data. Upgrade to Premium for real reports!\n"
                        f"⚠️ **{days} day{'s' if days != 1 else ''} left on your free trial.**",
                        file=file,
                        ephemeral=True
                    )
                    return

            # Paid or exempt users get full reports
            guild_tz_name = get_guild_setting(guild_id, "timezone", DEFAULT_TZ)
            if guild_tz_name is None:
                guild_tz_name = DEFAULT_TZ
            
            server_tier = get_guild_tier_string(guild_id)
            # Determine report range based on tier
            if server_tier == "basic":
                report_days = 7  # Basic tier: 7 days max
            else:  # pro tier
                report_days = 30  # Pro tier: 30 days max
            
            # Generate report for tier-appropriate days
            from zoneinfo import ZoneInfo
            from datetime import timedelta
            try:
                guild_tz = ZoneInfo(guild_tz_name or DEFAULT_TZ)
            except Exception:
                guild_tz = ZoneInfo('UTC')
                guild_tz_name = "UTC"
            
            # Calculate date range based on tier limits
            end_date = datetime.now(guild_tz)
            start_date = end_date - timedelta(days=report_days)
            
            start_boundary = datetime.combine(start_date.date(), datetime.min.time()).replace(tzinfo=guild_tz)
            end_boundary = datetime.combine(end_date.date(), datetime.max.time()).replace(tzinfo=guild_tz)
            
            start_utc = start_boundary.astimezone(timezone.utc).isoformat()
            end_utc = end_boundary.astimezone(timezone.utc).isoformat()
            
            # Get all user sessions
            sessions_data = get_sessions_report(guild_id, None, start_utc, end_utc)
            
            if not sessions_data:
                await interaction.followup.send(
                    f"📭 No completed timesheet entries found for the last {report_days} days",
                    ephemeral=True
                )
                return
            
            # Group sessions by user
            user_sessions: dict[int, list[tuple]] = {}
            for session_row in sessions_data:
                user_id = session_row['user_id']
                clock_in_iso = session_row['clock_in']
                clock_out_iso = session_row['clock_out']
                duration_seconds = session_row['duration_seconds']
                if user_id not in user_sessions:
                    user_sessions[user_id] = []
                user_sessions[user_id].append((clock_in_iso, clock_out_iso, duration_seconds))
            
            # Generate CSV files for each user
            total_users = len(user_sessions)
            total_entries = len(sessions_data)
            start_date_str = start_date.strftime("%Y-%m-%d")
            end_date_str = end_date.strftime("%Y-%m-%d")
            tier_note = f"({server_tier.title()} tier - {report_days} days max)" if server_tier == "basic" else f"({server_tier.title()} tier)"
            
            if total_users == 1:
                # Single user: Send CSV file directly (not zipped)
                user_id, sessions = next(iter(user_sessions.items()))
                csv_content, user_display_name = await generate_individual_csv_report(bot, user_id, sessions, guild_id, guild_tz_name or DEFAULT_TZ)
                
                safe_user_name = sanitize_filename(user_display_name)
                filename = f"timesheet_report_{start_date_str}_to_{end_date_str}_{safe_user_name}.csv"
                file = discord.File(
                    io.BytesIO(csv_content.encode('utf-8')), 
                    filename=filename
                )
                
                await interaction.followup.send(
                    f"📊 Generated timesheet report for **{user_display_name}** {tier_note}\n"
                    f"📅 **Period:** Last {report_days} days ({start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')})\n"
                    f"📝 **Total Entries:** {total_entries} completed shifts\n"
                    f"🕐 **Timezone:** {guild_tz_name}",
                    file=file,
                    ephemeral=True
                )
            else:
                # Multiple users: Create zip file containing all CSV files
                zip_buffer = io.BytesIO()
                
                with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_archive:
                    for user_id, sessions in user_sessions.items():
                        csv_content, user_display_name = await generate_individual_csv_report(bot, user_id, sessions, guild_id, guild_tz_name or DEFAULT_TZ)
                        safe_user_name = sanitize_filename(user_display_name)
                        csv_filename = f"timesheet_report_{start_date_str}_to_{end_date_str}_{safe_user_name}.csv"
                        # Explicitly encode CSV content to UTF-8 bytes for zip
                        zip_archive.writestr(csv_filename, csv_content.encode('utf-8'))
                
                zip_buffer.seek(0)
                zip_filename = f"timesheet_reports_{start_date_str}_to_{end_date_str}_all_users.zip"
                
                zip_discord_file = discord.File(zip_buffer, filename=zip_filename)
                
                await interaction.followup.send(
                    f"📊 Generated timesheet reports for **{total_users} users** {tier_note}\n"
                    f"📅 **Period:** Last {report_days} days ({start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')})\n"
                    f"📝 **Total Entries:** {total_entries} completed shifts\n"
                    f"🕐 **Timezone:** {guild_tz_name}\n\n"
                    f"📁 **Delivery:** ZIP file containing individual CSV for each employee",
                    file=zip_discord_file,
                    ephemeral=True
                )
            
        except (discord.NotFound, discord.errors.NotFound):
            # Interaction expired or was deleted - silently handle this
            print(f"⚠️ Reports interaction expired/not found for user {interaction.user.id}")
        except discord.errors.InteractionResponded:
            # Interaction was already responded to - try followup
            try:
                await interaction.followup.send("❌ Reports interaction error. Please try again.", ephemeral=True)
            except Exception as e:
                print(f"⚠️ Failed to send followup after InteractionResponded: {e}")
        except Exception as e:
            # General error handling
            print(f"❌ Error in generate_reports callback: {e}")
            try:
                if not interaction.response.is_done():
                    await interaction.response.send_message(f"❌ Error generating reports: {str(e)}", ephemeral=True)
                else:
                    await interaction.followup.send(f"❌ Error generating reports: {str(e)}", ephemeral=True)
            except Exception:
                # If we can't even send an error message, just log it
                print(f"❌ Failed to send error message for generate_reports: {e}")

    async def show_upgrade(self, interaction: discord.Interaction):
        """Show upgrade options for free tier servers"""
        if not interaction.guild:
            await send_reply(interaction, "❌ This command must be used in a server.", ephemeral=True)
            return
        
        # This command should always be available.
        # No rate limiting or permission checks needed for showing upgrade options.

        embed = discord.Embed(
            title="⬆️ Upgrade Your Server",
            description="Unlock the full power of Time Warden!",
            color=discord.Color.gold()
        )
        embed.add_field(
            name="💎 Premium — $8/month",
            value="First month FREE!\n✅ Full team clock in/out\n✅ Web dashboard access\n✅ CSV reports & exports\n✅ 30-day data retention\n✅ Email reports\n✅ Time adjustments",
            inline=False
        )
        embed.add_field(
            name="🚀 Pro — $15/month (Coming Soon!)",
            value="Everything in Premium, plus:\n✅ Kiosk mode for shared devices\n✅ Ad-free dashboard\n✅ Priority support",
            inline=False
        )
        
        await send_reply(interaction, embed=embed, ephemeral=True)

    async def show_dashboard(self, interaction: discord.Interaction):
        """Show dashboard link - purchase page for free, normal dashboard for paid"""
        if not interaction.guild:
            await send_reply(interaction, "❌ This command must be used in a server.", ephemeral=True)
            return
            
        guild_id = interaction.guild.id
        user_id = interaction.user.id
        
        # RATE LIMITING: Check for spam/abuse
        is_allowed, request_count, action = check_rate_limit(guild_id, user_id, "dashboard")
        if not is_allowed:
            # Handle rate limit response
            if action == "server_abuse":
                await send_reply(interaction,
                    "🚨 **Server Abuse Detected**\n\nThis server has excessive spam activity. The bot is leaving this server.",
                    ephemeral=True
                )
                try:
                    await interaction.guild.leave()
                    print(f"🚨 Bot left guild {guild_id} due to abuse")
                except Exception as e:
                    print(f"❌ Failed to leave guild {guild_id}: {e}")
            elif action == "warning":
                await send_reply(interaction,
                    "⚠️ **Spam Detection Warning**\n\nYou're clicking the same button too quickly (5+ clicks in 30 seconds).\nPlease slow down.\n\n**⛔ Next violation will result in a 24-hour ban.**",
                    ephemeral=True
                )
            else:  # banned
                await send_reply(interaction,
                    "🚫 **24-Hour Ban**\n\nYour access has been temporarily suspended due to spam/abuse.\n**Ban Duration:** 24 hours",
                    ephemeral=True
                )
            return
        
        domain = get_domain()
        landing_page_url = f"https://{domain}/"
        
        embed = discord.Embed(
            title="🌐 On the Clock Dashboard",
            description=f"Access the web dashboard to manage your server settings, view reports, and purchase upgrades.",
            color=discord.Color.blue()
        )
        
        embed.add_field(
            name="🔗 Dashboard Link",
            value=f"[Open Dashboard]({landing_page_url})\n\nLog in with Discord to access your server settings and features.",
            inline=False
        )
        
        embed.set_footer(text="Tip: Use the dashboard to configure roles, timezone, and email settings")
        
        await send_reply(interaction, embed=embed, ephemeral=True)


class SetupInstructionsView(discord.ui.View):
    """Persistent view with a button that shows setup instructions"""
    def __init__(self):
        super().__init__(timeout=None)
    
    @discord.ui.button(
        label="📋 Setup Instructions",
        style=discord.ButtonStyle.primary,
        custom_id="setup:show_instructions"
    )
    async def show_instructions(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Show the setup instructions embed when button is clicked"""
        try:
            # Create the setup embed
            embed = create_setup_embed()
            
            # Send ephemeral message so only the user who clicked sees it
            await interaction.response.send_message(embed=embed, ephemeral=True)
            
        except Exception as e:
            print(f"❌ Error showing setup instructions: {e}")
            try:
                if not interaction.response.is_done():
                    await interaction.response.send_message(
                        "❌ Error loading setup instructions. Please try again.",
                        ephemeral=True
                    )
            except Exception:
                pass


# --- Timeclock Hub View (Bulletproof Button Persistence) ---
# Uses stable custom_ids with "tc:" prefix for maximum reliability
SUPPORT_DISCORD_URL = "https://discord.gg/tMGssTjkUt"
LANDING_PAGE_URL = "https://time-warden.com"

class TimeclockHubView(discord.ui.View):
    """
    Bulletproof timeclock hub with persistent buttons.
    
    Follows 2025 Discord best practices:
    - timeout=None for never-expiring buttons
    - Stable custom_id values with "tc:" prefix
    - Fast ACK (defer immediately in handlers)
    - Registered in setup_hook for post-restart reliability
    
    NOTE: This base view is registered for fallback handling.
    The actual view sent to users is built dynamically via build_timeclock_hub_view()
    to conditionally show/hide buttons based on subscription tier.
    """
    def __init__(self):
        super().__init__(timeout=None)  # Never timeout - critical for persistence
    
    @discord.ui.button(
        label="Clock In",
        style=discord.ButtonStyle.success,
        custom_id="tc:clock_in",
        emoji="⏰",
        row=0
    )
    async def clock_in_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Clock in button - ACK fast, then process"""
        await handle_tc_clock_in(interaction)
    
    @discord.ui.button(
        label="Clock Out",
        style=discord.ButtonStyle.secondary,
        custom_id="tc:clock_out",
        emoji="🏁",
        row=0
    )
    async def clock_out_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Clock out button - ACK fast, then process"""
        await handle_tc_clock_out(interaction)
    
    @discord.ui.button(
        label="My Adjustments",
        style=discord.ButtonStyle.primary,
        custom_id="tc:adjustments",
        emoji="📝",
        row=1
    )
    async def adjustments_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Link to dashboard adjustments page"""
        await handle_tc_adjustments(interaction)
    
    @discord.ui.button(
        label="My Hours",
        style=discord.ButtonStyle.primary,
        custom_id="tc:my_hours",
        emoji="📊",
        row=1
    )
    async def my_hours_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Link to dashboard user hours"""
        await handle_tc_my_hours(interaction)
    
    @discord.ui.button(
        label="Support",
        style=discord.ButtonStyle.danger,
        custom_id="tc:support",
        emoji="🆘",
        row=1
    )
    async def support_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Link to support Discord server"""
        await handle_tc_support(interaction)
    
    @discord.ui.button(
        label="Unlock Premium",
        style=discord.ButtonStyle.success,
        custom_id="tc:upgrade",
        emoji="⭐",
        row=2
    )
    async def upgrade_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Show upgrade options"""
        await handle_tc_upgrade(interaction)


# =============================================================================
# Demo Role Switcher View
# =============================================================================



# Track recent /setup_demo_roles calls to prevent duplicate execution
_setup_demo_roles_recent_calls: dict[tuple[int, int], float] = {}  # {(guild_id, user_id): timestamp}

class DemoRoleSwitcherView(discord.ui.View):
    """
    Persistent view for demo server role switching.
    Allows users to toggle between Admin and Employee personas for testing.
    After role assignment, automatically sends timeclock hub for seamless onboarding.
    """
    def __init__(self):
        super().__init__(timeout=None)  # REQUIRED for persistence
        
        # Add a prominent Kiosk advertisement button to the role selection view (Row 1)
        self.add_item(discord.ui.Button(
            label="📱 Test Kiosk Tablet Mode (BETA)",
            emoji="✨",
            url=f"https://time-warden.com/kiosk/{DEMO_SERVER_ID}",
            row=1
        ))

    @discord.ui.button(
        label="Become Admin",
        style=discord.ButtonStyle.danger,  # Red
        emoji="👑",
        custom_id="demo:become_admin",
        row=0
    )
    async def become_admin_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Switch user to Admin role"""
        await robust_defer(interaction, ephemeral=True)

        try:
            # Get both roles
            admin_role = interaction.guild.get_role(DEMO_ADMIN_ROLE_ID)
            employee_role = interaction.guild.get_role(DEMO_EMPLOYEE_ROLE_ID)

            if not admin_role:
                await send_reply(interaction, "❌ Demo Admin role not found. Please contact support.", ephemeral=True)
                return

            # Add admin role
            await interaction.user.add_roles(admin_role, reason="Demo: User chose Admin persona")

            # Remove employee role if they have it
            if employee_role and employee_role in interaction.user.roles:
                await interaction.user.remove_roles(employee_role, reason="Demo: Switched from Admin to Employee")

            # Send confirmation with dashboard link
            dashboard_url = "https://time-warden.com"
            await send_reply(
                interaction,
                f"✅ **You are now an Admin!**\n\n"
                f"🖥️ **[Open Dashboard]({dashboard_url})** - Manage employees, view reports, configure settings",
                ephemeral=True
            )

            embed = discord.Embed(
                title="⏰ Your Timeclock Hub",
                description=(
                    "As an **Admin**, you can:\n"
                    "• Clock in/out to test the employee experience\n"
                    "• View your hours and adjustments\n"
                    "• Access the full admin dashboard\n\n"
                    "Use the buttons below to interact with the timeclock system."
                ),
                color=0xFF0000  # Red for admin
            )
            view = build_timeclock_hub_view(interaction.guild_id, embed)

            await interaction.followup.send(embed=embed, view=view, ephemeral=True)
            print(f"📌 Sent ephemeral timeclock hub for admin user {interaction.user.id}")

        except discord.Forbidden:
            await send_reply(interaction, "❌ I don't have permission to manage roles. Please contact a server admin.", ephemeral=True)
        except Exception as e:
            print(f"❌ Error in become_admin: {e}")
            await send_reply(interaction, "❌ An error occurred. Please try again.", ephemeral=True)

    @discord.ui.button(
        label="Become Employee",
        style=discord.ButtonStyle.primary,  # Blue
        emoji="👷",
        custom_id="demo:become_employee",
        row=0
    )
    async def become_employee_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Switch user to Employee role"""
        await robust_defer(interaction, ephemeral=True)

        try:
            # Get both roles
            admin_role = interaction.guild.get_role(DEMO_ADMIN_ROLE_ID)
            employee_role = interaction.guild.get_role(DEMO_EMPLOYEE_ROLE_ID)

            if not employee_role:
                await send_reply(interaction, "❌ Demo Employee role not found. Please contact support.", ephemeral=True)
                return

            # Add employee role
            await interaction.user.add_roles(employee_role, reason="Demo: User chose Employee persona")

            # Remove admin role if they have it
            if admin_role and admin_role in interaction.user.roles:
                await interaction.user.remove_roles(admin_role, reason="Demo: Switched from Admin to Employee")

            # Generate and store a PIN for the demo user
            import random
            import hashlib
            
            pin = str(random.randint(1000, 9999))
            
            # The app.py hashing format: f"{guild_id}:{user_id}:{pin}"
            pin_hash = hashlib.sha256(f"{interaction.guild_id}:{interaction.user.id}:{pin}".encode()).hexdigest()
            
            with db() as conn:
                conn.execute("""
                    INSERT INTO employee_pins (guild_id, user_id, pin_hash)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (guild_id, user_id) 
                    DO UPDATE SET pin_hash = EXCLUDED.pin_hash, updated_at = NOW()
                """, (str(interaction.guild_id), str(interaction.user.id), pin_hash))

            # Send confirmation with dashboard and kiosk links
            dashboard_url = "https://time-warden.com"
            kiosk_url = f"https://time-warden.com/kiosk/{DEMO_SERVER_ID}"
            await send_reply(
                interaction,
                f"✅ **You are now an Employee!**\n\n"
                f"🖥️ **[Open Web Dashboard]({dashboard_url})** - Our core product. Clock in/out and view your hours.\n"
                f"📱 **[Try Kiosk Mode (BETA)]({kiosk_url})** - Upcoming tablet feature. Your test PIN is: **{pin}**",
                ephemeral=True
            )

            embed = discord.Embed(
                title="⏰ Your Timeclock Hub",
                description=(
                    "As an **Employee**, you can:\n"
                    "• Clock in/out using the buttons below\n"
                    "• View your hours and request adjustments\n"
                    "• Access your personal dashboard\n"
                    "• Try the Kiosk mode (tablet-friendly interface)\n\n"
                    "Use the buttons below to interact with the timeclock system."
                ),
                color=0x0099FF  # Blue for employee
            )
            view = build_timeclock_hub_view(interaction.guild_id, embed)

            await interaction.followup.send(embed=embed, view=view, ephemeral=True)
            print(f"📌 Sent ephemeral timeclock hub for employee user {interaction.user.id}")
            print(f"📌 Sent timeclock hub to channel as message {timeclock_msg.id} for employee user {interaction.user.id}")

        except discord.Forbidden:
            await send_reply(interaction, "❌ I don't have permission to manage roles. Please contact a server admin.", ephemeral=True)
        except Exception as e:
            print(f"❌ Error in become_employee: {e}")
            await send_reply(interaction, "❌ An error occurred. Please try again.", ephemeral=True)


def build_timeclock_hub_view(guild_id: int, embed: discord.Embed) -> discord.ui.View:
    """
    Factory function to dynamically build the timeclock hub view
    with conditional buttons based on subscription tier.
    
    Args:
        guild_id: The Discord guild ID to check subscription status
        embed: The discord.Embed object to which trial information may be added
        
    Returns:
        A discord.ui.View with the appropriate buttons
    """
    view = discord.ui.View(timeout=None)
    
    # Core buttons - always present (Row 0)
    clock_in_btn = discord.ui.Button(
        label="Clock In", style=discord.ButtonStyle.success, custom_id="tc:clock_in", emoji="⏰", row=0
    )
    clock_in_btn.callback = handle_tc_clock_in
    view.add_item(clock_in_btn)
    
    clock_out_btn = discord.ui.Button(
        label="Clock Out", style=discord.ButtonStyle.secondary, custom_id="tc:clock_out", emoji="🏁", row=0
    )
    clock_out_btn.callback = handle_tc_clock_out
    view.add_item(clock_out_btn)
    
    # Feature buttons - always present (Row 1)
    adjustments_btn = discord.ui.Button(
        label="My Adjustments", style=discord.ButtonStyle.primary, custom_id="tc:adjustments", emoji="📝", row=1
    )
    adjustments_btn.callback = handle_tc_adjustments
    view.add_item(adjustments_btn)
    
    my_hours_btn = discord.ui.Button(
        label="My Hours", style=discord.ButtonStyle.primary, custom_id="tc:my_hours", emoji="📊", row=1
    )
    my_hours_btn.callback = handle_tc_my_hours
    view.add_item(my_hours_btn)
    
    support_btn = discord.ui.Button(
        label="Support", style=discord.ButtonStyle.danger, custom_id="tc:support", emoji="🆘", row=1
    )
    support_btn.callback = handle_tc_support
    view.add_item(support_btn)

    # Conditional upgrade button and trial status
    access = get_guild_access_info(guild_id)
    if not access['is_exempt'] and access['tier'] == 'free':
        upgrade_btn = discord.ui.Button(
            label="⬆️ Upgrade — First Month Free!", style=discord.ButtonStyle.success, custom_id="tc:upgrade", row=2
        )
        upgrade_btn.callback = handle_tc_upgrade
        view.add_item(upgrade_btn)

        if not access['trial_active']:
            embed.add_field(name="⚠️ Trial Expired", value="Upgrade to continue using the bot.", inline=False)
        elif access['days_remaining'] <= 10:
            embed.add_field(name="⏳ Trial Ends Soon!", value=f"{access['days_remaining']} days left. Upgrade to keep access.", inline=False)

    return view


# --- Timeclock Hub Button Handlers ---
# Separated from view class for reuse in on_interaction fallback

async def handle_tc_clock_in(interaction: discord.Interaction):
    """Handle clock in from TimeclockHubView - ACK fast, then process"""
    # ACK immediately before any database work
    if not await robust_defer(interaction, ephemeral=True):
        return
    
    if not interaction.guild:
        await interaction.followup.send("❌ This command must be used in a server.", ephemeral=True)
        return
    
    guild_id = interaction.guild.id
    user_id = interaction.user.id
    
    # Check rate limit
    is_allowed, request_count, action = check_rate_limit(guild_id, user_id, "tc_clock_in")
    if not is_allowed:
        await handle_rate_limit_response(interaction, action)
        return

    # Check Kiosk Only Mode
    try:
        with db() as conn:
            cursor = conn.execute("SELECT kiosk_only_mode FROM guild_settings WHERE guild_id = %s", (guild_id,))
            settings = cursor.fetchone()
            
        if settings and settings.get('kiosk_only_mode'):
            await interaction.followup.send(
                "🖥️ **Kiosk Only Mode Active**\n\n"
                "Discord clocking is disabled for this server.\n"
                f"Please clock in physically at the terminal: `https://time-warden.com/kiosk/{guild_id}`",
                ephemeral=True
            )
            return
    except Exception as e:
        print(f"Error checking kiosk mode: {e}")

    # Check permissions
    server_tier = get_guild_tier_string(guild_id)
    if not isinstance(interaction.user, discord.Member):
        await interaction.followup.send("❌ Unable to verify permissions.", ephemeral=True)
        return
    
    if not user_has_clock_access(interaction.user, server_tier):
        await interaction.followup.send(
            "🔒 **Access Restricted**\n"
            "You need an employee role to use the timeclock.\n"
            "Ask an administrator to add your role with `/add_employee_role @yourrole`",
            ephemeral=True
        )
        return
    
    # PHASE 2: Free Tier App-Wide 3-User Hard-Cap
    if server_tier == 'free':
        try:
            with db() as conn:
                cursor = conn.execute("SELECT COUNT(*) as count FROM employee_profiles WHERE guild_id = %s AND is_active = TRUE", (guild_id,))
                active_count = cursor.fetchone()['count']
            if active_count > 3:
                await interaction.followup.send(
                    "🔒 **Server Cap Reached**\n\n"
                    f"Your Premium Trial has expired and this server has {active_count} active profiles.\n"
                    "The **Free Tier** limit is 3 employees.\n\n"
                    "Please ask your Server Administrator to upgrade to Premium, or archive unused profiles from the Web Dashboard.",
                    ephemeral=True
                )
                return
        except Exception as e:
            print(f"Error checking free tier limits: {e}")

    # Check if already clocked in with transactional lock to prevent race conditions
    try:
        with db() as conn:
            # 1. Acquire an advisory lock keyed to the user_id to strongly serialize requests
            cursor = conn.execute("SELECT pg_try_advisory_xact_lock(%s)", (user_id,))
            lock_row = cursor.fetchone()
            # The query returns a RealDictRow where the key is 'pg_try_advisory_xact_lock', but we can just use list values
            lock_acquired = list(lock_row.values())[0] if lock_row else False
            
            if not lock_acquired:
                await interaction.followup.send(
                    "⚠️ **Processing**\n\n"
                    "Your previous clock-in request is still processing. Please wait a moment.",
                    ephemeral=True
                )
                return
            
            # 2. Check for active session inside the lock
            cursor = conn.execute(
                "SELECT session_id as id, clock_in_time as clock_in FROM timeclock_sessions WHERE user_id = %s AND guild_id = %s AND clock_out_time IS NULL FOR UPDATE",
                (user_id, guild_id)
            )
            existing = cursor.fetchone()
        
            if existing:
                clock_in_time = safe_parse_timestamp(existing['clock_in'])
                await interaction.followup.send(
                    f"⚠️ **Already Clocked In**\n\n"
                    f"You clocked in at <t:{int(clock_in_time.timestamp())}:f>\n"
                    f"Use **Clock Out** to end your shift first.",
                    ephemeral=True
                )
                return
            
            # 3. Perform clock in inside the same locked connection
            now = datetime.now(timezone.utc)
            conn.execute(
                "INSERT INTO timeclock_sessions (user_id, guild_id, clock_in_time) VALUES (%s, %s, %s)",
                (user_id, guild_id, now.isoformat())
            )
            
        # Post native text alerts to discord_log_channel_id
        try:
            guild_settings = get_guild_settings(guild_id)
            log_channel_id = guild_settings.get('discord_log_channel_id')
            if log_channel_id:
                log_channel = bot.get_channel(int(log_channel_id))
                if log_channel:
                    tz_name = guild_settings.get('timezone', 'UTC')
                    in_time_formatted = fmt(now, tz_name)
                    user_display_name = get_user_display_name(interaction.user, guild_id)
                    try:
                        await log_channel.send(
                            f"🟢 **{user_display_name}** clocked in at `{in_time_formatted}`"
                        )
                    except discord.Forbidden:
                        print(f"⚠️ Missing permissions to send clock-in log in channel {log_channel_id} (Guild {guild_id})")
        except Exception as e:
            print(f"Error sending log channel alert for clock in: {e}")
        
        # Ensure employee profile exists
        member = interaction.user
        ensure_employee_profile(
            guild_id, user_id,
            member.name, member.display_name,
            str(member.avatar.url) if member.avatar else str(member.default_avatar.url)
        )
        
        access = get_guild_access_info(guild_id)
        trial_msg = ""
        if access['tier'] == 'free' and access['trial_active'] and not access['is_exempt']:
            days = access['days_remaining']
            if days <= 3:
                trial_msg = f"\n\n🚨 **Trial expires in {days} day{'s' if days != 1 else ''}!** Your team will lose clock access. Use `/upgrade` now!"
            elif days <= 7:
                trial_msg = f"\n\n⚠️ **{days} days left** on your free trial. Use `/upgrade` to keep access!"
            elif days <= 10:
                trial_msg = f"\n\n💡 {days} days left on your free trial."

        await interaction.followup.send(
            f"✅ **Clocked In!**\n\n"
            f"**Time:** <t:{int(now.timestamp())}:f>\n"
            f"Have a productive shift!{trial_msg}",
            ephemeral=True
        )
        print(f"✅ [TC Hub] User {user_id} clocked in at guild {guild_id}")
        
    except Exception as e:
        print(f"❌ [TC Hub] Clock in error for {user_id}: {e}")
        await interaction.followup.send(
            "❌ **Error**\nFailed to clock in. Please try again.",
            ephemeral=True
        )


async def handle_tc_clock_out(interaction: discord.Interaction):
    """Handle clock out from TimeclockHubView - ACK fast, then process"""
    # ACK immediately
    if not await robust_defer(interaction, ephemeral=True):
        return
    
    if not interaction.guild:
        await interaction.followup.send("❌ This command must be used in a server.", ephemeral=True)
        return
    
    guild_id = interaction.guild.id
    user_id = interaction.user.id
    
    # Check rate limit
    is_allowed, request_count, action = check_rate_limit(guild_id, user_id, "tc_clock_out")
    if not is_allowed:
        await handle_rate_limit_response(interaction, action)
        return

    # Check Kiosk Only Mode
    try:
        with db() as conn:
            cursor = conn.execute("SELECT kiosk_only_mode FROM guild_settings WHERE guild_id = %s", (guild_id,))
            settings = cursor.fetchone()
            
        if settings and settings.get('kiosk_only_mode'):
            await interaction.followup.send(
                "🖥️ **Kiosk Only Mode Active**\n\n"
                "Discord clocking is disabled for this server.\n"
                f"Please clock out physically at the terminal: `https://time-warden.com/kiosk/{guild_id}`",
                ephemeral=True
            )
            return
    except Exception as e:
        print(f"Error checking kiosk mode: {e}")

    # Check permissions
    server_tier = get_guild_tier_string(guild_id)
    if not isinstance(interaction.user, discord.Member):
        await interaction.followup.send("❌ Unable to verify permissions.", ephemeral=True)
        return
    
    if not user_has_clock_access(interaction.user, server_tier):
        await interaction.followup.send(
            "🔒 **Access Restricted**\n"
            "You need an employee role to use the timeclock.",
            ephemeral=True
        )
        return
    
    try:
        # Find active session
        with db() as conn:
            cursor = conn.execute(
                "SELECT session_id as id, clock_in_time as clock_in FROM timeclock_sessions WHERE user_id = %s AND guild_id = %s AND clock_out_time IS NULL",
                (user_id, guild_id)
            )
            session = cursor.fetchone()
        
        if not session:
            await interaction.followup.send(
                "⚠️ **Not Clocked In**\n\n"
                "You're not currently on the clock.\n"
                "Use **Clock In** to start a shift.",
                ephemeral=True
            )
            return
        
        # Clock out
        now = datetime.now(timezone.utc)
        clock_in_time = safe_parse_timestamp(session['clock_in'])
        if clock_in_time.tzinfo is None:
            clock_in_time = clock_in_time.replace(tzinfo=timezone.utc)
        
        elapsed = now - clock_in_time
        hours = elapsed.total_seconds() / 3600
        hours_int = int(hours)
        minutes = int((hours - hours_int) * 60)
        
        with db() as conn:
            conn.execute(
                "UPDATE timeclock_sessions SET clock_out_time = %s WHERE session_id = %s",
                (now.isoformat(), session['id'])
            )
            
        # Post native text alerts to discord_log_channel_id
        try:
            guild_settings = get_guild_settings(guild_id)
            log_channel_id = guild_settings.get('discord_log_channel_id')
            if log_channel_id:
                log_channel = bot.get_channel(int(log_channel_id))
                if log_channel:
                    tz_name = guild_settings.get('timezone', 'UTC')
                    out_time_formatted = fmt(now, tz_name)
                    user_display_name = get_user_display_name(interaction.user, guild_id)
                    try:
                        await log_channel.send(
                            f"🔴 **{user_display_name}** clocked out at `{out_time_formatted}` ({hours_int}h {minutes}m)"
                        )
                    except discord.Forbidden:
                        print(f"⚠️ Missing permissions to send clock-out log in channel {log_channel_id} (Guild {guild_id})")
        except Exception as e:
            print(f"Error sending log channel alert for clock out: {e}")
        
        access = get_guild_access_info(guild_id)
        trial_msg = ""
        if access['tier'] == 'free' and access['trial_active'] and not access['is_exempt']:
            days = access['days_remaining']
            if days <= 3:
                trial_msg = f"\n\n🚨 **Trial expires in {days} day{'s' if days != 1 else ''}!** Your team will lose clock access. Use `/upgrade` now!"
            elif days <= 7:
                trial_msg = f"\n\n⚠️ **{days} days left** on your free trial. Use `/upgrade` to keep access!"
            elif days <= 10:
                trial_msg = f"\n\n💡 {days} days left on your free trial."

        await interaction.followup.send(
            f"✅ **Clocked Out!**\n\n"
            f"**Started:** <t:{int(clock_in_time.timestamp())}:f>\n"
            f"**Ended:** <t:{int(now.timestamp())}:f>\n"
            f"**Duration:** {hours_int}h {minutes}m\n\n"
            f"Great work today!{trial_msg}",
            ephemeral=True
        )
        print(f"✅ [TC Hub] User {user_id} clocked out at guild {guild_id} ({hours:.2f}h)")
        
    except Exception as e:
        print(f"❌ [TC Hub] Clock out error for {user_id}: {e}")
        await interaction.followup.send(
            "❌ **Error**\nFailed to clock out. Please try again.",
            ephemeral=True
        )


async def handle_tc_adjustments(interaction: discord.Interaction):
    """Handle adjustments button - link to dashboard with signed URL"""
    # ACK immediately
    if not await robust_defer(interaction, ephemeral=True):
        return
    
    if not interaction.guild:
        await interaction.followup.send("❌ Use this in a server.", ephemeral=True)
        return
    
    url = generate_dashboard_deeplink(
        interaction.guild.id,
        interaction.user.id,
        'adjustments'
    )
    
    embed = discord.Embed(
        title="📝 Time Adjustments",
        description="Click the button below to manage your time adjustments in the dashboard.",
        color=0xD4AF37
    )
    
    view = discord.ui.View()
    view.add_item(discord.ui.Button(label="Open Dashboard", url=url, style=discord.ButtonStyle.link))
    
    await interaction.followup.send(embed=embed, view=view, ephemeral=True)


async def handle_tc_my_hours(interaction: discord.Interaction):
    """Handle my hours button - show summary and link to dashboard with signed URL"""
    # ACK immediately
    if not await robust_defer(interaction, ephemeral=True):
        return
    
    if not interaction.guild:
        await interaction.followup.send("❌ Use this in a server.", ephemeral=True)
        return
    
    guild_id = interaction.guild.id
    user_id = interaction.user.id
    
    url = generate_dashboard_deeplink(
        guild_id,
        user_id,
        'profile'
    )
    
    try:
        # Get hours summary for this pay period (last 14 days)
        with db() as conn:
            cursor = conn.execute("""
                SELECT 
                    COALESCE(SUM(
                        EXTRACT(EPOCH FROM (COALESCE(clock_out_time, NOW()) - clock_in_time)) / 3600
                    ), 0) as total_hours,
                    COUNT(*) as session_count
                FROM timeclock_sessions 
                WHERE user_id = %s AND guild_id = %s 
                AND clock_in_time >= NOW() - INTERVAL '14 days'
            """, (user_id, guild_id))
            row = cursor.fetchone()
        
        total_hours = float(row['total_hours']) if row['total_hours'] else 0
        session_count = row['session_count'] if row else 0
        
        embed = discord.Embed(
            title="📊 My Hours",
            description="Your time tracking summary",
            color=0xD4AF37
        )
        embed.add_field(
            name="📅 Last 14 Days",
            value=f"**Total Hours:** {total_hours:.2f}h\n**Sessions:** {session_count}",
            inline=False
        )
        
        view = discord.ui.View()
        view.add_item(discord.ui.Button(label="View Full Details", url=url, style=discord.ButtonStyle.link))
        
        await interaction.followup.send(embed=embed, view=view, ephemeral=True)
        
    except Exception as e:
        print(f"❌ [TC Hub] My hours error for {user_id}: {e}")
        embed = discord.Embed(
            title="❌ Error",
            description="Couldn't load hours summary. Click below to view in dashboard.",
            color=0xED4245
        )
        view = discord.ui.View()
        view.add_item(discord.ui.Button(label="Try Dashboard", url=url, style=discord.ButtonStyle.link))
        await interaction.followup.send(embed=embed, view=view, ephemeral=True)


async def handle_tc_support(interaction: discord.Interaction):
    """Handle support button - link to Discord support server"""
    # ACK immediately
    if not await robust_defer(interaction, ephemeral=True):
        return
    
    embed = discord.Embed(
        title="🆘 Need Help?",
        description="Join our support Discord for assistance!",
        color=0xED4245
    )
    embed.add_field(
        name="📞 Support Server",
        value=f"**[Join Support Discord]({SUPPORT_DISCORD_URL})**\n\nGet help with:\n• Setup and configuration\n• Billing questions\n• Bug reports\n• Feature requests",
        inline=False
    )
    embed.set_footer(text="On the Clock • Professional Time Tracking")
    
    await interaction.followup.send(embed=embed, ephemeral=True)


async def handle_tc_upgrade(interaction: discord.Interaction):
    """Handle upgrade button - show subscription options based on current tier"""
    # ACK immediately
    if not await robust_defer(interaction, ephemeral=True):
        return
    
    if not interaction.guild:
        await interaction.followup.send("❌ This command must be used in a server.", ephemeral=True)
        return

    embed = discord.Embed(
        title="⬆️ Upgrade Your Server",
        description="Unlock the full power of Time Warden!",
        color=discord.Color.gold()
    )
    embed.add_field(
        name="💎 Premium — $8/month",
        value="First month FREE!\n✅ Full team clock in/out\n✅ Web dashboard access\n✅ CSV reports & exports\n✅ 30-day data retention\n✅ Email reports\n✅ Time adjustments",
        inline=False
    )
    embed.add_field(
        name="🚀 Pro — $15/month (Coming Soon!)",
        value="Everything in Premium, plus:\n✅ Kiosk mode for shared devices\n✅ Ad-free dashboard\n✅ Priority support",
        inline=False
    )
    
    await interaction.followup.send(embed=embed, ephemeral=True)



@bot.event
async def on_ready():
    # Persistent views are now registered in setup_hook (both new and legacy views)
    # This ensures backward compatibility with existing posted messages
    
    # Start email scheduler for automated reports and warnings
    try:
        start_scheduler(bot)
        print("✅ Email scheduler started successfully")
    except Exception as e:
        print(f"⚠️ Failed to start email scheduler: {e}")
    
    # Debug: Check what commands are in the tree
    commands = tree.get_commands()
    print(f"📋 Commands in tree: {len(commands)}")
    for cmd in commands:
        description = getattr(cmd, 'description', 'No description')
        print(f"   - {cmd.name}: {description}")
    
    # Try syncing commands with better error handling
    synced_count = 0
    sync_location = "nowhere"

    try:
        if GUILD_ID:
            # Try guild-specific sync first (main production server)
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
    if bot.user:
        print(f"🤖 Logged in as {bot.user} ({bot.user.id})")
    else:
        print("🤖 Bot user information not available")
    
    # Update bot_guilds table with all connected guilds
    try:
        with db() as conn:
            # First, mark ALL guilds as not present (to catch any the bot has left)
            conn.execute("""
                UPDATE bot_guilds 
                SET is_present = FALSE, left_at = COALESCE(left_at, NOW())
                WHERE is_present = TRUE OR is_present IS NULL
            """)
            
            # Then mark only the guilds we're actually in as present
            current_guild_ids = [str(guild.id) for guild in bot.guilds]
            for guild in bot.guilds:
                conn.execute("""
                    INSERT INTO bot_guilds (guild_id, guild_name, joined_at, is_present, left_at)
                    VALUES (%s, %s, NOW(), TRUE, NULL)
                    ON CONFLICT (guild_id) DO UPDATE 
                    SET guild_name = EXCLUDED.guild_name, is_present = TRUE, left_at = NULL
                """, (str(guild.id), guild.name))
        print(f"✅ Updated bot_guilds table with {len(bot.guilds)} guilds")
    except Exception as e:
        print(f"❌ Error updating bot_guilds table: {e}")

    # Backfill trial start dates for existing guilds
    try:
        with db() as conn:
            for guild in bot.guilds:
                conn.execute("""
                    INSERT INTO guild_settings (guild_id, trial_start_date)
                    VALUES (%s, NOW())
                    ON CONFLICT (guild_id) DO NOTHING
                """, (guild.id,))
        print(f"✅ Backfilled trial start dates for {len(bot.guilds)} guilds")
    except Exception as e:
        print(f"❌ Error backfilling trial start dates: {e}")

    # --- Employee Profile Catch-up ---
    print("🔄 Running employee profile catch-up...")
    try:
        with db() as conn:
            for guild in bot.guilds:
                try:
                    employee_roles = get_employee_roles(guild.id)
                    if not employee_roles:
                        continue
                        
                    for member in guild.members:
                        if member.bot:
                            continue
                            
                        # Check if they have an employee role
                        has_role = any(r.id in employee_roles for r in member.roles)
                        if has_role:
                            # Ensure profile exists
                            ensure_employee_profile(
                                guild.id, member.id, 
                                member.name, member.display_name, 
                                str(member.avatar.url) if member.avatar else str(member.default_avatar.url)
                            )
                except Exception as e:
                    print(f"Error processing guild {guild.id} for catch-up: {e}")
        print("✅ Employee profile catch-up complete")
    except Exception as e:
        print(f"❌ Error in employee profile catch-up: {e}")

def create_setup_embed() -> discord.Embed:
    """Create the setup instructions embed (reusable for DMs and button responses)"""
    embed = discord.Embed(
        title="⏰ Welcome to Time Warden!",
        description=(
            "Thanks for adding our professional Discord timeclock bot to your server!\n\n"
            "**You now have a 30-day Premium Trial with full access to all features.**\n"
            "*(After 30 days, the Free Tier applies a strict 3-employee limit.)*"
        ),
        color=discord.Color.blurple()
    )
    
    # Add setup instructions
    embed.add_field(
        name="🚀 Quick Setup Guide",
        value=(
            "1️⃣ **Visit the Dashboard:** Log in at https://time-warden.com\n"
            "2️⃣ **Set Employee Roles:** Add roles that can use the timeclock\n"
            "3️⃣ **Set Admin Roles** (optional): Add roles for report/settings access\n"
            "4️⃣ **Start Tracking:** Use `/clock` to get your timeclock interface\n\n"
            "💡 **Tip:** Use `/setup` anytime to see setup instructions!"
        ),
        inline=False
    )
    
    # Add subscription tier information
    embed.add_field(
        name="💼 After Your Trial",
        value=(
            "Upgrade to Premium to continue using all features.\n\n"
            "**💎 Premium ($8/month, first month FREE!):**\n"
            "• Full team access\n"
            "• CSV reports & exports\n"
            "• 30-day data retention\n"
            "• Dashboard & all features\n\n"
            "Use `/upgrade` to subscribe!"
        ),
        inline=False
    )
    
    # Add footer with support info
    embed.add_field(
        name="💬 Need Help?",
        value=(
            "Join our support server for assistance:\n"
            "🔗 https://discord.gg/tMGssTjkUt\n\n"
            "Run `/help` anytime to see all available commands!"
        ),
        inline=False
    )
    embed.set_footer(
        text="On the Clock - Professional Discord Timeclock Management",
        icon_url=bot.user.avatar.url if bot.user and bot.user.avatar else None
    )
    
    return embed

def create_employee_welcome_embed(guild_name: str, dashboard_url: str | None = None) -> discord.Embed:
    """Create a welcome embed for new employees when they're assigned an employee role."""
    embed = discord.Embed(
        title="Welcome to the Team!",
        description=(
            f"You've been added as an employee on **{guild_name}**'s timeclock system.\n\n"
            "Use the `/clock` command in Discord to track your work hours."
        ),
        color=0x57F287  # Green
    )
    
    embed.add_field(
        name="Getting Started",
        value=(
            "**How to use the timeclock:**\n"
            "1. Type `/clock` in any channel to open your personal timeclock\n"
            "2. Click **Clock In** when you start work\n"
            "3. Click **Clock Out** when you're done\n"
            "4. Use **My Hours** to view your time summary"
        ),
        inline=False
    )
    
    embed.add_field(
        name="Available Features",
        value=(
            "**Clock In/Out** - Track your work sessions\n"
            "**My Hours** - View weekly hour summary\n"
            "**My Adjustments** - Request time corrections if needed"
        ),
        inline=False
    )
    
    embed.add_field(
        name="Quick Tips",
        value=(
            "Your timeclock is private - only you can see your status.\n"
            "Admins can view team hours and generate reports.\n"
            "Questions? Ask your server administrator for help."
        ),
        inline=False
    )
    
    embed.set_footer(
        text="On the Clock - Professional Time Tracking for Discord",
        icon_url=bot.user.avatar.url if bot.user and bot.user.avatar else None
    )
    
    return embed

async def send_employee_welcome_dm(member: discord.Member, guild: discord.Guild) -> bool:
    """Send a welcome DM to a new employee. Returns True if sent successfully."""
    try:
        embed = create_employee_welcome_embed(guild.name)
        await member.send(embed=embed)
        
        # Mark as sent in database
        with db() as conn:
            conn.execute("""
                UPDATE employee_profiles 
                SET welcome_dm_sent = TRUE 
                WHERE guild_id = %s AND user_id = %s
            """, (guild.id, member.id))
        
        print(f"Employee welcome DM sent to {member} for {guild.name}")
        return True
        
    except discord.Forbidden:
        print(f"Could not DM {member} - DMs disabled")
        return False
    except Exception as e:
        print(f"Error sending employee welcome DM to {member}: {e}")
        return False


def trigger_welcome_dm(guild_id: int, user_id: int) -> dict:
    """
    Sync wrapper to trigger a welcome DM from Flask.
    Returns {'success': True/False, 'message': str}
    """
    try:
        guild = bot.get_guild(guild_id)
        if not guild:
            return {'success': False, 'message': 'Guild not found'}
        
        member = guild.get_member(user_id)
        if not member:
            return {'success': False, 'message': 'Member not found in guild'}
        
        async def _send_dm():
            return await send_employee_welcome_dm(member, guild)
        
        if bot.loop and bot.loop.is_running():
            future = asyncio.run_coroutine_threadsafe(_send_dm(), bot.loop)
            result = future.result(timeout=10)
        else:
            return {'success': False, 'message': 'Bot event loop not running'}
        
        if result:
            return {'success': True, 'message': 'Welcome DM sent'}
        else:
            return {'success': False, 'message': 'Could not send DM - user may have DMs disabled'}
            
    except Exception as e:
        print(f"Error in trigger_welcome_dm: {e}")
        return {'success': False, 'message': str(e)}


_recent_guild_joins = {}

@bot.event
async def on_guild_join(guild):
    """Send welcome message with setup instructions when bot joins a new server"""
    now = datetime.now(timezone.utc)
    last_join = _recent_guild_joins.get(guild.id)
    if last_join and (now - last_join).total_seconds() < 60:
        print(f"⚠️ Duplicate on_guild_join for {guild.name} (ID: {guild.id}) — skipping")
        return
    _recent_guild_joins[guild.id] = now
    
    print(f"🎉 Bot joined new server: {guild.name} (ID: {guild.id})")
    
    inviter = guild.owner
    
    embed = create_setup_embed()
    
    try:
        if inviter:
            await inviter.send(embed=embed)
            print(f"✅ Sent welcome DM to {inviter} in {guild.name}")
        else:
            print(f"⚠️ Could not find owner for {guild.name}")
    except discord.Forbidden:
        print(f"❌ Could not DM owner of {guild.name} - DMs disabled")
    except Exception as e:
        print(f"❌ Error sending welcome DM for {guild.name}: {e}")
    
    try:
        target_channel = guild.system_channel
        if not target_channel:
            for channel in guild.text_channels:
                if channel.permissions_for(guild.me).send_messages:
                    target_channel = channel
                    break
        
        if target_channel:
            view = SetupInstructionsView()
            
            welcome_text = f"👋 Welcome! I'm **On the Clock**, your professional Discord timeclock bot.\n\n"
            if inviter:
                welcome_text += f"{inviter.mention} added me to help manage your team's time tracking.\n\n"
            welcome_text += "Click the button below for setup instructions and getting started guide!"
            
            await target_channel.send(welcome_text, view=view)
            print(f"✅ Sent welcome button to #{target_channel.name} in {guild.name}")
        else:
            print(f"⚠️ Could not find any text channel to send welcome button in {guild.name}")
    except Exception as e:
        print(f"❌ Error sending welcome button to channel in {guild.name}: {e}")
    
    # Add guild to bot_guilds table
    try:
        with db() as conn:
            conn.execute("""
                INSERT INTO bot_guilds (guild_id, guild_name, joined_at, is_present, left_at)
                VALUES (%s, %s, NOW(), TRUE, NULL)
                ON CONFLICT (guild_id) DO UPDATE 
                SET guild_name = EXCLUDED.guild_name, joined_at = NOW(), is_present = TRUE, left_at = NULL
            """, (str(guild.id), guild.name))
        print(f"✅ Added {guild.name} to bot_guilds table")
    except Exception as e:
        print(f"❌ Error adding guild to bot_guilds table: {e}")

    # Set trial start date
    try:
        with db() as conn:
            conn.execute("""
                INSERT INTO guild_settings (guild_id, trial_start_date)
                VALUES (%s, NOW())
                ON CONFLICT (guild_id) DO NOTHING
            """, (guild.id,))
        print(f"✅ Set trial start date for {guild.name}")
    except Exception as e:
        print(f"❌ Error setting trial start date for {guild.name}: {e}")


@bot.event
async def on_member_join(member):
    """Handle new members joining - special handling for demo server"""
    if member.guild.id != DEMO_SERVER_ID:
        # Check if they are a registered employee in a non-demo server
        try:
            with db() as conn:
                cursor = conn.execute(
                    "SELECT 1 FROM employee_profiles WHERE guild_id = %s AND user_id = %s",
                    (member.guild.id, member.id)
                )
                is_employee = cursor.fetchone()
                
                if is_employee:
                    # They are a returning employee, re-apply the role if configured
                    cursor = conn.execute(
                        "SELECT employee_role_id FROM guild_settings WHERE guild_id = %s",
                        (member.guild.id,)
                    )
                    row = cursor.fetchone()
                    if row and row['employee_role_id']:
                        role = member.guild.get_role(int(row['employee_role_id']))
                        if role:
                            await member.add_roles(role, reason="Auto-assigned for returning employee")
                            print(f"✅ Re-assigned employee role to {member.display_name} in {member.guild.name}")
        except Exception as e:
            print(f"❌ Error checking/assigning role for returning member {member.id} in {member.guild.id}: {e}")
        return
    
    print(f"👋 New member joined demo server: {member.display_name}")
    
    try:
        # Use production URL for OAuth compatibility
        dashboard_url = "https://time-warden.com"
        
        embed = discord.Embed(
            title="🎮 Welcome to the Time Warden Demo Server!",
            description="Thanks for checking out our Discord timeclock bot! This demo lets you explore **all features** with live test data.",
            color=0x00FFFF  # Cyan to match branding
        )
        embed.add_field(
            name="🎭 STEP 1: Choose Your Demo Persona",
            value="Click a button below to begin your demo:\n• 👷 **Become Employee** - Test clock in/out features\n• 👑 **Become Admin** - Manage employees and settings",
            inline=False
        )
        embed.add_field(
            name="🖥️ STEP 2: Try the Web Dashboard",
            value=f"[Login to Dashboard]({dashboard_url}/auth/login)\n\nExplore our core product! The full admin dashboard allows you to manage staff, edit timesheets, view reports, and configure server settings.",
            inline=False
        )
        embed.add_field(
            name="📱 STEP 3: Try the Kiosk Mode (BETA)",
            value=f"[Open Demo Kiosk]({dashboard_url}/kiosk/{DEMO_SERVER_ID})\n\nOur upcoming physical workplace solution. Test our tablet-friendly interface with PIN-based clock in/out.",
            inline=False
        )
        embed.add_field(
            name="💬 Discord Commands",
            value="• `/clock` - Open your personal timeclock\n• `/help` - See all available commands\n• `/report` - Generate timesheet reports",
            inline=False
        )
        embed.set_footer(text="Time Warden - Professional Time Tracking for Discord Teams")
        
        # Send Welcome DM as a reference
        try:
            await member.send(embed=embed)
            print(f"✅ Sent welcome DM to {member.display_name}")
        except discord.Forbidden:
            print(f"⚠️ Could not DM {member.display_name} - DMs disabled")
            
        # Send Interactive Onboarding directly in the server
        channel = member.guild.system_channel
        if not channel:
            # Fallback to the first available text channel we can send in
            for c in member.guild.text_channels:
                if c.permissions_for(member.guild.me).send_messages:
                    channel = c
                    break
                    
        if channel:
            view = DemoRoleSwitcherView()
            await channel.send(
                content=f"👋 Welcome {member.mention}! Please select your demo experience below:",
                embed=embed,
                view=view
            )
            print(f"✅ Sent interactive role selector to #{channel.name} for {member.display_name}")
            
    except Exception as e:
        print(f"❌ Error sending welcome messages: {e}")


@bot.event
async def on_guild_remove(guild):
    """Handle bot being removed from a server - archive paid servers, delete non-paid server data"""
    print(f"👋 Bot removed from server: {guild.name} (ID: {guild.id})")
    guild_id_str = str(guild.id)
    guild_id_int = guild.id
    
    try:
        with db() as conn:
            # Check if this server has paid access
            cursor = conn.execute(
                "SELECT bot_access_paid FROM server_subscriptions WHERE guild_id = %s",
                (guild_id_int,)
            )
            result = cursor.fetchone()
            has_paid_access = result and result.get('bot_access_paid', False)
            
            if has_paid_access:
                # PAID SERVER: Just mark as not present (archive) - keep all data for potential re-add
                conn.execute("""
                    UPDATE bot_guilds 
                    SET is_present = FALSE, left_at = NOW() 
                    WHERE guild_id = %s
                """, (guild_id_str,))
                print(f"📁 Archived paid server {guild.name} - subscription data preserved")
            else:
                # NON-PAID SERVER: Delete all server data
                print(f"🗑️ Cleaning up non-paid server {guild.name}...")
                
                # Delete employee profiles
                conn.execute("DELETE FROM employee_profiles WHERE guild_id = %s", (guild_id_int,))
                print(f"   - Deleted employee profiles")
                
                # Delete time adjustment requests
                conn.execute("DELETE FROM time_adjustment_requests WHERE guild_id = %s", (guild_id_int,))
                print(f"   - Deleted time adjustment requests")
                
                # Delete admin roles
                conn.execute("DELETE FROM admin_roles WHERE guild_id = %s", (guild_id_str,))
                print(f"   - Deleted admin roles")
                
                conn.execute("DELETE FROM employee_roles WHERE guild_id = %s", (guild_id_str,))
                print(f"   - Deleted employee roles")
                
                # Delete guild settings
                # conn.execute("DELETE FROM guild_settings WHERE guild_id = %s", (guild_id_int,))
                # print(f"   - Deleted guild settings")
                # Phase 2: We no longer delete guild_settings so trial_start_date is permanently preserved
                
                # Delete sessions
                conn.execute("DELETE FROM timeclock_sessions WHERE guild_id = %s", (guild_id_int,))
                print(f"   - Deleted sessions")
                
                # Delete server subscription record (if any non-paid entry exists)
                conn.execute("DELETE FROM server_subscriptions WHERE guild_id = %s AND (bot_access_paid = FALSE OR bot_access_paid IS NULL)", (guild_id_int,))
                
                # Delete from bot_guilds entirely
                conn.execute("DELETE FROM bot_guilds WHERE guild_id = %s", (guild_id_str,))
                print(f"✅ Completely removed non-paid server {guild.name} and all data")
                
    except Exception as e:
        print(f"❌ Error handling guild removal for {guild.name}: {e}")

@tree.command(name="setup", description="View timeclock setup information and instructions")
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def setup(interaction: discord.Interaction):
    """
    Display comprehensive onboarding guide for new users.
    Shows role management, dashboard features, and pricing information.
    """
    # Robust defer with proper fallback
    defer_success = await robust_defer(interaction, ephemeral=True)
    if not defer_success and not interaction.response.is_done():
        return
    
    guild_id = interaction.guild_id
    if guild_id is None:
        await interaction.edit_original_response(content="❌ This command must be used in a server.")
        return
    
    try:
        # Use the same domain detection as other functions
        dashboard_url = f"https://{get_domain()}"
        payment_url = f"https://{get_domain()}/upgrade"
        
        embed = discord.Embed(
            title="⏰ Welcome to Time Warden!",
            description="Complete onboarding guide for setting up your timeclock bot",
            color=discord.Color.blue()
        )
        
        embed.add_field(
            name="📚 Step 1: Quick Start Wiki",
            value=(
                f"Read the **[Official Wiki]({dashboard_url}/wiki)** for a step-by-step guide on setting up your server, kiosk mode, and generating reports."
            ),
            inline=False
        )
        
        embed.add_field(
            name="🌐 Step 2: Dashboard Setup",
            value=(
                f"Visit **[Your Dashboard]({dashboard_url})** and log in with Discord:\n"
                "• **Admin / Employee Roles** - Define who can manage vs clock-in\n"
                "• **Timezone** - Set your server's local display time\n"
                "• **Email Reports** - Automate PDF timesheets"
            ),
            inline=False
        )
        
        if guild_id == DEMO_SERVER_ID:
            embed.add_field(
                name="🚧 Demo Server Notice",
                value=(
                    "You are currently exploring the **Live Demo**.\n"
                    "• **PINs:** Kiosk PINs for Demo Employees are auto-generated.\n"
                    "• **Data:** Dummy data is automatically seeded for testing.\n"
                    "• **Reset:** Data is pruned periodically."
                ),
                inline=False
            )
        else:
            embed.add_field(
                name="💰 Step 3: Pricing & Tiers",
                value=(
                    "**Your server starts with a generous 1-Month Free Trial!**\n\n"
                    "**Premium** - $8/month\n"
                    "• Full timeclock functionality & 30-day data retention\n\n"
                    "**Pro** - $15/month\n"
                    "• Premium + Kiosk Mode & Ad-Free Dashboard\n\n"
                    f"🛒 [Manage Subscription]({payment_url})"
                ),
                inline=False
            )
            
        embed.add_field(
            name="🆘 Need Help?",
            value=(
                "Join our [Support Discord](https://discord.gg/tMGssTjkUt) for help with setup, billing, or custom requests."
            ),
            inline=False
        )
        
        embed.set_footer(text="Time Warden • Professional Time Tracking for Discord")
        
        await interaction.edit_original_response(embed=embed)
        print(f"✅ Displayed setup information for guild {guild_id}")
        
    except Exception as e:
        print(f"❌ Failed to display setup information: {e}")
        await interaction.edit_original_response(
            content="❌ **Setup Information Error**\n\n"
                   "Could not retrieve setup information.\n"
                   "Please try again or contact support if the issue persists."
        )


@tree.command(name="clock", description="Open your personal timeclock hub")
@app_commands.guild_only()
async def clock_command(interaction: discord.Interaction):
    """
    Personal timeclock hub command with bulletproof button persistence.
    
    Uses the TimeclockHubView with stable custom_ids and fast ACK
    for maximum reliability across bot restarts.
    
    Buttons: Clock In, Clock Out, My Adjustments, My Hours, Support, Upgrade
    """
    # ACK immediately - fast response is critical
    if not await robust_defer(interaction, ephemeral=True):
        return
    
    guild_id = interaction.guild_id
    if guild_id is None:
        await interaction.followup.send("❌ This command must be used in a server.", ephemeral=True)
        return

    access = get_guild_access_info(guild_id)
    if not access['is_exempt'] and access['tier'] == 'free' and not access['trial_active']:
        embed = discord.Embed(
            title="⏰ Free Trial Expired",
            description="Your 30-day free trial has ended.\nUpgrade to Premium to continue using the timeclock!",
            color=discord.Color.red()
        )
        embed.add_field(name="💎 Premium", value="$8/month (first month FREE!)\n✅ Full team clock in/out\n✅ Dashboard & reports\n✅ 30-day data retention", inline=False)
        embed.add_field(name="🚀 Pro", value="$15/month — Coming Soon!\n✅ Everything in Premium\n✅ Kiosk mode\n✅ Ad-free dashboard", inline=False)
        embed.add_field(name="⬆️ Upgrade", value="Use `/upgrade` or visit your dashboard to subscribe!", inline=False)
        await interaction.followup.send(embed=embed, ephemeral=True)
        return

    # Check Kiosk Only Mode
    try:
        with db() as conn:
            cursor = conn.execute("SELECT kiosk_only_mode FROM guild_settings WHERE guild_id = %s", (guild_id,))
            settings = cursor.fetchone()
            
        if settings and settings.get('kiosk_only_mode'):
            await interaction.followup.send(
                "🖥️ **Kiosk Only Mode Active**\n\n"
                "Discord clocking is disabled for this server.\n"
                f"Please manage your time physically at the terminal: `https://time-warden.com/kiosk/{guild_id}`",
                ephemeral=True
            )
            return
    except Exception as e:
        print(f"Error checking kiosk mode: {e}")

    # Check permissions
    server_tier = get_guild_tier_string(guild_id)
    if not isinstance(interaction.user, discord.Member):
        await interaction.followup.send("❌ Unable to verify permissions.", ephemeral=True)
        return
    
    if not user_has_clock_access(interaction.user, server_tier):
        if server_tier == "free":
            await interaction.followup.send(
                "⚠️ **Free Tier Limitation**\n\n"
                "Only administrators can use timeclock on the free tier.\n"
                "Use `/upgrade` to unlock full team access!",
                ephemeral=True
            )
        else:
            await interaction.followup.send(
                "❌ **Access Denied**\n\n"
                "You need an employee role to use the timeclock.\n"
                "Ask an administrator to add your role with `/add_employee_role @yourrole`",
                ephemeral=True
            )
        return
    
    try:
        user_id = interaction.user.id
        
        # Check if this is the user's first time using /clock
        is_first_clock_use = False
        with db() as conn:
            cursor = conn.execute(
                "SELECT first_clock_used FROM employee_profiles WHERE guild_id = %s AND user_id = %s",
                (guild_id, user_id)
            )
            row = cursor.fetchone()
            if row and not row.get('first_clock_used', True):
                is_first_clock_use = True
                # Mark as used
                conn.execute("""
                    UPDATE employee_profiles 
                    SET first_clock_used = TRUE, first_clock_at = NOW()
                    WHERE guild_id = %s AND user_id = %s
                """, (guild_id, user_id))
        
        # Show first-time onboarding guide
        if is_first_clock_use:
            welcome_embed = discord.Embed(
                title="Welcome to Your Timeclock!",
                description="This is your personal time management hub. Here's a quick guide:",
                color=0x57F287
            )
            welcome_embed.add_field(
                name="How It Works",
                value=(
                    "**Clock In** - Start tracking your work time\n"
                    "**Clock Out** - End your shift and log your hours\n"
                    "**My Hours** - View your weekly summary\n"
                    "**My Adjustments** - Request time corrections"
                ),
                inline=False
            )
            welcome_embed.add_field(
                name="Tips",
                value=(
                    "Your timeclock is private - only you see your interface.\n"
                    "Buttons work even if the bot restarts.\n"
                    "Use `/clock` anytime to access your hub."
                ),
                inline=False
            )
            welcome_embed.set_footer(text="Click any button below to get started!")
            
            view = build_timeclock_hub_view(guild_id, welcome_embed)
            await interaction.followup.send(embed=welcome_embed, view=view, ephemeral=True)
            print(f"First-time /clock onboarding sent to {interaction.user} in guild {guild_id}")
            return
        
        # Get current status
        with db() as conn:
            cursor = conn.execute(
                "SELECT clock_in_time as clock_in FROM timeclock_sessions WHERE user_id = %s AND guild_id = %s AND clock_out_time IS NULL",
                (user_id, guild_id)
            )
            active_session = cursor.fetchone()
        
        # Build status embed
        if active_session:
            clock_in_time = safe_parse_timestamp(active_session['clock_in'])
            if clock_in_time.tzinfo is None:
                clock_in_time = clock_in_time.replace(tzinfo=timezone.utc)
            elapsed = datetime.now(timezone.utc) - clock_in_time
            hours, remainder = divmod(int(elapsed.total_seconds()), 3600)
            minutes, _ = divmod(remainder, 60)
            
            embed = discord.Embed(
                title="⏰ Timeclock Hub",
                description="Your personal time management center",
                color=0x57F287  # Green for clocked in
            )
            embed.add_field(
                name="🟢 Status: Clocked In",
                value=f"**Started:** <t:{int(clock_in_time.timestamp())}:f>\n"
                      f"**Elapsed:** {hours}h {minutes}m",
                inline=False
            )
        else:
            embed = discord.Embed(
                title="⏰ Timeclock Hub",
                description="Your personal time management center",
                color=0xD4AF37  # Gold
            )
            embed.add_field(
                name="⚪ Status: Not Clocked In",
                value="Ready to start your shift!",
                inline=False
            )
        
        # Get quick stats (last 7 days)
        with db() as conn:
            cursor = conn.execute("""
                SELECT COALESCE(SUM(
                    EXTRACT(EPOCH FROM (COALESCE(clock_out_time, NOW()) - clock_in_time)) / 3600
                ), 0) as week_hours
                FROM timeclock_sessions 
                WHERE user_id = %s AND guild_id = %s 
                AND clock_in_time >= NOW() - INTERVAL '7 days'
            """, (user_id, guild_id))
            row = cursor.fetchone()
            week_hours = float(row['week_hours']) if row and row['week_hours'] else 0
        
        embed.add_field(
            name="📊 This Week",
            value=f"**Hours:** {week_hours:.1f}h",
            inline=True
        )
        
        embed.set_footer(text="Buttons below work even after bot restarts • On the Clock")
        
        # Send with bulletproof view
        view = build_timeclock_hub_view(guild_id, embed)
        await interaction.followup.send(embed=embed, view=view, ephemeral=True)
        print(f"✅ [TC Hub] Sent timeclock hub to {interaction.user} in guild {guild_id}")
        
    except Exception as e:
        print(f"❌ [TC Hub] Error creating hub for {interaction.user}: {e}")
        await interaction.followup.send(
            "❌ **Error**\nCouldn't load timeclock hub. Please try again.",
            ephemeral=True
        )


# REMOVED: Settings commands moved to dashboard
# /set_recipient, /set_timezone, /toggle_name_display, /mobile
# These features are now available in the dashboard under Timezone Settings



# REMOVED: Role management commands moved to dashboard
# /add_admin_role, /remove_admin_role, /list_admin_roles
# /set_main_role, /show_main_role, /clear_main_role
# /add_employee_role, /remove_employee_role, /list_employee_roles
# These features are now available in the Dashboard under Admin Roles and Employee Roles


@tree.command(name="upgrade", description="View subscription plans and upgrade your server")
@app_commands.guild_only()
async def upgrade_command(interaction: discord.Interaction):
    if interaction.guild_id is None:
        await send_reply(interaction, "❌ This command must be used in a server.", ephemeral=True)
        return

    guild_id = interaction.guild_id
    access = get_guild_access_info(guild_id)
    domain = get_domain()
    purchase_url = f"https://{domain}/purchase/premium"

    if access['is_exempt']:
        embed = discord.Embed(
            title="⭐ Full Access Granted",
            description="This server has full access to all features. No upgrade needed!",
            color=discord.Color.gold()
        )
        await send_reply(interaction, embed=embed, ephemeral=True)
        return

    if access['tier'] == 'pro':
        embed = discord.Embed(
            title="🚀 Pro Plan Active",
            description="This server is on the **Pro** plan — you have access to everything!",
            color=discord.Color.purple()
        )
        embed.add_field(name="Includes", value="All Premium features + Kiosk Mode + Ad-free Dashboard", inline=False)
        await send_reply(interaction, embed=embed, ephemeral=True)
        return

    if access['tier'] == 'premium':
        embed = discord.Embed(
            title="💎 Premium Plan Active",
            description="This server is on the **Premium** plan.",
            color=discord.Color.blue()
        )
        embed.add_field(
            name="🚀 Upgrade to Pro ($15/mo)",
            value="Get Kiosk Mode for shared-device clock-in, ad-free dashboard, and priority support.",
            inline=False
        )
        embed.add_field(name="How to Upgrade", value=f"Visit your [dashboard]({purchase_url}) to manage your subscription.", inline=False)
        await send_reply(interaction, embed=embed, ephemeral=True)
        return

    if access['trial_active']:
        days = access['days_remaining']
        embed = discord.Embed(
            title="🆓 Free Trial Active",
            description=f"You have **{days} day{'s' if days != 1 else ''}** remaining on your free trial.",
            color=discord.Color.green()
        )
    else:
        embed = discord.Embed(
            title="⚠️ Trial Expired",
            description="Your free trial has ended. Subscribe to continue using the bot!",
            color=discord.Color.red()
        )

    embed.add_field(
        name="💎 Premium — $8/month",
        value=(
            "**First month FREE!**\n"
            "• Full bot access (clock in/out, reports)\n"
            "• Web dashboard with team management\n"
            "• CSV report exports\n"
            "• Email automation & reminders\n"
            "• 30-day data retention\n"
            "• Calendar view & time adjustments"
        ),
        inline=False
    )
    embed.add_field(
        name="🚀 Pro — $15/month (Coming Soon)",
        value=(
            "Everything in Premium, plus:\n"
            "• Kiosk Mode for shared devices\n"
            "• Ad-free dashboard\n"
            "• Priority support"
        ),
        inline=False
    )
    embed.add_field(
        name="👉 Subscribe Now",
        value=f"**[Click here to subscribe]({purchase_url})**",
        inline=False
    )
    embed.set_footer(text="Cancel anytime. Your first month of Premium is completely free!")

    await send_reply(interaction, embed=embed, ephemeral=True)


@tree.command(name="help", description="List all available slash commands")
@app_commands.guild_only()
async def help_command(interaction: discord.Interaction):
    if interaction.guild_id is None:
        await send_reply(interaction, "❌ This command must be used in a server.", ephemeral=True)
        return
    
    guild_id = interaction.guild_id
    access = get_guild_access_info(guild_id)

    tier_display = ""
    tier_color = discord.Color.greyple()
    footer_text = ""

    if access['is_exempt']:
        tier_display = "⭐ Full Access"
        tier_color = discord.Color.gold()
        footer_text = "⭐ Full Access"
    elif access['tier'] == 'pro':
        tier_display = "🚀 PRO PLAN"
        tier_color = discord.Color.purple()
        footer_text = "🚀 Pro Plan Active"
    elif access['tier'] == 'premium':
        tier_display = "💎 PREMIUM PLAN"
        tier_color = discord.Color.blue()
        footer_text = "💎 Premium Plan Active"
    elif access['trial_active']:
        tier_display = "🆓 FREE TRIAL"
        tier_color = discord.Color.green()
        days = access['days_remaining']
        footer_text = f"🆓 Free Trial - {days} day{'s' if days != 1 else ''} remaining"
    else:
        tier_display = "⚠️ TRIAL EXPIRED"
        tier_color = discord.Color.red()
        footer_text = "⚠️ Trial Expired — Use /upgrade to continue"

    embed = discord.Embed(
        title="⏰ On the Clock - Help",
        description=f"**Your Server:** {tier_display}\n\nSimple time tracking for your team, right in Discord.",
        color=tier_color
    )
    
    embed.add_field(
        name="📱 Discord Commands",
        value=(
            "`/clock` - Open your timeclock (clock in/out, view hours)\n"
            "`/setup` - View setup instructions\n"
            "`/help` - This help menu"
        ),
        inline=False
    )
    
    embed.add_field(
        name="🖱️ Right-Click Actions (Admins)",
        value=(
            "Right-click any user → Apps:\n"
            "• **View Hours** - See employee's weekly hours\n"
            "• **View Profile** - Open employee's dashboard profile\n"
            "• **Send Shift Report** - Email shift report to recipients\n"
            "• **Force Clock Out** - Clock out an employee\n"
            "• **Ban from Timeclock** - Temporarily block access"
        ),
        inline=False
    )
    
    embed.add_field(
        name="🌐 Dashboard Features",
        value=(
            "**[time-warden.com/dashboard](https://time-warden.com/dashboard)**\n\n"
            "• **Role Management** - Set admin & employee roles\n"
            "• **Team Management** - Manage your team\n"
            "• **Time Adjustments** - Review & approve corrections\n"
            "• 💎 **Reports** - Export CSV timesheets\n"
            "• 💎 **Email Automation** - Daily reports & reminders\n"
            "• 🚀 **Kiosk Mode** - Shared device clock-in\n"
            "• **Calendar View** - Edit time entries"
        ),
        inline=False
    )
    
    if not access['is_exempt'] and access['tier'] == 'free':
        embed.add_field(
            name="⬆️ Upgrade to Premium",
            value=(
                "**Free Trial:** 30-day full access trial\n"
                "**Premium ($8/month, first month FREE!):** Full team access, dashboard, reports, 30-day retention\n"
                "**Pro ($15/month — Coming Soon!):** Kiosk mode + ad-free dashboard\n\n"
                "👉 Visit the dashboard to upgrade!"
            ),
            inline=False
        )
    else:
        embed.add_field(
            name="✅ Premium Active",
            value="You have full access to all dashboard features!",
            inline=False
        )
    
    embed.set_footer(text=footer_text)
    
    await send_reply(interaction, embed=embed, ephemeral=True)

# =============================================================================
# PHASE 5: FEEDBACK FUNNEL
# =============================================================================
class FeedbackModal(discord.ui.Modal, title="Submit Feedback"):
    feedback = discord.ui.TextInput(
        label="Your Feedback / Bug Report",
        style=discord.TextStyle.paragraph,
        placeholder="Tell us what you love, what needs fixing, or feature requests...",
        required=True,
        max_length=2000
    )

    async def on_submit(self, interaction: discord.Interaction):
        await send_reply(interaction, "✅ Thank you! Your feedback has been sent directly to our development team.", ephemeral=True)
        
        webhook_url = os.environ.get('DEVELOPER_WEBHOOK_URL')
        if not webhook_url:
            print("⚠️ DEVELOPER_WEBHOOK_URL not configured. Feedback suppressed.")
            return
            
        embed = discord.Embed(
            title="New User Feedback submitted!",
            description=self.feedback.value,
            color=discord.Color.gold(),
            timestamp=discord.utils.utcnow()
        )
        embed.set_author(name=f"{interaction.user} ({interaction.user.id})", icon_url=interaction.user.display_avatar.url if interaction.user.display_avatar else None)
        
        if interaction.guild:
            embed.set_footer(text=f"Server: {interaction.guild.name} ({interaction.guild.id})")
        else:
            embed.set_footer(text="Sent via DM")

        def send_webhook():
            try:
                import requests
                requests.post(webhook_url, json={"embeds": [embed.to_dict()]}, timeout=5)
            except Exception as e:
                print(f"❌ Failed to send feedback webhook: {e}")

        import threading
        t = threading.Thread(target=send_webhook)
        t.daemon = True
        t.start()


@tree.command(name="feedback", description="Send feedback, feature requests, or bug reports directly to the developers")
async def feedback_command(interaction: discord.Interaction):
    await interaction.response.send_modal(FeedbackModal())

# --- Scheduled Tasks ---
def schedule_daily_cleanup():
    """Schedule daily cleanup task"""
    def daily_cleanup():
        # Wait 60 seconds after startup before first cleanup attempt
        threading.Event().wait(60)
        
        while True:
            try:
                # Run cleanup
                deleted_count = cleanup_old_sessions()
                if deleted_count > 0:
                    print(f"🧹 Daily cleanup: Removed {deleted_count} old session records")
                
                # Sleep for 24 hours
                threading.Event().wait(86400)  # 24 hours in seconds
            except psycopg2.OperationalError as e:
                if "locked" in str(e).lower():
                    print(f"⏳ Database locked during daily cleanup, skipping this cycle: {e}")
                    threading.Event().wait(3600)  # Wait 1 hour before retrying
                else:
                    print(f"❌ Database error during daily cleanup: {e}")
                    threading.Event().wait(3600)  # Wait 1 hour before retrying
            except Exception as e:
                print(f"❌ Error during daily cleanup: {e}")
                threading.Event().wait(3600)  # Wait 1 hour before retrying
    
    cleanup_thread = threading.Thread(target=daily_cleanup, daemon=True)
    cleanup_thread.start()
    print("⏰ Daily cleanup scheduler started")

# REMOVED: Subscription and data management commands moved to dashboard
# /report, /data_cleanup, /purge, /upgrade, /cancel_subscription, /subscription_status
# These features are now available in the Dashboard

# =============================================================================
# TIME ADJUSTMENT REVIEW VIEW
# =============================================================================
class AdjustmentReviewView(discord.ui.View):
    """View for admins to approve/deny adjustment requests directly from Discord"""
    def __init__(self, request_id: int, guild_id: int):
        super().__init__(timeout=None)  # Persistent view
        self.request_id = request_id
        self.guild_id = guild_id

    @discord.ui.button(label="✅ Approve", style=discord.ButtonStyle.success, custom_id="adj_approve")
    async def approve_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        # Check permissions
        if not user_has_admin_access(interaction.user):
            await interaction.response.send_message("❌ You do not have permission to review adjustments.", ephemeral=True)
            return

        await interaction.response.defer()
        
        success, message = approve_adjustment(self.request_id, self.guild_id, interaction.user.id)
        
        if success:
            embed = interaction.message.embeds[0]
            embed.color = discord.Color.green()
            embed.set_field_at(0, name="Status", value="✅ Approved", inline=True)
            embed.add_field(name="Reviewed By", value=interaction.user.mention, inline=True)
            
            # Disable buttons
            for item in self.children:
                item.disabled = True
                
            await interaction.edit_original_response(embed=embed, view=self)
            await interaction.followup.send(f"✅ Adjustment request #{self.request_id} approved.", ephemeral=True)
        else:
            await interaction.followup.send(f"❌ Error: {message}", ephemeral=True)

    @discord.ui.button(label="❌ Deny", style=discord.ButtonStyle.danger, custom_id="adj_deny")
    async def deny_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        # Check permissions
        if not user_has_admin_access(interaction.user):
            await interaction.response.send_message("❌ You do not have permission to review adjustments.", ephemeral=True)
            return

        await interaction.response.defer()
        
        success, message = deny_adjustment(self.request_id, self.guild_id, interaction.user.id)
        
        if success:
            embed = interaction.message.embeds[0]
            embed.color = discord.Color.red()
            embed.set_field_at(0, name="Status", value="❌ Denied", inline=True)
            embed.add_field(name="Reviewed By", value=interaction.user.mention, inline=True)
            
            # Disable buttons
            for item in self.children:
                item.disabled = True
                
            await interaction.edit_original_response(embed=embed, view=self)
            await interaction.followup.send(f"✅ Adjustment request #{self.request_id} denied.", ephemeral=True)
        else:
            await interaction.followup.send(f"❌ Error: {message}", ephemeral=True)

async def notify_admins_of_adjustment(guild_id: int, request_id: int):
    """Send notification to admins about a new adjustment request"""
    try:
        guild = bot.get_guild(guild_id)
        if not guild:
            return

        # Get request details
        with db() as conn:
            cursor = conn.execute("""
                SELECT r.*, u.display_name, u.username 
                FROM time_adjustment_requests r
                LEFT JOIN employee_profiles u ON r.user_id = u.user_id AND r.guild_id = u.guild_id
                WHERE r.id = %s
            """, (request_id,))
            req = cursor.fetchone()
            
        if not req:
            return

        # Create Embed
        embed = discord.Embed(
            title="⏳ Time Adjustment Request",
            description=f"User **{req['display_name'] or req['username']}** has requested a time adjustment.",
            color=discord.Color.gold(),
            timestamp=datetime.now(timezone.utc)
        )
        
        embed.add_field(name="Status", value="⏳ Pending", inline=True)
        embed.add_field(name="Type", value=req['request_type'].replace('_', ' ').title(), inline=True)
        embed.add_field(name="Reason", value=req['reason'], inline=False)
        
        if req['original_clock_in']:
            embed.add_field(name="Original Time", value=f"{req['original_clock_in']}", inline=True)
        if req['requested_clock_in']:
            embed.add_field(name="Requested Time", value=f"{req['requested_clock_in']}", inline=True)

        view = AdjustmentReviewView(request_id, guild_id)

        # Build ping string for mapped Admin Roles
        admin_ping_str = ""
        with db() as conn:
            cursor = conn.execute("SELECT role_id FROM admin_roles WHERE guild_id = %s", (guild_id,))
            roles = cursor.fetchall()
            if roles:
                admin_ping_str = " ".join([f"<@&{r['role_id']}>" for r in roles])

        # Notify via Log Channel if configured
        log_channel_id = get_guild_setting(guild_id, "log_channel_id")
        if log_channel_id:
            channel = guild.get_channel(int(log_channel_id))
            if channel:
                msg_content = f"🔔 {admin_ping_str} New Time Adjustment Request!" if admin_ping_str else "🔔 New Time Adjustment Request!"
                await channel.send(content=msg_content, embed=embed, view=view)
                return

        # Fallback: Notify Owner DM
        owner_id = guild.owner_id
        owner = guild.get_member(owner_id)
        if owner:
            try:
                await owner.send(content=f"New adjustment request in **{guild.name}**:", embed=embed, view=view)
            except:
                pass

    except Exception as e:
        print(f"❌ Error notifying admins of adjustment: {e}")

# =============================================================================
# BROADCAST FUNCTION (Called from Flask API)
# =============================================================================

async def send_broadcast_to_guilds(guild_ids: list, title: str, message: str) -> dict:
    """
    Send a broadcast message to multiple guilds.
    Returns dict with sent_count and failed_count.
    """
    import logging
    logger = logging.getLogger('bot.broadcast')
    
    sent_count = 0
    failed_count = 0
    
    for guild_id in guild_ids:
        try:
            guild = bot.get_guild(int(guild_id))
            if not guild:
                logger.warning(f"[BROADCAST] Guild {guild_id} not found in cache")
                failed_count += 1
                continue
            
            # Create the broadcast embed
            embed = discord.Embed(
                title=f"📢 {title}",
                description=message,
                color=discord.Color.gold(),
                timestamp=datetime.now(timezone.utc)
            )
            embed.set_footer(text="On the Clock Bot Announcement")
            
            # Find a channel to send to
            channel_to_use = None
            
            # First, try to use the broadcast channel if configured
            broadcast_channel_id = get_guild_setting(int(guild_id), "broadcast_channel_id")
            if broadcast_channel_id:
                channel_to_use = guild.get_channel(int(broadcast_channel_id))
            
            # If no broadcast channel, try to find system channel
            if not channel_to_use and guild.system_channel:
                if guild.system_channel.permissions_for(guild.me).send_messages:
                    channel_to_use = guild.system_channel
            
            # If still no channel, find first text channel we can send to
            if not channel_to_use:
                for channel in guild.text_channels:
                    if channel.permissions_for(guild.me).send_messages:
                        channel_to_use = channel
                        break
            
            if channel_to_use:
                await channel_to_use.send(embed=embed)
                logger.info(f"[BROADCAST] Sent to {guild.name} (#{channel_to_use.name})")
                sent_count += 1
            else:
                logger.warning(f"[BROADCAST] No sendable channel found in {guild.name}")
                failed_count += 1
                
        except discord.Forbidden:
            logger.warning(f"[BROADCAST] Permission denied for guild {guild_id}")
            failed_count += 1
        except Exception as e:
            logger.error(f"[BROADCAST] Error sending to guild {guild_id}: {e}")
            failed_count += 1
    
    logger.info(f"[BROADCAST] Complete: {sent_count} sent, {failed_count} failed")
    return {'success': True, 'sent_count': sent_count, 'failed_count': failed_count}

# =============================================================================
# OWNER-ONLY SUPER ADMIN COMMANDS (Only visible to bot owner)
# =============================================================================

@tree.command(name="setup_demo_roles", description="[OWNER] Post the demo role switcher message")
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def setup_demo_roles_command(interaction: discord.Interaction):
    """
    Posts a persistent message with buttons for users to switch between Admin and Employee roles.
    Only works on the demo server. Admins use this to set up the role switcher.
    """
    if interaction.user.id != interaction.guild.owner_id and interaction.user.id != BOT_OWNER_ID:
        await interaction.response.send_message("❌ This command is strictly locked to the Server Owner.", ephemeral=True)
        return
    import time
    execution_id = f"{interaction.user.id}-{int(time.time() * 1000)}"
    print(f"🎭 [SETUP_DEMO_ROLES] Execution ID: {execution_id} - Command invoked by {interaction.user} in guild {interaction.guild_id}")

    # Verify this is the demo server
    if interaction.guild_id != DEMO_SERVER_ID:
        await send_reply(
            interaction,
            "❌ This command only works on the demo server.",
            ephemeral=True
        )
        return

    await robust_defer(interaction, ephemeral=True)

    # Deduplication check - prevent duplicate execution within 2-second window
    call_key = (interaction.guild_id, interaction.user.id)
    current_time = time.time()

    if call_key in _setup_demo_roles_recent_calls:
        last_call = _setup_demo_roles_recent_calls[call_key]
        if current_time - last_call < 2.0:
            print(f"🎭 [SETUP_DEMO_ROLES] {execution_id} - Duplicate call detected (last call {current_time - last_call:.2f}s ago) - ignoring")
            await send_reply(interaction, "⏳ Please wait - already processing your request.", ephemeral=True)
            return

    # Record this call
    _setup_demo_roles_recent_calls[call_key] = current_time

    # Clean up old entries (older than 10 seconds)
    for k, v in list(_setup_demo_roles_recent_calls.items()):
        if current_time - v >= 10.0:
            del _setup_demo_roles_recent_calls[k]

    try:
        # Create the embed
        embed = discord.Embed(
            title="🎭 Choose Your Role",
            description=(
                "Welcome to the Time Warden demo! Choose how you'd like to experience our timeclock system.\n\n"
                "You can switch between roles at any time by clicking the buttons below."
            ),
            color=0x00FFFF  # Cyan
        )

        embed.add_field(
            name="👑 Admin Mode",
            value=(
                "Experience the Dashboard as a **Manager**.\n"
                "• Approve timesheets and view reports\n"
                "• Configure settings and manage roles\n"
                "• Access all administrative features"
            ),
            inline=False
        )

        embed.add_field(
            name="👷 Employee Mode",
            value=(
                "Experience the Dashboard as **Staff**.\n"
                "• Clock in/out from Discord or Dashboard\n"
                "• View your own timesheet history\n"
                "• Request time adjustments"
            ),
            inline=False
        )

        embed.set_footer(text="💡 Both roles are safe for testing - choose what you want to explore!")

        # Create the view with buttons
        view = DemoRoleSwitcherView()

        # Send the message
        print(f"🎭 [SETUP_DEMO_ROLES] {execution_id} - Sending embed to channel {interaction.channel.id}")
        message = await interaction.channel.send(embed=embed, view=view)
        print(f"🎭 [SETUP_DEMO_ROLES] {execution_id} - Message sent successfully with ID {message.id}")

        await send_reply(
            interaction,
            "✅ Demo role switcher posted! Users can now choose their role.",
            ephemeral=True
        )
        print(f"🎭 [SETUP_DEMO_ROLES] {execution_id} - Command completed successfully")

    except Exception as e:
        print(f"❌ [SETUP_DEMO_ROLES] {execution_id} - Error: {e}")
        await send_reply(
            interaction,
            "❌ Failed to post role switcher. Please try again.",
            ephemeral=True
        )


@tree.command(name="owner_broadcast", description="[OWNER] Send announcement to all servers")
@app_commands.describe(
    title="Title of the broadcast message",
    message="The message content to send",
    target="Which servers to send to"
)
@app_commands.choices(target=[
    app_commands.Choice(name="All Servers", value="all"),
    app_commands.Choice(name="Paid Servers Only", value="paid"),
    app_commands.Choice(name="Free Tier Only", value="free")
])
async def owner_broadcast_command(interaction: discord.Interaction, title: str, message: str, target: str = "all"):
    """Owner-only command to broadcast messages to all servers"""
    if interaction.user.id != BOT_OWNER_ID:
        await send_reply(interaction, "❌ Access denied.", ephemeral=True)
        return
    
    await interaction.response.defer(ephemeral=True)
    
    try:
        # Get guild IDs based on target
        # Note: bot_guilds.guild_id is TEXT, server_subscriptions.guild_id is BIGINT - must cast for JOIN
        with db() as conn:
            if target == 'all':
                cursor = conn.execute("""
                    SELECT DISTINCT guild_id FROM bot_guilds WHERE is_present = TRUE
                """)
            elif target == 'paid':
                cursor = conn.execute("""
                    SELECT bg.guild_id FROM bot_guilds bg
                    JOIN server_subscriptions ss ON CAST(bg.guild_id AS BIGINT) = ss.guild_id
                    WHERE bg.is_present = TRUE AND ss.bot_access_paid = TRUE
                """)
            else:  # free
                cursor = conn.execute("""
                    SELECT bg.guild_id FROM bot_guilds bg
                    LEFT JOIN server_subscriptions ss ON CAST(bg.guild_id AS BIGINT) = ss.guild_id
                    WHERE bg.is_present = TRUE AND (ss.bot_access_paid IS NULL OR ss.bot_access_paid = FALSE)
                """)
            
            guild_rows = cursor.fetchall()
            guild_ids = [row['guild_id'] for row in guild_rows]
        
        if not guild_ids:
            await interaction.followup.send("❌ No servers found matching the target filter.", ephemeral=True)
            return
        
        # Send the broadcast
        result = await send_broadcast_to_guilds(guild_ids, title, message)
        
        embed = discord.Embed(
            title="📢 Broadcast Complete",
            color=discord.Color.gold() if result['failed_count'] == 0 else discord.Color.orange()
        )
        embed.add_field(name="Target", value=target.title(), inline=True)
        embed.add_field(name="Sent", value=str(result['sent_count']), inline=True)
        embed.add_field(name="Failed", value=str(result['failed_count']), inline=True)
        embed.add_field(name="Title", value=title[:100], inline=False)
        embed.add_field(name="Message Preview", value=message[:200] + ("..." if len(message) > 200 else ""), inline=False)
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
    except Exception as e:
        print(f"Broadcast command error: {e}")
        await interaction.followup.send(f"❌ Broadcast failed: {str(e)}", ephemeral=True)

@tree.command(name="owner_grant", description="[OWNER] Grant subscription tier to current server")
@app_commands.describe(tier="Subscription tier to grant")
@app_commands.choices(tier=[
    app_commands.Choice(name="Premium", value="bot_access"),
    app_commands.Choice(name="Pro Retention (30-day)", value="pro")
])
async def owner_grant_tier(interaction: discord.Interaction, tier: str):
    """Owner-only command to grant subscription tiers"""
    if interaction.user.id != BOT_OWNER_ID:
        await send_reply(interaction, "❌ Access denied.", ephemeral=True)
        return
        
    # Robust defer with proper fallback
    defer_success = await robust_defer(interaction, ephemeral=True)
    if not defer_success and not interaction.response.is_done():
        # If defer failed and interaction isn't done, we can't proceed
        return
    
    if interaction.guild is None:
        await interaction.followup.send("❌ This command must be used in a server.", ephemeral=True)
        return
        
    guild_id = interaction.guild.id
    guild_name = interaction.guild.name
    
    try:
        # Handle bot access grant differently
        if tier == "bot_access":
            set_bot_access(guild_id, True)
            
            embed = discord.Embed(
                title="👑 Owner Grant Successful",
                description=f"Manually granted **Bot Access** to this server",
                color=discord.Color.gold()
            )
            
            embed.add_field(name="Server", value=guild_name, inline=True)
            embed.add_field(name="Server ID", value=str(guild_id), inline=True)
            embed.add_field(name="Grant Type", value="Bot Access", inline=True)
            embed.add_field(name="Granted By", value="Bot Owner (Manual)", inline=True)
            
            embed.add_field(
                name="Features Unlocked",
                value="• Full team access\n• CSV Reports\n• Role management\n• Dashboard access",
                inline=False
            )
        else:
            # Check current tier
            current_tier = get_guild_tier_string(guild_id)

            # Grant the new tier (no Stripe subscription - manual owner grant)
            set_server_tier(guild_id, tier, subscription_id=f"owner_grant_{int(time.time())}", customer_id="owner_manual")
            
            # Also ensure bot access is granted (retention requires bot access)
            set_bot_access(guild_id, True)
            
            tier_display = "7-Day Retention" if tier == "basic" else "30-Day Retention"
            
            embed = discord.Embed(
                title="👑 Owner Grant Successful",
                description=f"Manually granted **{tier_display}** to this server",
                color=discord.Color.gold()
            )
            
            embed.add_field(name="Server", value=guild_name, inline=True)
            embed.add_field(name="Server ID", value=str(guild_id), inline=True)
            embed.add_field(name="Previous Tier", value=current_tier.title(), inline=True)
            embed.add_field(name="New Tier", value=tier.title(), inline=True)
            embed.add_field(name="Granted By", value="Bot Owner (Manual)", inline=True)
            embed.add_field(name="Type", value="Owner Override", inline=True)
            
            embed.add_field(
                name="Features Unlocked",
                value="• 30-day data retention\n• Advanced reporting\n• Extended history" if tier == "pro" else "• 7-day data retention\n• Extended reporting",
                inline=False
            )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
    except Exception as e:
        await interaction.followup.send(f"❌ Error granting tier: {str(e)}", ephemeral=True)


@tree.command(name="owner_grant_server", description="[OWNER] Grant subscription to any server by ID")
@app_commands.describe(
    server_id="Discord server ID to grant subscription to",
    tier="Subscription tier to grant"
)
@app_commands.choices(tier=[
    app_commands.Choice(name="Premium", value="bot_access"),
    app_commands.Choice(name="Pro Retention (30-day)", value="pro")
])
async def owner_grant_server_by_id(interaction: discord.Interaction, server_id: str, tier: str):
    """Owner-only command to grant subscriptions to any server by ID"""
    if interaction.user.id != BOT_OWNER_ID:
        await send_reply(interaction, "❌ Access denied.", ephemeral=True)
        return
        
    # Robust defer with proper fallback
    defer_success = await robust_defer(interaction, ephemeral=True)
    if not defer_success and not interaction.response.is_done():
        # If defer failed and interaction isn't done, we can't proceed
        return
    
    try:
        # Validate server ID
        try:
            guild_id = int(server_id)
        except ValueError:
            await interaction.followup.send("❌ Invalid server ID format.", ephemeral=True)
            return
        
        # Try to get guild info (if bot is in that server)
        guild = bot.get_guild(guild_id)
        guild_name = guild.name if guild else f"Server ID: {guild_id}"
        
        # Check if bot is in the server
        if not guild:
            await interaction.followup.send(f"⚠️ Bot is not in server {guild_id}. Grant will still be applied if server adds bot later.", ephemeral=True)
        
        # Handle bot access grant differently
        if tier == "bot_access":
            set_bot_access(guild_id, True)
            
            embed = discord.Embed(
                title="🌐 Remote Server Grant Successful",
                description=f"Granted **Bot Access** to remote server",
                color=discord.Color.purple()
            )
            
            embed.add_field(name="Target Server", value=guild_name, inline=True)
            embed.add_field(name="Server ID", value=str(guild_id), inline=True)
            embed.add_field(name="Bot Present", value="✅ Yes" if guild else "❌ No", inline=True)
            embed.add_field(name="Grant Type", value="Bot Access", inline=True)
            
            if guild:
                embed.add_field(name="Member Count", value=str(guild.member_count), inline=True)
                embed.add_field(name="Server Owner", value=str(guild.owner), inline=True)
            
            embed.add_field(
                name="Features Unlocked",
                value="• Full team access\n• CSV Reports\n• Role management\n• Dashboard access",
                inline=False
            )
        else:
            # Check current tier
            current_tier = get_guild_tier_string(guild_id)

            # Grant the tier
            set_server_tier(guild_id, tier, subscription_id=f"owner_remote_{int(time.time())}", customer_id="owner_remote")
            
            # Also ensure bot access is granted (retention requires bot access)
            set_bot_access(guild_id, True)
            
            tier_display = "7-Day Retention" if tier == "basic" else "30-Day Retention"
            
            embed = discord.Embed(
                title="🌐 Remote Server Grant Successful",
                description=f"Granted **{tier_display}** to remote server",
                color=discord.Color.purple()
            )
            
            embed.add_field(name="Target Server", value=guild_name, inline=True)
            embed.add_field(name="Server ID", value=str(guild_id), inline=True)
            embed.add_field(name="Bot Present", value="✅ Yes" if guild else "❌ No", inline=True)
            embed.add_field(name="Previous Tier", value=current_tier.title(), inline=True)
            embed.add_field(name="New Tier", value=tier.title(), inline=True)
            embed.add_field(name="Grant Type", value="Remote Owner Override", inline=True)
            
            if guild:
                embed.add_field(name="Member Count", value=str(guild.member_count), inline=True)
                embed.add_field(name="Server Owner", value=str(guild.owner), inline=True)
            
            embed.add_field(
                name="Status",
                value="✅ Subscription active immediately" if guild else "⏳ Will activate when bot joins server",
                inline=False
            )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
    except Exception as e:
        await interaction.followup.send(f"❌ Error granting remote server subscription: {str(e)}", ephemeral=True)

# ---------------------------------------------------------
# LAYER 3: LEGAL, PRIVACY, & COMPLIANCE TOOLS
# ---------------------------------------------------------

@bot.event
async def on_guild_remove(guild):
    """Fires when the bot is kicked from a server. Instantly terminates subscriptions and sets presence flag to False."""
    try:
        print(f"[{datetime.now()}] Bot removed from server: {guild.name} ({guild.id})")
        with get_db() as conn:
            # 1. Mark bot as not present
            conn.execute("""
                UPDATE bot_guilds 
                SET is_present = FALSE, left_at = NOW() 
                WHERE guild_id = %s
            """, (str(guild.id),))
            
            # 2. Cancel active Stripe subscriptions to prevent phantom billing
            cursor = conn.execute("""
                SELECT subscription_id FROM server_subscriptions 
                WHERE guild_id = %s AND status = 'active' AND subscription_id IS NOT NULL
            """, (str(guild.id),))
            sub = cursor.fetchone()
            
            if sub and sub['subscription_id']:
                import stripe
                try:
                    stripe.Subscription.modify(
                        sub['subscription_id'],
                        cancel_at_period_end=True
                    )
                    conn.execute("""
                        UPDATE server_subscriptions 
                        SET cancel_at_period_end = TRUE 
                        WHERE guild_id = %s
                    """, (str(guild.id),))
                    print(f"  -> Successfully issued Stripe cancellation for severed guild {guild.id}")
                except Exception as stripe_error:
                    print(f"  -> Stripe cancellation failed for severed guild {guild.id}: {stripe_error}")
    except Exception as e:
        print(f"Error handling guild removal for {guild.id}: {e}")

@app_commands.command(name="my_data", description="[PRIVACY] View or delete your personal data (GDPR/CCPA Compliance)")
@app_commands.choices(action=[
    app_commands.Choice(name="View My Data", value="view"),
    app_commands.Choice(name="Delete My Data (Irreversible)", value="delete")
])
async def my_data_command(interaction: discord.Interaction, action: app_commands.Choice[str]):
    """Allow users to view or wipe their dataset from our servers."""
    user_id = str(interaction.user.id)
    guild_id = str(interaction.guild_id)
    
    if action.value == "view":
        await interaction.response.send_message(
            "🗄️ **Your Data Summary:**\n"
            "We store your Discord ID, Username, configured Timezone, and Clock-In timestamps required for payroll generation.\n"
            "To request a full JSON export, please email privacy@ontheclock.bot.",
            ephemeral=True
        )
        return
        
    elif action.value == "delete":
        try:
            with get_db() as conn:
                # Scramble profile, delete pins, and drop active sessions
                conn.execute("""
                    UPDATE employee_profiles 
                    SET first_name = 'Deleted', 
                        last_name = 'User', 
                        email = NULL,
                        timesheet_email = NULL,
                        phone = NULL,
                        is_active = FALSE
                    WHERE user_id = %s
                """, (user_id,))
                
                conn.execute("DELETE FROM employee_pins WHERE user_id = %s", (user_id,))
                conn.execute("DELETE FROM timeclock_sessions WHERE user_id = %s", (user_id,))
                
                await interaction.response.send_message(
                    "⚠️ **DATA ERASED**\n"
                    "Your personal information (Name, Email, Phone, PINs, and Time Logs) has been wiped from this server's database.\n"
                    "You will no longer appear on payroll exports.", 
                    ephemeral=True
                )
        except Exception as e:
            await interaction.response.send_message("❌ Database error during data removal request.", ephemeral=True)

bot.tree.add_command(my_data_command)

@app_commands.command(name="timezone", description="Set your personal dashboard and reporting timezone")
async def timezone_command(interaction: discord.Interaction, tz_string: str):
    """Allow employees to set their personal timezone"""
    import pytz
    if tz_string not in pytz.all_timezones:
        await interaction.response.send_message(
            f"❌ Invalid timezone: `{tz_string}`.\n"
            "Example valid formats: `America/New_York`, `America/Los_Angeles`, `Europe/London`.", 
            ephemeral=True
        )
        return
        
    try:
        with get_db() as conn:
            conn.execute("""
                INSERT INTO user_preferences (user_id, dashboard_timezone, timezone_configured)
                VALUES (%s, %s, TRUE)
                ON CONFLICT (user_id) DO UPDATE SET 
                dashboard_timezone = EXCLUDED.dashboard_timezone,
                timezone_configured = TRUE
            """, (str(interaction.user.id), tz_string))
            
            await interaction.response.send_message(f"✅ Your personal timezone is now locked to **{tz_string}**.", ephemeral=True)
    except Exception as e:
        await interaction.response.send_message("❌ Failed to save timezone preference.", ephemeral=True)

bot.tree.add_command(timezone_command)

@tree.command(name="owner_server_listings", description="[OWNER] View all servers with employee/admin headcounts")
async def owner_server_listings(interaction: discord.Interaction):
    """Owner-only command to list all servers with employee/admin headcounts"""
    if interaction.user.id != BOT_OWNER_ID:
        await send_reply(interaction, "❌ Access denied.", ephemeral=True)
        return
        
    # Robust defer with proper fallback
    defer_success = await robust_defer(interaction, ephemeral=True)
    if not defer_success and not interaction.response.is_done():
        # If defer failed and interaction isn't done, we can't proceed
        return
    
    try:
        embed = discord.Embed(
            title="📊 Server Listings",
            description=f"Bot is active in {len(bot.guilds)} servers",
            color=discord.Color.blue()
        )
        
        server_data = []
        
        for guild in bot.guilds:
            # Get bot access and retention tier status
            has_bot_access = check_bot_access(guild.id)
            retention_tier = get_retention_tier(guild.id)
            
            # Determine paid/free status
            paid_status = "Paid" if has_bot_access else "Free"
            
            # Format retention tier for display
            retention_display = {
                'none': 'None',
                '7day': '7-Day',
                '30day': '30-Day'
            }.get(retention_tier, 'None')
            
            # Get server owner (may be None if owner left)
            owner_name = str(guild.owner) if guild.owner else "Unknown"
            
            # Get bot join date
            joined_at = guild.me.joined_at if guild.me else None
            if joined_at:
                # Format as MM/DD/YY HH:MM AM/PM
                joined_date_str = joined_at.strftime("%m/%d/%y %I:%M %p")
            else:
                joined_date_str = "Unknown"
            
            server_data.append({
                'name': guild.name,
                'id': guild.id,
                'owner': owner_name,
                'member_count': guild.member_count,
                'retention_tier': retention_display,
                'paid_status': paid_status,
                'joined_at': joined_date_str
            })
        
        # Sort by member count (largest first)
        server_data.sort(key=lambda x: x['member_count'], reverse=True)
        
        # Add server info to embed (limit to prevent message too long)
        for i, server in enumerate(server_data[:15]):  # Show first 15 servers
            status_emoji = "💳" if server['paid_status'] == "Paid" else "🆓"
            
            embed.add_field(
                name=f"{status_emoji} {server['name'][:30]}" + ("..." if len(server['name']) > 30 else ""),
                value=f"**ID:** {server['id']}\n"
                      f"**Joined:** {server['joined_at']}\n"
                      f"**Owner:** {server['owner'][:25]}\n"
                      f"**Users:** {server['member_count']}\n"
                      f"**Retention:** {server['retention_tier']}\n"
                      f"**Status:** {server['paid_status']}",
                inline=True
            )
        
        if len(server_data) > 15:
            embed.add_field(
                name="...",
                value=f"And {len(server_data) - 15} more servers",
                inline=False
            )
        
        # Add summary
        total_members = sum(s['member_count'] for s in server_data)
        paid_count = len([s for s in server_data if s['paid_status'] == 'Paid'])
        free_count = len([s for s in server_data if s['paid_status'] == 'Free'])
        retention_7day = len([s for s in server_data if s['retention_tier'] == '7-Day'])
        retention_30day = len([s for s in server_data if s['retention_tier'] == '30-Day'])
        
        embed.add_field(
            name="📈 Summary",
            value=f"**Total Servers:** {len(server_data)}\n"
                  f"**Total Users:** {total_members:,}\n"
                  f"**Paid Servers:** {paid_count}\n"
                  f"**Free Servers:** {free_count}\n"
                  f"**7-Day Retention:** {retention_7day}\n"
                  f"**30-Day Retention:** {retention_30day}",
            inline=False
        )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
    except Exception as e:
        await interaction.followup.send(f"❌ Error fetching server listings: {str(e)}", ephemeral=True)


# --- Context Menu Commands (Right-Click Actions) ---

@tree.context_menu(name="View Hours")
async def context_view_hours(interaction: discord.Interaction, user: discord.Member):
    """Right-click context menu to view a user's hours"""
    await interaction.response.defer(ephemeral=True)
    
    guild_id = interaction.guild_id
    if not guild_id:
        await interaction.followup.send("❌ This command must be used in a server.", ephemeral=True)
        return

    access = get_guild_access_info(guild_id)
    if not access['is_exempt'] and access['tier'] == 'free' and not access['trial_active']:
        embed = discord.Embed(
            title="⏰ Free Trial Expired",
            description="Your 30-day free trial has ended.\nUpgrade to Premium to use this feature!",
            color=discord.Color.red()
        )
        embed.add_field(name="⬆️ Upgrade", value="Use `/upgrade` or visit your dashboard to subscribe!", inline=False)
        await interaction.followup.send(embed=embed, ephemeral=True)
        return

    # Check if invoker is admin
    if interaction.user and isinstance(interaction.user, discord.Member) and not interaction.user.guild_permissions.administrator:
        await interaction.followup.send("❌ Only admins can use this.", ephemeral=True)
        return
    
    # Get user's hours for last 7 days
    with db() as conn:
        cursor = conn.execute("""
            SELECT 
                SUM(EXTRACT(EPOCH FROM (COALESCE(clock_out_time, NOW()) - clock_in_time))/3600) as total_hours
            FROM timeclock_sessions
            WHERE guild_id = %s AND user_id = %s
            AND clock_in_time > NOW() - INTERVAL '7 days'
        """, (interaction.guild_id, user.id))
        result = cursor.fetchone()
        hours = result['total_hours'] if result and result['total_hours'] else 0
    
    embed = discord.Embed(
        title=f"📊 Hours for {user.display_name}",
        description=f"Last 7 days: **{hours:.1f} hours**",
        color=0xD4AF37
    )
    
    await interaction.followup.send(embed=embed, ephemeral=True)


@tree.context_menu(name="Force Clock Out")
async def context_force_clockout(interaction: discord.Interaction, user: discord.Member):
    """Right-click context menu to force clock out a user"""
    await interaction.response.defer(ephemeral=True)

    guild_id = interaction.guild_id
    if not guild_id:
        await interaction.followup.send("❌ This command must be used in a server.", ephemeral=True)
        return

    access = get_guild_access_info(guild_id)
    if not access['is_exempt'] and access['tier'] == 'free' and not access['trial_active']:
        embed = discord.Embed(
            title="⏰ Free Trial Expired",
            description="Your 30-day free trial has ended.\nUpgrade to Premium to use this feature!",
            color=discord.Color.red()
        )
        embed.add_field(name="⬆️ Upgrade", value="Use `/upgrade` or visit your dashboard to subscribe!", inline=False)
        await interaction.followup.send(embed=embed, ephemeral=True)
        return
    
    # Check if invoker is admin
    if interaction.user and isinstance(interaction.user, discord.Member) and not interaction.user.guild_permissions.administrator:
        await interaction.followup.send("❌ Only admins can use this.", ephemeral=True)
        return
    
    # Find active session and clock out
    with db() as conn:
        cursor = conn.execute("""
            UPDATE timeclock_sessions 
            SET clock_out_time = NOW()
            WHERE guild_id = %s AND user_id = %s AND clock_out_time IS NULL
            RETURNING session_id
        """, (interaction.guild_id, user.id))
        result = cursor.fetchone()
    
    if result:
        await interaction.followup.send(f"✅ Force clocked out {user.display_name}", ephemeral=True)
    else:
        await interaction.followup.send(f"ℹ️ {user.display_name} wasn't clocked in.", ephemeral=True)


@tree.context_menu(name="Ban from Timeclock")
async def context_ban_user(interaction: discord.Interaction, user: discord.Member):
    """Right-click context menu to ban a user from timeclock (24-hour ban)"""
    await interaction.response.defer(ephemeral=True)

    guild_id = interaction.guild_id
    if not guild_id:
        await interaction.followup.send("❌ This command must be used in a server.", ephemeral=True)
        return

    access = get_guild_access_info(guild_id)
    if not access['is_exempt'] and access['tier'] == 'free' and not access['trial_active']:
        embed = discord.Embed(
            title="⏰ Free Trial Expired",
            description="Your 30-day free trial has ended.\nUpgrade to Premium to use this feature!",
            color=discord.Color.red()
        )
        embed.add_field(name="⬆️ Upgrade", value="Use `/upgrade` or visit your dashboard to subscribe!", inline=False)
        await interaction.followup.send(embed=embed, ephemeral=True)
        return
    
    # Check if invoker is admin
    if interaction.user and isinstance(interaction.user, discord.Member) and not interaction.user.guild_permissions.administrator:
        await interaction.followup.send("❌ Only admins can use this.", ephemeral=True)
        return
    
    # Check if user is already banned
    if interaction.guild_id and is_user_banned(interaction.guild_id, user.id):
        await interaction.followup.send(f"ℹ️ {user.display_name} is already banned from the timeclock.", ephemeral=True)
        return
    
    # Ban user for 24 hours using existing function
    if interaction.guild_id:
        ban_user_24h(interaction.guild_id, user.id, "Banned via admin context menu")
        await interaction.followup.send(f"🚫 {user.display_name} has been banned from the timeclock for 24 hours.", ephemeral=True)
    else:
        await interaction.followup.send("❌ Error: Guild ID not found.", ephemeral=True)


@tree.context_menu(name="View Profile")
async def context_view_profile(interaction: discord.Interaction, user: discord.Member):
    """Right-click context menu to view employee profile in dashboard"""
    await interaction.response.defer(ephemeral=True)
    
    # Check if invoker is admin or the user themselves
    is_admin = isinstance(interaction.user, discord.Member) and interaction.user.guild_permissions.administrator
    is_self = interaction.user.id == user.id
    
    if not is_admin and not is_self:
        await interaction.followup.send("❌ You can only view your own profile or be an admin.", ephemeral=True)
        return
    
    # Check if user has an employee profile
    from app import get_db
    with get_db() as conn:
        cursor = conn.execute("""
            SELECT user_id FROM employee_profiles
            WHERE guild_id = %s AND user_id = %s AND is_active = TRUE
        """, (interaction.guild_id, user.id))
        profile = cursor.fetchone()
    
    if not profile:
        await interaction.followup.send(f"ℹ️ {user.display_name} doesn't have an employee profile yet.", ephemeral=True)
        return
    
    domain = get_domain()
    profile_url = f"https://{domain}/dashboard/server/{interaction.guild_id}/profile/{user.id}"
    
    embed = discord.Embed(
        title=f"📋 Profile: {user.display_name}",
        description=f"[Click here to view {'your' if is_self else 'their'} profile]({profile_url})",
        color=discord.Color.blue()
    )
    if user.display_avatar:
        embed.set_thumbnail(url=user.display_avatar.url)
    
    await interaction.followup.send(embed=embed, ephemeral=True)


@tree.context_menu(name="Send Shift Report")
async def context_send_shift_report(interaction: discord.Interaction, user: discord.Member):
    """Right-click context menu to email employee's shift report to configured recipients"""
    await interaction.response.defer(ephemeral=True)

    guild_id = interaction.guild_id
    if not guild_id:
        await interaction.followup.send("❌ This command must be used in a server.", ephemeral=True)
        return

    access = get_guild_access_info(guild_id)
    if not access['is_exempt'] and access['tier'] == 'free' and not access['trial_active']:
        embed = discord.Embed(
            title="⏰ Free Trial Expired",
            description="Your 30-day free trial has ended.\nUpgrade to Premium to use this feature!",
            color=discord.Color.red()
        )
        embed.add_field(name="⬆️ Upgrade", value="Use `/upgrade` or visit your dashboard to subscribe!", inline=False)
        await interaction.followup.send(embed=embed, ephemeral=True)
        return
    
    if interaction.user and isinstance(interaction.user, discord.Member) and not interaction.user.guild_permissions.administrator:
        await interaction.followup.send("❌ Only admins can send shift reports.", ephemeral=True)
        return
    
    guild_id = interaction.guild_id
    
    # Get verified email recipients
    from app import get_db
    with get_db() as conn:
        cursor = conn.execute("""
            SELECT email FROM email_recipients
            WHERE guild_id = %s AND verified = TRUE
        """, (guild_id,))
        recipients = [row['email'] for row in cursor.fetchall()]
    
    if not recipients:
        await interaction.followup.send("❌ No verified email recipients configured. Add emails in Dashboard → Email Settings.", ephemeral=True)
        return
    
    # Get guild settings for timezone and sessions
    with get_db() as conn:
        tz_cursor = conn.execute("SELECT timezone FROM guild_settings WHERE guild_id = %s", (str(guild_id),))
        tz_row = tz_cursor.fetchone()
        guild_tz = tz_row['timezone'] if tz_row and tz_row.get('timezone') else 'America/Chicago'
        
        cursor = conn.execute("""
            SELECT clock_in_time, clock_out_time,
                   EXTRACT(EPOCH FROM (COALESCE(clock_out_time, NOW()) - clock_in_time)) / 3600.0 as hours
            FROM timeclock_sessions
            WHERE guild_id = %s AND user_id = %s
            AND clock_in_time >= date_trunc('week', NOW() AT TIME ZONE %s)
            ORDER BY clock_in_time
        """, (guild_id, user.id, guild_tz))
        sessions = cursor.fetchall()
    
    if not sessions:
        await interaction.followup.send(f"ℹ️ {user.display_name} has no sessions this week.", ephemeral=True)
        return
    
    # Calculate total hours
    total_hours = sum(s['hours'] or 0 for s in sessions)
    
    if interaction.guild:
        server_name = interaction.guild.name
    else:
        server_name = "Unknown Server"
        
    report_lines = [f"Shift Report for {user.display_name}", f"Server: {server_name}", f"Week of {datetime.now().strftime('%B %d, %Y')}", "", "Sessions:"]
    
    for s in sessions:
        clock_in = s['clock_in_time'].strftime('%a %m/%d %I:%M %p') if s['clock_in_time'] else 'N/A'
        clock_out = s['clock_out_time'].strftime('%I:%M %p') if s['clock_out_time'] else 'In Progress'
        hours = s['hours'] or 0
        report_lines.append(f"  {clock_in} - {clock_out} ({hours:.2f} hrs)")
    
    report_lines.append(f"\nTotal Hours: {total_hours:.2f}")
    report_text = "\n".join(report_lines)
    
    # Import at function level to avoid circular imports
    from email_utils import queue_email
    
    try:
        for email in recipients:
            queue_email(
                email_type="shift_report",
                recipients=[email],
                subject=f"Shift Report: {user.display_name} - {server_name}",
                text_content=report_text,
                guild_id=int(guild_id) if guild_id else None
            )
        
        await interaction.followup.send(f"✅ Shift report for {user.display_name} queued for {len(recipients)} recipient(s).\n\n**Total Hours:** {total_hours:.2f}", ephemeral=True)
    except Exception as e:
        print(f"❌ Error sending shift report: {e}")
        await interaction.followup.send(f"❌ Failed to send report: {str(e)}", ephemeral=True)


# --- Bot HTTP API Server for Dashboard Integration ---
BOT_API_PORT = int(os.getenv("BOT_API_PORT", "8081"))
BOT_API_SECRET = os.getenv("BOT_API_SECRET", secrets.token_hex(32))  # Shared secret for auth

def verify_api_request(request: web.Request) -> bool:
    """
    Verify request is from authorized dashboard using shared secret
    Includes Webhook Replay Defense matching Timestamp hashes. 
    """
    import hmac
    import hashlib
    import time
    
    # 1. Check basic bearer
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return False
    token = auth_header[7:]  # Remove 'Bearer ' prefix
    
    if not secrets.compare_digest(token, BOT_API_SECRET):
        return False
        
    # 2. Replay Defense: Enforce Timestamp freshness (< 30s old)
    timestamp_str = request.headers.get('X-Timestamp')
    signature = request.headers.get('X-Signature')
    
    if not timestamp_str or not signature:
        print("⚠️ API Request blocked: Missing Replay Defense headers.")
        return False
        
    try:
        timestamp_float = float(timestamp_str)
        if abs(time.time() - timestamp_float) > 30: # 30 second window
            print(f"⚠️ API Request blocked: Timestamp {timestamp_float} is outside the 30s replay window.")
            return False
    except ValueError:
        return False
        
    # 3. Cryptographic Signature Match
    # Rebuild the expected signature: HMAC-SHA256(Secret, Timestamp)
    expected_mac = hmac.new(
        BOT_API_SECRET.encode('utf-8'),
        timestamp_str.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    if not secrets.compare_digest(expected_mac, signature):
        print("⚠️ API Request blocked: Cryptographic signature mismatch.")
        return False
        
    return True

async def handle_add_admin_role(request: web.Request):
    """HTTP endpoint: Add admin role"""
    if not verify_api_request(request):
        return web.json_response({'success': False, 'error': 'Unauthorized'}, status=401)
    
    try:
        data = await request.json()
        guild_id = int(request.match_info['guild_id'])
        role_id = int(data.get('role_id'))
        
        # Use existing bot function
        add_admin_role(guild_id, role_id)
        
        return web.json_response({
            'success': True,
            'message': 'Admin role added successfully',
            'role_id': str(role_id)
        })
    except Exception as e:
        print(f"❌ Error adding admin role via API: {e}")
        return web.json_response({'success': False, 'error': str(e)}, status=500)

async def handle_remove_admin_role(request: web.Request):
    """HTTP endpoint: Remove admin role"""
    if not verify_api_request(request):
        return web.json_response({'success': False, 'error': 'Unauthorized'}, status=401)
    
    try:
        data = await request.json()
        guild_id = int(request.match_info['guild_id'])
        role_id = int(data.get('role_id'))
        
        # Use existing bot function
        remove_admin_role(guild_id, role_id)
        
        return web.json_response({
            'success': True,
            'message': 'Admin role removed successfully',
            'role_id': str(role_id)
        })
    except Exception as e:
        print(f"❌ Error removing admin role via API: {e}")
        return web.json_response({'success': False, 'error': str(e)}, status=500)

async def sync_employees_for_role(guild_id: int, role_id: int) -> int:
    """Sync all members with a given role into employee_profiles. Returns count of new profiles created."""
    guild = bot.get_guild(guild_id)
    if not guild:
        print(f"⚠️ Cannot sync employees - guild {guild_id} not found")
        return 0
    
    role = guild.get_role(role_id)
    if not role:
        print(f"⚠️ Cannot sync employees - role {role_id} not found in guild {guild_id}")
        return 0
    
    server_tier = get_guild_tier_string(guild_id)
    
    new_count = 0
    for member in role.members:
        if member.bot:
            continue
            
        # PHASE 2: Free Tier App-Wide 3-User Hard-Cap during sync
        if server_tier == 'free':
            try:
                with db() as conn:
                    # Check if already an active employee
                    cursor = conn.execute("SELECT is_active FROM employee_profiles WHERE guild_id = %s AND user_id = %s", (guild_id, member.id))
                    existing = cursor.fetchone()
                
                # Only enforce cap if they are completely new or inactive
                if not existing or not existing['is_active']:
                    with db() as conn:
                        cursor = conn.execute("SELECT COUNT(*) as count FROM employee_profiles WHERE guild_id = %s AND is_active = TRUE", (guild_id,))
                        active_count = cursor.fetchone()['count']
                        
                    if active_count >= 3:
                        print(f"🔒 Sync blocked for {member.name} in guild {guild_id}: Free tier limit (3) reached.")
                        continue # Skip adding this member to respect the cap
            except Exception as e:
                print(f"Error checking free tier limits during sync: {e}")
        
        avatar_url = str(member.display_avatar.url) if member.display_avatar else None
        is_new = ensure_employee_profile(
            guild_id=guild_id,
            user_id=member.id,
            username=member.name,
            display_name=member.display_name,
            avatar_url=avatar_url
        )
        if is_new:
            new_count += 1
    
    if new_count > 0:
        print(f"👥 Synced {new_count} new employees from role '{role.name}' in guild {guild_id}")
    
    return new_count

async def handle_add_employee_role(request: web.Request):
    """HTTP endpoint: Add employee role"""
    if not verify_api_request(request):
        print(f"⚠️ Unauthorized employee role add attempt")
        return web.json_response({'success': False, 'error': 'Unauthorized'}, status=401)
    
    try:
        data = await request.json()
        guild_id = int(request.match_info['guild_id'])
        role_id = int(data.get('role_id'))
        
        print(f"📥 API: Adding employee role {role_id} to guild {guild_id}")
        
        # Use existing bot function
        add_employee_role(guild_id, role_id)
        
        # Sync members with this role into employee_profiles
        synced_count = await sync_employees_for_role(guild_id, role_id)
        
        print(f"✅ API: Successfully added employee role {role_id} to guild {guild_id} (synced {synced_count} employees)")
        
        return web.json_response({
            'success': True,
            'message': f'Employee role added successfully. {synced_count} employees synced.',
            'role_id': str(role_id),
            'synced_count': synced_count
        })
    except Exception as e:
        print(f"❌ Error adding employee role via API (guild {request.match_info.get('guild_id')}): {e}")
        return web.json_response({'success': False, 'error': str(e)}, status=500)

async def handle_remove_employee_role(request: web.Request):
    """HTTP endpoint: Remove employee role"""
    if not verify_api_request(request):
        print(f"⚠️ Unauthorized employee role remove attempt")
        return web.json_response({'success': False, 'error': 'Unauthorized'}, status=401)
    
    try:
        data = await request.json()
        guild_id = int(request.match_info['guild_id'])
        role_id = int(data.get('role_id'))
        user_id = data.get('user_id') # Might be passed, might not be
        
        print(f"📥 API: Removing employee role {role_id} from guild {guild_id}")
        
        # Use existing bot function
        remove_employee_role(guild_id, role_id)
        
        print(f"✅ API: Successfully removed employee role {role_id} from guild {guild_id}")
        
        # Dispatch webhook if user_id is provided
        if user_id:
            import asyncio
            asyncio.create_task(dispatch_webhook_event(
                guild_id=guild_id,
                user_id=int(user_id),
                event_type='employee_removed'
            ))
        
        return web.json_response({
            'success': True,
            'message': 'Employee role removed successfully',
            'role_id': str(role_id)
        })
    except Exception as e:
        print(f"❌ Error removing employee role via API (guild {request.match_info.get('guild_id')}): {e}")
        return web.json_response({'success': False, 'error': str(e)}, status=500)

async def handle_sync_employees(request: web.Request):
    """HTTP endpoint: Sync all employees from configured roles into employee_profiles"""
    if not verify_api_request(request):
        print(f"⚠️ Unauthorized employee sync attempt")
        return web.json_response({'success': False, 'error': 'Unauthorized'}, status=401)
    
    try:
        guild_id = int(request.match_info['guild_id'])
        
        print(f"📥 API: Syncing employees for guild {guild_id}")
        
        # Get all employee roles for this guild
        employee_role_ids = get_employee_roles(guild_id)
        
        total_synced = 0
        for role_id in employee_role_ids:
            synced = await sync_employees_for_role(guild_id, role_id)
            total_synced += synced
        
        print(f"✅ API: Synced {total_synced} employees across {len(employee_role_ids)} roles for guild {guild_id}")
        
        return web.json_response({
            'success': True,
            'message': f'Synced {total_synced} new employees from {len(employee_role_ids)} roles',
            'synced_count': total_synced,
            'roles_checked': len(employee_role_ids)
        })
    except Exception as e:
        print(f"❌ Error syncing employees via API (guild {request.match_info.get('guild_id')}): {e}")
        import traceback
        traceback.print_exc()
        return web.json_response({'success': False, 'error': str(e)}, status=500)

async def handle_prune_ghosts(request: web.Request):
    """HTTP endpoint: Prune ghost employees who left the server or lost roles"""
    if not verify_api_request(request):
        return web.json_response({'success': False, 'error': 'Unauthorized'}, status=401)
        
    try:
        guild_id = int(request.match_info['guild_id'])
        guild = bot.get_guild(guild_id)
        
        if not guild:
            # Maybe the bot hasn't fully loaded the guild cache yet, or the ID is mistyped
            print(f"⚠️ [Prune Ghosts] Guild {guild_id} not found in bot cache. Skipping auto-prune.")
            return web.json_response({'success': False, 'error': 'Guild not found in bot cache'}, status=404)
            
        employee_role_ids = get_employee_roles(guild_id)
        # print(f"🔍 [Prune Ghosts] Guild {guild_id} expects roles: {employee_role_ids}")
        archived_count = 0
        
        with db() as conn:
            # Only pull active employees
            cursor = conn.execute("SELECT user_id, display_name FROM employee_profiles WHERE guild_id = %s AND is_active = TRUE", (guild_id,))
            active_employees = cursor.fetchall()
            
            for emp in active_employees:
                user_id = emp['user_id']
                member = guild.get_member(user_id)
                
                # Check 1: Did they leave the Discord server completely?
                if not member:
                    archive_employee(guild_id, user_id, reason="left_server_auto_prune")
                    archived_count += 1
                    continue
                    
                # Check 2: Are they still in the server, but lost their specific Employee role?
                if employee_role_ids: # only check if the guild actually uses employee roles
                    has_role = any(r.id in employee_role_ids for r in member.roles)
                    if not has_role:
                        archive_employee(guild_id, user_id, reason="lost_role_auto_prune")
                        archived_count += 1
                        
        if archived_count > 0:
            print(f"🧹 Auto-pruned {archived_count} ghost employees from guild {guild_id}")
            
        return web.json_response({
            'success': True,
            'archived_count': archived_count
        })
    except Exception as e:
        print(f"❌ Error auto-pruning ghosts (guild {request.match_info.get('guild_id')}): {e}")
        import traceback
        traceback.print_exc()
        return web.json_response({'success': False, 'error': str(e)}, status=500)

async def handle_send_onboarding(request: web.Request):
    """HTTP endpoint: Send onboarding DMs to all employees with profile links"""
    if not verify_api_request(request):
        print(f"⚠️ Unauthorized onboarding attempt")
        return web.json_response({'success': False, 'error': 'Unauthorized'}, status=401)
    
    try:
        guild_id = int(request.match_info['guild_id'])
        
        print(f"📨 API: Sending onboarding DMs for guild {guild_id}")
        
        guild = bot.get_guild(guild_id)
        if not guild:
            return web.json_response({'success': False, 'error': 'Guild not found'}, status=404)
        
        # Get all employee profiles for this guild
        with db() as conn:
            cursor = conn.execute("""
                SELECT user_id, display_name, full_name FROM employee_profiles
                WHERE guild_id = %s AND is_active = TRUE
            """, (guild_id,))
            employees = cursor.fetchall()
        
        if not employees:
            return web.json_response({'success': False, 'error': 'No employees found'}, status=404)
        
        sent_count = 0
        failed_count = 0
        domain = get_domain()
        
        for emp in employees:
            try:
                user_id = emp['user_id']
                display_name = emp['display_name'] or emp['full_name'] or 'Team Member'
                
                member = guild.get_member(user_id)
                if not member:
                    continue
                
                profile_url = f"https://{domain}/dashboard/server/{guild_id}/profile/{user_id}"
                
                embed = discord.Embed(
                    title="📋 Welcome! Set Up Your Profile",
                    description=f"Hi {display_name}! Your admin has invited you to set up your profile for **{guild.name}**.",
                    color=discord.Color.blue()
                )
                
                embed.add_field(
                    name="🔗 Your Profile Page",
                    value=f"**[Click here to set up your profile]({profile_url})**\n\nOn your profile page you can:\n• Set your email for notifications\n• View your hours and stats\n• Track your work history",
                    inline=False
                )
                
                embed.add_field(
                    name="⏰ Using the Timeclock",
                    value="Use `/clock` in Discord to clock in/out and view your hours.",
                    inline=False
                )
                
                embed.set_footer(text="On the Clock • Professional Time Tracking")
                
                await member.send(embed=embed)
                sent_count += 1
                print(f"  ✓ Sent onboarding to {member.display_name}")
                
            except discord.Forbidden:
                failed_count += 1
                print(f"  ✗ Cannot DM user {emp['user_id']} (DMs disabled)")
            except Exception as e:
                failed_count += 1
                print(f"  ✗ Failed to send to {emp['user_id']}: {e}")
        
        message = f"Sent onboarding to {sent_count} employees"
        if failed_count > 0:
            message += f" ({failed_count} failed - DMs may be disabled)"
        
        print(f"✅ API: {message}")
        
        return web.json_response({
            'success': True,
            'message': message,
            'sent_count': sent_count,
            'failed_count': failed_count
        })
    except Exception as e:
        print(f"❌ Error sending onboarding (guild {request.match_info.get('guild_id')}): {e}")
        import traceback
        traceback.print_exc()
        return web.json_response({'success': False, 'error': str(e)}, status=500)

async def handle_get_channels(request: web.Request):
    """HTTP endpoint: Fetch list of text channels for a guild"""
    if not verify_api_request(request):
        return web.json_response({'success': False, 'error': 'Unauthorized'}, status=401)
        
    guild_id_str = request.match_info.get('guild_id')
    if not guild_id_str or not guild_id_str.isdigit():
        return web.json_response({'success': False, 'error': 'Invalid guild ID'}, status=400)
        
    try:
        guild_id = int(guild_id_str)
        guild = bot.get_guild(guild_id)
        
        if not guild:
            return web.json_response({
                'success': True,
                'channels': []
            })
            
        channels = [
            {'id': str(c.id), 'name': c.name}
            for c in guild.text_channels
            if c.permissions_for(guild.me).send_messages
        ]
        
        # Sort alphabetically
        channels.sort(key=lambda x: x['name'].lower())
        
        return web.json_response({
            'success': True,
            'channels': channels
        })
    except Exception as e:
        print(f"❌ Error fetching channels for {guild_id_str}: {e}")
        return web.json_response({'success': False, 'error': str(e)}, status=500)

async def handle_test_message(request: web.Request):
    """HTTP endpoint: Send a test message to a specific channel"""
    if not verify_api_request(request):
        return web.json_response({'success': False, 'error': 'Unauthorized'}, status=401)
        
    guild_id_str = request.match_info.get('guild_id')
    
    try:
        data = await request.json()
        channel_id_str = data.get('channel_id')
        
        if not channel_id_str or not channel_id_str.isdigit():
            return web.json_response({'success': False, 'error': 'Invalid channel ID'}, status=400)
            
        channel_id = int(channel_id_str)
        channel = bot.get_channel(channel_id)
        
        if not channel:
            # Fallback to fetch if not cached
            try:
                channel = await bot.fetch_channel(channel_id)
            except:
                return web.json_response({'success': False, 'error': 'Channel not found or bot lacks access.'}, status=404)
                
        try:
            await channel.send("✅ **Time Warden Integration Test**\n\nThis channel has been successfully linked to your Time Warden dashboard. You will now receive notifications here.")
            return web.json_response({'success': True, 'message': 'Test message sent successfully'})
        except discord.Forbidden:
            return web.json_response({'success': False, 'error': 'The bot lacks permission to send messages in this channel.'}, status=403)
            
    except Exception as e:
        print(f"❌ Error sending test message to {guild_id_str}: {e}")
        return web.json_response({'success': False, 'error': str(e)}, status=500)

async def handle_broadcast(request: web.Request):
    """HTTP endpoint: Send broadcast message to guilds"""
    if not verify_api_request(request):
        print(f"⚠️ Unauthorized broadcast attempt via API")
        return web.json_response({'success': False, 'error': 'Unauthorized'}, status=401)
    
    try:
        data = await request.json()
        guild_ids = data.get('guild_ids', [])
        title = data.get('title', '').strip()
        message = data.get('message', '').strip()
        
        if not guild_ids:
            return web.json_response({'success': False, 'error': 'No guild IDs provided'}, status=400)
        
        if not title or not message:
            return web.json_response({'success': False, 'error': 'Title and message are required'}, status=400)
        
        print(f"📢 API Broadcast request: {len(guild_ids)} guilds, title: {title[:50]}...")
        
        result = await send_broadcast_to_guilds(guild_ids, title, message)
        
        print(f"📢 API Broadcast complete: {result.get('sent_count', 0)} sent, {result.get('failed_count', 0)} failed")
        
        return web.json_response(result)
        
    except Exception as e:
        print(f"❌ Error in broadcast API: {e}")
        import traceback
        traceback.print_exc()
        return web.json_response({'success': False, 'error': str(e)}, status=500)

async def handle_check_user_admin(request: web.Request):
    """HTTP endpoint: Check if user has admin permissions in a guild (real-time check)"""
    if not verify_api_request(request):
        print(f"⚠️ Unauthorized admin check attempt")
        return web.json_response({'success': False, 'error': 'Unauthorized'}, status=401)
    
    try:
        guild_id = int(request.match_info['guild_id'])
        user_id = int(request.match_info['user_id'])
        
        # Get the guild from bot's cache
        guild = bot.get_guild(guild_id)
        if not guild:
            return web.json_response({
                'success': True,
                'is_member': False,
                'is_admin': False,
                'reason': 'guild_not_found'
            })
        
        # Try cache first to avoid Discord API rate limits
        member = guild.get_member(user_id)
        
        # If not in cache, fetch from API
        if not member:
            try:
                member = await guild.fetch_member(user_id)
            except discord.NotFound:
                return web.json_response({
                    'success': True,
                    'is_member': False,
                    'is_admin': False,
                    'reason': 'not_member'
                })
            except discord.HTTPException as e:
                print(f"❌ Discord API error fetching member {user_id} in guild {guild_id}: {e}")
                return web.json_response({
                    'success': False,
                    'error': f'Discord API error: {str(e)}'
                }, status=500)
        
        # Check if user is owner
        if guild.owner_id == user_id:
            return web.json_response({
                'success': True,
                'is_member': True,
                'is_admin': True,
                'is_owner': True,
                'reason': 'owner'
            })
        
        # Check if user has administrator permission
        if member.guild_permissions.administrator:
            return web.json_response({
                'success': True,
                'is_member': True,
                'is_admin': True,
                'is_owner': False,
                'reason': 'has_admin_permission'
            })
        
        # Check if user has any admin roles from database
        admin_roles = get_admin_roles(guild_id)
        user_role_ids = {role.id for role in member.roles}
        has_admin_role = any(role_id in user_role_ids for role_id in admin_roles)
        
        return web.json_response({
            'success': True,
            'is_member': True,
            'is_admin': has_admin_role,
            'is_owner': False,
            'reason': 'has_admin_role' if has_admin_role else 'no_admin_access'
        })
        
    except Exception as e:
        print(f"❌ Error checking user admin status (guild {request.match_info.get('guild_id')}, user {request.match_info.get('user_id')}): {e}")
        import traceback
        traceback.print_exc()
        return web.json_response({'success': False, 'error': str(e)}, status=500)

async def handle_reports_export(request: web.Request):
    """HTTP endpoint: Generate reports (CSV, Payroll, PDF)"""
    if not verify_api_request(request):
        print(f"⚠️ Unauthorized reports export attempt")
        return web.json_response({'success': False, 'error': 'Unauthorized'}, status=401)
        
    try:
        data = await request.json()
        guild_id = int(request.match_info['guild_id'])
        export_type = data.get('export_type', 'standard_csv')
        start_date_str = data.get('start_date')
        end_date_str = data.get('end_date')
        
        print(f"📥 API: Generating {export_type} report for guild {guild_id} from {start_date_str} to {end_date_str}")
        
        # Get guild timezone
        guild_settings = get_guild_settings(guild_id)
        guild_tz = guild_settings.get('timezone') or 'America/Chicago'
        
        # Build UTC boundaries
        start_dt = safe_parse_timestamp(start_date_str)
        end_dt = safe_parse_timestamp(end_date_str)
        
        # Fetch data
        with db() as conn:
            cursor = conn.execute("""
                SELECT user_id, clock_in_time as clock_in, clock_out_time as clock_out,
                       EXTRACT(EPOCH FROM (clock_out_time - clock_in_time)) as duration_seconds
                FROM timeclock_sessions
                WHERE guild_id = %s 
                  AND clock_out_time IS NOT NULL
                  AND clock_in_time >= %s
                  AND clock_in_time <= %s
                ORDER BY user_id, clock_in_time
            """, (guild_id, start_dt, end_dt))
            sessions = cursor.fetchall()
            
        if not sessions:
            return web.json_response({
                'success': False,
                'error': 'No completed timeclock sessions found for the selected date range.'
            }, status=404)
            
        # Generate requested format
        import base64
        filename = f"timesheet_{guild_id}_{start_dt.strftime('%Y%m%d')}.csv"
        
        if export_type == 'standard_csv':
            content = await generate_csv_report(bot, sessions, guild_id, guild_tz)
            mime_type = "text/csv"
        elif export_type == 'payroll_csv':
            # Stub for Phase 3
            content = await generate_csv_report(bot, sessions, guild_id, guild_tz)
            filename = f"payroll_{guild_id}_{start_dt.strftime('%Y%m%d')}.csv"
            mime_type = "text/csv"
        elif export_type == 'pdf':
            # Stub for Phase 3
            content = await generate_csv_report(bot, sessions, guild_id, guild_tz)
            filename = f"report_{guild_id}_{start_dt.strftime('%Y%m%d')}.txt"
            mime_type = "text/plain"
        else:
            return web.json_response({'success': False, 'error': f'Unsupported export type: {export_type}'}, status=400)
            
        # Base64 encode the final file payload to safely transfer over HTTP JSON
        b64_content = base64.b64encode(content.encode('utf-8')).decode('utf-8')
        
        print(f"✅ API: Generated {export_type} report for guild {guild_id}")
        
        return web.json_response({
            'success': True,
            'filename': filename,
            'mime_type': mime_type,
            'content': b64_content,
            'record_count': len(sessions)
        })
        
    except Exception as e:
        print(f"❌ Error exporting reports via API (guild {request.match_info.get('guild_id')}): {e}")
        import traceback
        traceback.print_exc()
        return web.json_response({'success': False, 'error': str(e)}, status=500)

async def handle_health(request: web.Request):
    """Health check endpoint for the bot API"""
    auth_header = request.headers.get('Authorization', '')
    expected_token = f'Bearer {BOT_API_SECRET}'
    
    if auth_header != expected_token:
        return web.json_response({'healthy': False, 'error': 'Unauthorized'}, status=401)
    
    bot_ready = bot.is_ready() if bot else False
    guild_count = len(bot.guilds) if bot and bot_ready else 0
    
    return web.json_response({
        'healthy': bot_ready,
        'message': f'Bot ready with {guild_count} guilds' if bot_ready else 'Bot not ready',
        'guilds': guild_count,
        'latency_ms': round(bot.latency * 1000, 2) if bot_ready else None
    })


async def start_bot_api_server():
    """Start aiohttp server for bot API endpoints"""
    app = web.Application()
    app.router.add_get('/health', handle_health)
    app.router.add_post('/api/guild/{guild_id}/admin-roles/add', handle_add_admin_role)
    app.router.add_post('/api/guild/{guild_id}/admin-roles/remove', handle_remove_admin_role)
    app.router.add_post('/api/guild/{guild_id}/employee-roles/add', handle_add_employee_role)
    app.router.add_post('/api/guild/{guild_id}/employee-roles/remove', handle_remove_employee_role)
    app.router.add_post('/api/guild/{guild_id}/employees/sync', handle_sync_employees)
    app.router.add_post('/api/guild/{guild_id}/employees/prune-ghosts', handle_prune_ghosts)
    app.router.add_post('/api/guild/{guild_id}/employees/send-onboarding', handle_send_onboarding)
    app.router.add_get('/api/guild/{guild_id}/user/{user_id}/check-admin', handle_check_user_admin)
    app.router.add_post('/api/guild/{guild_id}/reports/export', handle_reports_export)
    app.router.add_get('/api/guild/{guild_id}/channels', handle_get_channels)
    app.router.add_post('/api/guild/{guild_id}/test-message', handle_test_message)
    app.router.add_post('/api/broadcast', handle_broadcast)
    
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', BOT_API_PORT)
    await site.start()
    print(f"🔌 Bot API server running on http://0.0.0.0:{BOT_API_PORT}")
    print(f"🔐 API Secret: {BOT_API_SECRET[:16]}... (set BOT_API_SECRET env var)")

async def run_bot_with_api():
    """Run Discord bot and API server concurrently"""
    # Start API server in background
    asyncio.create_task(start_bot_api_server())
    
    # Start Discord bot (will block until disconnected)
    await bot.start(TOKEN)

if __name__ == "__main__":
    # Run database migrations first with exclusive locking
    print("🔧 Running database migrations...")
    run_migrations()
    
    # Initialize database tables
    init_db()
    
    if not TOKEN:
        raise SystemExit("Set DISCORD_TOKEN in your environment.")
    
    # Health check server disabled - Flask app handles web server
    # health_thread = threading.Thread(target=start_health_server, daemon=True)
    # health_thread.start()
    print(f"✅ Health check server disabled (Flask app handles web server)")
    
    # Start daily cleanup scheduler
    schedule_daily_cleanup()
    
    # Start Discord bot with API server
    print(f"🤖 Starting Discord bot with API server...")
    asyncio.run(run_bot_with_api())
