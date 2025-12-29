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
from http.server import HTTPServer, BaseHTTPRequestHandler
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
from email_utils import send_timeclock_report_email
# Import migrations
from migrations import run_migrations
from scheduler import start_scheduler, stop_scheduler

# --- Config / Secrets ---
TOKEN = os.getenv("DISCORD_TOKEN")            # required
DATABASE_URL = os.getenv("DATABASE_URL")      # PostgreSQL connection string
GUILD_ID = os.getenv("GUILD_ID")              # optional but makes commands appear instantly (guild sync)
DEFAULT_TZ = "America/New_York"
HTTP_PORT = int(os.getenv("HEALTH_PORT", "8080"))     # Health check server port (Flask uses 5000)

# PostgreSQL connection pool for better performance
db_pool = None

# --- Bot Owner Configuration ---
BOT_OWNER_ID = int(os.getenv("BOT_OWNER_ID", "107103438139056128"))  # Discord user ID for super admin access

# --- Discord Application Configuration ---
DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID", "1418446753379913809")  # Discord application client ID

# --- Discord Data Caching ---
# Simple in-memory cache for Discord API data to reduce rate limiting
DISCORD_CACHE = {
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
user_interaction_timestamps = {}  # {(guild_id, user_id, button_name): [timestamp1, timestamp2, ...]}

# --- Stripe Configuration ---
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")
STRIPE_PRICE_IDS = {
    'bot_access': os.getenv('STRIPE_PRICE_BOT_ACCESS'),
    'retention_7day': os.getenv('STRIPE_PRICE_RETENTION_7DAY'),
    'retention_30day': os.getenv('STRIPE_PRICE_RETENTION_30DAY')
}

# Session storage - now using database for persistence instead of in-memory dictionaries

# Guild-based locks to prevent race conditions in setup operations
guild_setup_locks: Dict[int, asyncio.Lock] = {}

def get_guild_lock(guild_id: int) -> asyncio.Lock:
    """Get or create an asyncio lock for a specific guild"""
    if guild_id not in guild_setup_locks:
        guild_setup_locks[guild_id] = asyncio.Lock()
    return guild_setup_locks[guild_id]

# --- Owner-Only Access Decorator ---
def owner_only(func):
    """Decorator to restrict commands to bot owner only"""
    async def wrapper(interaction: discord.Interaction, *args, **kwargs):
        if interaction.user.id != BOT_OWNER_ID:
            # Silently ignore - command won't even be visible to non-owners
            return
        return await func(interaction, *args, **kwargs)
    return wrapper

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
        return 'on-the-clock.replit.app'
    else:
        # In development, use the dev domain
        domains = os.getenv('REPLIT_DOMAINS', '')
        return domains.split(',')[0] if domains else 'localhost:5000'


def generate_dashboard_deeplink(guild_id: int, user_id: int, page: str, secret: str = None) -> str:
    """Generate a signed deep-link URL for dashboard navigation"""
    if secret is None:
        secret = os.getenv('SESSION_SECRET', 'fallback-secret')
    
    # Create timestamp and signature
    timestamp = int(time.time())
    data = f"{guild_id}:{user_id}:{page}:{timestamp}"
    signature = hashlib.sha256(f"{data}:{secret}".encode()).hexdigest()[:16]
    
    # Build URL
    base_url = "https://on-the-clock.replit.app"
    return f"{base_url}/deeplink/{page}?guild={guild_id}&user={user_id}&t={timestamp}&sig={signature}"


def create_secure_checkout_session(guild_id: int, product_type: str, guild_name: str = "") -> str:
    """Create a secure Stripe checkout session with proper validation
    
    Args:
        guild_id: Discord guild/server ID
        product_type: One of 'bot_access', 'retention_7day', 'retention_30day'
        guild_name: Optional guild name for confirmation messages
    
    Returns:
        Checkout session URL
    
    Raises:
        ValueError: If Stripe is not configured, product_type is invalid, or checkout fails
    """
    if not stripe.api_key:
        raise ValueError("STRIPE_SECRET_KEY not configured")
    
    if product_type not in STRIPE_PRICE_IDS:
        raise ValueError(f"Invalid product_type: {product_type}. Must be one of: {', '.join(STRIPE_PRICE_IDS.keys())}")
    
    # CRITICAL: Server-side enforcement - prevent retention purchase without bot access
    if product_type in ['retention_7day', 'retention_30day']:
        if not check_bot_access(guild_id):
            raise ValueError("Bot access must be purchased before adding retention plans")
    
    domain = get_domain()
    
    # Determine mode based on product type
    # 'bot_access' is a one-time payment, retention products are subscriptions
    mode = 'payment' if product_type == 'bot_access' else 'subscription'
    
    try:
        # Build metadata
        metadata = {
            'guild_id': str(guild_id),
            'product_type': product_type
        }
        
        # Add guild_name to metadata if provided
        if guild_name:
            metadata['guild_name'] = guild_name
        
        checkout_session = stripe.checkout.Session.create(
            line_items=[{
                'price': STRIPE_PRICE_IDS[product_type],
                'quantity': 1,
            }],
            mode=mode,
            success_url=f'https://{domain}/success?session_id={{CHECKOUT_SESSION_ID}}',
            cancel_url=f'https://{domain}/cancel',
            metadata=metadata,
            automatic_tax={'enabled': True},
            billing_address_collection='required',
        )
        
        return checkout_session.url or ""
        
    except StripeError as e:
        raise ValueError(f"Stripe error: {str(e)}")
    except Exception as e:
        raise ValueError(f"Checkout creation failed: {str(e)}")

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
            
            # Get bot status info inline to avoid method issues
            bot_instance = getattr(type(self), 'bot', None)
            bot_status = "🟢 Online" if bot_instance and bot_instance.is_ready() else "🔴 Offline"
            guild_count = len(bot_instance.guilds) if bot_instance and bot_instance.is_ready() else "Loading..."
            
            
            # Read the functional dashboard file
            try:
                with open('functional_dashboard.html', 'r', encoding='utf-8') as f:
                    dashboard_content = f.read()
                
                # Update the status in the dashboard
                dashboard_content = dashboard_content.replace(
                    'Bot Online • 127 Servers',
                    f'Bot {bot_status} • {guild_count} Servers'
                )
                
                self.wfile.write(dashboard_content.encode('utf-8'))
                return
                
            except FileNotFoundError:
                # Fallback to simple HTML if dashboard file not found
                pass
            
            html_content = f"""
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
            margin-bottom: 8px;
                    }}
                    .status-value {{
            font-size: 1.1em;
            color: #5865F2;
                    }}
                    .features {{
            text-align: left;
            margin: 30px 0;
            background: #36393f;
            border-radius: 15px;
            padding: 25px;
            border: 1px solid #42464d;
                    }}
                    .features h3 {{
            color: #5865F2;
            margin-bottom: 15px;
            text-align: center;
                    }}
                    .features ul {{
            list-style: none;
            color: #dcddde;
                    }}
                    .features li {{
            margin: 8px 0;
            padding-left: 25px;
            position: relative;
                    }}
                    .features li:before {{
            content: "✅";
            position: absolute;
            left: 0;
                    }}
                    .add-bot-btn {{
            display: inline-block;
            background: #5865F2;
            color: white;
            padding: 15px 30px;
            border-radius: 10px;
            text-decoration: none;
            font-weight: bold;
            font-size: 1.1em;
            margin: 20px 0;
            transition: background-color 0.3s;
                    }}
                    .add-bot-btn:hover {{
            background: #4752C4;
                    }}
                    .beta-warning {{
            background: #faa61a;
            color: #2c2f36;
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
            font-weight: bold;
                    }}
                    .beta-warning h3 {{
            margin-bottom: 10px;
                    }}
                    .beta-warning ul {{
            text-align: left;
            margin: 10px 0;
                    }}
                    .pricing-info {{
            background: #36393f;
            border-radius: 15px;
            padding: 25px;
            margin: 20px 0;
            border: 1px solid #42464d;
                    }}
                    .pricing-info h3 {{
            color: #5865F2;
            margin-bottom: 20px;
                    }}
                    .pricing-tier {{
            background: #2c2f36;
            padding: 15px;
            margin: 10px 0;
            border-radius: 8px;
            border-left: 4px solid #5865F2;
                    }}
                    .free-tier {{
            border-left-color: #faa61a;
                    }}
                    .pro-tier {{
            border-left-color: #57F287;
                    }}
                    .footer {{
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #42464d;
            color: #b9bbbe;
            font-size: 0.9em;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
            <div class="bot-title">⏰ On the Clock</div>
            <div class="bot-subtitle">Professional Discord Timeclock Bot for Business Teams</div>
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
                <div class="status-value">Just Now</div>
            </div>
                    </div>
                    
                    <div class="features">
            <h3>🚀 Core Features</h3>
            <ul>
                <li>Easy timeclock functions with Discord buttons</li>
                <li>Automatic timezone support with EST default</li>
                <li>CSV timesheet reports for payroll</li>
                <li>Multi-tier subscription system (Free/Basic/Pro)</li>
                <li>Role-based access control</li>
                <li>Private time entry via DMs</li>
                <li>Automatic data retention policies</li>
                <li>Stripe payment integration</li>
                <li>Real-time "On the Clock" status display</li>
                <li>Admin purge and cleanup commands</li>
            </ul>
                    </div>
                    
                    <div class="features">
            <h3>🎉 Version 1.1 - No More Timeout Issues!</h3>
            <ul>
                <li><strong>New Way:</strong> Type <code>/clock</code> to access your personal timeclock with fresh buttons</li>
                <li><strong>Setup:</strong> Admins use <code>/setup_timeclock</code> to post instructions in channels</li>
                <li><strong>Always Works:</strong> Fresh buttons every time - no more timeout errors!</li>
                <li><strong>Private Interface:</strong> Only you see your timeclock responses (ephemeral)</li>
                <li><strong>Zero Maintenance:</strong> No refresh commands needed - just works!</li>
                <li><strong>Help:</strong> Use <code>/help</code> to see all available commands</li>
            </ul>
                    </div>
                    
                    
                    <div class="beta-warning">
            <h3>⚠️ Beta Service Disclaimer</h3>
            <p>This bot is currently in beta testing. Please be aware:</p>
            <ul>
                <li>💾 Data loss is possible and backups are not guaranteed</li>
                <li>🚫 This service may be discontinued at any time without notice</li>
                <li>📜 No warranty or guarantee of service availability is provided</li>
            </ul>
            <p><strong>Use at your own risk.</strong> This bot is provided "as-is" without any warranties.</p>
                    </div>
                    
                    <div class="pricing-info">
            <h3>💰 Pricing Plans</h3>
            <div class="pricing-tier free-tier">
                <strong>Free Tier</strong><br>
                24-hour data retention • Dashboard features visible but locked • Perfect for testing
            </div>
            <div class="pricing-tier">
                <strong>Dashboard Premium - <s>$10</s> $5 One-Time (Beta Price!)</strong><br>
                Full dashboard access • 7-day data retention • CSV Reports • All features unlocked
            </div>
            <div class="pricing-tier pro-tier">
                <strong>Pro Retention - $5/month</strong><br>
                30-day data retention • Extended reporting • Perfect for monthly payroll
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
            self.wfile.write(json.dumps(response).encode())
        
        
        elif self.path.startswith("/api/"):
            # API endpoints for dashboard data
            self.handle_api_request()
        
        # Remove insecure GET checkout endpoint - checkout now done via Discord commands only
        elif self.path.startswith("/success") or self.path.startswith("/cancel"):
            # Handle payment result pages (with or without query parameters)
            self.handle_payment_result()
        elif self.path.startswith('/api/guild/') and '/employee-status' in self.path:
            # Handle employee status request
            self.handle_api_employee_status()
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        if self.path == "/webhook":
            # Handle Stripe webhooks
            self.handle_stripe_webhook()
        elif self.path.startswith('/api/guild/') and '/settings' in self.path:
            # Handle guild settings updates
            self.handle_api_settings_update()
        elif self.path.startswith('/api/guild/') and '/admin-roles' in self.path:
            # Handle admin role updates
            self.handle_api_admin_roles_update()
        elif self.path.startswith('/api/guild/') and '/employee-roles' in self.path:
            # Handle employee role updates
            self.handle_api_employee_roles_update()
        elif self.path.startswith('/api/guild/') and '/recipients' in self.path:
            # Handle recipients updates
            self.handle_api_recipients_update()
        else:
            self.send_response(404)
            self.end_headers()
    
    def handle_api_employee_status(self):
        """Handle GET /api/guild/{id}/employee-status"""
        try:
            # Extract guild ID from path /api/guild/{id}/employee-status
            parts = self.path.split('/')
            if len(parts) < 4:
                self.send_json_response({"error": "Invalid path"}, 400)
                return
                
            guild_id_str = parts[3]
            guild_id = int(guild_id_str)
            
            bot_instance = getattr(type(self), 'bot', None)
            if not bot_instance:
                self.send_json_response({"error": "Bot not initialized"}, 500)
                return
                
            guild = bot_instance.get_guild(guild_id)
            if not guild:
                self.send_json_response({"error": "Guild not found"}, 404)
                return
                
            statuses = {}
            for member in guild.members:
                statuses[str(member.id)] = str(member.status)
                
            self.send_json_response({"success": True, "statuses": statuses})
            
        except ValueError:
            self.send_json_response({"error": "Invalid guild ID"}, 400)
        except Exception as e:
            print(f"❌ Employee status API error: {e}")
            self.send_json_response({"error": "Server error"}, 500)

    def handle_payment_result(self):
        """Handle success/cancel pages"""
        if self.path.startswith("/success"):
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            html = """
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Payment Successful</title>
            </head>
            <body style="font-family: Arial; text-align: center; padding: 50px;">
                <h1>🎉 Payment Successful!</h1>
                <p>Your Discord server subscription is now active!</p>
                <p>Return to Discord to start using your premium features.</p>
            </body></html>
            """
            self.wfile.write(html.encode('utf-8'))
        else:  # cancel
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            html = """
            <html><body style="font-family: Arial; text-align: center; padding: 50px;">
                <h1>❌ Payment Cancelled</h1>
                <p>No charges were made. You can try again anytime.</p>
                <p>Return to Discord and use the upgrade command again when ready.</p>
            </body></html>
            """
            self.wfile.write(html.encode())
    
    def handle_stripe_webhook(self):
        """Handle Stripe webhook events with proper signature verification"""
        try:
            if not STRIPE_WEBHOOK_SECRET:
                print("❌ STRIPE_WEBHOOK_SECRET not configured")
                self.send_response(400)
                self.end_headers()
                return
                
            content_length = int(self.headers['Content-Length'])
            payload = self.rfile.read(content_length)
            sig_header = self.headers.get('stripe-signature')
            
            if not sig_header:
                print("❌ Missing Stripe signature header")
                self.send_response(400)
                self.end_headers()
                return
                
            try:
                # Verify webhook signature using Stripe
                event = stripe.Webhook.construct_event(
                    payload, sig_header, STRIPE_WEBHOOK_SECRET
                )
                
                event_type = event.get('type')
                event_id = event.get('id', 'unknown')
                print(f"🔔 Processing Stripe webhook: {event_type} (ID: {event_id})")
                
                if event_type == 'checkout.session.completed':
                    session = event['data']['object']
                    self.process_checkout_completed(session, event_id)
                elif event_type == 'customer.subscription.updated':
                    subscription = event['data']['object']
                    self.handle_subscription_change(subscription, event_id)
                elif event_type == 'customer.subscription.deleted':
                    subscription = event['data']['object']
                    self.handle_subscription_cancellation(subscription, event_id)
                elif event_type == 'invoice.payment_failed':
                    invoice = event['data']['object']
                    self.handle_payment_failure(invoice, event_id)
                else:
                    print(f"ℹ️ Unhandled Stripe event type: {event_type}")
                    
            except ValueError as e:
                print(f"❌ Invalid webhook payload: {e}")
                self.send_response(400)
                return
            except SignatureVerificationError as e:
                print(f"❌ Invalid webhook signature: {e}")
                self.send_response(400)
                return
            except Exception as e:
                print(f"❌ Error processing webhook: {e}")
                import traceback
                traceback.print_exc()
                self.send_response(500)
                return
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"received": true}')
            
        except Exception as e:
            print(f"❌ Webhook error: {e}")
            self.send_response(400)
            self.end_headers()
    
    def process_checkout_completed(self, session, event_id='unknown'):
        """Process a completed checkout session"""
        try:
            session_id = session.get('id', 'unknown')
            payment_status = session.get('payment_status', 'unknown')
            status = session.get('status', 'unknown')
            
            print(f"💳 WEBHOOK: Processing checkout session {session_id}")
            print(f"   Payment Status: {payment_status}, Session Status: {status}")
            
            # Retrieve full session with line items to verify pricing
            print(f"   📥 Retrieving full session details from Stripe...")
            full_session = stripe.checkout.Session.retrieve(
                session['id'],
                expand=['line_items']
            )
            
            # Extract price_id from session
            price_id = None
            if full_session.line_items and full_session.line_items.data:
                line_item = full_session.line_items.data[0]
                if line_item.price:
                    price_id = line_item.price.id
                    print(f"   🏷️  Price ID extracted: {price_id}")
            
            if not price_id:
                print(f"❌ WEBHOOK FAILED: No price ID found in checkout session {session_id}")
                self.log_webhook_event('checkout.session.completed', event_id, None, 'failed', {
                    'session_id': session_id,
                    'error': 'No price ID found'
                })
                return
            
            # Match price_id against STRIPE_PRICE_IDS to determine product_type
            product_type = None
            for ptype, pid in STRIPE_PRICE_IDS.items():
                if pid == price_id:
                    product_type = ptype
                    break
            
            if not product_type:
                print(f"❌ WEBHOOK FAILED: Unknown price ID {price_id} in checkout session {session_id}")
                print(f"   Known price IDs: {STRIPE_PRICE_IDS}")
                self.log_webhook_event('checkout.session.completed', event_id, None, 'failed', {
                    'session_id': session_id,
                    'price_id': price_id,
                    'error': 'Unknown price ID'
                })
                return
            
            print(f"   📦 Product type identified: {product_type}")
            
            guild_id = session.get('metadata', {}).get('guild_id')
            guild_name = session.get('metadata', {}).get('guild_name', 'Unknown Server')
            
            if not guild_id:
                print(f"❌ WEBHOOK FAILED: No guild_id in session {session_id} metadata")
                self.log_webhook_event('checkout.session.completed', event_id, None, 'failed', {
                    'session_id': session_id,
                    'error': 'No guild_id in metadata'
                })
                return
            
            guild_id = int(guild_id)
            print(f"   🏰 Server: {guild_name} (ID: {guild_id})")
            
            # Extract customer details for logging
            customer_email = full_session.customer_details.get('email', 'N/A') if full_session.customer_details else 'N/A'
            customer_id = session.get('customer', 'N/A')
            
            print(f"   👤 Customer: {customer_email} (Stripe ID: {customer_id})")
            
            # Process based on product type
            if product_type == 'bot_access':
                # One-time bot access payment
                print(f"   🔧 Granting bot access to server {guild_id}...")
                set_bot_access(guild_id, True)
                print(f"✅ WEBHOOK SUCCESS: Bot access granted to {guild_name} (ID: {guild_id})")
                print(f"   Customer: {customer_email}, Session: {session_id}")
                
                # Log webhook event
                self.log_webhook_event('checkout.session.completed', event_id, guild_id, 'success', {
                    'session_id': session_id,
                    'product_type': product_type,
                    'guild_name': guild_name,
                    'customer_email': customer_email,
                    'customer_id': customer_id
                })
                
                # Notify bot owner
                bot_instance = getattr(type(self), 'bot', None)
                if bot_instance and bot_instance.loop:
                    asyncio.run_coroutine_threadsafe(
                        self.notify_owner("purchase", True, {
                            'guild_id': guild_id,
                            'guild_name': guild_name,
                            'product_type': product_type,
                            'customer_email': customer_email,
                            'customer_id': customer_id,
                            'session_id': session_id
                        }),
                        bot_instance.loop
                    )
                    
                    # Notify server owner about successful activation
                    asyncio.run_coroutine_threadsafe(
                        notify_server_owner_bot_access(guild_id, granted_by="purchase"),
                        bot_instance.loop
                    )
                
            elif product_type == 'retention_7day':
                # DEPRECATED: 7-day retention subscription is retired
                # New pricing model grants 7-day retention automatically with bot_access purchase
                # This handler exists only to gracefully handle any legacy/orphaned checkout sessions
                print(f"⚠️ WEBHOOK: retention_7day product is DEPRECATED - redirecting to 30-day tier")
                print(f"   Session: {session_id}, Customer: {customer_email}")
                
                # Treat as 30-day subscription for any legacy purchases
                if check_bot_access(guild_id):
                    subscription_id = session.get('subscription')
                    customer_id = session.get('customer')
                    set_retention_tier(guild_id, '30day')
                    
                    with db() as conn:
                        conn.execute("""
                            INSERT INTO server_subscriptions (guild_id, subscription_id, customer_id, status)
                            VALUES (%s, %s, %s, 'active')
                            ON CONFLICT(guild_id) DO UPDATE SET 
                                subscription_id = %s,
                                customer_id = %s,
                                status = 'active'
                        """, (guild_id, subscription_id, customer_id, subscription_id, customer_id))
                    
                    print(f"✅ WEBHOOK SUCCESS: Legacy 7-day upgraded to 30-day for {guild_name}")
                    
                    self.log_webhook_event('checkout.session.completed', event_id, guild_id, 'success', {
                        'session_id': session_id,
                        'product_type': 'retention_7day_upgraded_to_30day',
                        'guild_name': guild_name,
                        'customer_email': customer_email
                    })
                else:
                    print(f"❌ WEBHOOK FAILED: Bot access not paid for deprecated 7-day product")
                    self.log_webhook_event('checkout.session.completed', event_id, guild_id, 'failed', {
                        'session_id': session_id,
                        'product_type': product_type,
                        'error': 'Deprecated product + no bot access'
                    })
                
            elif product_type == 'retention_30day':
                # 30-day retention subscription
                print(f"   🔍 Verifying bot access before granting retention...")
                # CRITICAL: Server-side enforcement - verify bot access before granting retention
                if not check_bot_access(guild_id):
                    print(f"❌ WEBHOOK FAILED: Retention purchase blocked - bot access not paid for server {guild_id}")
                    print(f"   Customer {customer_email} must purchase bot access first")
                    
                    # Log webhook event as failed
                    self.log_webhook_event('checkout.session.completed', event_id, guild_id, 'failed', {
                        'session_id': session_id,
                        'product_type': product_type,
                        'guild_name': guild_name,
                        'customer_email': customer_email,
                        'error': 'Bot access not paid - retention purchase blocked'
                    })
                    
                    # Notify owner of blocked purchase
                    bot_instance = getattr(type(self), 'bot', None)
                    if bot_instance and bot_instance.loop:
                        asyncio.run_coroutine_threadsafe(
                            self.notify_owner("purchase", False, {
                                'guild_id': guild_id,
                                'guild_name': guild_name,
                                'product_type': product_type,
                                'customer_email': customer_email,
                                'customer_id': customer_id,
                                'session_id': session_id,
                                'error': 'Retention purchase blocked - bot access required first'
                            }),
                            bot_instance.loop
                        )
                    
                    # TODO: Consider refunding the payment automatically here
                    return
                
                print(f"   ✓ Bot access verified")
                subscription_id = session.get('subscription')
                customer_id = session.get('customer')
                print(f"   🔧 Setting 30-day retention tier...")
                set_retention_tier(guild_id, '30day')
                
                # Store subscription_id and customer_id in database
                with db() as conn:
                    conn.execute("""
                        INSERT INTO server_subscriptions (guild_id, subscription_id, customer_id, status)
                        VALUES (%s, %s, %s, 'active')
                        ON CONFLICT(guild_id) DO UPDATE SET 
                            subscription_id = %s,
                            customer_id = %s,
                            status = 'active'
                    """, (guild_id, subscription_id, customer_id, subscription_id, customer_id))
                
                print(f"✅ WEBHOOK SUCCESS: 30-day retention granted to {guild_name} (ID: {guild_id})")
                print(f"   Customer: {customer_email}, Subscription: {subscription_id}")
                
                # Log webhook event
                self.log_webhook_event('checkout.session.completed', event_id, guild_id, 'success', {
                    'session_id': session_id,
                    'product_type': product_type,
                    'guild_name': guild_name,
                    'customer_email': customer_email,
                    'subscription_id': subscription_id
                })
                
                # Notify owner
                bot_instance = getattr(type(self), 'bot', None)
                if bot_instance and bot_instance.loop:
                    asyncio.run_coroutine_threadsafe(
                        self.notify_owner("purchase", True, {
                            'guild_id': guild_id,
                            'guild_name': guild_name,
                            'product_type': product_type,
                            'customer_email': customer_email,
                            'customer_id': customer_id,
                            'session_id': session_id
                        }),
                        bot_instance.loop
                    )
                
        except Exception as e:
            print(f"❌ WEBHOOK ERROR: Exception processing checkout session: {e}")
            import traceback
            traceback.print_exc()
    
    def handle_subscription_cancellation(self, subscription, event_id='unknown'):
        """Handle subscription cancellation events"""
        try:
            # Find guild by subscription_id or customer_id
            subscription_id = subscription.get('id')
            customer_id = subscription.get('customer')
            
            print(f"🚫 WEBHOOK: Processing subscription cancellation")
            print(f"   Subscription ID: {subscription_id}")
            print(f"   Customer ID: {customer_id}")
            
            if not subscription_id:
                print("❌ WEBHOOK FAILED: No subscription ID in cancellation event")
                return
                
            with db() as conn:
                cursor = conn.execute("""
                    SELECT guild_id FROM server_subscriptions 
                    WHERE subscription_id = %s OR customer_id = %s
                """, (subscription_id, customer_id))
                result = cursor.fetchone()
                
                if result:
                    guild_id = result['guild_id']
                    print(f"   🏰 Found server: ID {guild_id}")
                    
                    # Set retention tier to 'none' (user keeps bot access if they paid for it)
                    print(f"   🔧 Removing retention tier (setting to 'none')...")
                    set_retention_tier(guild_id, 'none')
                    
                    # Update subscription status to canceled in database
                    print(f"   💾 Updating database: marking subscription as canceled...")
                    conn.execute("""
                        UPDATE server_subscriptions 
                        SET status = 'canceled', subscription_id = NULL
                        WHERE guild_id = %s
                    """, (guild_id,))
                    
                    # Trigger immediate data deletion for that guild
                    print(f"   🗑️  Purging timeclock data...")
                    purge_timeclock_data_only(guild_id)
                    
                    print(f"✅ WEBHOOK SUCCESS: Subscription canceled for server {guild_id}")
                    print(f"   Retention removed, data purged, bot access retained")
                    
                    # Log webhook event
                    self.log_webhook_event('customer.subscription.deleted', event_id, guild_id, 'success', {
                        'subscription_id': subscription_id,
                        'customer_id': customer_id
                    })
                    
                    # Notify owner
                    bot_instance = getattr(type(self), 'bot', None)
                    if bot_instance and bot_instance.loop:
                        asyncio.run_coroutine_threadsafe(
                            self.notify_owner("cancellation", True, {
                                'guild_id': guild_id,
                                'subscription_id': subscription_id
                            }),
                            bot_instance.loop
                        )
                else:
                    print(f"❌ WEBHOOK FAILED: No guild found for subscription {subscription_id}")
                    
                    # Notify owner of failure
                    bot_instance = getattr(type(self), 'bot', None)
                    if bot_instance and bot_instance.loop:
                        asyncio.run_coroutine_threadsafe(
                            self.notify_owner("cancellation", False, {
                                'subscription_id': subscription_id,
                                'error': 'No guild found for subscription'
                            }),
                            bot_instance.loop
                        )
                    
        except Exception as e:
            print(f"❌ WEBHOOK ERROR: Exception processing subscription cancellation: {e}")
            import traceback
            traceback.print_exc()
    
    def handle_subscription_change(self, subscription, event_id='unknown'):
        """Handle subscription change events (updates, renewals, etc.)"""
        try:
            subscription_id = subscription.get('id')
            customer_id = subscription.get('customer')
            status = subscription.get('status')
            current_period_end = subscription.get('current_period_end')
            
            if not subscription_id:
                print("❌ No subscription ID in subscription change event")
                return
                
            with db() as conn:
                cursor = conn.execute("""
                    SELECT guild_id FROM server_subscriptions 
                    WHERE subscription_id = %s OR customer_id = %s
                """, (subscription_id, customer_id))
                result = cursor.fetchone()
                
                if result:
                    guild_id = result['guild_id']
                    
                    # Update subscription status in database
                    conn.execute("""
                        UPDATE server_subscriptions 
                        SET status = %s
                        WHERE guild_id = %s
                    """, (status, guild_id))
                    
                    # Handle retention tier based on subscription status
                    if status == 'active':
                        # Keep retention_tier as is
                        print(f"✅ Subscription active: Guild {guild_id} - retention tier maintained")
                        
                    elif status in ['past_due', 'canceled']:
                        # Set retention_tier to 'none'
                        set_retention_tier(guild_id, 'none')
                        print(f"⚠️ Subscription {status}: Guild {guild_id} - retention tier set to 'none'")
                        
                    else:
                        # Other statuses (trialing, incomplete, etc.)
                        print(f"ℹ️ Subscription status changed: Guild {guild_id} status -> {status}")
                    
                    # Update expires_at timestamp if available
                    if current_period_end:
                        expires_at = datetime.fromtimestamp(current_period_end, tz=timezone.utc)
                        conn.execute("""
                            UPDATE server_subscriptions 
                            SET expires_at = %s
                            WHERE guild_id = %s
                        """, (expires_at.isoformat(), guild_id))
                        print(f"📅 Subscription expires_at updated for Guild {guild_id}: {expires_at.isoformat()}")
                        
                else:
                    print(f"❌ No guild found for subscription {subscription_id}")
                    
        except Exception as e:
            print(f"❌ Error processing subscription change: {e}")
            import traceback
            traceback.print_exc()
    
    def handle_payment_failure(self, invoice, event_id='unknown'):
        """Handle payment failure events"""
        try:
            customer_id = invoice.get('customer')
            subscription_id = invoice.get('subscription')
            amount_due = invoice.get('amount_due', 0) / 100  # Convert cents to dollars
            attempt_count = invoice.get('attempt_count', 0)
            
            print(f"⚠️ WEBHOOK: Processing payment failure")
            print(f"   Customer ID: {customer_id}")
            print(f"   Subscription ID: {subscription_id}")
            print(f"   Amount Due: ${amount_due:.2f}")
            print(f"   Attempt Count: {attempt_count}")
            
            if not customer_id and not subscription_id:
                print("❌ WEBHOOK FAILED: No customer or subscription ID in payment failure event")
                return
                
            with db() as conn:
                cursor = conn.execute("""
                    SELECT guild_id FROM server_subscriptions 
                    WHERE subscription_id = %s OR customer_id = %s
                """, (subscription_id, customer_id))
                result = cursor.fetchone()
                
                if result:
                    guild_id = result['guild_id']
                    print(f"   🏰 Found server: ID {guild_id}")
                    
                    # Update subscription status to past_due
                    print(f"   💾 Marking subscription as past_due in database...")
                    conn.execute("""
                        UPDATE server_subscriptions 
                        SET status = 'past_due'
                        WHERE guild_id = %s
                    """, (guild_id,))
                    
                    print(f"✅ WEBHOOK SUCCESS: Payment failure processed for server {guild_id}")
                    print(f"   Status set to 'past_due' - awaiting Stripe retry or cancellation")
                    
                    # Log webhook event
                    self.log_webhook_event('invoice.payment_failed', event_id, guild_id, 'success', {
                        'subscription_id': subscription_id,
                        'amount_due': amount_due,
                        'attempt_count': attempt_count
                    })
                    
                    # Notify owner
                    bot_instance = getattr(type(self), 'bot', None)
                    if bot_instance and bot_instance.loop:
                        asyncio.run_coroutine_threadsafe(
                            self.notify_owner("payment_failure", True, {
                                'guild_id': guild_id,
                                'subscription_id': subscription_id,
                                'amount_due': amount_due,
                                'attempt_count': attempt_count
                            }),
                            bot_instance.loop
                        )
                    
                    # Note: We don't immediately downgrade on payment failure
                    # Stripe usually allows a grace period before cancellation
                    
                else:
                    print(f"❌ WEBHOOK FAILED: No guild found for customer {customer_id} or subscription {subscription_id}")
                    
        except Exception as e:
            print(f"❌ WEBHOOK ERROR: Exception processing payment failure: {e}")
            import traceback
            traceback.print_exc()
    
    def log_webhook_event(self, event_type: str, event_id: str, guild_id: int, status: str, details: dict):
        """
        Log webhook event to database for owner dashboard.
        
        Args:
            event_type: Type of Stripe event (checkout.session.completed, etc.)
            event_id: Stripe event ID
            guild_id: Guild ID (None if not applicable)
            status: 'success' or 'failed'
            details: Dictionary with event details (will be stored as JSON)
        """
        try:
            import json
            details_json = json.dumps(details)
            
            with db() as conn:
                conn.execute("""
                    INSERT INTO webhook_events (event_type, event_id, guild_id, status, details)
                    VALUES (%s, %s, %s, %s, %s)
                """, (event_type, event_id, guild_id, status, details_json))
            
            print(f"📝 Webhook event logged: {event_type} - {status}")
        except Exception as e:
            print(f"⚠️ Failed to log webhook event: {e}")
    
    async def notify_owner(self, event_type: str, success: bool, details: dict):
        """
        Send DM to bot owner about webhook events.
        
        Args:
            event_type: Type of event (purchase, cancellation, payment_failure)
            success: Whether the webhook processing succeeded
            details: Dictionary with event details
        """
        try:
            bot_instance = getattr(type(self), 'bot', None)
            if not bot_instance or not bot_instance.is_ready():
                print(f"⚠️ Owner notification skipped: Bot not ready")
                return
            
            owner = await bot_instance.fetch_user(BOT_OWNER_ID)
            if not owner:
                print(f"⚠️ Owner notification skipped: Owner user not found")
                return
            
            # Build the notification message
            status_emoji = "✅" if success else "❌"
            status_text = "SUCCESS" if success else "FAILED"
            
            if event_type == "purchase":
                embed = discord.Embed(
                    title=f"{status_emoji} Purchase {status_text}",
                    color=discord.Color.green() if success else discord.Color.red(),
                    timestamp=datetime.now(timezone.utc)
                )
                embed.add_field(name="Server", value=f"{details.get('guild_name', 'Unknown')} (ID: {details.get('guild_id', 'N/A')})", inline=False)
                embed.add_field(name="Product", value=details.get('product_type', 'Unknown'), inline=True)
                embed.add_field(name="Customer Email", value=details.get('customer_email', 'N/A'), inline=True)
                embed.add_field(name="Stripe Customer", value=details.get('customer_id', 'N/A'), inline=False)
                embed.add_field(name="Session ID", value=details.get('session_id', 'N/A'), inline=False)
                
                if not success and 'error' in details:
                    embed.add_field(name="Error", value=details['error'], inline=False)
                
            elif event_type == "cancellation":
                embed = discord.Embed(
                    title=f"{status_emoji} Subscription Cancellation {status_text}",
                    color=discord.Color.orange() if success else discord.Color.red(),
                    timestamp=datetime.now(timezone.utc)
                )
                embed.add_field(name="Server ID", value=details.get('guild_id', 'N/A'), inline=True)
                embed.add_field(name="Subscription ID", value=details.get('subscription_id', 'N/A'), inline=False)
                
                if not success and 'error' in details:
                    embed.add_field(name="Error", value=details['error'], inline=False)
                    
            elif event_type == "payment_failure":
                embed = discord.Embed(
                    title=f"⚠️ Payment Failure",
                    color=discord.Color.yellow(),
                    timestamp=datetime.now(timezone.utc)
                )
                embed.add_field(name="Server ID", value=details.get('guild_id', 'N/A'), inline=True)
                embed.add_field(name="Amount Due", value=f"${details.get('amount_due', 0):.2f}", inline=True)
                embed.add_field(name="Attempt Count", value=details.get('attempt_count', 'N/A'), inline=True)
                embed.add_field(name="Subscription ID", value=details.get('subscription_id', 'N/A'), inline=False)
                
            else:
                # Generic notification
                embed = discord.Embed(
                    title=f"{status_emoji} Webhook Event {status_text}",
                    description=f"Event Type: {event_type}",
                    color=discord.Color.blue(),
                    timestamp=datetime.now(timezone.utc)
                )
                for key, value in details.items():
                    embed.add_field(name=key.replace('_', ' ').title(), value=str(value), inline=True)
            
            await owner.send(embed=embed)
            print(f"📧 Owner notification sent: {event_type} - {status_text}")
            
        except discord.Forbidden:
            print(f"⚠️ Owner notification failed: Owner has DMs disabled")
        except Exception as e:
            print(f"⚠️ Owner notification error: {e}")
    
    def purge_all_guild_data(self, guild_id: int):
        """Purge all data for a guild when subscription lapses"""
        try:
            with db() as conn:
                # Set timeout for database operations
                                # Delete all sessions data
                sessions_cursor = conn.execute("DELETE FROM sessions WHERE guild_id = %s", (guild_id,))
                sessions_deleted = sessions_cursor.rowcount
                
                # Delete guild settings
                settings_cursor = conn.execute("DELETE FROM guild_settings WHERE guild_id = %s", (guild_id,))
                settings_deleted = settings_cursor.rowcount
                
                # Delete authorized roles
                auth_roles_cursor = conn.execute("DELETE FROM authorized_roles WHERE guild_id = %s", (guild_id,))
                auth_roles_deleted = auth_roles_cursor.rowcount
                
                # Delete admin roles
                admin_roles_cursor = conn.execute("DELETE FROM admin_roles WHERE guild_id = %s", (guild_id,))
                admin_roles_deleted = admin_roles_cursor.rowcount
                
                # Delete clock roles
                employee_roles_cursor = conn.execute("DELETE FROM employee_roles WHERE guild_id = %s", (guild_id,))
                employee_roles_deleted = employee_roles_cursor.rowcount
                
                # Reset subscription to free tier (don't delete subscription record)
                conn.execute("""
                    UPDATE server_subscriptions 
                    SET tier = 'free', subscription_id = NULL, customer_id = NULL, 
                        expires_at = NULL, status = 'cancelled'
                    WHERE guild_id = %s
                """, (guild_id,))
                
                print(f"🗑️ Data purged for Guild {guild_id}: {sessions_deleted} sessions, {settings_deleted} settings, {auth_roles_deleted} auth roles, {admin_roles_deleted} admin roles, {employee_roles_deleted} clock roles")
                
        except Exception as e:
            print(f"❌ Error purging guild data for {guild_id}: {e}")
            

    def send_json_response(self, data, status=200):
        """Send JSON response"""
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))
        

    def handle_api_settings_update(self):
        """Handle POST /api/guild/{id}/settings - Update general guild settings"""
        try:
            # Check session
            session_id = self.get_session_id()
            if not session_id:
                self.send_json_response({'error': 'Not authenticated'}, 401)
                return
                
            session = get_user_session(session_id)
            if not session:
                self.send_json_response({'error': 'Session expired'}, 401)
                return
            
            # Extract guild ID from path
            path_parts = self.path.split('/')
            guild_id_str = None
            for i, part in enumerate(path_parts):
                if part == 'guild' and i + 1 < len(path_parts):
                    guild_id_str = path_parts[i + 1]
                    break
                    
            if not guild_id_str:
                self.send_json_response({'error': 'Invalid URL'}, 400)
                return
                
            guild_id = int(guild_id_str)
            
            # Check admin access
            user_guild = None
            for ug in session.get('guilds', []):
                if ug['id'] == guild_id_str:
                    user_guild = ug
                    break
                    
            if not user_guild or not self.user_has_dashboard_admin_access(session['user_id'], guild_id, user_guild):
                self.send_json_response({'error': 'Admin access required'}, 403)
                return
                
            # Parse request body
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 10000:  # 10KB limit
                self.send_json_response({'error': 'Request too large'}, 400)
                return
                
            post_data = self.rfile.read(content_length)
            try:
                data = json.loads(post_data.decode('utf-8'))
            except json.JSONDecodeError:
                self.send_json_response({'error': 'Invalid JSON'}, 400)
                return
                
            # Update settings
            updated_settings = {}
            
            if 'timezone' in data:
                timezone = data['timezone'].strip()
                if timezone:
                    set_guild_setting(guild_id, 'timezone', timezone)
                    updated_settings['timezone'] = timezone
                    
            if 'name_display_mode' in data:
                mode = data['name_display_mode']
                if mode in ['username', 'nickname']:
                    set_guild_setting(guild_id, 'name_display_mode', mode)
                    updated_settings['name_display_mode'] = mode
                    
            if 'recipient_user_id' in data:
                recipient_id = data['recipient_user_id']
                if recipient_id is None or (isinstance(recipient_id, str) and recipient_id.isdigit()):
                    set_guild_setting(guild_id, 'recipient_user_id', int(recipient_id) if recipient_id else None)
                    updated_settings['recipient_user_id'] = recipient_id
                    
            if 'main_admin_role_id' in data:
                role_id = data['main_admin_role_id']
                if role_id is None or (isinstance(role_id, str) and role_id.isdigit()):
                    set_guild_setting(guild_id, 'main_admin_role_id', int(role_id) if role_id else None)
                    updated_settings['main_admin_role_id'] = role_id
                    
            self.send_json_response({'success': True, 'updated': updated_settings})
            
        except ValueError:
            self.send_json_response({'error': 'Invalid guild ID'}, 400)
        except Exception as e:
            print(f"❌ Settings update error: {e}")
            self.send_json_response({'error': 'Server error'}, 500)

    def handle_api_admin_roles_update(self):
        """Handle POST /api/guild/{id}/admin-roles - Add/remove admin roles"""
        try:
            # Check session
            session_id = self.get_session_id()
            if not session_id:
                self.send_json_response({'error': 'Not authenticated'}, 401)
                return
                
            session = get_user_session(session_id)
            if not session:
                self.send_json_response({'error': 'Session expired'}, 401)
                return
            
            # Extract guild ID from path
            path_parts = self.path.split('/')
            guild_id_str = None
            for i, part in enumerate(path_parts):
                if part == 'guild' and i + 1 < len(path_parts):
                    guild_id_str = path_parts[i + 1]
                    break
                    
            if not guild_id_str:
                self.send_json_response({'error': 'Invalid URL'}, 400)
                return
                
            guild_id = int(guild_id_str)
            
            # Check admin access
            user_guild = None
            for ug in session.get('guilds', []):
                if ug['id'] == guild_id_str:
                    user_guild = ug
                    break
                    
            if not user_guild or not self.user_has_dashboard_admin_access(session['user_id'], guild_id, user_guild):
                self.send_json_response({'error': 'Admin access required'}, 403)
                return
                
            # Parse request body
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            try:
                data = json.loads(post_data.decode('utf-8'))
            except json.JSONDecodeError:
                self.send_json_response({'error': 'Invalid JSON'}, 400)
                return
                
            action = data.get('action')  # 'add' or 'remove'
            role_id = data.get('role_id')
            
            if not action or not role_id or action not in ['add', 'remove']:
                self.send_json_response({'error': 'Invalid request'}, 400)
                return
                
            try:
                role_id = int(role_id)
            except ValueError:
                self.send_json_response({'error': 'Invalid role ID'}, 400)
                return
                
            if action == 'add':
                add_admin_role(guild_id, role_id)
            else:
                remove_admin_role(guild_id, role_id)
                
            self.send_json_response({'success': True, 'action': action, 'role_id': str(role_id)})
            
        except ValueError:
            self.send_json_response({'error': 'Invalid guild ID'}, 400)
        except Exception as e:
            print(f"❌ Admin roles update error: {e}")
            self.send_json_response({'error': 'Server error'}, 500)

    def handle_api_employee_roles_update(self):
        """Handle POST /api/guild/{id}/employee-roles - Add/remove employee roles"""
        try:
            # Check session
            session_id = self.get_session_id()
            if not session_id:
                self.send_json_response({'error': 'Not authenticated'}, 401)
                return
                
            session = get_user_session(session_id)
            if not session:
                self.send_json_response({'error': 'Session expired'}, 401)
                return
            
            # Extract guild ID from path
            path_parts = self.path.split('/')
            guild_id_str = None
            for i, part in enumerate(path_parts):
                if part == 'guild' and i + 1 < len(path_parts):
                    guild_id_str = path_parts[i + 1]
                    break
                    
            if not guild_id_str:
                self.send_json_response({'error': 'Invalid URL'}, 400)
                return
                
            guild_id = int(guild_id_str)
            
            # Check admin access
            user_guild = None
            for ug in session.get('guilds', []):
                if ug['id'] == guild_id_str:
                    user_guild = ug
                    break
                    
            if not user_guild or not self.user_has_dashboard_admin_access(session['user_id'], guild_id, user_guild):
                self.send_json_response({'error': 'Admin access required'}, 403)
                return
                
            # Parse request body
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            try:
                data = json.loads(post_data.decode('utf-8'))
            except json.JSONDecodeError:
                self.send_json_response({'error': 'Invalid JSON'}, 400)
                return
                
            action = data.get('action')  # 'add' or 'remove'
            role_id = data.get('role_id')
            
            if not action or not role_id or action not in ['add', 'remove']:
                self.send_json_response({'error': 'Invalid request'}, 400)
                return
                
            try:
                role_id = int(role_id)
            except ValueError:
                self.send_json_response({'error': 'Invalid role ID'}, 400)
                return
                
            if action == 'add':
                add_employee_role(guild_id, role_id)
            else:
                remove_employee_role(guild_id, role_id)
                
            self.send_json_response({'success': True, 'action': action, 'role_id': str(role_id)})
            
        except ValueError:
            self.send_json_response({'error': 'Invalid guild ID'}, 400)
        except Exception as e:
            print(f"❌ Employee roles update error: {e}")
            self.send_json_response({'error': 'Server error'}, 500)

    def handle_api_guild_roles(self, session: Dict, guild_id_str: str):
        """Handle GET /api/guild/{id}/roles - Get available Discord roles for the guild"""
        try:
            guild_id = int(guild_id_str)
            
            # Check if user has access to this guild
            user_guild = None
            for ug in session.get('guilds', []):
                if ug['id'] == guild_id_str:
                    user_guild = ug
                    break
                    
            if not user_guild or not self.user_has_dashboard_admin_access(session['user_id'], guild_id, user_guild):
                self.send_json_response({"error": "Admin access required"}, 403)
                return
                
            # Check cache first
            cached_roles = get_cached_discord_data("guild_roles", guild_id)
            if cached_roles:
                self.send_json_response({"roles": cached_roles})
                return

            # Get bot guild data
            bot_instance = getattr(type(self), 'bot', None)
            if not bot_instance or not bot_instance.is_ready():
                self.send_json_response({"error": "Bot not ready"}, 503)
                return
                
            bot_guild = bot_instance.get_guild(guild_id)
            if not bot_guild:
                self.send_json_response({"error": "Guild not found"}, 404)
                return
                
            # Get all roles (excluding @everyone)
            roles = []
            for role in bot_guild.roles:
                if role.name != "@everyone":
                    roles.append({
                        "id": str(role.id),
                        "name": role.name,
                        "color": role.color.value,
                        "position": role.position,
                        "mentionable": role.mentionable,
                        "hoist": role.hoist,
                        "managed": role.managed
                    })
                    
            # Sort by position (higher position = higher in hierarchy)
            roles.sort(key=lambda r: r["position"], reverse=True)
            
            # Cache the results for better performance
            set_cached_discord_data("guild_roles", guild_id, roles)
            
            self.send_json_response({"roles": roles})
            
        except ValueError:
            self.send_json_response({'error': 'Invalid guild ID'}, 400)
        except Exception as e:
            print(f"❌ Guild roles API error: {e}")
            self.send_json_response({'error': 'Server error'}, 500)

    def handle_api_guild_member(self, session: Dict, guild_id_str: str):
        """Handle GET /api/guild/{id}/member - Get user's guild member data including current roles"""
        try:
            guild_id = int(guild_id_str)
            
            # Check if user has access to this guild
            user_guild = None
            for ug in session.get('guilds', []):
                if ug['id'] == guild_id_str:
                    user_guild = ug
                    break
                    
            if not user_guild:
                self.send_json_response({"error": "Guild access required"}, 403)
                return
                
            # Get user's Discord guild member data using OAuth access token
            access_token = session.get('access_token')
            if not access_token:
                self.send_json_response({"error": "Access token not found"}, 401)
                return
                
            member_data = get_discord_guild_member(access_token, guild_id_str)
            if not member_data:
                self.send_json_response({"error": "Unable to fetch guild member data"}, 500)
                return
                
            # Get bot guild data to fetch role details
            bot_instance = getattr(type(self), 'bot', None)
            if not bot_instance or not bot_instance.is_ready():
                self.send_json_response({"error": "Bot not ready"}, 503)
                return
                
            bot_guild = bot_instance.get_guild(guild_id)
            if not bot_guild:
                self.send_json_response({"error": "Guild not found"}, 404)
                return
                
            # Get role details for user's roles
            user_roles = []
            user_role_ids = member_data.get('roles', [])
            
            for role_id in user_role_ids:
                bot_role = bot_guild.get_role(int(role_id))
                if bot_role and bot_role.name != "@everyone":
                    user_roles.append({
                        "id": str(bot_role.id),
                        "name": bot_role.name,
                        "color": bot_role.color.value,
                        "position": bot_role.position,
                        "mentionable": bot_role.mentionable,
                        "hoist": bot_role.hoist,
                        "managed": bot_role.managed,
                        "permissions": str(bot_role.permissions.value)
                    })
            
            # Sort by position (higher position = higher in hierarchy)
            user_roles.sort(key=lambda r: r["position"], reverse=True)
            
            # Check if user has admin or employee access using unified OAuth-based logic
            has_admin_access = self.is_dashboard_admin(session, guild_id)
            
            # For employee access, check clock roles using OAuth member data
            has_employee_access = has_admin_access  # Admins always have employee access
            
            if not has_admin_access:
                # Check if user has specific employee/clock roles using existing member_data
                user_role_ids = [int(role_id) for role_id in member_data.get('roles', [])]
                
                # Check clock roles from database
                employee_roles = get_employee_roles(guild_id)
                
                # If no clock roles configured, fall back to admin-only access
                if not employee_roles:
                    has_employee_access = has_admin_access
                else:
                    has_employee_access = any(role_id in user_role_ids for role_id in employee_roles)
            
            response_data = {
                "user": {
                    "id": member_data.get('user', {}).get('id'),
                    "username": member_data.get('user', {}).get('username'),
                    "avatar": member_data.get('user', {}).get('avatar'),
                    "nick": member_data.get('nick')
                },
                "roles": user_roles,
                "joined_at": member_data.get('joined_at'),
                "premium_since": member_data.get('premium_since'),
                "timeclock_access": {
                    "admin": has_admin_access,
                    "employee": has_employee_access
                }
            }
            
            self.send_json_response(response_data)
            
        except ValueError:
            self.send_json_response({'error': 'Invalid guild ID'}, 400)
        except Exception as e:
            print(f"❌ Guild member API error: {e}")
            self.send_json_response({'error': 'Server error'}, 500)

    def handle_api_guild_members(self, session: Dict, guild_id_str: str):
        """Handle GET /api/guild/{id}/members?query=... - Search guild members for recipients"""
        try:
            guild_id = int(guild_id_str)
            
            # Check if user has access to this guild
            user_guild = None
            for ug in session.get('guilds', []):
                if ug['id'] == guild_id_str:
                    user_guild = ug
                    break
                    
            if not user_guild or not self.user_has_dashboard_admin_access(session['user_id'], guild_id, user_guild):
                self.send_json_response({"error": "Admin access required"}, 403)
                return
                
            # Get bot guild data
            bot_instance = getattr(type(self), 'bot', None)
            if not bot_instance or not bot_instance.is_ready():
                self.send_json_response({"error": "Bot not ready"}, 503)
                return
                
            bot_guild = bot_instance.get_guild(guild_id)
            if not bot_guild:
                self.send_json_response({"error": "Guild not found"}, 404)
                return
            
            # Parse query parameters for search
            from urllib.parse import urlparse, parse_qs
            parsed_url = urlparse(self.path)
            query_params = parse_qs(parsed_url.query)
            
            search_query = query_params.get('query', [''])[0].lower().strip()
            limit = min(int(query_params.get('limit', ['50'])[0]), 100)  # Max 100 members
            
            # Check cache first (only for full member lists without search)
            if not search_query:
                cached_members = get_cached_discord_data("guild_members", guild_id)
                if cached_members:
                    # Apply limit to cached data
                    limited_members = cached_members[:limit]
                    # Return same API contract as non-cached path
                    self.send_json_response({
                        "members": limited_members,
                        "total_shown": len(limited_members),
                        "has_more": len(cached_members) > limit,
                        "query": ""
                    })
                    return
            
            # Get guild members (limited to first 1000 due to Discord API limitations without special intents)
            members = []
            member_count = 0
            
            for member in bot_guild.members:
                if member_count >= limit:
                    break
                    
                # Skip bots unless specifically searching for them
                if member.bot and 'bot' not in search_query:
                    continue
                
                # Filter by search query if provided
                if search_query:
                    search_targets = [
                        member.display_name.lower(),
                        member.name.lower(),
                        str(member.id)
                    ]
                    if member.nick:
                        search_targets.append(member.nick.lower())
                        
                    if not any(search_query in target for target in search_targets):
                        continue
                
                # Add member to results
                members.append({
                    "id": str(member.id),
                    "username": member.name,
                    "display_name": member.display_name,
                    "avatar": member.avatar.url if member.avatar else None,
                    "bot": member.bot,
                    "nick": member.nick,
                    "joined_at": member.joined_at.isoformat() if member.joined_at else None
                })
                member_count += 1
                
            # Cache the results for better performance (only for full member lists without search)
            if not search_query:
                set_cached_discord_data("guild_members", guild_id, members)
                
            self.send_json_response({
                "members": members,
                "total_shown": len(members),
                "has_more": member_count >= limit,
                "query": search_query
            })
            
        except ValueError:
            self.send_json_response({'error': 'Invalid guild ID'}, 400)
        except Exception as e:
            print(f"❌ Guild members API error: {e}")
            self.send_json_response({'error': 'Server error'}, 500)

    def handle_api_get_guild_settings(self, session: Dict, guild_id_str: str):
        """Handle GET /api/guild/{id}/settings - Get current guild settings"""
        try:
            guild_id = int(guild_id_str)
            
            # Check if user has access to this guild
            user_guild = None
            for ug in session.get('guilds', []):
                if ug['id'] == guild_id_str:
                    user_guild = ug
                    break
                    
            if not user_guild or not self.user_has_dashboard_admin_access(session['user_id'], guild_id, user_guild):
                self.send_json_response({"error": "Admin access required"}, 403)
                return
                
            # Get current guild settings
            settings = {
                "timezone": get_guild_setting(guild_id, "timezone") or "UTC",
                "name_display_mode": get_guild_setting(guild_id, "name_display_mode") or "username", 
                "recipient_user_id": get_guild_setting(guild_id, "recipient_user_id"),
                "main_admin_role_id": get_guild_setting(guild_id, "main_admin_role_id"),
                "subscription_tier": get_server_tier(guild_id),
                "admin_roles": get_admin_roles(guild_id),
                "employee_roles": get_employee_roles(guild_id)
            }
            
            self.send_json_response({"settings": settings})
            
        except ValueError:
            self.send_json_response({'error': 'Invalid guild ID'}, 400)
        except Exception as e:
            print(f"❌ Guild settings API error: {e}")
            self.send_json_response({'error': 'Server error'}, 500)

    def handle_api_get_admin_roles(self, session, guild_id_str):
        """Handle GET /api/guild/{id}/admin-roles - Get current admin roles"""
        try:
            guild_id = int(guild_id_str)
            
            # Check if user has access to this guild
            user_guild = None
            for ug in session.get('guilds', []):
                if ug['id'] == guild_id_str:
                    user_guild = ug
                    break
                    
            if not user_guild or not self.user_has_dashboard_admin_access(session['user_id'], guild_id, user_guild):
                self.send_json_response({"error": "Admin access required"}, 403)
                return
                
            # Get bot guild data
            bot_instance = getattr(type(self), 'bot', None)
            if not bot_instance or not bot_instance.is_ready():
                self.send_json_response({"error": "Bot not ready"}, 503)
                return
                
            bot_guild = bot_instance.get_guild(guild_id)
            if not bot_guild:
                self.send_json_response({"error": "Guild not found"}, 404)
                return
                
            # Get configured admin roles
            admin_role_ids = get_admin_roles(guild_id)
            admin_roles = []
            
            for role_id in admin_role_ids:
                role = bot_guild.get_role(role_id)
                if role:
                    admin_roles.append({
                        "id": str(role.id),
                        "name": role.name,
                        "color": role.color.value,
                        "position": role.position,
                        "mentionable": role.mentionable,
                        "hoist": role.hoist,
                        "managed": role.managed
                    })
                else:
                    # Role was deleted, keep the ID for cleanup reference
                    admin_roles.append({
                        "id": str(role_id),
                        "name": f"<Deleted Role: {role_id}>",
                        "color": 0,
                        "position": 0,
                        "mentionable": False,
                        "hoist": False,
                        "managed": False,
                        "deleted": True
                    })
                    
            # Sort by position (higher position = higher in hierarchy)
            admin_roles.sort(key=lambda r: r["position"], reverse=True)
            
            self.send_json_response({"admin_roles": admin_roles})
            
        except ValueError:
            self.send_json_response({'error': 'Invalid guild ID'}, 400)
        except Exception as e:
            print(f"❌ Get admin roles API error: {e}")
            self.send_json_response({'error': 'Server error'}, 500)

    def handle_api_get_employee_roles(self, session, guild_id_str):
        """Handle GET /api/guild/{id}/employee-roles - Get current employee roles"""
        try:
            guild_id = int(guild_id_str)
            
            # Check if user has access to this guild
            user_guild = None
            for ug in session.get('guilds', []):
                if ug['id'] == guild_id_str:
                    user_guild = ug
                    break
                    
            if not user_guild or not self.user_has_dashboard_admin_access(session['user_id'], guild_id, user_guild):
                self.send_json_response({"error": "Admin access required"}, 403)
                return
                
            # Get bot guild data
            bot_instance = getattr(type(self), 'bot', None)
            if not bot_instance or not bot_instance.is_ready():
                self.send_json_response({"error": "Bot not ready"}, 503)
                return
                
            bot_guild = bot_instance.get_guild(guild_id)
            if not bot_guild:
                self.send_json_response({"error": "Guild not found"}, 404)
                return
                
            # Get configured employee roles
            employee_role_ids = get_employee_roles(guild_id)
            employee_roles = []
            
            for role_id in employee_role_ids:
                role = bot_guild.get_role(role_id)
                if role:
                    employee_roles.append({
                        "id": str(role.id),
                        "name": role.name,
                        "color": role.color.value,
                        "position": role.position,
                        "mentionable": role.mentionable,
                        "hoist": role.hoist,
                        "managed": role.managed
                    })
                else:
                    # Role was deleted, keep the ID for cleanup reference
                    employee_roles.append({
                        "id": str(role_id),
                        "name": f"<Deleted Role: {role_id}>",
                        "color": 0,
                        "position": 0,
                        "mentionable": False,
                        "hoist": False,
                        "managed": False,
                        "deleted": True
                    })
                    
            # Sort by position (higher position = higher in hierarchy)
            employee_roles.sort(key=lambda r: r["position"], reverse=True)
            
            self.send_json_response({"employee_roles": employee_roles})
            
        except ValueError:
            self.send_json_response({'error': 'Invalid guild ID'}, 400)
        except Exception as e:
            print(f"❌ Get employee roles API error: {e}")
            self.send_json_response({'error': 'Server error'}, 500)

    def handle_api_get_recipients(self, session, guild_id_str):
        """Handle GET /api/guild/{id}/recipients - Get current report recipients"""
        try:
            # Validate guild ID format
            try:
                guild_id = int(guild_id_str)
            except ValueError:
                self.send_json_response({'error': 'Invalid guild ID format'}, 400)
                return
            
            # Check if user has access to this guild
            user_guild = None
            for ug in session.get('guilds', []):
                if ug['id'] == guild_id_str:
                    user_guild = ug
                    break
                    
            if not user_guild:
                self.send_json_response({'error': 'Access denied: Guild not found in user permissions'}, 403)
                return
            
            # CRITICAL: Check admin permissions for this specific guild
            if not self.user_has_dashboard_admin_access(session['user_id'], guild_id, user_guild):
                self.send_json_response({'error': 'Insufficient permissions: Admin access required for recipients management'}, 403)
                return
            
            # Get all recipients
            recipients = get_report_recipients(guild_id)
            
            # Format recipients for frontend
            discord_recipients = []
            email_recipients = []
            
            for recipient_row in recipients:
                recipient_id = recipient_row['id']
                recipient_type = recipient_row['recipient_type']
                discord_user_id = recipient_row['recipient_id']
                email_address = recipient_row['email_address']
                
                if recipient_type == 'discord' and discord_user_id:
                    try:
                        # Try to get user info - fallback to ID if not found
                        bot_instance = getattr(type(self), 'bot', None)
                        if bot_instance:
                            user = bot_instance.get_user(int(discord_user_id))
                            if user:
                                discord_recipients.append({
                                    'id': recipient_id,
                                    'user_id': discord_user_id,
                                    'username': user.name,
                                    'display_name': user.display_name or user.name,
                                    'avatar': user.avatar.url if user.avatar else None
                                })
                                continue
                        
                        # Fallback for unknown users
                        discord_recipients.append({
                            'id': recipient_id,
                            'user_id': discord_user_id,
                            'username': f'Unknown User ({discord_user_id})',
                            'display_name': f'Unknown User ({discord_user_id})',
                            'avatar': None
                        })
                    except Exception:
                        discord_recipients.append({
                            'id': recipient_id,
                            'user_id': discord_user_id,
                            'username': f'Unknown User ({discord_user_id})',
                            'display_name': f'Unknown User ({discord_user_id})',
                            'avatar': None
                        })
                
                elif recipient_type == 'email' and email_address:
                    email_recipients.append({
                        'id': recipient_id,
                        'email': email_address
                    })
            
            self.send_json_response({
                'discord_recipients': discord_recipients,
                'email_recipients': email_recipients
            })
            
        except Exception as e:
            print(f"❌ Error in handle_api_get_recipients: {e}")
            self.send_json_response({"error": "Server error"}, 500)

    def handle_api_recipients_update(self):
        """Handle POST /api/guild/{id}/recipients - Add/remove recipients"""
        try:
            # Check session
            session_id = self.get_session_id()
            if not session_id:
                self.send_json_response({'error': 'Not authenticated'}, 401)
                return
                
            session = get_user_session(session_id)
            if not session:
                self.send_json_response({'error': 'Session expired'}, 401)
                return
            
            # Parse guild ID from path
            path_parts = self.path.split('/')
            if len(path_parts) < 4:
                self.send_json_response({'error': 'Invalid path'}, 400)
                return
                
            guild_id_str = path_parts[3]
            try:
                guild_id = int(guild_id_str)
            except ValueError:
                self.send_json_response({'error': 'Invalid guild ID'}, 400)
                return
            
            # Check if user has access to this guild
            user_guild = None
            for ug in session.get('guilds', []):
                if ug['id'] == guild_id_str:
                    user_guild = ug
                    break
                    
            if not user_guild:
                self.send_json_response({'error': 'Guild not found'}, 404)
                return
            
            # Check admin permissions
            if not self.user_has_dashboard_admin_access(session['user_id'], guild_id, user_guild):
                self.send_json_response({'error': 'Admin access required'}, 403)
                return
            
            # Parse request body
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                self.send_json_response({'error': 'Empty request body'}, 400)
                return
                
            post_data = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(post_data)
            
            action = data.get('action')  # 'add' or 'remove'
            recipient_type = data.get('recipient_type')  # 'discord' or 'email'
            
            if action not in ['add', 'remove']:
                self.send_json_response({'error': 'Invalid action'}, 400)
                return
                
            if recipient_type not in ['discord', 'email']:
                self.send_json_response({'error': 'Invalid recipient type'}, 400)
                return
            
            if action == 'add':
                if recipient_type == 'discord':
                    user_id = data.get('user_id')
                    if not user_id:
                        self.send_json_response({'error': 'user_id required for discord recipients'}, 400)
                        return
                    
                    # Validate Discord user ID format (should be numeric string)
                    try:
                        discord_user_id = int(user_id)
                        if discord_user_id <= 0:
                            self.send_json_response({'error': 'Invalid Discord user ID: must be positive integer'}, 400)
                            return
                    except (ValueError, TypeError):
                        self.send_json_response({'error': 'Invalid Discord user ID format: must be numeric'}, 400)
                        return
                    
                    success = add_report_recipient(guild_id, 'discord', str(discord_user_id), None)
                    if success:
                        self.send_json_response({'message': 'Discord recipient added successfully'})
                    else:
                        self.send_json_response({'error': 'Recipient already exists for this guild'}, 409)
                        
                elif recipient_type == 'email':
                    email = data.get('email')
                    if not email:
                        self.send_json_response({'error': 'email required for email recipients'}, 400)
                        return
                    
                    # Basic email validation (RFC-like check)
                    if not isinstance(email, str) or '@' not in email or len(email) < 5 or len(email) > 254:
                        self.send_json_response({'error': 'Invalid email format'}, 400)
                        return
                    
                    # Additional email format checks
                    email_parts = email.split('@')
                    if len(email_parts) != 2 or not email_parts[0] or not email_parts[1] or '.' not in email_parts[1]:
                        self.send_json_response({'error': 'Invalid email format: must contain valid local and domain parts'}, 400)
                        return
                    
                    success = add_report_recipient(guild_id, 'email', None, email.lower().strip())
                    if success:
                        self.send_json_response({'message': 'Email recipient added successfully'})
                    else:
                        self.send_json_response({'error': 'Email recipient already exists for this guild'}, 409)
            
            elif action == 'remove':
                if recipient_type == 'discord':
                    user_id = data.get('user_id')
                    if not user_id:
                        self.send_json_response({'error': 'user_id required for Discord recipient removal'}, 400)
                        return
                    
                    # Validate Discord user ID format for removal
                    try:
                        discord_user_id = int(user_id)
                        if discord_user_id <= 0:
                            self.send_json_response({'error': 'Invalid Discord user ID for removal'}, 400)
                            return
                    except (ValueError, TypeError):
                        self.send_json_response({'error': 'Invalid Discord user ID format for removal'}, 400)
                        return
                    
                    remove_report_recipient(guild_id, 'discord', str(discord_user_id), None)
                    
                elif recipient_type == 'email':
                    email = data.get('email')
                    if not email:
                        self.send_json_response({'error': 'email required for email recipient removal'}, 400)
                        return
                    
                    # Basic validation for email removal
                    if not isinstance(email, str) or '@' not in email:
                        self.send_json_response({'error': 'Invalid email format for removal'}, 400)
                        return
                    
                    remove_report_recipient(guild_id, 'email', None, email.lower().strip())
                
                self.send_json_response({'message': 'Recipient removed successfully'})
                
        except json.JSONDecodeError:
            self.send_json_response({'error': 'Invalid JSON'}, 400)
        except Exception as e:
            print(f"❌ Error in handle_api_recipients_update: {e}")
            self.send_json_response({"error": "Server error"}, 500)

    def handle_api_request(self):
        """Handle API requests for dashboard data"""
        try:
            # Check session
            session_id = self.get_session_id()
            if not session_id:
                self.send_json_response({"error": "Not authenticated"}, 401)
                return
                
            session = get_user_session(session_id)
            if not session:
                self.send_json_response({"error": "Session expired"}, 401)
                return
            
            # Route API endpoints
            if self.path == "/api/user":
                self.handle_api_user(session)
            elif self.path == "/api/logout":
                self.handle_api_logout(session)
            elif self.path.startswith("/api/guild/"):
                # Parse guild-specific endpoints
                path_parts = self.path.split("/")
                if len(path_parts) >= 4:
                    guild_id = path_parts[3]
                    
                    if len(path_parts) == 4:
                        # /api/guild/{id}
                        self.handle_api_guild(session, guild_id)
                    elif len(path_parts) == 5:
                        endpoint = path_parts[4]
                        if endpoint == "roles":
                            # /api/guild/{id}/roles
                            self.handle_api_guild_roles(session, guild_id)
                        elif endpoint == "member":
                            # /api/guild/{id}/member
                            self.handle_api_guild_member(session, guild_id)
                        elif endpoint == "recipients":
                            # /api/guild/{id}/recipients
                            self.handle_api_get_recipients(session, guild_id)
                        elif endpoint == "members":
                            # /api/guild/{id}/members
                            self.handle_api_guild_members(session, guild_id)
                        elif endpoint == "settings":
                            # /api/guild/{id}/settings
                            self.handle_api_get_guild_settings(session, guild_id)
                        else:
                            self.send_json_response({"error": "Endpoint not found"}, 404)
                    else:
                        self.send_json_response({"error": "Invalid API path"}, 400)
                else:
                    self.send_json_response({"error": "Invalid API path"}, 400)
            else:
                self.send_json_response({"error": "Endpoint not found"}, 404)
                
        except Exception as e:
            print(f"❌ API request error: {e}")
            self.send_json_response({"error": "Internal server error"}, 500)

    def handle_api_user(self, session: Dict):
        """Handle /api/user endpoint"""
        user_data = {
            "id": session['user_id'],
            "username": session['username'],
            "discriminator": session['discriminator'],
            "avatar": session['avatar'],
            "guilds": []
        }
        
        # Filter guilds to only include ones where the bot is present AND user has admin access
        bot_instance = getattr(type(self), 'bot', None)
        if bot_instance and bot_instance.is_ready():
            bot_guilds = {guild.id: guild for guild in bot_instance.guilds}
            
            for user_guild in session.get('guilds', []):
                guild_id = int(user_guild['id'])
                if guild_id in bot_guilds:
                    # Only include guilds where user has admin access
                    if self.user_has_dashboard_admin_access(session['user_id'], guild_id, user_guild):
                        bot_guild = bot_guilds[guild_id]
                        user_data['guilds'].append({
                            "id": str(guild_id),
                            "name": user_guild['name'],
                            "icon": user_guild.get('icon'),
                            "owner": user_guild.get('owner', False),
                            "permissions": user_guild.get('permissions', '0'),
                            "member_count": bot_guild.member_count,
                            "tier": get_server_tier(guild_id)
                        })
        
        self.send_json_response(user_data)

    def handle_api_logout(self, session: Dict):
        """Handle /api/logout endpoint - Clear session and logout user"""
        try:
            session_id = self.get_session_id()
            
            # Delete the user session from database
            if session_id:
                delete_success = delete_user_session(session_id)
                print(f"🔄 Logout: Session deletion {'successful' if delete_success else 'failed'} for user {session.get('username', 'unknown')}")
            
            # Clear the session cookie
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            
            # Clear session cookies (both current and legacy)
            self.send_header('Set-Cookie', 'otc_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0')
            self.send_header('Set-Cookie', 'session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0')
            
            # Add cache control headers to prevent caching
            self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
            self.send_header('Pragma', 'no-cache')
            self.send_header('Expires', '0')
            
            # Add Clear-Site-Data header for thorough cleanup
            self.send_header('Clear-Site-Data', '"cache", "cookies", "storage"')
            
            self.end_headers()
            
            response_data = {
                "success": True,
                "message": "Logged out successfully",
                "redirect": "/"
            }
            
            self.wfile.write(json.dumps(response_data).encode('utf-8'))
            
        except Exception as e:
            print(f"❌ Logout error: {e}")
            self.send_json_response({"error": "Logout failed"}, 500)

    def handle_api_guild(self, session: Dict, guild_id_str: str):
        """Handle /api/guild/{id} endpoint"""
        try:
            guild_id = int(guild_id_str)
            
            # Check if user has access to this guild
            user_guilds = session.get('guilds', [])
            user_guild = None
            for ug in user_guilds:
                if ug['id'] == guild_id_str:
                    user_guild = ug
                    break
                    
            if not user_guild:
                self.send_json_response({"error": "Access denied"}, 403)
                return
                
            # Check if user has admin permissions in this guild
            if not self.user_has_dashboard_admin_access(session['user_id'], guild_id, user_guild):
                self.send_json_response({"error": "Admin access required"}, 403)
                return
                
            # Get bot guild data
            bot_instance = getattr(type(self), 'bot', None)
            if not bot_instance or not bot_instance.is_ready():
                self.send_json_response({"error": "Bot not ready"}, 503)
                return
                
            bot_guild = bot_instance.get_guild(guild_id)
            if not bot_guild:
                self.send_json_response({"error": "Guild not found"}, 404)
                return
                
            # Get server data
            tier = get_server_tier(guild_id)
            retention_days = get_retention_days(guild_id)
            
            # Count currently clocked in users
            with db() as conn:
                cursor = conn.execute("""
                    SELECT COUNT(*) as count FROM sessions 
                    WHERE guild_id = %s AND clock_out IS NULL
                """, (guild_id,))
                clocked_in_count = cursor.fetchone()['count']
                
            # Get admin and employee roles
            admin_roles = []
            employee_roles = []
            
            with db() as conn:
                # Get admin roles
                cursor = conn.execute("SELECT role_id FROM admin_roles WHERE guild_id = %s", (guild_id,))
                admin_role_ids = [row['role_id'] for row in cursor.fetchall()]
                
                # Get employee roles  
                cursor = conn.execute("SELECT role_id FROM employee_roles WHERE guild_id = %s", (guild_id,))
                employee_role_ids = [row['role_id'] for row in cursor.fetchall()]
                
            # Get role names from Discord
            for role_id in admin_role_ids:
                role = bot_guild.get_role(role_id)
                if role:
                    admin_roles.append({"id": str(role_id), "name": role.name})
                    
            for role_id in employee_role_ids:
                role = bot_guild.get_role(role_id)
                if role:
                    employee_roles.append({"id": str(role_id), "name": role.name})
            
            guild_data = {
                "id": str(guild_id),
                "name": bot_guild.name,
                "icon": str(bot_guild.icon) if bot_guild.icon else None,
                "member_count": bot_guild.member_count,
                "online_count": sum(1 for member in bot_guild.members if member.status != discord.Status.offline),
                "tier": tier,
                "retention_days": retention_days,
                "clocked_in_count": clocked_in_count,
                "admin_roles": admin_roles,
                "employee_roles": employee_roles
            }
            
            self.send_json_response(guild_data)
            
        except ValueError:
            self.send_json_response({"error": "Invalid guild ID"}, 400)
        except Exception as e:
            print(f"❌ Guild API error: {e}")
            self.send_json_response({"error": "Server error"}, 500)

    
    def log_message(self, format, *args):
        # Suppress default HTTP server logs to avoid cluttering Discord bot logs
        pass


def purge_all_guild_data_DANGEROUS(guild_id: int):
    """⚠️ DANGEROUS: Complete data wipe - deletes ALL settings, roles, and timeclock data.
    
    WARNING: This function destroys:
    - All timeclock sessions
    - Guild settings (timezone, display mode, etc.)
    - All authorized roles
    - All admin roles
    - All employee roles
    - Resets subscription to free tier
    
    ⚠️ SECURITY: This should ONLY be called by server OWNERS (not just admins)
    ⚠️ USE WITH EXTREME CAUTION - This is NOT reversible
    
    For normal data cleanup, use purge_timeclock_data_only() instead.
    """
    try:
        with db() as conn:
            # Set timeout for database operations
                        # Delete all sessions data
            sessions_cursor = conn.execute("DELETE FROM sessions WHERE guild_id = %s", (guild_id,))
            sessions_deleted = sessions_cursor.rowcount
            
            # Delete guild settings
            settings_cursor = conn.execute("DELETE FROM guild_settings WHERE guild_id = %s", (guild_id,))
            settings_deleted = settings_cursor.rowcount
            
            # Delete authorized roles
            auth_roles_cursor = conn.execute("DELETE FROM authorized_roles WHERE guild_id = %s", (guild_id,))
            auth_roles_deleted = auth_roles_cursor.rowcount
            
            # Delete admin roles
            admin_roles_cursor = conn.execute("DELETE FROM admin_roles WHERE guild_id = %s", (guild_id,))
            admin_roles_deleted = admin_roles_cursor.rowcount
            
            # Delete clock roles
            employee_roles_cursor = conn.execute("DELETE FROM employee_roles WHERE guild_id = %s", (guild_id,))
            employee_roles_deleted = employee_roles_cursor.rowcount
            
            # Reset subscription to free tier (don't delete subscription record)
            conn.execute("""
                UPDATE server_subscriptions 
                SET tier = 'free', subscription_id = NULL, customer_id = NULL, 
                    expires_at = NULL, status = 'cancelled'
                WHERE guild_id = %s
            """, (guild_id,))
            
            print(f"⚠️ COMPLETE DATA WIPE for Guild {guild_id}: {sessions_deleted} sessions, {settings_deleted} settings, {auth_roles_deleted} auth roles, {admin_roles_deleted} admin roles, {employee_roles_deleted} clock roles")
            return sessions_deleted + settings_deleted + auth_roles_deleted + admin_roles_deleted + employee_roles_deleted
            
    except Exception as e:
        print(f"❌ Error purging all guild data for {guild_id}: {e}")
        raise
    
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
    
    def handle_subscription_change(self, subscription):
        """Handle subscription status changes"""
        try:
            # Find guild by customer_id or subscription_id
            with db() as conn:
                cursor = conn.execute("""
                    SELECT guild_id FROM server_subscriptions 
                    WHERE subscription_id = %s OR customer_id = %s
                """, (subscription['id'], subscription['customer']))
                result = cursor.fetchone()
                
                if result:
                    guild_id = result['guild_id']
                    status = subscription['status']
                    current_period_end = subscription['current_period_end']
                    
                    # Update subscription status
                    conn.execute("""
                        UPDATE server_subscriptions 
                        SET status = %s, expires_at = %s
                        WHERE guild_id = %s
                    """, (status, datetime.fromtimestamp(current_period_end, timezone.utc).isoformat(), guild_id))
                    
                    print(f"🔄 Subscription updated: Guild {guild_id} -> {status}")
                    
        except Exception as e:
            print(f"❌ Error handling subscription change: {e}")
    
    def handle_payment_failure(self, invoice):
        """Handle failed payments"""
        try:
            customer_id = invoice['customer']
            
            with db() as conn:
                cursor = conn.execute("""
                    SELECT guild_id FROM server_subscriptions 
                    WHERE customer_id = %s
                """, (customer_id,))
                result = cursor.fetchone()
                
                if result:
                    guild_id = result['guild_id']
                    
                    # Mark as past_due but don't downgrade immediately
                    conn.execute("""
                        UPDATE server_subscriptions 
                        SET status = 'past_due'
                        WHERE guild_id = %s
                    """, (guild_id,))
                    
                    print(f"⚠️ Payment failed: Guild {guild_id} marked as past_due")
                    
        except Exception as e:
            print(f"❌ Error handling payment failure: {e}")

    def handle_oauth_login(self):
        """Handle OAuth login initiation"""
        try:
            # Generate state parameter for security
            state = secrets.token_urlsafe(32)
            
            # Store state in database instead of memory
            if not create_oauth_session(state, self.client_address[0], expiry_minutes=15):
                self.send_response(500)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b"<h1>OAuth Error</h1><p>Failed to create session</p>")
                return
            
            # Generate Discord OAuth URL
            oauth_url = get_discord_oauth_url(state)
            
            # Redirect to Discord OAuth
            self.send_response(302)
            self.send_header('Location', oauth_url)
            self.end_headers()
            
            print(f"🔗 OAuth login initiated from {self.client_address[0]} with state: {state[:8]}...")
            
        except Exception as e:
            print(f"❌ OAuth login error: {e}")
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"<h1>OAuth Error</h1><p>Failed to initiate login</p>")


    def send_oauth_error(self, message: str):
        """Send OAuth error page"""
        self.send_response(400)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Authentication Error</title>
            <style>
                body {{ font-family: Arial; text-align: center; padding: 50px; background: #1a1a2e; color: white; }}
                .error {{ background: rgba(255,107,107,0.1); padding: 20px; border-radius: 10px; border: 1px solid #ff6b6b; }}
            </style>
        </head>
        <body>
            <div class="error">
                <h1>🔒 Authentication Error</h1>
                <p>{message}</p>
                <p><a href="/" style="color: #5865F2;">Return to Dashboard</a></p>
            </div>
        </body>
        </html>
        """
        self.wfile.write(html.encode('utf-8'))


def start_health_server():
    """Start the health check HTTP server in a separate thread"""
    # Pass bot reference to handler to fix LSP error
    setattr(HealthCheckHandler, 'bot', bot)
    httpd = HTTPServer(('0.0.0.0', HTTP_PORT), HealthCheckHandler)
    print(f"🔧 Health check server starting on http://0.0.0.0:{HTTP_PORT}")
    httpd.serve_forever()

def init_db_pool():
    """Initialize PostgreSQL connection pool"""
    global db_pool
    if not DATABASE_URL:
        raise ValueError("DATABASE_URL environment variable is not set")
    db_pool = psycopg2.pool.ThreadedConnectionPool(
        minconn=1,
        maxconn=10,
        dsn=DATABASE_URL
    )
    print("✅ PostgreSQL connection pool initialized")
    
    # Run migrations on startup
    print("🔄 Running database migrations...")
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

def run_migrations():
    """PostgreSQL migrations - schema already exists, just verify connection"""
    try:
        with db() as conn:
            conn.execute("SELECT 1")
        print("✅ PostgreSQL connection verified")
        return True
    except Exception as e:
        print(f"❌ PostgreSQL connection failed: {e}")
        return False

def run_migrations_old_sqlite():
    """OLD SQLite migrations - no longer used"""
    import time
    import random
    
    max_retries = 5
    for attempt in range(max_retries):
        try:
            with db() as conn:
                # Begin exclusive transaction
                cursor = conn.cursor()
                cursor.execute("BEGIN")
                
                # Check if customer_id column exists
                cursor.execute("SELECT column_name FROM information_schema.columns WHERE table_name = 'server_subscriptions'")
                columns = {row['column_name'] for row in cursor.fetchall()}
                
                if 'customer_id' not in columns:
                    print("🔧 Adding missing customer_id column to server_subscriptions table...")
                    conn.execute("ALTER TABLE server_subscriptions ADD COLUMN customer_id TEXT")
                    print("✅ Migration completed: customer_id column added")
                else:
                    print("✅ Migration check: customer_id column already exists")
                
                # Check if bot_access_paid column exists
                cursor.execute("SELECT column_name FROM information_schema.columns WHERE table_name = 'server_subscriptions'")
                columns = {row['column_name'] for row in cursor.fetchall()}
                
                if 'bot_access_paid' not in columns:
                    print("🔧 Adding bot_access_paid column to server_subscriptions table...")
                    conn.execute("ALTER TABLE server_subscriptions ADD COLUMN bot_access_paid BOOLEAN DEFAULT FALSE")
                    # Migrate existing data: Set bot_access_paid=TRUE for tier='basic' or tier='pro'
                    conn.execute("""
                        UPDATE server_subscriptions 
                        SET bot_access_paid = TRUE 
                        WHERE tier IN ('basic', 'pro')
                    """)
                    print("✅ Migration completed: bot_access_paid column added and data migrated")
                else:
                    print("✅ Migration check: bot_access_paid column already exists")
                
                # Check if retention_tier column exists
                cursor.execute("SELECT column_name FROM information_schema.columns WHERE table_name = 'server_subscriptions'")
                columns = {row['column_name'] for row in cursor.fetchall()}
                
                if 'retention_tier' not in columns:
                    print("🔧 Adding retention_tier column to server_subscriptions table...")
                    conn.execute("ALTER TABLE server_subscriptions ADD COLUMN retention_tier TEXT DEFAULT 'none'")
                    # Migrate existing data based on tier
                    conn.execute("""
                        UPDATE server_subscriptions 
                        SET retention_tier = '7day' 
                        WHERE tier = 'basic'
                    """)
                    conn.execute("""
                        UPDATE server_subscriptions 
                        SET retention_tier = '30day' 
                        WHERE tier = 'pro'
                    """)
                    print("✅ Migration completed: retention_tier column added and data migrated")
                else:
                    print("✅ Migration check: retention_tier column already exists")
                
                conn.commit()
                return True
                
        except psycopg2.OperationalError as e:
            if "locked" in str(e).lower() and attempt < max_retries - 1:
                wait_time = (2 ** attempt) + random.uniform(0, 1)
                print(f"⏳ Database locked on migration attempt {attempt + 1}, retrying in {wait_time:.1f}s...")
                time.sleep(wait_time)
                continue
            else:
                print(f"❌ Migration failed after {attempt + 1} attempts: {e}")
                raise
        except Exception as e:
            print(f"❌ Migration error: {e}")
            raise
    
    return False

def init_db():
    """PostgreSQL schema already exists - no initialization needed"""
    print("✅ Using existing PostgreSQL schema (tables already created during migration)")
    pass

def get_server_tier(guild_id: int) -> str:
    """Get subscription tier for a server (free/basic/pro)"""
    with db() as conn:
        cursor = conn.execute(
            "SELECT tier, status FROM server_subscriptions WHERE guild_id = %s",
            (guild_id,)
        )
        result = cursor.fetchone()
        if not result:
            return "free"
        
        tier = result['tier']
        status = result['status']
        # If subscription is canceled, treat as free tier
        if status == "canceled":
            return "free"
        
        return tier

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
        owner = guild.get_member(owner_id)
        
        if not owner:
            logger.warning(f"⚠️ [NOTIFY] Owner member not in cache, attempting to fetch...")
            try:
                # Fetch the user object (not a full member, but has basic info)
                owner = await bot.fetch_user(owner_id)
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
                "• Use `/setup` to get started\n"
                "• Add employee roles with `/add_employee_role`\n"
                "• Employees can use `/clock` to track time\n"
                "• Admins can generate reports with `/report`\n"
                "• Configure email settings in the dashboard"
            ),
            inline=False
        )
        
        embed.add_field(
            name="📊 Dashboard Access",
            value="Visit your [server dashboard](https://on-the-clock.replit.app/dashboard) to configure settings",
            inline=False
        )
        
        embed.add_field(
            name="💾 Data Retention",
            value="Currently using **24-hour** deletion. Upgrade to 7-day or 30-day retention for longer data storage.",
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
    current_tier = get_server_tier(guild_id)
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
                        DELETE FROM sessions 
                        WHERE guild_id = %s AND clock_out IS NOT NULL AND clock_out < %s
                    """, (guild_id, cutoff_date.isoformat()))
                    deleted_count = cursor.rowcount
                else:
                    # Clean up all guilds based on their individual retention policies
                    guilds_cursor = conn.execute("SELECT DISTINCT guild_id FROM sessions")
                    guild_ids = [row['guild_id'] for row in guilds_cursor.fetchall()]
                    
                    for guild_id in guild_ids:
                        if guild_id is None:
                            continue  # Skip invalid guild IDs
                        retention_days = get_retention_days(guild_id)
                        cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)
                        
                        cursor = conn.execute("""
                            DELETE FROM sessions 
                            WHERE guild_id = %s AND clock_out IS NOT NULL AND clock_out < %s
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
                    DELETE FROM sessions 
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
        'main_admin_role_id': "SELECT main_admin_role_id FROM guild_settings WHERE guild_id=%s"
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
        tz = timezone.utc

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
            FROM sessions s
            LEFT JOIN employee_profiles u ON s.user_id = u.user_id AND s.guild_id = u.guild_id
            WHERE s.guild_id = %s
            ORDER BY s.user_id
        """, (guild_id,))
        all_employees = cursor.fetchall()
        
        for emp in all_employees:
            user_id = emp['user_id']
            
            # Check if currently clocked in
            cursor = conn.execute("""
                SELECT clock_in 
                FROM sessions 
                WHERE guild_id = %s AND user_id = %s AND clock_out IS NULL
                LIMIT 1
            """, (guild_id, user_id))
            active_session = cursor.fetchone()
            
            # Get most recent completed session for clock out time
            cursor = conn.execute("""
                SELECT clock_out
                FROM sessions
                WHERE guild_id = %s AND user_id = %s AND clock_out IS NOT NULL
                ORDER BY clock_out DESC
                LIMIT 1
            """, (guild_id, user_id))
            last_completed = cursor.fetchone()
            
            is_clocked_in = active_session is not None
            clock_in = active_session['clock_in'] if active_session else None
            clock_out = last_completed['clock_out'] if last_completed else None
            
            # Calculate historical hours
            
            # Hours Today
            cursor = conn.execute("""
                SELECT SUM(duration_seconds) as total
                FROM sessions
                WHERE guild_id = %s AND user_id = %s 
                AND clock_out IS NOT NULL
                AND clock_in >= %s
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
                SELECT SUM(duration_seconds) as total
                FROM sessions
                WHERE guild_id = %s AND user_id = %s 
                AND clock_out IS NOT NULL
                AND clock_in >= %s
            """, (guild_id, user_id, week_start_utc.isoformat()))
            result = cursor.fetchone()
            hours_week = result['total'] if result and result['total'] else 0
            hours_week += current_duration

            # Hours Month
            cursor = conn.execute("""
                SELECT SUM(duration_seconds) as total
                FROM sessions
                WHERE guild_id = %s AND user_id = %s 
                AND clock_out IS NOT NULL
                AND clock_in >= %s
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

def create_adjustment_request(guild_id: int, user_id: int, request_type: str, 
                              original_session_id: Optional[int], 
                              requested_data: Dict, reason: str) -> Optional[int]:
    """
    Create a new adjustment request.
    requested_data should contain: requested_clock_in, requested_clock_out (ISO strings or datetimes)
    Returns: request_id or None if failed
    """
    try:
        with db() as conn:
            # If modifying existing session, get original data for audit trail
            original_clock_in = None
            original_clock_out = None
            original_duration = None
            
            if original_session_id:
                cursor = conn.execute("""
                    SELECT clock_in, clock_out, duration_seconds 
                    FROM sessions WHERE id = %s AND guild_id = %s
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
            # Get request details
            cursor = conn.execute("""
                SELECT * FROM time_adjustment_requests 
                WHERE id = %s AND guild_id = %s AND status = 'pending'
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
                    INSERT INTO sessions (guild_id, user_id, clock_in, clock_out, duration_seconds)
                    VALUES (%s, %s, %s, %s, %s)
                """, (guild_id, user_id, request['requested_clock_in'], request['requested_clock_out'], duration))
                
            elif req_type in ['modify_clockin', 'modify_clockout']:
                session_id = request['original_session_id']
                if not session_id:
                    return False, "Original session ID missing"
                
                # Update session
                updates = []
                params = []
                
                if request['requested_clock_in']:
                    updates.append("clock_in = %s")
                    params.append(request['requested_clock_in'])
                    
                if request['requested_clock_out']:
                    updates.append("clock_out = %s")
                    params.append(request['requested_clock_out'])
                
                # Recalculate duration if both exist (or one exists and we fetch the other)
                # For simplicity, let's fetch current state and merge
                cursor = conn.execute("SELECT clock_in, clock_out FROM sessions WHERE id = %s", (session_id,))
                current = cursor.fetchone()
                
                if not current:
                    return False, "Original session not found"
                
                new_in = safe_parse_timestamp(request['requested_clock_in']) if request['requested_clock_in'] else safe_parse_timestamp(current['clock_in'])
                new_out = safe_parse_timestamp(request['requested_clock_out']) if request['requested_clock_out'] else safe_parse_timestamp(current['clock_out'])
                
                if new_in and new_out:
                    duration = int((new_out - new_in).total_seconds())
                    updates.append("duration_seconds = %s")
                    params.append(duration)
                
                params.append(session_id)
                
                query = "UPDATE sessions SET " + ', '.join(updates) + " WHERE id = %s"
                conn.execute(query, tuple(params))
                
            elif req_type == 'delete_session':
                session_id = request['original_session_id']
                conn.execute("DELETE FROM sessions WHERE id = %s", (session_id,))
            
            # Mark request as approved
            conn.execute("""
                UPDATE time_adjustment_requests 
                SET status = 'approved', reviewed_by = %s, reviewed_at = NOW()
                WHERE id = %s
            """, (reviewer_user_id, request_id))
            
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
                RETURNING id
            """, (reviewer_user_id, request_id, guild_id))
            
            if cursor.fetchone():
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
                   r.created_at, r.reviewed_at, r.reviewed_by
            FROM time_adjustment_requests r
            WHERE r.guild_id = %s AND r.user_id = %s
            ORDER BY r.created_at DESC
            LIMIT %s
        """, (guild_id, user_id, limit))
        return cursor.fetchall()

# --- Report Recipients Management ---

def add_report_recipient(guild_id: int, recipient_type: str, recipient_id: Optional[str] = None, email_address: Optional[str] = None):
    """Add a report recipient for a guild"""
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
            return True
    except psycopg2.IntegrityError:
        # Recipient already exists
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
    
    # Send emails to email recipients if auto-send is enabled
    if auto_send_enabled:
        email_recipients = get_report_recipients(guild_id, recipient_type='email')
        if email_recipients:
            try:
                user_name = get_user_display_name(interaction.user, guild_id)  # type: ignore[arg-type]
                
                # Create CSV for single clock-out entry
                duration_hours = round(elapsed / 3600, 2)
                csv_content = f"User ID,Clock In,Clock Out,Duration (hours)\n{interaction.user.id},{start_dt.isoformat()},{end_dt.isoformat()},{duration_hours}"
                
                email_addresses = [row['email_address'] for row in email_recipients if row['email_address']]
                
                if email_addresses:
                    report_period = f"Clock-out at {fmt(end_dt, tz_name)} - {user_name}"
                    await send_timeclock_report_email(
                        to=email_addresses,
                        guild_name=guild_name,
                        csv_content=csv_content,
                        report_period=report_period
                    )
                    notification_sent = True
                    print(f"✅ Clock-out email sent to {len(email_addresses)} recipient(s)")
            except Exception as e:
                errors.append(f"Failed to send clock-out email: {str(e)}")
                print(f"❌ Clock-out email failed: {str(e)}")
    
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
        'main_admin_role_id': "UPDATE guild_settings SET main_admin_role_id=%s WHERE guild_id=%s"
    }
    
    if key not in update_queries:
        raise ValueError(f"Invalid column name: {key}")
    
    with db() as conn:
        conn.execute("INSERT INTO guild_settings(guild_id) VALUES (%s) ON CONFLICT (guild_id) DO NOTHING", (guild_id,))
        conn.execute(update_queries[key], (value, guild_id))

def get_user_display_name(user: discord.Member, guild_id: int) -> str:
    """Get user display name based on guild preference: 'username' or 'nickname'"""
    display_mode = get_guild_setting(guild_id, "name_display_mode", "username")
    
    if display_mode == "nickname" and hasattr(user, 'display_name'):
        return user.display_name
    else:
        return user.name

def get_active_session(guild_id: int, user_id: int):
    with db() as conn:
        cur = conn.execute("""
            SELECT id, clock_in FROM sessions
            WHERE guild_id=%s AND user_id=%s AND clock_out IS NULL
            ORDER BY id DESC LIMIT 1
        """, (guild_id, user_id))
        return cur.fetchone()

def start_session(guild_id: int, user_id: int, clock_in_iso: str):
    with db() as conn:
        conn.execute("""
            INSERT INTO sessions (guild_id, user_id, clock_in)
            VALUES (%s, %s, %s)
        """, (guild_id, user_id, clock_in_iso))

def close_session(session_id: int, clock_out_iso: str, duration_s: int):
    with db() as conn:
        conn.execute("""
            UPDATE sessions SET clock_out=%s, duration_seconds=%s WHERE id=%s
        """, (clock_out_iso, duration_s, session_id))

def get_sessions_report(guild_id: int, user_id: Optional[int], start_utc: str, end_utc: str):
    """Get sessions for report generation within date range (UTC boundaries)."""
    with db() as conn:
        if user_id is not None:
            # Report for specific user
            cur = conn.execute("""
                SELECT user_id, clock_in, clock_out, duration_seconds
                FROM sessions
                WHERE guild_id=%s AND user_id=%s 
                AND clock_out IS NOT NULL
                AND clock_in < %s
                AND clock_out >= %s
                ORDER BY clock_in
            """, (guild_id, user_id, end_utc, start_utc))
        else:
            # Report for all users
            cur = conn.execute("""
                SELECT user_id, clock_in, clock_out, duration_seconds
                FROM sessions
                WHERE guild_id=%s 
                AND clock_out IS NOT NULL
                AND clock_in < %s
                AND clock_out >= %s
                ORDER BY user_id, clock_in
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
        guild_tz = timezone.utc
    
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
            SELECT clock_in, clock_out FROM sessions
            WHERE guild_id=%s AND user_id=%s AND clock_out IS NOT NULL
            AND clock_in < %s AND clock_out >= %s
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
            SELECT clock_in, clock_out FROM sessions
            WHERE guild_id=%s AND user_id=%s AND clock_out IS NOT NULL
            AND clock_in < %s AND clock_out >= %s
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
        # Fetch Discord user to get display name based on guild preference
        try:
            discord_user = await bot.fetch_user(user_id)
            user_display_name = get_user_display_name(discord_user, guild_id)
        except:
            user_display_name = f"User-{user_id}"  # Fallback if user not found
        
        # Calculate date range for this user
        all_dates = []
        for clock_in, _, _ in sessions:
            date_formatted = fmt(clock_in, guild_tz).split()[0]
            all_dates.append(date_formatted)
        
        date_range = f"{min(all_dates)} to {max(all_dates)}" if len(set(all_dates)) > 1 else min(all_dates)
        
        # Employee header with username
        writer.writerow([f"Employee: {user_display_name} - Shift Report ({date_range})"])
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
    
    # Fetch Discord user to get display name based on guild preference
    try:
        discord_user = await bot.fetch_user(user_id)
        user_display_name = get_user_display_name(discord_user, guild_id)
    except:
        user_display_name = f"User-{user_id}"  # Fallback if user not found
    
    # Calculate date range for this user
    all_dates = []
    for clock_in, _, _ in sessions:
        date_formatted = fmt(clock_in, guild_tz).split()[0]
        all_dates.append(date_formatted)
    
    date_range = f"{min(all_dates)} to {max(all_dates)}" if len(set(all_dates)) > 1 else min(all_dates)
    
    # Employee header with username
    writer.writerow([f"Employee: {user_display_name} - Shift Report ({date_range})"])
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
            sessions_cursor = conn.execute("DELETE FROM sessions WHERE guild_id = %s", (guild_id,))
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
def ensure_employee_profile(guild_id: int, user_id: int, username: str, display_name: str, avatar_url: str) -> bool:
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
presence_update_cache = {}

def update_employee_presence(guild_id: int, user_id: int, status: str):
    """Update employee's last seen status with debounce."""
    key = f"{guild_id}:{user_id}"
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
    
    print("✅ Persistent view setup complete - ephemeral interface mode")

bot.setup_hook = setup_hook

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
    """Handle member updates - check for role changes to reactivate"""
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
            # Also ensure profile exists
            ensure_employee_profile(
                guild_id, after.id, 
                after.name, after.display_name, 
                str(after.avatar.url) if after.avatar else str(after.default_avatar.url)
            )
            
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
        server_tier = get_server_tier(guild_id)
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
                    SELECT user_id, clock_in 
                    FROM sessions 
                    WHERE guild_id = %s AND clock_out IS NULL
                    ORDER BY clock_in ASC
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
                    guild_tz = timezone.utc
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
                            SELECT clock_in, clock_out 
                            FROM sessions 
                            WHERE guild_id = %s AND user_id = %s 
                            AND clock_in >= %s AND clock_in <= %s
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
            server_tier = get_server_tier(guild_id)
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
            
            if get_active_session(guild_id, user_id):
                await interaction.followup.send("You're already clocked in.", ephemeral=True)
                return
                
            start_session(guild_id, user_id, now_utc().isoformat())
            
            # --- NEW: Profile Setup Logic ---
            try:
                # Ensure profile exists
                avatar_url = str(interaction.user.avatar.url) if interaction.user.avatar else str(interaction.user.default_avatar.url)
                ensure_employee_profile(
                    guild_id, user_id, 
                    interaction.user.name, interaction.user.display_name, 
                    avatar_url
                )
                
                # Check if we should send setup link (first clock-in)
                with db() as conn:
                    cursor = conn.execute(
                        "SELECT profile_sent_on_first_clockin, profile_setup_completed FROM employee_profiles WHERE guild_id = %s AND user_id = %s",
                        (guild_id, user_id)
                    )
                    row = cursor.fetchone()
                    
                    if row and not row['profile_sent_on_first_clockin'] and not row['profile_setup_completed']:
                        # Generate token and link
                        token = generate_profile_setup_token(guild_id, user_id)
                        domain = get_domain()
                        protocol = "https" if "replit.app" in domain else "http"
                        setup_url = f"{protocol}://{domain}/setup-profile/{token}"
                        
                        # Send ephemeral message with link
                        await interaction.followup.send(
                            f"✅ **Clocked In!**\n\n"
                            f"👋 **Welcome to the team!**\n"
                            f"Please take a moment to set up your employee profile:\n"
                            f"👉 [**Complete Your Profile**]({setup_url})\n"
                            f"*(This link expires in 30 days)*", 
                            ephemeral=True
                        )
                        
                        # Mark as sent
                        conn.execute(
                            "UPDATE employee_profiles SET profile_sent_on_first_clockin = TRUE WHERE guild_id = %s AND user_id = %s",
                            (guild_id, user_id)
                        )
                        return # Exit early since we sent the message
            except Exception as e:
                print(f"Error in profile setup logic: {e}")
            # --------------------------------
            
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
            server_tier = get_server_tier(guild_id)
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
            await interaction.followup.send(
                f"🔚 Clocked out.\n**In:** {fmt(start_dt, tz_name)}\n**Out:** {fmt(end_dt, tz_name)}\n**Total:** {human_duration(elapsed)}",
                ephemeral=True
            )

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
        try:
            if interaction.guild is None:
                await send_reply(interaction, "Use this in a server.", ephemeral=True)
                return
            
            guild_id = interaction.guild.id
            user_id = interaction.user.id
            
            # RATE LIMITING: Check for spam/abuse
            is_allowed, request_count, action = check_rate_limit(guild_id, user_id, "help")
            if not is_allowed:
                # Use send_reply for show_help, but still need to handle server abuse
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
            
            # Check clock access permissions
            server_tier = get_server_tier(interaction.guild.id)
            # Type guard: ensure we have a Member for guild-specific functions
            if not isinstance(interaction.user, discord.Member):
                await send_reply(interaction,
                    "❌ Unable to verify access permissions. Please try again.",
                    ephemeral=True
                )
                return
            
            if not user_has_clock_access(interaction.user, server_tier):
                await send_reply(interaction,
                    "🔒 **Access Restricted**\n"
                    "You need an employee role to use the timeclock.\n"
                    "Ask an administrator to add your role with `/add_employee_role @yourrole`",
                    ephemeral=True
                )
                return
            
            # Get current server tier for comprehensive help display
            server_tier = get_server_tier(interaction.guild.id)
            tier_color = {"free": discord.Color.green(), "basic": discord.Color.blue(), "pro": discord.Color.purple()}
            
            embed = discord.Embed(
                title="📋 Complete Command Reference",
                description=f"**Current Plan:** {server_tier.title()}\n\n**All 21 available slash commands organized by function:**",
                color=tier_color.get(server_tier, discord.Color.green())
            )
        
            # Setup & Configuration Commands
            embed.add_field(
                name="⚙️ Setup & Configuration",
                value=(
                    "`/setup_timeclock [channel]` - Post a persistent Clock In/Clock Out message\n"
                    "`/set_recipient <user>` - Set who receives private time entries (DMs)\n"
                    "`/set_timezone <timezone>` - Set display timezone (e.g., America/New_York)\n"
                    "`/toggle_name_display` - Toggle between username and nickname display\n"
                    "`/help` - List all available slash commands"
                ),
                inline=False
            )
            
            # Admin Role Management Commands
            embed.add_field(
                name="👤 Admin Role Management",
                value=(
                    "`/add_admin_role <role>` - Add a role that can access Reports and Upgrade buttons\n"
                    "`/remove_admin_role <role>` - Remove a role's admin access to Reports and Upgrade buttons\n"
                    "`/list_admin_roles` - List all roles with admin access\n"
                    "`/set_main_role <role>` - Set the primary admin role (gets all admin functions)\n"
                    "`/show_main_role` - View the current main admin role\n"
                    "`/clear_main_role` - Remove the main admin role designation"
                ),
                inline=False
            )
            
            # Employee Role Management Commands
            embed.add_field(
                name="👥 Employee Role Management",
                value=(
                    "`/add_employee_role <role>` - Add a role that can use timeclock functions\n"
                    "`/remove_employee_role <role>` - Remove a role's access to timeclock functions\n"
                    "`/list_employee_roles` - List all roles that can use timeclock functions"
                ),
                inline=False
            )
            
            # Reports & Data Management Commands
            embed.add_field(
                name="📊 Reports & Data Management",
                value=(
                    "`/report <user> <start_date> <end_date>` - Generate CSV timesheet report for individual user\n"
                    "`/data_cleanup` - Manually trigger data cleanup (Admin only)\n"
                    "`/purge` - Permanently delete timeclock data (preserves subscription)"
                ),
                inline=False
            )
            
            # Subscription Management Commands
            embed.add_field(
                name="💳 Subscription Management",
                value=(
                    "`/upgrade` - Upgrade your server to Dashboard Premium or Pro Retention\n"
                    "`/cancel_subscription` - Learn how to cancel your subscription\n"
                    "`/subscription_status` - View current subscription status"
                ),
                inline=False
            )
            
            # Tier Information & Features
            tier_info = "\n\n**Plan Features:**\n"
            if server_tier == "free":
                tier_info += (
                    "🆓 **Free Tier:** Admin-only testing • Sample reports • Employee roles configured but inactive\n"
                    "💡 **Upgrade Benefits:** Dashboard Premium ($5 one-time) unlocks full team access & real CSV reports"
                )
            elif server_tier == "basic":
                tier_info += (
                    "💙 **Dashboard Premium:** Full team access • Real CSV reports • 7-day data retention\n"
                    "💡 **Pro Retention Benefits:** 30-day retention • Multiple manager notifications • Extended features"
                )
            else:  # pro tier
                tier_info += "💜 **Pro Retention:** All features unlocked • 30-day retention • Multiple managers • Priority support"
            
            embed.add_field(
                name="🔘 Interactive Timeclock Buttons",
                value=(
                    "🟢 **Clock In** - Start tracking your time\n"
                    "🔴 **Clock Out** - Stop tracking and log your shift\n"
                    "📊 **Reports** - Generate timesheet reports (admin access)\n"
                    "⬆️ **Upgrade** - Upgrade to Dashboard Premium/Pro Retention\n" + 
                    tier_info
                ),
                inline=False
            )
        
            embed.set_footer(text=f"💡 {server_tier.title()} Plan Active | 20 total commands available | Contact admin for upgrades")
            
            await send_reply(interaction, embed=embed, ephemeral=True)
            
        except (discord.NotFound, discord.errors.NotFound):
            # Interaction expired or was deleted - silently handle this
            print(f"⚠️ Help interaction expired/not found for user {interaction.user.id}")
        except Exception as e:
            # General error handling
            print(f"❌ Error in show_help callback: {e}")
            try:
                await send_reply(interaction, "❌ An error occurred while showing help. Please try again.", ephemeral=True)
            except Exception:
                # If we can't even send an error message, just log it
                print(f"❌ Failed to send error message for show_help: {e}")

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
            
            guild_id = interaction.guild.id
            server_tier = get_server_tier(guild_id)
            
            # Free tier: Admin only + fake data 
            if server_tier == "free":
                fake_csv = "Date,Clock In,Clock Out,Duration\n2024-01-01,09:00,17:00,8.0 hours\nThis is the free version, please upgrade for more options"
                filename = f"sample_report_last_30_days.csv"
                
                file = discord.File(
                    io.BytesIO(fake_csv.encode('utf-8')), 
                    filename=filename
                )
            
                await interaction.followup.send(
                    f"📊 **Free Tier Sample Report**\n"
                    f"🎯 This is sample data. Upgrade to Dashboard Premium (~~$10~~ $5 one-time) for real reports!\n"
                    f"📅 Date Range: Last 30 days",
                    file=file,
                    ephemeral=True
                )
                return
            
            # Basic and Pro tier: Full reports access with retention limits
            guild_tz_name = get_guild_setting(guild_id, "timezone", DEFAULT_TZ)
            if guild_tz_name is None:
                guild_tz_name = DEFAULT_TZ
            
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
                guild_tz = timezone.utc
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
            user_sessions = {}
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
            
        guild_id = interaction.guild.id
        user_id = interaction.user.id
        
        # RATE LIMITING: Check for spam/abuse
        is_allowed, request_count, action = check_rate_limit(guild_id, user_id, "upgrade")
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
        
        server_tier = get_server_tier(guild_id)
        has_bot_access = check_bot_access(guild_id)
        
        # Show appropriate message based on current status
        if has_bot_access:
            await send_reply(interaction, "✅ This server already has bot access! Use `/upgrade` to add data retention if needed.", ephemeral=True)
            return
        
        embed = discord.Embed(
            title="🚀 Unlock Full Bot Access",
            description="Get complete control of your team's time tracking:",
            color=discord.Color.gold()
        )
        
        embed.add_field(
            name="💎 Dashboard Premium - ~~$10~~ $5 One-Time (Beta Price!)",
            value="• **Unlimited team members** can use timeclock\n"
                  "• **All admin commands** unlocked\n"
                  "• **CSV Reports** for tracking\n"
                  "• **Role management** features\n"
                  "• **Dashboard access** for settings\n"
                  "• **7-day data retention** (included!)",
            inline=False
        )
        
        embed.add_field(
            name="📦 Optional Add-On",
            value="**Pro Retention:** $5/month - Extend to 30-day data retention\n\n"
                  "*Can be added after Dashboard Premium purchase*",
            inline=False
        )
        
        embed.add_field(
            name="🔗 Get Started",
            value="Use `/upgrade` command to purchase bot access via secure Stripe checkout!",
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
SUPPORT_DISCORD_URL = "https://discord.gg/KdTRTqdPcj"

class TimeclockHubView(discord.ui.View):
    """
    Bulletproof timeclock hub with persistent buttons.
    
    Follows 2025 Discord best practices:
    - timeout=None for never-expiring buttons
    - Stable custom_id values with "tc:" prefix
    - Fast ACK (defer immediately in handlers)
    - Registered in setup_hook for post-restart reliability
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
        label="Upgrade",
        style=discord.ButtonStyle.success,
        custom_id="tc:upgrade",
        emoji="🚀",
        row=2
    )
    async def upgrade_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Show upgrade options"""
        await handle_tc_upgrade(interaction)


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
    
    # Check permissions
    server_tier = get_server_tier(guild_id)
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
    
    # Check if already clocked in
    try:
        with db() as conn:
            cursor = conn.execute(
                "SELECT id, clock_in FROM sessions WHERE user_id = %s AND guild_id = %s AND clock_out IS NULL",
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
        
        # Perform clock in
        now = datetime.now(timezone.utc)
        with db() as conn:
            conn.execute(
                "INSERT INTO sessions (user_id, guild_id, clock_in) VALUES (%s, %s, %s)",
                (user_id, guild_id, now.isoformat())
            )
        
        # Ensure employee profile exists
        member = interaction.user
        ensure_employee_profile(
            guild_id, user_id,
            member.name, member.display_name,
            str(member.avatar.url) if member.avatar else str(member.default_avatar.url)
        )
        
        await interaction.followup.send(
            f"✅ **Clocked In!**\n\n"
            f"**Time:** <t:{int(now.timestamp())}:f>\n"
            f"Have a productive shift!",
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
    
    # Check permissions
    server_tier = get_server_tier(guild_id)
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
                "SELECT id, clock_in FROM sessions WHERE user_id = %s AND guild_id = %s AND clock_out IS NULL",
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
                "UPDATE sessions SET clock_out = %s WHERE id = %s",
                (now.isoformat(), session['id'])
            )
        
        await interaction.followup.send(
            f"✅ **Clocked Out!**\n\n"
            f"**Started:** <t:{int(clock_in_time.timestamp())}:f>\n"
            f"**Ended:** <t:{int(now.timestamp())}:f>\n"
            f"**Duration:** {hours_int}h {minutes}m\n\n"
            f"Great work today!",
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
                        EXTRACT(EPOCH FROM (COALESCE(clock_out, NOW()) - clock_in)) / 3600
                    ), 0) as total_hours,
                    COUNT(*) as session_count
                FROM sessions 
                WHERE user_id = %s AND guild_id = %s 
                AND clock_in >= NOW() - INTERVAL '14 days'
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
    """Handle upgrade button - show subscription options"""
    # ACK immediately
    if not await robust_defer(interaction, ephemeral=True):
        return
    
    if not interaction.guild:
        await interaction.followup.send("❌ This command must be used in a server.", ephemeral=True)
        return
    
    guild_id = interaction.guild.id
    
    # Check current subscription status
    has_bot_access = check_bot_access(guild_id)
    retention_tier = get_retention_tier(guild_id)
    
    # Build upgrade embed based on current status
    embed = discord.Embed(
        title="🚀 Upgrade Your Server",
        color=0x57F287
    )
    
    if not has_bot_access:
        embed.description = "Unlock powerful time tracking features!"
        embed.add_field(
            name="📊 Dashboard Premium ($5 one-time)",
            value="• 7-day data retention\n• Full dashboard access\n• CSV reports & exports\n• Time adjustment requests\n• Email automation",
            inline=False
        )
        embed.add_field(
            name="📈 Pro Retention ($5/month add-on)",
            value="• 30-day data retention\n• Perfect for long-term tracking",
            inline=False
        )
    elif retention_tier != '30day':
        embed.description = "You have Dashboard Premium! Consider adding Pro Retention."
        embed.add_field(
            name="📈 Pro Retention ($5/month)",
            value="• Upgrade to 30-day data retention\n• Keep your time records longer",
            inline=False
        )
        embed.add_field(
            name="✅ Your Current Plan",
            value="Dashboard Premium (7-day retention)",
            inline=False
        )
    else:
        embed.description = "You're on the best plan! Thank you for your support."
        embed.add_field(
            name="✅ Your Current Plan",
            value="Dashboard Premium + Pro Retention (30-day)",
            inline=False
        )
    
    embed.set_footer(text="On the Clock • Professional Time Tracking")
    
    # Add upgrade button linking to the upgrade page
    view = discord.ui.View()
    upgrade_url = f"https://on-the-clock.replit.app/upgrade/{guild_id}"
    view.add_item(discord.ui.Button(label="View Upgrade Options", url=upgrade_url, style=discord.ButtonStyle.link))
    
    await interaction.followup.send(embed=embed, view=view, ephemeral=True)


# --- Global on_interaction Fallback Handler ---
# Catches button interactions that might have lost their view reference after bot restart

@bot.event
async def on_interaction(interaction: discord.Interaction):
    """
    Global fallback handler for button interactions.
    
    This catches tc: prefixed buttons that might have lost their view
    reference after a bot restart, ensuring bulletproof reliability.
    """
    # Only handle component (button) interactions
    if interaction.type != discord.InteractionType.component:
        return
    
    # Get the custom_id from interaction data
    custom_id = interaction.data.get('custom_id', '') if interaction.data else ''
    
    # Only handle our tc: prefixed buttons as fallback
    if not custom_id.startswith('tc:'):
        return
    
    # Check if interaction is already handled by the view
    if interaction.response.is_done():
        return
    
    print(f"🔄 [Fallback] Handling orphaned button: {custom_id}")
    
    try:
        if custom_id == 'tc:clock_in':
            await handle_tc_clock_in(interaction)
        elif custom_id == 'tc:clock_out':
            await handle_tc_clock_out(interaction)
        elif custom_id == 'tc:adjustments':
            await handle_tc_adjustments(interaction)
        elif custom_id == 'tc:my_hours':
            await handle_tc_my_hours(interaction)
        elif custom_id == 'tc:support':
            await handle_tc_support(interaction)
        elif custom_id == 'tc:upgrade':
            await handle_tc_upgrade(interaction)
        else:
            print(f"⚠️ [Fallback] Unknown tc: button: {custom_id}")
            
    except Exception as e:
        print(f"❌ [Fallback] Error handling {custom_id}: {e}")
        try:
            if not interaction.response.is_done():
                await interaction.response.send_message(
                    "❌ An error occurred. Please try again.",
                    ephemeral=True
                )
            else:
                await interaction.followup.send(
                    "❌ An error occurred. Please try again.",
                    ephemeral=True
                )
        except Exception:
            pass


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
        title="⏰ Welcome to On the Clock!",
        description=(
            "Thanks for adding our professional Discord timeclock bot to your server!\n\n"
            "**⚠️ Free mode is for testing - data is auto-deleted after 24 hours.**"
        ),
        color=discord.Color.blurple()
    )
    
    # DATA DELETION WARNING - Top-level field for maximum visibility
    embed.add_field(
        name="⚠️ IMPORTANT: Data Deletion Policy",
        value=(
            "**All time entries are purged after 24 hours unless a retention add-on is active.**\n"
            "Free tier is for testing only. Upgrade to save your data!"
        ),
        inline=False
    )
    
    # Add setup instructions
    embed.add_field(
        name="🚀 Quick Setup Guide",
        value=(
            "1️⃣ **Set Employee Roles:** Use `/add_employee_role @role` to grant timeclock access\n"
            "2️⃣ **Set Admin Roles** (optional): Use `/add_admin_role @role` for report/upgrade access\n"
            "3️⃣ **Start Tracking:** Use `/clock` to get your timeclock interface\n"
            "4️⃣ **Get Reports:** Admins can use `/report @user` to export CSV timesheets\n\n"
            "💡 **Tip:** Use `/setup` anytime to see all available commands!"
        ),
        inline=False
    )
    
    # Add free tier features
    embed.add_field(
        name="🆓 Free Tier - What You Get",
        value=(
            "✅ Employee role management\n"
            "✅ Clock in/out tracking via `/clock`\n"
            "✅ View current status (who's clocked in)\n"
            "✅ Basic timezone settings\n\n"
            "**Note:** Reports visible but locked. Upgrade to unlock CSV exports!"
        ),
        inline=False
    )
    
    # Add subscription tier information - NEW MODEL
    embed.add_field(
        name="💼 Upgrade Options",
        value=(
            "**🔓 Dashboard Premium (~~$10~~ $5 one-time - Beta Price!):**\n"
            "• Unlock real reports & CSV exports\n"
            "• Full dashboard access\n"
            "• 7-day data retention included\n"
            "• One-time payment, lifetime access\n\n"
            "**📁 Optional: Pro Retention ($5/month):**\n"
            "• Extend to 30-day data retention\n\n"
            "Use `/upgrade` to unlock features!"
        ),
        inline=False
    )
    
    # Add feature highlights
    embed.add_field(
        name="✨ Key Features",
        value=(
            "• One-click time tracking with Discord buttons\n"
            "• Smart timezone support (EST/EDT by default)\n"
            "• Professional CSV reports for payroll\n"
            "• Real-time \"who's on the clock\" status\n"
            "• Role-based access control\n"
            "• Secure Stripe payment integration"
        ),
        inline=False
    )
    
    # Add footer with support info
    embed.add_field(
        name="💬 Need Help?",
        value=(
            "Join our support server for assistance:\n"
            "🔗 https://discord.gg/KdTRTqdPcj\n\n"
            "Run `/help` anytime to see all available commands!"
        ),
        inline=False
    )
    embed.set_footer(
        text="On the Clock - Professional Discord Timeclock Management",
        icon_url=bot.user.avatar.url if bot.user and bot.user.avatar else None
    )
    
    return embed

@bot.event
async def on_guild_join(guild):
    """Send welcome message with setup instructions when bot joins a new server"""
    print(f"🎉 Bot joined new server: {guild.name} (ID: {guild.id})")
    
    # Try to find the person who added the bot (guild owner as fallback)
    inviter = guild.owner
    
    # Create the setup embed using the helper function
    embed = create_setup_embed()
    
    # Try to send the welcome message to the server owner via DM
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
    
    # ALSO send a welcome message with button to first available text channel
    try:
        target_channel = guild.system_channel
        if not target_channel:
            # Find first text channel the bot can send to
            for channel in guild.text_channels:
                if channel.permissions_for(guild.me).send_messages:
                    target_channel = channel
                    break
        
        if target_channel:
            # Create the SetupInstructionsView button
            view = SetupInstructionsView()
            
            # Send a brief welcome message with the button
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
                conn.execute("DELETE FROM admin_roles WHERE guild_id = %s", (guild_id_int,))
                print(f"   - Deleted admin roles")
                
                # Delete employee roles  
                conn.execute("DELETE FROM employee_roles WHERE guild_id = %s", (guild_id_int,))
                print(f"   - Deleted employee roles")
                
                # Delete guild settings
                conn.execute("DELETE FROM guild_settings WHERE guild_id = %s", (guild_id_int,))
                print(f"   - Deleted guild settings")
                
                # Delete sessions
                conn.execute("DELETE FROM sessions WHERE guild_id = %s", (guild_id_int,))
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
            title="⏰ Welcome to On the Clock!",
            description="Complete onboarding guide for setting up your timeclock bot",
            color=discord.Color.blue()
        )
        
        embed.add_field(
            name="👥 Step 1: Configure Roles",
            value=(
                "**Admin Roles** (can view reports and manage settings):\n"
                "`/add_admin_role @role` - Grant admin access\n"
                "`/list_admin_roles` - View configured admin roles\n\n"
                "**Employee Roles** (can use timeclock functions):\n"
                "`/add_employee_role @role` - Grant timeclock access\n"
                "`/list_employee_roles` - View configured employee roles\n\n"
                "💡 Discord administrators always have full access"
            ),
            inline=False
        )
        
        embed.add_field(
            name="🌐 Step 2: Explore the Dashboard",
            value=(
                f"Visit **{dashboard_url}** to access:\n"
                "• **Settings** - Configure server preferences\n"
                "• **Role Management** - Manage admin and employee roles\n"
                "• **Email Configuration** - Set up report delivery\n"
                "• **Timezone Settings** - Customize display timezone\n"
                "• **Reports & Analytics** - View team activity\n\n"
                "Login with Discord for full access to your server settings"
            ),
            inline=False
        )
        
        embed.add_field(
            name="💰 Step 3: Understand Pricing",
            value=(
                "**Dashboard Premium** - ~~$10~~ $5 one-time (Beta Price!)\n"
                "• Unlocks full bot functionality for your entire team\n"
                "• Includes 7-day data retention\n"
                "• One-time payment, no recurring charges\n\n"
                "**Optional: Pro Retention** - $5/month\n"
                "• Extend to 30-day data retention\n\n"
                "💡 Free tier available for testing (24-hour data retention)\n"
                f"🛒 Purchase: {payment_url}"
            ),
            inline=False
        )
        
        embed.add_field(
            name="🚀 Getting Started",
            value=(
                "**For Employees:**\n"
                "• Type `/clock` to access your personal timeclock\n"
                "• Use the buttons to clock in/out\n\n"
                "**For Admins:**\n"
                "• Type `/help` for a full command reference\n"
                "• Use `/report` to generate timesheet reports\n"
                "• Configure roles using commands above"
            ),
            inline=False
        )
        
        embed.add_field(
            name="🆘 Need Help?",
            value=(
                "Join our Discord support server:\n"
                "https://discord.gg/KdTRTqdPcj\n\n"
                "Get assistance with setup, billing, and troubleshooting"
            ),
            inline=False
        )
        
        embed.set_footer(text="On the Clock • Professional Time Tracking for Discord")
        
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
    
    # Check permissions
    server_tier = get_server_tier(guild_id)
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
        
        # Get current status
        with db() as conn:
            cursor = conn.execute(
                "SELECT clock_in FROM sessions WHERE user_id = %s AND guild_id = %s AND clock_out IS NULL",
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
                    EXTRACT(EPOCH FROM (COALESCE(clock_out, NOW()) - clock_in)) / 3600
                ), 0) as week_hours
                FROM sessions 
                WHERE user_id = %s AND guild_id = %s 
                AND clock_in >= NOW() - INTERVAL '7 days'
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
        await interaction.followup.send(embed=embed, view=TimeclockHubView(), ephemeral=True)
        print(f"✅ [TC Hub] Sent timeclock hub to {interaction.user} in guild {guild_id}")
        
    except Exception as e:
        print(f"❌ [TC Hub] Error creating hub for {interaction.user}: {e}")
        await interaction.followup.send(
            "❌ **Error**\nCouldn't load timeclock hub. Please try again.",
            ephemeral=True
        )


@tree.command(name="set_recipient", description="Set who receives private time entries (DMs)")
@app_commands.describe(user="Manager/admin who should receive time entries via DM")
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def set_recipient(interaction: discord.Interaction, user: discord.User):
    guild_id = interaction.guild_id
    if guild_id is None:
        await send_reply(interaction, "❌ This command must be used in a server.", ephemeral=True)
        return
    set_guild_setting(guild_id, "recipient_user_id", user.id)
    await send_reply(
        interaction, 
        f"✅ **Set recipient to {user.mention}**\n\n"
        f"**Discord DMs:** This user will receive Discord DMs when employees clock out.\n\n"
        f"**Email Reports:** If email notifications are enabled in the dashboard, emails will be sent to the email addresses you configure there (not to individual Discord users).",
        ephemeral=True
    )

@tree.command(name="set_timezone", description="Set display timezone (e.g., America/New_York)")
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def set_timezone(interaction: discord.Interaction, tz: str):
    guild_id = interaction.guild_id
    if guild_id is None:
        await send_reply(interaction, "❌ This command must be used in a server.", ephemeral=True)
        return
    set_guild_setting(guild_id, "timezone", tz)
    await send_reply(interaction, f"✅ Timezone set to `{tz}` (display only).", ephemeral=True)

@tree.command(name="toggle_name_display", description="Toggle between username and nickname display")
@app_commands.describe(mode="Choose 'username' (Discord username) or 'nickname' (server display name)")
@app_commands.choices(mode=[
    app_commands.Choice(name="Username (Discord username)", value="username"),
    app_commands.Choice(name="Nickname (Server display name)", value="nickname")
])
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def toggle_name_display(interaction: discord.Interaction, mode: app_commands.Choice[str]):
    guild_id = interaction.guild_id
    if guild_id is None:
        await send_reply(interaction, "❌ This command must be used in a server.", ephemeral=True)
        return
    set_guild_setting(guild_id, "name_display_mode", mode.value)
    
    if mode.value == "username":
        await send_reply(interaction,
            "✅ **Name Display Set to Username**\n"
            "The bot will now show Discord usernames (e.g., `john_doe`) in reports and messages.",
            ephemeral=True
        )
    else:
        await send_reply(interaction,
            "✅ **Name Display Set to Nickname**\n"
            "The bot will now show server display names (e.g., `John D.`) in reports and messages.",
            ephemeral=True
        )

@tree.command(name="mobile", description="Toggle mobile/tablet clock-in restrictions")
@app_commands.describe(enabled="Enable (block mobile) or disable (allow mobile) restriction")
@app_commands.choices(enabled=[
    app_commands.Choice(name="Restrict mobile/tablet devices (employees must use desktop)", value="on"),
    app_commands.Choice(name="Allow mobile/tablet devices (default)", value="off")
])
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def mobile_restriction_cmd(interaction: discord.Interaction, enabled: app_commands.Choice[str]):
    guild_id = interaction.guild_id
    if guild_id is None:
        await send_reply(interaction, "❌ This command must be used in a server.", ephemeral=True)
        return
    
    # Update mobile restriction setting
    restrict = (enabled.value == "on")
    
    with db() as conn:
        # Ensure a record exists
        cursor = conn.execute("SELECT guild_id FROM server_subscriptions WHERE guild_id = %s", (guild_id,))
        exists = cursor.fetchone()
        
        if exists:
            conn.execute(
                "UPDATE server_subscriptions SET restrict_mobile_clockin = %s WHERE guild_id = %s",
                (restrict, guild_id)
            )
        else:
            # Insert new record with all required default values
            conn.execute(
                """INSERT INTO server_subscriptions 
                   (guild_id, tier, bot_access_paid, retention_tier, restrict_mobile_clockin) 
                   VALUES (%s, 'free', FALSE, 'none', %s)""",
                (guild_id, restrict)
            )
    
    if restrict:
        await send_reply(interaction,
            "📱 **Mobile Clock-In Restricted**\n\n"
            "Employees can now **only** clock in/out from desktop or web browser.\n"
            "Mobile and tablet devices are blocked.\n\n"
            "⚠️ **Limitations:**\n"
            "• Discord can't distinguish phones from tablets\n"
            "• Users on multiple devices (desktop + phone) may bypass this\n"
            "• Invisible/offline users can't be detected",
            ephemeral=True
        )
    else:
        await send_reply(interaction,
            "✅ **Mobile Clock-In Allowed**\n\n"
            "Employees can now clock in/out from any device (desktop, mobile, or tablet).",
            ephemeral=True
        )



@tree.command(name="add_admin_role", description="Add a role that can access Reports and Upgrade buttons")
@app_commands.describe(role="Role to grant admin access (Reports, Upgrade buttons)")
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def add_admin_role_cmd(interaction: discord.Interaction, role: discord.Role):
    await interaction.response.defer(ephemeral=True)
    
    guild_id = interaction.guild_id
    if guild_id is None:
        await interaction.followup.send("❌ This command must be used in a server.")
        return
    add_admin_role(guild_id, role.id)
    await interaction.followup.send(f"✅ Added {role.mention} to admin roles. They can now use Reports and Upgrade buttons.")

@tree.command(name="remove_admin_role", description="Remove a role's admin access to Reports and Upgrade buttons")
@app_commands.describe(role="Role to remove admin access from")
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def remove_admin_role_cmd(interaction: discord.Interaction, role: discord.Role):
    await interaction.response.defer(ephemeral=True)
    
    guild_id = interaction.guild_id
    if guild_id is None:
        await interaction.followup.send("❌ This command must be used in a server.")
        return
    remove_admin_role(guild_id, role.id)
    await interaction.followup.send(f"✅ Removed {role.mention} from admin roles. They can no longer use Reports and Upgrade buttons.")

@tree.command(name="list_admin_roles", description="List all roles with admin access")
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def list_admin_roles(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    
    guild_id = interaction.guild_id
    if guild_id is None:
        await interaction.followup.send("❌ This command must be used in a server.")
        return
    
    admin_role_ids = get_admin_roles(guild_id)
    
    embed = discord.Embed(
        title="🛡️ Admin Roles",
        description="Roles that can access Reports and Upgrade buttons:",
        color=discord.Color.blue()
    )
    
    # Always show Administrator role first (permanent, cannot be removed)
    embed.add_field(name="Built-in Admin Role", value="@Admin (Discord Administrators)", inline=False)
    
    # Show custom admin roles if any are configured
    if admin_role_ids:
        admin_roles = []
        for role_id in admin_role_ids:
            role = interaction.guild.get_role(role_id) if interaction.guild else None
            if role:
                admin_roles.append(role.mention)
            else:
                admin_roles.append(f"<Deleted Role: {role_id}>")
        embed.add_field(name="Custom Admin Roles", value="\n".join(admin_roles), inline=False)
    else:
        embed.add_field(name="Custom Admin Roles", value="*No custom admin roles configured*", inline=False)
    
    embed.add_field(name="Note", value="Discord Administrators always have admin access.", inline=False)
    
    await interaction.followup.send(embed=embed)

@tree.command(name="set_main_role", description="Set the primary admin role (gets all admin functions)")
@app_commands.describe(role="Role to designate as main admin (gets Reports, Upgrade, all admin access)")
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def set_main_role(interaction: discord.Interaction, role: discord.Role):
    """Set the primary admin role that gets all admin functions"""
    guild_id = interaction.guild_id
    if guild_id is None:
        await send_reply(interaction, "❌ This command must be used in a server.", ephemeral=True)
        return
    set_guild_setting(guild_id, "main_admin_role_id", role.id)
    
    embed = discord.Embed(
        title="🛡️ Main Admin Role Set",
        description=f"**{role.mention}** is now the main admin role for this server.",
        color=discord.Color.green()
    )
    embed.add_field(
        name="What this means:",
        value=(
            "• This role gets **all admin functions** (Reports, Upgrade, etc.)\n"
            "• Works in addition to Discord Administrators\n"
            "• Perfect for designating manager roles\n"
            "• Useful for Top.gg reviewers and testing"
        ),
        inline=False
    )
    embed.add_field(
        name="Management:",
        value="Use `/show_main_role` to view or `/clear_main_role` to remove",
        inline=False
    )
    
    await send_reply(interaction, embed=embed, ephemeral=True)

@tree.command(name="show_main_role", description="View the current main admin role")
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def show_main_role(interaction: discord.Interaction):
    """Show the current main admin role"""
    guild_id = interaction.guild_id
    if guild_id is None:
        await send_reply(interaction, "❌ This command must be used in a server.", ephemeral=True)
        return
    
    main_role_id = get_guild_setting(guild_id, "main_admin_role_id")
    
    if not main_role_id:
        embed = discord.Embed(
            title="🛡️ Main Admin Role",
            description="No main admin role is currently set.",
            color=discord.Color.orange()
        )
        embed.add_field(
            name="To set a main admin role:",
            value="Use `/set_main_role @role` to designate a role with all admin functions",
            inline=False
        )
    else:
        role = interaction.guild.get_role(main_role_id) if interaction.guild else None
        if role:
            embed = discord.Embed(
                title="🛡️ Main Admin Role",
                description=f"**{role.mention}** is the main admin role.",
                color=discord.Color.blue()
            )
            embed.add_field(
                name="Permissions:",
                value="This role has access to all admin functions (Reports, Upgrade buttons, etc.)",
                inline=False
            )
        else:
            embed = discord.Embed(
                title="🛡️ Main Admin Role",
                description="Main admin role was set but the role has been deleted.",
                color=discord.Color.red()
            )
            embed.add_field(
                name="Fix this:",
                value="Use `/clear_main_role` to clear the invalid role, then `/set_main_role` to set a new one",
                inline=False
            )
    
    await send_reply(interaction, embed=embed, ephemeral=True)

@tree.command(name="clear_main_role", description="Remove the main admin role designation") 
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def clear_main_role(interaction: discord.Interaction):
    """Clear the main admin role"""
    guild_id = interaction.guild_id
    if guild_id is None:
        await send_reply(interaction, "❌ This command must be used in a server.", ephemeral=True)
        return
    
    main_role_id = get_guild_setting(guild_id, "main_admin_role_id")
    
    if not main_role_id:
        await send_reply(interaction,
            "No main admin role is currently set.",
            ephemeral=True
        )
        return
    
    # Get role name before clearing (if it exists)
    role = interaction.guild.get_role(main_role_id) if interaction.guild else None
    role_name = role.mention if role else f"<Deleted Role: {main_role_id}>"
    
    # Clear the main admin role
    set_guild_setting(guild_id, "main_admin_role_id", None)
    
    embed = discord.Embed(
        title="🛡️ Main Admin Role Cleared",
        description=f"**{role_name}** is no longer the main admin role.",
        color=discord.Color.green()
    )
    embed.add_field(
        name="Current Admin Access:",
        value=(
            "• Discord Administrators (always have access)\n"
            "• Custom admin roles (if any set via `/add_admin_role`)"
        ),
        inline=False
    )
    
    await send_reply(interaction, embed=embed, ephemeral=True)

@tree.command(name="add_employee_role", description="Add a role that can use timeclock functions")
@app_commands.describe(role="Role to grant employee access (timeclock functions)")
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def add_employee_role_cmd(interaction: discord.Interaction, role: discord.Role):
    await interaction.response.defer(ephemeral=True)
    
    guild_id = interaction.guild_id
    if guild_id is None:
        await interaction.followup.send("❌ This command must be used in a server.")
        return
    add_employee_role(guild_id, role.id)
    server_tier = get_server_tier(guild_id)
    
    # Provide helpful context based on server tier
    if server_tier == "free":
        message = f"✅ Added {role.mention} to employee roles.\n🎉 **Employee roles work on free tier!** Only limitation is shorter data retention compared to paid plans."
    else:
        message = f"✅ Added {role.mention} to employee roles. Members with this role can now use timeclock functions."
    
    await interaction.followup.send(message)

@tree.command(name="remove_employee_role", description="Remove a role's access to timeclock functions")
@app_commands.describe(role="Role to remove employee access from")
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def remove_employee_role_cmd(interaction: discord.Interaction, role: discord.Role):
    await interaction.response.defer(ephemeral=True)
    
    if interaction.guild_id is None:
        await interaction.followup.send("❌ This command must be used in a server.")
        return
    remove_employee_role(interaction.guild_id, role.id)
    await interaction.followup.send(f"✅ Removed {role.mention} from employee roles. They can no longer use timeclock functions (unless admin).")

@tree.command(name="list_employee_roles", description="List all roles that can use timeclock functions")
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def list_employee_roles(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    
    if interaction.guild_id is None:
        await interaction.followup.send("❌ This command must be used in a server.")
        return
    clock_role_ids = get_employee_roles(interaction.guild_id)
    server_tier = get_server_tier(interaction.guild_id)
    
    embed = discord.Embed(
        title="👥 Employee Access Roles",
        description="Roles that can use timeclock functions:",
        color=discord.Color.green()
    )
    
    # Always show Administrator role first (permanent, cannot be removed)
    embed.add_field(name="Built-in Employee Access", value="@Admin (Discord Administrators)", inline=False)
    
    # Show custom employee roles if any are configured
    if clock_role_ids:
        employee_roles = []
        if interaction.guild:  # Additional null check for LSP
            for role_id in clock_role_ids:
                role = interaction.guild.get_role(role_id)
                if role:
                    employee_roles.append(role.mention)
                else:
                    employee_roles.append(f"<Deleted Role: {role_id}>")
        
        embed.add_field(name="Custom Employee Roles", value="\n".join(employee_roles), inline=False)
        
        if server_tier == "free":
            embed.add_field(name="⚠️ Free Tier Limitation", value="These roles are configured but won't take effect until you upgrade to Dashboard Premium. Currently only admins can use timeclock functions.", inline=False)
    else:
        if server_tier == "free":
            embed.add_field(name="Custom Employee Roles", value="*No custom employee roles configured.*\nUpgrade to Dashboard Premium to configure roles for team access!", inline=False)
        else:
            embed.add_field(name="Custom Employee Roles", value="*No custom employee roles configured.*\nUse `/add_employee_role @role` to grant access to your team!", inline=False)
    
    embed.add_field(name="Note", value="Administrators always have timeclock access regardless of role configuration.", inline=False)
    
    await interaction.followup.send(embed=embed)


@tree.command(name="help", description="List all available slash commands")
@app_commands.guild_only()
async def help_command(interaction: discord.Interaction):
    if interaction.guild_id is None:
        await send_reply(interaction, "❌ This command must be used in a server.", ephemeral=True)
        return
    
    guild_id = interaction.guild_id
    
    has_bot_access = check_bot_access(guild_id)
    retention_tier = get_retention_tier(guild_id)
    
    if retention_tier == '30day':
        tier_display = "🚀 PRO RETENTION"
        tier_color = discord.Color.gold()
    elif has_bot_access:
        tier_display = "💎 DASHBOARD PREMIUM"
        tier_color = discord.Color.blue()
    else:
        tier_display = "🆓 FREE TIER"
        tier_color = discord.Color.greyple()
    
    embed = discord.Embed(
        title="📋 On the Clock - Command Help",
        description=f"**Your Server:** {tier_display}",
        color=tier_color
    )
    
    embed.add_field(
        name="🆓 FREE TIER (All Users)",
        value=(
            "• `/clock` - Quick clock in/out\n"
            "• `/setup` - View onboarding info\n"
            "• Clock in/out buttons work\n"
            "• 24-hour data retention ⚠️"
        ),
        inline=False
    )
    
    embed.add_field(
        name="💎 DASHBOARD PREMIUM ($5 One-Time)",
        value=(
            "• Everything in Free, plus:\n"
            "• 7-day data retention\n"
            "• Full dashboard access\n"
            "• CSV reports\n"
            "• Time adjustment requests\n"
            "• Email automation"
        ),
        inline=False
    )
    
    embed.add_field(
        name="🚀 PRO RETENTION ($5/month)",
        value=(
            "• Everything in Premium, plus:\n"
            "• 30-day data retention\n"
            "• Long-term tracking"
        ),
        inline=False
    )
    
    is_admin = False
    if isinstance(interaction.user, discord.Member):
        is_admin = interaction.user.guild_permissions.administrator
    
    if is_admin:
        embed.add_field(
            name="🔧 ADMIN COMMANDS",
            value=(
                "**Role Management:**\n"
                "`/add_admin_role` `/remove_admin_role` `/list_admin_roles`\n"
                "`/add_employee_role` `/remove_employee_role` `/list_employee_roles`\n"
                "`/set_main_role` `/show_main_role` `/clear_main_role`\n\n"
                "**Configuration:**\n"
                "`/set_recipient` `/set_timezone` `/toggle_name_display`\n\n"
                "**Reports & Data:**\n"
                "`/report` `/data_cleanup` `/purge`\n\n"
                "**Subscription:**\n"
                "`/upgrade` `/subscription_status` `/cancel_subscription`"
            ),
            inline=False
        )
    
    if not has_bot_access:
        embed.add_field(
            name="⬆️ Upgrade Your Server",
            value="Use `/upgrade` to unlock premium features!",
            inline=False
        )
    
    await send_reply(interaction, embed=embed, ephemeral=True)

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
    # Robust defer with proper fallback
    defer_success = await robust_defer(interaction, ephemeral=True)
    if not defer_success and not interaction.response.is_done():
        # If defer failed and interaction isn't done, we can't proceed
        return
    
    # Check bot access for reports (NEW MONETIZATION MODEL)
    if interaction.guild is None:
        await interaction.followup.send("❌ This command must be used in a server.", ephemeral=True)
        return
        
    guild_id = interaction.guild.id
    
    # Type guard: ensure we have a Member for guild-specific functions
    if not isinstance(interaction.user, discord.Member):
        await interaction.followup.send(
            "❌ Unable to verify admin permissions. Please try again.",
            ephemeral=True
        )
        return
    
    # Check if bot access is paid (NEW MODEL: $5 one-time payment)
    if not check_bot_access(guild_id):
        # No bot access - show dummy report with upgrade prompt
        user_display_name = get_user_display_name(user, guild_id)
        
        # Create dummy CSV
        fake_csv = (
            "Date,Clock In,Clock Out,Duration\n"
            "2024-01-01,09:00,17:00,8.0 hours\n"
            "2024-01-02,09:30,18:00,8.5 hours\n"
            "2024-01-03,08:45,16:45,8.0 hours\n\n"
            "This is sample data. Upgrade to unlock real reports!"
        )
        filename = f"{user_display_name}_SAMPLE_report_{start_date}_to_{end_date}.csv"
        
        file = discord.File(
            io.BytesIO(fake_csv.encode('utf-8')), 
            filename=filename
        )
        
        await interaction.followup.send(
            f"🔒 **Reports Feature Locked**\n\n"
            f"📊 This is a **sample report** with dummy data for **{user_display_name}**.\n\n"
            f"**To unlock real reports:**\n"
            f"1️⃣ Purchase **Full Bot Access** ($5 one-time per server)\n"
            f"2️⃣ Get instant access to real CSV exports\n\n"
            f"**⚠️ Remember:** Free tier has 24-hour data deletion!\n"
            f"Add a retention plan to keep your data longer.\n\n"
            f"Use `/upgrade` to unlock full bot access!",
            file=file,
            ephemeral=True
        )
        return
    
    # Bot access is paid - use get_retention_days for proper retention calculation
    # NEW MODEL: bot_access_paid = true automatically gets 7 days, subscription gets 30 days
    max_days = get_retention_days(guild_id)
    retention_tier = get_retention_tier(guild_id)
    
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
        
        # Check retention limits based on retention tier
        days_requested = (end_dt - start_dt).days + 1
        if days_requested > max_days:
            # Create appropriate upgrade message based on current tier
            if max_days == 1:
                # Free tier - suggest Dashboard Premium
                upgrade_msg = "\n\n💡 Upgrade to **Dashboard Premium** (~~$10~~ $5 one-time) to unlock 7-day retention!"
            elif max_days == 7:
                # Dashboard Premium - suggest Pro Retention
                upgrade_msg = "\n\n💡 Upgrade to **Pro Retention** ($5/month) for 30-day data retention!"
            else:
                upgrade_msg = ""
            
            await interaction.followup.send(
                f"❌ **Data Retention Limitation**: Your current plan allows reports up to {max_days} day{'s' if max_days != 1 else ''} maximum.\n"
                f"You requested {days_requested} days. Please choose a shorter date range.{upgrade_msg}",
                ephemeral=True
            )
            return
            
    except ValueError:
        await interaction.followup.send(
            "❌ Invalid date format. Please use YYYY-MM-DD (e.g., 2024-01-15)", 
            ephemeral=True
        )
        return
    
    # Get guild timezone (guild_id already checked above)
    guild_tz_name = get_guild_setting(guild_id, "timezone", DEFAULT_TZ)
    
    # Convert date range to UTC boundaries for proper filtering
    try:
        from zoneinfo import ZoneInfo
        guild_tz = ZoneInfo(guild_tz_name or DEFAULT_TZ)
    except Exception:
        guild_tz = timezone.utc
        guild_tz_name = "UTC"  # Use actual UTC if timezone is invalid
    
    # Create start and end boundaries in guild timezone, then convert to UTC
    start_boundary = datetime.combine(start_dt.date(), datetime.min.time()).replace(tzinfo=guild_tz)
    end_boundary = datetime.combine(end_dt.date(), datetime.max.time()).replace(tzinfo=guild_tz)
    
    start_utc = start_boundary.astimezone(timezone.utc).isoformat()
    end_utc = end_boundary.astimezone(timezone.utc).isoformat()
    
    # Generate report for specific user (guild_id already checked above)
    user_id = user.id
    sessions_data = get_sessions_report(guild_id, user_id, start_utc, end_utc)
    
    if not sessions_data:
        user_display_name = get_user_display_name(user, guild_id)
        await interaction.followup.send(
            f"📭 No completed timesheet entries found for **{user_display_name}** between {start_date} and {end_date}",
            ephemeral=True
        )
        return
    
    # Generate single CSV
    csv_content = await generate_csv_report(bot, sessions_data, guild_id, guild_tz_name or DEFAULT_TZ)
    
    # Create file using display name preference at the beginning
    user_display_name = get_user_display_name(user, guild_id)
    filename = f"{user_display_name}_timesheet_report_{start_date}_to_{end_date}.csv"
    
    file = discord.File(
        io.BytesIO(csv_content.encode('utf-8')), 
        filename=filename
    )
    
    # Send file
    total_entries = len(sessions_data)
    
    await interaction.followup.send(
        f"📊 Generated timesheet report for **{user_display_name}**\n"
        f"📅 **Period:** {start_date} to {end_date}\n"
        f"📝 **Entries:** {total_entries} completed shifts\n"
        f"🕐 **Timezone:** {guild_tz_name}",
        file=file,
        ephemeral=True
    )
    
    # Also send email reports to configured email recipients
    try:
        recipients = get_report_recipients(guild_id)
        email_recipients = [r for r in recipients if r[1] == 'email' and r[3]]  # recipient_type == 'email' and email_address exists
        
        if email_recipients:
            email_addresses = [r[3] for r in email_recipients]  # Extract email addresses
            
            try:
                guild_name = interaction.guild.name if interaction.guild else f"Server-{guild_id}"
                report_period = f"{start_date} to {end_date} - {user_display_name}"
                
                # Send email report to all email recipients
                result = await send_timeclock_report_email(
                    to=email_addresses,
                    guild_name=guild_name,
                    csv_content=csv_content,
                    report_period=report_period
                )
                
                print(f"✅ Email report sent to {len(email_addresses)} recipients for {user_display_name}")
                
            except Exception as email_error:
                print(f"❌ Failed to send email report: {email_error}")
                
    except Exception as e:
        print(f"⚠️ Email report delivery attempt failed: {e}")

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

@tree.command(name="data_cleanup", description="Manually trigger data cleanup (Admin only)")
@app_commands.describe(user="Optional: Delete all timeclock data for a specific server member only")
@app_commands.default_permissions(administrator=True)  
@app_commands.guild_only()
async def manual_cleanup(interaction: discord.Interaction, user: Optional[discord.Member] = None):
    """Allow admins to manually trigger data cleanup - either for old sessions or for a specific user"""
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
        
        if user:
            # Delete all data for the specific user
            deleted_count = cleanup_user_sessions(guild_id, user.id)
            
            embed = discord.Embed(
                title="🗑️ User Data Cleanup Complete",
                color=discord.Color.green()
            )
            embed.add_field(name="Target User", value=f"{user.mention} ({user.name})", inline=True)
            embed.add_field(name="Records Removed", value=f"{deleted_count} sessions", inline=True)
            embed.add_field(
                name="⚠️ Action Performed",
                value=f"All timeclock data for **{user.name}** has been permanently deleted from this server.",
                inline=False
            )
            
        else:
            # Clean up old sessions based on retention policy
            deleted_count = cleanup_old_sessions(guild_id)
            retention_days = get_retention_days(guild_id)
            tier = get_server_tier(guild_id)
            
            embed = discord.Embed(
                title="🧹 Data Cleanup Complete",
                color=discord.Color.green()
            )
            embed.add_field(name="Records Removed", value=f"{deleted_count} old sessions", inline=True)
            embed.add_field(name="Current Tier", value=f"{tier.title()}", inline=True)
            embed.add_field(name="Data Retention", value=f"{retention_days} days", inline=True)
            embed.add_field(
                name="Retention Policy",
                value="**Free:** No retention (test only)\n**Dashboard Premium:** 7 days (1 week)\n**Pro Retention:** 30 days (1 month)",
                inline=False
            )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
    except (discord.NotFound, discord.errors.NotFound):
        # Interaction expired or was deleted - silently handle this
        print(f"⚠️ Data cleanup interaction expired/not found for user {interaction.user.id}")
    except discord.errors.InteractionResponded:
        # Interaction was already responded to - try followup
        try:
            await interaction.followup.send("❌ Cleanup interaction error. Please try again.", ephemeral=True)
        except Exception as e:
            print(f"⚠️ Failed to send followup after InteractionResponded: {e}")
    except Exception as e:
        # General error handling
        print(f"❌ Error in data_cleanup command: {e}")
        try:
            if not interaction.response.is_done():
                await interaction.response.send_message(f"❌ Error during cleanup: {str(e)}", ephemeral=True)
            else:
                await interaction.followup.send(f"❌ Error during cleanup: {str(e)}", ephemeral=True)
        except Exception:
            # If we can't even send an error message, just log it
            print(f"❌ Failed to send error message for data_cleanup: {e}")

class PurgeConfirmationView(discord.ui.View):
    """Confirmation view for purge command"""
    def __init__(self, guild_id: int):
        super().__init__(timeout=60.0)  # 60 second timeout
        self.guild_id = guild_id
        self.confirmed = False
    
    @discord.ui.button(label="✅ Yes, Purge Timeclock Data", style=discord.ButtonStyle.danger, custom_id="purge_yes")
    async def confirm_purge(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Handle purge confirmation"""
        # Robust defer with proper fallback
        defer_success = await robust_defer(interaction, ephemeral=True)
        if not defer_success and not interaction.response.is_done():
            # If defer failed and interaction isn't done, we can't proceed
            return
        
        # OWNER-ONLY CHECK: Only server owner can confirm purge
        if not isinstance(interaction.user, discord.Member):
            await interaction.followup.send("❌ Unable to verify permissions.", ephemeral=True)
            return
        
        if interaction.user.id != interaction.guild.owner_id:
            await interaction.followup.send("❌ Only the **server owner** can purge data.", ephemeral=True)
            return
        
        try:
            # Use standalone purge function
            purge_timeclock_data_only(self.guild_id)
            
            embed = discord.Embed(
                title="🗑️ Timeclock Data Purge Complete",
                description="All timeclock sessions have been permanently removed.",
                color=discord.Color.green()
            )
            embed.add_field(
                name="What was removed:",
                value="• All time clock sessions (all users, all dates)",
                inline=False
            )
            embed.add_field(
                name="What was preserved:",
                value="• Subscription status remains unchanged\n• Server settings kept intact\n• Role permissions preserved",
                inline=False
            )
            embed.add_field(
                name="⚠️ This action cannot be undone",
                value="Your timeclock history has been cleared, but your subscription and settings remain active.",
                inline=False
            )
            
            await interaction.followup.send(embed=embed, ephemeral=True)
            self.confirmed = True
            
            # Disable all buttons
            for item in self.children:
                if isinstance(item, discord.ui.Button):
                    item.disabled = True
            
        except Exception as e:
            await interaction.followup.send(f"❌ Error during purge: {str(e)}", ephemeral=True)
    
    @discord.ui.button(label="❌ Cancel", style=discord.ButtonStyle.secondary, custom_id="purge_no")
    async def cancel_purge(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Handle purge cancellation"""
        embed = discord.Embed(
            title="✅ Purge Cancelled",
            description="No timeclock data was removed. Your server data remains intact.",
            color=discord.Color.green()
        )
        
        await interaction.response.edit_message(embed=embed, view=None)
    
    async def on_timeout(self):
        """Handle timeout"""
        # Disable all buttons when timeout occurs
        for item in self.children:
            if isinstance(item, discord.ui.Button):
                item.disabled = True

@tree.command(name="purge", description="Permanently delete timeclock data (preserves subscription)")
@app_commands.default_permissions(administrator=True)  
@app_commands.guild_only()
async def purge_data(interaction: discord.Interaction):
    """Allow SERVER OWNERS ONLY to manually purge timeclock data"""
    # Robust defer with proper fallback
    defer_success = await robust_defer(interaction, ephemeral=True)
    if not defer_success and not interaction.response.is_done():
        # If defer failed and interaction isn't done, we can't proceed
        return
    
    if interaction.guild is None:
        await interaction.followup.send("❌ This command must be used in a server.", ephemeral=True)
        return
        
    guild_id = interaction.guild.id
    
    # Type guard: ensure we have a Member for guild-specific functions
    if not isinstance(interaction.user, discord.Member):
        await interaction.followup.send(
            "❌ Unable to verify permissions. Please try again.",
            ephemeral=True
        )
        return
    
    # OWNER-ONLY CHECK: Only server owner can purge data
    if interaction.user.id != interaction.guild.owner_id:
        await interaction.followup.send(
            "❌ Only the **server owner** can use this command. This is a destructive operation that permanently deletes all timeclock data.",
            ephemeral=True
        )
        return
    
    # Create warning embed
    embed = discord.Embed(
        title="⚠️ WARNING: Timeclock Data Purge",
        description="This will **permanently delete ALL timeclock sessions**!",
        color=discord.Color.orange()
    )
    embed.add_field(
        name="What will be deleted:",
        value="• **All time clock sessions** (all users, all dates)",
        inline=False
    )
    embed.add_field(
        name="What will be preserved:",
        value=(
            "• **Subscription status** (Dashboard Premium/Pro Retention remain active)\n"
            "• **Server settings** (timezone, recipients, etc.)\n"
            "• **Role permissions** for buttons"
        ),
        inline=False
    )
    embed.add_field(
        name="⚠️ THIS CANNOT BE UNDONE",
        value="All historical timeclock data will be permanently lost.",
        inline=False
    )
    
    # Create confirmation view
    view = PurgeConfirmationView(guild_id)
    
    await interaction.followup.send(embed=embed, view=view, ephemeral=True)

# --- Subscription Management Commands ---
@tree.command(name="upgrade", description="Upgrade your server with bot access or data retention")
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def upgrade_server(interaction: discord.Interaction):
    """Show upgrade options based on current access level (NEW MONETIZATION MODEL)"""
    # Robust defer with proper fallback
    defer_success = await robust_defer(interaction, ephemeral=True)
    if not defer_success and not interaction.response.is_done():
        return
    
    if interaction.guild is None:
        await interaction.followup.send("❌ This command must be used in a server.", ephemeral=True)
        return
        
    guild_id = interaction.guild.id
    
    try:
        # Check Stripe configuration first
        if not stripe.api_key:
            await interaction.followup.send(
                "❌ Payment system is not configured. Please contact support.",
                ephemeral=True
            )
            return
        
        # Check current bot access status
        has_bot_access = check_bot_access(guild_id)
        retention_tier = get_retention_tier(guild_id)
        
        if not has_bot_access:
            # STEP 1: Offer Dashboard Premium ($5 one-time with 7-day retention)
            checkout_url = create_secure_checkout_session(guild_id, "bot_access")
            
            embed = discord.Embed(
                title="🔓 Dashboard Premium",
                description=(
                    "**Unlock full access to On the Clock!**\n\n"
                    "Currently on **Free Tier** with 24-hour data deletion.\n"
                    "Upgrade to unlock the dashboard and 7-day retention."
                ),
                color=discord.Color.gold()
            )
            embed.add_field(
                name="✨ What You Get:",
                value=(
                    "✅ Full dashboard access\n"
                    "✅ 7-day data retention (up from 24 hours)\n"
                    "✅ Real CSV reports & exports\n"
                    "✅ All bot features unlocked\n"
                    "✅ One-time payment, lifetime access"
                ),
                inline=False
            )
            embed.add_field(
                name="💳 Pricing:",
                value="~~$10~~ **$5 one-time** (Beta Price!) - No recurring fees!",
                inline=False
            )
            
            # Create button for bot access checkout
            view = discord.ui.View()
            button = discord.ui.Button(
                label="Dashboard Premium - $5 One-Time",
                style=discord.ButtonStyle.success,
                url=checkout_url
            )
            view.add_item(button)
            
            await interaction.followup.send(embed=embed, view=view, ephemeral=True)
            
        else:
            # STEP 2: Bot access paid - they already have 7-day retention, offer 30-day upgrade
            current_retention_display = "7 days" if retention_tier in ('none', '7day') else "30 days"
            
            if retention_tier == "30day":
                # Already have 30-day (max tier)
                embed = discord.Embed(
                    title="✅ Pro Retention Active",
                    description=(
                        "**You're on the maximum plan!**\n\n"
                        "• Dashboard Premium: ✅ Active\n"
                        "• Pro Retention (30-day): ✅ Active\n\n"
                        "Thank you for supporting On the Clock! 🎉"
                    ),
                    color=discord.Color.green()
                )
                
                await interaction.followup.send(embed=embed, ephemeral=True)
                
            else:
                # Has bot access (7-day retention), offer Pro Retention upgrade
                embed = discord.Embed(
                    title="⬆️ Upgrade to Pro Retention",
                    description=(
                        "**✅ Dashboard Premium Active!**\n\n"
                        "You currently have **7-day data retention** included with Dashboard Premium.\n\n"
                        "Upgrade to **Pro Retention** for full month reporting!"
                    ),
                    color=discord.Color.blue()
                )
                
                embed.add_field(
                    name="📊 Current Plan",
                    value=(
                        "✅ Dashboard Premium (one-time)\n"
                        "✅ 7-day data retention (included)\n"
                        "✅ Full dashboard access\n"
                        "✅ CSV reports & exports"
                    ),
                    inline=False
                )
                
                embed.add_field(
                    name="📈 Pro Retention - $5/month",
                    value=(
                        "• **30-day data retention**\n"
                        "• Full month reporting\n"
                        "• Extended historical data\n"
                        "• Perfect for monthly payroll"
                    ),
                    inline=False
                )
                
                # Create button for 30-day retention
                view = discord.ui.View()
                checkout_url_30day = create_secure_checkout_session(guild_id, "retention_30day")
                button_30day = discord.ui.Button(
                    label="Pro Retention - $5/month",
                    style=discord.ButtonStyle.success,
                    url=checkout_url_30day
                )
                view.add_item(button_30day)
                
                await interaction.followup.send(embed=embed, view=view, ephemeral=True)
        
    except Exception as e:
        await interaction.followup.send(
            f"❌ Error creating upgrade options: {str(e)}", 
            ephemeral=True
        )

@tree.command(name="cancel_subscription", description="Learn how to cancel your subscription")
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def cancel_subscription(interaction: discord.Interaction):
    """Provide instructions for canceling subscription"""
    # Robust defer with proper fallback
    defer_success = await robust_defer(interaction, ephemeral=True)
    if not defer_success and not interaction.response.is_done():
        # If defer failed and interaction isn't done, we can't proceed
        return
    
    if interaction.guild is None:
        await interaction.followup.send("❌ This command must be used in a server.", ephemeral=True)
        return
        
    guild_id = interaction.guild.id
    
    try:
        # Check current subscription status
        current_tier = get_server_tier(guild_id)
        
        if current_tier == "free":
            embed = discord.Embed(
                title="📋 Subscription Information",
                description="Your server is currently on the **Free** plan and has no active subscription to cancel.",
                color=discord.Color.green()
            )
            
            embed.add_field(
                name="Current Status",
                value="✅ No subscription - No action needed",
                inline=False
            )
            
            embed.add_field(
                name="Want to upgrade?",
                value="Use `/upgrade` to get Dashboard Premium ($5 one-time) or Pro Retention ($5/month)",
                inline=False
            )
            
        else:
            embed = discord.Embed(
                title="🚨 How to Cancel Your Subscription",
                description=f"Your server is currently on the **{current_tier.title()}** plan. Here's how to cancel:",
                color=discord.Color.red()
            )
            
            embed.add_field(
                name="Step 1: Access Stripe Customer Portal",
                value="Visit [Stripe Customer Portal](https://billing.stripe.com/p/login) and log in with the email used for payment",
                inline=False
            )
            
            embed.add_field(
                name="Step 2: Find Your Subscription",
                value="Look for your 'On the Clock Discord Bot' subscription in your billing dashboard",
                inline=False
            )
            
            embed.add_field(
                name="Step 3: Cancel Subscription",
                value="Click 'Cancel subscription' and follow the prompts to confirm cancellation",
                inline=False
            )
            
            embed.add_field(
                name="⚠️ IMPORTANT: Data Deletion Warning",
                value="**When you cancel your subscription, ALL DATA will be permanently deleted:**\n" +
                      "• All timeclock sessions and history\n" +
                      "• Guild settings and configurations\n" +
                      "• Role permissions and authorizations\n" +
                      "• CSV reports and exports\n" +
                      "\n**This action cannot be undone!**",
                inline=False
            )
            
            embed.add_field(
                name="📅 When Does Deletion Happen?",
                value="Data deletion occurs immediately upon subscription cancellation. Your server will be downgraded to Free tier.",
                inline=False
            )
            
            embed.add_field(
                name="💾 Want to Keep Your Data?",
                value="Before canceling, use the **Reports** button to export and save your timeclock data as CSV files.",
                inline=False
            )
            
            embed.add_field(
                name="🔄 Need Help?",
                value="Contact our support if you need assistance with cancellation or have questions about data retention.",
                inline=False
            )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
    except Exception as e:
        await interaction.followup.send(
            f"❌ Error fetching cancellation information: {str(e)}", 
            ephemeral=True
        )

@tree.command(name="subscription_status", description="View current subscription status")
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def subscription_status(interaction: discord.Interaction):
    """Show current subscription tier and details"""
    # Robust defer with proper fallback
    defer_success = await robust_defer(interaction, ephemeral=True)
    if not defer_success and not interaction.response.is_done():
        # If defer failed and interaction isn't done, we can't proceed
        return
    
    if interaction.guild is None:
        await interaction.followup.send("❌ This command must be used in a server.", ephemeral=True)
        return
        
    guild_id = interaction.guild.id
    
    try:
        with db() as conn:
            cursor = conn.execute("""
                SELECT tier, subscription_id, customer_id, expires_at, status
                FROM server_subscriptions 
                WHERE guild_id = %s
            """, (guild_id,))
            result = cursor.fetchone()
            
            if not result:
                tier = "free"
                subscription_id = None
                customer_id = None
                expires_at = None
                status = "active"
            else:
                tier = result['tier']
                subscription_id = result['subscription_id']
                customer_id = result['customer_id']
                expires_at = result['expires_at']
                status = result['status']
        
        tier_colors = {"free": discord.Color.green(), "basic": discord.Color.blue(), "pro": discord.Color.purple()}
        tier_emojis = {"free": "🆓", "basic": "💼", "pro": "⭐"}
        tier_display_names = {"free": "Free Tier", "basic": "Dashboard Premium", "pro": "Pro Retention"}
        
        embed = discord.Embed(
            title=f"{tier_emojis.get(tier, '❓')} Subscription Status",
            color=tier_colors.get(tier, discord.Color.greyple())
        )
        
        embed.add_field(name="Current Plan", value=tier_display_names.get(tier, tier.title()), inline=True)
        embed.add_field(name="Status", value=status.title(), inline=True)
        
        if subscription_id:
            embed.add_field(name="Subscription ID", value=f"`{subscription_id}`", inline=True)
        
        if expires_at:
            embed.add_field(name="Next Billing", value=f"<t:{int(datetime.fromisoformat(expires_at).timestamp())}:f>", inline=True)
        
        # Show plan features
        plan_features = {
            'free': "• Admin-only testing\n• Sample reports\n• No data retention",
            'basic': "• Full team access\n• All admin commands\n• CSV Reports\n• Role management\n• 7-day data retention",
            'pro': "• Everything in Dashboard Premium\n• Extended CSV reports\n• Multiple managers\n• 30-day data retention"
        }
        
        embed.add_field(
            name="Plan Features",
            value=plan_features.get(tier, "Unknown plan"),
            inline=False
        )
        
        # Show upgrade options for lower tiers
        if tier == "free":
            embed.add_field(
                name="Upgrade Options",
                value="Use `/upgrade` to get Dashboard Premium ($5 one-time) or Pro Retention ($5/month)!",
                inline=False
            )
        elif tier == "basic":
            embed.add_field(
                name="Upgrade Option",
                value="Use `/upgrade` to add Pro Retention ($5/month) for 30-day data storage!",
                inline=False
            )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
    except Exception as e:
        await interaction.followup.send(
            f"❌ Error fetching subscription status: {str(e)}", 
            ephemeral=True
        )

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

        # Notify via Log Channel if configured
        log_channel_id = get_guild_setting(guild_id, "log_channel_id")
        if log_channel_id:
            channel = guild.get_channel(int(log_channel_id))
            if channel:
                await channel.send(embed=embed, view=view)
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
            
            # First, try to use the log channel if configured
            log_channel_id = get_guild_setting(guild_id, "log_channel_id")
            if log_channel_id:
                channel_to_use = guild.get_channel(int(log_channel_id))
            
            # If no log channel, try to find system channel
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
    return {'sent_count': sent_count, 'failed_count': failed_count}

# =============================================================================
# OWNER-ONLY SUPER ADMIN COMMANDS (Only visible to bot owner)
# =============================================================================

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
        with db() as conn:
            if target == 'all':
                cursor = conn.execute("""
                    SELECT DISTINCT guild_id FROM bot_guilds WHERE is_present = TRUE
                """)
            elif target == 'paid':
                cursor = conn.execute("""
                    SELECT bg.guild_id FROM bot_guilds bg
                    JOIN server_subscriptions ss ON bg.guild_id = ss.guild_id
                    WHERE bg.is_present = TRUE AND ss.bot_access_paid = TRUE
                """)
            else:  # free
                cursor = conn.execute("""
                    SELECT bg.guild_id FROM bot_guilds bg
                    LEFT JOIN server_subscriptions ss ON bg.guild_id = ss.guild_id
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
        logger.error(f"Broadcast command error: {e}")
        await interaction.followup.send(f"❌ Broadcast failed: {str(e)}", ephemeral=True)

@tree.command(name="owner_grant", description="[OWNER] Grant subscription tier to current server")
@app_commands.describe(tier="Subscription tier to grant")
@app_commands.choices(tier=[
    app_commands.Choice(name="Dashboard Premium (7-day retention)", value="bot_access"),
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
            embed.add_field(name="Grant Type", value="Bot Access ($5)", inline=True)
            embed.add_field(name="Granted By", value="Bot Owner (Manual)", inline=True)
            
            embed.add_field(
                name="Features Unlocked",
                value="• Full team access\n• CSV Reports\n• Role management\n• Dashboard access",
                inline=False
            )
        else:
            # Check current tier
            current_tier = get_server_tier(guild_id)
            
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
    app_commands.Choice(name="Dashboard Premium (7-day retention)", value="bot_access"),
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
            embed.add_field(name="Grant Type", value="Bot Access ($5)", inline=True)
            
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
            current_tier = get_server_tier(guild_id)
            
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
    
    # Check if invoker is admin
    if not interaction.user.guild_permissions.administrator:
        await interaction.followup.send("❌ Only admins can use this.", ephemeral=True)
        return
    
    # Get user's hours for last 7 days
    with db() as conn:
        cursor = conn.execute("""
            SELECT 
                SUM(EXTRACT(EPOCH FROM (COALESCE(clock_out, NOW()) - clock_in))/3600) as total_hours
            FROM time_sessions
            WHERE guild_id = %s AND user_id = %s
            AND clock_in > NOW() - INTERVAL '7 days'
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
    
    # Check if invoker is admin
    if not interaction.user.guild_permissions.administrator:
        await interaction.followup.send("❌ Only admins can use this.", ephemeral=True)
        return
    
    # Find active session and clock out
    with db() as conn:
        cursor = conn.execute("""
            UPDATE time_sessions 
            SET clock_out = NOW()
            WHERE guild_id = %s AND user_id = %s AND clock_out IS NULL
            RETURNING id
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
    
    # Check if invoker is admin
    if not interaction.user.guild_permissions.administrator:
        await interaction.followup.send("❌ Only admins can use this.", ephemeral=True)
        return
    
    # Check if user is already banned
    if is_user_banned(interaction.guild_id, user.id):
        await interaction.followup.send(f"ℹ️ {user.display_name} is already banned from the timeclock.", ephemeral=True)
        return
    
    # Ban user for 24 hours using existing function
    ban_user_24h(interaction.guild_id, user.id, "Banned via admin context menu")
    
    await interaction.followup.send(f"🚫 {user.display_name} has been banned from the timeclock for 24 hours.", ephemeral=True)


# --- Bot HTTP API Server for Dashboard Integration ---
BOT_API_PORT = int(os.getenv("BOT_API_PORT", "8081"))
BOT_API_SECRET = os.getenv("BOT_API_SECRET", secrets.token_hex(32))  # Shared secret for auth

def verify_api_request(request: web.Request) -> bool:
    """Verify request is from authorized dashboard using shared secret"""
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return False
    token = auth_header[7:]  # Remove 'Bearer ' prefix
    return secrets.compare_digest(token, BOT_API_SECRET)

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
        
        print(f"✅ API: Successfully added employee role {role_id} to guild {guild_id}")
        
        return web.json_response({
            'success': True,
            'message': 'Employee role added successfully',
            'role_id': str(role_id)
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
        
        print(f"📥 API: Removing employee role {role_id} from guild {guild_id}")
        
        # Use existing bot function
        remove_employee_role(guild_id, role_id)
        
        print(f"✅ API: Successfully removed employee role {role_id} from guild {guild_id}")
        
        return web.json_response({
            'success': True,
            'message': 'Employee role removed successfully',
            'role_id': str(role_id)
        })
    except Exception as e:
        print(f"❌ Error removing employee role via API (guild {request.match_info.get('guild_id')}): {e}")
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
        
        # Fetch the member from Discord API (not just cache)
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

async def start_bot_api_server():
    """Start aiohttp server for bot API endpoints"""
    app = web.Application()
    app.router.add_post('/api/guild/{guild_id}/admin-roles/add', handle_add_admin_role)
    app.router.add_post('/api/guild/{guild_id}/admin-roles/remove', handle_remove_admin_role)
    app.router.add_post('/api/guild/{guild_id}/employee-roles/add', handle_add_employee_role)
    app.router.add_post('/api/guild/{guild_id}/employee-roles/remove', handle_remove_employee_role)
    app.router.add_get('/api/guild/{guild_id}/user/{user_id}/check-admin', handle_check_user_admin)
    
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
