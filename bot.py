import os
import sqlite3
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

# --- Config / Secrets ---
TOKEN = os.getenv("DISCORD_TOKEN")            # required
DB_PATH = os.getenv("TIMECLOCK_DB", "timeclock.db")
GUILD_ID = os.getenv("GUILD_ID")              # optional but makes commands appear instantly (guild sync)
DEFAULT_TZ = "America/New_York"
HTTP_PORT = int(os.getenv("HEALTH_PORT", "8080"))     # Health check server port (Flask uses 5000)

# --- Bot Owner Configuration ---
BOT_OWNER_ID = 107103438139056128  # Your Discord user ID for super admin access

# --- Discord Data Caching ---
# Simple in-memory cache for Discord API data to reduce rate limiting
DISCORD_CACHE = {
    "guild_roles": {},    # guild_id -> {timestamp, data}
    "guild_members": {},  # guild_id -> {timestamp, data}
}
CACHE_DURATION = 300  # 5 minutes cache duration

# --- Stripe Configuration ---
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")
STRIPE_PRICE_IDS = {
    'basic': 'price_1SAHpL3Jrp0J9Adlfowh5qpr',   # $5/month LIVE
    'pro': 'price_1SAHqH3Jrp0J9AdlFSJpJ32A'      # $10/month LIVE
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


def create_secure_checkout_session(guild_id: int, tier: str) -> str:
    """Create a secure Stripe checkout session with proper validation"""
    if not stripe.api_key:
        raise ValueError("STRIPE_SECRET_KEY not configured")
    
    if tier not in STRIPE_PRICE_IDS:
        raise ValueError(f"Invalid tier: {tier}")
    
    domain = get_domain()
    
    try:
        checkout_session = stripe.checkout.Session.create(
            line_items=[{
                'price': STRIPE_PRICE_IDS[tier],
                'quantity': 1,
            }],
            mode='subscription',
            success_url=f'https://{domain}/success?session_id={{CHECKOUT_SESSION_ID}}',
            cancel_url=f'https://{domain}/cancel',
            metadata={
                'guild_id': str(guild_id),
                'tier': tier
            },
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
            <h3>💰 Subscription Plans</h3>
            <div class="pricing-tier free-tier">
                <strong>Free - Testing Only</strong><br>
                Server admin can test all features • Sample reports only • No data retention
            </div>
            <div class="pricing-tier">
                <strong>Basic - $5/month</strong><br>
                Full team access • Timeclock functions • CSV Reports • 1 week data retention
            </div>
            <div class="pricing-tier pro-tier">
                <strong>Pro - $10/month</strong><br>
                Everything in Basic • Extended CSV Reports • Multiple Managers • 30 days data retention
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
                print(f"🔔 Processing Stripe webhook: {event_type}")
                
                if event_type == 'checkout.session.completed':
                    session = event['data']['object']
                    self.process_checkout_completed(session)
                elif event_type == 'customer.subscription.updated':
                    subscription = event['data']['object']
                    self.handle_subscription_change(subscription)
                elif event_type == 'customer.subscription.deleted':
                    subscription = event['data']['object']
                    self.handle_subscription_cancellation(subscription)
                elif event_type == 'invoice.payment_failed':
                    invoice = event['data']['object']
                    self.handle_payment_failure(invoice)
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
    
    def process_checkout_completed(self, session):
        """Process a completed checkout session"""
        try:
            # Retrieve full session with line items to verify pricing
            full_session = stripe.checkout.Session.retrieve(
                session['id'],
                expand=['line_items']
            )
            
            # Verify the price ID matches our expected tiers
            if full_session.line_items and full_session.line_items.data and full_session.line_items.data[0].price:
                price_id = full_session.line_items.data[0].price.id
                
                tier = None
                for t, pid in STRIPE_PRICE_IDS.items():
                    if pid == price_id:
                        tier = t
                        break
                
                if not tier:
                    print(f"❌ Unknown price ID in checkout: {price_id}")
                    return
                
                guild_id = session.get('metadata', {}).get('guild_id')
                
                if guild_id:
                    subscription_id = session.get('subscription')
                    customer_id = session.get('customer')
                    
                    # Update database with verified subscription
                    set_server_tier(int(guild_id), tier, subscription_id, customer_id)
                    print(f"✅ Subscription activated: Guild {guild_id} -> {tier.title()}")
                else:
                    print("❌ No guild_id found in session metadata")
            else:
                print("❌ No line items found in checkout session")
                
        except Exception as e:
            print(f"❌ Error processing checkout session: {e}")
            import traceback
            traceback.print_exc()
    
    def handle_subscription_cancellation(self, subscription):
        """Handle subscription cancellation events"""
        try:
            # Find guild by subscription_id or customer_id
            subscription_id = subscription.get('id')
            customer_id = subscription.get('customer')
            
            if not subscription_id:
                print("❌ No subscription ID in cancellation event")
                return
                
            with db() as conn:
                cursor = conn.execute("""
                    SELECT guild_id FROM server_subscriptions 
                    WHERE subscription_id = ? OR customer_id = ?
                """, (subscription_id, customer_id))
                result = cursor.fetchone()
                
                if result:
                    guild_id = result[0]
                    
                    # Update subscription status to canceled and downgrade to free
                    conn.execute("""
                        UPDATE server_subscriptions 
                        SET tier = 'free', status = 'canceled'
                        WHERE guild_id = ?
                    """, (guild_id,))
                    
                    # Purge data according to free tier policy (no retention)
                    purge_timeclock_data_only(guild_id)
                    
                    print(f"✅ Subscription cancelled: Guild {guild_id} downgraded to free")
                else:
                    print(f"❌ No guild found for subscription {subscription_id}")
                    
        except Exception as e:
            print(f"❌ Error processing subscription cancellation: {e}")
            import traceback
            traceback.print_exc()
    
    def handle_subscription_change(self, subscription):
        """Handle subscription change events (updates, renewals, etc.)"""
        try:
            subscription_id = subscription.get('id')
            customer_id = subscription.get('customer')
            status = subscription.get('status')
            
            if not subscription_id:
                print("❌ No subscription ID in subscription change event")
                return
                
            with db() as conn:
                cursor = conn.execute("""
                    SELECT guild_id FROM server_subscriptions 
                    WHERE subscription_id = ? OR customer_id = ?
                """, (subscription_id, customer_id))
                result = cursor.fetchone()
                
                if result:
                    guild_id = result[0]
                    
                    # Update subscription status  
                    if status in ['active', 'trialing', 'past_due', 'canceled', 'incomplete', 'incomplete_expired', 'unpaid']:
                        conn.execute("""
                            UPDATE server_subscriptions 
                            SET status = ?
                            WHERE guild_id = ?
                        """, (status, guild_id))
                        
                        # Only downgrade and purge for truly inactive subscriptions
                        if status in ['canceled', 'incomplete_expired', 'unpaid']:
                            conn.execute("""
                                UPDATE server_subscriptions 
                                SET tier = 'free'
                                WHERE guild_id = ?
                            """, (guild_id,))
                            # Purge data according to free tier policy
                            purge_timeclock_data_only(guild_id)
                        
                        print(f"✅ Subscription updated: Guild {guild_id} status -> {status}")
                    else:
                        print(f"⚠️ Unknown subscription status: {status}")
                else:
                    print(f"❌ No guild found for subscription {subscription_id}")
                    
        except Exception as e:
            print(f"❌ Error processing subscription change: {e}")
            import traceback
            traceback.print_exc()
    
    def handle_payment_failure(self, invoice):
        """Handle payment failure events"""
        try:
            customer_id = invoice.get('customer')
            subscription_id = invoice.get('subscription')
            
            if not customer_id and not subscription_id:
                print("❌ No customer or subscription ID in payment failure event")
                return
                
            with db() as conn:
                cursor = conn.execute("""
                    SELECT guild_id FROM server_subscriptions 
                    WHERE subscription_id = ? OR customer_id = ?
                """, (subscription_id, customer_id))
                result = cursor.fetchone()
                
                if result:
                    guild_id = result[0]
                    
                    # Update subscription status to past_due
                    conn.execute("""
                        UPDATE server_subscriptions 
                        SET status = 'past_due'
                        WHERE guild_id = ?
                    """, (guild_id,))
                    
                    print(f"⚠️ Payment failed: Guild {guild_id} marked as past_due")
                    
                    # Note: We don't immediately downgrade on payment failure
                    # Stripe usually allows a grace period before cancellation
                    
                else:
                    print(f"❌ No guild found for customer {customer_id} or subscription {subscription_id}")
                    
        except Exception as e:
            print(f"❌ Error processing payment failure: {e}")
            import traceback
            traceback.print_exc()
    
    def purge_all_guild_data(self, guild_id: int):
        """Purge all data for a guild when subscription lapses"""
        try:
            with db() as conn:
                # Set timeout for database operations
                conn.execute("PRAGMA busy_timeout = 5000")
                
                # Delete all sessions data
                sessions_cursor = conn.execute("DELETE FROM sessions WHERE guild_id = ?", (guild_id,))
                sessions_deleted = sessions_cursor.rowcount
                
                # Delete guild settings
                settings_cursor = conn.execute("DELETE FROM guild_settings WHERE guild_id = ?", (guild_id,))
                settings_deleted = settings_cursor.rowcount
                
                # Delete authorized roles
                auth_roles_cursor = conn.execute("DELETE FROM authorized_roles WHERE guild_id = ?", (guild_id,))
                auth_roles_deleted = auth_roles_cursor.rowcount
                
                # Delete admin roles
                admin_roles_cursor = conn.execute("DELETE FROM admin_roles WHERE guild_id = ?", (guild_id,))
                admin_roles_deleted = admin_roles_cursor.rowcount
                
                # Delete clock roles
                employee_roles_cursor = conn.execute("DELETE FROM employee_roles WHERE guild_id = ?", (guild_id,))
                employee_roles_deleted = employee_roles_cursor.rowcount
                
                # Reset subscription to free tier (don't delete subscription record)
                conn.execute("""
                    UPDATE server_subscriptions 
                    SET tier = 'free', subscription_id = NULL, customer_id = NULL, 
                        expires_at = NULL, status = 'cancelled'
                    WHERE guild_id = ?
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
                recipient_id, recipient_type, discord_user_id, email_address, created_at = recipient_row
                
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
                    SELECT COUNT(*) FROM sessions 
                    WHERE guild_id = ? AND clock_out IS NULL
                """, (guild_id,))
                clocked_in_count = cursor.fetchone()[0]
                
            # Get admin and employee roles
            admin_roles = []
            employee_roles = []
            
            with db() as conn:
                # Get admin roles
                cursor = conn.execute("SELECT role_id FROM admin_roles WHERE guild_id = ?", (guild_id,))
                admin_role_ids = [row[0] for row in cursor.fetchall()]
                
                # Get employee roles  
                cursor = conn.execute("SELECT role_id FROM employee_roles WHERE guild_id = ?", (guild_id,))
                employee_role_ids = [row[0] for row in cursor.fetchall()]
                
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


def purge_guild_data_for_testing(guild_id: int):
    """Standalone function to purge guild data for testing purposes"""
    try:
        with db() as conn:
            # Set timeout for database operations
            conn.execute("PRAGMA busy_timeout = 5000")
            
            # Delete all sessions data
            sessions_cursor = conn.execute("DELETE FROM sessions WHERE guild_id = ?", (guild_id,))
            sessions_deleted = sessions_cursor.rowcount
            
            # Delete guild settings
            settings_cursor = conn.execute("DELETE FROM guild_settings WHERE guild_id = ?", (guild_id,))
            settings_deleted = settings_cursor.rowcount
            
            # Delete authorized roles
            auth_roles_cursor = conn.execute("DELETE FROM authorized_roles WHERE guild_id = ?", (guild_id,))
            auth_roles_deleted = auth_roles_cursor.rowcount
            
            # Delete admin roles
            admin_roles_cursor = conn.execute("DELETE FROM admin_roles WHERE guild_id = ?", (guild_id,))
            admin_roles_deleted = admin_roles_cursor.rowcount
            
            # Delete clock roles
            employee_roles_cursor = conn.execute("DELETE FROM employee_roles WHERE guild_id = ?", (guild_id,))
            employee_roles_deleted = employee_roles_cursor.rowcount
            
            # Reset subscription to free tier (don't delete subscription record)
            conn.execute("""
                UPDATE server_subscriptions 
                SET tier = 'free', subscription_id = NULL, customer_id = NULL, 
                    expires_at = NULL, status = 'cancelled'
                WHERE guild_id = ?
            """, (guild_id,))
            
            print(f"🗑️ Data purged for Guild {guild_id}: {sessions_deleted} sessions, {settings_deleted} settings, {auth_roles_deleted} auth roles, {admin_roles_deleted} admin roles, {employee_roles_deleted} clock roles")
            return sessions_deleted + settings_deleted + auth_roles_deleted + admin_roles_deleted + employee_roles_deleted
            
    except Exception as e:
        print(f"❌ Error purging guild data for {guild_id}: {e}")
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
                    WHERE subscription_id = ? OR customer_id = ?
                """, (subscription['id'], subscription['customer']))
                result = cursor.fetchone()
                
                if result:
                    guild_id = result[0]
                    status = subscription['status']
                    current_period_end = subscription['current_period_end']
                    
                    # Update subscription status
                    conn.execute("""
                        UPDATE server_subscriptions 
                        SET status = ?, expires_at = ?
                        WHERE guild_id = ?
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
                    WHERE customer_id = ?
                """, (customer_id,))
                result = cursor.fetchone()
                
                if result:
                    guild_id = result[0]
                    
                    # Mark as past_due but don't downgrade immediately
                    conn.execute("""
                        UPDATE server_subscriptions 
                        SET status = 'past_due'
                        WHERE guild_id = ?
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

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")  # Write-Ahead Logging for better concurrency
    conn.execute("PRAGMA busy_timeout = 5000")  # 5 second timeout globally
    conn.execute("PRAGMA synchronous = NORMAL")  # Balance between safety and performance
    return conn

def run_migrations():
    """Run database migrations with exclusive locking before any other operations"""
    import time
    import random
    
    max_retries = 5
    for attempt in range(max_retries):
        try:
            with db() as conn:
                # Begin exclusive transaction
                conn.execute("BEGIN IMMEDIATE")
                
                # Check if customer_id column exists
                cursor = conn.execute("PRAGMA table_info(server_subscriptions)")
                columns = {row[1] for row in cursor.fetchall()}
                
                if 'customer_id' not in columns:
                    print("🔧 Adding missing customer_id column to server_subscriptions table...")
                    conn.execute("ALTER TABLE server_subscriptions ADD COLUMN customer_id TEXT")
                    print("✅ Migration completed: customer_id column added")
                else:
                    print("✅ Migration check: customer_id column already exists")
                
                conn.commit()
                return True
                
        except sqlite3.OperationalError as e:
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
    with db() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS guild_settings (
            guild_id INTEGER PRIMARY KEY,
            recipient_user_id INTEGER,
            button_channel_id INTEGER,
            button_message_id INTEGER,
            timezone TEXT DEFAULT 'America/New_York',
            name_display_mode TEXT DEFAULT 'username'
        )
        """)
        
        # Add name_display_mode column if it doesn't exist (for existing databases)
        try:
            conn.execute("ALTER TABLE guild_settings ADD COLUMN name_display_mode TEXT DEFAULT 'username'")
        except:
            pass  # Column already exists
        
        # Migration 1: Convert role_id from INTEGER to TEXT for Discord snowflakes
        # Run BEFORE table creation to migrate existing data
        try:
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='admin_roles'")
            if cursor.fetchone():
                # Table exists, check if it needs migration
                cursor = conn.execute("PRAGMA table_info(admin_roles)")
                columns = cursor.fetchall()
                role_id_col = next((col for col in columns if col[1] == 'role_id'), None)
                if role_id_col and 'INTEGER' in role_id_col[2].upper():
                    print("🔧 Migrating admin_roles: Converting role_id from INTEGER to TEXT...")
                    conn.execute("""
                    CREATE TABLE admin_roles_new (
                        guild_id TEXT,
                        role_id TEXT,
                        PRIMARY KEY (guild_id, role_id)
                    )
                    """)
                    conn.execute("""
                    INSERT INTO admin_roles_new (guild_id, role_id)
                    SELECT CAST(guild_id AS TEXT), CAST(role_id AS TEXT) FROM admin_roles
                    """)
                    conn.execute("DROP TABLE admin_roles")
                    conn.execute("ALTER TABLE admin_roles_new RENAME TO admin_roles")
                    print("✅ admin_roles migration completed")
        except Exception as e:
            print(f"⚠️ admin_roles migration skipped or failed: {e}")
        
        try:
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='employee_roles'")
            if cursor.fetchone():
                # Table exists, check if it needs migration
                cursor = conn.execute("PRAGMA table_info(employee_roles)")
                columns = cursor.fetchall()
                role_id_col = next((col for col in columns if col[1] == 'role_id'), None)
                if role_id_col and 'INTEGER' in role_id_col[2].upper():
                    print("🔧 Migrating employee_roles: Converting role_id from INTEGER to TEXT...")
                    conn.execute("""
                    CREATE TABLE employee_roles_new (
                        guild_id TEXT,
                        role_id TEXT,
                        PRIMARY KEY (guild_id, role_id)
                    )
                    """)
                    conn.execute("""
                    INSERT INTO employee_roles_new (guild_id, role_id)
                    SELECT CAST(guild_id AS TEXT), CAST(role_id AS TEXT) FROM employee_roles
                    """)
                    conn.execute("DROP TABLE employee_roles")
                    conn.execute("ALTER TABLE employee_roles_new RENAME TO employee_roles")
                    print("✅ employee_roles migration completed")
        except Exception as e:
            print(f"⚠️ employee_roles migration skipped or failed: {e}")
        
        # Migration 2: Convert main_admin_role_id from INTEGER to TEXT
        try:
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='guild_settings'")
            if cursor.fetchone():
                cursor = conn.execute("PRAGMA table_info(guild_settings)")
                columns = cursor.fetchall()
                main_admin_col = next((col for col in columns if col[1] == 'main_admin_role_id'), None)
                if main_admin_col and 'INTEGER' in main_admin_col[2].upper():
                    print("🔧 Migrating guild_settings: Converting main_admin_role_id from INTEGER to TEXT...")
                    conn.execute("ALTER TABLE guild_settings ADD COLUMN main_admin_role_id_new TEXT")
                    conn.execute("UPDATE guild_settings SET main_admin_role_id_new = CAST(main_admin_role_id AS TEXT) WHERE main_admin_role_id IS NOT NULL")
                    conn.execute("""
                    CREATE TABLE guild_settings_new (
                        guild_id INTEGER PRIMARY KEY,
                        recipient_user_id INTEGER,
                        button_channel_id INTEGER,
                        button_message_id INTEGER,
                        timezone TEXT DEFAULT 'America/New_York',
                        name_display_mode TEXT DEFAULT 'username',
                        main_admin_role_id TEXT
                    )
                    """)
                    conn.execute("""
                    INSERT INTO guild_settings_new 
                    SELECT guild_id, recipient_user_id, button_channel_id, button_message_id, 
                           timezone, name_display_mode, main_admin_role_id_new 
                    FROM guild_settings
                    """)
                    conn.execute("DROP TABLE guild_settings")
                    conn.execute("ALTER TABLE guild_settings_new RENAME TO guild_settings")
                    print("✅ guild_settings.main_admin_role_id migration completed")
        except Exception as e:
            print(f"⚠️ guild_settings migration skipped or failed: {e}")
        
        # Add main_admin_role_id column if it doesn't exist (for main admin role feature)
        try:
            conn.execute("ALTER TABLE guild_settings ADD COLUMN main_admin_role_id TEXT")
        except:
            pass  # Column already exists
        
        # Now create tables if they don't exist (with correct TEXT types)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS authorized_roles (
            guild_id TEXT,
            role_id TEXT,
            PRIMARY KEY (guild_id, role_id)
        )
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS admin_roles (
            guild_id TEXT,
            role_id TEXT,
            PRIMARY KEY (guild_id, role_id)
        )
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS employee_roles (
            guild_id TEXT,
            role_id TEXT,
            PRIMARY KEY (guild_id, role_id)
        )
        """)
        
        try:
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='clock_roles'")
            if cursor.fetchone():
                conn.execute("INSERT OR IGNORE INTO employee_roles (guild_id, role_id) SELECT CAST(guild_id AS TEXT), CAST(role_id AS TEXT) FROM clock_roles")
                conn.execute("DROP TABLE clock_roles")
        except:
            pass
        
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
        
        # Add indexes for performance
        conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_sessions_guild_clock_out 
        ON sessions(guild_id, clock_out)
        """)
        conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_sessions_guild_user_clock_out 
        ON sessions(guild_id, user_id, clock_out)
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS server_subscriptions (
            guild_id INTEGER PRIMARY KEY,
            tier TEXT NOT NULL DEFAULT 'free',
            subscription_id TEXT,
            customer_id TEXT,
            expires_at TEXT,
            status TEXT DEFAULT 'active'
        )
        """)
        
        # Recipients table for multiple report recipients per guild
        conn.execute("""
        CREATE TABLE IF NOT EXISTS report_recipients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            guild_id INTEGER NOT NULL,
            recipient_type TEXT NOT NULL CHECK(recipient_type IN ('discord', 'email')),
            recipient_id TEXT,  -- Discord user ID for 'discord' type
            email_address TEXT, -- Email address for 'email' type
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (guild_id) REFERENCES guild_settings (guild_id),
            UNIQUE(guild_id, recipient_type, recipient_id),
            UNIQUE(guild_id, recipient_type, email_address)
        )
        """)
        
        # Index for performance
        conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_report_recipients_guild 
        ON report_recipients(guild_id)
        """)
        
        # Bot guilds table to track which servers the bot is connected to
        conn.execute("""
        CREATE TABLE IF NOT EXISTS bot_guilds (
            guild_id TEXT PRIMARY KEY,
            guild_name TEXT,
            joined_at TEXT NOT NULL
        )
        """)



# --- Subscription/Tier Management ---
def get_server_tier(guild_id: int) -> str:
    """Get subscription tier for a server (free/basic/pro)"""
    with db() as conn:
        cursor = conn.execute(
            "SELECT tier, status FROM server_subscriptions WHERE guild_id = ?",
            (guild_id,)
        )
        result = cursor.fetchone()
        if not result:
            return "free"
        
        tier, status = result
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
                INSERT OR REPLACE INTO server_subscriptions 
                (guild_id, tier, subscription_id, expires_at, status, customer_id) 
                VALUES (?, ?, ?, NULL, 'active', ?)
            """, (guild_id, tier, subscription_id, customer_id))
        elif subscription_id:
            # Subscription without customer (legacy)
            conn.execute("""
                INSERT OR REPLACE INTO server_subscriptions 
                (guild_id, tier, subscription_id, expires_at, status) 
                VALUES (?, ?, ?, NULL, 'active')
            """, (guild_id, tier, subscription_id))
        else:
            # Free tier or manual assignment
            conn.execute("""
                INSERT OR REPLACE INTO server_subscriptions 
                (guild_id, tier, expires_at, status) 
                VALUES (?, ?, NULL, 'active')
            """, (guild_id, tier))

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
    """Get data retention days based on subscription tier"""
    tier = get_server_tier(guild_id)
    retention_policy = {
        'free': 0,       # No retention - test only
        'basic': 7,      # 1 week  
        'pro': 30        # 1 month (30 days)
    }
    return retention_policy.get(tier, 0)

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
                        WHERE guild_id = ? AND clock_out IS NOT NULL AND clock_out < ?
                    """, (guild_id, cutoff_date.isoformat()))
                    deleted_count = cursor.rowcount
                else:
                    # Clean up all guilds based on their individual retention policies
                    guilds_cursor = conn.execute("SELECT DISTINCT guild_id FROM sessions")
                    guild_ids = [row[0] for row in guilds_cursor.fetchall()]
                    
                    for guild_id in guild_ids:
                        if guild_id is None:
                            continue  # Skip invalid guild IDs
                        retention_days = get_retention_days(guild_id)
                        cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)
                        
                        cursor = conn.execute("""
                            DELETE FROM sessions 
                            WHERE guild_id = ? AND clock_out IS NOT NULL AND clock_out < ?
                        """, (guild_id, cutoff_date.isoformat()))
                        deleted_count += cursor.rowcount
                
                # Optimize database after cleanup (only if we deleted something)
                if deleted_count > 0:
                    conn.execute("PRAGMA wal_checkpoint")
                    # Skip VACUUM in background cleanup to avoid long locks
                    
            # Success - exit retry loop
            break
            
        except sqlite3.OperationalError as e:
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
                # Set timeout for database operations
                conn.execute("PRAGMA busy_timeout = 5000")
                
                # Delete all sessions for the specific user in this guild
                cursor = conn.execute("""
                    DELETE FROM sessions 
                    WHERE guild_id = ? AND user_id = ?
                """, (guild_id, user_id))
                deleted_count = cursor.rowcount
                
                # Optimize database after cleanup (only if we deleted something)
                if deleted_count > 0:
                    conn.execute("PRAGMA wal_checkpoint")
                    
            # Success - exit retry loop
            break
            
        except sqlite3.OperationalError as e:
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
        'recipient_user_id': "SELECT recipient_user_id FROM guild_settings WHERE guild_id=?",
        'timezone': "SELECT timezone FROM guild_settings WHERE guild_id=?",
        'name_display_mode': "SELECT name_display_mode FROM guild_settings WHERE guild_id=?",
        'main_admin_role_id': "SELECT main_admin_role_id FROM guild_settings WHERE guild_id=?"
    }
    
    if key not in column_queries:
        raise ValueError(f"Invalid column name: {key}")
    
    with db() as conn:
        cur = conn.execute(column_queries[key], (guild_id,))
        row = cur.fetchone()
        return row[0] if row and row[0] is not None else default

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
                VALUES (?, ?, ?, ?)
            """, (guild_id, recipient_type, recipient_id, email_address))
            return True
    except sqlite3.IntegrityError:
        # Recipient already exists
        return False

def remove_report_recipient(guild_id: int, recipient_type: str, recipient_id: Optional[str] = None, email_address: Optional[str] = None):
    """Remove a report recipient for a guild"""
    with db() as conn:
        if recipient_type == 'discord':
            conn.execute("""
                DELETE FROM report_recipients 
                WHERE guild_id = ? AND recipient_type = ? AND recipient_id = ?
            """, (guild_id, recipient_type, recipient_id))
        else:  # email
            conn.execute("""
                DELETE FROM report_recipients 
                WHERE guild_id = ? AND recipient_type = ? AND email_address = ?
            """, (guild_id, recipient_type, email_address))

def get_report_recipients(guild_id: int, recipient_type: Optional[str] = None):
    """Get all report recipients for a guild, optionally filtered by type"""
    with db() as conn:
        if recipient_type:
            cursor = conn.execute("""
                SELECT id, recipient_type, recipient_id, email_address, created_at
                FROM report_recipients 
                WHERE guild_id = ? AND recipient_type = ?
                ORDER BY created_at ASC
            """, (guild_id, recipient_type))
        else:
            cursor = conn.execute("""
                SELECT id, recipient_type, recipient_id, email_address, created_at
                FROM report_recipients 
                WHERE guild_id = ?
                ORDER BY recipient_type, created_at ASC
            """, (guild_id,))
        
        return cursor.fetchall()

async def send_timeclock_notifications(guild_id: int, interaction: discord.Interaction, start_dt: datetime, end_dt: datetime, elapsed: int, tz_name: str):
    """Send timeclock notifications to all configured recipients"""
    # Get all recipients for this guild
    all_recipients = get_report_recipients(guild_id)
    
    # Also check for legacy single recipient
    legacy_recipient_id = get_guild_setting(guild_id, "recipient_user_id")
    
    # Prepare the notification embed
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
    
    # Send to new recipients system
    for recipient_row in all_recipients:
        recipient_id, recipient_type, discord_user_id, email_address, created_at = recipient_row
        
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
        
        elif recipient_type == 'email' and email_address:
            try:
                # Send email notification
                guild_name = interaction.guild.name if interaction.guild else "Unknown Server"
                # In guild interactions, user is always a Member
                user_name = get_user_display_name(interaction.user, guild_id)  # type: ignore[arg-type]
                
                # Create plain text email content
                email_text = f"""
Timeclock Entry Notification

Employee: {user_name} (ID: {interaction.user.id})
Server: {guild_name}

Clock In: {fmt(start_dt, tz_name)}
Clock Out: {fmt(end_dt, tz_name)}
Total Duration: {human_duration(elapsed)}

Timestamp: {end_dt.strftime('%Y-%m-%d %H:%M:%S')} UTC
""".strip()
                
                # Send email using our email utility
                from email_utils import send_email
                result = await send_email(
                    to=email_address,
                    subject=f"Timeclock Entry - {user_name} ({guild_name})",
                    text=email_text
                )
                
                notification_sent = True
                print(f"✅ Email notification sent to {email_address}")
                
            except Exception as e:
                errors.append(f"Failed to send email to {email_address}: {str(e)}")
                print(f"❌ Email notification failed for {email_address}: {str(e)}")
    
    # Fallback to legacy recipient if no new recipients configured
    if not all_recipients and legacy_recipient_id:
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
        'recipient_user_id': "UPDATE guild_settings SET recipient_user_id=? WHERE guild_id=?",
        'timezone': "UPDATE guild_settings SET timezone=? WHERE guild_id=?",
        'name_display_mode': "UPDATE guild_settings SET name_display_mode=? WHERE guild_id=?",
        'main_admin_role_id': "UPDATE guild_settings SET main_admin_role_id=? WHERE guild_id=?"
    }
    
    if key not in update_queries:
        raise ValueError(f"Invalid column name: {key}")
    
    with db() as conn:
        conn.execute("INSERT OR IGNORE INTO guild_settings(guild_id) VALUES (?)", (guild_id,))
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



def add_admin_role(guild_id: int, role_id: int):
    """Add a role as admin for Reports/Upgrade button access."""
    with db() as conn:
        # Convert IDs to strings for database storage (Discord snowflakes)
        conn.execute("INSERT OR IGNORE INTO admin_roles (guild_id, role_id) VALUES (?, ?)", 
                     (str(guild_id), str(role_id)))

def remove_admin_role(guild_id: int, role_id: int):
    """Remove a role from admin Reports/Upgrade button access."""
    with db() as conn:
        # Convert IDs to strings for database storage (Discord snowflakes)
        conn.execute("DELETE FROM admin_roles WHERE guild_id=? AND role_id=?", 
                     (str(guild_id), str(role_id)))

def get_admin_roles(guild_id: int):
    """Get all admin role IDs for a guild. Returns integers for Discord.py compatibility."""
    with db() as conn:
        cur = conn.execute("SELECT role_id FROM admin_roles WHERE guild_id=?", (str(guild_id),))
        # Convert back to int for Discord.py (role.id is an int)
        return [int(row[0]) for row in cur.fetchall()]

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
        conn.execute("INSERT OR IGNORE INTO employee_roles (guild_id, role_id) VALUES (?, ?)", 
                     (str(guild_id), str(role_id)))

def remove_employee_role(guild_id: int, role_id: int):
    """Remove a role from timeclock functions access."""
    with db() as conn:
        # Convert IDs to strings for database storage (Discord snowflakes)
        conn.execute("DELETE FROM employee_roles WHERE guild_id=? AND role_id=?", 
                     (str(guild_id), str(role_id)))

def get_employee_roles(guild_id: int):
    """Get all clock role IDs for a guild. Returns integers for Discord.py compatibility."""
    with db() as conn:
        cur = conn.execute("SELECT role_id FROM employee_roles WHERE guild_id=?", (str(guild_id),))
        # Convert back to int for Discord.py (role.id is an int)
        return [int(row[0]) for row in cur.fetchall()]

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

async def generate_csv_report(bot, sessions_data, guild_id, guild_tz="America/New_York"):
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
        # Fetch Discord user to get display name based on guild preference
        try:
            discord_user = await bot.fetch_user(user_id)
            user_display_name = get_user_display_name(discord_user, guild_id)
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
            conn.execute("PRAGMA busy_timeout = 5000")
            
            # Delete all sessions data only
            sessions_cursor = conn.execute("DELETE FROM sessions WHERE guild_id = ?", (guild_id,))
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

# --- Discord bot ---
intents = discord.Intents.default()
# Note: members intent requires privileged intent in Discord Developer Portal
# For now, we'll use a fallback approach that works with default intents
bot = commands.Bot(command_prefix="!", intents=intents)
tree = bot.tree

# Register persistent views at startup to handle interactions after bot restart
async def setup_hook():
    """Setup hook to register persistent views when bot starts"""
    print("🔧 Registering persistent views...")
    
    # Register ONLY empty TimeClockView for handling interactions
    # This prevents old buttons from appearing in channels
    bot.add_view(TimeClockView())
    print("✅ TimeClockView registered")
    
    print("✅ Persistent view setup complete - ephemeral interface mode")

bot.setup_hook = setup_hook

class TimeClockView(discord.ui.View):
    def __init__(self, guild_id: Optional[int] = None):
        super().__init__(timeout=None)  # persistent view
        self.guild_id = guild_id
        
        # If guild_id is provided, build conditional view
        if guild_id:
            self._build_conditional_view(guild_id)

    def _build_conditional_view(self, guild_id: int):
        """Build view with conditional buttons based on server tier"""
        server_tier = get_server_tier(guild_id)
        
        # Add core buttons (row 0) - Clock In first, On the Clock last
        clock_in_btn = discord.ui.Button(
            label="Clock In", 
            style=discord.ButtonStyle.success, 
            custom_id="timeclock:clock_in", 
            row=0
        )
        clock_in_btn.callback = self.clock_in
        self.add_item(clock_in_btn)
        
        clock_out_btn = discord.ui.Button(
            label="Clock Out", 
            style=discord.ButtonStyle.danger, 
            custom_id="timeclock:clock_out", 
            row=0
        )
        clock_out_btn.callback = self.clock_out
        self.add_item(clock_out_btn)
        
        help_btn = discord.ui.Button(
            label="Help", 
            style=discord.ButtonStyle.primary, 
            custom_id="timeclock:help", 
            row=0
        )
        help_btn.callback = self.show_help
        self.add_item(help_btn)
        
        on_clock_btn = discord.ui.Button(
            label="On the Clock", 
            style=discord.ButtonStyle.secondary, 
            custom_id="timeclock:onclock", 
            row=0
        )
        on_clock_btn.callback = self.on_the_clock
        self.add_item(on_clock_btn)
        
        # Conditional second row buttons
        if server_tier == "free":
            # Add upgrade button for free servers
            upgrade_btn = discord.ui.Button(
                label="Upgrade", 
                style=discord.ButtonStyle.secondary, 
                custom_id="timeclock:upgrade", 
                emoji="🚀",
                row=1
            )
            upgrade_btn.callback = self.show_upgrade
            self.add_item(upgrade_btn)
        else:
            # Add reports button for paid servers
            reports_btn = discord.ui.Button(
                label="Reports", 
                style=discord.ButtonStyle.success, 
                custom_id="timeclock:reports", 
                row=1
            )
            reports_btn.callback = self.generate_reports
            self.add_item(reports_btn)

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
                    WHERE guild_id = ? AND clock_out IS NULL
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
            sorted_sessions = sorted(active_sessions, key=lambda x: x[1])
            
            user_details = []
            for i, (user_id, clock_in_iso) in enumerate(sorted_sessions, 1):
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
                    clock_in_utc = datetime.fromisoformat(clock_in_iso.replace('Z', '+00:00'))
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
                            WHERE guild_id = ? AND user_id = ? 
                            AND clock_in >= ? AND clock_in <= ?
                        """, (guild_id, user_id, day_start_utc, day_end_utc))
                        day_sessions = cursor.fetchall()
                    
                    # Calculate total day seconds
                    total_day_seconds = 0
                    for session_in, session_out in day_sessions:
                        if session_out:  # Completed session
                            start = datetime.fromisoformat(session_in.replace('Z', '+00:00'))
                            end = datetime.fromisoformat(session_out.replace('Z', '+00:00'))
                            total_day_seconds += (end - start).total_seconds()
                        else:  # Current active session
                            start = datetime.fromisoformat(session_in.replace('Z', '+00:00'))
                            total_day_seconds += (now_utc - start).total_seconds()
                    
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
            
            if get_active_session(guild_id, user_id):
                await interaction.followup.send("You're already clocked in.", ephemeral=True)
                return
                
            start_session(guild_id, user_id, now_utc().isoformat())
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
            
            active = get_active_session(guild_id, user_id)
            if not active:
                await interaction.followup.send("You don't have an active session.", ephemeral=True)
                return

            session_id, clock_in_iso = active
            start_dt = datetime.fromisoformat(clock_in_iso)
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
                    "`/upgrade` - Upgrade your server to Basic or Pro plan\n"
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
                    "💡 **Upgrade Benefits:** Basic ($5/mo) unlocks full team access & real CSV reports"
                )
            elif server_tier == "basic":
                tier_info += (
                    "💙 **Basic Tier:** Full team access • Real CSV reports • 7-day data retention\n"
                    "💡 **Pro Benefits:** 30-day retention • Multiple manager notifications • Extended features"
                )
            else:  # pro tier
                tier_info += "💜 **Pro Tier:** All features unlocked • 30-day retention • Multiple managers • Priority support"
            
            embed.add_field(
                name="🔘 Interactive Timeclock Buttons",
                value=(
                    "🟢 **Clock In** - Start tracking your time\n"
                    "🔴 **Clock Out** - Stop tracking and log your shift\n"
                    "📊 **Reports** - Generate timesheet reports (admin access)\n"
                    "⬆️ **Upgrade** - Upgrade to Basic/Pro plans\n" + 
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
                    f"🎯 This is sample data. Upgrade to Basic ($5/month) or Pro ($10/month) for real reports!\n"
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
            for user_id, clock_in_iso, clock_out_iso, duration_seconds in sessions_data:
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
        server_tier = get_server_tier(guild_id)
        
        # Only show for free tier
        if server_tier != "free":
            await send_reply(interaction, "This server already has a subscription!", ephemeral=True)
            return
        
        embed = discord.Embed(
            title="🚀 Upgrade Your Server",
            description="Choose a plan that fits your team's needs:",
            color=discord.Color.orange()
        )
        
        embed.add_field(
            name="💼 Basic Plan - $5/month",
            value="• Full team access to timeclock\n"
                  "• All admin commands\n"
                  "• CSV Reports\n"
                  "• Role management\n"
                  "• 7 days data retention",
            inline=True
        )
        
        embed.add_field(
            name="⭐ Pro Plan - $10/month",
            value="• Everything in Basic\n"
                  "• Extended CSV reports\n"
                  "• Multiple manager notifications\n"
                  "• 30 days data retention\n"
                  "• Priority support",
            inline=True
        )
        
        embed.add_field(
            name="🔗 How to Upgrade",
            value="Use `/upgrade basic` or `/upgrade pro` commands to get started with secure Stripe checkout!",
            inline=False
        )
        
        await send_reply(interaction, embed=embed, ephemeral=True)


@bot.event
async def on_ready():
    # Persistent views are now registered in setup_hook (both new and legacy views)
    # This ensures backward compatibility with existing posted messages
    
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
            for guild in bot.guilds:
                conn.execute("""
                    INSERT OR REPLACE INTO bot_guilds (guild_id, guild_name, joined_at)
                    VALUES (?, ?, datetime('now'))
                """, (str(guild.id), guild.name))
        print(f"✅ Updated bot_guilds table with {len(bot.guilds)} guilds")
    except Exception as e:
        print(f"❌ Error updating bot_guilds table: {e}")

@bot.event
async def on_guild_join(guild):
    """Send welcome message with setup instructions when bot joins a new server"""
    print(f"🎉 Bot joined new server: {guild.name} (ID: {guild.id})")
    
    # Try to find the person who added the bot (guild owner as fallback)
    inviter = guild.owner
    
    # Create a fancy welcome embed
    embed = discord.Embed(
        title="⏰ Welcome to On the Clock!",
        description="Thanks for adding our professional Discord timeclock bot to your server!",
        color=discord.Color.blurple()
    )
    
    # Add setup instructions
    embed.add_field(
        name="🚀 Quick Setup",
        value=(
            "1️⃣ Run `/setup_timeclock` in your desired channel\n"
            "2️⃣ Configure role access with `/add_employee_role @role`\n"
            "3️⃣ Set admin roles with `/add_admin_role @role` (optional)\n"
            "4️⃣ Your team can start tracking time immediately!"
        ),
        inline=False
    )
    
    # Add access control explanation
    embed.add_field(
        name="🔐 Access Control",
        value=(
            "**Timeclock functions:**\n"
            "• Free tier: Admins only\n"
            "• Basic/Pro tier: Any role you specify\n\n"
            "**Reports/Upgrade buttons:**\n"
            "• Discord Administrators\n"
            "• Custom admin roles (via `/add_admin_role`)"
        ),
        inline=False
    )
    
    # Add subscription tier information
    embed.add_field(
        name="💼 Subscription Tiers",
        value=(
            "**🆓 Free (Current):** Admin-only access, sample reports\n"
            "**💼 Basic ($5/month):** Full team access, 7-day reports\n"
            "**⭐ Pro ($10/month):** Everything + 30-day reports\n\n"
            "Use `/upgrade basic` or `/upgrade pro` to unlock full features!"
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
    embed.set_footer(
        text="Need help? Contact support or check our documentation",
        icon_url=bot.user.avatar.url if bot.user and bot.user.avatar else None
    )
    
    # Try to send the welcome message to the server owner
    try:
        if inviter:
            await inviter.send(embed=embed)
            print(f"✅ Sent welcome message to {inviter} in {guild.name}")
        else:
            print(f"⚠️ Could not find owner for {guild.name}")
    except discord.Forbidden:
        print(f"❌ Could not DM owner of {guild.name} - DMs disabled")
        # Try to send to system channel or first text channel as fallback
        target_channel = guild.system_channel
        if not target_channel:
            # Find first text channel the bot can send to
            for channel in guild.text_channels:
                if channel.permissions_for(guild.me).send_messages:
                    target_channel = channel
                    break
        
        if target_channel:
            try:
                await target_channel.send(f"👋 {inviter.mention}" if inviter else "👋 Hello!", embed=embed)
                print(f"✅ Sent welcome message to #{target_channel.name} in {guild.name}")
            except Exception as e:
                print(f"❌ Could not send welcome message anywhere in {guild.name}: {e}")
    except Exception as e:
        print(f"❌ Error sending welcome message for {guild.name}: {e}")
    
    # Add guild to bot_guilds table
    try:
        with db() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO bot_guilds (guild_id, guild_name, joined_at)
                VALUES (?, ?, datetime('now'))
            """, (str(guild.id), guild.name))
        print(f"✅ Added {guild.name} to bot_guilds table")
    except Exception as e:
        print(f"❌ Error adding guild to bot_guilds table: {e}")

@bot.event
async def on_guild_remove(guild):
    """Remove guild from bot_guilds table when bot leaves a server"""
    print(f"👋 Bot removed from server: {guild.name} (ID: {guild.id})")
    
    try:
        with db() as conn:
            conn.execute("DELETE FROM bot_guilds WHERE guild_id = ?", (str(guild.id),))
        print(f"✅ Removed {guild.name} from bot_guilds table")
    except Exception as e:
        print(f"❌ Error removing guild from bot_guilds table: {e}")

@tree.command(name="setup", description="View timeclock setup information and instructions")
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def setup(interaction: discord.Interaction):
    """
    Display timeclock setup information and instructions.
    Shows how to use the universal /clock command system.
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
        # Get server information
        server_tier = get_server_tier(guild_id)
        
        if server_tier == "free":
            access_info = "**Free Tier:** Only administrators can use the timeclock\n• Upgrade to Basic/Pro for full team access"
        else:
            access_info = "**Team Access:** All configured employee roles can use the timeclock"
        
        # Use the same domain detection as other functions
        dashboard_url = f"https://{get_domain()}"
        
        setup_message = (
            f"⏰ **Timeclock Setup Complete!**\n\n"
            f"**How to Use:**\n"
            f"• Type `/clock` anywhere in the server to access timeclock\n"
            f"• No channel setup needed - works from any channel!\n"
            f"• Fresh interface every time - no timeout issues\n"
            f"• All responses are private (only you see them)\n\n"
            f"**Current Access Level:**\n"
            f"{access_info}\n\n"
            f"**📊 Web Dashboard:**\n"
            f"• Visit **{dashboard_url}** for advanced management\n"
            f"• Login with Discord to view reports and settings\n"
            f"• Access real-time server statistics and admin tools\n\n"
            f"**Available Commands:**\n"
            f"• `/clock` - Access your timeclock interface\n"
            f"• `/help` - View all available commands\n"
            f"• `/upgrade` - Upgrade your server plan\n\n"
            f"**🎉 Setup Benefits:**\n"
            f"• **Universal Access:** Works from any channel\n"
            f"• **No Maintenance:** No buttons to refresh or manage\n"
            f"• **Always Reliable:** Zero interaction failures\n"
            f"• **Professional Experience:** Clean, private workflow\n\n"
            f"**🆘 Need Help?** Join support: https://discord.gg/KdTRTqdPcj"
        )
        
        await interaction.edit_original_response(content=setup_message)
        print(f"✅ Displayed setup information for guild {guild_id}")
        
    except Exception as e:
        print(f"❌ Failed to display setup information: {e}")
        await interaction.edit_original_response(
            content="❌ **Setup Information Error**\n\n"
                   "Could not retrieve setup information.\n"
                   "Please try again or contact support if the issue persists."
        )


@tree.command(name="clock", description="Access your personal timeclock interface")
@app_commands.guild_only()
async def clock_interface(interaction: discord.Interaction):
    """
    Provides users with their personal timeclock interface.
    Shows fresh buttons that never timeout - the new reliable way to clock in/out.
    """
    # Check if user has permission to use timeclock
    guild_id = interaction.guild_id
    if guild_id is None:
        await send_reply(interaction, "❌ This command must be used in a server.", ephemeral=True)
        return
    
    # Check if user has permission to use timeclock functions
    server_tier = get_server_tier(guild_id)
    
    # Type guard: ensure we have a Member for guild-specific functions
    if not isinstance(interaction.user, discord.Member):
        await send_reply(interaction,
            "❌ Unable to verify access permissions. Please try again.",
            ephemeral=True
        )
        return
    
    if not user_has_clock_access(interaction.user, server_tier):
        if server_tier == "free":
            await send_reply(interaction,
                "⚠️ **Free Tier Limitation**\n\n"
                "Only administrators can use timeclock functions on the free tier.\n"
                "Upgrade to Basic or Pro to unlock full team access!\n\n"
                "Use `/upgrade` to see subscription options.",
                ephemeral=True
            )
        else:
            await send_reply(interaction,
                "❌ **Access Denied**\n\n"
                "You don't have permission to use timeclock functions.\n"
                "Contact your server administrator to:\n"
                "• Add you to an employee role using `/add_employee_role`\n"
                "• Or grant you administrator permissions",
                ephemeral=True
            )
        return
    
    # Create fresh timeclock interface for this user
    try:
        # Create a non-persistent view with fresh buttons (no timeout issues!)
        view = TimeClockView(guild_id=guild_id)
        
        # Get current clock status for user
        user_id = interaction.user.id
        active_session = None
        
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.execute(
                "SELECT clock_in FROM sessions WHERE user_id = ? AND guild_id = ? AND clock_out IS NULL",
                (user_id, guild_id)
            )
            active_session = cursor.fetchone()
        
        # Build status message
        if active_session:
            clock_in_time = datetime.fromisoformat(active_session[0]).replace(tzinfo=timezone.utc)
            elapsed = datetime.now(timezone.utc) - clock_in_time
            hours, remainder = divmod(int(elapsed.total_seconds()), 3600)
            minutes, _ = divmod(remainder, 60)
            
            status_message = (
                f"🟢 **You're Currently Clocked In**\n\n"
                f"**Started:** <t:{int(clock_in_time.timestamp())}:f>\n"
                f"**Elapsed Time:** {hours}h {minutes}m\n\n"
                f"Use the buttons below to manage your time:"
            )
        else:
            status_message = (
                f"⚪ **Ready to Clock In**\n\n"
                f"You're not currently clocked in.\n"
                f"Use the buttons below to start tracking your time:"
            )
        
        # Send ephemeral response with fresh buttons
        await send_reply(interaction, 
            content=status_message,
            view=view, 
            ephemeral=True
        )
        
        print(f"✅ Provided fresh timeclock interface to {interaction.user} in guild {guild_id}")
        
    except Exception as e:
        print(f"❌ Error creating timeclock interface for {interaction.user}: {e}")
        await send_reply(interaction,
            "❌ **Error Creating Timeclock Interface**\n\n"
            "Something went wrong while creating your timeclock interface.\n"
            "Please try again, or contact your administrator if the problem persists.",
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
    await send_reply(interaction, f"✅ Set recipient to {user.mention}.", ephemeral=True)

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
            embed.add_field(name="⚠️ Free Tier Limitation", value="These roles are configured but won't take effect until you upgrade to Basic/Pro. Currently only admins can use timeclock functions.", inline=False)
    else:
        if server_tier == "free":
            embed.add_field(name="Custom Employee Roles", value="*No custom employee roles configured.*\nUpgrade to Basic/Pro to configure roles for team access!", inline=False)
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
    # Get current server tier
    server_tier = get_server_tier(interaction.guild_id)
    tier_color = {"free": discord.Color.green(), "basic": discord.Color.blue(), "pro": discord.Color.purple()}
    
    embed = discord.Embed(
        title="📋 Complete Command Reference",
        description=f"**Current Plan:** {server_tier.title()}\n\n**All available slash commands organized by function:**",
        color=tier_color.get(server_tier, discord.Color.green())
    )
    
    # Version 1.1 Update Notice
    embed.add_field(
        name="🎉 Version 1.1 - No More Timeouts!",
        value=(
            "**New `/clock` Command:** Access your timeclock interface with fresh buttons every time!\n"
            "**No More Issues:** Say goodbye to timeout errors and refresh commands\n"
            "**Easy to Use:** Just type `/clock` whenever you need to punch in or out"
        ),
        inline=False
    )
    
    # Core Timeclock Commands (new section)
    embed.add_field(
        name="⏰ Timeclock Commands",
        value=(
            "`/clock` - Access your personal timeclock interface (fresh buttons, never times out!)\n"
            "`/setup` - View timeclock setup information and instructions"
        ),
        inline=False
    )
    
    # Setup & Configuration Commands
    embed.add_field(
        name="⚙️ Setup & Configuration",
        value=(
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
            "`/upgrade` - Upgrade your server to Basic or Pro plan\n"
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
            "💡 **Upgrade Benefits:** Basic ($5/mo) unlocks full team access & real CSV reports"
        )
    elif server_tier == "basic":
        tier_info += (
            "💙 **Basic Tier:** Full team access • Real CSV reports • 7-day data retention\n"
            "💡 **Pro Benefits:** 30-day retention • Multiple manager notifications • Extended features"
        )
    else:  # pro tier
        tier_info += "💜 **Pro Tier:** All features unlocked • 30-day retention • Multiple managers • Priority support"
    
    embed.add_field(
        name="🔘 How to Use Your Timeclock",
        value=(
            "**Step 1:** Type `/clock` to access your personal timeclock\n"
            "**Step 2:** Use the fresh buttons that appear (only you see them)\n"
            "• 🟢 **Clock In** - Start tracking your time\n"
            "• 🔴 **Clock Out** - Stop tracking and log your shift\n"
            "• 📊 **Reports** - Generate timesheet reports (admin access)\n"
            "• ⬆️ **Upgrade** - Upgrade to Basic/Pro plans\n" + 
            tier_info
        ),
        inline=False
    )
    
    # Version 1.1 Benefits & Info
    embed.add_field(
        name="✨ Version 1.1 Benefits",
        value=(
            "🚫 **No More Timeouts:** Fresh buttons every time you use `/clock`\n"
            "⚡ **Always Works:** Zero maintenance, no refresh commands needed\n"
            "🔒 **Private Interface:** Only you see your timeclock responses\n"
            "🎯 **Reliable:** Never fails, never times out, always available"
        ),
        inline=False
    )
    
    embed.set_footer(text=f"💡 {server_tier.title()} Plan Active | Type /clock to access your timeclock!")
    
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
    
    # Check tier access for reports
    if interaction.guild is None:
        await interaction.followup.send("❌ This command must be used in a server.", ephemeral=True)
        return
        
    guild_id = interaction.guild.id
    server_tier = get_server_tier(guild_id)
    
    # Type guard: ensure we have a Member for guild-specific functions
    if not isinstance(interaction.user, discord.Member):
        await interaction.followup.send(
            "❌ Unable to verify admin permissions. Please try again.",
            ephemeral=True
        )
        return
    
    # Free tier: Admin only + fake data
    if server_tier == "free":
        if not user_has_admin_access(interaction.user):
            await interaction.followup.send(
                "🔒 **Free Tier Limitation**\n"
                "Only server administrators can test the report feature.\n"
                "Upgrade to Basic ($5/month) for full team access and CSV reports!",
                ephemeral=True
            )
            return
        
        # Return fake CSV for free tier
        fake_csv = "Date,Clock In,Clock Out,Duration\n2024-01-01,09:00,17:00,8.0 hours\nThis is the free version, please upgrade for more options"
        user_display_name = get_user_display_name(user, guild_id)
        filename = f"{user_display_name}_sample_report_{start_date}_to_{end_date}.csv"
        
        file = discord.File(
            io.BytesIO(fake_csv.encode('utf-8')), 
            filename=filename
        )
        await interaction.followup.send(
            f"📊 **Free Tier Sample Report** for **{user_display_name}**\n"
            f"🎯 This is sample data. Upgrade to Basic ($5/month) or Pro ($10/month) for real reports!\n"
            f"📅 Date Range: {start_date} to {end_date}",
            file=file,
            ephemeral=True
        )
        return
    
    # Basic and Pro tier: Full reports access with retention limits
    # Get tier limits
    tier_limits = {"basic": 7, "pro": 30}
    max_days = tier_limits.get(server_tier, 30)
    
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
        
        # Check retention limits for Basic tier
        days_requested = (end_dt - start_dt).days + 1
        if days_requested > max_days:
            await interaction.followup.send(
                f"❌ **{server_tier.title()} tier limitation**: Reports limited to {max_days} days maximum.\n"
                f"You requested {days_requested} days. Please choose a shorter date range.\n\n"
                f"💡 Upgrade to Pro for extended 30-day reports!" if server_tier == "basic" else "",
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
            except sqlite3.OperationalError as e:
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
                value="**Free:** No retention (test only)\n**Basic:** 7 days (1 week)\n**Pro:** 30 days (1 month)",
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
        
        # Check if user is a Member (should be in guild context) and has admin access
        if not isinstance(interaction.user, discord.Member) or not user_has_admin_access(interaction.user):
            await interaction.followup.send("❌ Only administrators can use this command.", ephemeral=True)
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
    """Allow admins to manually purge timeclock data only"""
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
            "❌ Unable to verify admin permissions. Please try again.",
            ephemeral=True
        )
        return
    
    # Double-check admin status
    if not is_server_admin(interaction.user):
        await interaction.followup.send("❌ Only server administrators can use this command.", ephemeral=True)
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
            "• **Subscription status** (Basic/Pro plans remain active)\n"
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
@tree.command(name="upgrade", description="Upgrade your server to Basic or Pro plan")
@app_commands.describe(plan="Choose Basic ($5/month) or Pro ($10/month)")
@app_commands.choices(plan=[
    app_commands.Choice(name="Basic - $5/month", value="basic"),
    app_commands.Choice(name="Pro - $10/month", value="pro")
])
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def upgrade_server(interaction: discord.Interaction, plan: str):
    """Create Stripe checkout link for server upgrade"""
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
        current_tier = get_server_tier(guild_id)
        
        # Check if already on this tier or higher
        tier_hierarchy = {'free': 0, 'basic': 1, 'pro': 2}
        if tier_hierarchy.get(current_tier, 0) >= tier_hierarchy.get(plan, 0):
            await interaction.followup.send(
                f"✅ Your server is already on **{current_tier.title()}** plan or higher!\n"
                f"Use `/subscription_status` to view current subscription details.",
                ephemeral=True
            )
            return
        
        # Check Stripe configuration
        if not stripe.api_key:
            await interaction.followup.send(
                "❌ Payment system is not configured. Please contact support.",
                ephemeral=True
            )
            return
        
        # Create secure checkout session server-side
        checkout_url = create_secure_checkout_session(guild_id, plan)
        
        plan_details = {
            'basic': "**Basic Plan - $5/month**\n• Full team access to timeclock\n• All admin commands\n• CSV Reports\n• Role management\n• 1 week data retention",
            'pro': "**Pro Plan - $10/month**\n• Everything in Basic\n• Extended CSV reports\n• Multiple manager notifications\n• 30 days data retention"
        }
        
        embed = discord.Embed(
            title=f"💳 Upgrade to {plan.title()} Plan",
            description=plan_details[plan],
            color=discord.Color.blue()
        )
        embed.add_field(
            name="Next Steps",
            value=f"Click the button below to complete your upgrade through Stripe.\n"
                  f"You'll be redirected to a secure checkout page.",
            inline=False
        )
        
        # Create a view with a button that opens the checkout URL
        view = discord.ui.View()
        button = discord.ui.Button(
            label=f"Upgrade to {plan.title()} - ${5 if plan == 'basic' else 10}/month",
            style=discord.ButtonStyle.primary,
            url=checkout_url
        )
        view.add_item(button)
        
        await interaction.followup.send(embed=embed, view=view, ephemeral=True)
        
    except Exception as e:
        await interaction.followup.send(
            f"❌ Error creating checkout session: {str(e)}", 
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
                value="Use `/upgrade basic` or `/upgrade pro` to start a subscription",
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
                WHERE guild_id = ?
            """, (guild_id,))
            result = cursor.fetchone()
            
            if not result:
                tier = "free"
                subscription_id = None
                customer_id = None
                expires_at = None
                status = "active"
            else:
                tier, subscription_id, customer_id, expires_at, status = result
        
        tier_colors = {"free": discord.Color.green(), "basic": discord.Color.blue(), "pro": discord.Color.purple()}
        tier_emojis = {"free": "🆓", "basic": "💼", "pro": "⭐"}
        
        embed = discord.Embed(
            title=f"{tier_emojis.get(tier, '❓')} Subscription Status",
            color=tier_colors.get(tier, discord.Color.greyple())
        )
        
        embed.add_field(name="Current Plan", value=tier.title(), inline=True)
        embed.add_field(name="Status", value=status.title(), inline=True)
        
        if subscription_id:
            embed.add_field(name="Subscription ID", value=f"`{subscription_id}`", inline=True)
        
        if expires_at:
            embed.add_field(name="Next Billing", value=f"<t:{int(datetime.fromisoformat(expires_at).timestamp())}:f>", inline=True)
        
        # Show plan features
        plan_features = {
            'free': "• Admin-only testing\n• Sample reports\n• No data retention",
            'basic': "• Full team access\n• All admin commands\n• CSV Reports\n• Role management\n• 1 week data retention",
            'pro': "• Everything in Basic\n• Extended CSV reports\n• Multiple managers\n• 30 days data retention"
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
                value="Use `/upgrade basic` or `/upgrade pro` to upgrade your server!",
                inline=False
            )
        elif tier == "basic":
            embed.add_field(
                name="Upgrade Option",
                value="Use `/upgrade pro` to upgrade to Pro plan!",
                inline=False
            )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
    except Exception as e:
        await interaction.followup.send(
            f"❌ Error fetching subscription status: {str(e)}", 
            ephemeral=True
        )

# =============================================================================
# OWNER-ONLY SUPER ADMIN COMMANDS (Only visible to bot owner)
# =============================================================================

@tree.command(name="owner_grant", description="[OWNER] Grant subscription tier to current server")
@app_commands.describe(tier="Subscription tier to grant")
@app_commands.choices(tier=[
    app_commands.Choice(name="Basic ($5/month)", value="basic"),
    app_commands.Choice(name="Pro ($10/month)", value="pro")
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
        # Check current tier
        current_tier = get_server_tier(guild_id)
        
        # Grant the new tier (no Stripe subscription - manual owner grant)
        set_server_tier(guild_id, tier, subscription_id=f"owner_grant_{int(time.time())}", customer_id="owner_manual")
        
        embed = discord.Embed(
            title="👑 Owner Grant Successful",
            description=f"Manually granted **{tier.title()}** tier to this server",
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
            value="• Full team access\n• CSV Reports\n• Role management\n• Extended retention" if tier == "pro" else "• Full team access\n• CSV Reports\n• Role management\n• 7-day retention",
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
    app_commands.Choice(name="Basic ($5/month)", value="basic"),
    app_commands.Choice(name="Pro ($10/month)", value="pro")
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
        
        # Check current tier
        current_tier = get_server_tier(guild_id)
        
        # Grant the tier
        set_server_tier(guild_id, tier, subscription_id=f"owner_remote_{int(time.time())}", customer_id="owner_remote")
        
        embed = discord.Embed(
            title="🌐 Remote Server Grant Successful",
            description=f"Granted **{tier.title()}** tier to remote server",
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
            # Get server tier
            tier = get_server_tier(guild.id)
            
            # Note: Without member intents, we can't count individual users by permissions/roles
            # We can only provide the total member count and role configuration info
            admin_count = "N/A*"
            employee_count = "N/A*"
            
            # Check if clock roles are configured (indicates employees beyond admins)
            employee_roles = get_employee_roles(guild.id)
            employee_setup = "Admin-only" if not employee_roles else f"{len(employee_roles)} employee roles"
            
            server_data.append({
                'name': guild.name,
                'id': guild.id,
                'member_count': guild.member_count,
                'admin_count': admin_count,
                'employee_count': employee_count,
                'employee_setup': employee_setup,
                'tier': tier
            })
        
        # Sort by member count (largest first)
        server_data.sort(key=lambda x: x['member_count'], reverse=True)
        
        # Add server info to embed (limit to prevent message too long)
        for i, server in enumerate(server_data[:15]):  # Show first 15 servers
            tier_emoji = {"free": "🆓", "basic": "💼", "pro": "⭐"}.get(server['tier'], "❓")
            
            embed.add_field(
                name=f"{tier_emoji} {server['name'][:30]}" + ("..." if len(server['name']) > 30 else ""),
                value=f"**Members:** {server['member_count']}\n"
                      f"**Access:** {server['employee_setup']}\n"
                      f"**Tier:** {server['tier'].title()}",
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
        admin_only_count = len([s for s in server_data if s['employee_setup'] == 'Admin-only'])
        role_configured_count = len([s for s in server_data if s['employee_setup'] != 'Admin-only'])
        
        embed.add_field(
            name="📈 Totals",
            value=f"**Servers:** {len(server_data)}\n"
                  f"**Total Members:** {total_members:,}\n"
                  f"**Admin-Only Access:** {admin_only_count} servers\n"
                  f"**Employee Roles Setup:** {role_configured_count} servers",
            inline=False
        )
        
        embed.add_field(
            name="ℹ️ Note",
            value="*Individual admin/employee counts require member intents to be enabled in Discord Developer Portal*",
            inline=False
        )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
    except Exception as e:
        await interaction.followup.send(f"❌ Error fetching server listings: {str(e)}", ephemeral=True)


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
        return web.json_response({'success': False, 'error': 'Unauthorized'}, status=401)
    
    try:
        data = await request.json()
        guild_id = int(request.match_info['guild_id'])
        role_id = int(data.get('role_id'))
        
        # Use existing bot function
        add_employee_role(guild_id, role_id)
        
        return web.json_response({
            'success': True,
            'message': 'Employee role added successfully',
            'role_id': str(role_id)
        })
    except Exception as e:
        print(f"❌ Error adding employee role via API: {e}")
        return web.json_response({'success': False, 'error': str(e)}, status=500)

async def handle_remove_employee_role(request: web.Request):
    """HTTP endpoint: Remove employee role"""
    if not verify_api_request(request):
        return web.json_response({'success': False, 'error': 'Unauthorized'}, status=401)
    
    try:
        data = await request.json()
        guild_id = int(request.match_info['guild_id'])
        role_id = int(data.get('role_id'))
        
        # Use existing bot function
        remove_employee_role(guild_id, role_id)
        
        return web.json_response({
            'success': True,
            'message': 'Employee role removed successfully',
            'role_id': str(role_id)
        })
    except Exception as e:
        print(f"❌ Error removing employee role via API: {e}")
        return web.json_response({'success': False, 'error': str(e)}, status=500)

async def start_bot_api_server():
    """Start aiohttp server for bot API endpoints"""
    app = web.Application()
    app.router.add_post('/api/guild/{guild_id}/admin-roles/add', handle_add_admin_role)
    app.router.add_post('/api/guild/{guild_id}/admin-roles/remove', handle_remove_admin_role)
    app.router.add_post('/api/guild/{guild_id}/employee-roles/add', handle_add_employee_role)
    app.router.add_post('/api/guild/{guild_id}/employee-roles/remove', handle_remove_employee_role)
    
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
