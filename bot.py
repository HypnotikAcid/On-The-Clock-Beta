import os
import sqlite3
import csv
import io
import zipfile
import json
import threading
import time
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
import stripe

import discord
from discord import app_commands
from discord.ext import commands

# --- Config / Secrets ---
TOKEN = os.getenv("DISCORD_TOKEN")            # required
DB_PATH = os.getenv("TIMECLOCK_DB", "timeclock.db")
GUILD_ID = os.getenv("GUILD_ID")              # optional but makes commands appear instantly (guild sync)
DEFAULT_TZ = "America/New_York"
HTTP_PORT = int(os.getenv("PORT", "5000"))     # Health check server port

# --- Bot Owner Configuration ---
BOT_OWNER_ID = 107103438139056128  # Your Discord user ID for super admin access

# --- Stripe Configuration ---
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")
STRIPE_PRICE_IDS = {
    'basic': 'price_1SAHpL3Jrp0J9Adlfowh5qpr',   # $5/month LIVE
    'pro': 'price_1SAHqH3Jrp0J9AdlFSJpJ32A'      # $10/month LIVE
}

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

# Get domain for Stripe redirects
def get_domain():
    if os.getenv('REPLIT_DEPLOYMENT'):
        return os.getenv('REPLIT_DEV_DOMAIN')
    else:
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
        
        return checkout_session.url
        
    except stripe.error.StripeError as e:
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
            
            # Get bot's client ID for invite URL
            bot_id = bot_instance.user.id if bot_instance and bot_instance.is_ready() and bot_instance.user else "1418446753379913809"
            invite_url = f"https://discord.com/api/oauth2/authorize?client_id={bot_id}&permissions=2048&scope=bot%20applications.commands"
            
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
        
        <a href="{invite_url}" class="add-bot-btn">
            🔗 Add Bot to Your Discord Server
        </a>
        
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
            print(f"🔔 Webhook received - Headers: {dict(self.headers)}")
            
            if not STRIPE_WEBHOOK_SECRET:
                print("❌ STRIPE_WEBHOOK_SECRET not configured")
                self.send_response(400)
                self.end_headers()
                return
                
            content_length = int(self.headers['Content-Length'])
            payload = self.rfile.read(content_length)
            sig_header = self.headers.get('stripe-signature')
            
            print(f"🔍 Payload length: {len(payload)}, Signature: {sig_header is not None}")
            
            if not sig_header:
                print("❌ Missing Stripe signature header")
                print("📋 Available headers:", list(self.headers.keys()))
                
            # Production webhook signature verification (ENABLED for live mode)
            print("🔐 Verifying webhook signature for production...")
            try:
                # Verify webhook signature using Stripe
                event = stripe.Webhook.construct_event(
                    payload, sig_header, STRIPE_WEBHOOK_SECRET
                )
                print(f"✅ Webhook signature verified successfully")
                print(f"🔔 Webhook event type: {event.get('type', 'unknown')}")
                
                if event.get('type') == 'checkout.session.completed':
                    print("💳 Processing checkout.session.completed event")
                    session = event['data']['object']
                    self.process_checkout_completed(session)
                elif event.get('type') == 'customer.subscription.updated':
                    print("🔄 Processing customer.subscription.updated event")
                    subscription = event['data']['object']
                    # Handle subscription updates if needed
                elif event.get('type') == 'customer.subscription.deleted':
                    print("❌ Processing customer.subscription.deleted event")
                    subscription = event['data']['object']
                    self.handle_subscription_cancellation(subscription)
                else:
                    print(f"ℹ️ Unhandled event type: {event.get('type')}")
                    
            except ValueError as e:
                print(f"❌ Invalid webhook payload: {e}")
                self.send_response(400)
                return
            except stripe.error.SignatureVerificationError as e:
                print(f"❌ Invalid webhook signature: {e}")
                self.send_response(400)
                return
            except Exception as debug_e:
                print(f"🐛 Error processing webhook: {debug_e}")
                import traceback
                traceback.print_exc()
                self.send_response(500)
                return
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"received": true}')
            return
            
            # Handle different event types
            if event['type'] == 'checkout.session.completed':
                session = event['data']['object']
                self.process_checkout_completed(session)
                        
            elif event['type'] == 'customer.subscription.updated':
                subscription = event['data']['object']
                self.handle_subscription_change(subscription)
                
            elif event['type'] == 'customer.subscription.deleted':
                subscription = event['data']['object']
                self.handle_subscription_cancellation(subscription)
                
            elif event['type'] == 'invoice.payment_failed':
                invoice = event['data']['object']
                self.handle_payment_failure(invoice)
            
            # Send success response
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
            print(f"🔄 Processing checkout session: {session.get('id', 'unknown')}")
            
            # Retrieve full session with line items to verify pricing
            full_session = stripe.checkout.Session.retrieve(
                session['id'],
                expand=['line_items']
            )
            
            print(f"📋 Session details: Customer={full_session.get('customer')}, Subscription={full_session.get('subscription')}")
            
            # Verify the price ID matches our expected tiers
            if full_session.line_items.data:
                price_id = full_session.line_items.data[0].price.id
                print(f"💰 Price ID: {price_id}")
                
                tier = None
                for t, pid in STRIPE_PRICE_IDS.items():
                    if pid == price_id:
                        tier = t
                        break
                
                if not tier:
                    print(f"❌ Unknown price ID in checkout: {price_id}")
                    print(f"🔍 Expected price IDs: {STRIPE_PRICE_IDS}")
                    return
                
                guild_id = session.get('metadata', {}).get('guild_id')
                print(f"🎯 Guild ID from metadata: {guild_id}")
                
                if guild_id:
                    subscription_id = session.get('subscription')
                    customer_id = session.get('customer')
                    
                    print(f"📝 Updating server tier: Guild {guild_id} -> {tier.title()}")
                    print(f"🔗 Subscription ID: {subscription_id}, Customer ID: {customer_id}")
                    
                    # Update database with verified subscription
                    set_server_tier(int(guild_id), tier, subscription_id, customer_id)
                    print(f"✅ Subscription activated: Guild {guild_id} -> {tier.title()}")
                else:
                    print("❌ No guild_id found in session metadata")
                    print(f"🔍 Available metadata: {session.get('metadata', {})}")
            else:
                print("❌ No line items found in checkout session")
                
        except Exception as e:
            print(f"❌ Error processing checkout session: {e}")
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
                clock_roles_cursor = conn.execute("DELETE FROM clock_roles WHERE guild_id = ?", (guild_id,))
                clock_roles_deleted = clock_roles_cursor.rowcount
                
                # Reset subscription to free tier (don't delete subscription record)
                conn.execute("""
                    UPDATE server_subscriptions 
                    SET tier = 'free', subscription_id = NULL, customer_id = NULL, 
                        expires_at = NULL, status = 'cancelled'
                    WHERE guild_id = ?
                """, (guild_id,))
                
                print(f"🗑️ Data purged for Guild {guild_id}: {sessions_deleted} sessions, {settings_deleted} settings, {auth_roles_deleted} auth roles, {admin_roles_deleted} admin roles, {clock_roles_deleted} clock roles")
                
        except Exception as e:
            print(f"❌ Error purging guild data for {guild_id}: {e}")

    def purge_timeclock_data_only(self, guild_id: int):
        """Purge only timeclock sessions data, preserving subscription and core settings"""
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
            clock_roles_cursor = conn.execute("DELETE FROM clock_roles WHERE guild_id = ?", (guild_id,))
            clock_roles_deleted = clock_roles_cursor.rowcount
            
            # Reset subscription to free tier (don't delete subscription record)
            conn.execute("""
                UPDATE server_subscriptions 
                SET tier = 'free', subscription_id = NULL, customer_id = NULL, 
                    expires_at = NULL, status = 'cancelled'
                WHERE guild_id = ?
            """, (guild_id,))
            
            print(f"🗑️ Data purged for Guild {guild_id}: {sessions_deleted} sessions, {settings_deleted} settings, {auth_roles_deleted} auth roles, {admin_roles_deleted} admin roles, {clock_roles_deleted} clock roles")
            return sessions_deleted + settings_deleted + auth_roles_deleted + admin_roles_deleted + clock_roles_deleted
            
    except Exception as e:
        print(f"❌ Error purging guild data for {guild_id}: {e}")
        raise
    
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
    
    def handle_subscription_cancellation(self, subscription):
        """Handle subscription cancellations"""
        try:
            with db() as conn:
                cursor = conn.execute("""
                    SELECT guild_id FROM server_subscriptions 
                    WHERE subscription_id = ?
                """, (subscription['id'],))
                result = cursor.fetchone()
                
                if result:
                    guild_id = result[0]
                    
                    # Purge all guild data and revert to free tier
                    self.purge_all_guild_data(guild_id)
                    print(f"⬇️ Subscription cancelled: Guild {guild_id} -> Free with data purged")
                    
        except Exception as e:
            print(f"❌ Error handling subscription cancellation: {e}")
    
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
        # Get bot status info (use class attribute to avoid LSP error)
        bot_instance = getattr(type(self), 'bot', None)
        bot_status = "🟢 Online" if bot_instance and bot_instance.is_ready() else "🔴 Offline"
        guild_count = len(bot_instance.guilds) if bot_instance and bot_instance.is_ready() else "Loading..."
        
        # Get bot's client ID for invite URL
        bot_id = bot_instance.user.id if bot_instance and bot_instance.is_ready() and bot_instance.user else "1418446753379913809"
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
        .free-tier {{
            border-left-color: #28a745;
            background: #1e3a28;
        }}
        .pro-tier {{
            border-left-color: #5865F2;
            background: #2b2d42;
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
                    <strong>⏱️ Timeclock</strong><br>
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
    
    def log_message(self, format, *args):
        # Suppress default HTTP server logs to avoid cluttering Discord bot logs
        pass

def start_health_server():
    """Start the health check HTTP server in a separate thread"""
    # Pass bot reference to handler to fix LSP error
    HealthCheckHandler.bot = bot
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
        
        # Add main_admin_role_id column if it doesn't exist (for main admin role feature)
        try:
            conn.execute("ALTER TABLE guild_settings ADD COLUMN main_admin_role_id INTEGER")
        except:
            pass  # Column already exists
        conn.execute("""
        CREATE TABLE IF NOT EXISTS authorized_roles (
            guild_id INTEGER,
            role_id INTEGER,
            PRIMARY KEY (guild_id, role_id)
        )
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS admin_roles (
            guild_id INTEGER,
            role_id INTEGER,
            PRIMARY KEY (guild_id, role_id)
        )
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS clock_roles (
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
        # If subscription is cancelled, treat as free tier
        if status == "cancelled":
            return "free"
        
        return tier

def set_server_tier(guild_id: int, tier: str, subscription_id: str = None, customer_id: str = None):
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

def cleanup_old_sessions(guild_id: int = None) -> int:
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

def get_guild_setting(guild_id: int, key: str, default=None):
    # Map of allowed keys to their SQL column queries
    column_queries = {
        'recipient_user_id': "SELECT recipient_user_id FROM guild_settings WHERE guild_id=?",
        'button_channel_id': "SELECT button_channel_id FROM guild_settings WHERE guild_id=?",
        'button_message_id': "SELECT button_message_id FROM guild_settings WHERE guild_id=?",
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

def set_guild_setting(guild_id: int, key: str, value):
    # Map of allowed keys to their SQL update queries
    update_queries = {
        'recipient_user_id': "UPDATE guild_settings SET recipient_user_id=? WHERE guild_id=?",
        'button_channel_id': "UPDATE guild_settings SET button_channel_id=? WHERE guild_id=?",
        'button_message_id': "UPDATE guild_settings SET button_message_id=? WHERE guild_id=?",
        'timezone': "UPDATE guild_settings SET timezone=? WHERE guild_id=?",
        'name_display_mode': "UPDATE guild_settings SET name_display_mode=? WHERE guild_id=?",
        'main_admin_role_id': "UPDATE guild_settings SET main_admin_role_id=? WHERE guild_id=?"
    }
    
    if key not in update_queries:
        raise ValueError(f"Invalid column name: {key}")
    
    with db() as conn:
        conn.execute("INSERT OR IGNORE INTO guild_settings(guild_id) VALUES (?)", (guild_id,))
        conn.execute(update_queries[key], (value, guild_id))

def get_user_display_name(user: discord.User, guild_id: int) -> str:
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
        conn.execute("INSERT OR IGNORE INTO admin_roles (guild_id, role_id) VALUES (?, ?)", 
                     (guild_id, role_id))

def remove_admin_role(guild_id: int, role_id: int):
    """Remove a role from admin Reports/Upgrade button access."""
    with db() as conn:
        conn.execute("DELETE FROM admin_roles WHERE guild_id=? AND role_id=?", 
                     (guild_id, role_id))

def get_admin_roles(guild_id: int):
    """Get all admin role IDs for a guild."""
    with db() as conn:
        cur = conn.execute("SELECT role_id FROM admin_roles WHERE guild_id=?", (guild_id,))
        return [row[0] for row in cur.fetchall()]

def user_has_admin_access(user: discord.Member):
    """Check if user has admin access (Discord admin OR custom admin role OR main admin role)."""
    # Check Discord administrator permission first
    if user.guild_permissions.administrator:
        return True
    
    user_role_ids = [role.id for role in user.roles]
    
    # Check main admin role (primary designated admin role)
    main_admin_role_id = get_guild_setting(user.guild.id, "main_admin_role_id")
    if main_admin_role_id and main_admin_role_id in user_role_ids:
        return True
    
    # Check custom admin roles (additional admin roles)
    admin_roles = get_admin_roles(user.guild.id)
    return any(role_id in user_role_ids for role_id in admin_roles)

def add_employee_role(guild_id: int, role_id: int):
    """Add a role that can use timeclock functions."""
    with db() as conn:
        conn.execute("INSERT OR IGNORE INTO clock_roles (guild_id, role_id) VALUES (?, ?)", 
                     (guild_id, role_id))

def remove_employee_role(guild_id: int, role_id: int):
    """Remove a role from timeclock functions access."""
    with db() as conn:
        conn.execute("DELETE FROM clock_roles WHERE guild_id=? AND role_id=?", 
                     (guild_id, role_id))

def get_clock_roles(guild_id: int):
    """Get all clock role IDs for a guild."""
    with db() as conn:
        cur = conn.execute("SELECT role_id FROM clock_roles WHERE guild_id=?", (guild_id,))
        return [row[0] for row in cur.fetchall()]

def user_has_clock_access(user: discord.Member, server_tier: str):
    """Check if user can access clock buttons based on server tier and roles."""
    guild_id = user.guild.id
    
    # All tiers: check clock roles OR admin access
    # If no clock roles are configured, default to admin-only
    clock_roles = get_clock_roles(guild_id)
    if not clock_roles:
        return user_has_admin_access(user)
    
    # Check if user has any of the configured clock roles
    user_role_ids = [role.id for role in user.roles]
    has_clock_role = any(role_id in user_role_ids for role_id in clock_roles)
    
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
bot = commands.Bot(command_prefix="!", intents=intents)
tree = bot.tree

class TimeClockView(discord.ui.View):
    def __init__(self, guild_id: int = None):
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
            custom_id="timeclock:in", 
            row=0
        )
        clock_in_btn.callback = self.clock_in
        self.add_item(clock_in_btn)
        
        clock_out_btn = discord.ui.Button(
            label="Clock Out", 
            style=discord.ButtonStyle.danger, 
            custom_id="timeclock:out", 
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
        # Defer immediately to prevent timeout
        await interaction.response.defer(ephemeral=True)
        
        if interaction.guild is None:
            await interaction.followup.send("Use this in a server.", ephemeral=True)
            return
            
        guild_id = interaction.guild.id
        
        # Check clock access permissions
        server_tier = get_server_tier(guild_id)
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
                guild_tz = ZoneInfo(tz_name)
            except Exception:
                # If timezone fails, fallback to EST instead of UTC
                guild_tz = ZoneInfo(DEFAULT_TZ)
                tz_name = "America/New_York (EST)"
            
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
                    total_day_time = format_duration_hhmmss(total_day_seconds)
                    shift_time = format_shift_duration(shift_seconds)
                    
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
        # Defer immediately to prevent timeout
        await interaction.response.defer(ephemeral=True)
        
        if interaction.guild is None:
            await interaction.followup.send("Use this in a server.", ephemeral=True)
            return
        guild_id = interaction.guild.id
        user_id = interaction.user.id
        
        # Check clock access permissions
        server_tier = get_server_tier(guild_id)
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

    async def clock_out(self, interaction: discord.Interaction):
        # Defer immediately to prevent timeout
        await interaction.response.defer(ephemeral=True)
        
        if interaction.guild is None:
            await interaction.followup.send("Use this in a server.", ephemeral=True)
            return
        guild_id = interaction.guild.id
        user_id = interaction.user.id
        
        # Check clock access permissions
        server_tier = get_server_tier(guild_id)
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

        tz_name = get_guild_setting(guild_id, "timezone", DEFAULT_TZ)
        await interaction.followup.send(
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

    async def show_help(self, interaction: discord.Interaction):
        """Show help commands instead of user time info"""
        if interaction.guild is None:
            await interaction.response.send_message("Use this in a server.", ephemeral=True)
            return
        
        # Check clock access permissions
        server_tier = get_server_tier(interaction.guild.id)
        if not user_has_clock_access(interaction.user, server_tier):
            await interaction.response.send_message(
                "🔒 **Access Restricted**\n"
                "You need an employee role to use the timeclock.\n"
                "Ask an administrator to add your role with `/add_employee_role @yourrole`",
                ephemeral=True
            )
            return
            
        embed = discord.Embed(
            title="🛠️ Timeclock Help Commands",
            description="Available slash commands for the timeclock bot:",
            color=discord.Color.blue()
        )
        
        # Basic commands
        embed.add_field(
            name="📊 General Commands",
            value="`/help` - Show all commands\n"
                  "`/subscription_status` - View subscription details\n"
                  "`/cancel_subscription` - Learn how to cancel",
            inline=False
        )
        
        # Admin commands
        embed.add_field(
            name="👑 Admin Commands",
            value="`/setup_timeclock` - Create timeclock interface\n"
                  "`/report @user start-date end-date` - Generate CSV reports\n"
                  "`/data_cleanup` - Clean old data\n"
                  "`/purge` - Delete ALL server data",
            inline=False
        )
        
        # Settings commands
        embed.add_field(
            name="⚙️ Settings Commands",
            value="`/set_timezone` - Set server timezone\n"
                  "`/set_recipient` - Set manager for notifications\n"
                  "`/toggle_name_display` - Switch username/nickname",
            inline=False
        )
        
        # Subscription commands
        embed.add_field(
            name="💳 Subscription Commands",
            value="`/upgrade basic` - Upgrade to Basic ($5/month)\n"
                  "`/upgrade pro` - Upgrade to Pro ($10/month)",
            inline=False
        )
        
        await interaction.response.send_message(embed=embed, ephemeral=True)

    async def generate_reports(self, interaction: discord.Interaction):
        if interaction.guild is None:
            await interaction.response.send_message("Use this in a server.", ephemeral=True)
            return
        
        # Check if user has admin access (Discord admin OR custom admin role)
        if not user_has_admin_access(interaction.user):
            await interaction.response.send_message("❌ You need administrator permissions or an admin role to generate reports.", ephemeral=True)
            return
        
        await interaction.response.defer(ephemeral=True)
        
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
        
        # Determine report range based on tier
        if server_tier == "basic":
            report_days = 7  # Basic tier: 7 days max
        else:  # pro tier
            report_days = 30  # Pro tier: 30 days max
        
        # Generate report for tier-appropriate days
        from zoneinfo import ZoneInfo
        from datetime import timedelta
        try:
            guild_tz = ZoneInfo(guild_tz_name)
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
            csv_content, user_display_name = await generate_individual_csv_report(bot, user_id, sessions, guild_id, guild_tz_name)
            
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
                    csv_content, user_display_name = await generate_individual_csv_report(bot, user_id, sessions, guild_id, guild_tz_name)
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

    async def show_upgrade(self, interaction: discord.Interaction):
        """Show upgrade options for free tier servers"""
        guild_id = interaction.guild.id
        server_tier = get_server_tier(guild_id)
        
        # Only show for free tier
        if server_tier != "free":
            await interaction.response.send_message("This server already has a subscription!", ephemeral=True)
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
        
        await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.event
async def on_ready():
    # Register persistent TimeClockView to handle interactions from old button messages
    # This prevents "interaction failed" errors after bot restarts
    bot.add_view(TimeClockView())
    
    # Note: Using dynamic views now, no need to add static view
    # Views are created with guild-specific conditional buttons in setup_timeclock
    
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
        icon_url=bot.user.avatar.url if bot.user.avatar else None
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

@tree.command(name="setup_timeclock", description="Post a persistent Clock In/Clock Out message")
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def setup_timeclock(interaction: discord.Interaction, channel: Optional[discord.TextChannel] = None):
    ch = channel or interaction.channel
    if ch is None:
        await interaction.response.send_message("No channel resolved.", ephemeral=True)
        return
    
    # Defer the response early to avoid timeout issues
    await interaction.response.defer(ephemeral=True)
    
    # Use guild-specific lock to prevent race conditions
    guild_lock = get_guild_lock(interaction.guild_id)
    
    async with guild_lock:
        print(f"🔒 Acquired lock for guild {interaction.guild_id}")
        print(f"🔧 Setting up timeclock in {ch.name} (Guild: {interaction.guild_id})")
        
        # Enhanced cleanup: Remove ALL existing timeclock messages using component detection
        deleted_count = 0
        try:
            # Delete tracked message first
            old_channel_id = get_guild_setting(interaction.guild_id, "button_channel_id")
            old_message_id = get_guild_setting(interaction.guild_id, "button_message_id")
            
            if old_channel_id and old_message_id:
                try:
                    old_channel = bot.get_channel(old_channel_id)
                    if old_channel:
                        old_message = await old_channel.fetch_message(old_message_id)
                        await old_message.delete()
                        deleted_count += 1
                        print(f"🧹 Deleted tracked timeclock message in {old_channel.name}")
                except Exception as e:
                    print(f"⚠️ Could not delete tracked message: {e}")
            
            # More robust cleanup: Find messages with timeclock custom_ids
            async for message in ch.history(limit=100):
                if (message.author == bot.user and 
                    message.components and
                    any(component.children for component in message.components
                        if any(button.custom_id and button.custom_id.startswith("timeclock:")
                               for button in component.children if hasattr(button, 'custom_id')))):
                    try:
                        await message.delete()
                        deleted_count += 1
                        print(f"🧹 Deleted timeclock message by custom_id (ID: {message.id})")
                    except Exception as e:
                        print(f"⚠️ Could not delete message {message.id}: {e}")
            
            print(f"🧹 Total messages cleaned up: {deleted_count}")
            
        except Exception as e:
            print(f"⚠️ Error during cleanup: {e}")
        
        # Create new timeclock message with conditional buttons based on server tier
        view = TimeClockView(guild_id=interaction.guild_id)
        msg = await ch.send("**Time Clock** — Click a button to record your time.\n(Only you see confirmations.)", view=view)
        
        # Store the new message info
        set_guild_setting(interaction.guild_id, "button_channel_id", ch.id)
        set_guild_setting(interaction.guild_id, "button_message_id", msg.id)
        
        print(f"✅ Created new timeclock message (ID: {msg.id}) in {ch.name}")
        print(f"🔓 Released lock for guild {interaction.guild_id}")
        
    await interaction.followup.send(f"✅ Posted timeclock in {ch.mention}.", ephemeral=True)

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

@tree.command(name="toggle_name_display", description="Toggle between username and nickname display")
@app_commands.describe(mode="Choose 'username' (Discord username) or 'nickname' (server display name)")
@app_commands.choices(mode=[
    app_commands.Choice(name="Username (Discord username)", value="username"),
    app_commands.Choice(name="Nickname (Server display name)", value="nickname")
])
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def toggle_name_display(interaction: discord.Interaction, mode: app_commands.Choice[str]):
    set_guild_setting(interaction.guild_id, "name_display_mode", mode.value)
    
    if mode.value == "username":
        await interaction.response.send_message(
            "✅ **Name Display Set to Username**\n"
            "The bot will now show Discord usernames (e.g., `john_doe`) in reports and messages.",
            ephemeral=True
        )
    else:
        await interaction.response.send_message(
            "✅ **Name Display Set to Nickname**\n"
            "The bot will now show server display names (e.g., `John D.`) in reports and messages.",
            ephemeral=True
        )



@tree.command(name="add_admin_role", description="Add a role that can access Reports and Upgrade buttons")
@app_commands.describe(role="Role to grant admin access (Reports, Upgrade buttons)")
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def add_admin_role(interaction: discord.Interaction, role: discord.Role):
    add_admin_role(interaction.guild_id, role.id)
    await interaction.response.send_message(f"✅ Added {role.mention} to admin roles. They can now use Reports and Upgrade buttons.", ephemeral=True)

@tree.command(name="remove_admin_role", description="Remove a role's admin access to Reports and Upgrade buttons")
@app_commands.describe(role="Role to remove admin access from")
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def remove_admin_role_cmd(interaction: discord.Interaction, role: discord.Role):
    remove_admin_role(interaction.guild_id, role.id)
    await interaction.response.send_message(f"✅ Removed {role.mention} from admin roles. They can no longer use Reports and Upgrade buttons.", ephemeral=True)

@tree.command(name="list_admin_roles", description="List all roles with admin access")
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def list_admin_roles(interaction: discord.Interaction):
    admin_role_ids = get_admin_roles(interaction.guild_id)
    
    if not admin_role_ids:
        await interaction.response.send_message("No custom admin roles configured. Only Discord Administrators can use Reports/Upgrade buttons.", ephemeral=True)
        return
    
    # Get role objects
    admin_roles = []
    for role_id in admin_role_ids:
        role = interaction.guild.get_role(role_id)
        if role:
            admin_roles.append(role.mention)
        else:
            admin_roles.append(f"<Deleted Role: {role_id}>")
    
    embed = discord.Embed(
        title="🛡️ Admin Roles",
        description="Roles that can access Reports and Upgrade buttons:",
        color=discord.Color.blue()
    )
    embed.add_field(name="Custom Admin Roles", value="\n".join(admin_roles), inline=False)
    embed.add_field(name="Note", value="Discord Administrators always have admin access.", inline=False)
    
    await interaction.response.send_message(embed=embed, ephemeral=True)

@tree.command(name="set_main_role", description="Set the primary admin role (gets all admin functions)")
@app_commands.describe(role="Role to designate as main admin (gets Reports, Upgrade, all admin access)")
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def set_main_role(interaction: discord.Interaction, role: discord.Role):
    """Set the primary admin role that gets all admin functions"""
    set_guild_setting(interaction.guild_id, "main_admin_role_id", role.id)
    
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
    
    await interaction.response.send_message(embed=embed, ephemeral=True)

@tree.command(name="show_main_role", description="View the current main admin role")
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def show_main_role(interaction: discord.Interaction):
    """Show the current main admin role"""
    main_role_id = get_guild_setting(interaction.guild_id, "main_admin_role_id")
    
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
        role = interaction.guild.get_role(main_role_id)
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
    
    await interaction.response.send_message(embed=embed, ephemeral=True)

@tree.command(name="clear_main_role", description="Remove the main admin role designation") 
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def clear_main_role(interaction: discord.Interaction):
    """Clear the main admin role"""
    main_role_id = get_guild_setting(interaction.guild_id, "main_admin_role_id")
    
    if not main_role_id:
        await interaction.response.send_message(
            "No main admin role is currently set.",
            ephemeral=True
        )
        return
    
    # Get role name before clearing (if it exists)
    role = interaction.guild.get_role(main_role_id)
    role_name = role.mention if role else f"<Deleted Role: {main_role_id}>"
    
    # Clear the main admin role
    set_guild_setting(interaction.guild_id, "main_admin_role_id", None)
    
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
    
    await interaction.response.send_message(embed=embed, ephemeral=True)

@tree.command(name="add_employee_role", description="Add a role that can use timeclock functions")
@app_commands.describe(role="Role to grant employee access (timeclock functions)")
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def add_employee_role_cmd(interaction: discord.Interaction, role: discord.Role):
    add_employee_role(interaction.guild_id, role.id)
    server_tier = get_server_tier(interaction.guild_id)
    
    # Provide helpful context based on server tier
    if server_tier == "free":
        message = f"✅ Added {role.mention} to employee roles.\n🎉 **Employee roles work on free tier!** Only limitation is shorter data retention compared to paid plans."
    else:
        message = f"✅ Added {role.mention} to employee roles. Members with this role can now use timeclock functions."
    
    await interaction.response.send_message(message, ephemeral=True)

@tree.command(name="remove_employee_role", description="Remove a role's access to timeclock functions")
@app_commands.describe(role="Role to remove employee access from")
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def remove_employee_role_cmd(interaction: discord.Interaction, role: discord.Role):
    remove_employee_role(interaction.guild_id, role.id)
    await interaction.response.send_message(f"✅ Removed {role.mention} from employee roles. They can no longer use timeclock functions (unless admin).", ephemeral=True)

@tree.command(name="list_employee_roles", description="List all roles that can use timeclock functions")
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def list_employee_roles(interaction: discord.Interaction):
    clock_role_ids = get_clock_roles(interaction.guild_id)
    server_tier = get_server_tier(interaction.guild_id)
    
    embed = discord.Embed(
        title="👥 Employee Access Roles",
        description="Roles that can use timeclock functions:",
        color=discord.Color.green()
    )
    
    if not clock_role_ids:
        if server_tier == "free":
            embed.add_field(name="Access Control", value="**Free Tier:** Only administrators can use timeclock functions.\nUpgrade to Basic/Pro and configure roles for team access!", inline=False)
        else:
            embed.add_field(name="Access Control", value="**No employee roles configured.** Only administrators can use timeclock functions.\nUse `/add_employee_role @role` to grant access to your team!", inline=False)
    else:
        # Get role objects
        employee_roles = []
        for role_id in clock_role_ids:
            role = interaction.guild.get_role(role_id)
            if role:
                employee_roles.append(role.mention)
            else:
                employee_roles.append(f"<Deleted Role: {role_id}>")
        
        embed.add_field(name="Employee Roles", value="\n".join(employee_roles), inline=False)
        
        if server_tier == "free":
            embed.add_field(name="⚠️ Free Tier Limitation", value="These roles are configured but won't take effect until you upgrade to Basic/Pro. Currently only admins can use timeclock functions.", inline=False)
    
    embed.add_field(name="Note", value="Administrators always have timeclock access regardless of role configuration.", inline=False)
    
    await interaction.response.send_message(embed=embed, ephemeral=True)


@tree.command(name="help", description="List all available slash commands")
@app_commands.guild_only()
async def help_command(interaction: discord.Interaction):
    # Get current server tier
    server_tier = get_server_tier(interaction.guild_id)
    tier_color = {"free": discord.Color.green(), "basic": discord.Color.blue(), "pro": discord.Color.purple()}
    
    embed = discord.Embed(
        title="📋 Complete Command Reference",
        description=f"**Current Plan:** {server_tier.title()}\n\n**All 20 available slash commands organized by function:**",
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
    
    # Check tier access for reports
    guild_id = interaction.guild_id
    server_tier = get_server_tier(guild_id)
    
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
        user_display_name = get_user_display_name(user, interaction.guild_id)
        filename = f"{user_display_name}_sample_report_{start_date}_to_{end_date}.csv"
        
        file = discord.File(
            io.BytesIO(fake_csv.encode('utf-8')), 
            filename=filename
        )
        
        user_display_name = get_user_display_name(user, interaction.guild_id)
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
        user_display_name = get_user_display_name(user, interaction.guild_id)
        await interaction.followup.send(
            f"📭 No completed timesheet entries found for **{user_display_name}** between {start_date} and {end_date}",
            ephemeral=True
        )
        return
    
    # Generate single CSV
    csv_content = await generate_csv_report(bot, sessions_data, interaction.guild_id, guild_tz_name)
    
    # Create file using display name preference at the beginning
    user_display_name = get_user_display_name(user, interaction.guild_id)
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
@app_commands.default_permissions(administrator=True)  
@app_commands.guild_only()
async def manual_cleanup(interaction: discord.Interaction):
    """Allow admins to manually trigger data cleanup"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        deleted_count = cleanup_old_sessions(interaction.guild_id)
        retention_days = get_retention_days(interaction.guild_id)
        tier = get_server_tier(interaction.guild_id)
        
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
        
    except Exception as e:
        await interaction.followup.send(
            f"❌ Error during cleanup: {str(e)}", 
            ephemeral=True
        )

class PurgeConfirmationView(discord.ui.View):
    """Confirmation view for purge command"""
    def __init__(self, guild_id: int):
        super().__init__(timeout=60.0)  # 60 second timeout
        self.guild_id = guild_id
        self.confirmed = False
    
    @discord.ui.button(label="✅ Yes, Purge Timeclock Data", style=discord.ButtonStyle.danger, custom_id="purge_yes")
    async def confirm_purge(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Handle purge confirmation"""
        if not user_has_admin_access(interaction.user):
            await interaction.response.send_message("❌ Only administrators can use this command.", ephemeral=True)
            return
        
        await interaction.response.defer(ephemeral=True)
        
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
            item.disabled = True

@tree.command(name="purge", description="Permanently delete timeclock data (preserves subscription)")
@app_commands.default_permissions(administrator=True)  
@app_commands.guild_only()
async def purge_data(interaction: discord.Interaction):
    """Allow admins to manually purge timeclock data only"""
    # Double-check admin status
    if not is_server_admin(interaction.user):
        await interaction.response.send_message("❌ Only server administrators can use this command.", ephemeral=True)
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
    view = PurgeConfirmationView(interaction.guild_id)
    
    await interaction.response.send_message(embed=embed, view=view, ephemeral=True)

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
    await interaction.response.defer(ephemeral=True)
    
    try:
        current_tier = get_server_tier(interaction.guild_id)
        
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
        checkout_url = create_secure_checkout_session(interaction.guild_id, plan)
        
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
    await interaction.response.defer(ephemeral=True)
    
    try:
        # Check current subscription status
        current_tier = get_server_tier(interaction.guild_id)
        
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
    await interaction.response.defer(ephemeral=True)
    
    try:
        with db() as conn:
            cursor = conn.execute("""
                SELECT tier, subscription_id, customer_id, expires_at, status
                FROM server_subscriptions 
                WHERE guild_id = ?
            """, (interaction.guild_id,))
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
        await interaction.response.send_message("❌ Access denied.", ephemeral=True)
        return
        
    await interaction.response.defer(ephemeral=True)
    
    try:
        guild_id = interaction.guild_id
        guild_name = interaction.guild.name if interaction.guild else "Unknown"
        
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
        await interaction.response.send_message("❌ Access denied.", ephemeral=True)
        return
        
    await interaction.response.defer(ephemeral=True)
    
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

if __name__ == "__main__":
    # Run database migrations first with exclusive locking
    print("🔧 Running database migrations...")
    run_migrations()
    
    # Initialize database tables
    init_db()
    
    if not TOKEN:
        raise SystemExit("Set DISCORD_TOKEN in your environment.")
    
    # Start health check server in a separate thread
    health_thread = threading.Thread(target=start_health_server, daemon=True)
    health_thread.start()
    print(f"✅ Health check server thread started")
    
    # Start daily cleanup scheduler
    schedule_daily_cleanup()
    
    # Start Discord bot (this will block)
    print(f"🤖 Starting Discord bot...")
    bot.run(TOKEN)
