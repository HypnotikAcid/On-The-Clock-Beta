import os
import json
import traceback
from datetime import datetime
import stripe
from stripe import SignatureVerificationError
from flask import request, jsonify, current_app as app
from flask import Blueprint, request, jsonify, current_app as app
billing_bp = Blueprint('billing', __name__)
from flask import Blueprint, request, jsonify, current_app as app
billing_bp = Blueprint('billing', __name__)
STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET')
STRIPE_PRICE_IDS = {
    'premium': os.environ.get('STRIPE_PRICE_PREMIUM'),
    'pro': os.environ.get('STRIPE_PRICE_PRO'),
}
STRIPE_PRICE_IDS_LEGACY = {
    'bot_access': os.environ.get('STRIPE_PRICE_BOT_ACCESS'),
    'retention_7day': os.environ.get('STRIPE_PRICE_RETENTION_7DAY'),
    'retention_30day': os.environ.get('STRIPE_PRICE_RETENTION_30DAY'),
}

def create_secure_checkout_session(guild_id: int, product_type: str, guild_name: str = "", apply_trial_coupon: bool = False) -> str:
    """Create a secure Stripe checkout session - implemented directly in app.py to avoid bot module import blocking."""
    if not stripe.api_key:
        raise ValueError("STRIPE_SECRET_KEY not configured")
    
    price_map = {
        'premium': os.environ.get('STRIPE_PRICE_PREMIUM'),
        'pro': os.environ.get('STRIPE_PRICE_PRO'),
    }
    
    if product_type not in price_map:
        raise ValueError(f"Invalid product_type: {product_type}")
    
    price_id = price_map[product_type]
    if not price_id:
        raise ValueError(f"Stripe price ID not configured for {product_type}")
    
    if os.getenv('REPLIT_ENVIRONMENT') == 'production':
        domain = 'time-warden.com'
    else:
        domains = os.getenv('REPLIT_DOMAINS', '')
        domain = domains.split(',')[0] if domains else 'localhost:5000'
    
    try:
        metadata = {
            'guild_id': str(guild_id),
            'product_type': product_type
        }
        if guild_name:
            metadata['guild_name'] = guild_name
        
        session_params = {
            'line_items': [{'price': price_id, 'quantity': 1}],
            'mode': 'subscription',
            'success_url': f'https://{domain}/success?session_id={{CHECKOUT_SESSION_ID}}',
            'cancel_url': f'https://{domain}/cancel',
            'metadata': metadata,
            'subscription_data': {'metadata': metadata},
        }
        
        if apply_trial_coupon:
            coupon_id = os.getenv('STRIPE_COUPON_FIRST_MONTH', 'sfaexZAF')
            try:
                coupon = stripe.Coupon.retrieve(coupon_id)
                if coupon.valid:
                    session_params['discounts'] = [{'coupon': coupon_id}]
                    metadata['trial_applied'] = 'true'
                    app.logger.info(f"[STRIPE] Coupon {coupon_id} validated and applied")
                else:
                    app.logger.warning(f"[STRIPE] Coupon {coupon_id} is no longer valid, skipping")
            except Exception as ce:
                app.logger.warning(f"[STRIPE] Coupon validation failed: {ce}, skipping coupon")
        
        app.logger.info(f"[STRIPE] Creating checkout session for guild {guild_id}, product {product_type}, trial={apply_trial_coupon}")
        app.logger.info(f"[STRIPE] Price ID: {price_id}, domain: {domain}")
        
        stripe.max_network_retries = 1
        checkout_session = stripe.checkout.Session.create(**session_params)
        app.logger.info(f"[STRIPE] Checkout session created: {checkout_session.id}")
        
        return checkout_session.url or ""
        
    except stripe.StripeError as e:
        app.logger.error(f"[STRIPE] Stripe API error: {e}")
        raise ValueError(f"Stripe error: {str(e)}")
    except Exception as e:
        app.logger.error(f"[STRIPE] Checkout creation failed: {e}")
        raise ValueError(f"Checkout creation failed: {str(e)}")

def log_purchase_and_notify(guild_id, guild_name, customer_email, customer_id, product_type, amount_cents, stripe_session_id):
    """Log purchase to history table and send email notification to owner"""
    try:
        # Log to purchase_history table (using Flask's get_db for production)
        with get_db() as conn:
            conn.execute("""
                INSERT INTO purchase_history 
                (guild_id, guild_name, customer_email, customer_id, product_type, amount_cents, stripe_session_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (guild_id, guild_name, customer_email, customer_id, product_type, amount_cents, stripe_session_id))
        
        app.logger.info(f"[OK] Purchase logged: {product_type} for guild {guild_id}")
        
        # Send email notification to owner
        owner_email = os.getenv('OWNER_EMAIL')
        if owner_email:
            from email_utils import send_email
            import asyncio
            
            product_display = {
                'premium': 'Premium ($8/mo)',
                'pro': 'Pro ($15/mo)',
                'bot_access': 'Bot Access (Legacy)',
                'retention_7day': '7-Day Retention (Legacy)',
                'retention_30day': '30-Day Retention (Legacy)'
            }.get(product_type, product_type)
            
            amount_display = f"${amount_cents / 100:.2f}" if amount_cents else "N/A"
            
            subject = f"New Purchase: {product_display}"
            text_content = f"""
New Purchase Notification

Product: {product_display}
Amount: {amount_display}

Server Details:
- Guild ID: {guild_id}
- Guild Name: {guild_name}

Customer Details:
- Email: {customer_email or 'N/A'}
- Stripe Customer ID: {customer_id or 'N/A'}

Stripe Session: {stripe_session_id}

This purchase has been automatically processed and the customer should now have access.

---
Time Warden Bot - Purchase Notification
"""
            
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            
            loop.run_until_complete(send_email(
                to=[owner_email],
                subject=subject,
                text=text_content
            ))
            app.logger.info(f"[OK] Purchase notification email sent to owner for guild {guild_id}")
        else:
            app.logger.warning("[WARN] OWNER_EMAIL not configured - skipping purchase notification")
            
    except Exception as e:
        app.logger.error(f"[ERROR] Failed to log purchase or send notification: {e}")
        app.logger.error(traceback.format_exc())

def notify_owner_webhook_failure(event_type, error_message, guild_id=None):
    """Send email/discord alert to owner when a Stripe webhook fails."""
    try:
        # Respect Owner Toggles
        with get_db() as conn:
            cursor = conn.execute("SELECT alert_stripe_failures FROM owner_settings LIMIT 1")
            row = cursor.fetchone()
            if row and not row['alert_stripe_failures']:
                return
                
        owner_email = os.getenv('OWNER_EMAIL')
        if not owner_email:
            return
        from email_utils import queue_email
        subject = f"⚠️ Stripe Webhook Failed: {event_type}"
        text_content = f"""Stripe Webhook Failure Alert

Event Type: {event_type}
Error: {error_message}
Guild ID: {guild_id or 'N/A'}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}

Please check the deployment logs for more details.

---
Time Warden Bot - Webhook Alert
"""
        queue_email(
            email_type='webhook_failure',
            recipients=[owner_email],
            subject=subject,
            text_content=text_content,
            guild_id=guild_id
        )
        app.logger.info(f"[OK] Webhook failure alert queued for owner: {event_type}")
    except Exception as notify_err:
        app.logger.error(f"[ERROR] Could not queue webhook failure alert: {notify_err}")

@billing_bp.route("/webhook", methods=["POST"])
def stripe_webhook():
    """Handle Stripe webhook events"""
    payload = request.data
    sig_header = request.headers.get('stripe-signature')
    
    if not STRIPE_WEBHOOK_SECRET:
        app.logger.error("[ERROR] STRIPE_WEBHOOK_SECRET not configured")
        return jsonify({'error': 'Webhook secret not configured'}), 400
    
    if not sig_header:
        app.logger.error("[ERROR] Missing Stripe signature header")
        return jsonify({'error': 'Missing signature'}), 400
    
    try:
        # Verify webhook signature
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
        
        event_type = event.get('type')
        app.logger.info(f"≡ƒoo Processing Stripe webhook: {event_type}")
        
        # Handle different event types
        if event_type == 'checkout.session.completed':
            handle_checkout_completed(event['data']['object'])
        elif event_type == 'customer.subscription.created':
            handle_subscription_change(event['data']['object'])
        elif event_type == 'customer.subscription.updated':
            handle_subscription_change(event['data']['object'])
        elif event_type == 'customer.subscription.deleted':
            handle_subscription_cancellation(event['data']['object'])
        elif event_type == 'invoice.payment_succeeded':
            app.logger.info(f"[OK] Invoice payment succeeded: {event['data']['object'].get('id')}")
        elif event_type == 'invoice.payment_failed':
            handle_payment_failure(event['data']['object'])
        else:
            app.logger.info(f"[INFO] Unhandled Stripe event type: {event_type}")
        
        return jsonify({'received': True}), 200
        
    except SignatureVerificationError as e:
        app.logger.error(f"[ERROR] Invalid webhook signature: {e}")
        return jsonify({'error': 'Invalid signature'}), 400
    except ValueError as e:
        app.logger.error(f"[ERROR] Invalid webhook payload: {e}")
        return jsonify({'error': 'Invalid payload'}), 400
    except Exception as e:
        app.logger.error(f"[ERROR] Error processing webhook: {e}")
        app.logger.error(traceback.format_exc())
        notify_owner_webhook_failure(locals().get('event_type', 'unknown'), str(e))
        return jsonify({'error': 'Internal error'}), 500

def handle_checkout_completed(session):
    """Process a completed checkout session - handles new subscription model"""
    try:
        full_session = stripe.checkout.Session.retrieve(
            session['id'],
            expand=['line_items']
        )
        
        price_id = None
        amount_cents = None
        if full_session.line_items and full_session.line_items.data:
            line_item = full_session.line_items.data[0]
            if line_item.price:
                price_id = line_item.price.id
            amount_cents = line_item.amount_total if hasattr(line_item, 'amount_total') else None
        
        if not price_id:
            app.logger.error("[ERROR] No price ID found in checkout session")
            return
        
        product_type = None
        all_price_ids = {**STRIPE_PRICE_IDS, **STRIPE_PRICE_IDS_LEGACY}
        for ptype, pid in all_price_ids.items():
            if pid == price_id:
                product_type = ptype
                break
        
        if not product_type:
            app.logger.error(f"[ERROR] Unknown price ID in checkout: {price_id}")
            return
        
        guild_id = session.get('metadata', {}).get('guild_id')
        guild_name = session.get('metadata', {}).get('guild_name', 'Unknown Server')
        
        if not guild_id:
            app.logger.error("[ERROR] No guild_id found in session metadata")
            return
        
        guild_id = int(guild_id)
        subscription_id = session.get('subscription')
        customer_id = session.get('customer')
        
        customer_email = None
        if full_session.customer_details:
            customer_email = full_session.customer_details.get('email')
        
        log_purchase_and_notify(
            guild_id=guild_id,
            guild_name=guild_name,
            customer_email=customer_email,
            customer_id=customer_id,
            product_type=product_type,
            amount_cents=amount_cents,
            stripe_session_id=session['id']
        )
        
        if product_type in ('premium', 'bot_access'):
            from app import flask_set_bot_access, flask_set_retention_tier
            flask_set_bot_access(guild_id, True)
            flask_set_retention_tier(guild_id, '30day')
            with get_db() as conn:
                conn.execute("""
                    INSERT INTO server_subscriptions (guild_id, subscription_id, customer_id, status, bot_access_paid, retention_tier, tier)
                    VALUES (%s, %s, %s, 'active', TRUE, '30day', 'premium')
                    ON CONFLICT(guild_id) DO UPDATE SET 
                        subscription_id = COALESCE(%s, server_subscriptions.subscription_id),
                        customer_id = COALESCE(%s, server_subscriptions.customer_id),
                        status = 'active',
                        bot_access_paid = TRUE,
                        retention_tier = '30day',
                        tier = 'premium'
                """, (guild_id, subscription_id, customer_id, subscription_id, customer_id))
            app.logger.info(f"[OK] Premium subscription activated for server {guild_id}")
            
        elif product_type == 'pro':
            from app import flask_set_bot_access, flask_set_retention_tier
            flask_set_bot_access(guild_id, True)
            flask_set_retention_tier(guild_id, '30day')
            with get_db() as conn:
                conn.execute("""
                    INSERT INTO server_subscriptions (guild_id, subscription_id, customer_id, status, bot_access_paid, retention_tier, tier)
                    VALUES (%s, %s, %s, 'active', TRUE, '30day', 'pro')
                    ON CONFLICT(guild_id) DO UPDATE SET 
                        subscription_id = COALESCE(%s, server_subscriptions.subscription_id),
                        customer_id = COALESCE(%s, server_subscriptions.customer_id),
                        status = 'active',
                        bot_access_paid = TRUE,
                        retention_tier = '30day',
                        tier = 'pro'
                """, (guild_id, subscription_id, customer_id, subscription_id, customer_id))
            app.logger.info(f"[OK] Pro subscription activated for server {guild_id}")
        
        elif product_type in ('retention_7day', 'retention_30day'):
            from app import flask_set_retention_tier
            retention_val = '7day' if product_type == 'retention_7day' else '30day'
            flask_set_retention_tier(guild_id, retention_val)
            with get_db() as conn:
                conn.execute("""
                    INSERT INTO server_subscriptions (guild_id, subscription_id, customer_id, status, bot_access_paid, retention_tier)
                    VALUES (%s, %s, %s, 'active', TRUE, %s)
                    ON CONFLICT(guild_id) DO UPDATE SET 
                        subscription_id = COALESCE(%s, server_subscriptions.subscription_id),
                        customer_id = COALESCE(%s, server_subscriptions.customer_id),
                        status = 'active',
                        bot_access_paid = TRUE,
                        retention_tier = %s
                """, (guild_id, subscription_id, customer_id, retention_val, subscription_id, customer_id, retention_val))
            app.logger.info(f"[OK] Legacy {retention_val} retention granted for server {guild_id}")
        
        trial_applied = session.get('metadata', {}).get('trial_applied')
        if trial_applied == 'true':
            try:
                with get_db() as conn:
                    conn.execute("""
                        INSERT INTO trial_usage (guild_id, grant_type)
                        VALUES (%s, 'checkout')
                        ON CONFLICT (guild_id) DO NOTHING
                    """, (guild_id,))
                app.logger.info(f"[OK] Trial usage recorded for server {guild_id} via checkout")
            except Exception as trial_error:
                app.logger.warning(f"Could not record trial usage: {trial_error}")
            
    except Exception as e:
        app.logger.error(f"[ERROR] Error processing checkout session: {e}")
        app.logger.error(traceback.format_exc())

def handle_subscription_change(subscription):
    """Handle subscription create/update events - status changes, plan changes.
    
    Deduplicates with checkout.session.completed: if the guild already has an active
    subscription with this subscription_id, only update status fields (don't re-process).
    """
    try:
        subscription_id = subscription.get('id')
        status = subscription.get('status')
        cancel_at_period_end = subscription.get('cancel_at_period_end', False)
        current_period_end = subscription.get('current_period_end')
        
        if not subscription_id:
            app.logger.error("[ERROR] No subscription ID in subscription change event")
            return
        
        guild_id = None
        metadata = subscription.get('metadata', {})
        if metadata.get('guild_id'):
            guild_id = int(metadata['guild_id'])
        
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT guild_id, status, bot_access_paid FROM server_subscriptions WHERE subscription_id = %s",
                (subscription_id,)
            )
            result = cursor.fetchone()
            
            if result:
                guild_id = result['guild_id']
                existing_status = result.get('status')
                already_active = result.get('bot_access_paid', False) and existing_status in ('active', 'trialing')
                
                if already_active and status in ('active', 'trialing'):
                    conn.execute("""
                        UPDATE server_subscriptions 
                        SET cancel_at_period_end = %s, current_period_end = %s
                        WHERE subscription_id = %s
                    """, (cancel_at_period_end, current_period_end, subscription_id))
                    app.logger.info(f"[OK] Subscription {subscription_id} already active for server {guild_id} - updated period fields only")
                    return
            elif guild_id:
                conn.execute("""
                    INSERT INTO server_subscriptions (guild_id, subscription_id, customer_id, status, bot_access_paid, cancel_at_period_end, current_period_end)
                    VALUES (%s, %s, %s, %s, TRUE, %s, %s)
                    ON CONFLICT(guild_id) DO UPDATE SET
                        subscription_id = COALESCE(EXCLUDED.subscription_id, server_subscriptions.subscription_id),
                        status = %s,
                        bot_access_paid = TRUE,
                        cancel_at_period_end = %s,
                        current_period_end = %s
                """, (guild_id, subscription_id, subscription.get('customer'), status, cancel_at_period_end, current_period_end, status, cancel_at_period_end, current_period_end))
                app.logger.info(f"[OK] Created subscription record for server {guild_id} from lifecycle event")
            else:
                app.logger.warning(f"[WARN] No server found for subscription {subscription_id} and no metadata")
                return
            
            conn.execute("""
                UPDATE server_subscriptions 
                SET status = %s,
                    cancel_at_period_end = %s,
                    current_period_end = %s
                WHERE subscription_id = %s
            """, (status, cancel_at_period_end, current_period_end, subscription_id))
            
            if status in ('active', 'trialing'):
                from app import flask_set_bot_access
                flask_set_bot_access(guild_id, True)
                app.logger.info(f"[OK] Subscription {subscription_id} active for server {guild_id}")
            elif status in ('past_due', 'unpaid'):
                app.logger.warning(f"[WARN] Subscription {subscription_id} is {status} for server {guild_id}")
            elif status == 'canceled':
                from app import flask_set_bot_access
                flask_set_bot_access(guild_id, False)
                app.logger.info(f"[OK] Subscription canceled, access revoked for server {guild_id}")
        
    except Exception as e:
        app.logger.error(f"[ERROR] Error processing subscription change: {e}")
        app.logger.error(traceback.format_exc())

def handle_subscription_cancellation(subscription):
    """Handle subscription deletion/cancellation events"""
    try:
        subscription_id = subscription.get('id')
        customer_id = subscription.get('customer')
        current_period_end = subscription.get('current_period_end')
        cancel_at_period_end = subscription.get('cancel_at_period_end', False)
        
        if not subscription_id:
            app.logger.error("[ERROR] No subscription ID in cancellation event")
            return
        
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT guild_id FROM server_subscriptions 
                WHERE subscription_id = %s OR customer_id = %s
            """, (subscription_id, customer_id))
            result = cursor.fetchone()
            
            if result:
                guild_id = result['guild_id']
                
                # Check if we should cancel immediately or at period end
                now_timestamp = int(datetime.now().timestamp())
                
                if current_period_end and current_period_end > now_timestamp:
                    # Cancel at period end - just update the flags
                    conn.execute("""
                        UPDATE server_subscriptions 
                        SET cancel_at_period_end = TRUE,
                            current_period_end = %s
                        WHERE guild_id = %s
                    """, (current_period_end, guild_id))
                    app.logger.info(f"[OK] Subscription set to cancel at period end for server {guild_id}")
                else:
                    # Immediate cancellation
                    from app import flask_set_bot_access, flask_set_retention_tier
                    flask_set_bot_access(guild_id, False)
                    flask_set_retention_tier(guild_id, 'none')
                    
                    conn.execute("""
                        UPDATE server_subscriptions 
                        SET status = 'canceled', 
                            subscription_id = NULL, 
                            bot_access_paid = FALSE,
                            cancel_at_period_end = FALSE
                        WHERE guild_id = %s
                    """, (guild_id,))
                    
                    app.logger.info(f"[OK] Subscription canceled for server {guild_id}, access revoked")
            else:
                app.logger.error(f"[ERROR] No guild found for subscription {subscription_id}")
                
    except Exception as e:
        app.logger.error(f"[ERROR] Error processing subscription cancellation: {e}")
        app.logger.error(traceback.format_exc())

def handle_payment_failure(invoice):
    """Handle payment failure events"""
    try:
        customer_id = invoice.get('customer')
        subscription_id = invoice.get('subscription')
        
        if not customer_id and not subscription_id:
            app.logger.error("[ERROR] No customer or subscription ID in payment failure event")
            return
        
        # Using Flask's get_db for production database
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT guild_id FROM server_subscriptions 
                WHERE subscription_id = %s OR customer_id = %s
            """, (subscription_id, customer_id))
            result = cursor.fetchone()
            
            if result:
                guild_id = result['guild_id']
                
                conn.execute("""
                    UPDATE server_subscriptions 
                    SET status = 'past_due'
                    WHERE guild_id = %s
                """, (guild_id,))
                
                app.logger.warning(f"[WARN] Payment failed: Guild {guild_id} marked as past_due")
                notify_owner_webhook_failure(
                    'invoice.payment_failed',
                    f"Payment failed for guild {guild_id}. Subscription marked as past_due.",
                    guild_id=guild_id
                )
            else:
                app.logger.error(f"[ERROR] No guild found for customer {customer_id}")
                
    except Exception as e:
        app.logger.error(f"[ERROR] Error processing payment failure: {e}")
        app.logger.error(traceback.format_exc())

