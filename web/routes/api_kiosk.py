import os
import traceback
import logging
from flask import Blueprint, render_template, redirect, request, session, jsonify, current_app as app
from werkzeug.security import generate_password_hash, check_password_hash

from app import (
    require_auth, require_kiosk_access, require_kiosk_session, require_paid_api_access,
    get_flask_guild_access, get_all_user_guilds, is_demo_server, 
    __version__, CHANGELOG, verify_guild_access, Entitlements, UserRole, _parse_stickers,
    get_bot, flask_check_bot_access
)
from web.utils.db import get_db

kiosk_bp = Blueprint('api_kiosk', __name__)
@kiosk_bp.route("/kiosk/<guild_id>")
@require_kiosk_access
def kiosk_page(guild_id):
    """Render the kiosk control center for a specific guild"""
    return render_template("kiosk.html", guild_id=guild_id)

@kiosk_bp.route("/api/kiosk/<guild_id>/employees")
@require_kiosk_access
def api_kiosk_employees(guild_id):
    """Get all employees for the kiosk display optimized with CTE"""
    try:
        import threading
        import requests
        
        # Fire-and-forget background task to auto-prune ghost employees
        def prune_ghosts():
            try:
                bot_api_secret = os.getenv('BOT_API_SECRET')
                bot_port = os.getenv('BOT_API_PORT', '8081')
                response = requests.post(
                    f"http://127.0.0.1:{bot_port}/api/guild/{guild_id}/employees/prune-ghosts", 
                    headers={'Authorization': f'Bearer {bot_api_secret}'} if bot_api_secret else {},
                    timeout=2
                )
                if response.status_code != 200:
                    app.logger.warning(f"[Prune Ghosts] Bot API returned {response.status_code}: {response.text}")
            except Exception as e:
                import traceback
                app.logger.warning(f"Error kicking off prune_ghosts background thread: {e}\n{traceback.format_exc()}")
                
        threading.Thread(target=prune_ghosts, daemon=True).start()
        
        with get_db() as conn:
            # Check if kiosk customization is enabled for this guild
            settings_cursor = conn.execute("""
                SELECT COALESCE(allow_kiosk_customization, false) as allow_kiosk_customization
                FROM guild_settings WHERE guild_id = %s
            """, (int(guild_id),))
            settings_row = settings_cursor.fetchone()
            allow_kiosk_customization = settings_row['allow_kiosk_customization'] if settings_row else False
            
            # Using CTE (Common Table Expression) to optimize subqueries
            # This allows us to calculate counts for all employees in one pass 
            # rather than running a subquery per row, which scales much better.
            cursor = conn.execute("""
                WITH pending_counts AS (
                    SELECT user_id::text, COUNT(*) as count 
                    FROM time_adjustment_requests 
                    WHERE guild_id = %s AND status = 'pending'
                    GROUP BY user_id
                ),
                missing_punch_counts AS (
                    SELECT user_id::text, COUNT(*) as count
                    FROM timeclock_sessions
                    WHERE guild_id = %s 
                    AND clock_out_time IS NULL
                    AND clock_in_time < NOW() - INTERVAL '8 hours'
                    AND DATE(clock_in_time) > CURRENT_DATE - INTERVAL '7 days'
                    GROUP BY user_id
                )
                SELECT ep.user_id, ep.display_name, ep.first_name, ep.last_name, ep.avatar_url,
                       ep.position, ep.department, ep.email, ep.timesheet_email, ep.accent_color, ep.profile_background,
                       ep.catchphrase, ep.selected_stickers,
                       EXISTS(SELECT 1 FROM employee_pins WHERE guild_id = %s AND user_id = ep.user_id) as has_pin,
                       EXISTS(SELECT 1 FROM timeclock_sessions WHERE guild_id = %s AND user_id::text = ep.user_id::text AND clock_out_time IS NULL) as is_clocked_in,
                       COALESCE(pc.count, 0) as pending_requests,
                       COALESCE(mpc.count, 0) as missing_punches
                FROM employee_profiles ep
                LEFT JOIN pending_counts pc ON pc.user_id = ep.user_id::text
                LEFT JOIN missing_punch_counts mpc ON mpc.user_id = ep.user_id::text
                WHERE ep.guild_id = %s AND ep.is_active = TRUE
                ORDER BY COALESCE(ep.display_name, ep.first_name, ep.user_id::text)
            """, (str(guild_id), str(guild_id), int(guild_id), str(guild_id), int(guild_id)))
            employees = cursor.fetchall()
        
        employee_list = []
        for emp in employees:
            display_name = emp['display_name'] or f"{emp['first_name'] or ''} {emp['last_name'] or ''}".strip() or f"User {emp['user_id']}"
            has_email = bool(emp.get('timesheet_email') or emp.get('email'))
            pending_requests = emp.get('pending_requests', 0)
            missing_punches = emp.get('missing_punches', 0)
            has_alerts = not has_email or pending_requests > 0 or missing_punches > 0
            
            employee_list.append({
                'user_id': str(emp['user_id']),
                'display_name': display_name,
                'avatar_url': emp['avatar_url'],
                'position': emp['position'],
                'has_pin': emp['has_pin'],
                'is_clocked_in': emp['is_clocked_in'],
                'has_email': has_email,
                'has_alerts': has_alerts,
                'pending_requests': pending_requests,
                'missing_punches': missing_punches,
                'accent_color': emp.get('accent_color') or 'cyan',
                'profile_background': emp.get('profile_background') or 'default',
                'catchphrase': emp.get('catchphrase') or '',
                'selected_stickers': _parse_stickers(emp.get('selected_stickers'))
            })
        
        return jsonify({
            'success': True, 
            'employees': employee_list,
            'allow_kiosk_customization': allow_kiosk_customization
        })
    except Exception as e:
        app.logger.error(f"Error fetching kiosk employees: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@kiosk_bp.route("/api/kiosk/<guild_id>/pin/create", methods=["POST"])
@require_kiosk_access
def api_kiosk_create_pin(guild_id):
    """Create a PIN for an employee"""
    try:
        import hashlib
        data = request.get_json()
        user_id = data.get('user_id')
        pin = data.get('pin')

        if not user_id or not pin or len(pin) != 4 or not pin.isdigit():
            return jsonify({'success': False, 'error': 'Invalid PIN format'}), 400

        # Hash the PIN
        pin_hash = hashlib.sha256(f"{guild_id}:{user_id}:{pin}".encode()).hexdigest()
        
        with get_db() as conn:
            conn.execute("""
                INSERT INTO employee_pins (guild_id, user_id, pin_hash)
                VALUES (%s, %s, %s)
                ON CONFLICT (guild_id, user_id) 
                DO UPDATE SET pin_hash = EXCLUDED.pin_hash, updated_at = NOW()
            """, (str(guild_id), str(user_id), pin_hash))
        
        app.logger.info(f"PIN created for user {user_id} in guild {guild_id}")
        return jsonify({'success': True})
    except Exception as e:
        app.logger.error(f"Error creating PIN: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@kiosk_bp.route("/api/kiosk/<guild_id>/pin/verify", methods=["POST"])
@require_kiosk_access
def api_kiosk_verify_pin(guild_id):
    """Verify an employee's PIN"""
    try:
        import hashlib
        data = request.get_json()
        user_id = data.get('user_id')
        pin = data.get('pin')
        
        if not user_id or not pin:
            return jsonify({'success': False, 'error': 'Missing credentials'}), 400
        
        # Brute Force Protection
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if client_ip:
            client_ip = client_ip.split(',')[0].strip()
        else:
            client_ip = 'unknown'
            
        rate_limit_key = f"kiosk_pin_attempts_{guild_id}_{user_id}_{client_ip}"
        
        # Simple memory-based rate limiting (in a real app, use Redis)
        if not hasattr(app, 'pin_attempts'):
            app.pin_attempts = {}
            
        import time
        now = time.time()
        
        # Cleanup old attempts (older than 15 minutes)
        app.pin_attempts = {k: v for k, v in app.pin_attempts.items() if now - v['time'] < 900}
        
        if rate_limit_key in app.pin_attempts:
            if app.pin_attempts[rate_limit_key]['count'] >= 5:
                # 15 minute lockout
                time_left = int(900 - (now - app.pin_attempts[rate_limit_key]['time']))
                return jsonify({
                    'success': False, 
                    'error': f'Too many failed attempts. Try again in {time_left // 60} minutes.',
                    'locked_out': True
                }), 429

        # Hash the PIN to compare
        pin_hash = hashlib.sha256(f"{guild_id}:{user_id}:{pin}".encode()).hexdigest()
        
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT pin_hash FROM employee_pins
                WHERE guild_id = %s AND user_id = %s
            """, (str(guild_id), str(user_id)))
            result = cursor.fetchone()
        
        if not result or result['pin_hash'] != pin_hash:
            # Record failed attempt
            if rate_limit_key not in app.pin_attempts:
                app.pin_attempts[rate_limit_key] = {'count': 1, 'time': now}
            else:
                app.pin_attempts[rate_limit_key]['count'] += 1
                app.pin_attempts[rate_limit_key]['time'] = now
                
            attempts_left = 5 - app.pin_attempts[rate_limit_key]['count']
            return jsonify({'success': False, 'error': f'Incorrect PIN. {attempts_left} attempts remaining.'}), 401
        
        # Reset attempts on success
        if rate_limit_key in app.pin_attempts:
            del app.pin_attempts[rate_limit_key]
            
        # Issue Session Shield Token
        session['active_kiosk_user'] = {
            'guild_id': guild_id,
            'user_id': user_id,
            'expires': now + 300 # 5 minute validity
        }
        
        return jsonify({'success': True})
    except Exception as e:
        app.logger.error(f"Error verifying PIN: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@kiosk_bp.route("/api/kiosk/<guild_id>/employee/<user_id>/info")
@require_kiosk_access
@require_kiosk_session
def api_kiosk_employee_info(guild_id, user_id):
    """Get employee info for the kiosk action screen"""
    try:
        from datetime import timedelta
        
        with get_db() as conn:
            # Get employee profile including customization
            cursor = conn.execute("""
                SELECT display_name, first_name, last_name, avatar_url, position, department, 
                       email, timesheet_email, accent_color, profile_background, catchphrase, selected_stickers
                FROM employee_profiles
                WHERE guild_id = %s AND user_id = %s
            """, (str(guild_id), str(user_id)))
            profile = cursor.fetchone()
            
            # Check if kiosk customization is allowed for this guild (use COALESCE for safety)
            cursor = conn.execute("""
                SELECT COALESCE(allow_kiosk_customization, false) as allow_kiosk_customization 
                FROM guild_settings WHERE guild_id = %s
            """, (str(guild_id),))
            guild_settings = cursor.fetchone()
            allow_customization = guild_settings['allow_kiosk_customization'] if guild_settings else False
            
            # Prefer timesheet_email over regular email
            employee_email = None
            if profile:
                employee_email = profile.get('timesheet_email') or profile.get('email')
            
            # Check if clocked in (using timeclock_sessions)
            cursor = conn.execute("""
                SELECT clock_in_time FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s AND clock_out_time IS NULL
                ORDER BY clock_in_time DESC LIMIT 1
            """, (str(guild_id), str(user_id)))
            active_session = cursor.fetchone()
            
            # Get today's hours (using timeclock_sessions)
            today = datetime.now().date()
            cursor = conn.execute("""
                SELECT COALESCE(SUM(EXTRACT(EPOCH FROM (clock_out_time - clock_in_time))), 0) as total
                FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s 
                AND DATE(clock_in_time) = %s AND clock_out_time IS NOT NULL
            """, (str(guild_id), str(user_id), today))
            today_result = cursor.fetchone()
            today_minutes = float(today_result['total'] or 0) / 60
            
            # Add current session time if clocked in
            if active_session:
                clock_in_time = active_session['clock_in_time']
                if clock_in_time.tzinfo:
                    elapsed = (datetime.now(clock_in_time.tzinfo) - clock_in_time).total_seconds()
                else:
                    elapsed = (datetime.now() - clock_in_time).total_seconds()
                today_minutes += elapsed / 60
            
            # Get week's hours (Monday to Sunday)
            week_start = today - timedelta(days=today.weekday())
            cursor = conn.execute("""
                SELECT COALESCE(SUM(EXTRACT(EPOCH FROM (clock_out_time - clock_in_time))), 0) as total
                FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s 
                AND DATE(clock_in_time) >= %s AND clock_out_time IS NOT NULL
            """, (str(guild_id), str(user_id), week_start))
            week_result = cursor.fetchone()
            week_minutes = float(week_result['total'] or 0) / 60 + (today_minutes if active_session else 0)
            
            # Get last punch
            cursor = conn.execute("""
                SELECT clock_in_time, clock_out_time FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s
                ORDER BY COALESCE(clock_out_time, clock_in_time) DESC LIMIT 1
            """, (str(guild_id), str(user_id)))
            last_session = cursor.fetchone()
            
            last_punch = None
            if last_session:
                if last_session['clock_out_time']:
                    last_punch = f"Clocked out {last_session['clock_out_time'].strftime('%I:%M %p on %b %d')}"
                else:
                    last_punch = f"Clocked in at {last_session['clock_in_time'].strftime('%I:%M %p')}"
            
            # Get pending time adjustment requests for this employee
            cursor = conn.execute("""
                SELECT id, request_type, created_at FROM time_adjustment_requests
                WHERE guild_id = %s AND user_id = %s AND status = 'pending'
                ORDER BY created_at DESC LIMIT 5
            """, (str(guild_id), str(user_id)))
            pending_requests = cursor.fetchall()
            
            # Get recently resolved requests (last 7 days)
            cursor = conn.execute("""
                SELECT id, request_type, status, reviewed_at FROM time_adjustment_requests
                WHERE guild_id = %s AND user_id = %s AND status IN ('approved', 'denied')
                AND reviewed_at > NOW() - INTERVAL '7 days'
                ORDER BY reviewed_at DESC LIMIT 5
            """, (str(guild_id), str(user_id)))
            resolved_requests = cursor.fetchall()
            
            # Check for missing punches (sessions from last 7 days without clock_out)
            cursor = conn.execute("""
                SELECT session_id, clock_in_time FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s 
                AND clock_out_time IS NULL
                AND clock_in_time < NOW() - INTERVAL '8 hours'
                AND DATE(clock_in_time) > CURRENT_DATE - INTERVAL '7 days'
                ORDER BY clock_in_time DESC
            """, (str(guild_id), str(user_id)))
            missing_punches = cursor.fetchall()
        
        # Build notifications list
        notifications = []
        
        # Missing punches
        for mp in missing_punches:
            clock_in_dt = mp['clock_in_time']
            notifications.append({
                'type': 'alert',
                'icon': '⚠️',
                'text': f"Missing clock-out from {clock_in_dt.strftime('%b %d at %I:%M %p')}"
            })
        
        # Pending requests
        for pr in pending_requests:
            req_type = pr['request_type'] or 'adjustment'
            notifications.append({
                'type': 'pending',
                'icon': '⏳',
                'text': f"Time {req_type} request pending review"
            })
        
        # Resolved requests
        for rr in resolved_requests:
            req_type = rr['request_type'] or 'adjustment'
            status = rr['status']
            if status == 'approved':
                notifications.append({
                    'type': 'approved',
                    'icon': '✅',
                    'text': f"Time {req_type} request was approved"
                })
            else:
                notifications.append({
                    'type': 'denied',
                    'icon': '❌',
                    'text': f"Time {req_type} request was denied"
                })
        
        # Determine if there are important alerts (missing punches, pending requests, or missing email)
        has_alerts = len(missing_punches) > 0 or len(pending_requests) > 0 or not employee_email
        
        # Build customization data (only if allowed by guild)
        customization = {}
        if allow_customization and profile:
            customization = {
                'accent_color': profile.get('accent_color') or 'cyan',
                'profile_background': profile.get('profile_background') or 'default',
                'catchphrase': profile.get('catchphrase') or '',
                'selected_stickers': _parse_stickers(profile.get('selected_stickers'))
            }
        
        return jsonify({
            'success': True,
            'avatar_url': profile['avatar_url'] if profile else None,
            'position': profile['position'] if profile else None,
            'email': employee_email,
            'is_clocked_in': active_session is not None,
            'today_hours': float(today_minutes),
            'week_hours': float(week_minutes),
            'last_punch': last_punch,
            'notifications': notifications,
            'has_alerts': has_alerts,
            'pending_requests_count': len(pending_requests),
            'missing_punches_count': len(missing_punches),
            'allow_customization': allow_customization,
            'customization': customization
        })
    except Exception as e:
        app.logger.error(f"Error fetching kiosk employee info: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Rate limiting cache for forgot-PIN requests
# Format: {key: last_request_time} where key can be guild:user, guild, or ip
_forgot_pin_rate_limit: dict[str, float] = {}
_forgot_pin_guild_limit: dict[str, float] = {}  # Per-guild limit (max 10 requests per 10 minutes per guild)
_forgot_pin_ip_limit: dict[str, float] = {}  # Per-IP limit (max 5 requests per 10 minutes per IP)

def _clean_old_rate_limits():
    """Clean up expired rate limit entries to prevent memory bloat"""
    current_time = time_module.time()
    cutoff = current_time - 1800  # 30 minutes
    for cache in [_forgot_pin_rate_limit, _forgot_pin_guild_limit, _forgot_pin_ip_limit]:
        expired_keys = [k for k, v in cache.items() if v < cutoff]
        for k in expired_keys:
            del cache[k]

@kiosk_bp.route("/api/kiosk/<guild_id>/forgot-pin", methods=["POST"])
@require_kiosk_access
def api_kiosk_forgot_pin(guild_id):
    """Handle forgot PIN request - logs the request and can notify admin
    
    Security measures:
    - Per-user rate limit: 1 request per 5 minutes
    - Per-guild rate limit: 10 requests per 10 minutes
    - Per-IP rate limit: 5 requests per 10 minutes
    - Employee validation (no enumeration leaks)
    """
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        display_name = data.get('display_name', 'Unknown')
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        
        if not user_id:
            return jsonify({'success': False, 'error': 'Missing user ID'}), 400
        
        current_time = time_module.time()
        
        # Clean old entries occasionally
        if len(_forgot_pin_rate_limit) > 1000:
            _clean_old_rate_limits()
        
        # Per-IP rate limit: Max 5 requests per 10 minutes
        ip_key = f"ip:{client_ip}"
        ip_requests = _forgot_pin_ip_limit.get(ip_key, [])
        ip_requests = [t for t in ip_requests if current_time - t < 600]
        if len(ip_requests) >= 5:
            app.logger.warning(f"IP rate limited forgot PIN request from {client_ip}")
            return jsonify({'success': True, 'message': 'Too many requests. Please try again later.'})
        
        # Per-guild rate limit: Max 10 requests per 10 minutes
        guild_key = f"guild:{guild_id}"
        guild_requests = _forgot_pin_guild_limit.get(guild_key, [])
        guild_requests = [t for t in guild_requests if current_time - t < 600]
        if len(guild_requests) >= 10:
            app.logger.warning(f"Guild rate limited forgot PIN request for guild {guild_id}")
            return jsonify({'success': True, 'message': 'Too many requests for this server. Please try again later.'})
        
        # Per-user rate limit: 1 request per 5 minutes
        user_key = f"{guild_id}:{user_id}"
        last_request = _forgot_pin_rate_limit.get(user_key, 0)
        if current_time - last_request < 300:
            remaining = int(300 - (current_time - last_request))
            app.logger.warning(f"User rate limited forgot PIN request for {user_id} in guild {guild_id}")
            return jsonify({'success': True, 'message': f'Request already submitted. Please wait {remaining // 60} minutes.'})
        
        # Validate user exists as an employee in this guild (security: prevent enumeration attacks)
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT user_id FROM employee_profiles
                WHERE guild_id = %s AND user_id = %s
            """, (str(guild_id), str(user_id)))
            if not cursor.fetchone():
                # Don't reveal whether user exists - return generic success
                app.logger.warning(f"Forgot PIN request for non-existent user {user_id} in guild {guild_id}")
                return jsonify({'success': True, 'message': 'If this employee exists, admin has been notified'})
        
        # Update all rate limits
        _forgot_pin_rate_limit[user_key] = current_time
        _forgot_pin_ip_limit[ip_key] = ip_requests + [current_time]
        _forgot_pin_guild_limit[guild_key] = guild_requests + [current_time]
        
        # Log the forgot PIN request
        app.logger.info(f"FORGOT PIN REQUEST: User {display_name} (ID: {user_id}) in guild {guild_id} requested PIN reset")

        # Demo server protection - no emails in demo mode
        if is_demo_server(guild_id):
            app.logger.info(f"Demo server: Blocking forgot PIN email for guild {guild_id}")
            return jsonify({
                'success': True,
                'message': 'PIN reset request sent to admins'
            }), 200

        # Try to send notification email to verified report recipients
        try:
            with get_db() as conn:
                recipients_cursor = conn.execute(
                    """SELECT email_address FROM report_recipients 
                       WHERE guild_id = %s AND recipient_type = 'email' 
                       AND verification_status = 'verified'""",
                    (str(guild_id),)
                )
                recipients = [row['email_address'] for row in recipients_cursor.fetchall()]
                
                if recipients:
                    import asyncio
                    from email_utils import send_email
                    
                    subject = f"PIN Reset Request - {display_name}"
                    text_content = f"""An employee has requested a PIN reset.

Employee: {display_name}
User ID: {user_id}

Please assist this employee in resetting their kiosk PIN.

- Time Warden Bot"""
                    
                    def send_notification():
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        try:
                            loop.run_until_complete(send_email(to=recipients, subject=subject, text=text_content))
                        finally:
                            loop.close()
                    
                    import threading
                    thread = threading.Thread(target=send_notification, daemon=True)
                    thread.start()
        except Exception as email_err:
            app.logger.warning(f"Failed to send forgot PIN notification email: {email_err}")
        
        return jsonify({'success': True, 'message': 'Admin has been notified'})
    except Exception as e:
        app.logger.error(f"Error handling forgot PIN request: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@kiosk_bp.route("/api/kiosk/<guild_id>/clock", methods=["POST"])
@require_kiosk_access
@require_kiosk_session
def api_kiosk_clock(guild_id):
    """Handle clock in/out from kiosk - uses timeclock_sessions for dashboard sync"""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        action = data.get('action')  # 'in' or 'out'

        if not user_id or action not in ['in', 'out']:
            return jsonify({'success': False, 'error': 'Invalid request'}), 400

        now = datetime.now()
        
        # Guild-based locks to prevent double-tap DB spawns on slow Kiosk tablets
        import threading
        if not hasattr(app, 'guild_kiosk_locks'):
            app.guild_kiosk_locks = {}
        if guild_id not in app.guild_kiosk_locks:
            app.guild_kiosk_locks[guild_id] = threading.Lock()
            
        with app.guild_kiosk_locks[guild_id]:
            with get_db() as conn:
                if action == 'in':
                    # Check not already clocked in (using timeclock_sessions)
                    cursor = conn.execute("""
                        SELECT session_id FROM timeclock_sessions
                        WHERE guild_id = %s AND user_id = %s AND clock_out_time IS NULL
                    """, (str(guild_id), str(user_id)))
                    if cursor.fetchone():
                        return jsonify({'success': False, 'message': 'Already clocked in'}), 400
                    
                    # Create new session in timeclock_sessions
                    conn.execute("""
                        INSERT INTO timeclock_sessions (guild_id, user_id, clock_in_time)
                        VALUES (%s, %s, %s)
                    """, (str(guild_id), str(user_id), now))
                    
                    app.logger.info(f"Kiosk clock IN: user {user_id} in guild {guild_id}")
                    
                    # Fire and forget role mutation and webhooks
                    from scheduler import discord_bot
                    if discord_bot:
                        import asyncio
                        from bot import mutate_employee_roles, dispatch_webhook_event
                        app.logger.info(f"Triggering asynchronous role sync and webhooks for {user_id} in {guild_id}")
                        asyncio.run_coroutine_threadsafe(mutate_employee_roles(int(guild_id), int(user_id), 'in'), discord_bot.loop)
                        asyncio.run_coroutine_threadsafe(
                            dispatch_webhook_event(int(guild_id), int(user_id), 'clock_in', {'timestamp': now.isoformat()}),
                            discord_bot.loop
                        )
                        
                else:  # action == 'out'
                    # Find active session in timeclock_sessions
                    cursor = conn.execute("""
                        SELECT session_id, clock_in_time FROM timeclock_sessions
                        WHERE guild_id = %s AND user_id = %s AND clock_out_time IS NULL
                        ORDER BY clock_in_time DESC LIMIT 1
                    """, (str(guild_id), str(user_id)))
                    session = cursor.fetchone()
                    
                    if not session:
                        return jsonify({'success': False, 'message': 'Not clocked in'}), 400
                    
                    # Update session with clock out time
                    conn.execute("""
                        UPDATE timeclock_sessions 
                        SET clock_out_time = %s
                        WHERE session_id = %s
                    """, (now, session['session_id']))
                    
                    app.logger.info(f"Kiosk clock OUT: user {user_id} in guild {guild_id}")
                    
                    # Fire and forget role mutation and webhooks
                    from scheduler import discord_bot
                    if discord_bot:
                        import asyncio
                        from bot import mutate_employee_roles, dispatch_webhook_event
                        app.logger.info(f"Triggering asynchronous role sync and webhooks for {user_id} in {guild_id}")
                        asyncio.run_coroutine_threadsafe(mutate_employee_roles(int(guild_id), int(user_id), 'out'), discord_bot.loop)
                        
                        duration_seconds = (now - session['clock_in_time']).total_seconds()
                        asyncio.run_coroutine_threadsafe(
                            dispatch_webhook_event(int(guild_id), int(user_id), 'clock_out', {
                                'timestamp': now.isoformat(),
                                'duration_minutes': round(duration_seconds / 60.0, 2)
                            }),
                            discord_bot.loop
                        )
                    
                    # Return session_id for email functionality
                    return jsonify({'success': True, 'action': action, 'session_id': session['session_id']})
        
        return jsonify({'success': True, 'action': action})
    except Exception as e:
        app.logger.error(f"Error with kiosk clock action: {e}")
        return jsonify({'success': False, 'error': "An internal error occurred."}), 500

@kiosk_bp.route("/api/kiosk/<guild_id>/employee/<user_id>/email", methods=["GET", "POST"])
@require_kiosk_access
def api_kiosk_employee_email(guild_id, user_id):
    """Get or save email for kiosk employee"""
    if request.method == "POST":
        # Save email
        try:
            data = request.get_json()
            email = data.get('email', '').strip()

            if not email:
                return jsonify({'success': False, 'error': 'Email is required'}), 400

            # Basic email validation
            import re
            if not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email):
                return jsonify({'success': False, 'error': 'Invalid email format'}), 400

            # Demo server protection - fake success, no DB write
            if is_demo_server(guild_id):
                app.logger.info(f"Demo server: Blocking email update for guild {guild_id}")
                return jsonify({
                    'success': True,
                    'message': 'Email address updated successfully',
                    'demo_note': f'In live server: Email {email} would be saved to employee profile',
                    'email': email
                }), 200
            
            with get_db() as conn:
                # Update both email and timesheet_email for consistency
                conn.execute("""
                    UPDATE employee_profiles 
                    SET email = %s, timesheet_email = %s
                    WHERE guild_id = %s AND user_id = %s
                """, (email, email, str(guild_id), str(user_id)))
            
            app.logger.info(f"Email updated for user {user_id} in guild {guild_id}")
            return jsonify({'success': True, 'email': email})
        except Exception as e:
            app.logger.error(f"Error saving employee email: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    # GET - retrieve email
    try:
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT email, timesheet_email FROM employee_profiles
                WHERE guild_id = %s AND user_id = %s
            """, (str(guild_id), str(user_id)))
            profile = cursor.fetchone()
            
            if profile:
                # Prefer timesheet_email if set, otherwise use regular email
                email = profile.get('timesheet_email') or profile.get('email')
                return jsonify({'success': True, 'email': email})
            
            return jsonify({'success': True, 'email': None})
    except Exception as e:
        app.logger.error(f"Error fetching employee email: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@kiosk_bp.route("/api/kiosk/<guild_id>/send-shift-email", methods=["POST"])
@require_kiosk_access
@require_kiosk_session
def api_kiosk_send_shift_email(guild_id):
    """Send shift summary email to employee after clock-out"""
    try:
        from email_utils import ReplitMailSender
        import asyncio
        import pytz
        
        data = request.get_json()
        if not data:
            app.logger.error("No JSON data received in shift email request")
            return jsonify({'success': False, 'error': 'Invalid request data'}), 400
        user_id = data.get('user_id')
        email = data.get('email')
        session_id = data.get('session_id')
        
        if not user_id or not email:
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400

        # Demo server protection - no emails in demo mode
        if is_demo_server(guild_id):
            app.logger.info(f"Demo server: Blocking shift email for guild {guild_id}")
            return jsonify({
                'success': True,
                'message': 'Shift summary email sent successfully'
            }), 200

        with get_db() as conn:
            # Get guild info
            cursor = conn.execute("""
                SELECT guild_name FROM bot_guilds WHERE guild_id = %s
            """, (str(guild_id),))
            guild_row = cursor.fetchone()
            guild_name = guild_row['guild_name'] if guild_row else 'Unknown Server'
            
            # Get guild timezone
            cursor = conn.execute("""
                SELECT timezone FROM guild_settings WHERE guild_id = %s
            """, (str(guild_id),))
            tz_row = cursor.fetchone()
            guild_tz_str = tz_row['timezone'] if tz_row else 'America/New_York'
            guild_tz = pytz.timezone(guild_tz_str)
            
            # Get employee name
            cursor = conn.execute("""
                SELECT first_name, last_name FROM employee_profiles
                WHERE guild_id = %s AND user_id = %s
            """, (str(guild_id), str(user_id)))
            emp_row = cursor.fetchone()
            emp_name = emp_row['first_name'] or emp_row['last_name'] if emp_row else 'Employee'
            
            # Get the session details
            if session_id:
                cursor = conn.execute("""
                    SELECT clock_in_time, clock_out_time FROM timeclock_sessions
                    WHERE session_id = %s
                """, (session_id,))
            else:
                # Fallback: get most recent completed session
                cursor = conn.execute("""
                    SELECT clock_in_time, clock_out_time FROM timeclock_sessions
                    WHERE guild_id = %s AND user_id = %s AND clock_out_time IS NOT NULL
                    ORDER BY clock_out_time DESC LIMIT 1
                """, (str(guild_id), str(user_id)))
            
            session = cursor.fetchone()
            
            if not session:
                return jsonify({'success': False, 'error': 'No session found'}), 400
            
            clock_in = session['clock_in_time']
            clock_out = session['clock_out_time']
            
            # Convert to guild timezone for display
            if clock_in.tzinfo is None:
                clock_in = pytz.utc.localize(clock_in)
            if clock_out.tzinfo is None:
                clock_out = pytz.utc.localize(clock_out)
            
            clock_in_local = clock_in.astimezone(guild_tz)
            clock_out_local = clock_out.astimezone(guild_tz)
            
            # Calculate duration
            duration = clock_out - clock_in
            hours = int(duration.total_seconds() // 3600)
            minutes = int((duration.total_seconds() % 3600) // 60)
            duration_str = f"{hours}h {minutes}m" if hours > 0 else f"{minutes}m"
            
            # Save email for future use
            cursor = conn.execute("""
                SELECT id FROM employee_profiles WHERE guild_id = %s AND user_id = %s
            """, (str(guild_id), str(user_id)))
            if cursor.fetchone():
                conn.execute("""
                    UPDATE employee_profiles SET timesheet_email = %s
                    WHERE guild_id = %s AND user_id = %s
                """, (email, str(guild_id), str(user_id)))
        
        # Build email content
        subject = f"Shift Summary - {clock_out_local.strftime('%B %d, %Y')}"
        
        html_content = f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #1a1f2e; color: #c9d1d9; padding: 30px; border-radius: 12px;">
            <div style="text-align: center; margin-bottom: 30px;">
                <h1 style="color: #D4AF37; margin: 0;">Time Warden</h1>
                <p style="color: #8b949e; margin: 5px 0 0 0;">{guild_name}</p>
            </div>
            
            <h2 style="color: #c9d1d9; border-bottom: 1px solid #30363d; padding-bottom: 10px;">Shift Summary</h2>
            
            <p>Hello {emp_name},</p>
            <p>Here is your shift summary for today:</p>
            
            <div style="background: rgba(212, 175, 55, 0.1); border: 1px solid rgba(212, 175, 55, 0.3); border-radius: 8px; padding: 20px; margin: 20px 0;">
                <table style="width: 100%; border-collapse: collapse;">
                    <tr>
                        <td style="padding: 8px 0; color: #8b949e;">Date:</td>
                        <td style="padding: 8px 0; text-align: right; font-weight: bold;">{clock_in_local.strftime('%A, %B %d, %Y')}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px 0; color: #8b949e;">Clock In:</td>
                        <td style="padding: 8px 0; text-align: right; font-weight: bold;">{clock_in_local.strftime('%I:%M %p')}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px 0; color: #8b949e;">Clock Out:</td>
                        <td style="padding: 8px 0; text-align: right; font-weight: bold;">{clock_out_local.strftime('%I:%M %p')}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px 0; color: #8b949e; border-top: 1px solid #30363d;">Total Time:</td>
                        <td style="padding: 8px 0; text-align: right; font-weight: bold; color: #D4AF37; border-top: 1px solid #30363d;">{duration_str}</td>
                    </tr>
                </table>
            </div>
            
            <p style="color: #8b949e; font-size: 12px; text-align: center; margin-top: 30px;">
                This is an automated message from Time Warden. Please do not reply to this email.
            </p>
        </div>
        """
        
        text_content = f"""
Shift Summary - {guild_name}

Hello {emp_name},

Here is your shift summary for today:

Date: {clock_in_local.strftime('%A, %B %d, %Y')}
Clock In: {clock_in_local.strftime('%I:%M %p')}
Clock Out: {clock_out_local.strftime('%I:%M %p')}
Total Time: {duration_str}

This is an automated message from Time Warden.
        """
        
        # Send email
        mail_sender = ReplitMailSender()
        
        # Detach into a background thread so the HTTP request completes instantaneously 
        # (Fixes "Sluggish UX" from synchronous SendGrid calls)
        def send_async_email(email_to, sub, ht, tx):
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(
                    mail_sender.send_email(
                        to=email_to,
                        subject=sub,
                        html=ht,
                        text=tx
                    )
                )
                app.logger.info(f"Background shift summary sent to {email_to}")
            except Exception as e:
                app.logger.error(f"Background email failed: {e}")
            finally:
                loop.close()

        threading.Thread(target=send_async_email, args=(email, subject, html_content, text_content), daemon=True).start()
        
        app.logger.info(f"Shift email queued for {email} for user {user_id}")
        return jsonify({'success': True})
            
    except Exception as e:
        app.logger.error(f"Error sending shift email: {e}")
        return jsonify({'success': False, 'error': "An internal error occurred."}), 500

@kiosk_bp.route("/api/server/<guild_id>/kiosk-mode", methods=["GET"])
@require_paid_api_access
def api_get_kiosk_mode(user_session, guild_id):
    """Get kiosk mode setting for a server"""
    try:
        guild, _ = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT kiosk_only_mode FROM guild_settings WHERE guild_id = %s
            """, (int(guild_id),))
            result = cursor.fetchone()
        
        return jsonify({
            'success': True,
            'kiosk_mode_only': bool(result.get('kiosk_only_mode', False)) if result else False
        })
    except Exception as e:
        app.logger.error(f"Error fetching kiosk mode: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@kiosk_bp.route("/api/server/<guild_id>/kiosk-mode", methods=["POST"])
@require_paid_api_access
def api_set_kiosk_mode(user_session, guild_id):
    """Set kiosk mode setting for a server"""
    try:
        guild, _ = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        data = request.get_json()
        kiosk_mode_only = bool(data.get('kiosk_mode_only', False))
        
        with get_db() as conn:
            cursor = conn.execute("SELECT guild_id FROM guild_settings WHERE guild_id = %s", (int(guild_id),))
            if cursor.fetchone():
                conn.execute("""
                    UPDATE guild_settings SET kiosk_only_mode = %s WHERE guild_id = %s
                """, (kiosk_mode_only, int(guild_id)))
            else:
                conn.execute("""
                    INSERT INTO guild_settings (guild_id, kiosk_only_mode) VALUES (%s, %s)
                """, (int(guild_id), kiosk_mode_only))
        
        app.logger.info(f"Kiosk mode set to {kiosk_mode_only} for guild {guild_id}")
        return jsonify({'success': True, 'kiosk_mode_only': kiosk_mode_only})
    except Exception as e:
        app.logger.error(f"Error setting kiosk mode: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@kiosk_bp.route("/api/kiosk/<guild_id>/employee/<user_id>/today-sessions")
@require_kiosk_access
@require_kiosk_session
def api_kiosk_today_sessions(guild_id, user_id):
    """Get today's sessions for a kiosk employee - used for time adjustment modal"""
    try:
        from datetime import datetime, timezone
        import pytz
        
        with get_db() as conn:
            # Get guild timezone
            cursor = conn.execute(
                "SELECT timezone FROM guild_settings WHERE guild_id = %s",
                (int(guild_id),)
            )
            tz_row = cursor.fetchone()
            guild_tz_str = tz_row['timezone'] if tz_row else 'America/New_York'
            guild_tz = pytz.timezone(guild_tz_str)
            
            # Calculate today's date range in guild timezone
            now_utc = datetime.now(timezone.utc)
            now_local = now_utc.astimezone(guild_tz)
            today_start = now_local.replace(hour=0, minute=0, second=0, microsecond=0)
            today_end = now_local.replace(hour=23, minute=59, second=59, microsecond=999999)
            
            # Convert to UTC for query
            today_start_utc = today_start.astimezone(timezone.utc)
            today_end_utc = today_end.astimezone(timezone.utc)
            
            # Get today's sessions
            cursor = conn.execute("""
                SELECT session_id, clock_in_time, clock_out_time,
                       EXTRACT(EPOCH FROM (COALESCE(clock_out_time, NOW()) - clock_in_time)) as duration_seconds
                FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s
                AND clock_in_time >= %s AND clock_in_time <= %s
                ORDER BY clock_in_time ASC
            """, (str(guild_id), str(user_id), today_start_utc, today_end_utc))
            
            sessions = []
            total_seconds = 0
            is_clocked_in = False
            
            for row in cursor.fetchall():
                clock_in_utc = row['clock_in_time']
                clock_out_utc = row['clock_out_time']
                
                # Convert to local time
                if clock_in_utc:
                    if clock_in_utc.tzinfo is None:
                        clock_in_utc = clock_in_utc.replace(tzinfo=timezone.utc)
                    clock_in_local = clock_in_utc.astimezone(guild_tz)
                else:
                    clock_in_local = None
                
                if clock_out_utc:
                    if clock_out_utc.tzinfo is None:
                        clock_out_utc = clock_out_utc.replace(tzinfo=timezone.utc)
                    clock_out_local = clock_out_utc.astimezone(guild_tz)
                else:
                    clock_out_local = None
                    is_clocked_in = True  # No clock out means currently clocked in
                
                duration = row['duration_seconds'] or 0
                total_seconds += duration
                
                sessions.append({
                    'session_id': row['session_id'],
                    'clock_in': clock_in_local.strftime('%H:%M') if clock_in_local else None,
                    'clock_in_iso': clock_in_utc.isoformat() if clock_in_utc else None,
                    'clock_out': clock_out_local.strftime('%H:%M') if clock_out_local else None,
                    'clock_out_iso': clock_out_utc.isoformat() if clock_out_utc else None,
                    'duration_minutes': int(duration / 60),
                    'is_active': clock_out_utc is None
                })
            
            return jsonify({
                'success': True,
                'sessions': sessions,
                'is_clocked_in': is_clocked_in,
                'today_total_minutes': int(total_seconds / 60),
                'date': now_local.strftime('%Y-%m-%d'),
                'timezone': guild_tz_str
            })
            
    except Exception as e:
        app.logger.error(f"Error fetching kiosk today sessions: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@kiosk_bp.route("/api/kiosk/<guild_id>/adjustment", methods=["POST"])
@require_kiosk_access
@require_kiosk_session
def api_kiosk_submit_adjustment(guild_id):
    """
    Submit a time adjustment request from the kiosk.
    Populates all required metadata fields for admin review compatibility.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400

        user_id = data.get('user_id')
        reason = data.get('reason', '').strip()
        changes = data.get('changes', [])

        if not user_id:
            return jsonify({'success': False, 'error': 'User ID is required'}), 400
        if not reason:
            return jsonify({'success': False, 'error': 'Please provide a reason for the adjustment'}), 400
        if not changes or len(changes) == 0:
            return jsonify({'success': False, 'error': 'No changes provided'}), 400

        # Demo server protection - fake success, no DB write
        if is_demo_server(guild_id):
            app.logger.info(f"Demo server: Blocking adjustment submission for guild {guild_id}")
            return jsonify({
                'success': True,
                'message': 'Time adjustment request submitted',
                'demo_note': 'In live server: Request would be submitted to admin for approval',
                'request_id': 'DEMO-001'
            }), 200
        
        user_id = int(user_id)
        guild_id_int = int(guild_id)
        
        from datetime import datetime, timezone
        import pytz
        
        created_requests = []
        
        with get_db() as conn:
            # Get guild timezone
            cursor = conn.execute(
                "SELECT timezone FROM guild_settings WHERE guild_id = %s",
                (guild_id_int,)
            )
            tz_row = cursor.fetchone()
            guild_tz_str = tz_row['timezone'] if tz_row else 'America/New_York'
            guild_tz = pytz.timezone(guild_tz_str)
            
            # Get today's date in proper format
            now_local = datetime.now(timezone.utc).astimezone(guild_tz)
            session_date_str = now_local.strftime('%Y-%m-%d')
            session_date = now_local.date()  # For DATE column
            
            for change in changes:
                session_id = change.get('session_id')
                new_clock_in = change.get('new_clock_in')
                new_clock_out = change.get('new_clock_out')
                is_new = change.get('is_new', False)
                
                # For new sessions
                if is_new:
                    if not new_clock_in or not new_clock_out:
                        continue  # Skip incomplete new sessions
                    
                    # Validate times - clock_out must be after clock_in
                    try:
                        date_parts = session_date_str.split('-')
                        in_parts = new_clock_in.split(':')
                        out_parts = new_clock_out.split(':')
                        
                        in_local = datetime(int(date_parts[0]), int(date_parts[1]), int(date_parts[2]),
                                           int(in_parts[0]), int(in_parts[1]))
                        out_local = datetime(int(date_parts[0]), int(date_parts[1]), int(date_parts[2]),
                                            int(out_parts[0]), int(out_parts[1]))
                        
                        # Validate clock_out is after clock_in
                        if out_local <= in_local:
                            app.logger.warning(f"Invalid time range: clock_out {out_local} <= clock_in {in_local}")
                            continue
                        
                        requested_clock_in = guild_tz.localize(in_local).astimezone(pytz.utc)
                        requested_clock_out = guild_tz.localize(out_local).astimezone(pytz.utc)
                        
                        # Check for overlapping sessions (handle NULL clock_out for active sessions)
                        cursor = conn.execute("""
                            SELECT session_id FROM timeclock_sessions
                            WHERE guild_id = %s AND user_id = %s
                            AND NOT (COALESCE(clock_out_time, NOW()) <= %s OR clock_in_time >= %s)
                        """, (str(guild_id), str(user_id), requested_clock_in, requested_clock_out))
                        
                        if cursor.fetchone():
                            app.logger.warning(f"Overlapping session detected for new entry")
                            continue  # Skip overlapping sessions
                        
                        # Calculate duration for new session
                        calculated_duration = int((requested_clock_out - requested_clock_in).total_seconds())
                        
                        # Insert adjustment request for new session with all metadata
                        cursor = conn.execute("""
                            INSERT INTO time_adjustment_requests 
                            (guild_id, user_id, request_type, original_session_id,
                             requested_clock_in, requested_clock_out, reason, status, source,
                             session_date, calculated_duration)
                            VALUES (%s, %s, 'add_session', NULL, %s, %s, %s, 'pending', 'kiosk', %s, %s)
                            RETURNING id
                        """, (guild_id_int, user_id, requested_clock_in, requested_clock_out, 
                              reason, session_date, calculated_duration))
                        
                        result = cursor.fetchone()
                        if result:
                            created_requests.append(result['id'])
                            
                    except Exception as e:
                        app.logger.error(f"Error parsing new session times: {e}")
                        continue
                        
                else:
                    # Modifying existing session
                    if not session_id:
                        continue
                    
                    # Verify session belongs to user and get original data
                    cursor = conn.execute("""
                        SELECT session_id, clock_in_time, clock_out_time,
                               EXTRACT(EPOCH FROM (clock_out_time - clock_in_time))::integer as original_duration
                        FROM timeclock_sessions
                        WHERE session_id = %s AND guild_id = %s AND user_id = %s
                    """, (session_id, str(guild_id), str(user_id)))
                    
                    original = cursor.fetchone()
                    if not original:
                        continue  # Skip invalid sessions
                    
                    # Parse new times
                    requested_clock_in = None
                    requested_clock_out = None
                    clock_in_changed = False
                    clock_out_changed = False
                    
                    if new_clock_in:
                        try:
                            date_parts = session_date_str.split('-')
                            time_parts = new_clock_in.split(':')
                            local_dt = datetime(int(date_parts[0]), int(date_parts[1]), int(date_parts[2]),
                                               int(time_parts[0]), int(time_parts[1]))
                            requested_clock_in = guild_tz.localize(local_dt).astimezone(pytz.utc)
                            clock_in_changed = True
                        except Exception as e:
                            app.logger.error(f"Error parsing clock_in: {e}")
                    
                    if new_clock_out:
                        try:
                            date_parts = session_date_str.split('-')
                            time_parts = new_clock_out.split(':')
                            local_dt = datetime(int(date_parts[0]), int(date_parts[1]), int(date_parts[2]),
                                               int(time_parts[0]), int(time_parts[1]))
                            requested_clock_out = guild_tz.localize(local_dt).astimezone(pytz.utc)
                            clock_out_changed = True
                        except Exception as e:
                            app.logger.error(f"Error parsing clock_out: {e}")
                    
                    if not (clock_in_changed or clock_out_changed):
                        continue  # No actual changes
                    
                    # Determine request type based on what changed
                    if clock_in_changed and clock_out_changed:
                        request_type = 'modify_session'
                    elif clock_in_changed:
                        request_type = 'modify_clockin'
                    else:
                        request_type = 'modify_clockout'
                    
                    # Calculate new duration if both times are available
                    calculated_duration = None
                    final_clock_in = requested_clock_in if clock_in_changed else original['clock_in_time']
                    final_clock_out = requested_clock_out if clock_out_changed else original['clock_out_time']
                    
                    if final_clock_in and final_clock_out:
                        # Ensure both have timezone info
                        if final_clock_in.tzinfo is None:
                            final_clock_in = final_clock_in.replace(tzinfo=timezone.utc)
                        if final_clock_out.tzinfo is None:
                            final_clock_out = final_clock_out.replace(tzinfo=timezone.utc)
                        
                        # Check for overlapping sessions (exclude the session being modified)
                        cursor = conn.execute("""
                            SELECT session_id FROM timeclock_sessions
                            WHERE guild_id = %s AND user_id = %s AND session_id != %s
                            AND NOT (COALESCE(clock_out_time, NOW()) <= %s OR clock_in_time >= %s)
                        """, (str(guild_id), str(user_id), session_id, final_clock_in, final_clock_out))
                        
                        if cursor.fetchone():
                            app.logger.warning(f"Overlapping session detected for modification of session {session_id}")
                            continue  # Skip overlapping modifications
                        
                        calculated_duration = int((final_clock_out - final_clock_in).total_seconds())
                    
                    # Insert adjustment request with all metadata
                    cursor = conn.execute("""
                        INSERT INTO time_adjustment_requests 
                        (guild_id, user_id, request_type, original_session_id,
                         original_clock_in, original_clock_out, original_duration,
                         requested_clock_in, requested_clock_out, reason, status, source,
                         session_date, calculated_duration)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'pending', 'kiosk', %s, %s)
                        RETURNING id
                    """, (guild_id_int, user_id, request_type, session_id,
                          original['clock_in_time'], original['clock_out_time'], 
                          original['original_duration'],
                          requested_clock_in, requested_clock_out, reason,
                          session_date, calculated_duration))
                    
                    result = cursor.fetchone()
                    if result:
                        created_requests.append(result['id'])
        
        if created_requests:
            app.logger.info(f"Kiosk adjustment requests created: {created_requests} for user {user_id} in guild {guild_id}")
            return jsonify({
                'success': True,
                'message': 'Adjustment request submitted for admin review',
                'request_ids': created_requests
            })
        else:
            return jsonify({
                'success': False,
                'error': 'No valid changes to submit'
            }), 400
            
    except Exception as e:
        app.logger.error(f"Error submitting kiosk adjustment: {e}")

