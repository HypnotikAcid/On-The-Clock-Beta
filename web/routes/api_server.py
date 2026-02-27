import os
import traceback
import logging
import pytz
from datetime import datetime
from flask import Blueprint, render_template, redirect, request, session, jsonify, current_app as app, send_file
import requests

from app import (
    require_auth, require_paid_api_access, get_flask_guild_access, get_all_user_guilds, is_demo_server, 
    __version__, CHANGELOG, get_db, verify_guild_access, Entitlements, UserRole,
    send_email, send_onboarding_email, sanitize_csv_string,
    _get_bot_module, get_bot_guild_ids, get_guild_roles_from_bot, get_guild_settings, get_guild_text_channels, validate_bot_api_url, validate_role_in_guild, _parse_stickers
)

api_server_bp = Blueprint('api_server', __name__)
@api_server_bp.route("/api/server/<guild_id>/admin-roles/add", methods=["POST"])
@require_paid_api_access
def api_add_admin_role(user_session, guild_id):
    """API endpoint to add an admin role - Proxies to bot API"""
    try:
        # Check for BOT_API_SECRET
        bot_api_secret = os.getenv('BOT_API_SECRET')
        if not bot_api_secret:
            app.logger.error("BOT_API_SECRET not configured")
            return jsonify({'success': False, 'error': 'Server configuration error - BOT_API_SECRET missing'}), 500

        # Validate guild_id format to prevent SSRF
        if not guild_id.isdigit() or len(guild_id) > 20:
            return jsonify({'success': False, 'error': 'Invalid guild ID format'}), 400

        # Verify user has access
        guild, _ = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403

        # Get role_id from request
        data = request.get_json()
        if not data or 'role_id' not in data:
            return jsonify({'success': False, 'error': 'Missing role_id'}), 400

        role_id = str(data['role_id'])

        # DEMO SERVER SECURITY: Restrict to safe role subset
        if is_demo_server(guild_id):
            if role_id not in DEMO_ALLOWED_ADMIN_ROLES:
                app.logger.warning(f"Demo server security: Blocked attempt to add non-whitelisted admin role {role_id}")
                return jsonify({
                    'success': False,
                    'error': 'Demo Mode: You can only map the designated Demo Admin role for security.'
                }), 403

        # Validate role belongs to guild
        if not validate_role_in_guild(guild_id, role_id):
            return jsonify({'success': False, 'error': 'Invalid role for this server'}), 400

        # Forward request to bot API (Bot as Boss)
        # Using constant base URL with validated guild_id (digits only, max 20 chars)
        bot_api_url = f"{BOT_API_BASE_URL}/api/guild/{guild_id}/admin-roles/add"
        
        # Validate URL to prevent SSRF
        if not validate_bot_api_url(bot_api_url):
            app.logger.error(f"SSRF protection: Invalid bot API URL rejected")
            return jsonify({'success': False, 'error': 'Invalid request'}), 400
        
        # Cryptographic Signature for Replay Defense
        import time, hmac, hashlib
        timestamp_str = str(time.time())
        signature = hmac.new(
            bot_api_secret.encode('utf-8'),
            timestamp_str.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        response = requests.post(
            bot_api_url,
            json={'role_id': role_id},
            headers={
                'Authorization': f'Bearer {bot_api_secret}',
                'X-Timestamp': timestamp_str,
                'X-Signature': signature
            },
            timeout=5
        )
        
        if response.ok:
            app.logger.info(f"Added admin role {role_id} to guild {guild_id} by user {user_session.get('username')}")
            return jsonify(response.json())
        else:
            app.logger.error(f"Bot API error: {response.status_code} - {response.text}")
            return jsonify({'success': False, 'error': 'Bot API error'}), response.status_code
            
    except Exception as e:
        app.logger.error(f"Error adding admin role: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@api_server_bp.route("/api/server/<guild_id>/admin-roles/remove", methods=["POST"])
@require_paid_api_access
def api_remove_admin_role(user_session, guild_id):
    """API endpoint to remove an admin role - Proxies to bot API"""
    try:
        # Check for BOT_API_SECRET
        bot_api_secret = os.getenv('BOT_API_SECRET')
        if not bot_api_secret:
            app.logger.error("BOT_API_SECRET not configured")
            return jsonify({'success': False, 'error': 'Server configuration error - BOT_API_SECRET missing'}), 500

        # Validate guild_id format to prevent SSRF
        if not guild_id.isdigit() or len(guild_id) > 20:
            return jsonify({'success': False, 'error': 'Invalid guild ID format'}), 400

        # Verify user has access
        guild, _ = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403

        # Get role_id from request
        data = request.get_json()
        if not data or 'role_id' not in data:
            return jsonify({'success': False, 'error': 'Missing role_id'}), 400

        role_id = str(data['role_id'])

        # DEMO SERVER SECURITY: Restrict to safe role subset
        if is_demo_server(guild_id):
            if role_id not in DEMO_ALLOWED_ADMIN_ROLES:
                app.logger.warning(f"Demo server security: Blocked attempt to remove non-whitelisted admin role {role_id}")
                return jsonify({
                    'success': False,
                    'error': 'Demo Mode: You can only manage the designated Demo Admin role for security.'
                }), 403

        # Validate role belongs to guild
        if not validate_role_in_guild(guild_id, role_id):
            return jsonify({'success': False, 'error': 'Invalid role for this server'}), 400

        # Forward request to bot API (Bot as Boss)
        # Using constant base URL with validated guild_id (digits only, max 20 chars)
        bot_api_url = f"{BOT_API_BASE_URL}/api/guild/{guild_id}/admin-roles/remove"
        
        # Validate URL to prevent SSRF
        if not validate_bot_api_url(bot_api_url):
            app.logger.error(f"SSRF protection: Invalid bot API URL rejected")
            return jsonify({'success': False, 'error': 'Invalid request'}), 400
        
        # Cryptographic Signature for Replay Defense
        import time, hmac, hashlib
        timestamp_str = str(time.time())
        signature = hmac.new(
            bot_api_secret.encode('utf-8'),
            timestamp_str.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        response = requests.post(
            bot_api_url,
            json={'role_id': role_id},
            headers={
                'Authorization': f'Bearer {bot_api_secret}',
                'X-Timestamp': timestamp_str,
                'X-Signature': signature
            },
            timeout=5
        )
        
        if response.ok:
            app.logger.info(f"Removed admin role {role_id} from guild {guild_id} by user {user_session.get('username')}")
            return jsonify(response.json())
        else:
            app.logger.error(f"Bot API error: {response.status_code} - {response.text}")
            return jsonify({'success': False, 'error': 'Bot API error'}), response.status_code
            
    except Exception as e:
        app.logger.error(f"Error removing admin role: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@api_server_bp.route("/api/server/<guild_id>/employee-roles/add", methods=["POST"])
@require_paid_api_access
def api_add_employee_role(user_session, guild_id):
    """API endpoint to add an employee role - Proxies to bot API"""
    try:
        # Check for BOT_API_SECRET
        bot_api_secret = os.getenv('BOT_API_SECRET')
        if not bot_api_secret:
            app.logger.error("BOT_API_SECRET not configured")
            return jsonify({'success': False, 'error': 'Server configuration error - BOT_API_SECRET missing'}), 500

        # Validate guild_id format to prevent SSRF
        if not guild_id.isdigit() or len(guild_id) > 20:
            return jsonify({'success': False, 'error': 'Invalid guild ID format'}), 400

        # Verify user has access
        guild, _ = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403

        # Get role_id from request
        data = request.get_json()
        if not data or 'role_id' not in data:
            return jsonify({'success': False, 'error': 'Missing role_id'}), 400

        role_id = str(data['role_id'])

        # DEMO SERVER SECURITY: Restrict to safe role subset
        if is_demo_server(guild_id):
            if role_id not in DEMO_ALLOWED_EMPLOYEE_ROLES:
                app.logger.warning(f"Demo server security: Blocked attempt to add non-whitelisted employee role {role_id}")
                return jsonify({
                    'success': False,
                    'error': 'Demo Mode: You can only map the designated Demo Employee role for security.'
                }), 403

        # Validate role belongs to guild
        if not validate_role_in_guild(guild_id, role_id):
            return jsonify({'success': False, 'error': 'Invalid role for this server'}), 400

        # Forward request to bot API (Bot as Boss)
        # Using constant base URL with validated guild_id (digits only, max 20 chars)
        bot_api_url = f"{BOT_API_BASE_URL}/api/guild/{guild_id}/employee-roles/add"
        
        # Validate URL to prevent SSRF
        if not validate_bot_api_url(bot_api_url):
            app.logger.error(f"SSRF protection: Invalid bot API URL rejected")
            return jsonify({'success': False, 'error': 'Invalid request'}), 400
        
        # Cryptographic Signature for Replay Defense
        import time, hmac, hashlib
        timestamp_str = str(time.time())
        signature = hmac.new(
            bot_api_secret.encode('utf-8'),
            timestamp_str.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        app.logger.info(f"≡ƒou Flask calling bot API: {bot_api_url} with role_id={role_id}")
        
        response = requests.post(
            bot_api_url,
            json={'role_id': role_id},
            headers={
                'Authorization': f'Bearer {bot_api_secret}',
                'X-Timestamp': timestamp_str,
                'X-Signature': signature
            },
            timeout=5
        )
        
        app.logger.info(f"≡ƒou Bot API response: status={response.status_code}, ok={response.ok}")
        
        if response.ok:
            app.logger.info(f"Added employee role {role_id} to guild {guild_id} by user {user_session.get('username')}")
            return jsonify(response.json())
        else:
            app.logger.error(f"Bot API error: {response.status_code} - {response.text}")
            return jsonify({'success': False, 'error': 'Bot API error'}), response.status_code
            
    except Exception as e:
        app.logger.error(f"Error adding employee role: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@api_server_bp.route("/api/server/<guild_id>/employee-roles/remove", methods=["POST"])
@require_paid_api_access
def api_remove_employee_role(user_session, guild_id):
    """API endpoint to remove an employee role - Proxies to bot API"""
    try:
        # Check for BOT_API_SECRET
        bot_api_secret = os.getenv('BOT_API_SECRET')
        if not bot_api_secret:
            app.logger.error("BOT_API_SECRET not configured")
            return jsonify({'success': False, 'error': 'Server configuration error - BOT_API_SECRET missing'}), 500

        # Validate guild_id format to prevent SSRF
        if not guild_id.isdigit() or len(guild_id) > 20:
            return jsonify({'success': False, 'error': 'Invalid guild ID format'}), 400

        # Verify user has access
        guild, _ = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403

        # Get role_id from request
        data = request.get_json()
        if not data or 'role_id' not in data:
            return jsonify({'success': False, 'error': 'Missing role_id'}), 400

        role_id = str(data['role_id'])

        # DEMO SERVER SECURITY: Restrict to safe role subset
        if is_demo_server(guild_id):
            if role_id not in DEMO_ALLOWED_EMPLOYEE_ROLES:
                app.logger.warning(f"Demo server security: Blocked attempt to remove non-whitelisted employee role {role_id}")
                return jsonify({
                    'success': False,
                    'error': 'Demo Mode: You can only manage the designated Demo Employee role for security.'
                }), 403

        # Validate role belongs to guild
        if not validate_role_in_guild(guild_id, role_id):
            return jsonify({'success': False, 'error': 'Invalid role for this server'}), 400

        # Forward request to bot API (Bot as Boss)
        # Using constant base URL with validated guild_id (digits only, max 20 chars)
        bot_api_url = f"{BOT_API_BASE_URL}/api/guild/{guild_id}/employee-roles/remove"
        
        # Validate URL to prevent SSRF
        if not validate_bot_api_url(bot_api_url):
            app.logger.error(f"SSRF protection: Invalid bot API URL rejected")
            return jsonify({'success': False, 'error': 'Invalid request'}), 400
        
        # Cryptographic Signature for Replay Defense
        import time, hmac, hashlib
        timestamp_str = str(time.time())
        signature = hmac.new(
            bot_api_secret.encode('utf-8'),
            timestamp_str.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        response = requests.post(
            bot_api_url,
            json={'role_id': role_id, 'user_id': user_session.get('user_id')},
            headers={
                'Authorization': f'Bearer {bot_api_secret}',
                'X-Timestamp': timestamp_str,
                'X-Signature': signature
            },
            timeout=5
        )
        
        if response.ok:
            app.logger.info(f"Removed employee role {role_id} from guild {guild_id} by user {user_session.get('username')}")
            return jsonify(response.json())
        else:
            app.logger.error(f"Bot API error: {response.status_code} - {response.text}")
            return jsonify({'success': False, 'error': 'Bot API error'}), response.status_code
            
    except Exception as e:
        app.logger.error(f"Error removing employee role: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@api_server_bp.route("/api/server/<guild_id>/timezone", methods=["POST"])
@require_paid_api_access
def api_update_timezone(user_session, guild_id):
    """API endpoint to update timezone"""
    try:
        # Verify user has access
        guild, _ = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Get timezone from request
        data = request.get_json()
        if not data or 'timezone' not in data:
            return jsonify({'success': False, 'error': 'Missing timezone'}), 400
        
        timezone_str = data['timezone']
        
        # Validate timezone
        try:
            from zoneinfo import ZoneInfo, available_timezones
            if timezone_str not in available_timezones():
                return jsonify({'success': False, 'error': 'Invalid timezone'}), 400
        except Exception as tz_error:
            app.logger.error(f"Timezone validation error: {str(tz_error)}")
            return jsonify({'success': False, 'error': 'Invalid timezone'}), 400
        
        # Update or insert guild settings
        with get_db() as conn:
            # Check if settings exist
            cursor = conn.execute("SELECT guild_id FROM guild_settings WHERE guild_id = %s", (guild_id,))
            exists = cursor.fetchone()
            
            if exists:
                conn.execute(
                    "UPDATE guild_settings SET timezone = %s WHERE guild_id = %s",
                    (timezone_str, guild_id)
                )
            else:
                conn.execute(
                    "INSERT INTO guild_settings (guild_id, timezone) VALUES (%s, %s)",
                    (guild_id, timezone_str)
                )
        
        app.logger.info(f"Updated timezone to {timezone_str} for guild {guild_id} by user {user_session.get('username')}")
        return jsonify({'success': True, 'message': 'Timezone updated successfully', 'timezone': timezone_str})
    except Exception as e:
        app.logger.error(f"Error updating timezone: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@api_server_bp.route("/api/server/<guild_id>/broadcast-channel", methods=["POST"])
@require_paid_api_access
def api_update_broadcast_channel(user_session, guild_id):
    """API endpoint to update broadcast channel setting"""
    try:
        # Verify user has access
        guild, _ = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Get channel_id from request
        data = request.get_json()
        if data is None:
            return jsonify({'success': False, 'error': 'Missing data'}), 400
        
        channel_id = data.get('channel_id')
        
        # Validate channel_id format (should be null or a numeric string)
        if channel_id is not None:
            if not isinstance(channel_id, str) or not channel_id.isdigit():
                return jsonify({'success': False, 'error': 'Invalid channel ID'}), 400
            channel_id = int(channel_id)
        
        # Update or insert guild settings
        with get_db() as conn:
            cursor = conn.execute("SELECT guild_id FROM guild_settings WHERE guild_id = %s", (guild_id,))
            exists = cursor.fetchone()
            
            if exists:
                conn.execute(
                    "UPDATE guild_settings SET broadcast_channel_id = %s WHERE guild_id = %s",
                    (channel_id, guild_id)
                )
            else:
                conn.execute(
                    "INSERT INTO guild_settings (guild_id, broadcast_channel_id) VALUES (%s, %s)",
                    (guild_id, channel_id)
                )
        
        app.logger.info(f"Updated broadcast channel to {channel_id} for guild {guild_id} by user {user_session.get('username')}")
        return jsonify({'success': True, 'message': 'Broadcast channel updated successfully'})
    except Exception as e:
        app.logger.error(f"Error updating broadcast channel: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@api_server_bp.route("/api/server/<guild_id>/email-settings", methods=["POST"])
@require_paid_api_access
def api_update_email_settings(user_session, guild_id):
    """API endpoint to update email settings"""
    try:
        # Verify user has access
        guild, _ = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Get email settings from request
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Missing data'}), 400
        
        auto_send_on_clockout = bool(data.get('auto_send_on_clockout', False))
        auto_email_before_delete = bool(data.get('auto_email_before_delete', False))
        subject_line = data.get('subject_line')
        reply_to_address = data.get('reply_to_address')
        cc_addresses = data.get('cc_addresses')
        
        # FAIL-SAFE: Check if any email recipients are configured before enabling email features
        if auto_send_on_clockout or auto_email_before_delete:
            with get_db() as conn:
                cursor = conn.execute(
                    "SELECT COUNT(*) as count FROM report_recipients WHERE guild_id = %s AND recipient_type = 'email'",
                    (guild_id,)
                )
                recipient_count = cursor.fetchone()['count']
                
                if recipient_count == 0:
                    return jsonify({
                        'success': False, 
                        'error': 'Please add at least one email recipient before enabling email automation features.',
                        'requires_recipients': True
                    }), 400
        
        # Update or insert email settings
        with get_db() as conn:
            # Check if settings exist
            cursor = conn.execute("SELECT guild_id FROM email_settings WHERE guild_id = %s", (guild_id,))
            exists = cursor.fetchone()
            
            if exists:
                conn.execute(
                    """UPDATE email_settings 
                       SET auto_send_on_clockout = %s, auto_email_before_delete = %s, subject_line = %s, reply_to_address = %s, cc_addresses = %s
                       WHERE guild_id = %s""",
                    (auto_send_on_clockout, auto_email_before_delete, subject_line, reply_to_address, cc_addresses, guild_id)
                )
            else:
                conn.execute(
                    """INSERT INTO email_settings (guild_id, auto_send_on_clockout, auto_email_before_delete, subject_line, reply_to_address, cc_addresses) 
                       VALUES (%s, %s, %s, %s, %s, %s)""",
                    (guild_id, auto_send_on_clockout, auto_email_before_delete, subject_line, reply_to_address, cc_addresses)
                )
            
            app.logger.info(f"[OK] Email settings committed for guild {guild_id} by user {user_session.get('username')}")
            
            return jsonify({
                'success': True, 
                'message': 'Email settings updated successfully',
                'auto_send_on_clockout': auto_send_on_clockout,
                'auto_email_before_delete': auto_email_before_delete,
                'subject_line': subject_line,
                'reply_to_address': reply_to_address,
                'cc_addresses': cc_addresses
            })
    except Exception as e:
        app.logger.error(f"Error updating email settings: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@api_server_bp.route("/api/server/<guild_id>/email-settings-status", methods=["GET"])
@require_paid_api_access
def api_get_email_settings_status(user_session, guild_id):
    """API endpoint to fetch email settings status for a server"""
    try:
        # Verify user has access
        guild, _ = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Fetch email settings
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT auto_send_on_clockout, auto_email_before_delete, subject_line, reply_to_address, cc_addresses FROM email_settings WHERE guild_id = %s",
                (guild_id,)
            )
            settings = cursor.fetchone()
            
        if settings:
            return jsonify({
                'success': True,
                'auto_send_on_clockout': settings['auto_send_on_clockout'],
                'auto_email_before_delete': settings['auto_email_before_delete'],
                'subject_line': settings['subject_line'],
                'reply_to_address': settings['reply_to_address'],
                'cc_addresses': settings['cc_addresses']
            })
        else:
            return jsonify({
                'success': True,
                'auto_send_on_clockout': True, # Default
                'auto_email_before_delete': True # Default
            })
    except Exception as e:
        app.logger.error(f"Error fetching email settings status: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error'}), 500

@api_server_bp.route("/api/server/<guild_id>/work-day-time", methods=["POST"])
@require_paid_api_access
def api_update_work_day_time(user_session, guild_id):
    """API endpoint to update work day end time"""
    try:
        # Verify user has access
        guild, _ = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Get work day end time from request
        data = request.get_json()
        if not data or 'work_day_end_time' not in data:
            return jsonify({'success': False, 'error': 'Missing work day end time'}), 400
        
        work_day_end_time = data['work_day_end_time']
        
        # Validate time format (HH:MM)
        import re
        if not re.match(r'^([01][0-9]|2[0-3]):[0-5][0-9]$', work_day_end_time):
            return jsonify({'success': False, 'error': 'Invalid time format. Use HH:MM'}), 400
        
        # FAIL-SAFE: Check if any email recipients are configured (work day end time triggers email reports)
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT COUNT(*) as count FROM report_recipients WHERE guild_id = %s AND recipient_type = 'email'",
                (guild_id,)
            )
            recipient_count = cursor.fetchone()['count']
            
            if recipient_count == 0:
                return jsonify({
                    'success': False, 
                    'error': 'Please add at least one email recipient before setting work day end time for automated reports.',
                    'requires_recipients': True
                }), 400
        
        # Update or insert guild settings
        with get_db() as conn:
            # Check if settings exist
            cursor = conn.execute("SELECT guild_id FROM guild_settings WHERE guild_id = %s", (guild_id,))
            exists = cursor.fetchone()
            
            if exists:
                conn.execute(
                    "UPDATE guild_settings SET work_day_end_time = %s WHERE guild_id = %s",
                    (work_day_end_time, guild_id)
                )
            else:
                # Insert with proper defaults for all columns
                conn.execute(
                    """INSERT INTO guild_settings (guild_id, timezone, name_display_mode, work_day_end_time) 
                       VALUES (%s, 'America/New_York', 'username', %s)""",
                    (guild_id, work_day_end_time)
                )
            
            app.logger.info(f"[OK] Work day end time committed: {work_day_end_time} for guild {guild_id}")
            
            return jsonify({'success': True, 'message': 'Work day end time updated successfully', 'work_day_end_time': work_day_end_time})
    except Exception as e:
        app.logger.error(f"Error updating work day end time: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@api_server_bp.route("/api/server/<guild_id>/kiosk-customization", methods=["POST"])
@require_paid_api_access
def api_update_kiosk_customization(user_session, guild_id):
    """API endpoint to update kiosk button customization setting"""
    try:
        guild, _ = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        data = request.get_json()
        if not data or 'allow_kiosk_customization' not in data:
            return jsonify({'success': False, 'error': 'Missing setting'}), 400
        
        allow_customization = bool(data['allow_kiosk_customization'])
        
        with get_db() as conn:
            conn.execute("""
                INSERT INTO guild_settings (guild_id, allow_kiosk_customization)
                VALUES (%s, %s)
                ON CONFLICT (guild_id) DO UPDATE SET allow_kiosk_customization = EXCLUDED.allow_kiosk_customization
            """, (guild_id, allow_customization))
            
            app.logger.info(f"[OK] Kiosk customization setting committed: {allow_customization} for guild {guild_id}")
            
            return jsonify({'success': True, 'allow_kiosk_customization': allow_customization})
    except Exception as e:
        app.logger.error(f"Error updating kiosk customization: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error'}), 500

@api_server_bp.route("/api/server/<guild_id>/email-recipients", methods=["GET"])
@require_paid_api_access
def api_get_email_recipients(user_session, guild_id):
    """API endpoint to fetch email recipients for a server"""
    try:
        guild, _ = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        with get_db() as conn:
            cursor = conn.execute(
                """SELECT id, email_address, created_at, 
                          COALESCE(verification_status, 'verified') as verification_status, 
                          verified_at
                   FROM report_recipients 
                   WHERE guild_id = %s AND recipient_type = 'email'
                   ORDER BY created_at DESC""",
                (guild_id,)
            )
            recipients = cursor.fetchall()
            
        emails = [
            {
                'id': row['id'],
                'email': row['email_address'],
                'created_at': row['created_at'],
                'verification_status': row['verification_status'],
                'verified_at': row.get('verified_at')
            }
            for row in recipients
        ]
        
        return jsonify({'success': True, 'emails': emails})
    except Exception as e:
        app.logger.error(f"Error fetching email recipients: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@api_server_bp.route("/api/server/<guild_id>/email-recipients/add", methods=["POST"])
@require_paid_api_access
def api_add_email_recipient(user_session, guild_id):
    """API endpoint to add an email recipient with verification"""
    try:
        guild, _ = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        data = request.get_json()
        if not data or 'email' not in data:
            return jsonify({'success': False, 'error': 'Missing email address'}), 400
        
        email = data['email'].strip().lower()
        
        import re
        import secrets
        import hashlib
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            return jsonify({'success': False, 'error': 'Invalid email address format'}), 400
        
        verification_code = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
        code_hash = hashlib.sha256(verification_code.encode()).hexdigest()
        
        with get_db() as conn:
            try:
                cursor = conn.execute(
                    """INSERT INTO report_recipients (guild_id, recipient_type, email_address, verification_status, verification_code_hash, verification_code_sent_at) 
                       VALUES (%s, 'email', %s, 'pending', %s, NOW())
                       RETURNING id""",
                    (guild_id, email, code_hash)
                )
                result = cursor.fetchone()
                recipient_id = result['id'] if result else None
                
                conn.execute("""
                    INSERT INTO email_settings (guild_id, auto_send_on_clockout, auto_email_before_delete)
                    VALUES (%s, TRUE, TRUE)
                    ON CONFLICT (guild_id) DO NOTHING
                """, (guild_id,))
                
                app.logger.info(f"[OK] Email recipient added (pending verification): {email} for guild {guild_id}")
                
            except psycopg2.IntegrityError:
                return jsonify({'success': False, 'error': 'Email address already exists'}), 400
            except Exception as db_error:
                app.logger.error(f"Database error adding email recipient: {db_error}")
                raise
        
        try:
            from email_utils import send_email
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            subject = "Verify your email for Time Warden"
            text_content = f"""Hello!

You've added this email to receive notifications from Time Warden.

Your verification code is: {verification_code}

Enter this code in the dashboard to verify your email address.

If you didn't request this, you can safely ignore this email.

- Time Warden Bot"""
            
            result = loop.run_until_complete(send_email(to=[email], subject=subject, text=text_content))
            loop.close()
            
            if result.get('success'):
                app.logger.info(f"[OK] Verification email sent to {email}")
            else:
                app.logger.warning(f"Failed to send verification email to {email}: {result.get('error')}")
        except Exception as email_error:
            app.logger.error(f"Error sending verification email: {email_error}")
        
        return jsonify({
            'success': True, 
            'message': 'Email added! Check your inbox for a verification code.', 
            'id': recipient_id, 
            'email': email,
            'verification_status': 'pending'
        })
    except Exception as e:
        app.logger.error(f"Error adding email recipient: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@api_server_bp.route("/api/server/<guild_id>/email-recipients/verify", methods=["POST"])
@require_paid_api_access
def api_verify_email_recipient(user_session, guild_id):
    """API endpoint to verify an email recipient with a code"""
    try:
        import hashlib
        
        guild, _ = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        data = request.get_json()
        if not data or 'id' not in data or 'code' not in data:
            return jsonify({'success': False, 'error': 'Missing recipient ID or verification code'}), 400
        
        recipient_id = int(data['id'])
        code = data['code'].strip()
        
        if not code.isdigit() or len(code) != 6:
            return jsonify({'success': False, 'error': 'Invalid code format. Enter the 6-digit code from your email.'}), 400
        
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        
        with get_db() as conn:
            cursor = conn.execute(
                """SELECT id, verification_code_hash, verification_status, verification_attempts, verification_code_sent_at
                   FROM report_recipients 
                   WHERE id = %s AND guild_id = %s AND recipient_type = 'email'""",
                (recipient_id, guild_id)
            )
            recipient = cursor.fetchone()
            
            if not recipient:
                return jsonify({'success': False, 'error': 'Recipient not found'}), 404
            
            if recipient['verification_status'] == 'verified':
                return jsonify({'success': True, 'message': 'Email already verified'})
            
            attempts = recipient['verification_attempts'] or 0
            if attempts >= 5:
                return jsonify({'success': False, 'error': 'Too many failed attempts. Please resend the verification code.'}), 429
            
            if recipient['verification_code_sent_at']:
                from datetime import datetime, timedelta
                import pytz
                code_sent_at = recipient['verification_code_sent_at']
                if code_sent_at.tzinfo is None:
                    code_sent_at = pytz.UTC.localize(code_sent_at)
                if datetime.now(pytz.UTC) - code_sent_at > timedelta(hours=24):
                    return jsonify({'success': False, 'error': 'Verification code expired. Please resend the code.'}), 400
            
            if recipient['verification_code_hash'] != code_hash:
                new_attempts = attempts + 1
                conn.execute(
                    "UPDATE report_recipients SET verification_attempts = %s WHERE id = %s",
                    (new_attempts, recipient_id)
                )
                remaining = max(0, 5 - new_attempts)
                return jsonify({'success': False, 'error': f'Incorrect code. {remaining} attempts remaining.'}), 400
            
            conn.execute(
                """UPDATE report_recipients 
                   SET verification_status = 'verified', verified_at = NOW(), verification_code_hash = NULL, verification_attempts = 0
                   WHERE id = %s""",
                (recipient_id,)
            )
            
            app.logger.info(f"[OK] Email verified for recipient {recipient_id} in guild {guild_id}")
            
        return jsonify({'success': True, 'message': 'Email verified successfully!'})
    except Exception as e:
        app.logger.error(f"Error verifying email: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@api_server_bp.route("/api/server/<guild_id>/email-recipients/resend", methods=["POST"])
@require_paid_api_access
def api_resend_verification(user_session, guild_id):
    """API endpoint to resend verification code"""
    try:
        import secrets
        import hashlib
        
        guild, _ = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        data = request.get_json()
        if not data or 'id' not in data:
            return jsonify({'success': False, 'error': 'Missing recipient ID'}), 400
        
        recipient_id = int(data['id'])
        
        with get_db() as conn:
            cursor = conn.execute(
                """SELECT id, email_address, verification_status, verification_code_sent_at
                   FROM report_recipients 
                   WHERE id = %s AND guild_id = %s AND recipient_type = 'email'""",
                (recipient_id, guild_id)
            )
            recipient = cursor.fetchone()
            
            if not recipient:
                return jsonify({'success': False, 'error': 'Recipient not found'}), 404
            
            if recipient['verification_status'] == 'verified':
                return jsonify({'success': True, 'message': 'Email already verified'})
            
            if recipient['verification_code_sent_at']:
                from datetime import datetime, timedelta
                import pytz
                code_sent_at = recipient['verification_code_sent_at']
                if code_sent_at.tzinfo is None:
                    code_sent_at = pytz.UTC.localize(code_sent_at)
                if datetime.now(pytz.UTC) - code_sent_at < timedelta(minutes=1):
                    return jsonify({'success': False, 'error': 'Please wait 1 minute before requesting a new code.'}), 429
            
            verification_code = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
            code_hash = hashlib.sha256(verification_code.encode()).hexdigest()
            
            conn.execute(
                """UPDATE report_recipients 
                   SET verification_code_hash = %s, verification_code_sent_at = NOW(), verification_attempts = 0
                   WHERE id = %s""",
                (code_hash, recipient_id)
            )
            
            email = recipient['email_address']
        
        try:
            from email_utils import send_email
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            subject = "Your new verification code for Time Warden"
            text_content = f"""Hello!

Here's your new verification code: {verification_code}

Enter this code in the dashboard to verify your email address.

- Time Warden Bot"""
            
            result = loop.run_until_complete(send_email(to=[email], subject=subject, text=text_content))
            loop.close()
            
            if result.get('success'):
                app.logger.info(f"[OK] Verification code resent to {email}")
            else:
                app.logger.warning(f"Failed to resend verification email to {email}: {result.get('error')}")
                return jsonify({'success': False, 'error': 'Failed to send email. Please try again.'}), 500
        except Exception as email_error:
            app.logger.error(f"Error resending verification email: {email_error}")
            return jsonify({'success': False, 'error': 'Failed to send email'}), 500
        
        return jsonify({'success': True, 'message': 'New verification code sent!'})
    except Exception as e:
        app.logger.error(f"Error resending verification: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@api_server_bp.route("/api/server/<guild_id>/email-recipients/remove", methods=["POST"])
@require_paid_api_access
def api_remove_email_recipient(user_session, guild_id):
    """API endpoint to remove an email recipient"""
    try:
        # Verify user has access
        guild, _ = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Get email ID from request
        data = request.get_json()
        if not data or 'id' not in data:
            return jsonify({'success': False, 'error': 'Missing recipient ID'}), 400
        
        recipient_id = data['id']
        
        # Remove from database
        with get_db() as conn:
            cursor = conn.execute(
                """DELETE FROM report_recipients 
                   WHERE id = %s AND guild_id = %s AND recipient_type = 'email'""",
                (recipient_id, guild_id)
            )
            
            if cursor.rowcount == 0:
                return jsonify({'success': False, 'error': 'Recipient not found'}), 404
            
            app.logger.info(f"[OK] Email recipient removed: {recipient_id} for guild {guild_id}")
            
            # FAIL-SAFE: Check remaining recipients and auto-disable email settings if none left
            remaining_cursor = conn.execute(
                "SELECT COUNT(*) as count FROM report_recipients WHERE guild_id = %s AND recipient_type = 'email'",
                (guild_id,)
            )
            remaining_count = remaining_cursor.fetchone()['count']
            
            email_settings_disabled = False
            if remaining_count == 0:
                # Auto-disable all email-dependent settings
                conn.execute(
                    "UPDATE email_settings SET auto_send_on_clockout = FALSE, auto_email_before_delete = FALSE WHERE guild_id = %s",
                    (guild_id,)
                )
                conn.execute(
                    "UPDATE guild_settings SET work_day_end_time = NULL WHERE guild_id = %s",
                    (guild_id,)
                )
                email_settings_disabled = True
                app.logger.info(f"[OK] Auto-disabled email settings for guild {guild_id} (no recipients remaining)")
            
            return jsonify({
                'success': True, 
                'message': 'Email recipient removed successfully',
                'remaining_count': remaining_count,
                'email_settings_disabled': email_settings_disabled
            })
    except Exception as e:
        app.logger.error(f"Error removing email recipient: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@api_server_bp.route("/api/server/<guild_id>/test-email", methods=["POST"])
@require_paid_api_access
def api_send_test_email(user_session, guild_id):
    """Send a test email to verify email setup is working"""
    try:
        guild, _ = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT email_address FROM report_recipients WHERE guild_id = %s AND recipient_type = 'email'",
                (guild_id,)
            )
            recipients = [row['email_address'] for row in cursor.fetchall()]
        
        if not recipients:
            return jsonify({'success': False, 'error': 'No email recipients configured. Add at least one email address first.'}), 400
        
        guild_name = guild.get('name', f'Server {guild_id}')
        
        from email_utils import send_email, log_email_to_file
        import asyncio
        
        subject = f"Test Email - {guild_name}"
        text_content = f"""Test Email from Time Warden

This is a test email to confirm your email setup is working correctly.

Server: {guild_name}
Recipients: {', '.join(recipients)}

If you received this email, your daily report emails are configured correctly!

---
Time Warden Discord Bot
https://time-warden.com
"""
        
        log_email_to_file(
            event_type="test_email_attempt",
            recipients=recipients,
            subject=subject,
            context={"guild_id": str(guild_id), "guild_name": guild_name, "source": "dashboard_test"}
        )
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(send_email(to=recipients, subject=subject, text=text_content))
        finally:
            loop.close()
        
        log_email_to_file(
            event_type="test_email_sent",
            recipients=recipients,
            subject=subject,
            context={"guild_id": str(guild_id), "result": str(result)},
            success=True
        )
        
        app.logger.info(f"[OK] Test email sent to {recipients} for guild {guild_id}")
        
        return jsonify({
            'success': True,
            'message': f'Test email sent to {len(recipients)} recipient(s)',
            'recipients': recipients
        })
        
    except Exception as e:
        app.logger.error(f"Error sending test email: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': f'Failed to send test email: {str(e)}'}), 500

@api_server_bp.route("/api/server/<guild_id>/data", methods=["GET"])
@require_api_auth  # Changed from require_paid_api_access to allow employees
def api_get_server_data(user_session, guild_id):
    """API endpoint to fetch server roles and settings for dashboard integration"""
    try:
        # Verify user has access (admin OR employee)
        guild, access_level = verify_guild_access(user_session, guild_id, allow_employee=True)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Check if bot is present
        bot_guild_ids = get_bot_guild_ids()
        if guild_id not in bot_guild_ids:
            return jsonify({'success': False, 'error': 'Bot not present in this server'}), 404
        
        # Determine user_role_tier based on access_level and Discord permissions
        if access_level == 'employee':
            user_role_tier = 'employee'
        elif guild.get('owner', False):
            user_role_tier = 'owner'
        else:
            permissions = int(guild.get('permissions', '0'))
            if permissions & 0x8:
                user_role_tier = 'admin'
            else:
                user_role_tier = 'employee'
        
        # For employees, only return limited data
        if access_level == 'employee':
            return jsonify({
                'success': True,
                'guild': guild,
                'roles': [],  # Employees don't need role list
                'text_channels': [],  # Employees don't need channel list
                'current_settings': {
                    'timezone': get_guild_settings(guild_id).get('timezone', 'America/New_York')
                },
                'current_user_id': user_session.get('user_id'),
                'user_role_tier': user_role_tier,
                'access_level': access_level
            })
        
        # For admins, return full data
        roles = get_guild_roles_from_bot(guild_id)
        if not roles:
            return jsonify({'success': False, 'error': 'Could not fetch server roles'}), 500
        
        current_settings = get_guild_settings(guild_id)
        text_channels = get_guild_text_channels(guild_id)
        
        return jsonify({
            'success': True,
            'guild': guild,
            'roles': roles,
            'text_channels': text_channels,
            'current_settings': current_settings,
            'current_user_id': user_session.get('user_id'),
            'user_role_tier': user_role_tier,
            'access_level': access_level
        })
    except Exception as e:
        app.logger.error(f"Error fetching server data: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500


@api_server_bp.route("/api/server/<guild_id>/settings", methods=["GET"])
@require_paid_api_access
def api_get_server_settings(user_session, guild_id):
    """API endpoint to fetch server settings for dashboard pages"""
    access = get_flask_guild_access(guild_id)
    if not access['is_exempt'] and access['tier'] == 'free' and not access['trial_active']:
        return jsonify({
            'success': False,
            'error': 'Your free trial has expired. Upgrade to Premium to continue.',
            'code': 'TRIAL_EXPIRED',
            'upgrade_url': f'/dashboard/purchase?guild_id={guild_id}',
            'trial_expired': True
        }), 403
    try:
        guild, access_level = verify_guild_access(user_session, guild_id, allow_employee=True)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        settings = get_guild_settings(guild_id)
        
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT bot_access_paid, retention_tier, tier, grandfathered, cancel_at_period_end, current_period_end
                FROM server_subscriptions WHERE guild_id = %s
            """, (int(guild_id),))
            sub_row = cursor.fetchone()
            if sub_row:
                settings['bot_access_paid'] = sub_row.get('bot_access_paid', False)
                settings['retention_tier'] = sub_row.get('retention_tier', 'none')
                settings['tier'] = sub_row.get('tier', 'free')
                from entitlements import Entitlements
                guild_tier = Entitlements.get_guild_tier(
                    bool(sub_row.get('bot_access_paid', False)),
                    sub_row.get('retention_tier', 'none'),
                    bool(sub_row.get('grandfathered', False))
                )
                settings['tier'] = guild_tier.value
                settings['retention_days'] = Entitlements.get_retention_days(guild_tier)
                settings['cancel_at_period_end'] = sub_row.get('cancel_at_period_end', False)
                settings['current_period_end'] = sub_row.get('current_period_end')
        
        settings['trial_info'] = {
            'is_trial': access['tier'] == 'free',
            'trial_active': access['trial_active'],
            'days_remaining': access['days_remaining'],
            'is_exempt': access['is_exempt']
        }
        
        return jsonify({'success': True, 'settings': settings})
    except Exception as e:
        app.logger.error(f"Error fetching server settings: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error'}), 500


@api_server_bp.route("/api/server/<guild_id>/settings", methods=["POST"])
@require_api_auth
def api_save_server_settings(user_session, guild_id):
    """API endpoint to save general server settings (admin only)"""
    try:
        guild, access_level = verify_guild_access(user_session, guild_id)
        if not guild or access_level != 'admin':
            return jsonify({'success': False, 'error': 'Access denied. Admin only.'}), 403
            
        data = request.json
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
            
        updates = {}
        if 'discord_log_channel_id' in data:
            val = data['discord_log_channel_id']
            updates['discord_log_channel_id'] = str(val) if val else None
        elif 'log_channel_id' in data:
            val = data['log_channel_id']
            updates['discord_log_channel_id'] = str(val) if val else None

        if 'discord_report_channel_id' in data:
            val = data['discord_report_channel_id']
            updates['discord_report_channel_id'] = str(val) if val else None
        elif 'report_channel_id' in data:
            val = data['report_channel_id']
            updates['discord_report_channel_id'] = str(val) if val else None
                
        if 'auto_prune_logs_days' in data:
            try:
                updates['auto_prune_logs_days'] = int(data['auto_prune_logs_days'])
            except ValueError:
                updates['auto_prune_logs_days'] = 0

        if 'auto_prune_reports_days' in data:
            try:
                updates['auto_prune_reports_days'] = int(data['auto_prune_reports_days'])
            except ValueError:
                updates['auto_prune_reports_days'] = 0
                
        if 'has_completed_onboarding' in data:
            updates['has_completed_onboarding'] = bool(data['has_completed_onboarding'])
            
        if 'report_name_format' in data:
            valid_formats = ['full_name', 'discord_username', 'discord_nickname_or_username', 'user_id_only']
            fmt = data['report_name_format']
            updates['report_name_format'] = fmt if fmt in valid_formats else 'full_name'
                
        # Legacy fallback
        if 'auto_prune_days' in data and 'auto_prune_logs_days' not in data:
            try:
                updates['auto_prune_logs_days'] = int(data['auto_prune_days'])
            except ValueError:
                pass
                
        if not updates:
            return jsonify({'success': False, 'error': 'No valid fields to update'}), 400
            
        set_clauses = []
        values = []
        for key, value in updates.items():
            set_clauses.append(f"{key} = %s")
            values.append(value)
            
        values.append(guild_id)
        query = f"UPDATE guild_settings SET {', '.join(set_clauses)} WHERE guild_id = %s"
        
        with get_db() as conn:
            # Handle unmigrated schemas gracefully
            try:
                conn.execute(query, tuple(values))
            except Exception as inner_e:
                if 'does not exist' in str(inner_e):
                    # Filter out new columns and try again
                    safe_updates = {}
                    for k, v in updates.items():
                        if k in ['discord_log_channel_id', 'has_completed_onboarding', 'report_name_format']:
                            safe_updates[k] = v
                    if not safe_updates:
                        return jsonify({'success': True, 'message': 'Schema not migrated, ignored new fields.'})
                    
                    set_clauses = [f"{k} = %s" for k in safe_updates.keys()]
                    safe_values = list(safe_updates.values()) + [guild_id]
                    q = f"UPDATE guild_settings SET {', '.join(set_clauses)} WHERE guild_id = %s"
                    conn.execute(q, tuple(safe_values))
                else:
                    raise inner_e
            
        return jsonify({'success': True, 'message': 'Settings updated successfully'})
    except Exception as e:
        app.logger.error(f"Error updating general settings for {guild_id}: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to save settings'}), 500


@api_server_bp.route("/api/server/<guild_id>/subscription/cancel", methods=["POST"])
@require_server_owner
def api_cancel_subscription(user_session, guild_id):
    """API endpoint to cancel a server's Stripe subscription at period end"""
    if is_demo_server(guild_id):
        return jsonify({'success': True, 'cancel_at_period_end': True, 'demo_note': 'Demo server subscriptions cannot be modified.'})
        
    try:
        # access_level verified by @require_server_owner
        with get_db() as conn:
            cursor = conn.execute("SELECT subscription_id FROM server_subscriptions WHERE guild_id = %s AND status IN ('active', 'trialing')", (int(guild_id),))
            sub_row = cursor.fetchone()
            if not sub_row or not sub_row['subscription_id']:
                return jsonify({'success': False, 'error': 'No active subscription found'}), 404
                
            subscription_id = sub_row['subscription_id']
            
            import stripe
            stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
            
            # Cancel at period end
            updated_sub = stripe.Subscription.modify(
                subscription_id,
                cancel_at_period_end=True
            )
            
            # Update local DB immediately
            conn.execute("""
                UPDATE server_subscriptions 
                SET cancel_at_period_end = TRUE,
                    current_period_end = %s
                WHERE subscription_id = %s
            """, (updated_sub.get('current_period_end'), subscription_id))
            
            return jsonify({
                'success': True, 
                'cancel_at_period_end': True,
                'current_period_end': updated_sub.get('current_period_end')
            })
            
    except Exception as e:
        app.logger.error(f"Error canceling subscription: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error'}), 500

@api_server_bp.route("/api/server/<guild_id>/subscription/resume", methods=["POST"])
@require_server_owner
def api_resume_subscription(user_session, guild_id):
    """API endpoint to resume a canceled server's Stripe subscription"""
    if is_demo_server(guild_id):
        return jsonify({'success': True, 'cancel_at_period_end': False, 'demo_note': 'Demo server subscriptions cannot be modified.'})
        
    try:
        # access_level verified by @require_server_owner
        with get_db() as conn:
            cursor = conn.execute("SELECT subscription_id FROM server_subscriptions WHERE guild_id = %s AND status IN ('active', 'trialing') AND cancel_at_period_end = TRUE", (int(guild_id),))
            sub_row = cursor.fetchone()
            if not sub_row or not sub_row['subscription_id']:
                return jsonify({'success': False, 'error': 'No pending cancellation found'}), 404
                
            subscription_id = sub_row['subscription_id']
            
            import stripe
            stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
            
            # Resume subscription
            updated_sub = stripe.Subscription.modify(
                subscription_id,
                cancel_at_period_end=False
            )
            
            # Update local DB immediately
            conn.execute("""
                UPDATE server_subscriptions 
                SET cancel_at_period_end = FALSE
                WHERE subscription_id = %s
            """, (subscription_id,))
            
            return jsonify({
                'success': True, 
                'cancel_at_period_end': False,
                'current_period_end': updated_sub.get('current_period_end')
            })
            
    except Exception as e:
        app.logger.error(f"Error resuming subscription: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error'}), 500


@api_server_bp.route("/api/server/<guild_id>/employees", methods=["GET"])
@require_api_auth
def api_get_server_employees(user_session, guild_id):
    """API endpoint to fetch employees for dashboard pages (admin only)"""
    access = get_flask_guild_access(guild_id)
    if not access['is_exempt'] and access['tier'] == 'free' and not access['trial_active']:
        return jsonify({
            'success': False,
            'error': 'Your free trial has expired. Upgrade to Premium to continue.',
            'code': 'TRIAL_EXPIRED',
            'upgrade_url': f'/dashboard/purchase?guild_id={guild_id}',
            'trial_expired': True
        }), 403
    try:
        guild, access_level = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Get guild timezone for accurate week calculation
        guild_settings = get_guild_settings(guild_id)
        guild_tz = guild_settings.get('timezone') or 'America/Chicago'
        
        employees = []
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT ep.user_id, ep.full_name, ep.display_name,
                       ep.is_active, ep.avatar_url, ep.welcome_dm_sent, 
                       ep.first_clock_used, ep.first_clock_at, ep.email,
                       (SELECT COUNT(*) > 0 FROM timeclock_sessions ts 
                        WHERE ts.user_id = ep.user_id AND ts.guild_id = ep.guild_id 
                        AND ts.clock_out_time IS NULL) as is_clocked_in,
                       (SELECT clock_in_time FROM timeclock_sessions ts 
                        WHERE ts.user_id = ep.user_id AND ts.guild_id = ep.guild_id 
                        AND ts.clock_out_time IS NULL ORDER BY clock_in_time DESC LIMIT 1) as current_session_start,
                       (SELECT COALESCE(SUM(EXTRACT(EPOCH FROM (COALESCE(clock_out_time, NOW()) - clock_in_time))), 0)
                        FROM timeclock_sessions ts 
                        WHERE ts.user_id = ep.user_id AND ts.guild_id = ep.guild_id
                        AND clock_in_time >= date_trunc('week', NOW() AT TIME ZONE %s)) / 60.0 as weekly_minutes,
                       (SELECT COUNT(*) FROM time_adjustment_requests tar
                        WHERE tar.user_id = ep.user_id AND tar.guild_id = ep.guild_id
                        AND tar.status = 'pending') as pending_adjustments,
                       (SELECT token FROM employee_profile_tokens ept
                        WHERE ept.user_id = ep.user_id AND ept.guild_id = ep.guild_id
                        AND ept.expires_at > NOW() LIMIT 1) IS NOT NULL as has_kiosk_pin
                FROM employee_profiles ep
                WHERE ep.guild_id = %s AND ep.is_active = TRUE
                ORDER BY COALESCE(ep.display_name, ep.full_name)
            """, (guild_tz, int(guild_id),))
            
            for row in cursor.fetchall():
                current_session_duration = None
                if row['is_clocked_in'] and row.get('current_session_start'):
                    duration_seconds = (datetime.now(pytz.UTC) - row['current_session_start'].replace(tzinfo=pytz.UTC)).total_seconds()
                    current_session_duration = int(duration_seconds / 60)
                
                employees.append({
                    'user_id': str(row['user_id']),
                    'username': row['full_name'] or '',
                    'display_name': row['display_name'] or row['full_name'] or 'Unknown',
                    'is_active': row['is_active'],
                    'is_clocked_in': row['is_clocked_in'],
                    'avatar_url': row['avatar_url'],
                    'current_session_duration': current_session_duration,
                    'weekly_minutes': round(row.get('weekly_minutes') or 0, 1),
                    'pending_adjustments': row.get('pending_adjustments') or 0,
                    'has_kiosk_pin': row.get('has_kiosk_pin') or False,
                    'welcome_dm_sent': row.get('welcome_dm_sent') or False,
                    'first_clock_used': row.get('first_clock_used') or False,
                    'has_email': bool(row.get('email'))
                })
        
        return jsonify({'success': True, 'employees': employees})
    except Exception as e:
        app.logger.error(f"Error fetching employees: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error'}), 500


@api_server_bp.route("/api/server/<guild_id>/employees/sync", methods=["POST"])
@require_api_auth
def api_sync_server_employees(user_session, guild_id):
    """API endpoint to sync employees from Discord roles into employee_profiles (admin only)"""
    access = get_flask_guild_access(guild_id)
    if not access['is_exempt'] and access['tier'] == 'free' and not access['trial_active']:
        return jsonify({
            'success': False,
            'error': 'Your free trial has expired. Upgrade to Premium to continue.',
            'code': 'TRIAL_EXPIRED',
            'upgrade_url': f'/dashboard/purchase?guild_id={guild_id}',
            'trial_expired': True
        }), 403
    try:
        guild, access_level = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Call bot API to sync employees
        bot_api_url = f"http://127.0.0.1:8081/api/guild/{guild_id}/employees/sync"
        bot_api_secret = os.environ.get('BOT_API_SECRET')
        
        if not bot_api_secret:
            bot_module = _get_bot_module()
            if bot_module:
                bot_api_secret = getattr(bot_module, 'BOT_API_SECRET', None)
        
        if not bot_api_secret:
            return jsonify({'success': False, 'error': 'Bot API not configured'}), 500
        
        import requests
        response = requests.post(
            bot_api_url,
            headers={'Authorization': f'Bearer {bot_api_secret}'},
            json={},
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            return jsonify({
                'success': True,
                'message': data.get('message', 'Employees synced'),
                'synced_count': data.get('synced_count', 0)
            })
        else:
            return jsonify({'success': False, 'error': f"Bot returned {response.status_code}"}), response.status_code
    except Exception as e:
        app.logger.error(f"Error syncing employees: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error'}), 500


@api_server_bp.route("/api/server/<guild_id>/kiosk-settings", methods=["POST"])
@require_api_auth
def api_save_kiosk_settings(user_session, guild_id):
    """API endpoint to save Kiosk-specific settings (admin only)"""
    try:
        guild, access_level = verify_guild_access(user_session, guild_id)
        if not guild or access_level != 'admin':
            return jsonify({'success': False, 'error': 'Access denied'}), 403
            
        data = request.json
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
            
        updates = {}
        if 'allow_kiosk_customization' in data:
            updates['allow_kiosk_customization'] = bool(data['allow_kiosk_customization'])
        
        if 'kiosk_only_mode' in data:
            updates['kiosk_only_mode'] = bool(data['kiosk_only_mode'])
            
        if not updates:
            return jsonify({'success': False, 'error': 'No valid fields to update'}), 400
            
        set_clauses = []
        values = []
        for key, value in updates.items():
            set_clauses.append(f"{key} = %s")
            values.append(value)
            
        values.append(guild_id)
        
        query = f"UPDATE guild_settings SET {', '.join(set_clauses)} WHERE guild_id = %s"
        
        with get_db() as conn:
            conn.execute(query, tuple(values))
            
        return jsonify({'success': True, 'message': 'Kiosk settings updated successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': 'Failed to save settings'}), 500


@api_server_bp.route("/api/server/<guild_id>/reports/preview", methods=["POST"])
@require_api_auth
def api_preview_reports(user_session, guild_id):
    """API endpoint to get live JSON preview of a report (admin only)"""
    try:
        guild, access_level = verify_guild_access(user_session, guild_id)
        if not guild or access_level != 'admin':
            return jsonify({'success': False, 'error': 'Access denied. Admin only.'}), 403
            
        access = get_flask_guild_access(guild_id)
        is_paid = access['is_exempt'] or access['tier'] in ['pro', 'premium'] or access['trial_active']
            
        data = request.json
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
            
        start_date_str = data.get('start_date')
        end_date_str = data.get('end_date')
        
        if not start_date_str or not end_date_str:
            return jsonify({'success': False, 'error': 'Start and end dates are required'}), 400
            
        # Parse dates
        start_dt = datetime.fromisoformat(start_date_str.replace('Z', '+00:00'))
        end_dt = datetime.fromisoformat(end_date_str.replace('Z', '+00:00'))
        
        # Enforce 24h limit for Free Tier
        if not is_paid:
            age_hours = (datetime.now(timezone.utc) - start_dt).total_seconds() / 3600
            if age_hours > 24:
                return jsonify({
                    'success': False,
                    'error': 'Free tier is limited to 24 hours of history for previews. Upgrade to Pro for unlimited history.',
                    'code': 'PRO_REQUIRED',
                    'upgrade_url': f'/dashboard/purchase?guild_id={guild_id}&plan=pro'
                }), 403
        
        # Enforce 31-day max range to prevent massive JSON payloads
        if (end_dt - start_dt).days > 31:
            return jsonify({'success': False, 'error': 'Preview date range cannot exceed 31 days. Use Export for larger ranges.'}), 400
            
        query = '''
            SELECT 
                ts.user_id,
                COALESCE(ep.display_name, ep.full_name) as display_name,
                ts.clock_in_time,
                ts.clock_out_time,
                EXTRACT(EPOCH FROM (ts.clock_out_time - ts.clock_in_time)) / 60.0 as duration_minutes
            FROM timeclock_sessions ts
            LEFT JOIN employee_profiles ep ON ts.guild_id = ep.guild_id AND ts.user_id = ep.user_id
            WHERE ts.guild_id = %s 
              AND ts.clock_in_time >= %s 
              AND ts.clock_in_time <= %s
              AND ts.clock_out_time IS NOT NULL
            ORDER BY ts.clock_in_time DESC
        '''
        
        results = []
        with get_db() as conn:
            cursor = conn.execute(query, (int(guild_id), start_dt, end_dt))
            
            for row in cursor.fetchall():
                results.append({
                    'user_id': str(row['user_id']),
                    'display_name': row['display_name'] or str(row['user_id']),
                    'clock_in_time': row['clock_in_time'].isoformat() if row['clock_in_time'] else None,
                    'clock_out_time': row['clock_out_time'].isoformat() if row['clock_out_time'] else None,
                    'duration_minutes': round(float(row['duration_minutes']), 2) if row['duration_minutes'] is not None else 0
                })
                
        return jsonify({
            'success': True,
            'sessions': results,
            'count': len(results)
        })
    except Exception as e:
        app.logger.error(f"Error previewing reports for {guild_id}: {str(e)}")
        return jsonify({'success': False, 'error': f'Failed to generate preview: {str(e)}'}), 500



@api_server_bp.route("/api/server/<guild_id>/reports/export", methods=["POST"])
@require_api_auth
def api_export_reports(user_session, guild_id):
    """API endpoint to generate and download reports (admin only)"""
    access = get_flask_guild_access(guild_id)
    if not access['is_exempt'] and access['tier'] == 'free' and not access['trial_active']:
        return jsonify({
            'success': False,
            'error': 'Your free trial has expired. Upgrade to Premium to export reports.',
            'code': 'TRIAL_EXPIRED',
            'upgrade_url': f'/dashboard/purchase?guild_id={guild_id}',
            'trial_expired': True
        }), 403
        
    try:
        guild, access_level = verify_guild_access(user_session, guild_id)
        if not guild or access_level != 'admin':
            return jsonify({'success': False, 'error': 'Access denied. Admin only.'}), 403
            
        data = request.json
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
            
        export_type = data.get('export_type', 'standard_csv')
        start_date_str = data.get('start_date')
        end_date_str = data.get('end_date')
        
        if not start_date_str or not end_date_str:
            return jsonify({'success': False, 'error': 'Start and end dates are required'}), 400
            
        # Parse dates
        start_date = datetime.fromisoformat(start_date_str.replace('Z', '+00:00'))
        end_date = datetime.fromisoformat(end_date_str.replace('Z', '+00:00'))
        
        # Enforce 90-day max range to prevent OOM
        if (end_date - start_date).days > 90:
            return jsonify({'success': False, 'error': 'Report date range cannot exceed 90 days.'}), 400
            
        # Check tier restrictions
        is_pro = access['tier'] == 'pro' or access['is_exempt']
        if export_type in ['payroll_csv', 'pdf'] and not is_pro and not access['trial_active']:
            return jsonify({
                'success': False,
                'error': f'{export_type.upper()} exports require the Pro Plan.',
                'code': 'PRO_REQUIRED',
                'upgrade_url': f'/dashboard/purchase?guild_id={guild_id}&plan=pro'
            }), 403
            
        # Trigger bot API to generate and return the report
        bot_api_url = f"http://127.0.0.1:8081/api/guild/{guild_id}/reports/export"
        bot_api_secret = os.environ.get('BOT_API_SECRET')
        
        if not bot_api_secret:
            bot_module = _get_bot_module()
            if bot_module:
                bot_api_secret = getattr(bot_module, 'BOT_API_SECRET', None)
                
        if not bot_api_secret:
            return jsonify({'success': False, 'error': 'Bot API not configured'}), 500
            
        import requests
        response = requests.post(
            bot_api_url,
            headers={'Authorization': f'Bearer {bot_api_secret}'},
            json={
                'export_type': export_type,
                'start_date': start_date_str,
                'end_date': end_date_str
            },
            timeout=60 # Reports can take some time
        )
        
        if response.status_code == 200:
            return jsonify(response.json())
        else:
            error_msg = 'Failed to generate report'
            try:
                error_msg = response.json().get('error', error_msg)
            except:
                pass
            return jsonify({'success': False, 'error': error_msg}), response.status_code
            
    except ValueError as e:
        return jsonify({'success': False, 'error': f'Invalid date format: {str(e)}'}), 400
    except Exception as e:
        app.logger.error(f"Error exporting report: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error'}), 500


@api_server_bp.route("/api/server/<guild_id>/discord-channels", methods=["GET"])
@require_api_auth
def api_get_discord_channels(user_session, guild_id):
    """API endpoint to fetch a list of text channels for the UI (admin only)"""
    try:
        guild, access_level = verify_guild_access(user_session, guild_id)
        if not guild or access_level != 'admin':
            return jsonify({'success': False, 'error': 'Access denied. Admin only.'}), 403
            
        bot_api_url = f"http://127.0.0.1:8081/api/guild/{guild_id}/channels"
        bot_api_secret = os.environ.get('BOT_API_SECRET')
        
        if not bot_api_secret:
            bot_module = _get_bot_module()
            if bot_module:
                bot_api_secret = getattr(bot_module, 'BOT_API_SECRET', None)
                
        if not bot_api_secret:
            return jsonify({'success': False, 'error': 'Bot API not configured'}), 500
            
        import requests
        response = requests.get(
            bot_api_url,
            headers={'Authorization': f'Bearer {bot_api_secret}'},
            timeout=5
        )
        
        if response.status_code == 200:
            return jsonify(response.json())
        else:
            return jsonify({'success': False, 'error': 'Failed to fetch channels from bot'}), response.status_code
            
    except Exception as e:
        app.logger.error(f"Error fetching discord channels for {guild_id}: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error'}), 500


@api_server_bp.route("/api/server/<guild_id>/test-discord-routing", methods=["POST"])
@require_api_auth
def api_test_discord_routing(user_session, guild_id):
    """API endpoint to send a test message to a specified channel"""
    try:
        guild, access_level = verify_guild_access(user_session, guild_id)
        if not guild or access_level != 'admin':
            return jsonify({'success': False, 'error': 'Access denied. Admin only.'}), 403
            
        data = request.json
        channel_id = data.get('channel_id')
        
        if not channel_id:
            return jsonify({'success': False, 'error': 'Channel ID is required'}), 400
            
        bot_api_url = f"http://127.0.0.1:8081/api/guild/{guild_id}/test-message"
        bot_api_secret = os.environ.get('BOT_API_SECRET')
        
        if not bot_api_secret:
            bot_module = _get_bot_module()
            if bot_module:
                bot_api_secret = getattr(bot_module, 'BOT_API_SECRET', None)
                
        if not bot_api_secret:
            return jsonify({'success': False, 'error': 'Bot API not configured'}), 500
            
        import requests
        response = requests.post(
            bot_api_url,
            headers={'Authorization': f'Bearer {bot_api_secret}'},
            json={'channel_id': channel_id},
            timeout=10
        )
        
        if response.status_code == 200:
            return jsonify(response.json())
        else:
            try:
                error_msg = response.json().get('error', 'Failed to send test message')
            except:
                error_msg = 'Failed to send test message'
            return jsonify({'success': False, 'error': error_msg}), response.status_code
            
    except Exception as e:
        app.logger.error(f"Error testing discord routing for {guild_id}: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error'}), 500




@api_server_bp.route("/api/server/<guild_id>/employees/send-onboarding", methods=["POST"])
@require_api_auth
def api_send_employee_onboarding(user_session, guild_id):
    """API endpoint to send onboarding DMs to all employees (admin only, premium only)"""
    access = get_flask_guild_access(guild_id)
    if not access['is_exempt'] and access['tier'] == 'free' and not access['trial_active']:
        return jsonify({
            'success': False,
            'error': 'Your free trial has expired. Upgrade to Premium to continue.',
            'code': 'TRIAL_EXPIRED',
            'upgrade_url': f'/dashboard/purchase?guild_id={guild_id}',
            'trial_expired': True
        }), 403
    try:
        guild, access_level = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        if access_level != 'admin':
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        
        # Check premium access
        guild_settings = get_guild_settings(guild_id)
        if not guild_settings.get('has_bot_access'):
            return jsonify({'success': False, 'error': 'Premium feature - please upgrade'}), 403
        
        # Call bot API to send onboarding DMs
        bot_api_url = f"http://127.0.0.1:8081/api/guild/{guild_id}/employees/send-onboarding"
        bot_api_secret = os.environ.get('BOT_API_SECRET')
        
        if not bot_api_secret:
            bot_module = _get_bot_module()
            if bot_module:
                bot_api_secret = getattr(bot_module, 'BOT_API_SECRET', None)
        
        if not bot_api_secret:
            return jsonify({'success': False, 'error': 'Bot API not configured'}), 500
        
        import requests
        response = requests.post(
            bot_api_url,
            headers={'Authorization': f'Bearer {bot_api_secret}'},
            json={},
            timeout=60
        )
        
        if response.status_code == 200:
            data = response.json()
            return jsonify({
                'success': True,
                'message': data.get('message', 'Onboarding sent'),
                'sent_count': data.get('sent_count', 0)
            })
        else:
            error_data = response.json() if response.content else {}
            return jsonify({'success': False, 'error': error_data.get('error', 'Failed to send onboarding')}), 500
            
    except Exception as e:
        app.logger.error(f"Error sending onboarding: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error'}), 500


@api_server_bp.route("/api/server/<guild_id>/employee/<user_id>/profile", methods=["GET"])
@require_api_auth
def api_get_employee_profile(user_session, guild_id, user_id):
    """API endpoint to fetch employee profile with stats"""
    access = get_flask_guild_access(guild_id)
    if not access['is_exempt'] and access['tier'] == 'free' and not access['trial_active']:
        return jsonify({
            'success': False,
            'error': 'Your free trial has expired. Upgrade to Premium to continue.',
            'code': 'TRIAL_EXPIRED',
            'upgrade_url': f'/dashboard/purchase?guild_id={guild_id}',
            'trial_expired': True
        }), 403
    try:
        guild, access_level = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Allow access if: user is viewing their own profile OR user is admin
        viewer_user_id = user_session.get('user_id')
        is_admin = access_level == 'admin'
        is_own_profile = str(viewer_user_id) == str(user_id)
        
        if not is_admin and not is_own_profile:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Get guild timezone
        guild_settings = get_guild_settings(guild_id)
        guild_tz = guild_settings.get('timezone') or 'America/Chicago'
        
        with get_db() as conn:
            # Get employee profile info
            cursor = conn.execute("""
                SELECT ep.user_id, ep.full_name, ep.display_name, ep.avatar_url,
                       ep.email, ep.hire_date, ep.position, ep.department, ep.company_role,
                       ep.first_clock_at, ep.bio, ep.is_active,
                       ep.profile_setup_completed, ep.welcome_dm_sent, ep.first_clock_used,
                       ep.phone, ep.avatar_choice, ep.profile_background, ep.catchphrase,
                       ep.selected_stickers, ep.accent_color
                FROM employee_profiles ep
                WHERE ep.guild_id = %s AND ep.user_id = %s
            """, (int(guild_id), int(user_id)))
            profile_row = cursor.fetchone()
            app.logger.debug(f"Profile fetched for user {user_id}: {profile_row is not None}")

            if not profile_row:
                return jsonify({'success': False, 'error': 'Employee not found'}), 404

            app.logger.debug(f"Calculating stats for user {user_id}")
            # Calculate stats from timeclock_sessions
            stats_cursor = conn.execute("""
                SELECT 
                    COUNT(*) as total_sessions,
                    COALESCE(SUM(EXTRACT(EPOCH FROM (COALESCE(clock_out_time, NOW()) - clock_in_time))), 0) / 3600.0 as total_hours,
                    COALESCE(MAX(EXTRACT(EPOCH FROM (clock_out_time - clock_in_time))), 0) / 3600.0 as longest_shift_hours,
                    MIN(clock_in_time) as first_session,
                    MAX(clock_in_time) as last_session
                FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s AND clock_out_time IS NOT NULL
            """, (int(guild_id), int(user_id)))
            stats_row = stats_cursor.fetchone()

            # Safety check: ensure stats_row is not None
            if not stats_row:
                app.logger.warning(f"No stats_row returned for user {user_id} in guild {guild_id}")
                # Create default stats row
                stats_row = {
                    'total_sessions': 0,
                    'total_hours': 0,
                    'longest_shift_hours': 0,
                    'first_session': None,
                    'last_session': None
                }

            # Calculate this week's hours
            week_cursor = conn.execute("""
                SELECT COALESCE(SUM(EXTRACT(EPOCH FROM (COALESCE(clock_out_time, NOW()) - clock_in_time))), 0) / 3600.0 as weekly_hours
                FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s
                AND clock_in_time >= date_trunc('week', NOW() AT TIME ZONE %s)
            """, (int(guild_id), int(user_id), guild_tz))
            week_row = week_cursor.fetchone()

            # Safety check: ensure week_row is not None
            if not week_row:
                app.logger.warning(f"No week_row returned for user {user_id} in guild {guild_id}")
                week_row = {'weekly_hours': 0}

            app.logger.debug(f"Calculating weekly hours for user {user_id}")

            # Calculate average weekly hours (total hours / weeks since first clock)
            first_clock = profile_row.get('first_clock_at') or stats_row.get('first_session')
            avg_weekly = 0
            if first_clock and stats_row.get('total_hours'):
                try:
                    # Ensure first_clock is a datetime object
                    if isinstance(first_clock, datetime):
                        naive_first_clock = first_clock.replace(tzinfo=None) if first_clock.tzinfo else first_clock
                        weeks_active = max(1, (datetime.now() - naive_first_clock).days / 7)
                        avg_weekly = round(stats_row['total_hours'] / weeks_active, 1)
                    else:
                        app.logger.warning(f"first_clock is not datetime: {type(first_clock)}")
                except Exception as e:
                    app.logger.error(f"Error calculating avg_weekly: {e}")
                    avg_weekly = 0
            
            # Calculate average daily hours
            avg_daily = 0
            if stats_row.get('total_sessions') and stats_row['total_sessions'] > 0:
                avg_daily = round(stats_row['total_hours'] / stats_row['total_sessions'], 1)
            
            # Calculate tenure
            app.logger.debug(f"Calculating tenure for user {user_id}")
            hire_date = profile_row.get('hire_date')
            tenure_text = "Not set"
            if hire_date:
                try:
                    if isinstance(hire_date, datetime):
                        hire_with_tz = hire_date.replace(tzinfo=pytz.UTC) if hire_date.tzinfo is None else hire_date
                        days = (datetime.now(pytz.UTC) - hire_with_tz).days
                        if days < 30:
                            tenure_text = f"{days} days"
                        elif days < 365:
                            months = days // 30
                            tenure_text = f"{months} month{'s' if months > 1 else ''}"
                        else:
                            years = days // 365
                            months = (days % 365) // 30
                            tenure_text = f"{years} year{'s' if years > 1 else ''}"
                            if months > 0:
                                tenure_text += f", {months} mo"
                    else:
                        app.logger.warning(f"hire_date is not datetime: {type(hire_date)}")
                except Exception as e:
                    app.logger.error(f"Error calculating tenure: {e}")
                    tenure_text = "Error calculating tenure"

            app.logger.debug(f"Checking clock status for user {user_id}")
            # Check if currently clocked in
            clock_cursor = conn.execute("""
                SELECT clock_in_time FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s AND clock_out_time IS NULL
                ORDER BY clock_in_time DESC LIMIT 1
            """, (int(guild_id), int(user_id)))
            clock_row = clock_cursor.fetchone()
            is_clocked_in = clock_row is not None

            app.logger.debug(f"Checking tier for guild {guild_id}")
            # Check server subscription tier for premium customization access using Entitlements
            tier_cursor = conn.execute("""
                SELECT bot_access_paid, COALESCE(retention_tier, 'none') as retention_tier,
                       COALESCE(grandfathered, FALSE) as grandfathered
                FROM server_subscriptions WHERE guild_id = %s
            """, (int(guild_id),))
            tier_row = tier_cursor.fetchone()
            if tier_row:
                guild_tier = Entitlements.get_guild_tier(
                    bool(tier_row['bot_access_paid']),
                    tier_row['retention_tier'],
                    bool(tier_row['grandfathered'])
                )
            else:
                guild_tier = UserTier.FREE
            # Customization available for Premium, Pro, and Grandfathered tiers
            has_premium_customization = guild_tier in [UserTier.PREMIUM, UserTier.PRO, UserTier.GRANDFATHERED]

            app.logger.debug(f"Building profile response for user {user_id}")
            profile_data = {
                'user_id': str(profile_row['user_id']),
                'display_name': profile_row['display_name'] or profile_row['full_name'] or 'Unknown',
                'full_name': profile_row['full_name'] or '',
                'avatar_url': profile_row['avatar_url'],
                'email': profile_row['email'] if is_own_profile or is_admin else None,
                'phone': profile_row.get('phone') if is_own_profile or is_admin else None,
                'hire_date': profile_row['hire_date'].isoformat() if profile_row.get('hire_date') else None,
                'position': profile_row['position'] or '',
                'department': profile_row['department'] or '',
                'company_role': profile_row['company_role'] or '',
                'bio': profile_row['bio'] or '',
                'is_active': profile_row['is_active'],
                'is_clocked_in': is_clocked_in,
                'tenure_text': tenure_text,
                'avatar_choice': profile_row.get('avatar_choice') or 'random',
                'profile_background': profile_row.get('profile_background') or 'default',
                'accent_color': profile_row.get('accent_color') or 'cyan',
                'catchphrase': profile_row.get('catchphrase') or '',
                'selected_stickers': _parse_stickers(profile_row.get('selected_stickers')),
                'stats': {
                    'total_hours': round(stats_row.get('total_hours') or 0, 1),
                    'total_sessions': stats_row.get('total_sessions') or 0,
                    'weekly_hours': round(week_row.get('weekly_hours') or 0, 1),
                    'avg_weekly_hours': avg_weekly,
                    'avg_daily_hours': avg_daily,
                    'longest_shift_hours': round(stats_row.get('longest_shift_hours') or 0, 1),
                    'first_session': stats_row.get('first_session').isoformat() if stats_row.get('first_session') else None,
                    'last_session': stats_row.get('last_session').isoformat() if stats_row.get('last_session') else None
                }
            }
            
            return jsonify({
                'success': True, 
                'profile': profile_data, 
                'is_own_profile': is_own_profile,
                'has_premium_customization': has_premium_customization,
                'guild_tier': guild_tier.value if guild_tier else 'free'
            })
    except Exception as e:
        app.logger.error(f"Error fetching employee profile for guild {guild_id}, user {user_id}")
        app.logger.error(f"Exception type: {type(e).__name__}")
        app.logger.error(f"Exception message: {str(e)}")
        app.logger.error(f"Full traceback:\n{traceback.format_exc()}")
        return jsonify({'success': False, 'error': 'Server error'}), 500


@api_server_bp.route("/api/server/<guild_id>/employee/<user_id>/profile", methods=["POST"])
@require_api_auth
def api_update_employee_profile(user_session, guild_id, user_id):
    """API endpoint to update employee's own profile (email, etc.)"""
    access = get_flask_guild_access(guild_id)
    if not access['is_exempt'] and access['tier'] == 'free' and not access['trial_active']:
        return jsonify({
            'success': False,
            'error': 'Your free trial has expired. Upgrade to Premium to continue.',
            'code': 'TRIAL_EXPIRED',
            'upgrade_url': f'/dashboard/purchase?guild_id={guild_id}',
            'trial_expired': True
        }), 403
    try:
        guild, access_level = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Only allow updating own profile (or admin can update any)
        viewer_user_id = user_session.get('user_id')
        is_admin = access_level == 'admin'
        is_own_profile = str(viewer_user_id) == str(user_id)
        
        if not is_admin and not is_own_profile:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        # Check server subscription tier for premium customization access using Entitlements
        with get_db() as conn:
            tier_cursor = conn.execute("""
                SELECT bot_access_paid, COALESCE(retention_tier, 'none') as retention_tier, 
                       COALESCE(grandfathered, FALSE) as grandfathered
                FROM server_subscriptions WHERE guild_id = %s
            """, (int(guild_id),))
            tier_row = tier_cursor.fetchone()
            if tier_row:
                guild_tier = Entitlements.get_guild_tier(
                    bool(tier_row['bot_access_paid']),
                    tier_row['retention_tier'],
                    bool(tier_row['grandfathered'])
                )
            else:
                guild_tier = UserTier.FREE
            # Customization available for Premium, Pro, and Grandfathered tiers
            has_premium_customization = guild_tier in [UserTier.PREMIUM, UserTier.PRO, UserTier.GRANDFATHERED]
        
        # Basic fields available to all tiers (text-based info)
        allowed_fields = ['email', 'phone', 'catchphrase']
        
        # Premium customization fields only for Premium/Pro tiers
        premium_fields = ['avatar_choice', 'profile_background', 'accent_color', 'selected_stickers']
        
        # Check if trying to update premium fields without proper tier
        for field in premium_fields:
            if field in data and not has_premium_customization:
                return jsonify({
                    'success': False, 
                    'error': 'Profile customization requires Premium tier. Upgrade to unlock custom avatars, backgrounds, and stickers.',
                    'upgrade_required': True
                }), 403
        
        # Add premium fields if server has Premium/Pro tier
        if has_premium_customization:
            allowed_fields.extend(premium_fields)
        
        if is_admin:
            allowed_fields.extend(['hire_date', 'position', 'department', 'company_role'])
        
        updates = []
        params = []
        
        for field in allowed_fields:
            if field in data:
                value = data[field]
                if field == 'email' and value:
                    # Basic email validation
                    import re
                    if not re.match(r'^[^@]+@[^@]+\.[^@]+$', value):
                        return jsonify({'success': False, 'error': 'Invalid email format'}), 400
                if field == 'phone' and value:
                    # Basic phone validation (allow digits, spaces, dashes, parentheses, plus)
                    import re
                    cleaned = re.sub(r'[^\d]', '', value)
                    if len(cleaned) < 7 or len(cleaned) > 15:
                        return jsonify({'success': False, 'error': 'Invalid phone number'}), 400
                if field == 'avatar_choice' and value:
                    # Validate avatar choice against allowed list
                    allowed_avatars = ['discord', 'random', 'superhero', 'ninja', 'pirate', 'astronaut',
                                       'wizard', 'unicorn', 'dinosaur', 'robot', 'skater', 'beach',
                                       'pumpkin', 'vampire', 'ghost', 'santa', 'snowman', 'cupid', 
                                       'leprechaun', 'bunny']
                    if value not in allowed_avatars:
                        return jsonify({'success': False, 'error': 'Invalid avatar choice'}), 400
                if field == 'profile_background' and value:
                    allowed_backgrounds = ['default', 'sunset', 'ocean', 'forest', 'fire', 'midnight',
                                           'candy', 'aurora', 'cosmic', 'golden', 'mint', 'cherry']
                    if value not in allowed_backgrounds:
                        return jsonify({'success': False, 'error': 'Invalid background choice'}), 400
                if field == 'accent_color' and value:
                    allowed_accents = ['cyan', 'magenta', 'gold', 'green', 'blue', 'red', 'purple', 'teal']
                    if value not in allowed_accents:
                        return jsonify({'success': False, 'error': 'Invalid accent color'}), 400
                if field == 'catchphrase' and value:
                    if len(value) > 50:
                        return jsonify({'success': False, 'error': 'Catchphrase too long (max 50 characters)'}), 400
                if field == 'selected_stickers':
                    # Validate stickers
                    allowed_stickers = ['star', 'coffee', 'fire', 'heart', 'lightning', 
                                        'rainbow', 'pizza', 'music', 'diamond', 'crown']
                    if not isinstance(value, list):
                        value = []
                    if len(value) > 5:
                        return jsonify({'success': False, 'error': 'Maximum 5 stickers allowed'}), 400
                    value = [s for s in value if s in allowed_stickers]
                    # Convert to JSON for storage
                    import json
                    value = json.dumps(value)
                updates.append(f"{field} = %s")
                params.append(value if value else None)
        
        if not updates:
            return jsonify({'success': False, 'error': 'No valid fields to update'}), 400
        
        params.extend([int(guild_id), int(user_id)])
        
        with get_db() as conn:
            conn.execute(f"""
                UPDATE employee_profiles 
                SET {', '.join(updates)}, updated_at = NOW()
                WHERE guild_id = %s AND user_id = %s
            """, params)
        
        return jsonify({'success': True, 'message': 'Profile updated'})
    except Exception as e:
        app.logger.error(f"Error updating employee profile: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error'}), 500


@api_server_bp.route("/api/server/<guild_id>/roles", methods=["GET"])
@require_api_auth
def api_get_server_roles(user_session, guild_id):
    """API endpoint to fetch roles for dashboard pages"""
    try:
        guild, access_level = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        all_roles = get_guild_roles_from_bot(guild_id) or []
        
        admin_roles = []
        employee_roles = []
        
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT role_id FROM admin_roles WHERE guild_id = %s
            """, (str(guild_id),))
            admin_role_ids = [str(row['role_id']) for row in cursor.fetchall()]
            
            cursor = conn.execute("""
                SELECT role_id FROM employee_roles WHERE guild_id = %s
            """, (str(guild_id),))
            employee_role_ids = [str(row['role_id']) for row in cursor.fetchall()]
        
        for role in all_roles:
            role_id = str(role.get('id'))
            if role_id in admin_role_ids:
                admin_roles.append(role)
            if role_id in employee_role_ids:
                employee_roles.append(role)
        
        return jsonify({
            'success': True,
            'all_roles': all_roles,
            'admin_roles': admin_roles,
            'employee_roles': employee_roles
        })
    except Exception as e:
        app.logger.error(f"Error fetching roles: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error'}), 500


@api_server_bp.route("/api/server/<guild_id>/channels", methods=["GET"])
@require_api_auth
def api_get_server_channels(user_session, guild_id):
    """API endpoint to fetch text channels for dashboard pages"""
    try:
        guild, access_level = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        channels = get_guild_text_channels(guild_id) or []
        
        return jsonify({'success': True, 'channels': channels})
    except Exception as e:
        app.logger.error(f"Error fetching channels: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error'}), 500


@api_server_bp.route("/api/server/<guild_id>/employee/<user_id>/entries", methods=["GET"])
@require_api_auth
def api_get_employee_entries(user_session, guild_id, user_id):
    """API endpoint to fetch time entries for an employee (for calendar view)"""
    try:
        guild, access_level = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        start_date = request.args.get('start', '')
        end_date = request.args.get('end', '')
        
        with get_db() as conn:
            query = """
                SELECT session_id, user_id, clock_in_time, clock_out_time,
                       EXTRACT(EPOCH FROM (clock_out_time - clock_in_time)) as duration_seconds
                FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s
            """
            params = [str(guild_id), str(user_id)]
            
            if start_date:
                query += " AND clock_in_time >= %s"
                params.append(start_date)
            if end_date:
                query += " AND clock_in_time <= %s"
                params.append(end_date + ' 23:59:59')
            
            query += " ORDER BY clock_in_time DESC"
            
            cursor = conn.execute(query, params)
            
            entries = []
            for row in cursor.fetchall():
                duration = row['duration_seconds']
                entries.append({
                    'id': row['session_id'],
                    'user_id': str(row['user_id']),
                    'clock_in_time': row['clock_in_time'].isoformat() if row['clock_in_time'] else None,
                    'clock_out_time': row['clock_out_time'].isoformat() if row['clock_out_time'] else None,
                    'duration_seconds': float(duration) if duration else 0
                })
        
        return jsonify({'success': True, 'entries': entries})
    except Exception as e:
        app.logger.error(f"Error fetching employee entries: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error'}), 500


@api_server_bp.route("/api/server/<guild_id>/employee/<user_id>/status", methods=["GET"])
@require_api_auth
def api_get_employee_status(user_session, guild_id, user_id):
    """API endpoint to fetch current clock status and hours for an employee"""
    try:
        guild, access_level = verify_guild_access(user_session, guild_id, allow_employee=True)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Employees can only view their own status
        if access_level == 'employee' and str(user_session.get('user_id')) != str(user_id):
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        with get_db() as conn:
            # Check if currently clocked in
            cursor = conn.execute("""
                SELECT session_id, clock_in_time FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s AND clock_out_time IS NULL
                ORDER BY clock_in_time DESC LIMIT 1
            """, (str(guild_id), str(user_id)))
            current_session = cursor.fetchone()
            
            is_clocked_in = current_session is not None
            current_session_start = current_session['clock_in_time'].isoformat() if current_session else None
            
            # Get hours today (calculate duration from timestamps, convert to minutes)
            cursor = conn.execute("""
                SELECT COALESCE(SUM(EXTRACT(EPOCH FROM (clock_out_time - clock_in_time)) / 60), 0) as total
                FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s
                AND DATE(clock_in_time) = CURRENT_DATE
                AND clock_out_time IS NOT NULL
            """, (str(guild_id), str(user_id)))
            hours_today = cursor.fetchone()['total'] or 0

            # Get hours this week (convert to minutes)
            cursor = conn.execute("""
                SELECT COALESCE(SUM(EXTRACT(EPOCH FROM (clock_out_time - clock_in_time)) / 60), 0) as total
                FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s
                AND clock_in_time >= DATE_TRUNC('week', CURRENT_DATE)
                AND clock_out_time IS NOT NULL
            """, (str(guild_id), str(user_id)))
            hours_week = cursor.fetchone()['total'] or 0

            # Get hours this month (convert to minutes)
            cursor = conn.execute("""
                SELECT COALESCE(SUM(EXTRACT(EPOCH FROM (clock_out_time - clock_in_time)) / 60), 0) as total
                FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s
                AND clock_in_time >= DATE_TRUNC('month', CURRENT_DATE)
                AND clock_out_time IS NOT NULL
            """, (str(guild_id), str(user_id)))
            hours_month = cursor.fetchone()['total'] or 0
        
        return jsonify({
            'success': True,
            'is_clocked_in': is_clocked_in,
            'current_session_start': current_session_start,
            'hours_today': hours_today,
            'hours_this_week': hours_week,
            'hours_this_month': hours_month
        })
    except Exception as e:
        app.logger.error(f"Error fetching employee status: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error'}), 500


@api_server_bp.route("/api/server/<guild_id>/employee/<user_id>/sessions", methods=["GET"])
@require_api_auth
def api_get_employee_sessions(user_session, guild_id, user_id):
    """API endpoint to fetch recent sessions for an employee"""
    try:
        guild, access_level = verify_guild_access(user_session, guild_id, allow_employee=True)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Employees can only view their own sessions
        if access_level == 'employee' and str(user_session.get('user_id')) != str(user_id):
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        try:
            limit = int(request.args.get('limit', 10))
            if limit < 1: limit = 1
            limit = min(limit, 50)
        except (ValueError, TypeError):
            limit = 10
        
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT session_id, clock_in_time, clock_out_time,
                       EXTRACT(EPOCH FROM (clock_out_time - clock_in_time)) as duration_seconds
                FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s
                ORDER BY clock_in_time DESC
                LIMIT %s
            """, (str(guild_id), str(user_id), limit))
            
            sessions = []
            for row in cursor.fetchall():
                duration_seconds = float(row['duration_seconds']) if row['duration_seconds'] else 0
                duration_minutes = int(duration_seconds // 60) if duration_seconds else 0
                sessions.append({
                    'id': row['session_id'],
                    'clock_in_time': row['clock_in_time'].isoformat() if row['clock_in_time'] else None,
                    'clock_out_time': row['clock_out_time'].isoformat() if row['clock_out_time'] else None,
                    'duration_minutes': duration_minutes
                })
        
        return jsonify({'success': True, 'sessions': sessions})
    except Exception as e:
        app.logger.error(f"Error fetching employee sessions: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error'}), 500


@api_server_bp.route("/api/server/<guild_id>/entries/<entry_id>", methods=["PUT"])
@require_api_auth
def api_update_entry(user_session, guild_id, entry_id):
    """API endpoint to update a time entry (admin only)"""
    try:
        guild, access_level = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        data = request.get_json()
        clock_in = data.get('clock_in_time')
        clock_out = data.get('clock_out_time')
        admin_notes = data.get('admin_notes', '')
        
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT session_id, user_id FROM timeclock_sessions 
                WHERE session_id = %s AND guild_id = %s
            """, (int(entry_id), str(guild_id)))
            entry = cursor.fetchone()
            
            if not entry:
                return jsonify({'success': False, 'error': 'Entry not found'}), 404
            
            conn.execute("""
                UPDATE timeclock_sessions 
                SET clock_in_time = %s, clock_out_time = %s
                WHERE session_id = %s AND guild_id = %s
            """, (clock_in, clock_out, int(entry_id), str(guild_id)))
        
        return jsonify({'success': True})
    except Exception as e:
        app.logger.error(f"Error updating entry: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error'}), 500


@api_server_bp.route("/api/server/<guild_id>/entries/<entry_id>", methods=["DELETE"])
@require_api_auth
def api_delete_entry(user_session, guild_id, entry_id):
    """API endpoint to delete a time entry (admin only)"""
    try:
        guild, access_level = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        with get_db() as conn:
            cursor = conn.execute("""
                DELETE FROM timeclock_sessions 
                WHERE session_id = %s AND guild_id = %s
                RETURNING session_id
            """, (int(entry_id), str(guild_id)))
            deleted = cursor.fetchone()
            
            if not deleted:
                return jsonify({'success': False, 'error': 'Entry not found'}), 404
        
        return jsonify({'success': True})
    except Exception as e:
        app.logger.error(f"Error deleting entry: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error'}), 500


@api_server_bp.route("/api/server/<guild_id>/calendar/monthly-summary", methods=["GET"])
@require_api_auth
def api_get_monthly_summary(user_session, guild_id):
    """
    Admin Calendar API: Get guild-wide daily summary for a month.
    Returns shift counts and total hours per day for all employees.
    """
    access = get_flask_guild_access(guild_id)
    if not access['is_exempt'] and access['tier'] == 'free' and not access['trial_active']:
        return jsonify({
            'success': False,
            'error': 'Your free trial has expired. Upgrade to Premium to continue.',
            'code': 'TRIAL_EXPIRED',
            'upgrade_url': f'/dashboard/purchase?guild_id={guild_id}',
            'trial_expired': True
        }), 403
    try:
        guild, access_level = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        year = request.args.get('year', type=int)
        month = request.args.get('month', type=int)
        
        if not year or not month:
            from datetime import date
            today = date.today()
            year = year or today.year
            month = month or today.month
        
        from datetime import datetime
        from calendar import monthrange
        
        _, last_day = monthrange(year, month)
        start_date = f"{year}-{month:02d}-01"
        end_date = f"{year}-{month:02d}-{last_day}"
        
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT 
                    DATE(s.clock_in_time) as work_date,
                    COUNT(DISTINCT s.user_id) as employee_count,
                    COUNT(s.session_id) as session_count,
                    COALESCE(SUM(EXTRACT(EPOCH FROM (COALESCE(s.clock_out_time, NOW()) - s.clock_in_time))), 0) as total_seconds,
                    COUNT(a.adjustment_id) as pending_adjustments
                FROM timeclock_sessions s
                LEFT JOIN time_adjustments a ON s.session_id = a.session_id AND a.status = 'pending'
                WHERE s.guild_id = %s 
                  AND s.clock_in_time >= %s
                  AND s.clock_in_time < %s::date + interval '1 day'
                GROUP BY DATE(s.clock_in_time)
                ORDER BY work_date
            """, (str(guild_id), start_date, end_date))
            
            days = {}
            for row in cursor.fetchall():
                date_str = row['work_date'].strftime('%Y-%m-%d')
                days[date_str] = {
                    'date': date_str,
                    'employee_count': row['employee_count'],
                    'session_count': row['session_count'],
                    'total_hours': round(row['total_seconds'] / 3600, 2),
                    'has_pending_adjustments': row['pending_adjustments'] > 0
                }
        
        return jsonify({
            'success': True,
            'year': year,
            'month': month,
            'days': days
        })
    except Exception as e:
        app.logger.error(f"Error fetching monthly summary: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error'}), 500


@api_server_bp.route("/api/server/<guild_id>/calendar/day-detail", methods=["GET"])
@require_api_auth
def api_get_day_detail(user_session, guild_id):
    """
    Admin Calendar API: Get all employees and their sessions for a specific day.
    Returns employee info with their clock in/out times.
    """
    access = get_flask_guild_access(guild_id)
    if not access['is_exempt'] and access['tier'] == 'free' and not access['trial_active']:
        return jsonify({
            'success': False,
            'error': 'Your free trial has expired. Upgrade to Premium to continue.',
            'code': 'TRIAL_EXPIRED',
            'upgrade_url': f'/dashboard/purchase?guild_id={guild_id}',
            'trial_expired': True
        }), 403
    try:
        guild, access_level = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        date_str = request.args.get('date')
        if not date_str:
            return jsonify({'success': False, 'error': 'Missing date parameter'}), 400
        
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT 
                    s.session_id,
                    s.user_id,
                    s.clock_in_time,
                    s.clock_out_time,
                    EXTRACT(EPOCH FROM (COALESCE(s.clock_out_time, NOW()) - s.clock_in_time)) as duration_seconds,
                    ep.display_name,
                    ep.username,
                    ep.avatar_url,
                    ep.position,
                    a.status as adjustment_status
                FROM timeclock_sessions s
                LEFT JOIN employee_profiles ep ON s.guild_id::text = ep.guild_id::text AND s.user_id::text = ep.user_id::text
                LEFT JOIN time_adjustments a ON s.session_id = a.session_id AND a.status = 'pending'
                WHERE s.guild_id = %s 
                  AND DATE(s.clock_in_time) = %s
                ORDER BY s.clock_in_time ASC
            """, (str(guild_id), date_str))
            
            sessions = []
            for row in cursor.fetchall():
                duration = row['duration_seconds']
                sessions.append({
                    'session_id': row['session_id'],
                    'user_id': str(row['user_id']),
                    'clock_in_time': row['clock_in_time'].isoformat() if row['clock_in_time'] else None,
                    'clock_out_time': row['clock_out_time'].isoformat() if row['clock_out_time'] else None,
                    'duration_seconds': float(duration) if duration else 0,
                    'display_name': row['display_name'] or row['username'] or 'Unknown',
                    'username': row['username'],
                    'avatar_url': row['avatar_url'],
                    'position': row['position'],
                    'has_pending_adjustment': True if row['adjustment_status'] == 'pending' else False
                })
        
        return jsonify({
            'success': True,
            'date': date_str,
            'sessions': sessions
        })
    except Exception as e:
        import traceback
        app.logger.error(f"Error fetching day detail for guild {guild_id}, date {request.args.get('date')}: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'success': False, 'error': 'Server error'}), 500


@api_server_bp.route("/api/server/<guild_id>/sessions/admin-create", methods=["POST"])
@require_api_auth
def api_admin_create_session(user_session, guild_id):
    """
    Admin API: Create a new session for an employee (admin logged them in/out).
    Used when employee forgot to clock in/out and admin is fixing it.
    """
    try:
        guild, access_level = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        data = request.get_json()
        user_id = data.get('user_id')
        clock_in = data.get('clock_in_time')
        clock_out = data.get('clock_out_time')
        
        if not user_id or not clock_in:
            return jsonify({'success': False, 'error': 'Missing user_id or clock_in_time'}), 400
        
        with get_db() as conn:
            cursor = conn.execute("""
                INSERT INTO timeclock_sessions (guild_id, user_id, clock_in_time, clock_out_time)
                VALUES (%s, %s, %s, %s)
                RETURNING session_id
            """, (str(guild_id), str(user_id), clock_in, clock_out))
            new_session = cursor.fetchone()
        
        app.logger.info(f"Admin {user_session.get('username')} created session for user {user_id} in guild {guild_id}")
        
        return jsonify({
            'success': True,
            'session_id': new_session['session_id']
        })
    except Exception as e:
        app.logger.error(f"Error creating admin session: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error'}), 500


@api_server_bp.route("/api/server/<guild_id>/bans", methods=["GET"])
@require_paid_api_access
def api_get_bans(user_session, guild_id):
    """API endpoint to fetch all banned users for a server"""
    try:
        guild, _ = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT user_id, banned_at, ban_expires_at, warning_count, reason 
                FROM banned_users 
                WHERE guild_id = %s
                ORDER BY banned_at DESC
            """, (guild_id,))
            
            bans = []
            for row in cursor.fetchall():
                bans.append({
                    'user_id': str(row['user_id']),
                    'banned_at': row['banned_at'],
                    'ban_expires_at': row['ban_expires_at'],
                    'warning_count': row['warning_count'],
                    'reason': row['reason']
                })
        
        return jsonify({'success': True, 'bans': bans})
    except Exception as e:
        app.logger.error(f"Error fetching bans: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@api_server_bp.route("/api/server/<guild_id>/bans/unban", methods=["POST"])
@require_paid_api_access
def api_unban_user(user_session, guild_id):
    """API endpoint to unban a user"""
    try:
        guild, _ = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        data = request.get_json()
        if not data or 'user_id' not in data:
            return jsonify({'success': False, 'error': 'Missing user_id'}), 400
        
        user_id = str(data['user_id'])
        
        with get_db() as conn:
            conn.execute(
                "DELETE FROM banned_users WHERE guild_id = %s AND user_id = %s",
                (guild_id, user_id)
            )
        
        app.logger.info(f"Unbanned user {user_id} from guild {guild_id} by {user_session.get('username')}")
        return jsonify({'success': True, 'message': 'User unbanned successfully'})
    except Exception as e:
        app.logger.error(f"Error unbanning user: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500

@api_server_bp.route("/api/server/<guild_id>/bans/permanent", methods=["POST"])
@require_paid_api_access
def api_make_ban_permanent(user_session, guild_id):
    """API endpoint to make a ban permanent"""
    try:
        guild, _ = verify_guild_access(user_session, guild_id)
        if not guild:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        data = request.get_json()
        if not data or 'user_id' not in data:
            return jsonify({'success': False, 'error': 'Missing user_id'}), 400
        
        user_id = str(data['user_id'])
        
        with get_db() as conn:
            conn.execute("""
                UPDATE banned_users 
                SET ban_expires_at = NULL, reason = 'permanent_ban'
                WHERE guild_id = %s AND user_id = %s
            """, (guild_id, user_id))
        
        app.logger.info(f"Made ban permanent for user {user_id} in guild {guild_id} by {user_session.get('username')}")
        return jsonify({'success': True, 'message': 'Ban made permanent'})
    except Exception as e:
        app.logger.error(f"Error making ban permanent: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Server error'}), 500


