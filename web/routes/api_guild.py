import os
import traceback
import logging
import pytz
from datetime import datetime, timezone
from flask import Blueprint, render_template, redirect, request, session, jsonify, current_app as app, send_file
import requests

from app import (
    require_auth,
    require_paid_api_access,
    get_flask_guild_access,
    get_all_user_guilds,
    flask_check_bot_access,
    flask_set_bot_access,
    create_secure_checkout_session
)
from web.utils.db import get_dbr_guilds, is_demo_server, \
    __version__, CHANGELOG, get_db, verify_guild_access, Entitlements, UserRole, \
    send_email, send_onboarding_email, sanitize_csv_string, \
    approve_adjustment, check_guild_paid_access, check_user_admin_realtime, create_adjustment_request, deny_adjustment


api_guild_bp = Blueprint('api_guild', __name__)
@api_guild_bp.route("/api/guild/<guild_id>/employees/active")
@require_paid_api_access
def api_get_active_employees(user_session, guild_id):
    """
    Get active employees and their stats for the dashboard.
    """
    try:
        # Get timezone preference from query param or default
        timezone_name = request.args.get('timezone', 'America/New_York')
        
        employees = get_active_employees_with_stats(int(guild_id), timezone_name)
        
        # Enrich with avatar URLs (optional, if we had them in DB or could fetch from Discord)
        # For now, we'll rely on the frontend to handle avatars or basic placeholders
        # If we wanted real avatars, we'd need to fetch from Discord API or store them
        
        return jsonify({
            'success': True,
            'employees': employees
        })
    except Exception as e:
        app.logger.error(f"Error fetching active employees: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@api_guild_bp.route("/api/guild/<guild_id>/employees/calendar-list")
@require_paid_api_access
def api_get_employees_for_calendar(user_session, guild_id):
    """
    Get all employees for the admin calendar dropdown.
    Returns employees from profiles and sessions tables.
    """
    try:
        employees = []
        seen_users = set()
        
        with get_db() as conn:
            # First, get employees from employee_profiles for this guild
            cursor = conn.execute("""
                SELECT DISTINCT user_id, COALESCE(first_name, 'User ' || CAST(user_id AS text)) AS display_name, last_name AS full_name
                FROM employee_profiles
                WHERE guild_id = %s
                ORDER BY display_name
            """, (str(guild_id),))
            
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
                SELECT DISTINCT s.user_id, COALESCE(p.first_name, 'User ' || CAST(s.user_id AS text)) AS display_name, p.last_name AS full_name
                FROM timeclock_sessions s
                LEFT JOIN employee_profiles p ON s.user_id = p.user_id AND s.guild_id = p.guild_id
                WHERE s.guild_id = %s
                ORDER BY display_name
            """, (str(guild_id),))
            
            for row in cursor.fetchall():
                user_id = str(row['user_id'])
                if user_id not in seen_users:
                    seen_users.add(user_id)
                    employees.append({
                        'user_id': user_id,
                        'display_name': row.get('display_name') or row.get('full_name') or f"User {user_id}"
                    })
        
        return jsonify({
            'success': True,
            'employees': employees
        })
    except Exception as e:
        app.logger.error(f"Error fetching employees for calendar: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@api_guild_bp.route("/api/guild/<guild_id>/on-the-clock")
@require_paid_api_access
def api_get_on_the_clock(user_session, guild_id):
    """
    Get currently clocked-in coworkers for employee view.
    Employees can only see who is on the clock, not detailed stats.
    """
    try:
        # Verify user has access to this guild (admin or employee)
        guild, access_level = verify_guild_access(user_session, guild_id, allow_employee=True)
        if not guild:
            app.logger.warning(f"On-the-clock access denied for user {user_session.get('user_id')} to guild {guild_id}")
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        timezone_name = request.args.get('timezone', 'America/New_York')
        employees = get_active_employees_with_stats(int(guild_id), timezone_name)
        
        # For employee view, only return basic info about clocked-in coworkers
        coworkers = []
        for emp in employees:
            if emp.get('is_clocked_in'):
                coworkers.append({
                    'user_id': emp['user_id'],
                    'display_name': emp.get('display_name') or emp.get('full_name') or 'Unknown',
                    'is_clocked_in': True
                })
        
        return jsonify({
            'success': True,
            'coworkers': coworkers
        })
    except Exception as e:
        app.logger.error(f"Error fetching on-the-clock: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@api_guild_bp.route("/api/guild/<guild_id>/adjustments", methods=["POST"])
@require_paid_api_access
def api_create_adjustment(user_session, guild_id):
    """
    Submit a new time adjustment request.
    """
    try:
        data = request.json
        if not data:
            return jsonify({'success': False, 'error': 'Missing request body'}), 400
            
        request_type = data.get('request_type')
        reason = data.get('reason')
        original_session_id = data.get('original_session_id')
        
        if not request_type or not reason:
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400
            
        # Validate request type
        if request_type not in ['modify_clockin', 'modify_clockout', 'add_session', 'delete_session']:
            return jsonify({'success': False, 'error': 'Invalid request type'}), 400
            
        # Prepare requested data
        requested_data = {
            'clock_in': data.get('requested_clock_in'),
            'clock_out': data.get('requested_clock_out')
        }
        
        request_id = create_adjustment_request(
            guild_id=int(guild_id),
            user_id=int(user_session['user_id']),
            request_type=request_type,
            original_session_id=original_session_id,
            requested_data=requested_data,
            reason=reason
        )
        
        if request_id:
            # Notify admins via Discord (async)
            from bot import notify_admins_of_adjustment, bot
            if bot and bot.loop:
                asyncio.run_coroutine_threadsafe(
                    notify_admins_of_adjustment(int(guild_id), request_id),
                    bot.loop
                )
            
            # Queue email notification to verified recipients (non-blocking)
            from email_utils import queue_adjustment_notification_email
            queue_adjustment_notification_email(
                int(guild_id),
                request_id,
                int(user_session['user_id']),
                request_type,
                reason
            )
            
            return jsonify({'success': True, 'request_id': request_id})
        else:
            return jsonify({'success': False, 'error': 'Failed to create request'}), 500
            
    except Exception as e:
        app.logger.error(f"Error creating adjustment: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@api_guild_bp.route("/api/guild/<guild_id>/adjustments/pending")
@require_paid_api_access
def api_get_pending_adjustments(user_session, guild_id):
    """
    Get pending adjustment requests (Admin only).
    """
    try:
        # Verify admin access (already checked by decorator, but good to be explicit)
        # In a real app, we might want to restrict this further to specific roles
        
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT r.*, COALESCE(u.first_name, 'User ' || CAST(r.user_id AS text)) AS display_name, u.last_name AS full_name, u.custom_avatar_url AS avatar_url 
                FROM time_adjustment_requests r 
                LEFT JOIN employee_profiles u ON r.user_id = u.user_id AND r.guild_id = u.guild_id 
                WHERE r.guild_id = %s AND r.status = 'pending' 
                ORDER BY r.created_at DESC
            """, (int(guild_id),))
            requests = cursor.fetchall()
        
        # Convert datetime objects to ISO strings for JSON serialization
        serialized_requests = []
        for req in requests:
            req_dict = dict(req)
            # Handle datetime fields
            for key, value in req_dict.items():
                if isinstance(value, datetime):
                    req_dict[key] = value.isoformat()
            serialized_requests.append(req_dict)
            
        return jsonify({'success': True, 'requests': serialized_requests})
        
    except Exception as e:
        app.logger.error(f"Error fetching adjustments: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@api_guild_bp.route("/api/guild/<guild_id>/adjustments/<request_id>/approve", methods=["POST"])
@require_paid_api_access
def api_approve_adjustment(user_session, guild_id, request_id):
    """
    Approve an adjustment request.
    """
    try:
        success, message = approve_adjustment(
            request_id=int(request_id),
            guild_id=int(guild_id),
            reviewer_user_id=int(user_session['user_id'])
        )
        
        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'error': message}), 400
            
    except Exception as e:
        app.logger.error(f"Error approving adjustment: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@api_guild_bp.route("/api/guild/<guild_id>/adjustments/<request_id>/deny", methods=["POST"])
@require_paid_api_access
def api_deny_adjustment(user_session, guild_id, request_id):
    """
    Deny an adjustment request.
    """
    try:
        success, message = deny_adjustment(
            request_id=int(request_id),
            guild_id=int(guild_id),
            reviewer_user_id=int(user_session['user_id'])
        )
        
        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'error': message}), 400
            
    except Exception as e:
        app.logger.error(f"Error denying adjustment: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@api_guild_bp.route("/api/guild/<guild_id>/adjustments/submit-day", methods=["POST"])
@require_api_auth
def api_submit_day_adjustment(user_session, guild_id):
    """
    Submit adjustment request(s) for a specific day from the calendar popup.
    Accepts multiple session changes in one request.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        session_date = data.get('session_date')
        reason = data.get('reason', '').strip()
        changes = data.get('changes', [])
        
        if not session_date:
            return jsonify({'success': False, 'error': 'Session date is required'}), 400
        if not reason:
            return jsonify({'success': False, 'error': 'Reason is required'}), 400
        if not changes or len(changes) == 0:
            return jsonify({'success': False, 'error': 'No changes provided'}), 400
        
        user_id = int(user_session['user_id'])
        guild_id_int = int(guild_id)
        
        # Check guild has paid access
        access_status = check_guild_paid_access(guild_id)
        if not access_status['bot_invited'] or not access_status['bot_access_paid']:
            return jsonify({'success': False, 'error': 'Server does not have paid access'}), 403
        
        created_requests = []
        invalid_sessions = []
        
        with get_db() as conn:
            # First, validate all sessions belong to the user
            for change in changes:
                session_id = change.get('session_id')
                if not session_id:
                    return jsonify({'success': False, 'error': 'Invalid session data - missing session_id'}), 400
                
                cursor = conn.execute("""
                    SELECT session_id, clock_in_time, clock_out_time,
                           EXTRACT(EPOCH FROM (clock_out_time - clock_in_time)) as duration_seconds
                    FROM timeclock_sessions
                    WHERE session_id = %s AND guild_id = %s AND user_id = %s
                """, (session_id, str(guild_id), str(user_id)))
                
                if not cursor.fetchone():
                    invalid_sessions.append(session_id)
            
            # Reject if any sessions are invalid (not owned by user)
            if invalid_sessions:
                return jsonify({
                    'success': False, 
                    'error': 'Access denied - one or more sessions do not belong to you'
                }), 403
            
            # Now process each valid change
            for change in changes:
                session_id = change.get('session_id')
                new_clock_in = change.get('new_clock_in')
                new_clock_out = change.get('new_clock_out')
                original_clock_in = change.get('original_clock_in')
                original_clock_out = change.get('original_clock_out')
                
                # Get original session data (we know it exists and belongs to user)
                cursor = conn.execute("""
                    SELECT session_id, clock_in_time as clock_in, clock_out_time as clock_out,
                           EXTRACT(EPOCH FROM (clock_out_time - clock_in_time)) as duration_seconds
                    FROM timeclock_sessions
                    WHERE session_id = %s AND guild_id = %s AND user_id = %s
                """, (session_id, str(guild_id), str(user_id)))
                
                original_session = cursor.fetchone()
                
                # Parse new times and combine with session date
                import pytz
                from datetime import datetime as dt
                
                # Get guild timezone
                cursor = conn.execute(
                    "SELECT timezone FROM guild_settings WHERE guild_id = %s",
                    (guild_id_int,)
                )
                tz_row = cursor.fetchone()
                guild_tz_str = tz_row['timezone'] if tz_row else 'America/New_York'
                guild_tz = pytz.timezone(guild_tz_str)
                
                # Parse new clock in/out times
                requested_clock_in = None
                requested_clock_out = None
                
                if new_clock_in:
                    try:
                        date_parts = session_date.split('-')
                        time_parts = new_clock_in.split(':')
                        local_dt = dt(int(date_parts[0]), int(date_parts[1]), int(date_parts[2]),
                                     int(time_parts[0]), int(time_parts[1]))
                        requested_clock_in = guild_tz.localize(local_dt).astimezone(pytz.utc)
                    except Exception as e:
                        app.logger.error(f"Error parsing clock_in time: {e}")
                
                if new_clock_out:
                    try:
                        date_parts = session_date.split('-')
                        time_parts = new_clock_out.split(':')
                        local_dt = dt(int(date_parts[0]), int(date_parts[1]), int(date_parts[2]),
                                     int(time_parts[0]), int(time_parts[1]))
                        requested_clock_out = guild_tz.localize(local_dt).astimezone(pytz.utc)
                    except Exception as e:
                        app.logger.error(f"Error parsing clock_out time: {e}")
                
                # Calculate new duration if both times are set
                calculated_duration = None
                if requested_clock_in and requested_clock_out:
                    calculated_duration = int((requested_clock_out - requested_clock_in).total_seconds())
                
                # Create the adjustment request
                cursor = conn.execute("""
                    INSERT INTO time_adjustment_requests (
                        guild_id, user_id, request_type, original_session_id,
                        original_clock_in, original_clock_out, original_duration,
                        requested_clock_in, requested_clock_out, reason,
                        session_date, calculated_duration, status
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'pending')
                    RETURNING id
                """, (
                    guild_id_int, user_id, 'modify_session', session_id,
                    original_session['clock_in'], original_session['clock_out'], 
                    original_session['duration_seconds'],
                    requested_clock_in, requested_clock_out, reason,
                    session_date, calculated_duration
                ))
                
                new_request_id = cursor.fetchone()['id']
                created_requests.append(new_request_id)
                
                app.logger.info(f"[OK] Created adjustment request {new_request_id} for session {session_id} by user {user_id}")
        
        if created_requests:
            return jsonify({
                'success': True, 
                'message': f'Created {len(created_requests)} adjustment request(s)',
                'request_ids': created_requests
            })
        else:
            return jsonify({'success': False, 'error': 'No valid changes to submit'}), 400
            
    except Exception as e:
        app.logger.error(f"Error submitting day adjustment: {e}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': str(e)}), 500

@api_guild_bp.route("/api/guild/<guild_id>/adjustments/history")
@require_api_auth
def api_get_adjustment_history(user_session, guild_id):
    """
    Get adjustment request history.
    For employees: returns their own requests.
    For admins: returns all requests (or filtered by user_id param).
    Returns all requests (pending, approved, denied) for audit trail.
    """
    try:
        viewer_user_id = int(user_session['user_id'])
        
        # Check if user is admin
        admin_status = check_user_admin_realtime(viewer_user_id, guild_id)
        is_admin = admin_status.get('is_admin', False)
        
        # Determine which user's requests to fetch
        requested_user_id = request.args.get('user_id')
        if requested_user_id:
            target_user_id = int(requested_user_id)
        else:
            target_user_id = viewer_user_id
        
        # Non-admins can only see their own requests
        if not is_admin and target_user_id != viewer_user_id:
            target_user_id = viewer_user_id
        
        with get_db() as conn:
            if is_admin and not requested_user_id:
                # Admin viewing all - get all history
                cursor = conn.execute("""
                    SELECT r.*, COALESCE(u.first_name, 'User ' || CAST(r.user_id AS text)) AS display_name, u.last_name AS full_name, u.custom_avatar_url AS avatar_url 
                    FROM time_adjustment_requests r 
                    LEFT JOIN employee_profiles u ON r.user_id = u.user_id AND r.guild_id = u.guild_id 
                    WHERE r.guild_id = %s 
                    ORDER BY r.created_at DESC LIMIT 100
                """, (int(guild_id),))
            else:
                # Get specific user's history
                cursor = conn.execute("""
                    SELECT r.*, COALESCE(u.first_name, 'User ' || CAST(r.user_id AS text)) AS display_name, u.last_name AS full_name, u.custom_avatar_url AS avatar_url 
                    FROM time_adjustment_requests r 
                    LEFT JOIN employee_profiles u ON r.user_id = u.user_id AND r.guild_id = u.guild_id 
                    WHERE r.guild_id = %s AND r.user_id = %s
                    ORDER BY r.created_at DESC LIMIT 100
                """, (int(guild_id), target_user_id))
                
            adjustment_requests = cursor.fetchall()
        
        serialized_requests = []
        for req in adjustment_requests:
            req_dict = dict(req)
            for key, value in req_dict.items():
                if isinstance(value, datetime):
                    req_dict[key] = value.isoformat()
            serialized_requests.append(req_dict)
            
        return jsonify({'success': True, 'requests': serialized_requests, 'history': serialized_requests})
        
    except Exception as e:
        app.logger.error(f"Error fetching adjustment history: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@api_guild_bp.route("/api/guild/<guild_id>/adjustments/admin-calendar")
@require_api_auth
def api_get_admin_calendar_adjustments(user_session, guild_id):
    """
    Get pending adjustment requests grouped by date for admin calendar view.
    Returns data for the entire guild (all employees) for the specified month.
    
    Query params:
        year: Target year (required, e.g. 2025)
        month: Target month 1-12 (required, e.g. 11)
    
    Access control:
    - Admin only (verified via check_user_admin_realtime)
    """
    try:
        import calendar as cal_module
        from collections import defaultdict
        
        # Input validation
        if not guild_id.isdigit() or len(guild_id) > 20:
            return jsonify({'success': False, 'error': 'Invalid guild ID format'}), 400
        
        # Check guild has paid access
        access_status = check_guild_paid_access(guild_id)
        if not access_status['bot_invited'] or not access_status['bot_access_paid']:
            return jsonify({'success': False, 'error': 'Server does not have paid access'}), 403
        
        # Verify admin access
        admin_status = check_user_admin_realtime(user_session['user_id'], guild_id)
        if not admin_status.get('is_admin', False):
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        
        # Get and validate query parameters
        year_str = request.args.get('year')
        month_str = request.args.get('month')
        
        if not year_str or not month_str:
            return jsonify({'success': False, 'error': 'Missing required parameters: year and month'}), 400
        
        try:
            year = int(year_str)
            month = int(month_str)
        except ValueError:
            return jsonify({'success': False, 'error': 'Invalid year or month format'}), 400
        
        if not (1 <= month <= 12):
            return jsonify({'success': False, 'error': 'Month must be 1-12'}), 400
        if not (2020 <= year <= 2100):
            return jsonify({'success': False, 'error': 'Invalid year'}), 400
        
        # Calculate date range for the month
        first_day = datetime(year, month, 1, tzinfo=timezone.utc)
        last_day_num = cal_module.monthrange(year, month)[1]
        last_day = datetime(year, month, last_day_num, 23, 59, 59, tzinfo=timezone.utc)
        
        # Query pending adjustment requests for the guild in the date range
        # Use session_date if available, otherwise fall back to created_at date
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT r.id, r.guild_id, r.user_id, r.request_type, r.reason,
                       r.original_session_id, r.original_clock_in, r.original_clock_out,
                       r.requested_clock_in, r.requested_clock_out,
                       r.session_date, r.created_at, r.status,
                       COALESCE(r.session_date, DATE(r.created_at)) as effective_date,
                       COALESCE(p.display_name, p.full_name, CAST(r.user_id AS TEXT)) as user_name,
                       p.avatar_url
                FROM time_adjustment_requests r
                LEFT JOIN employee_profiles p ON r.user_id = p.user_id AND r.guild_id = p.guild_id
                WHERE r.guild_id = %s 
                  AND r.status = 'pending'
                  AND COALESCE(r.session_date, DATE(r.created_at)) >= %s
                  AND COALESCE(r.session_date, DATE(r.created_at)) <= %s
                ORDER BY COALESCE(r.session_date, DATE(r.created_at)), r.created_at
            """, (int(guild_id), first_day.date(), last_day.date()))
            
            rows = cursor.fetchall()
        
        # Group requests by date
        days_dict = defaultdict(list)
        total_pending = 0
        
        for row in rows:
            row_dict = dict(row)
            effective_date = row_dict.get('effective_date')
            
            if effective_date:
                date_str = effective_date.isoformat() if hasattr(effective_date, 'isoformat') else str(effective_date)
            else:
                continue
            
            # Build request object
            request_obj = {
                'id': row_dict['id'],
                'user_id': str(row_dict['user_id']),
                'user_name': row_dict.get('user_name') or str(row_dict['user_id']),
                'request_type': row_dict['request_type'],
                'reason': row_dict.get('reason'),
                'original_clock_in': row_dict['original_clock_in'].isoformat() if row_dict.get('original_clock_in') else None,
                'original_clock_out': row_dict['original_clock_out'].isoformat() if row_dict.get('original_clock_out') else None,
                'requested_clock_in': row_dict['requested_clock_in'].isoformat() if row_dict.get('requested_clock_in') else None,
                'requested_clock_out': row_dict['requested_clock_out'].isoformat() if row_dict.get('requested_clock_out') else None,
                'created_at': row_dict['created_at'].isoformat() if row_dict.get('created_at') else None,
                'status': row_dict['status']
            }
            
            days_dict[date_str].append(request_obj)
            total_pending += 1
        
        # Build days array
        days = []
        for date_str, requests_list in sorted(days_dict.items()):
            days.append({
                'date': date_str,
                'pending_count': len(requests_list),
                'requests': requests_list
            })
        
        return jsonify({
            'success': True,
            'data': {
                'year': year,
                'month': month,
                'days': days,
                'total_pending': total_pending
            }
        })
        
    except Exception as e:
        app.logger.error(f"Error fetching admin calendar adjustments: {e}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': str(e)}), 500

@api_guild_bp.route("/api/guild/<guild_id>/adjustments/resolved")
@require_api_auth
def api_get_resolved_adjustments(user_session, guild_id):
    """
    Get resolved (approved/denied) adjustment requests for the entire guild.
    Returns the last 50 resolved requests, most recently resolved first.
    
    Access control:
    - Admin only (verified via check_user_admin_realtime)
    """
    try:
        if not guild_id.isdigit() or len(guild_id) > 20:
            return jsonify({'success': False, 'error': 'Invalid guild ID format'}), 400
        
        access_status = check_guild_paid_access(guild_id)
        if not access_status['bot_invited'] or not access_status['bot_access_paid']:
            return jsonify({'success': False, 'error': 'Server does not have paid access'}), 403
        
        admin_status = check_user_admin_realtime(user_session['user_id'], guild_id)
        if not admin_status.get('is_admin', False):
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT r.id, r.user_id, r.request_type, r.reason, r.status,
                       r.reviewed_at, r.reviewed_by, r.created_at,
                       COALESCE(p.display_name, p.full_name, CONCAT(p.first_name, ' ', p.last_name)) as display_name
                FROM time_adjustment_requests r
                LEFT JOIN employee_profiles p ON r.user_id = p.user_id AND r.guild_id = p.guild_id
                WHERE r.guild_id = %s AND r.status IN ('approved', 'denied')
                ORDER BY r.reviewed_at DESC NULLS LAST
                LIMIT 50
            """, (int(guild_id),))
            
            rows = cursor.fetchall()
        
        requests_list = []
        for row in rows:
            row_dict = dict(row)
            requests_list.append({
                'id': row_dict['id'],
                'user_id': str(row_dict['user_id']),
                'display_name': row_dict.get('display_name') or str(row_dict['user_id']),
                'request_type': row_dict['request_type'],
                'reason': row_dict.get('reason'),
                'status': row_dict['status'],
                'reviewed_at': row_dict['reviewed_at'].isoformat() if row_dict.get('reviewed_at') else None,
                'reviewed_by': str(row_dict['reviewed_by']) if row_dict.get('reviewed_by') else None,
                'created_at': row_dict['created_at'].isoformat() if row_dict.get('created_at') else None
            })
        
        return jsonify({
            'success': True,
            'requests': requests_list
        })
        
    except Exception as e:
        app.logger.error(f"Error fetching resolved adjustments: {e}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': str(e)}), 500


@api_guild_bp.route("/api/guild/<guild_id>/admin/master-calendar")
@require_api_auth
def api_get_admin_master_calendar(user_session, guild_id):
    """
    Get aggregated calendar data for all employees (admin only).
    Returns sessions grouped by date with employee breakdown per day.
    
    Query params:
        year: Target year (default: current year)
        month: Target month 1-12 (default: current month)
    """
    try:
        import calendar as cal_module
        import pytz
        
        # Input validation
        if not guild_id.isdigit() or len(guild_id) > 20:
            return jsonify({'success': False, 'error': 'Invalid guild ID format'}), 400
        
        # Check guild has paid access
        access_status = check_guild_paid_access(guild_id)
        if not access_status['bot_invited'] or not access_status['bot_access_paid']:
            return jsonify({'success': False, 'error': 'Server does not have paid access'}), 403
        
        # Verify admin access
        admin_status = check_user_admin_realtime(user_session['user_id'], guild_id)
        if not admin_status.get('is_admin', False):
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        
        # Get query parameters
        now = datetime.now(timezone.utc)
        year = int(request.args.get('year', now.year))
        month = int(request.args.get('month', now.month))
        
        if not (1 <= month <= 12):
            return jsonify({'success': False, 'error': 'Month must be 1-12'}), 400
        if not (2020 <= year <= 2100):
            return jsonify({'success': False, 'error': 'Invalid year'}), 400
        
        # Get guild timezone
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT timezone FROM guild_settings WHERE guild_id = %s",
                (int(guild_id),)
            )
            row = cursor.fetchone()
            guild_tz_str = row['timezone'] if row else 'America/New_York'
        
        guild_tz = pytz.timezone(guild_tz_str)
        first_day = datetime(year, month, 1, 0, 0, 0)
        last_day_num = cal_module.monthrange(year, month)[1]
        last_day = datetime(year, month, last_day_num, 23, 59, 59)
        
        # Convert to UTC for database query
        first_day_utc = guild_tz.localize(first_day).astimezone(pytz.utc)
        last_day_utc = guild_tz.localize(last_day).astimezone(pytz.utc)
        
        # Query all sessions for the month with employee info (using timeclock_sessions)
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT 
                    s.session_id as id,
                    s.user_id,
                    s.clock_in_time as clock_in,
                    s.clock_out_time as clock_out,
                    EXTRACT(EPOCH FROM (s.clock_out_time - s.clock_in_time)) as duration_seconds,
                    DATE(s.clock_in_time AT TIME ZONE 'UTC' AT TIME ZONE %s) as work_date,
                    COALESCE(p.display_name, p.full_name, s.user_id) as employee_name,
                    (
                        SELECT COUNT(tar.id)
                        FROM time_adjustment_requests tar
                        WHERE tar.guild_id = s.guild_id 
                          AND tar.user_id = s.user_id 
                          AND tar.status = 'pending'
                          AND DATE(tar.created_at AT TIME ZONE 'UTC' AT TIME ZONE %s) = DATE(s.clock_in_time AT TIME ZONE 'UTC' AT TIME ZONE %s)
                    ) as pending_adjustments
                FROM timeclock_sessions s
                LEFT JOIN employee_profiles p ON s.user_id = p.user_id::text AND s.guild_id = p.guild_id::text
                WHERE s.guild_id = %s
                  AND s.clock_in_time >= %s
                  AND s.clock_in_time <= %s
                ORDER BY s.clock_in_time ASC
            """, (guild_tz_str, guild_tz_str, guild_tz_str, str(guild_id), first_day_utc, last_day_utc))
            
            sessions = cursor.fetchall()
            
            # Also get list of all employees for dropdown
            cursor = conn.execute("""
                SELECT user_id, 
                       COALESCE(display_name, full_name, CAST(user_id AS TEXT)) as name
                FROM employee_profiles 
                WHERE guild_id = %s
                ORDER BY COALESCE(display_name, full_name, CAST(user_id AS TEXT))
            """, (int(guild_id),))
            employees = [{'user_id': str(r['user_id']), 'name': r['name']} for r in cursor.fetchall()]
        
        # Group sessions by date
        days_data = {}
        for session in sessions:
            date_key = session['work_date'].isoformat()
            
            if date_key not in days_data:
                days_data[date_key] = {
                    'date': date_key,
                    'employees': {},
                    'total_sessions': 0,
                    'total_hours': 0
                }
            
            user_id = str(session['user_id'])
            if user_id not in days_data[date_key]['employees']:
                days_data[date_key]['employees'][user_id] = {
                    'user_id': user_id,
                    'name': session['employee_name'],
                    'sessions': [],
                    'total_seconds': 0,
                    'pending_adjustments': 0
                }
            
            # Convert timestamps to guild timezone
            clock_in_local = session['clock_in'].replace(tzinfo=pytz.utc).astimezone(guild_tz)
            clock_out_local = session['clock_out'].replace(tzinfo=pytz.utc).astimezone(guild_tz) if session['clock_out'] else None
            
            session_data = {
                'id': session['id'],
                'clock_in': clock_in_local.isoformat(),
                'clock_out': clock_out_local.isoformat() if clock_out_local else None,
                'duration_seconds': session['duration_seconds'] or 0
            }
            
            days_data[date_key]['employees'][user_id]['sessions'].append(session_data)
            days_data[date_key]['employees'][user_id]['total_seconds'] += session['duration_seconds'] or 0
            
            # Use max to avoid duplicating the count if a user has multiple sessions in one day
            current_adjustments = days_data[date_key]['employees'][user_id]['pending_adjustments']
            days_data[date_key]['employees'][user_id]['pending_adjustments'] = max(current_adjustments, session['pending_adjustments'] or 0)
            days_data[date_key]['total_sessions'] += 1
            days_data[date_key]['total_hours'] += (session['duration_seconds'] or 0) / 3600
        
        # Convert employees dict to list for each day
        days_list = []
        for date_key in sorted(days_data.keys()):
            day = days_data[date_key]
            day['employees'] = list(day['employees'].values())
            day['employee_count'] = len(day['employees'])
            day['total_hours'] = round(day['total_hours'], 2)
            days_list.append(day)
        
        return jsonify({
            'success': True,
            'data': {
                'year': year,
                'month': month,
                'timezone': guild_tz_str,
                'days': days_list,
                'employees': employees
            }
        })
        
    except Exception as e:
        app.logger.error(f"Error fetching admin master calendar: {e}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': str(e)}), 500


@api_guild_bp.route("/api/guild/<guild_id>/employee/<user_id>/monthly-timecard")
@require_api_auth
def api_get_monthly_timecard(user_session, guild_id, user_id):
    """
    Get monthly timecard data for calendar view.
    Returns sessions grouped by date with daily totals.
    
    Access control:
    - Employees can view their OWN calendar
    - Admins can view any employee's calendar
    
    Query params:
        year: Target year (default: current year)
        month: Target month 1-12 (default: current month)
        timezone: Guild timezone (default: fetch from guild settings)
    """
    try:
        # Input validation
        if not guild_id.isdigit() or len(guild_id) > 20:
            return jsonify({'success': False, 'error': 'Invalid guild ID format'}), 400
        if not user_id.isdigit() or len(user_id) > 20:
            return jsonify({'success': False, 'error': 'Invalid user ID format'}), 400
        
        # Check guild has paid access
        access_status = check_guild_paid_access(guild_id)
        if not access_status['bot_invited'] or not access_status['bot_access_paid']:
            return jsonify({'success': False, 'error': 'Server does not have paid access'}), 403
        
        # Authorization: allow if viewing own data OR if admin
        current_user_id = str(user_session.get('user_id', ''))
        is_own_data = current_user_id == str(user_id)
        
        if not is_own_data:
            # Check if user is admin to view others' data
            admin_status = check_user_admin_realtime(user_session['user_id'], guild_id)
            if not admin_status.get('is_admin', False):
                return jsonify({'success': False, 'error': 'Access denied - you can only view your own calendar'}), 403
        
        # Get query parameters
        now = datetime.now(timezone.utc)
        year = int(request.args.get('year', now.year))
        month = int(request.args.get('month', now.month))
        
        # Validate month/year
        if not (1 <= month <= 12):
            return jsonify({'success': False, 'error': 'Month must be 1-12'}), 400
        if not (2020 <= year <= 2100):
            return jsonify({'success': False, 'error': 'Invalid year'}), 400
        
        # Get guild timezone
        guild_tz_str = request.args.get('timezone')
        if not guild_tz_str:
            with get_db() as conn:
                cursor = conn.execute(
                    "SELECT timezone FROM guild_settings WHERE guild_id = %s",
                    (int(guild_id),)
                )
                row = cursor.fetchone()
                guild_tz_str = row['timezone'] if row else 'America/New_York'
        
        # Calculate date range for the month
        import calendar
        from datetime import datetime as dt
        import pytz
        
        guild_tz = pytz.timezone(guild_tz_str)
        first_day = dt(year, month, 1, 0, 0, 0)
        last_day_num = calendar.monthrange(year, month)[1]
        last_day = dt(year, month, last_day_num, 23, 59, 59)
        
        # Convert to UTC for database query (sessions stored in UTC)
        first_day_utc = guild_tz.localize(first_day).astimezone(pytz.utc)
        last_day_utc = guild_tz.localize(last_day).astimezone(pytz.utc)
        
        # Query sessions for the month (using timeclock_sessions)
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT 
                    session_id as id,
                    clock_in_time as clock_in,
                    clock_out_time as clock_out,
                    EXTRACT(EPOCH FROM (clock_out_time - clock_in_time)) as duration_seconds,
                    DATE(clock_in_time AT TIME ZONE 'UTC' AT TIME ZONE %s) as work_date
                FROM timeclock_sessions
                WHERE guild_id = %s
                  AND user_id = %s
                  AND clock_in_time >= %s
                  AND clock_in_time <= %s
                ORDER BY clock_in_time ASC
            """, (guild_tz_str, str(guild_id), str(user_id), first_day_utc, last_day_utc))
            
            sessions = cursor.fetchall()
        
        # Group sessions by date
        sessions_by_date = {}
        for session in sessions:
            date_key = session['work_date'].isoformat()
            
            if date_key not in sessions_by_date:
                sessions_by_date[date_key] = {
                    'date': date_key,
                    'sessions': [],
                    'total_seconds': 0,
                    'total_hours': 0
                }
            
            # Convert timestamps to guild timezone for display
            clock_in_local = session['clock_in'].replace(tzinfo=pytz.utc).astimezone(guild_tz) if session['clock_in'] else None
            clock_out_local = session['clock_out'].replace(tzinfo=pytz.utc).astimezone(guild_tz) if session['clock_out'] else None
            
            session_data = {
                'id': session['id'],
                'clock_in': clock_in_local.isoformat() if clock_in_local else None,
                'clock_out': clock_out_local.isoformat() if clock_out_local else None,
                'duration_seconds': session['duration_seconds'] or 0
            }
            
            sessions_by_date[date_key]['sessions'].append(session_data)
            if session['duration_seconds']:
                sessions_by_date[date_key]['total_seconds'] += session['duration_seconds']
        
        # Calculate total hours for each date
        for date_key in sessions_by_date:
            total_seconds = sessions_by_date[date_key]['total_seconds']
            sessions_by_date[date_key]['total_hours'] = round(total_seconds / 3600, 2)
        
        # Fetch adjustment requests for this month to show status on calendar
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT 
                    id,
                    session_date,
                    original_session_id,
                    request_type,
                    status,
                    requested_clock_in,
                    requested_clock_out,
                    reason,
                    reviewed_by,
                    reviewed_at,
                    created_at
                FROM time_adjustment_requests
                WHERE guild_id = %s
                  AND user_id = %s
                  AND (
                      session_date >= %s AND session_date <= %s
                      OR (session_date IS NULL AND created_at >= %s AND created_at <= %s)
                  )
                ORDER BY created_at DESC
            """, (int(guild_id), int(user_id), 
                  f"{year}-{month:02d}-01", f"{year}-{month:02d}-{last_day_num}",
                  first_day_utc, last_day_utc))
            
            adjustments = cursor.fetchall()
        
        # Map adjustments to their dates
        adjustments_by_date = {}
        for adj in adjustments:
            if adj['session_date']:
                adj_date_key = adj['session_date'].isoformat()
            elif adj['requested_clock_in']:
                # Use requested_clock_in date if session_date not set
                adj_in_local = adj['requested_clock_in'].replace(tzinfo=pytz.utc).astimezone(guild_tz)
                adj_date_key = adj_in_local.strftime('%Y-%m-%d')
            else:
                continue
                
            if adj_date_key not in adjustments_by_date:
                adjustments_by_date[adj_date_key] = []
            
            adjustments_by_date[adj_date_key].append({
                'id': adj['id'],
                'request_type': adj['request_type'],
                'status': adj['status'],
                'reason': adj['reason'],
                'requested_clock_in': adj['requested_clock_in'].isoformat() if adj['requested_clock_in'] else None,
                'requested_clock_out': adj['requested_clock_out'].isoformat() if adj['requested_clock_out'] else None,
                'reviewed_by': str(adj['reviewed_by']) if adj['reviewed_by'] else None,
                'reviewed_at': adj['reviewed_at'].isoformat() if adj['reviewed_at'] else None,
                'created_at': adj['created_at'].isoformat() if adj['created_at'] else None
            })
        
        # Merge adjustments into session data and calculate day status
        for date_key in sessions_by_date:
            day_data = sessions_by_date[date_key]
            day_adjustments = adjustments_by_date.get(date_key, [])
            day_data['adjustments'] = day_adjustments
            
            # Determine overall status for the day
            # Priority: pending > approved/denied (show most relevant)
            if any(adj['status'] == 'pending' for adj in day_adjustments):
                day_data['adjustment_status'] = 'pending'
            elif any(adj['status'] == 'approved' for adj in day_adjustments):
                day_data['adjustment_status'] = 'approved'
            elif any(adj['status'] == 'denied' for adj in day_adjustments):
                day_data['adjustment_status'] = 'denied'
            else:
                day_data['adjustment_status'] = None
        
        # Convert to list sorted by date
        calendar_data = sorted(sessions_by_date.values(), key=lambda x: x['date'])
        
        return jsonify({
            'success': True,
            'data': {
                'year': year,
                'month': month,
                'timezone': guild_tz_str,
                'days': calendar_data
            }
        })
        
    except ValueError as e:
        app.logger.error(f"Invalid parameter in monthly timecard request: {e}")
        return jsonify({'success': False, 'error': 'Invalid parameters'}), 400
    except Exception as e:
        app.logger.error(f"Error fetching monthly timecard: {e}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Failed to fetch timecard data'}), 500

@api_guild_bp.route("/api/guild/<guild_id>/clock-out", methods=["POST"])
@require_api_auth
def api_clock_out(user_session, guild_id):
    """
    Clock out the current user from their active session.
    
    Validates that the user has an active session (clock_out IS NULL)
    and updates it with the current time as clock_out.
    """
    try:
        if not guild_id.isdigit() or len(guild_id) > 20:
            return jsonify({'success': False, 'error': 'Invalid guild ID'}), 400
        
        guild_id_int = int(guild_id)
        user_id = int(user_session['user_id'])
        
        access_status = check_guild_paid_access(guild_id)
        if not access_status['bot_invited'] or not access_status['bot_access_paid']:
            return jsonify({'success': False, 'error': 'Server does not have paid access'}), 403
        
        with get_db() as conn:
            if conn is None:
                app.logger.error("Database connection failed in api_clock_out")
                return jsonify({'success': False, 'error': 'Database connection error'}), 500
                
            cursor = conn.execute("""
                SELECT session_id, clock_in_time, clock_out_time
                FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s AND clock_out_time IS NULL
                ORDER BY clock_in_time DESC
                LIMIT 1
            """, (str(guild_id), str(user_id)))
            
            active_session = cursor.fetchone()
            
            if not active_session:
                return jsonify({'success': False, 'error': 'No active session found'}), 404
            
            session_id = active_session['session_id']
            clock_in = active_session['clock_in_time']
            clock_out_time = datetime.now(timezone.utc)
            
            if clock_in.tzinfo is None:
                clock_in = clock_in.replace(tzinfo=timezone.utc)
            
            duration_seconds = int((clock_out_time - clock_in).total_seconds())
            
            conn.execute("""
                UPDATE timeclock_sessions
                SET clock_out_time = %s
                WHERE session_id = %s
            """, (clock_out_time, session_id))
        
        return jsonify({
            'success': True,
            'message': 'Successfully clocked out',
            'session': {
                'id': session_id,
                'clock_in': clock_in.isoformat(),
                'clock_out': clock_out_time.isoformat(),
                'duration_seconds': duration_seconds
            }
        })
        
    except Exception as e:
        app.logger.error(f"Error clocking out: {e}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Failed to clock out'}), 500

@api_guild_bp.route("/api/guild/<guild_id>/admin/edit-session", methods=["POST"])
@require_api_auth
def api_admin_edit_session(user_session, guild_id):
    """
    Admin endpoint to directly edit a session's clock in/out times.
    Creates an audit log entry for the change.
    """
    try:
        if not guild_id.isdigit() or len(guild_id) > 20:
            return jsonify({'success': False, 'error': 'Invalid guild ID'}), 400
        
        # Check guild has paid access
        access_status = check_guild_paid_access(guild_id)
        if not access_status['bot_invited'] or not access_status['bot_access_paid']:
            return jsonify({'success': False, 'error': 'Server does not have paid access'}), 403
        
        # Verify admin access
        admin_status = check_user_admin_realtime(user_session['user_id'], guild_id)
        if not admin_status.get('is_admin', False):
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        
        data = request.get_json()
        session_id = data.get('session_id')
        new_clock_in = data.get('clock_in')
        new_clock_out = data.get('clock_out')
        reason = data.get('reason', 'Admin adjustment')
        
        if not session_id:
            return jsonify({'success': False, 'error': 'Session ID required'}), 400
        
        import pytz
        
        with get_db() as conn:
            # Get original session (using timeclock_sessions)
            cursor = conn.execute("""
                SELECT session_id, user_id, clock_in_time, clock_out_time,
                       EXTRACT(EPOCH FROM (clock_out_time - clock_in_time)) as duration_seconds
                FROM timeclock_sessions
                WHERE session_id = %s AND guild_id = %s
            """, (session_id, str(guild_id)))
            
            session = cursor.fetchone()
            if not session:
                return jsonify({'success': False, 'error': 'Session not found'}), 404
            
            # Parse new times
            updates = {}
            if new_clock_in:
                updates['clock_in_time'] = datetime.fromisoformat(new_clock_in.replace('Z', '+00:00'))
            if new_clock_out:
                updates['clock_out_time'] = datetime.fromisoformat(new_clock_out.replace('Z', '+00:00'))
            
            if not updates:
                return jsonify({'success': False, 'error': 'No changes provided'}), 400
            
            # Calculate new duration if both times are set
            final_clock_in = updates.get('clock_in_time', session['clock_in_time'])
            final_clock_out = updates.get('clock_out_time', session['clock_out_time'])
            
            if final_clock_in and final_clock_out:
                if final_clock_in.tzinfo is None:
                    final_clock_in = final_clock_in.replace(tzinfo=timezone.utc)
                if final_clock_out.tzinfo is None:
                    final_clock_out = final_clock_out.replace(tzinfo=timezone.utc)
                
                # Validate clock_out is after clock_in
                if final_clock_out <= final_clock_in:
                    return jsonify({'success': False, 'error': 'Clock out must be after clock in'}), 400
                
                new_duration = int((final_clock_out - final_clock_in).total_seconds())
                
                # Sanity check - max 24 hours per session
                if new_duration > 86400:
                    return jsonify({'success': False, 'error': 'Session duration cannot exceed 24 hours'}), 400
            else:
                new_duration = session['duration_seconds'] or 0
            
            # Update session (timeclock_sessions)
            conn.execute("""
                UPDATE timeclock_sessions
                SET clock_in_time = COALESCE(%s, clock_in_time),
                    clock_out_time = COALESCE(%s, clock_out_time)
                WHERE session_id = %s
            """, (updates.get('clock_in_time'), updates.get('clock_out_time'), session_id))
            
            # Log the change using JSONB details column (table schema: id, request_id, action, actor_id, timestamp, details)
            def safe_isoformat(val):
                """Safely convert datetime to ISO string, handling None and already-string values"""
                if val is None:
                    return None
                if isinstance(val, str):
                    return val
                if hasattr(val, 'isoformat'):
                    return val.isoformat()
                return str(val)
            
            audit_details = {
                'action_type': 'admin_edit',
                'guild_id': str(guild_id),
                'user_id': session['user_id'],
                'session_id': session_id,
                'old_clock_in': safe_isoformat(session['clock_in_time']),
                'old_clock_out': safe_isoformat(session['clock_out_time']),
                'new_clock_in': safe_isoformat(updates.get('clock_in_time')),
                'new_clock_out': safe_isoformat(updates.get('clock_out_time')),
                'reason': reason
            }
            conn.execute("""
                INSERT INTO adjustment_audit_log 
                (action, actor_id, details)
                VALUES (%s, %s, %s)
            """, ('admin_edit', int(user_session['user_id']), json.dumps(audit_details)))
        
        app.logger.info(f"Admin {user_session.get('username')} edited session {session_id} in guild {guild_id}")
        
        return jsonify({
            'success': True,
            'message': 'Session updated successfully',
            'session_id': session_id
        })
        
    except Exception as e:
        app.logger.error(f"Error editing session: {e}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': str(e)}), 500


@api_guild_bp.route("/api/guild/<guild_id>/employees/<user_id>/clock-out", methods=["POST"])
@require_paid_api_access
def api_admin_clock_out_employee(user_session, guild_id, user_id):
    """
    Admin endpoint to clock out a specific employee.
    
    This allows admins to manually clock out employees from the dashboard.
    Validates that the target user has an active session (clock_out IS NULL)
    and updates it with the current time as clock_out.
    """
    try:
        if not guild_id.isdigit() or len(guild_id) > 20:
            return jsonify({'success': False, 'error': 'Invalid guild ID'}), 400
        
        if not user_id.isdigit() or len(user_id) > 20:
            return jsonify({'success': False, 'error': 'Invalid user ID'}), 400
        
        guild_id_int = int(guild_id)
        user_id_int = int(user_id)
        
        access_status = check_guild_paid_access(guild_id)
        if not access_status['bot_invited'] or not access_status['bot_access_paid']:
            return jsonify({'success': False, 'error': 'Server does not have paid access'}), 403
        
        # CRITICAL: Verify the caller has admin access to this guild
        admin_status = check_user_admin_realtime(user_session['user_id'], guild_id)
        if not admin_status.get('is_admin', False):
            app.logger.warning(f"Non-admin user {user_session.get('user_id')} attempted to clock out user {user_id} in guild {guild_id}")
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        
        with get_db() as conn:
            if conn is None:
                app.logger.error("Database connection failed in api_admin_clock_out_employee")
                return jsonify({'success': False, 'error': 'Database connection error'}), 500
                
            cursor = conn.execute("""
                SELECT session_id, clock_in_time, clock_out_time
                FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s AND clock_out_time IS NULL
                ORDER BY clock_in_time DESC
                LIMIT 1
            """, (str(guild_id), str(user_id)))
            
            active_session = cursor.fetchone()
            
            if not active_session:
                return jsonify({'success': False, 'error': 'No active session found for this employee'}), 404
            
            session_id = active_session['session_id']
            clock_in = active_session['clock_in_time']
            clock_out_time = datetime.now(timezone.utc)
            
            if clock_in.tzinfo is None:
                clock_in = clock_in.replace(tzinfo=timezone.utc)
            
            duration_seconds = int((clock_out_time - clock_in).total_seconds())
            
            conn.execute("""
                UPDATE timeclock_sessions
                SET clock_out_time = %s
                WHERE session_id = %s
            """, (clock_out_time, session_id))
        
        app.logger.info(f"Admin {user_session.get('username')} clocked out user {user_id} in guild {guild_id}")
        
        return jsonify({
            'success': True,
            'message': 'Employee successfully clocked out',
            'session': {
                'id': session_id,
                'clock_in': clock_in.isoformat(),
                'clock_out': clock_out_time.isoformat(),
                'duration_seconds': duration_seconds
            }
        })
        
    except Exception as e:
        app.logger.error(f"Error in admin clock out: {e}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Failed to clock out employee'}), 500


@api_guild_bp.route("/api/server/<guild_id>/employee/<user_id>/reset-pin", methods=["POST"])
@require_paid_api_access
def api_reset_employee_pin(user_session, guild_id, user_id):
    """Reset/regenerate an employee's kiosk PIN token"""
    try:
        guild, access_level = verify_guild_access(user_session, guild_id)
        if not guild or access_level != 'admin':
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        
        with get_db() as conn:
            conn.execute("""
                DELETE FROM employee_profile_tokens 
                WHERE guild_id = %s AND user_id = %s
            """, (int(guild_id), int(user_id)))
            
            conn.execute("""
                INSERT INTO employee_profile_tokens (guild_id, user_id, delivery_method, expires_at)
                VALUES (%s, %s, 'ephemeral', NOW() + INTERVAL '30 days')
            """, (int(guild_id), int(user_id)))
        
        app.logger.info(f"Admin {user_session.get('username')} reset PIN for user {user_id} in guild {guild_id}")
        return jsonify({'success': True, 'message': 'Kiosk PIN has been reset'})
        
    except Exception as e:
        app.logger.error(f"Error resetting PIN: {e}")
        return jsonify({'success': False, 'error': 'Failed to reset PIN'}), 500


@api_guild_bp.route("/api/server/<guild_id>/employee/<user_id>/rerun-onboarding", methods=["POST"])
@require_paid_api_access
def api_rerun_employee_onboarding(user_session, guild_id, user_id):
    """Reset onboarding flags and trigger welcome DM for an employee"""
    try:
        guild, access_level = verify_guild_access(user_session, guild_id)
        if not guild or access_level != 'admin':
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        
        with get_db() as conn:
            cursor = conn.execute("""
                UPDATE employee_profiles 
                SET welcome_dm_sent = FALSE, first_clock_used = FALSE
                WHERE guild_id = %s AND user_id = %s
                RETURNING display_name, full_name
            """, (int(guild_id), int(user_id)))
            row = cursor.fetchone()
            
            if not row:
                return jsonify({'success': False, 'error': 'Employee not found'}), 404
        
        try:
            from bot import trigger_welcome_dm
            result = trigger_welcome_dm(int(guild_id), int(user_id))
            if result.get('success'):
                app.logger.info(f"Admin {user_session.get('username')} reran onboarding for user {user_id} in guild {guild_id}")
                return jsonify({'success': True, 'message': 'Welcome DM sent successfully'})
            else:
                return jsonify({'success': True, 'message': 'Onboarding flags reset (DM may not have sent - user may have DMs disabled)'})
        except Exception as dm_error:
            app.logger.warning(f"DM failed during rerun onboarding: {dm_error}")
            return jsonify({'success': True, 'message': 'Onboarding flags reset (DM could not be sent)'})
        
    except Exception as e:
        app.logger.error(f"Error rerunning onboarding: {e}")
        return jsonify({'success': False, 'error': 'Failed to rerun onboarding'}), 500


# Employee Detail View API Endpoints
@api_guild_bp.route("/api/guild/<guild_id>/employee/<user_id>/detail")
@require_paid_api_access
def api_get_employee_detail(user_session, guild_id, user_id):
    """
    Get comprehensive employee detail including profile, status, and statistics.
    """
    try:
        from bot import get_active_employees_with_stats
        
        # Get employee data with stats
        timezone_name = request.args.get('timezone', 'America/New_York')
        employees = get_active_employees_with_stats(int(guild_id), timezone_name)
        
        # Find the specific employee
        employee = None
        for emp in employees:
            if str(emp.get('user_id')) == str(user_id):
                employee = emp
                break
        
        # If not in active list, get from database (using Flask's get_db)
        if not employee:
            with get_db() as conn:
                cursor = conn.execute("""
                    SELECT user_id, username, display_name
                    FROM employee_profiles
                    WHERE guild_id = %s AND user_id = %s
                """, (int(guild_id), user_id))
                profile = cursor.fetchone()
                
                if profile:
                    employee = {
                        'user_id': profile['user_id'],
                        'username': profile['username'],
                        'display_name': profile['display_name'],
                        'status': 'clocked_out',
                        'hours_today': 0,
                        'hours_week': 0,
                        'hours_month': 0
                    }
        
        if not employee:
            return jsonify({'success': False, 'error': 'Employee not found'}), 404
        
        # Get total sessions count (using timeclock_sessions)
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT COUNT(*) as total_sessions
                FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s
            """, (str(guild_id), str(user_id)))
            result = cursor.fetchone()
            employee['total_sessions'] = result['total_sessions'] if result else 0
        
        return jsonify({'success': True, 'employee': employee})
        
    except Exception as e:
        app.logger.error(f"Error fetching employee detail: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@api_guild_bp.route("/api/guild/<guild_id>/employee/<user_id>/timecard")
@require_paid_api_access
def api_get_employee_timecard(user_session, guild_id, user_id):
    """
    Get weekly timecard for an employee showing daily clock in/out times.
    """
    try:
        from datetime import date, timedelta
        
        # Get week start (default to current week's Monday)
        week_param = request.args.get('week')
        if week_param:
            week_start = datetime.fromisoformat(week_param).date()
        else:
            today = date.today()
            week_start = today - timedelta(days=today.weekday())
        
        timezone_name = request.args.get('timezone', 'America/New_York')
        
        # Get sessions for the week (using Flask's get_db)
        week_end = week_start + timedelta(days=7)
        
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT clock_in_time as clock_in, clock_out_time as clock_out, 
                       EXTRACT(EPOCH FROM (clock_out_time - clock_in_time)) as duration_seconds
                FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s
                AND clock_in_time::date >= %s AND clock_in_time::date < %s
                ORDER BY clock_in_time ASC
            """, (str(guild_id), str(user_id), week_start, week_end))
            sessions = cursor.fetchall()
        
        # Build 7-day structure
        days = []
        week_total_seconds = 0
        day_names = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        
        for i in range(7):
            current_date = week_start + timedelta(days=i)
            day_sessions = [s for s in sessions if s['clock_in'].date() == current_date]
            
            if day_sessions:
                # Use first session of the day
                session = day_sessions[0]
                day_data = {
                    'date': current_date.isoformat(),
                    'day_name': day_names[i],
                    'clock_in': session['clock_in'].isoformat() if session['clock_in'] else None,
                    'clock_out': session['clock_out'].isoformat() if session['clock_out'] else None,
                    'duration_hours': round(session['duration_seconds'] / 3600, 2) if session['duration_seconds'] else 0,
                    'status': 'complete' if session['clock_out'] else 'in_progress'
                }
                week_total_seconds += session['duration_seconds'] or 0
            else:
                day_data = {
                    'date': current_date.isoformat(),
                    'day_name': day_names[i],
                    'clock_in': None,
                    'clock_out': None,
                    'duration_hours': 0,
                    'status': 'absent'
                }
            
            days.append(day_data)
        
        return jsonify({
            'success': True,
            'week_start': week_start.isoformat(),
            'days': days,
            'week_total_hours': round(week_total_seconds / 3600, 2)
        })
        
    except Exception as e:
        app.logger.error(f"Error fetching employee timecard: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@api_guild_bp.route("/api/guild/<guild_id>/employee/<user_id>/adjustments/recent")
@require_paid_api_access
def api_get_employee_recent_adjustments(user_session, guild_id, user_id):
    """
    Get top 3 most recent adjustment requests for an employee.
    """
    try:
        # Using Flask's get_db for production database
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT id, request_type, status, created_at, reason,
                       original_clock_in, original_clock_out,
                       requested_clock_in, requested_clock_out,
                       reviewed_by, reviewed_at
                FROM time_adjustment_requests
                WHERE guild_id = %s AND user_id = %s
                ORDER BY created_at DESC
                LIMIT 3
            """, (int(guild_id), user_id))
            requests = cursor.fetchall()
        
        serialized_requests = []
        for req in requests:
            req_dict = dict(req)
            for key, value in req_dict.items():
                if isinstance(value, datetime):
                    req_dict[key] = value.isoformat()
            serialized_requests.append(req_dict)
        
        return jsonify({'success': True, 'requests': serialized_requests})
        
    except Exception as e:
        app.logger.error(f"Error fetching recent adjustments: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


