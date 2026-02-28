import os
import traceback
import logging
from flask import Blueprint, render_template, redirect, request, session, jsonify, current_app as app

from app import (
    require_auth, get_flask_guild_access, get_all_user_guilds, is_demo_server, 
    __version__, CHANGELOG,  verify_guild_access, Entitlements, UserRole
)

from web.utils.db import get_db

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route("/dashboard/invite")
def dashboard_invite():
    """Page shown when user tries to access dashboard but bot is not invited to their server."""
    discord_client_id = os.getenv("DISCORD_CLIENT_ID", "1418446753379913809")
    invite_url = f"https://discord.com/oauth2/authorize?client_id={discord_client_id}&permissions=8&scope=bot%20applications.commands"
    return render_template('dashboard_invite.html', invite_url=invite_url)

@dashboard_bp.route("/dashboard/purchase")
def dashboard_purchase():
    """Page shown when user tries to access dashboard but server doesn't have paid bot access."""
    guild_id = request.args.get('guild_id')
    access = get_flask_guild_access(guild_id) if guild_id else None
    return render_template('dashboard_purchase.html', guild_id=guild_id, access=access)

@dashboard_bp.route("/dashboard/no-access")
def dashboard_no_access():
    """Page shown when user tries to access dashboard but doesn't have admin permissions."""
    return render_template('dashboard_no_access.html')

@dashboard_bp.route("/dashboard")
@require_auth
def dashboard(user_session):
    """Protected dashboard showing user info and guilds where user has admin or employee access"""
    try:
        app.logger.info(f"Dashboard accessed by user: {user_session.get('username')}")
        
        # Get all guilds where user has access (admin or employee)
        all_guilds = get_all_user_guilds(user_session)
        admin_guilds = all_guilds['admin_guilds']
        employee_guilds = all_guilds['employee_guilds']

        # Check if user is bot owner
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        is_bot_owner = str(user_session.get('user_id')) == str(bot_owner_id)

        # Create a modified user session with both admin and employee guilds
        dashboard_data = {
            **user_session,
            'guilds': admin_guilds,  # Maintain backward compatibility
            'admin_guilds': admin_guilds,
            'employee_guilds': employee_guilds,
            'total_guilds': len(user_session.get('guilds', [])),
            'filtered_count': len(admin_guilds) + len(employee_guilds),
            'is_bot_owner': is_bot_owner
        }
        
        app.logger.info(f"Showing {len(admin_guilds)} admin guilds and {len(employee_guilds)} employee-only guilds")
        return render_template('dashboard.html', 
                             user=dashboard_data, 
                             version=__version__, 
                             recent_updates=CHANGELOG[:3])  # Top 3 most recent updates
    except Exception as e:
        app.logger.error(f"Dashboard rendering error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return "<h1>Error</h1><p>Unable to load dashboard. Please try again later.</p><a href='/auth/logout'>Logout</a>", 500


def get_server_page_context(user_session, guild_id, active_page):
    """
    Helper to build common context for server-specific dashboard pages.
    Returns (context_dict, error_response) - error_response is None if successful.
    """
    guild, access_level = verify_guild_access(user_session, guild_id, allow_employee=True)
    if not guild:
        return None, redirect('/dashboard')


    is_demo_server_flag = is_demo_server(guild_id)
    view_as_employee = False
    last_demo_reset = None

    if is_demo_server_flag:
        view_as_employee = request.args.get('view_as') == 'employee' or session.get('demo_view_as_employee', False)
        if request.args.get('view_as') == 'employee':
            session['demo_view_as_employee'] = True
            view_as_employee = True
        elif request.args.get('view_as') == 'admin':
            session['demo_view_as_employee'] = False
            view_as_employee = False
        
        if view_as_employee and access_level == 'admin':
            access_level = 'employee'
    
    user_id = user_session.get('user_id')
    is_also_employee = False
    pending_adjustments = 0
    show_tz_reminder = False
    server_settings = {}
    
    total_shifts = 0
    with get_db() as conn:
        if access_level == 'admin':
            cursor = conn.execute("""
                SELECT COUNT(*) as count FROM time_adjustment_requests 
                WHERE guild_id = %s AND status = 'pending'
            """, (int(guild_id),))
            result = cursor.fetchone()
            pending_adjustments = result['count'] if result else 0
            
            cursor = conn.execute("""
                SELECT COUNT(*) as count FROM timeclock_sessions 
                WHERE guild_id = %s
            """, (int(guild_id),))
            result = cursor.fetchone()
            total_shifts = result['count'] if result else 0
            
            cursor = conn.execute("""
                SELECT 1 FROM employee_profiles 
                WHERE guild_id = %s AND user_id = %s AND is_active = TRUE
            """, (int(guild_id), user_id))
            is_also_employee = cursor.fetchone() is not None
            
            cursor = conn.execute("""
                SELECT timezone, has_completed_onboarding 
                FROM guild_settings WHERE guild_id = %s
            """, (int(guild_id),))
            tz_row = cursor.fetchone()
            show_tz_reminder = not tz_row or not tz_row.get('timezone')
            has_completed_onboarding = tz_row.get('has_completed_onboarding', False) if tz_row else False
        else:
            has_completed_onboarding = False
        
        # Get error_count for the server
        cursor = conn.execute("""
            SELECT COUNT(*) as error_count FROM error_logs
            WHERE guild_id = %s AND resolved = FALSE
        """, (int(guild_id),))
        error_row = cursor.fetchone()
        error_count = error_row['error_count'] if error_row else 0
        
        cursor = conn.execute("""
            SELECT bot_access_paid, retention_tier, tier, COALESCE(grandfathered, FALSE) as grandfathered
            FROM server_subscriptions WHERE guild_id = %s
        """, (int(guild_id),))
        sub_row = cursor.fetchone()
        if sub_row:
            server_settings = {
                'bot_access_paid': sub_row.get('bot_access_paid', False),
                'retention_tier': sub_row.get('retention_tier', 'none'),
                'tier': sub_row.get('tier', 'free'),
                'grandfathered': bool(sub_row.get('grandfathered', False))
            }
        
        # Get demo reset info if this is the demo server
        if is_demo_server_flag:
            cursor = conn.execute("""
                SELECT last_demo_reset FROM guild_settings WHERE guild_id = %s
            """, (int(guild_id),))
            demo_row = cursor.fetchone()
            if demo_row and demo_row.get('last_demo_reset'):
                last_demo_reset = demo_row['last_demo_reset']
    
    access = get_flask_guild_access(guild_id)

    context = {
        'user': user_session,
        'server': {
            'id': guild_id,
            'name': guild.get('name', 'Unknown Server'),
            'icon': guild.get('icon')
        },
        'user_role': access_level,
        'is_also_employee': is_also_employee,
        'active_page': active_page,
        'pending_adjustments': pending_adjustments,
        'total_shifts': total_shifts,
        'show_tz_reminder': show_tz_reminder,
        'server_settings': server_settings,
        'is_demo_server': is_demo_server_flag,
        'view_as_employee': view_as_employee,
        'last_demo_reset': last_demo_reset,
        'has_completed_onboarding': has_completed_onboarding,
        'access': access,
        'is_bot_owner': user_id == os.getenv("BOT_OWNER_ID", "107103438139056128"),
        'error_count': error_count
    }
    
    return context, None


def check_premium_access(context, feature_name='advanced_settings'):
    """
    Check if the server has premium access for a given feature.
    Returns None if access granted, or a redirect/template response if denied.
    """
    server_settings = context.get('server_settings', {})
    bot_access_paid = server_settings.get('bot_access_paid', False)
    retention_tier = server_settings.get('retention_tier', 'none')
    tier = server_settings.get('tier', 'free')
    
    is_grandfathered = tier == 'grandfathered' or server_settings.get('grandfathered', False)
    guild_tier = Entitlements.get_guild_tier(bot_access_paid, retention_tier, is_grandfathered)
    user_role = UserRole.ADMIN if context['user_role'] == 'admin' else UserRole.EMPLOYEE
    
    if not Entitlements.can_access_feature(guild_tier, user_role, feature_name):
        gate_context = context.copy()
        gate_context['premium_required'] = True
        gate_context['premium_feature'] = feature_name
        gate_context['locked_message'] = Entitlements.get_locked_message(feature_name)
        return render_template('dashboard_pages/premium_required.html', **gate_context)
    
    return None


def check_premium_api_access(guild_id, feature_name='advanced_settings'):
    """
    Check if a server has premium access for API endpoints.
    Returns None if access granted, or a JSON error response if denied.
    For use in API routes that don't have the full page context.
    """
    try:
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT bot_access_paid, retention_tier, tier, COALESCE(grandfathered, FALSE) as grandfathered
                FROM server_subscriptions WHERE guild_id = %s
            """, (int(guild_id),))
            sub_row = cursor.fetchone()
            
            if not sub_row:
                return jsonify({'success': False, 'error': 'Premium feature - please upgrade', 'premium_required': True}), 403
            
            bot_access_paid = sub_row.get('bot_access_paid', False)
            retention_tier = sub_row.get('retention_tier', 'none')
            tier = sub_row.get('tier', 'free')
            is_grandfathered = tier == 'grandfathered' or bool(sub_row.get('grandfathered', False))
            
            guild_tier = Entitlements.get_guild_tier(bot_access_paid, retention_tier, is_grandfathered)
            
            if not Entitlements.can_access_feature(guild_tier, UserRole.ADMIN, feature_name):
                locked_msg = Entitlements.get_locked_message(feature_name)
                return jsonify({
                    'success': False, 
                    'error': locked_msg['message'],
                    'premium_required': True,
                    'upgrade_price': locked_msg['beta_price']
                }), 403
            
            return None
    except Exception as e:
        logging.error(f"Premium API check error: {e}")
        return jsonify({'success': False, 'error': 'Premium feature - please upgrade', 'premium_required': True}), 403


@dashboard_bp.route("/setup-wizard")
@require_auth
def setup_wizard(user_session):
    """Guided setup wizard for first-time server admins"""
    guild_id = request.args.get('guild_id')

    # Validate guild_id parameter
    if not guild_id or not guild_id.isdigit() or len(guild_id) > 20:
        return redirect('/dashboard')

    # Verify user has admin access to this guild
    context, error = get_server_page_context(user_session, guild_id, 'setup-wizard')
    if error:
        return error

    # Only admins can access setup wizard
    if context['user_role'] != 'admin':
        return redirect(f'/dashboard/server/{guild_id}')

    # Render setup wizard with guild context
    return render_template('setup_wizard.html',
                          guild_id=guild_id,
                          guild_name=context.get('guild_name', 'Unknown Server'),
                          user_session=user_session)


@dashboard_bp.route("/templates/setup_wizard_steps/<step_file>")
@require_auth
def setup_wizard_step(user_session, step_file):
    """Serve setup wizard step HTML files for AJAX loading"""
    # Validate step file name (only allow step1.html through step5.html)
    if not step_file.startswith('step') or not step_file.endswith('.html'):
        return "Invalid step file", 404

    # Extract step number and validate range
    try:
        step_num = int(step_file.replace('step', '').replace('.html', ''))
        if step_num < 1 or step_num > 5:
            return "Invalid step number", 404
    except ValueError:
        return "Invalid step file", 404

    # Render the step template
    return render_template(f'setup_wizard_steps/{step_file}')


@dashboard_bp.route("/dashboard/server/<guild_id>")
@require_auth
def dashboard_server_overview(user_session, guild_id):
    """Server overview page"""
    if not guild_id.isdigit() or len(guild_id) > 20:
        return redirect('/dashboard')
    
    context, error = get_server_page_context(user_session, guild_id, 'overview')
    if error:
        return error
    
    return render_template('dashboard_pages/server_overview.html', **context)


@dashboard_bp.route("/dashboard/server/<guild_id>/admin-roles")
@require_auth
def dashboard_admin_roles(user_session, guild_id):
    """Admin roles management page"""
    if not guild_id.isdigit() or len(guild_id) > 20:
        return redirect('/dashboard')
    
    context, error = get_server_page_context(user_session, guild_id, 'admin-roles')
    if error:
        return error
    
    if context['user_role'] != 'admin':
        return redirect(f'/dashboard/server/{guild_id}')
    
    return render_template('dashboard_pages/admin_roles.html', **context)


@dashboard_bp.route("/dashboard/server/<guild_id>/employee-roles")
@require_auth
def dashboard_employee_roles(user_session, guild_id):
    """Employee roles management page"""
    if not guild_id.isdigit() or len(guild_id) > 20:
        return redirect('/dashboard')
    
    context, error = get_server_page_context(user_session, guild_id, 'employee-roles')
    if error:
        return error
    
    if context['user_role'] != 'admin':
        return redirect(f'/dashboard/server/{guild_id}')
    
    return render_template('dashboard_pages/employee_roles.html', **context)


@dashboard_bp.route("/dashboard/server/<guild_id>/email")
@require_auth
def dashboard_email_settings(user_session, guild_id):
    """Email settings page"""
    if not guild_id.isdigit() or len(guild_id) > 20:
        return redirect('/dashboard')
    
    context, error = get_server_page_context(user_session, guild_id, 'email')
    if error:
        return error
    
    if context['user_role'] != 'admin':
        return redirect(f'/dashboard/server/{guild_id}')
    
    premium_block = check_premium_access(context, 'email_automation')
    if premium_block:
        return premium_block
    
    return render_template('dashboard_pages/email_settings.html', **context)


@dashboard_bp.route("/dashboard/server/<guild_id>/timezone")
@require_auth
def dashboard_timezone_settings(user_session, guild_id):
    """Timezone settings page"""
    if not guild_id.isdigit() or len(guild_id) > 20:
        return redirect('/dashboard')
    
    context, error = get_server_page_context(user_session, guild_id, 'timezone')
    if error:
        return error
    
    if context['user_role'] != 'admin':
        return redirect(f'/dashboard/server/{guild_id}')
    
    return render_template('dashboard_pages/timezone_settings.html', **context)


@dashboard_bp.route("/dashboard/server/<guild_id>/employees")
@require_auth
def dashboard_employees(user_session, guild_id):
    """Employee status page"""
    if not guild_id.isdigit() or len(guild_id) > 20:
        return redirect('/dashboard')
    
    context, error = get_server_page_context(user_session, guild_id, 'employees')
    if error:
        return error
    
    if context['user_role'] != 'admin':
        return redirect(f'/dashboard/server/{guild_id}')
    
    premium_block = check_premium_access(context, 'employee_profiles_extended')
    if premium_block:
        return premium_block
    
    return render_template('dashboard_pages/employees.html', **context)


@dashboard_bp.route("/dashboard/server/<guild_id>/clock")
@require_auth
def dashboard_on_the_clock(user_session, guild_id):
    """On the clock page for employees (admins can also view for monitoring)"""
    if not guild_id.isdigit() or len(guild_id) > 20:
        return redirect('/dashboard')
    
    context, error = get_server_page_context(user_session, guild_id, 'clock')
    if error:
        return error
    
    return render_template('dashboard_pages/on_the_clock.html', **context)


@dashboard_bp.route("/dashboard/server/<guild_id>/adjustments")
@require_auth
def dashboard_adjustments(user_session, guild_id):
    """Time adjustments page"""
    if not guild_id.isdigit() or len(guild_id) > 20:
        return redirect('/dashboard')
    
    context, error = get_server_page_context(user_session, guild_id, 'adjustments')
    if error:
        return error
    
    premium_block = check_premium_access(context, 'time_adjustments')
    if premium_block:
        return premium_block
    
    return render_template('dashboard_pages/adjustments.html', **context)


@dashboard_bp.route("/dashboard/server/<guild_id>/reports")
@require_auth
def dashboard_reports(user_session, guild_id):
    """Reports & Exports UI page"""
    if not guild_id.isdigit() or len(guild_id) > 20:
        return redirect('/dashboard')
    
    context, error = get_server_page_context(user_session, guild_id, 'reports')
    if error:
        return error
        
    if context['user_role'] != 'admin':
        return redirect(f'/dashboard/server/{guild_id}')
        
    return render_template('dashboard_reports.html', **context)


@dashboard_bp.route("/dashboard/server/<guild_id>/integrations")
@require_auth
def dashboard_integrations(user_session, guild_id):
    """Integrations & Notifications UI page"""
    if not guild_id.isdigit() or len(guild_id) > 20:
        return redirect('/dashboard')
    
    context, error = get_server_page_context(user_session, guild_id, 'integrations')
    if error:
        return error
        
    if context['user_role'] != 'admin':
        return redirect(f'/dashboard/server/{guild_id}')
        
    return render_template('dashboard_integrations.html', **context)


@dashboard_bp.route("/dashboard/server/<guild_id>/calendar")
@require_auth
def dashboard_admin_calendar(user_session, guild_id):
    """Admin calendar page"""
    if not guild_id.isdigit() or len(guild_id) > 20:
        return redirect('/dashboard')
    
    context, error = get_server_page_context(user_session, guild_id, 'calendar')
    if error:
        return error
    
    if context['user_role'] != 'admin':
        return redirect(f'/dashboard/server/{guild_id}')
    
    premium_block = check_premium_access(context, 'advanced_settings')
    if premium_block:
        return premium_block
    
    return render_template('dashboard_pages/admin_calendar.html', **context)


@dashboard_bp.route("/dashboard/server/<guild_id>/bans")
@require_auth
def dashboard_ban_management(user_session, guild_id):
    """Ban management page"""
    if not guild_id.isdigit() or len(guild_id) > 20:
        return redirect('/dashboard')
    
    context, error = get_server_page_context(user_session, guild_id, 'bans')
    if error:
        return error
    
    if context['user_role'] != 'admin':
        return redirect(f'/dashboard/server/{guild_id}')
    
    premium_block = check_premium_access(context, 'ban_management')
    if premium_block:
        return premium_block
    
    return render_template('dashboard_pages/ban_management.html', **context)


@dashboard_bp.route("/dashboard/server/<guild_id>/beta")
@require_auth
def dashboard_beta_settings(user_session, guild_id):
    """Beta settings page (admin only)"""
    if not guild_id.isdigit() or len(guild_id) > 20:
        return redirect('/dashboard')
    
    context, error = get_server_page_context(user_session, guild_id, 'beta')
    if error:
        return error
    
    # Fetch beta settings
    with get_db() as conn:
        cursor = conn.execute("SELECT beta_enabled, allow_kiosk_customization FROM guild_settings WHERE guild_id = %s", (guild_id,))
        settings = cursor.fetchone()
        
    beta_enabled = settings['beta_enabled'] if settings else False
    allow_kiosk_customization = settings['allow_kiosk_customization'] if settings else True

    context['beta_enabled'] = beta_enabled
    context['allow_kiosk_customization'] = allow_kiosk_customization
    
    if context['user_role'] != 'admin':
        return redirect(f'/dashboard/server/{guild_id}')
    return render_template('dashboard_pages/beta_settings.html', **context)


@dashboard_bp.route("/dashboard/server/<guild_id>/kiosk")
@require_auth
def dashboard_kiosk_settings(user_session, guild_id):
    """Dedicated Kiosk settings page (demo server only)"""
    if not guild_id.isdigit() or len(guild_id) > 20:
        return redirect('/dashboard')
    
    # Gating the route to only the Demo Server for now
    if guild_id != '1419894879894507661':
        return redirect(f'/dashboard/server/{guild_id}')
        
    context, error = get_server_page_context(user_session, guild_id, 'kiosk')
    if error:
        return error
        
    if context['user_role'] != 'admin':
        return redirect(f'/dashboard/server/{guild_id}')
        
    # Fetch kiosk settings
    with get_db() as conn:
        cursor = conn.execute("SELECT allow_kiosk_customization, kiosk_only_mode FROM guild_settings WHERE guild_id = %s", (guild_id,))
        settings = cursor.fetchone()
        
    allow_kiosk_customization = settings['allow_kiosk_customization'] if settings else True
    
    # Safely get kiosk_only_mode since it was just added in a migration and might not be populated in all rows yet
    kiosk_only_mode = False
    if settings and 'kiosk_only_mode' in settings:
        kiosk_only_mode = settings['kiosk_only_mode'] if settings['kiosk_only_mode'] is not None else False

    context['allow_kiosk_customization'] = allow_kiosk_customization
    context['kiosk_only_mode'] = kiosk_only_mode
    
    return render_template('dashboard_pages/kiosk_settings.html', **context)


@dashboard_bp.route("/dashboard/server/<guild_id>/profile/<user_id>")
@require_auth
def dashboard_employee_profile(user_session, guild_id, user_id):
    """Employee profile page - viewable by the employee or admins"""
    access = get_flask_guild_access(guild_id)
    if not access['is_exempt'] and access['tier'] == 'free' and not access['trial_active']:
        return redirect(f'/dashboard/purchase?guild_id={guild_id}')

    if not guild_id.isdigit() or len(guild_id) > 20:
        return redirect('/dashboard')
    if not user_id.isdigit() or len(user_id) > 20:
        return redirect(f'/dashboard/server/{guild_id}')
    
    context, error = get_server_page_context(user_session, guild_id, 'profile')
    if error:
        return error
    
    # Allow access if: user is viewing their own profile OR user is admin
    viewer_user_id = user_session.get('user_id')
    if context['user_role'] != 'admin' and str(viewer_user_id) != str(user_id):
        return redirect(f'/dashboard/server/{guild_id}')
    
    # Add profile user_id to context for the template
    context['profile_user_id'] = user_id
    context['is_own_profile'] = str(viewer_user_id) == str(user_id)
    context['employee_id'] = user_id # Compatibility for employee_profile.html
    
    return render_template('dashboard_pages/employee_profile.html', **context)


