import os
import json
import secrets
import traceback
import time
from urllib.parse import urlparse
from datetime import datetime, timedelta, timezone
import requests
from flask import session, redirect, request, jsonify, current_app as app
from web.utils.db import get_db
from entitlements import Entitlements, UserTier

DISCORD_CLIENT_ID = os.getenv('DISCORD_CLIENT_ID', '1418446753379913809')
DISCORD_CLIENT_SECRET = os.environ.get('DISCORD_CLIENT_SECRET')
DISCORD_API_BASE = 'https://discord.com/api/v10'
BOT_API_BASE_URL = os.getenv('BOT_API_BASE_URL', 'http://localhost:8081')
DEMO_SERVER_ID = '1419894879894507661'

def is_demo_server(guild_id) -> bool:
    return str(guild_id) == DEMO_SERVER_ID

def validate_bot_api_url(url):
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'): return False
        if not parsed.hostname: return False
        hostname = parsed.hostname.lower()
        is_local = hostname in ('localhost', '127.0.0.1', '0.0.0.0', '::1')
        if os.environ.get('FLASK_ENV') == 'production' and is_local: return False
        if not url.startswith(BOT_API_BASE_URL): return False
        return True
    except Exception:
        return False

        """Optionally stores metadata (e.g. purchase_intent) that survives cross-domain redirects."""
    state = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
    metadata_json = json.dumps(metadata) if metadata else None
    
    with get_db() as conn:
        conn.execute(
            "INSERT INTO oauth_states (state, expires_at, metadata) VALUES (%s, %s, %s)",
            (state, expires_at.isoformat(), metadata_json)
        )
    return state

def verify_oauth_state(state):
    """Verify OAuth state and delete it. Returns (True, metadata_dict) or (False, None)."""
    with get_db() as conn:
        cursor = conn.execute(
            "SELECT state, metadata FROM oauth_states WHERE state = %s AND expires_at > %s",
            (state, datetime.now(timezone.utc).isoformat())
        )
        result = cursor.fetchone()
        
        if result:
            conn.execute("DELETE FROM oauth_states WHERE state = %s", (state,))
            metadata = None
            if result['metadata']:
                try:
                    metadata = json.loads(result['metadata'])
                except (json.JSONDecodeError, TypeError):
                    pass
            return True, metadata
    return False, None

def exchange_code_for_token(code, redirect_uri):
    """Exchange authorization code for access token"""
    data = {
        'client_id': DISCORD_CLIENT_ID,
        'client_secret': DISCORD_CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirect_uri
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    
    response = requests.post(f'{DISCORD_API_BASE}/oauth2/token', data=data, headers=headers, timeout=5)
    response.raise_for_status()
    return response.json()

def get_user_info(access_token):
    """Get Discord user information"""
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get(f'{DISCORD_API_BASE}/users/@me', headers=headers, timeout=5)
    response.raise_for_status()
    return response.json()

def get_user_guilds(access_token):
    """Get user's Discord guilds"""
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get(f'{DISCORD_API_BASE}/users/@me/guilds', headers=headers, timeout=5)
    response.raise_for_status()
    return response.json()

def create_user_session(user_data, access_token, refresh_token, guilds_data):
    """Create user session in database"""
    session_id = secrets.token_urlsafe(32)
    created_at = datetime.now(timezone.utc)
    expires_at = created_at + timedelta(hours=24)
    # Get real client IP from proxy headers (falls back to remote_addr)
    ip_address = request.access_route[0] if request.access_route else (request.remote_addr or 'unknown')
    
    with get_db() as conn:
        conn.execute("""
            INSERT INTO user_sessions 
            (session_id, user_id, username, discriminator, avatar, access_token, refresh_token, guilds_data, created_at, expires_at, ip_address)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            session_id,
            user_data['id'],
            user_data['username'],
            user_data.get('discriminator', '0'),
            user_data.get('avatar'),
            access_token,
            refresh_token,
            json.dumps(guilds_data),
            created_at.isoformat(),
            expires_at.isoformat(),
            ip_address
        ))
    return session_id

def get_user_session(session_id):
    """Get user session from database"""
    with get_db() as conn:
        cursor = conn.execute("""
            SELECT session_id, user_id, username, discriminator, avatar, access_token, guilds_data, expires_at
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
    return None

def delete_user_session(session_id):
    """Delete user session from database"""
    with get_db() as conn:
        conn.execute("DELETE FROM user_sessions WHERE session_id = %s", (session_id,))

def require_auth(f):
    """Decorator to require authentication"""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            session_id = session.get('session_id')
            if not session_id:
                app.logger.info("No session_id found, redirecting to login")
                return redirect('/auth/login')
            
            user_session = get_user_session(session_id)
            if not user_session:
                app.logger.warning(f"Invalid or expired session: {session_id[:8]}...")
                session.clear()
                return redirect('/auth/login')
            
            return f(user_session, *args, **kwargs)
        except Exception as e:
            app.logger.error(f"Authentication error: {str(e)}")
            app.logger.error(traceback.format_exc())
            session.clear()
            return redirect('/auth/login')
    return decorated_function

def require_api_auth(f):
    """Decorator to require authentication for API routes (returns JSON instead of redirect)"""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            session_id = session.get('session_id')
            if not session_id:
                return jsonify({'success': False, 'error': 'Unauthorized'}), 401
            
            user_session = get_user_session(session_id)
            if not user_session:
                session.clear()
                return jsonify({'success': False, 'error': 'Session expired'}), 401
            
            return f(user_session, *args, **kwargs)
        except Exception as e:
            app.logger.error(f"API authentication error: {str(e)}")
            app.logger.error(traceback.format_exc())
            return jsonify({'success': False, 'error': 'Authentication error'}), 500
    return decorated_function

def require_server_owner(f):
    """Decorator to require server owner access"""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            session_id = session.get('session_id')
            if not session_id:
                app.logger.info("No session_id found, redirecting to login")
                return redirect('/auth/login')
            
            user_session = get_user_session(session_id)
            if not user_session:
                app.logger.warning(f"Invalid or expired session: {session_id[:8]}...")
                session.clear()
                return redirect('/auth/login')
            
            # Determine guild_id from route (<guild_id>), query string (?guild_id=), or JSON body
            guild_id = kwargs.get('guild_id') or request.view_args.get('guild_id') or request.args.get('guild_id')
            if not guild_id and request.is_json:
                guild_id = request.json.get('guild_id')
                
            if not guild_id:
                if request.path.startswith('/api/'):
                    return jsonify({'success': False, 'error': 'guild_id required'}), 400
                return "<h1>Error</h1><p>No server selected.</p><a href='/'>Return Home</a>", 400
                
            guild, access_level = verify_guild_access(user_session, str(guild_id))
            if access_level != 'owner':
                app.logger.error(f"Unauthorized owner-only attempt for guild {guild_id} by user {user_session.get('user_id')}")
                if request.path.startswith('/api/'):
                    return jsonify({'success': False, 'error': 'Server Owner access required'}), 403
                return "<h1>Access Denied</h1><p>Only the Server Owner can perform this action.</p><a href='/'>Return Home</a>", 403
                
            return f(user_session, *args, **kwargs)
        except Exception as e:
            app.logger.error(f"Authentication error: {str(e)}")
            app.logger.error(traceback.format_exc())
            session.clear()
            return redirect('/auth/login')
    return decorated_function

_rate_limits = {}

def rate_limit_check(endpoint, identifier, max_requests, per_seconds):
    """
    Generic in-memory rate limiter to prevent Denial of Wallet attacks.
    Returns True if allowed, False if rate limited.
    """
    now = time_module.time()
    key = (endpoint, identifier)
    
    if key not in _rate_limits:
        _rate_limits[key] = []
        
    # Remove timestamps older than our window
    _rate_limits[key] = [t for t in _rate_limits[key] if now - t < per_seconds]
    
    if len(_rate_limits[key]) >= max_requests:
        return False
        
    _rate_limits[key].append(now)
    return True

def check_guild_paid_access(guild_id):
    """
    Check if a guild has paid bot access.
    Returns dict with: {'bot_invited': bool, 'bot_access_paid': bool}
    Performs fresh database lookup on every call (no caching).
    """
    try:
        with get_db() as conn:
            # Check if bot is in the guild (bot_guilds table)
            cursor = conn.execute("SELECT guild_id FROM bot_guilds WHERE guild_id = %s", (str(guild_id),))
            bot_invited = cursor.fetchone() is not None
            
            # Check if guild has paid bot access (server_subscriptions table)
            # Use string for comparison if the DB stores it that way, or ensure types match
            cursor = conn.execute(
                "SELECT bot_access_paid, status FROM server_subscriptions WHERE CAST(guild_id AS TEXT) = %s",
                (str(guild_id),)
            )
            result = cursor.fetchone()
            
            # A server is considered paid if bot_access_paid is True OR status is 'active'
            bot_access_paid = False
            if result:
                is_paid_flag = bool(result.get('bot_access_paid'))
                is_active_status = result.get('status') == 'active'
                bot_access_paid = is_paid_flag or is_active_status
            
            return {
                'bot_invited': bot_invited,
                'bot_access_paid': bot_access_paid
            }
    except Exception as e:
        app.logger.error(f"Error checking guild {guild_id} paid access: {e}")
        # Fail closed - deny access on error
        return {
            'bot_invited': False,
            'bot_access_paid': False
        }

def check_user_admin_realtime(user_id, guild_id):
    """
    Check if user has admin permissions in guild via bot API (real-time check).
    This replaces cached OAuth session data with live guild membership/permissions.
    Returns dict with: {'is_member': bool, 'is_admin': bool, 'reason': str}
    Performs fresh lookup via bot's Discord cache on every call (no caching).
    """
    # Demo server override: Grant admin access to all users for demo exploration
    if is_demo_server(guild_id):
        return {'is_member': True, 'is_admin': True, 'reason': 'demo_server'}
    
    try:
        import requests
        
        bot_api_secret = os.getenv('BOT_API_SECRET')
        if not bot_api_secret:
            app.logger.error("BOT_API_SECRET not set - cannot verify admin status")
            # Fail closed - deny access if we can't verify
            return {'is_member': False, 'is_admin': False, 'reason': 'api_secret_missing'}
        
        # Call bot API to check admin status
        url = f'{BOT_API_BASE_URL}/api/guild/{guild_id}/user/{user_id}/check-admin'
        
        # Validate URL to prevent SSRF
        if not validate_bot_api_url(url):
            app.logger.error(f"SSRF protection: Invalid bot API URL rejected")
            return {'is_member': False, 'is_admin': False, 'reason': 'invalid_url'}
        
        headers = {'Authorization': f'Bearer {bot_api_secret}'}
        
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                return {
                    'is_member': data.get('is_member', False),
                    'is_admin': data.get('is_admin', False),
                    'reason': data.get('reason', 'unknown')
                }
        
        app.logger.error(f"Bot API check failed for user {user_id} in guild {guild_id}: {response.status_code}")
        # Fail closed - deny access if bot API fails
        return {'is_member': False, 'is_admin': False, 'reason': 'bot_api_error'}
        
    except Exception as e:
        app.logger.error(f"Error checking user admin status (user {user_id}, guild {guild_id}): {e}")
        app.logger.error(traceback.format_exc())
        # Fail closed - deny access on error
        return {'is_member': False, 'is_admin': False, 'reason': 'check_error'}

def get_flask_guild_access(guild_id):
    """Check guild tier, trial status, and exemption for dashboard routes"""
    from entitlements import Entitlements, UserTier
    try:
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT ss.bot_access_paid, ss.retention_tier, ss.grandfathered,
                       gs.trial_start_date
                FROM server_subscriptions ss
                LEFT JOIN guild_settings gs ON ss.guild_id = gs.guild_id
                WHERE ss.guild_id = %s
            """, (int(guild_id),))
            row = cursor.fetchone()
            if not row:
                return {'tier': 'free', 'trial_active': False, 'days_remaining': 0, 'is_exempt': False}
            grandfathered = row.get('grandfathered', False) or False
            tier = Entitlements.get_guild_tier(
                row.get('bot_access_paid', False),
                row.get('retention_tier', 'none'),
                grandfathered
            )
            trial_start = row.get('trial_start_date')
            # Check for owner grants
            grant_cursor = conn.execute("""
                SELECT COUNT(*) as cnt FROM server_subscriptions
                WHERE guild_id = %s AND (grandfathered = true OR bot_access_paid = true)
            """, (int(guild_id),))
            grant_row = grant_cursor.fetchone()
            owner_granted = (grant_row and grant_row['cnt'] > 0) or False
            is_exempt = Entitlements.is_server_exempt(int(guild_id), grandfathered, owner_granted)
            return {
                'tier': tier.value,
                'trial_active': Entitlements.is_trial_active(trial_start),
                'days_remaining': Entitlements.get_trial_days_remaining(trial_start),
                'is_exempt': is_exempt
            }
    except Exception as e:
        app.logger.error(f"Error checking guild access: {e}")
        return {'tier': 'free', 'trial_active': False, 'days_remaining': 0, 'is_exempt': False}

def require_paid_access(f):
    """
    Decorator to require both authentication AND paid bot access for dashboard routes.
    Checks on every request (no caching) for real-time access control.
    
    Extracts guild_id from route parameters and validates:
    1. User is authenticated
    2. Bot is invited to the guild
    3. Guild has paid bot access
    4. User is admin in the guild
    
    Redirects to appropriate pages based on access state:
    - Not invited: /dashboard/invite
    - Invited but not paid: /dashboard/purchase
    - Paid but not admin: /dashboard/no-access
    """
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            # First check authentication
            session_id = session.get('session_id')
            if not session_id:
                app.logger.info("No session_id found, redirecting to login")
                return redirect('/auth/login')
            
            user_session = get_user_session(session_id)
            if not user_session:
                app.logger.warning(f"Invalid or expired session: {session_id[:8]}...")
                session.clear()
                return redirect('/auth/login')
            
            # Extract guild_id from route parameters
            guild_id = kwargs.get('guild_id')
            if not guild_id:
                # For routes without guild_id (like /dashboard), just require auth
                return f(user_session, *args, **kwargs)
            
            # Check bot access status (fresh DB lookup every time)
            access_status = check_guild_paid_access(guild_id)
            
            # Check if user is admin in this guild (real-time via bot API - ONLY source of truth)
            admin_status = check_user_admin_realtime(user_session['user_id'], guild_id)
            is_admin = admin_status.get('is_admin', False)
            is_member = admin_status.get('is_member', False)
            reason = admin_status.get('reason', 'unknown')
            
            # Log the check for debugging
            app.logger.info(f"Real-time admin check for user {user_session.get('username')} in guild {guild_id}: is_member={is_member}, is_admin={is_admin}, reason={reason}")
            
            # Fail closed on bot API errors
            if reason in ['api_secret_missing', 'bot_api_error', 'check_error']:
                app.logger.error(f"Bot API check failed for user {user_session.get('username')} in guild {guild_id}, denying access (fail closed)")
                session.clear()
                return redirect('/auth/login?error=api_check_failed')
            
            # Validate access requirements
            if not access_status['bot_invited']:
                app.logger.info(f"Bot not invited to guild {guild_id}, redirecting to invite page")
                return redirect(f'/dashboard/invite?guild_id={guild_id}')
            
            if not access_status['bot_access_paid']:
                app.logger.info(f"Guild {guild_id} does not have paid access, redirecting to purchase page")
                return redirect(f'/dashboard/purchase?guild_id={guild_id}')
            
            # Check guild membership (real-time from bot)
            if not is_member:
                app.logger.warning(f"User {user_session.get('username')} not member of guild {guild_id} (reason: {reason})")
                return redirect(f'/dashboard/no-access?guild_id={guild_id}')
            
            # Check admin permissions (real-time from bot)
            if not is_admin:
                app.logger.warning(f"User {user_session.get('username')} not admin in guild {guild_id} (reason: {reason})")
                return redirect(f'/dashboard/no-access?guild_id={guild_id}')
            
            # All checks passed - allow access
            return f(user_session, *args, **kwargs)
            
        except Exception as e:
            app.logger.error(f"Paid access check error: {str(e)}")
            app.logger.error(traceback.format_exc())
            session.clear()
            return redirect('/auth/login')
    return decorated_function

def require_paid_api_access(f):
    """
    API version of require_paid_access - returns JSON errors instead of redirects.
    """
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            # First check authentication
            session_id = session.get('session_id')
            if not session_id:
                return jsonify({'success': False, 'error': 'Unauthorized', 'code': 'NO_SESSION'}), 401
            
            user_session = get_user_session(session_id)
            if not user_session:
                session.clear()
                return jsonify({'success': False, 'error': 'Session expired', 'code': 'EXPIRED_SESSION'}), 401
            
            # Extract guild_id from route parameters
            guild_id = kwargs.get('guild_id')
            if not guild_id:
                return jsonify({'success': False, 'error': 'Missing guild_id', 'code': 'MISSING_GUILD'}), 400
            
            # Check bot access status (fresh DB lookup every time)
            access_status = check_guild_paid_access(guild_id)
            
            # Check if user is admin in this guild (real-time via bot API - ONLY source of truth)
            admin_status = check_user_admin_realtime(user_session['user_id'], guild_id)
            is_admin = admin_status.get('is_admin', False)
            is_member = admin_status.get('is_member', False)
            reason = admin_status.get('reason', 'unknown')
            
            # Log the check for debugging
            app.logger.info(f"Real-time admin check (API) for user {user_session.get('username')} in guild {guild_id}: is_member={is_member}, is_admin={is_admin}, reason={reason}")
            
            # Fail closed on bot API errors
            if reason in ['api_secret_missing', 'bot_api_error', 'check_error']:
                app.logger.error(f"Bot API check failed for user {user_session.get('username')} in guild {guild_id}, denying access (fail closed)")
                return jsonify({
                    'success': False,
                    'error': 'Access check failed',
                    'code': 'API_CHECK_FAILED'
                }), 500
            
            # Validate access requirements
            if not access_status['bot_invited']:
                return jsonify({
                    'success': False,
                    'error': 'Bot not invited to server',
                    'code': 'BOT_NOT_INVITED',
                    'redirect': f'/dashboard/invite?guild_id={guild_id}'
                }), 403
            
            if not access_status['bot_access_paid']:
                return jsonify({
                    'success': False,
                    'error': 'Server does not have paid bot access',
                    'code': 'NO_PAID_ACCESS',
                    'redirect': f'/dashboard/purchase?guild_id={guild_id}'
                }), 403
            
            # Check guild membership (real-time from bot)
            if not is_member:
                return jsonify({
                    'success': False,
                    'error': 'Not a member of this server',
                    'code': 'NOT_MEMBER',
                    'redirect': f'/dashboard/no-access?guild_id={guild_id}'
                }), 403
            
            # Check admin permissions (real-time from bot)
            if not is_admin:
                return jsonify({
                    'success': False,
                    'error': 'Admin access required',
                    'code': 'NOT_ADMIN',
                    'redirect': f'/dashboard/no-access?guild_id={guild_id}'
                }), 403
            
            # All checks passed - allow access
            return f(user_session, *args, **kwargs)
            
        except Exception as e:
            app.logger.error(f"API paid access check error: {str(e)}")
            app.logger.error(traceback.format_exc())
            return jsonify({'success': False, 'error': 'Access check error', 'code': 'CHECK_ERROR'}), 500
    return decorated_function

def get_bot_guild_ids():
    """Get list of guild IDs where the bot is currently present (as strings for OAuth comparison)"""
    try:
        with get_db() as conn:
            cursor = conn.execute("SELECT guild_id FROM bot_guilds WHERE is_present = TRUE OR is_present IS NULL")
            # Cast to string to match Discord OAuth guild IDs (which are strings)
            return set(str(row['guild_id']) for row in cursor.fetchall())
    except Exception as e:
        app.logger.error(f"Error fetching bot guild IDs: {e}")
        # Return empty set to avoid 500 errors if table missing or locked
        return set()

def user_has_admin_access(user_id, guild_id, user_guild):
    """
    Check if user has admin access to a guild.
    Returns True if user has:
    - Discord Owner permissions, OR
    - Discord Administrator permissions, OR
    - A custom admin role configured via bot slash commands, OR
    - The main admin role configured for the guild
    """
    # Check Discord owner permission
    if user_guild.get('owner', False):
        return True
    
    # Check Discord administrator permission (0x8 = ADMINISTRATOR)
    permissions = int(user_guild.get('permissions', '0'))
    if permissions & 0x8:  # Administrator permission
        return True
    
    # Check custom admin roles and main admin role from database
    # Note: We can't easily get user's role IDs from OAuth guilds endpoint
    # The guilds endpoint only gives us basic guild info and permissions
    # For now, we'll trust Discord permissions (owner/administrator)
    # Custom admin roles would require additional Discord API calls per guild

    return False

def require_kiosk_access(f):
    """
    Decorator for kiosk routes.
    - Demo server (1419894879894507661): Always allow (for public preview)
    - Production servers: Require Pro tier
    """
    from functools import wraps

    @wraps(f)
    def decorated_function(*args, **kwargs):
        guild_id = kwargs.get('guild_id')
        if not guild_id:
            return jsonify({
                'success': False,
                'error': 'Missing guild_id'
            }), 400

        # Demo server override - allow free exploration
        if is_demo_server(guild_id):
            app.logger.debug(f"Demo server kiosk access granted for guild {guild_id}")
            return f(*args, **kwargs)

        # For production servers, check Pro tier
        try:
            with get_db() as conn:
                cursor = conn.execute("""
                    SELECT bot_access_paid, retention_tier, grandfathered
                    FROM server_subscriptions
                    WHERE guild_id = %s
                """, (int(guild_id),))
                result = cursor.fetchone()

                if not result:
                    return jsonify({
                        'success': False,
                        'error': 'Server not found. Please invite the bot first.',
                        'code': 'NO_SUBSCRIPTION'
                    }), 404

                # Get tier using entitlements
                from entitlements import Entitlements, UserTier
                tier = Entitlements.get_guild_tier(
                    bot_access_paid=result['bot_access_paid'],
                    retention_tier=result['retention_tier'],
                    grandfathered=result.get('grandfathered', False)
                )

                # Check if tier allows kiosk (Pro tier required)
                if tier != UserTier.PRO:
                    return jsonify({
                        'success': False,
                        'error': 'Kiosk mode requires Pro tier subscription',
                        'code': 'PRO_REQUIRED',
                        'current_tier': tier.value,
                        'required_tier': 'pro',
                        'upgrade_url': f'https://ontheclock.app/dashboard/purchase?guild_id={guild_id}'
                    }), 403

                # Pro tier confirmed - proceed
                return f(*args, **kwargs)

        except Exception as e:
            app.logger.error(f"Error checking kiosk access for guild {guild_id}: {e}")
            return jsonify({
                'success': False,
                'error': 'Unable to verify kiosk access'
            }), 500

    return decorated_function

def require_kiosk_session(f):
    """
    Decorator for sensitive Kiosk actions (clocking, emailing).
    Requires the ephemeral `session['active_kiosk_user']` token issued by verify-pin.
    """
    from functools import wraps

    @wraps(f)
    def decorated_function(*args, **kwargs):
        guild_id = kwargs.get('guild_id')
        user_id = kwargs.get('user_id') or request.get_json(silent=True).get('user_id') if request.is_json else None
        
        # Pull token from session
        kiosk_token = session.get('active_kiosk_user')
        
        if not kiosk_token:
            return jsonify({'success': False, 'error': 'Unauthorized: No active kiosk session.'}), 401
            
        import time
        now = time.time()
        
        # Validate Session Expiry
        if now > kiosk_token.get('expires', 0):
            session.pop('active_kiosk_user', None)
            return jsonify({'success': False, 'error': 'Session expired. Please enter PIN again.'}), 401
            
        # Hard-gate: Target guild/user must match the token's authority
        if str(kiosk_token.get('guild_id')) != str(guild_id) or str(kiosk_token.get('user_id')) != str(user_id):
            return jsonify({'success': False, 'error': 'Token mismatch. Unauthorized.'}), 403
            
        return f(*args, **kwargs)

    return decorated_function

def filter_user_guilds(user_session):
    """
    Filter user's guilds to show only those where:
    1. The user has admin access (owner, administrator, or custom admin role), AND
    2. EITHER the bot is present OR the server has paid/granted access
    
    This allows admins to see servers where access was manually granted even if bot hasn't joined yet.
    Also adds subscription information and bot presence flag to each guild.
    """
    all_guilds = user_session.get('guilds', [])
    bot_guild_ids = get_bot_guild_ids()
    filtered_guilds = []
    
    # Fetch all subscription data in one query for efficiency
    subscription_data = {}
    with get_db() as conn:
        cursor = conn.execute(
            "SELECT guild_id, bot_access_paid, retention_tier FROM server_subscriptions"
        )
        for row in cursor.fetchall():
            subscription_data[str(row['guild_id'])] = {
                'bot_access_paid': bool(row['bot_access_paid']),
                'retention_tier': row['retention_tier']
            }
    
    for guild in all_guilds:
        guild_id = guild.get('id')
        
        # Check if user has admin access first
        if not user_has_admin_access(user_session['user_id'], guild_id, guild):
            continue
        
        # Check bot presence and payment status
        bot_is_present = guild_id in bot_guild_ids
        sub_info = subscription_data.get(guild_id, {'bot_access_paid': False, 'retention_tier': 'none'})
        has_paid_access = sub_info['bot_access_paid']
        
        # Show guild if EITHER bot is present OR they have paid access
        # This allows admins to see their dashboard even if bot hasn't joined yet after manual grant
        if not bot_is_present and not has_paid_access:
            continue
        
        # Add subscription info, bot presence, and access level to guild
        guild['bot_access_paid'] = has_paid_access
        guild['retention_tier'] = sub_info['retention_tier']
        guild['bot_is_present'] = bot_is_present
        guild['access_level'] = 'admin'
        
        # Guild passes filters
        filtered_guilds.append(guild)
    
    return filtered_guilds

def get_employee_guilds(user_id):
    """
    Get guilds where user has an active employee profile.
    Cross-references with bot_guilds to ensure bot is present.
    Returns list of guilds with format matching OAuth guild structure.
    """
    employee_guilds = []
    
    try:
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT 
                    ep.guild_id,
                    bg.guild_name,
                    COALESCE(ss.bot_access_paid, FALSE) as bot_access_paid,
                    COALESCE(ss.retention_tier, 'none') as retention_tier
                FROM employee_profiles ep
                JOIN bot_guilds bg ON CAST(bg.guild_id AS BIGINT) = ep.guild_id
                LEFT JOIN server_subscriptions ss ON ss.guild_id = ep.guild_id
                WHERE ep.user_id = %s AND ep.is_active = TRUE
                AND (bg.is_present = TRUE OR bg.is_present IS NULL)
            """, (int(user_id),))
            
            for row in cursor.fetchall():
                employee_guilds.append({
                    'id': str(row['guild_id']),
                    'name': row['guild_name'],
                    'icon': None,
                    'access_level': 'employee',
                    'bot_access_paid': bool(row['bot_access_paid']),
                    'retention_tier': row['retention_tier'] or 'none',
                    'bot_is_present': True
                })
    except Exception as e:
        app.logger.error(f"Error fetching employee guilds for user {user_id}: {e}")
        app.logger.error(traceback.format_exc())
    
    return employee_guilds

def get_all_user_guilds(user_session):
    """
    Get all guilds where user has access (admin or employee).
    Deduplicates: if user is admin on a guild, don't include it as employee-only.
    
    Returns dict with:
    - 'admin_guilds': guilds where user has admin access
    - 'employee_guilds': guilds where user is employee-only (not admin)
    """
    user_id = user_session.get('user_id')
    
    admin_guilds = filter_user_guilds(user_session)
    admin_guild_ids = set(g['id'] for g in admin_guilds)
    
    all_employee_guilds = get_employee_guilds(user_id)
    employee_only_guilds = [
        g for g in all_employee_guilds 
        if g['id'] not in admin_guild_ids
    ]
    
    return {
        'admin_guilds': admin_guilds,
        'employee_guilds': employee_only_guilds
    }

# Routes
DISCORD_OAUTH_SCOPES = 'identify guilds'

def get_redirect_uri():
    env_uri = os.environ.get('DISCORD_REDIRECT_URI')
    if env_uri:
        return env_uri
    from flask import url_for
    return url_for('auth_callback', _external=True, _scheme='https')

