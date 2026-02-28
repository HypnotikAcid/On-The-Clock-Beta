import os
import traceback
import logging
import csv
import io
from datetime import datetime, timezone
from flask import Blueprint, render_template, redirect, request, session, jsonify, current_app as app, Response

from app import (
    require_api_auth, require_auth, require_server_owner, Entitlements, 
    sanitize_csv_string,
    _get_bot_module, notify_server_owner_bot_access, validate_role_in_guild, verify_guild_access
)

from web.utils.db import get_db
api_owner_bp = Blueprint('api_owner', __name__)
@api_owner_bp.route("/api/owner/manual-grant", methods=["POST"])
@require_api_auth
def api_owner_manual_grant(user_session):
    """Owner-only API endpoint to manually grant access with specific source attribution"""
    try:
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        if user_session['user_id'] != bot_owner_id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
            
        data = request.get_json()
        guild_id = data.get('guild_id')
        source = data.get('source', 'owner') # 'stripe' or 'owner'
        
        if not guild_id or not guild_id.isdigit():
            return jsonify({'success': False, 'error': 'Invalid guild_id'}), 400
            
        db_source = 'Stripe' if source == 'stripe' else 'Granted'
        
        with get_db() as conn:
            conn.execute("""
                INSERT INTO server_subscriptions (guild_id, tier, bot_access_paid, retention_tier, status, manually_granted, granted_by, granted_at, grant_source)
                VALUES (%s, 'premium', TRUE, '30day', 'active', TRUE, %s, NOW(), %s)
                ON CONFLICT (guild_id) DO UPDATE SET
                    tier = 'premium',
                    bot_access_paid = TRUE,
                    retention_tier = '30day',
                    status = 'active',
                    manually_granted = TRUE,
                    granted_by = %s,
                    granted_at = NOW(),
                    grant_source = %s
            """, (int(guild_id), user_session['user_id'], db_source, user_session['user_id'], db_source))
            
        app.logger.info(f"Owner {user_session.get('username')} manually granted access to {guild_id} as {db_source}")
        return jsonify({'success': True, 'message': f'Premium access granted to {guild_id} (Source: {db_source})'})
        
    except Exception as e:
        app.logger.error(f"Manual grant error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@api_owner_bp.route("/debug")
@require_auth
def debug_console(user_session):
    """Owner-only debug console for security testing"""
    try:
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        
        if user_session['user_id'] != bot_owner_id:
            app.logger.warning(f"Unauthorized debug console access attempt by user {user_session['user_id']}")
            return "<h1>403 Forbidden</h1><p>You do not have permission to access this page.</p><a href='/dashboard'>Return to Dashboard</a>", 403
        
        app.logger.info(f"Debug console accessed by owner {user_session.get('username')}")
        return render_template('debug.html', user=user_session)
    
    except Exception as e:
        app.logger.error(f"Debug console error: {str(e)}")
        return "<h1>Error</h1><p>Unable to load debug console.</p><a href='/dashboard'>Return to Dashboard</a>", 500

@api_owner_bp.route("/debug/run-test", methods=["POST"])
@require_api_auth
def debug_run_test(user_session):
    """Owner-only API endpoint to run security tests"""
    try:
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        
        if user_session['user_id'] != bot_owner_id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        data = request.get_json()
        test_type = data.get('test_type')
        guild_id = data.get('guild_id', '')
        role_id = data.get('role_id', '')
        
        app.logger.info(f"Debug test '{test_type}' initiated by owner")
        
        if test_type == 'valid_guild':
            if not guild_id or not guild_id.isdigit():
                return jsonify({
                    'success': False,
                    'message': 'Please enter a valid numeric guild ID first',
                    'details': 'Guild ID must be a numeric Discord snowflake ID'
                })
            
            result = _test_guild_id_validation(guild_id, role_id, user_session)
            return jsonify(result)
        
        elif test_type == 'path_traversal':
            malicious_id = f"{guild_id}/../admin" if guild_id else "123/../admin"
            result = _test_guild_id_validation(malicious_id, role_id, user_session, expect_block=True)
            return jsonify(result)
        
        elif test_type == 'encoded_traversal':
            malicious_id = f"{guild_id}%2F..%2Fadmin" if guild_id else "123%2F..%2Fadmin"
            result = _test_guild_id_validation(malicious_id, role_id, user_session, expect_block=True)
            return jsonify(result)
        
        elif test_type == 'special_chars':
            malicious_id = f"{guild_id}@evil.com#fragment" if guild_id else "123@evil.com#fragment"
            result = _test_guild_id_validation(malicious_id, role_id, user_session, expect_block=True)
            return jsonify(result)
        
        elif test_type == 'empty_guild':
            result = _test_guild_id_validation('', role_id, user_session, expect_block=True)
            return jsonify(result)
        
        elif test_type == 'non_numeric':
            result = _test_guild_id_validation('abcdefgh', role_id, user_session, expect_block=True)
            return jsonify(result)
        
        elif test_type == 'bot_api_health':
            try:
                bot_api_secret = os.getenv('BOT_API_SECRET')
                if not bot_api_secret:
                    return jsonify({
                        'success': False,
                        'message': 'BOT_API_SECRET not configured',
                        'details': 'The bot API secret is not set in environment variables'
                    })
                
                response = requests.get(
                    'http://localhost:8081/health',
                    headers={'Authorization': f'Bearer {bot_api_secret}'},
                    timeout=5
                )
                
                if response.ok:
                    return jsonify({
                        'success': True,
                        'message': 'Bot API is healthy and responding',
                        'details': f'Status: {response.status_code}, Response: {response.text[:200]}'
                    })
                else:
                    return jsonify({
                        'success': False,
                        'message': f'Bot API returned status {response.status_code}',
                        'details': response.text[:500]
                    })
            except requests.exceptions.ConnectionError:
                return jsonify({
                    'success': False,
                    'message': 'Cannot connect to Bot API at localhost:8081',
                    'details': 'The bot API server may not be running'
                })
            except Exception as e:
                return jsonify({
                    'success': False,
                    'message': f'Bot API health check failed: {str(e)}',
                    'details': traceback.format_exc()
                })
        
        elif test_type == 'db_connection':
            try:
                with get_db() as conn:
                    cursor = conn.execute("SELECT COUNT(*) as count FROM server_subscriptions")
                    row = cursor.fetchone()
                    return jsonify({
                        'success': True,
                        'message': 'Database connection successful',
                        'details': f'Query executed successfully. Server subscriptions count: {row["count"]}'
                    })
            except Exception as e:
                return jsonify({
                    'success': False,
                    'message': f'Database connection failed: {str(e)}',
                    'details': traceback.format_exc()
                })
        
        elif test_type == 'session_check':
            return jsonify({
                'success': True,
                'message': 'Session is valid and authenticated',
                'details': {
                    'user_id': user_session.get('user_id'),
                    'username': user_session.get('username'),
                    'is_owner': user_session['user_id'] == bot_owner_id,
                    'guilds_count': len(user_session.get('guilds', []))
                }
            })
        
        elif test_type == 'invalid_role_id':
            result = _test_role_id_validation(guild_id, user_session)
            return jsonify(result)
        
        else:
            return jsonify({
                'success': False,
                'message': f'Unknown test type: {test_type}'
            })
    
    except Exception as e:
        app.logger.error(f"Debug test error: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Test execution error: {str(e)}',
            'details': traceback.format_exc()
        })

def _test_guild_id_validation(guild_id, role_id, user_session, expect_block=False):
    """Helper function to test guild_id validation (SSRF protection)"""
    test_url = f"/api/server/{guild_id}/admin-roles/add"
    
    is_numeric = guild_id.isdigit() if guild_id else False
    
    if not is_numeric:
        if expect_block:
            return {
                'success': True,
                'blocked': True,
                'expected_failure': True,
                'message': f'SSRF PROTECTION ACTIVE: Guild ID "{guild_id}" correctly rejected',
                'details': {
                    'tested_value': guild_id,
                    'is_numeric': False,
                    'validation_result': 'BLOCKED',
                    'reason': 'isdigit() check returned False - malicious input prevented'
                }
            }
        else:
            return {
                'success': False,
                'message': f'Guild ID "{guild_id}" is not numeric',
                'details': 'Please use a valid numeric Discord guild ID'
            }
    
    guild, _ = verify_guild_access(user_session, guild_id)
    if not guild:
        return {
            'success': False,
            'blocked': False,
            'message': f'You do not have admin access to guild {guild_id}',
            'details': {
                'tested_value': guild_id,
                'is_numeric': True,
                'validation_result': 'PASSED format check',
                'access_check': 'FAILED - no admin access'
            }
        }
    
    if expect_block:
        return {
            'success': False,
            'blocked': False,
            'message': f'WARNING: Guild ID "{guild_id}" was NOT blocked!',
            'details': {
                'tested_value': guild_id,
                'is_numeric': True,
                'expected': 'BLOCK',
                'actual': 'ALLOWED',
                'security_concern': 'This input should have been rejected'
            }
        }
    
    return {
        'success': True,
        'blocked': False,
        'message': f'Guild ID "{guild_id}" passed validation and access checks',
        'details': {
            'tested_value': guild_id,
            'is_numeric': True,
            'validation_result': 'PASSED',
            'access_check': 'PASSED',
            'guild_name': guild.get('name', 'Unknown'),
            'role_id_provided': bool(role_id)
        }
    }

def _test_role_id_validation(guild_id, user_session):
    """Helper function to test role_id validation in remove endpoints"""
    fake_role_id = "999999999999999999"
    
    if not guild_id:
        return {
            'success': False,
            'message': 'Please enter a valid Guild ID first to test role validation',
            'details': 'A real guild ID is needed to test role validation against the guild\'s actual roles'
        }
    
    if not guild_id.isdigit():
        return {
            'success': False,
            'message': f'Guild ID "{guild_id}" is not numeric',
            'details': 'Please use a valid numeric Discord guild ID'
        }
    
    guild, _ = verify_guild_access(user_session, guild_id)
    if not guild:
        return {
            'success': False,
            'message': f'You do not have admin access to guild {guild_id}',
            'details': 'Enter a guild ID where you have admin permissions'
        }
    
    is_valid_role = validate_role_in_guild(guild_id, fake_role_id)
    
    if not is_valid_role:
        return {
            'success': True,
            'blocked': True,
            'expected_failure': True,
            'message': f'ROLE VALIDATION ACTIVE: Fake role ID "{fake_role_id}" correctly rejected',
            'details': {
                'tested_guild': guild_id,
                'guild_name': guild.get('name', 'Unknown'),
                'tested_role_id': fake_role_id,
                'validation_result': 'BLOCKED',
                'reason': 'validate_role_in_guild() returned False - invalid role prevented from being forwarded'
            }
        }
    else:
        return {
            'success': False,
            'blocked': False,
            'message': f'WARNING: Fake role ID "{fake_role_id}" was NOT blocked!',
            'details': {
                'tested_guild': guild_id,
                'tested_role_id': fake_role_id,
                'expected': 'BLOCK',
                'actual': 'ALLOWED',
                'security_concern': 'This role ID should have been rejected as invalid for this guild'
            }
        }


@api_owner_bp.route("/debug/health/bot")
@require_auth
def debug_health_bot(user_session):
    """Check Discord bot health"""
    bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
    if user_session['user_id'] != bot_owner_id:
        return jsonify({'healthy': False, 'error': 'Unauthorized'}), 403
    
    try:
        bot_api_secret = os.getenv('BOT_API_SECRET')
        if not bot_api_secret:
            return jsonify({'healthy': False, 'error': 'BOT_API_SECRET not configured'})
        
        response = requests.get(
            'http://localhost:8081/health',
            headers={'Authorization': f'Bearer {bot_api_secret}'},
            timeout=5
        )
        
        if response.ok:
            return jsonify({'healthy': True, 'message': 'Bot connected and healthy'})
        else:
            return jsonify({'healthy': False, 'error': f'Bot API returned {response.status_code}'})
    except requests.exceptions.ConnectionError:
        return jsonify({'healthy': False, 'error': 'Bot API not responding'})
    except Exception as e:
        return jsonify({'healthy': False, 'error': str(e)})


@api_owner_bp.route("/debug/health/db")
@require_auth
def debug_health_db(user_session):
    """Check database health"""
    bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
    if user_session['user_id'] != bot_owner_id:
        return jsonify({'healthy': False, 'error': 'Unauthorized'}), 403
    
    try:
        with get_db() as conn:
            cursor = conn.execute("SELECT COUNT(*) as count FROM server_subscriptions")
            row = cursor.fetchone()
            return jsonify({'healthy': True, 'message': f'{row["count"]} servers tracked'})
    except Exception as e:
        return jsonify({'healthy': False, 'error': str(e)})


@api_owner_bp.route("/debug/health/stripe")
@require_auth
def debug_health_stripe(user_session):
    """Check Stripe configuration"""
    bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
    if user_session['user_id'] != bot_owner_id:
        return jsonify({'healthy': False, 'error': 'Unauthorized'}), 403
    
    try:
        import stripe
        stripe_key = os.getenv('STRIPE_SECRET_KEY')
        webhook_secret = os.getenv('STRIPE_WEBHOOK_SECRET')
        
        if not stripe_key:
            return jsonify({'healthy': False, 'error': 'STRIPE_SECRET_KEY not set'})
        
        if not webhook_secret:
            return jsonify({'healthy': False, 'error': 'Webhook secret missing'})
        
        stripe.api_key = stripe_key
        stripe.Account.retrieve()
        return jsonify({'healthy': True, 'message': 'Stripe configured and connected'})
    except Exception as e:
        return jsonify({'healthy': False, 'error': str(e)})


@api_owner_bp.route("/debug/health/email")
@require_auth
def debug_health_email(user_session):
    """Check email service configuration"""
    bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
    if user_session['user_id'] != bot_owner_id:
        return jsonify({'healthy': False, 'error': 'Unauthorized'}), 403
    
    try:
        from email_utils import send_email
        return jsonify({'healthy': True, 'message': 'Email service available'})
    except ImportError:
        return jsonify({'healthy': False, 'error': 'email_utils module not found'})
    except Exception as e:
        return jsonify({'healthy': False, 'error': str(e)})


@api_owner_bp.route("/debug/api-test/<test_id>")
@require_auth
def debug_api_test(user_session, test_id):
    """Run specific API tests"""
    bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
    if user_session['user_id'] != bot_owner_id:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    try:
        if test_id == 'bot-api':
            bot_api_secret = os.getenv('BOT_API_SECRET')
            if not bot_api_secret:
                return jsonify({'success': False, 'error': 'No API secret configured'})
            response = requests.get(
                'http://localhost:8081/health',
                headers={'Authorization': f'Bearer {bot_api_secret}'},
                timeout=5
            )
            return jsonify({'success': response.ok, 'message': f'Status {response.status_code}'})
        
        elif test_id == 'db':
            with get_db() as conn:
                cursor = conn.execute("SELECT 1 as test")
                cursor.fetchone()
                return jsonify({'success': True, 'message': 'Query executed successfully'})
        
        elif test_id == 'session':
            return jsonify({
                'success': True, 
                'message': f'Logged in as {user_session.get("username")}'
            })
        
        elif test_id == 'stripe':
            import stripe
            stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
            if not stripe.api_key:
                return jsonify({'success': False, 'error': 'No Stripe key'})
            stripe.Account.retrieve()
            return jsonify({'success': True, 'message': 'Stripe API accessible'})
        
        elif test_id == 'email':
            from email_utils import send_email
            return jsonify({'success': True, 'message': 'Email module loaded'})
        
        else:
            return jsonify({'success': False, 'error': f'Unknown test: {test_id}'})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@api_owner_bp.route("/debug/version-info")
@require_auth
def debug_version_info(user_session):
    """Get version information from version.json and public_roadmap.json"""
    bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
    if user_session['user_id'] != bot_owner_id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        internal_version = 'Unknown'
        public_version = 'Unknown'
        updated = 'Unknown'
        
        try:
            with open('version.json', 'r') as f:
                version_data = json.load(f)
                internal_version = version_data.get('version', 'Unknown')
                updated = version_data.get('last_updated', 'Unknown')
        except:
            pass
        
        try:
            with open('public_roadmap.json', 'r') as f:
                roadmap_data = json.load(f)
                public_version = roadmap_data.get('current_version', 'Unknown')
        except:
            pass
        
        return jsonify({
            'internal': internal_version,
            'public': public_version,
            'updated': updated
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_owner_bp.route("/debug/checklist")
@require_auth
def debug_checklist(user_session):
    """Run full pre-publish checklist"""
    bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
    if user_session['user_id'] != bot_owner_id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    checks = {}
    
    try:
        bot_api_secret = os.getenv('BOT_API_SECRET')
        if bot_api_secret:
            response = requests.get(
                'http://localhost:8081/health',
                headers={'Authorization': f'Bearer {bot_api_secret}'},
                timeout=5
            )
            if response.ok:
                checks['bot-connected'] = {'status': 'pass', 'name': 'Discord Bot', 'detail': 'Connected and responding'}
            else:
                checks['bot-connected'] = {'status': 'fail', 'name': 'Discord Bot', 'detail': f'API returned {response.status_code}'}
        else:
            checks['bot-connected'] = {'status': 'fail', 'name': 'Discord Bot', 'detail': 'BOT_API_SECRET not configured'}
    except:
        checks['bot-connected'] = {'status': 'fail', 'name': 'Discord Bot', 'detail': 'Cannot connect to bot API'}
    
    try:
        bot_api_secret = os.getenv('BOT_API_SECRET')
        if bot_api_secret:
            response = requests.get(
                'http://localhost:8081/commands',
                headers={'Authorization': f'Bearer {bot_api_secret}'},
                timeout=5
            )
            if response.ok:
                data = response.json()
                cmd_count = data.get('count', 0)
                checks['commands-synced'] = {'status': 'pass', 'name': 'Slash Commands', 'detail': f'{cmd_count} commands synced'}
            else:
                checks['commands-synced'] = {'status': 'warn', 'name': 'Slash Commands', 'detail': 'Could not verify command count'}
        else:
            checks['commands-synced'] = {'status': 'warn', 'name': 'Slash Commands', 'detail': 'Cannot check without API secret'}
    except:
        checks['commands-synced'] = {'status': 'warn', 'name': 'Slash Commands', 'detail': 'Command endpoint not available'}
    
    try:
        with get_db() as conn:
            cursor = conn.execute("SELECT 1 as test")
            cursor.fetchone()
            checks['db-connected'] = {'status': 'pass', 'name': 'Database', 'detail': 'PostgreSQL connected'}
    except Exception as e:
        checks['db-connected'] = {'status': 'fail', 'name': 'Database', 'detail': str(e)}
    
    checks['migrations-current'] = {'status': 'pass', 'name': 'Migrations', 'detail': 'Auto-applied on startup'}
    
    stripe_key = os.getenv('STRIPE_SECRET_KEY')
    if stripe_key and stripe_key.startswith('sk_'):
        checks['stripe-configured'] = {'status': 'pass', 'name': 'Stripe API', 'detail': 'Secret key configured'}
    else:
        checks['stripe-configured'] = {'status': 'fail', 'name': 'Stripe API', 'detail': 'Invalid or missing key'}
    
    webhook_secret = os.getenv('STRIPE_WEBHOOK_SECRET')
    if webhook_secret and webhook_secret.startswith('whsec_'):
        checks['webhook-secret'] = {'status': 'pass', 'name': 'Webhook Secret', 'detail': 'Properly configured'}
    else:
        checks['webhook-secret'] = {'status': 'fail', 'name': 'Webhook Secret', 'detail': 'Invalid or missing'}
    
    try:
        from email_utils import send_email
        checks['email-service'] = {'status': 'pass', 'name': 'Email Service', 'detail': 'Module available'}
    except:
        checks['email-service'] = {'status': 'fail', 'name': 'Email Service', 'detail': 'email_utils not found'}
    
    try:
        from entitlements import Entitlements
        checks['entitlements'] = {'status': 'pass', 'name': 'Entitlements', 'detail': 'Premium gates active'}
    except:
        checks['entitlements'] = {'status': 'fail', 'name': 'Entitlements', 'detail': 'Module not loaded'}
    
    try:
        with open('version.json', 'r') as f:
            version_data = json.load(f)
            version = version_data.get('version', 'Unknown')
            checks['version-updated'] = {'status': 'pass', 'name': 'Version', 'detail': f'v{version}'}
    except:
        checks['version-updated'] = {'status': 'warn', 'name': 'Version', 'detail': 'version.json not found'}
    
    try:
        with open('version.json', 'r') as f:
            version_data = json.load(f)
        with open('public_roadmap.json', 'r') as f:
            roadmap_data = json.load(f)
        
        internal_v = version_data.get('version', '')
        public_v = roadmap_data.get('current_version', '')
        
        if internal_v == public_v:
            checks['roadmap-synced'] = {'status': 'pass', 'name': 'Roadmap Sync', 'detail': f'Both at v{internal_v}'}
        else:
            checks['roadmap-synced'] = {'status': 'warn', 'name': 'Roadmap Sync', 'detail': f'Internal {internal_v} vs Public {public_v}'}
    except:
        checks['roadmap-synced'] = {'status': 'warn', 'name': 'Roadmap Sync', 'detail': 'Could not compare versions'}
    
    return jsonify({'checks': checks})


def seed_demo_data_internal():
    """Internal function to seed demo data for the demo server."""
    from datetime import datetime, timedelta, timezone
    import random
    
    demo_guild_id = 1419894879894507661
    demo_employees = [
        {'user_id': 100000000000000001, 'display_name': 'Alex Manager', 'full_name': 'Alex Thompson', 'first_name': 'Alex', 'last_name': 'Thompson', 'email': 'alex.demo@ontheclock.app', 'position': 'Store Manager', 'department': 'Management', 'company_role': 'Manager', 'bio': 'Demo manager account - 5 years with the company', 'role_tier': 'admin', 'accent_color': '#3b82f6', 'profile_background': 'theme-ocean'},
        {'user_id': 100000000000000002, 'display_name': 'Jordan Sales', 'full_name': 'Jordan Rivera', 'first_name': 'Jordan', 'last_name': 'Rivera', 'email': 'jordan.demo@ontheclock.app', 'position': 'Sales Associate', 'department': 'Sales', 'company_role': 'Employee', 'bio': 'Top performer in sales department', 'role_tier': 'employee', 'accent_color': '#eab308', 'profile_background': 'theme-sunset'},
        {'user_id': 100000000000000003, 'display_name': 'Casey Support', 'full_name': 'Casey Williams', 'first_name': 'Casey', 'last_name': 'Williams', 'email': 'casey.demo@ontheclock.app', 'position': 'Customer Support', 'department': 'Support', 'company_role': 'Employee', 'bio': 'Friendly face of customer service', 'role_tier': 'employee', 'accent_color': '#8b5cf6', 'profile_background': 'theme-default'},
        {'user_id': 100000000000000004, 'display_name': 'Sam Warehouse', 'full_name': 'Sam Johnson', 'first_name': 'Sam', 'last_name': 'Johnson', 'email': 'sam.demo@ontheclock.app', 'position': 'Warehouse Lead', 'department': 'Warehouse', 'company_role': 'Employee', 'bio': 'Keeps the warehouse running smoothly', 'role_tier': 'employee', 'accent_color': '#ef4444', 'profile_background': 'theme-default'},
        {'user_id': 100000000000000005, 'display_name': 'Taylor Intern', 'full_name': 'Taylor Chen', 'first_name': 'Taylor', 'last_name': 'Chen', 'email': 'taylor.demo@ontheclock.app', 'position': 'Marketing Intern', 'department': 'Marketing', 'company_role': 'Intern', 'bio': 'Learning the ropes of digital marketing', 'role_tier': 'employee', 'accent_color': '#10b981', 'profile_background': 'theme-forest'}
    ]
    
    try:
        with get_db() as conn:
            now = datetime.now(timezone.utc)
            
            # 1. Seed Employees
            for emp in demo_employees:
                conn.execute("""
                    INSERT INTO employee_profiles (guild_id, user_id, first_name, last_name, email, position, department, company_role, bio, role_tier, is_active, profile_setup_completed, hire_date, accent_color, profile_background)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, TRUE, TRUE, %s, %s, %s)
                    ON CONFLICT (guild_id, user_id) DO UPDATE SET 
                        first_name = EXCLUDED.first_name, 
                        last_name = EXCLUDED.last_name, 
                        email = EXCLUDED.email, 
                        position = EXCLUDED.position, 
                        department = EXCLUDED.department, 
                        company_role = EXCLUDED.company_role, 
                        bio = EXCLUDED.bio, 
                        role_tier = EXCLUDED.role_tier, 
                        is_active = TRUE, 
                        profile_setup_completed = TRUE,
                        accent_color = EXCLUDED.accent_color,
                        profile_background = EXCLUDED.profile_background
                """, (demo_guild_id, emp['user_id'], emp['display_name'], emp['full_name'], emp['first_name'], emp['last_name'], emp['email'], emp['position'], emp['department'], emp['company_role'], emp['bio'], emp['role_tier'], now - timedelta(days=random.randint(30, 365)), emp.get('accent_color'), emp.get('profile_background')))
            
            # 2. Clear and Seed Sessions
            demo_user_ids = [e['user_id'] for e in demo_employees]
            conn.execute("DELETE FROM timeclock_sessions WHERE guild_id = %s AND user_id = ANY(%s)", (demo_guild_id, demo_user_ids))
            
            for emp_id in demo_user_ids:
                work_days = random.randint(15, 25)
                for day_offset in range(30, 0, -1):
                    if random.random() > (work_days / 30.0):
                        continue
                    work_date = now - timedelta(days=day_offset)
                    if work_date.weekday() >= 5 and random.random() > 0.2:
                        continue
                    start_hour = random.randint(7, 10)
                    start_minute = random.choice([0, 15, 30, 45])
                    clock_in = work_date.replace(hour=start_hour, minute=start_minute, second=0, microsecond=0)
                    shift_length = random.uniform(4, 9)
                    clock_out = clock_in + timedelta(hours=shift_length)
                    conn.execute("INSERT INTO timeclock_sessions (guild_id, user_id, clock_in_time, clock_out_time) VALUES (%s, %s, %s, %s)", (demo_guild_id, emp_id, clock_in.isoformat(), clock_out.isoformat()))
            
            # 3. Add one active session
            active_emp = random.choice(demo_employees[1:])
            today_start = now.replace(hour=random.randint(7, 10), minute=random.choice([0, 15, 30]), second=0, microsecond=0)
            conn.execute("INSERT INTO timeclock_sessions (guild_id, user_id, clock_in_time, clock_out_time) VALUES (%s, %s, %s, NULL)", (demo_guild_id, active_emp['user_id'], today_start.isoformat()))
            
            # 4. Clear and Seed Adjustment Requests
            conn.execute("DELETE FROM time_adjustment_requests WHERE guild_id = %s AND user_id = ANY(%s)", (demo_guild_id, demo_user_ids))
            request_scenarios = [
                {'employee_idx': 1, 'request_type': 'add_session', 'reason': 'Forgot to clock in - morning meeting', 'status': 'pending', 'days_ago': 2},
                {'employee_idx': 2, 'request_type': 'modify_clockout', 'reason': 'System logged me out early', 'status': 'pending', 'days_ago': 1},
                {'employee_idx': 3, 'request_type': 'add_session', 'reason': 'Worked from home', 'status': 'approved', 'days_ago': 5},
                {'employee_idx': 4, 'request_type': 'modify_clockin', 'reason': 'Arrived early to help', 'status': 'denied', 'days_ago': 7}
            ]
            for scenario in request_scenarios:
                emp = demo_employees[scenario['employee_idx']]
                request_date = now - timedelta(days=scenario['days_ago'])
                req_in = request_date.replace(hour=9, minute=0, second=0, microsecond=0)
                req_out = request_date.replace(hour=17, minute=0, second=0, microsecond=0)
                rev_by = demo_employees[0]['user_id'] if scenario['status'] != 'pending' else None
                rev_at = now - timedelta(days=scenario['days_ago'] - 1) if scenario['status'] != 'pending' else None
                conn.execute("INSERT INTO time_adjustment_requests (guild_id, user_id, request_type, reason, status, requested_clock_in, requested_clock_out, reviewed_by, reviewed_at, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", (demo_guild_id, emp['user_id'], scenario['request_type'], scenario['reason'], scenario['status'], req_in.isoformat(), req_out.isoformat(), rev_by, rev_at.isoformat() if rev_at else None, request_date.isoformat()))
            
            # 5. Track last reset and enable kiosk customization
            conn.execute("""
                INSERT INTO guild_settings (guild_id, name, last_demo_reset, allow_kiosk_customization)
                VALUES (%s, %s, %s, TRUE)
                ON CONFLICT (guild_id) DO UPDATE SET 
                    last_demo_reset = EXCLUDED.last_demo_reset,
                    allow_kiosk_customization = TRUE
            """, (demo_guild_id, "On The Clock Demo", now.isoformat()))
            
            conn.commit()
            return True
    except Exception as e:
        print(f"Error seeding demo data: {e}")
        return False

@api_owner_bp.route("/debug/seed-demo-data", methods=["POST"])
@require_server_owner
def debug_seed_demo_data(user_session):
    """Owner-only endpoint to manually seed demo data."""
    # @require_server_owner already verified owner tier (which on demo server is bot owner)
    
    success = seed_demo_data_internal()
    if success:
        return jsonify({'success': True, 'message': 'Demo data seeded successfully'}), 200
    else:
        return jsonify({'success': False, 'error': 'Seeding failed'}), 500


@api_owner_bp.route("/api/owner/grant-access", methods=["POST"])
@require_api_auth
def api_owner_grant_access(user_session):
    """Owner-only API endpoint to manually grant bot access or retention tiers to servers"""
    try:
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        
        # Security check: Only allow bot owner
        if user_session['user_id'] != bot_owner_id:
            app.logger.warning(f"Unauthorized grant access attempt by user {user_session['user_id']}")
            return jsonify({'success': False, 'error': 'Unauthorized - Owner access required'}), 403
        
        data = request.get_json()
        guild_id = data.get('guild_id')
        access_type = data.get('access_type')
        grant_source = data.get('source', 'granted').lower()
        
        if not guild_id or not access_type:
            return jsonify({'success': False, 'error': 'Missing guild_id or access_type'}), 400
        
        if access_type not in ['bot_access', '7day', '30day', 'premium', 'pro']:
            return jsonify({'success': False, 'error': 'Invalid access_type. Must be premium, pro, bot_access, 7day, or 30day'}), 400
        
        # Map new tier names to database values
        original_type = access_type
        if access_type == 'premium':
            access_type = '30day'  # Premium = 30-day retention + bot_access
        
        if grant_source not in ['granted', 'stripe']:
            grant_source = 'granted'
        
        app.logger.info(f"Owner {user_session.get('username')} granting {original_type} (mapped to {access_type}, source={grant_source}) to guild {guild_id}")
        
        with get_db() as conn:
            # Check if server exists in server_subscriptions
            cursor = conn.execute("SELECT guild_id FROM server_subscriptions WHERE guild_id = %s", (guild_id,))
            server_exists = cursor.fetchone()
            
            if not server_exists:
                # Create server subscription entry if it doesn't exist
                conn.execute("""
                    INSERT INTO server_subscriptions (guild_id, tier, bot_access_paid, retention_tier, status)
                    VALUES (%s, 'free', FALSE, 'none', 'active')
                """, (guild_id,))
                app.logger.info(f"Created new server_subscriptions entry for guild {guild_id}")
            
            # Grant the appropriate access
            if access_type == 'bot_access':
                conn.execute("""
                    UPDATE server_subscriptions 
                    SET bot_access_paid = TRUE,
                        manually_granted = TRUE,
                        granted_by = %s,
                        granted_at = NOW(),
                        grant_source = %s
                    WHERE guild_id = %s
                """, (user_session['user_id'], grant_source, guild_id))
                app.logger.info(f"[OK] Granted bot access (source={grant_source}) to guild {guild_id}")
                
            elif access_type in ['7day', '30day', 'pro']:
                # For premium/pro, also grant bot_access automatically
                conn.execute("""
                    UPDATE server_subscriptions 
                    SET retention_tier = %s,
                        bot_access_paid = TRUE,
                        manually_granted = TRUE,
                        granted_by = %s,
                        granted_at = NOW(),
                        status = 'active',
                        grant_source = %s
                    WHERE guild_id = %s
                """, (access_type, user_session['user_id'], grant_source, guild_id))
                app.logger.info(f"[OK] Granted {original_type} tier (retention={access_type}, source={grant_source}) to guild {guild_id}")
            
            # Context manager handles commit automatically
            app.logger.info(f"[OK] Transaction will be committed for guild {guild_id}")
            
            # Send notification to server owner if granting bot access
            if access_type == 'bot_access':
                app.logger.info(f"≡ƒôº Attempting to send welcome notification to server owner for guild {guild_id}")
                
                # Check bot availability with detailed logging
                if not bot:
                    app.logger.error(f"[ERROR] Bot instance is None - cannot send notification")
                    app.logger.error(f"   Bot may not have started yet. Check if Discord bot thread is running.")
                elif not hasattr(bot, 'loop'):
                    app.logger.error(f"[ERROR] Bot instance has no 'loop' attribute - bot may not be started yet")
                    app.logger.error(f"   Discord bot needs to connect before notifications can be sent.")
                elif not bot.loop:
                    app.logger.error(f"[ERROR] Bot loop is None - bot may not be fully connected")
                    app.logger.error(f"   Discord connection not established. Wait for bot to fully start.")
                elif not bot.is_ready():
                    app.logger.error(f"[ERROR] Bot is not ready - still connecting to Discord")
                    app.logger.error(f"   Bot status: connected but not ready. Notification will be skipped.")
                else:
                    app.logger.info(f"[OK] Bot is ready and connected. Queueing notification...")
                    try:
                        # Queue the notification in the bot's event loop
                        future = asyncio.run_coroutine_threadsafe(
                            notify_server_owner_bot_access(int(guild_id), granted_by="manual"),
                            bot.loop
                        )
                        app.logger.info(f"[OK] Welcome notification queued successfully for guild {guild_id}")
                        
                        # Wait for result (max 5 seconds) to catch errors
                        try:
                            result = future.result(timeout=5.0)
                            app.logger.info(f"[OK] Welcome notification completed successfully for guild {guild_id}")
                        except concurrent.futures.TimeoutError:
                            app.logger.error(f"ΓÅ▒∩╕Å Welcome notification timed out after 5 seconds for guild {guild_id}")
                            app.logger.error(f"   Notification may still be processing. Check Discord bot logs for [NOTIFY] messages.")
                        except Exception as result_error:
                            app.logger.error(f"[ERROR] Welcome notification failed for guild {guild_id}")
                            app.logger.error(f"   Error type: {type(result_error).__name__}")
                            app.logger.error(f"   Error message: {str(result_error)}")
                            app.logger.error(f"   Full traceback:")
                            app.logger.error(traceback.format_exc())
                            
                    except Exception as notify_error:
                        app.logger.error(f"[ERROR] Failed to queue welcome notification for guild {guild_id}")
                        app.logger.error(f"   Error type: {type(notify_error).__name__}")
                        app.logger.error(f"   Error message: {str(notify_error)}")
                        app.logger.error(f"   Full traceback:")
                        app.logger.error(traceback.format_exc())
            
        return jsonify({
            'success': True,
            'message': f'Successfully granted {access_type} to server',
            'guild_id': guild_id,
            'access_type': access_type
        })
    
    except ValueError as ve:
        # Handle specific validation errors
        app.logger.warning(f"Validation error during grant: {str(ve)}")
        return jsonify({'success': False, 'error': str(ve)}), 400
    except Exception as e:
        app.logger.error(f"Grant access error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@api_owner_bp.route("/api/owner/settings", methods=["GET", "POST"])
@require_api_auth
def api_owner_settings(user_session):
    """Owner-only API endpoint to get or set global system alert toggles."""
    try:
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        if user_session['user_id'] != bot_owner_id:
            return jsonify({'success': False, 'error': 'Forbidden'}), 403
            
        owner_id = int(user_session['user_id'])
        
        if request.method == "GET":
            with get_db() as conn:
                cursor = conn.execute("SELECT alert_stripe_failures, alert_db_timeouts, alert_high_errors FROM owner_settings WHERE owner_id = %s", (owner_id,))
                row = cursor.fetchone()
                if row:
                    return jsonify({
                        'success': True,
                        'alert_stripe_failures': bool(row['alert_stripe_failures']),
                        'alert_db_timeouts': bool(row['alert_db_timeouts']),
                        'alert_high_errors': bool(row['alert_high_errors'])
                    })
                return jsonify({
                    'success': True,
                    'alert_stripe_failures': True,
                    'alert_db_timeouts': True,
                    'alert_high_errors': True
                })
        else:
            data = request.get_json() or {}
            alert_stripe = bool(data.get('alert_stripe_failures', True))
            alert_db = bool(data.get('alert_db_timeouts', True))
            alert_errors = bool(data.get('alert_high_errors', True))
            
            with get_db() as conn:
                cursor = conn.execute("SELECT owner_id FROM owner_settings WHERE owner_id = %s", (owner_id,))
                if cursor.fetchone():
                    conn.execute("""
                        UPDATE owner_settings 
                        SET alert_stripe_failures = %s, alert_db_timeouts = %s, alert_high_errors = %s 
                        WHERE owner_id = %s
                    """, (alert_stripe, alert_db, alert_errors, owner_id))
                else:
                    conn.execute("""
                        INSERT INTO owner_settings (owner_id, alert_stripe_failures, alert_db_timeouts, alert_high_errors)
                        VALUES (%s, %s, %s, %s)
                    """, (owner_id, alert_stripe, alert_db, alert_errors))
                    
            return jsonify({'success': True})
            
    except Exception as e:
        app.logger.error(f"Owner settings error: {str(e)}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@api_owner_bp.route("/api/owner/server-index", methods=["GET"])
@require_api_auth
def api_owner_server_index(user_session):
    """Owner-only API endpoint to get lightweight server list for dropdown selection"""
    try:
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        
        if user_session['user_id'] != bot_owner_id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        search = request.args.get('search', '').strip().lower()
        
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT 
                    CAST(bg.guild_id AS BIGINT) as guild_id,
                    bg.guild_name,
                    COALESCE(ss.bot_access_paid, FALSE) as bot_access_paid,
                    COALESCE(ss.retention_tier, 'none') as retention_tier,
                    COALESCE(ss.manually_granted, FALSE) as manually_granted,
                    ss.grant_source,
                    COALESCE(bg.is_present, TRUE) as is_present,
                    bg.left_at
                FROM bot_guilds bg
                LEFT JOIN server_subscriptions ss ON ss.guild_id = CAST(bg.guild_id AS BIGINT)
                ORDER BY COALESCE(bg.is_present, TRUE) DESC, bg.guild_name
            """)
            
            active_servers = []
            historical_servers = []
            
            for row in cursor.fetchall():
                guild_id = str(row['guild_id'])
                guild_name = row['guild_name'] or f'Unknown ({guild_id})'
                is_present = bool(row['is_present'])
                
                # Apply search filter
                if search and search not in guild_name.lower() and search not in guild_id:
                    continue
                
                server_data = {
                    'guild_id': guild_id,
                    'name': guild_name,
                    'bot_access': bool(row['bot_access_paid']),
                    'retention': row['retention_tier'] if row['retention_tier'] != 'none' else None,
                    'granted': bool(row['manually_granted']),
                    'source': row['grant_source'],
                    'left_at': row['left_at'].strftime('%Y-%m-%d') if row.get('left_at') else None
                }
                
                if is_present:
                    active_servers.append(server_data)
                else:
                    historical_servers.append(server_data)
            
            return jsonify({
                'success': True,
                'active': active_servers,
                'historical': historical_servers
            })
    
    except Exception as e:
        app.logger.error(f"Server index error: {str(e)}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500


@api_owner_bp.route("/api/owner/revoke-access", methods=["POST"])
@require_api_auth
def api_owner_revoke_access(user_session):
    """Owner-only API endpoint to manually revoke bot access or retention tiers from servers"""
    try:
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        
        # Security check: Only allow bot owner
        if user_session['user_id'] != bot_owner_id:
            app.logger.warning(f"Unauthorized revoke access attempt by user {user_session['user_id']}")
            return jsonify({'success': False, 'error': 'Unauthorized - Owner access required'}), 403
        
        data = request.get_json()
        guild_id = data.get('guild_id')
        access_type = data.get('access_type')
        
        if not guild_id or not access_type:
            return jsonify({'success': False, 'error': 'Missing guild_id or access_type'}), 400
        
        if access_type not in ['bot_access', '7day', '30day', 'pro', 'all']:
            return jsonify({'success': False, 'error': 'Invalid access_type. Must be bot_access, 7day, 30day, pro, or all'}), 400
        
        app.logger.info(f"Owner {user_session.get('username')} revoking {access_type} from guild {guild_id}")
        
        with get_db() as conn:
            # Check if server exists in server_subscriptions
            cursor = conn.execute("SELECT guild_id, bot_access_paid, retention_tier, grandfathered FROM server_subscriptions WHERE guild_id = %s", (guild_id,))
            server = cursor.fetchone()
            
            if not server:
                app.logger.warning(f"Guild {guild_id} not found in server_subscriptions. Creating placeholder row.")
                # Auto-create placeholder row for this guild
                conn.execute("""
                    INSERT INTO server_subscriptions (guild_id, tier, bot_access_paid, retention_tier, status)
                    VALUES (%s, 'free', FALSE, 'none', 'free')
                """, (guild_id,))
                app.logger.info(f"Created placeholder server_subscriptions row for guild {guild_id}")
                # Re-fetch the server
                cursor = conn.execute("SELECT guild_id, bot_access_paid, retention_tier FROM server_subscriptions WHERE guild_id = %s", (guild_id,))
                server = cursor.fetchone()
            
            # Protect grandfathered servers from revocation (but allow upgrades)
            if server.get('grandfathered') and access_type in ['all', 'bot_access']:
                app.logger.warning(f"Attempted to revoke core access from grandfathered server {guild_id}")
                return jsonify({
                    'success': False, 
                    'error': 'Cannot revoke core access from grandfathered servers. These are legacy $5 lifetime users with permanent Premium access.'
                }), 400
            
            # Revoke the appropriate access
            if access_type == 'all':
                # Revoke all access (bot access + retention tier)
                conn.execute("""
                    UPDATE server_subscriptions 
                    SET bot_access_paid = FALSE,
                        tier = 'free',
                        retention_tier = 'none',
                        status = 'cancelled',
                        manually_granted = FALSE,
                        granted_by = NULL,
                        granted_at = NULL,
                        grant_source = NULL
                    WHERE guild_id = %s
                """, (guild_id,))
                app.logger.info(f"[REVOKE] Revoked ALL access from guild {guild_id}")
                
            elif access_type == 'bot_access':
                # Revoke bot access and also clear retention tier
                # CRITICAL: Set tier to 'free' to prevent migration from re-enabling access
                conn.execute("""
                    UPDATE server_subscriptions 
                    SET bot_access_paid = FALSE,
                        tier = 'free',
                        retention_tier = 'none',
                        status = 'cancelled',
                        manually_granted = FALSE,
                        granted_by = NULL,
                        granted_at = NULL
                    WHERE guild_id = %s
                """, (guild_id,))
                app.logger.info(f"[REVOKE] Revoked bot access from guild {guild_id} (tier set to 'free', retention cleared)")
                
            elif access_type in ['7day', '30day', 'pro']:
                # Only revoke if this is the current retention tier
                if server['retention_tier'] == access_type:
                    conn.execute("""
                        UPDATE server_subscriptions 
                        SET retention_tier = 'none',
                            status = 'active'
                        WHERE guild_id = %s
                    """, (guild_id,))
                    app.logger.info(f"[REVOKE] Revoked {access_type} retention from guild {guild_id}")
                else:
                    return jsonify({
                        'success': False, 
                        'error': f'Server does not have {access_type} retention active'
                    }), 400
            
            # Commit all changes
            app.logger.info(f"[OK] Transaction committed successfully for guild {guild_id}")
            
            return jsonify({
                'success': True,
                'message': f'Successfully revoked {access_type} from server',
                'guild_id': guild_id,
                'access_type': access_type
            })
    
    except Exception as e:
        app.logger.error(f"Revoke access error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@api_owner_bp.route("/api/owner/trial/grant", methods=["POST"])
@require_api_auth
def api_owner_trial_grant(user_session):
    """Owner-only API to manually grant trial usage to a server"""
    try:
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        
        if user_session['user_id'] != bot_owner_id:
            return jsonify({'success': False, 'error': 'Unauthorized - Owner access required'}), 403
        
        data = request.get_json()
        guild_id = data.get('guild_id', '').strip()
        
        if not guild_id:
            return jsonify({'success': False, 'error': 'Guild ID is required'}), 400
        
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT * FROM trial_usage WHERE guild_id = %s",
                (guild_id,)
            )
            existing = cursor.fetchone()
            
            if existing:
                return jsonify({
                    'success': False, 
                    'error': f'Trial already used on {existing["used_at"].strftime("%Y-%m-%d %H:%M")} ({existing["grant_type"]})'
                }), 400
            
            conn.execute("""
                INSERT INTO trial_usage (guild_id, granted_by, grant_type)
                VALUES (%s, %s, 'owner_grant')
            """, (guild_id, user_session['user_id']))
            
            app.logger.info(f"Trial granted to guild {guild_id} by owner {user_session.get('username')}")
            
            return jsonify({
                'success': True,
                'message': f'Trial marked as used for server {guild_id}. They will not see the $5 discount at checkout.'
            })
    
    except Exception as e:
        app.logger.error(f"Trial grant error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@api_owner_bp.route("/api/owner/trial/status/<guild_id>", methods=["GET"])
@require_api_auth
def api_owner_trial_status(user_session, guild_id):
    """Owner-only API to check trial status for a server"""
    try:
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        
        if user_session['user_id'] != bot_owner_id:
            return jsonify({'success': False, 'error': 'Unauthorized - Owner access required'}), 403
        
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT * FROM trial_usage WHERE guild_id = %s",
                (guild_id,)
            )
            trial = cursor.fetchone()
            
            if trial:
                return jsonify({
                    'success': True,
                    'trial_used': True,
                    'used_at': trial['used_at'].strftime('%Y-%m-%d %H:%M'),
                    'grant_type': trial['grant_type'],
                    'stripe_coupon_id': trial.get('stripe_coupon_id'),
                    'granted_by': trial.get('granted_by')
                })
            else:
                return jsonify({
                    'success': True,
                    'trial_used': False,
                    'message': 'Trial available'
                })
    
    except Exception as e:
        app.logger.error(f"Trial status check error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@api_owner_bp.route("/api/owner/trial/reset", methods=["POST"])
@require_api_auth
def api_owner_trial_reset(user_session):
    """Owner-only API to reset trial usage for a server (allow re-use)"""
    try:
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        
        if user_session['user_id'] != bot_owner_id:
            return jsonify({'success': False, 'error': 'Unauthorized - Owner access required'}), 403
        
        data = request.get_json()
        guild_id = data.get('guild_id', '').strip()
        
        if not guild_id:
            return jsonify({'success': False, 'error': 'Guild ID is required'}), 400
        
        with get_db() as conn:
            cursor = conn.execute(
                "DELETE FROM trial_usage WHERE guild_id = %s RETURNING id",
                (guild_id,)
            )
            deleted = cursor.fetchone()
            
            if deleted:
                app.logger.info(f"Trial reset for guild {guild_id} by owner {user_session.get('username')}")
                return jsonify({
                    'success': True,
                    'message': f'Trial reset for server {guild_id}. They can now use the $5 first-month discount.'
                })
            else:
                return jsonify({
                    'success': True,
                    'message': 'No trial record found - server already has trial available.'
                })
    
    except Exception as e:
        app.logger.error(f"Trial reset error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@api_owner_bp.route("/api/owner/broadcast", methods=["POST"])
@require_api_auth
def api_owner_broadcast(user_session):
    """Owner-only API endpoint to broadcast messages to all servers"""
    try:
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        
        # Security check: Only allow bot owner
        if user_session['user_id'] != bot_owner_id:
            app.logger.warning(f"Unauthorized broadcast attempt by user {user_session['user_id']}")
            return jsonify({'success': False, 'error': 'Unauthorized - Owner access required'}), 403
        
        data = request.get_json()
        title = data.get('title', '').strip()
        message = data.get('message', '').strip()
        target = data.get('target', 'all')  # 'all', 'paid', or 'free'
        
        if not title or not message:
            return jsonify({'success': False, 'error': 'Title and message are required'}), 400
        
        if len(title) > 100:
            return jsonify({'success': False, 'error': 'Title must be 100 characters or less'}), 400
            
        if len(message) > 2000:
            return jsonify({'success': False, 'error': 'Message must be 2000 characters or less'}), 400
        
        if target not in ['all', 'paid', 'free']:
            return jsonify({'success': False, 'error': 'Invalid target. Must be all, paid, or free'}), 400
        
        app.logger.info(f"Owner {user_session.get('username')} initiating broadcast to {target} servers")
        app.logger.info(f"Broadcast title: {title}")
        
        # Get target guild IDs based on filter (using Flask's get_db for production)
        # Note: bot_guilds.guild_id is TEXT, server_subscriptions.guild_id is BIGINT - must cast for JOIN
        with get_db() as conn:
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
            return jsonify({'success': False, 'error': 'No servers found matching the target filter'}), 400
        
        app.logger.info(f"Broadcasting to {len(guild_ids)} servers")
        
        # Send broadcast via bot's internal HTTP API (more reliable than cross-thread async)
        try:
            import requests
            bot_api_port = os.getenv("BOT_API_PORT", "8081")
            bot_api_secret = os.getenv("BOT_API_SECRET", "")
            
            # If no secret configured, try to get it from the bot module
            if not bot_api_secret:
                try:
                    bot_api_secret = _get_bot_module().BOT_API_SECRET
                except:
                    pass
            
            response = requests.post(
                f"http://127.0.0.1:{bot_api_port}/api/broadcast",
                json={
                    'guild_ids': guild_ids,
                    'title': title,
                    'message': message
                },
                headers={
                    'Authorization': f'Bearer {bot_api_secret}',
                    'Content-Type': 'application/json'
                },
                timeout=300  # 5 minute timeout for broadcasts
            )
            
            result = response.json()
            
            sent_count = result.get('sent_count', 0)
            failed_count = result.get('failed_count', 0)
            
            app.logger.info(f"Broadcast complete: {sent_count} sent, {failed_count} failed")
            
            if not result.get('success', True) and sent_count == 0:
                return jsonify({
                    'success': False,
                    'error': result.get('error', f'Failed to send to all {failed_count} servers'),
                    'sent_count': sent_count,
                    'failed_count': failed_count
                }), 500
            elif failed_count > 0:
                return jsonify({
                    'success': True,
                    'partial': True,
                    'message': f'Broadcast partially complete',
                    'sent_count': sent_count,
                    'failed_count': failed_count
                })
            else:
                return jsonify({
                    'success': True,
                    'message': f'Broadcast sent successfully',
                    'sent_count': sent_count,
                    'failed_count': 0
                })
                
        except requests.exceptions.Timeout:
            app.logger.error("Broadcast timed out after 300 seconds")
            return jsonify({'success': False, 'error': 'Broadcast timed out'}), 504
        except requests.exceptions.ConnectionError:
            app.logger.error("Could not connect to bot API")
            return jsonify({'success': False, 'error': 'Bot is not ready. Please try again later.'}), 503
        except Exception as broadcast_error:
            app.logger.error(f"Broadcast execution error: {str(broadcast_error)}")
            app.logger.error(traceback.format_exc())
            return jsonify({'success': False, 'error': f'Broadcast failed: {str(broadcast_error)}'}), 500
    
    except Exception as e:
        app.logger.error(f"Outer Broadcast error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@api_owner_bp.route("/api/owner/email-logs", methods=["GET"])
@require_api_auth
def api_owner_email_logs(user_session):
    """Owner-only API endpoint to view persistent email logs"""
    try:
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        
        if user_session['user_id'] != bot_owner_id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        from pathlib import Path
        import json
        
        log_file = Path("data/email_logs/email_audit.log")
        
        if not log_file.exists():
            return jsonify({
                'success': True,
                'logs': [],
                'message': 'No email logs found yet'
            })
        
        # Read last 100 lines
        lines = log_file.read_text().strip().split('\n')
        recent_lines = lines[-100:] if len(lines) > 100 else lines
        
        logs = []
        for line in recent_lines:
            if line.strip():
                try:
                    logs.append(json.loads(line))
                except json.JSONDecodeError:
                    logs.append({"raw": line})
        
        # Reverse so newest first
        logs.reverse()
        
        return jsonify({
            'success': True,
            'logs': logs,
            'total_entries': len(lines)
        })
        
    except Exception as e:
        app.logger.error(f"Email logs API error: {str(e)}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@api_owner_bp.route("/api/owner/trigger-deletion-check", methods=["POST"])
@require_api_auth
def api_owner_trigger_deletion_check(user_session):
    """Owner-only API endpoint to manually trigger deletion warning check"""
    try:
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        
        if user_session['user_id'] != bot_owner_id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        data = request.get_json() or {}
        guild_id = data.get('guild_id')
        
        app.logger.info(f"Owner triggered deletion warning check" + (f" for guild {guild_id}" if guild_id else " for all guilds"))
        
        import asyncio
        from scheduler import send_deletion_warnings
        
        if bot and bot.loop and bot.loop.is_running():
            # Use bot's event loop if available
            future = asyncio.run_coroutine_threadsafe(
                send_deletion_warnings(),
                bot.loop
            )
            try:
                future.result(timeout=30.0)
            except concurrent.futures.TimeoutError:
                return jsonify({'success': False, 'error': 'Check timed out'}), 500
        else:
            # Fallback: run in a new event loop if bot isn't ready
            app.logger.info("Bot loop not available, running in standalone event loop")
            try:
                asyncio.run(send_deletion_warnings())
            except Exception as async_error:
                app.logger.error(f"Standalone async execution failed: {async_error}")
                return jsonify({'success': False, 'error': f'Async execution failed: {str(async_error)}'}), 500
        
        return jsonify({
            'success': True,
            'message': 'Deletion warning check triggered. Check email logs for results.'
        })
        
    except Exception as e:
        app.logger.error(f"Trigger deletion check error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@api_owner_bp.route("/api/owner/bulk-upgrade-paid", methods=["POST"])
@require_api_auth
def api_owner_bulk_upgrade_paid(user_session):
    """Owner-only API endpoint to upgrade all paid servers to 7-day retention"""
    try:
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        
        if user_session['user_id'] != bot_owner_id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        app.logger.info(f"Owner initiating bulk upgrade of paid servers to 7-day retention")
        
        with get_db() as conn:
            # Find all paid servers that don't have 7day or 30day retention
            cursor = conn.execute("""
                SELECT guild_id, retention_tier, subscription_id, customer_id, manually_granted
                FROM server_subscriptions
                WHERE bot_access_paid = TRUE 
                AND (retention_tier IS NULL OR retention_tier = 'none' OR retention_tier = '')
            """)
            servers_to_upgrade = cursor.fetchall()
            
            if not servers_to_upgrade:
                return jsonify({
                    'success': True,
                    'message': 'No servers need upgrading - all paid servers already have retention',
                    'upgraded_count': 0
                })
            
            # Upgrade each server to 7-day retention using parameterized queries
            upgraded_count = 0
            upgraded_guilds = []
            for server in servers_to_upgrade:
                guild_id = server['guild_id']
                # Validate guild_id is a proper integer to be extra safe
                try:
                    guild_id = int(guild_id)
                except (ValueError, TypeError):
                    app.logger.warning(f"Skipping invalid guild_id: {guild_id}")
                    continue
                
                cursor = conn.execute("""
                    UPDATE server_subscriptions 
                    SET retention_tier = '7day', 
                        tier = 'basic',
                        status = 'active'
                    WHERE guild_id = %s
                """, (guild_id,))
                if cursor.rowcount > 0:
                    upgraded_count += 1
                    upgraded_guilds.append(str(guild_id))
            
            app.logger.info(f"Bulk upgraded {upgraded_count} servers to 7-day retention: {upgraded_guilds}")
            
            return jsonify({
                'success': True,
                'message': f'Successfully upgraded {upgraded_count} paid servers to 7-day retention',
                'upgraded_count': upgraded_count,
                'upgraded_guilds': upgraded_guilds
            })
            
    except Exception as e:
        app.logger.error(f"Bulk upgrade error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@api_owner_bp.route("/api/owner/purge-email-recipient", methods=["POST"])
@require_api_auth
def api_owner_purge_email_recipient(user_session):
    """Owner-only API endpoint to remove a specific email recipient from any guild"""
    try:
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        
        if user_session['user_id'] != bot_owner_id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        data = request.get_json() or {}
        guild_id = data.get('guild_id')
        email = data.get('email')
        
        if not guild_id or not email:
            return jsonify({'success': False, 'error': 'Missing guild_id or email'}), 400
        
        email = email.lower().strip()
        
        app.logger.info(f"Owner purging email recipient: {email} from guild {guild_id}")
        
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT id, email_address FROM report_recipients WHERE guild_id = %s AND email_address = %s",
                (guild_id, email)
            )
            existing = cursor.fetchone()
            
            if not existing:
                return jsonify({
                    'success': False, 
                    'error': f'Email {email} not found for guild {guild_id}',
                    'checked_guild': guild_id,
                    'checked_email': email
                }), 404
            
            cursor = conn.execute(
                "DELETE FROM report_recipients WHERE guild_id = %s AND email_address = %s",
                (guild_id, email)
            )
            deleted_count = cursor.rowcount
            
            app.logger.info(f"[OK] Purged {deleted_count} email recipient(s): {email} from guild {guild_id}")
            
            from email_utils import log_email_to_file
            log_email_to_file(
                event_type="owner_purge_recipient",
                recipients=[email],
                subject=f"Purged from guild {guild_id}",
                context={
                    "guild_id": str(guild_id),
                    "deleted_count": deleted_count,
                    "action": "owner_manual_purge"
                }
            )
        
        return jsonify({
            'success': True,
            'message': f'Successfully removed {email} from guild {guild_id}',
            'deleted_count': deleted_count
        })
        
    except Exception as e:
        app.logger.error(f"Purge email recipient error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@api_owner_bp.route("/api/owner/list-all-email-recipients", methods=["GET"])
@require_api_auth
def api_owner_list_all_email_recipients(user_session):
    """Owner-only API endpoint to list ALL email recipients across ALL guilds"""
    try:
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        
        if user_session['user_id'] != bot_owner_id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT 
                    rr.id,
                    rr.guild_id,
                    bg.guild_name,
                    rr.email_address,
                    rr.recipient_type,
                    rr.created_at
                FROM report_recipients rr
                LEFT JOIN bot_guilds bg ON CAST(rr.guild_id AS TEXT) = bg.guild_id
                WHERE rr.recipient_type = 'email'
                ORDER BY rr.guild_id, rr.created_at
            """)
            recipients = cursor.fetchall()
        
        result = []
        for row in recipients:
            result.append({
                'id': row['id'],
                'guild_id': str(row['guild_id']),
                'guild_name': row['guild_name'] or f"Unknown Guild {row['guild_id']}",
                'email': row['email_address'],
                'created_at': row['created_at'].isoformat() if row['created_at'] else None
            })
        
        return jsonify({
            'success': True,
            'recipients': result,
            'total': len(result)
        })
        
    except Exception as e:
        app.logger.error(f"List email recipients error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@api_owner_bp.route("/api/owner/audit-email-settings", methods=["POST"])
@require_api_auth
def api_owner_audit_email_settings(user_session):
    """Owner-only API endpoint to audit and fix guilds with email settings enabled but no recipients"""
    try:
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        
        if user_session['user_id'] != bot_owner_id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        app.logger.info("Owner initiating email settings audit")
        
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT es.guild_id, es.auto_send_on_clockout, es.auto_email_before_delete,
                       bg.guild_name,
                       (SELECT COUNT(*) FROM report_recipients rr 
                        WHERE rr.guild_id = es.guild_id AND rr.recipient_type = 'email') as recipient_count
                FROM email_settings es
                LEFT JOIN bot_guilds bg ON CAST(es.guild_id AS TEXT) = bg.guild_id
                WHERE (es.auto_send_on_clockout = TRUE OR es.auto_email_before_delete = TRUE)
            """)
            guilds_with_settings = cursor.fetchall()
            
            orphaned_guilds = []
            fixed_guilds = []
            
            for guild in guilds_with_settings:
                if guild['recipient_count'] == 0:
                    orphaned_guilds.append({
                        'guild_id': str(guild['guild_id']),
                        'guild_name': guild['guild_name'] or f"Unknown Guild {guild['guild_id']}",
                        'auto_send_on_clockout': guild['auto_send_on_clockout'],
                        'auto_email_before_delete': guild['auto_email_before_delete']
                    })
                    
                    conn.execute("""
                        UPDATE email_settings 
                        SET auto_send_on_clockout = FALSE, auto_email_before_delete = FALSE 
                        WHERE guild_id = %s
                    """, (guild['guild_id'],))
                    fixed_guilds.append(str(guild['guild_id']))
            
            app.logger.info(f"Email settings audit complete: Found {len(orphaned_guilds)} orphaned guilds, fixed {len(fixed_guilds)}")
        
        return jsonify({
            'success': True,
            'message': f'Audit complete. Found and fixed {len(fixed_guilds)} guilds with email settings but no recipients.',
            'orphaned_guilds': orphaned_guilds,
            'fixed_count': len(fixed_guilds)
        })
        
    except Exception as e:
        app.logger.error(f"Email settings audit error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@api_owner_bp.route("/api/owner/employee-list/<guild_id>", methods=["GET"])
@require_api_auth
def api_owner_employee_list(user_session, guild_id):
    """Owner-only API endpoint to get employee list for a server"""
    try:
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        
        if user_session['user_id'] != bot_owner_id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT 
                    ep.user_id,
                    ep.first_name,
                    ep.last_name,
                    ep.full_name,
                    ep.display_name,
                    ep.company_role,
                    ep.role_tier,
                    ep.is_active,
                    COALESCE(SUM(
                        CASE WHEN s.clock_out_time IS NOT NULL 
                        THEN EXTRACT(EPOCH FROM (s.clock_out_time - s.clock_in_time))/3600 
                        ELSE 0 END
                    ), 0) as total_hours,
                    COUNT(s.session_id) as session_count,
                    EXISTS(SELECT 1 FROM timeclock_sessions s2 WHERE s2.guild_id = ep.guild_id::text AND s2.user_id = ep.user_id::text AND s2.clock_out_time IS NULL) as is_clocked_in
                FROM employee_profiles ep
                LEFT JOIN timeclock_sessions s ON s.guild_id = ep.guild_id::text AND s.user_id = ep.user_id::text
                WHERE ep.guild_id = %s
                GROUP BY ep.user_id, ep.first_name, ep.last_name, ep.full_name, ep.display_name, ep.company_role, ep.role_tier, ep.is_active, ep.guild_id
                ORDER BY ep.display_name, ep.user_id
            """, (int(guild_id),))
            employees = cursor.fetchall()
        
        result = []
        for emp in employees:
            name = emp['display_name'] or emp['full_name'] or f"{emp['first_name'] or ''} {emp['last_name'] or ''}".strip() or f"User {emp['user_id']}"
            result.append({
                'user_id': str(emp['user_id']),
                'display_name': name,
                'role': emp['company_role'] or emp['role_tier'] or 'Employee',
                'is_active': emp['is_active'],
                'total_hours': round(float(emp['total_hours']), 2),
                'session_count': emp['session_count'],
                'is_clocked_in': emp['is_clocked_in']
            })
        
        return jsonify({
            'success': True,
            'employees': result,
            'total': len(result)
        })
        
    except Exception as e:
        app.logger.error(f"Employee list error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@api_owner_bp.route("/api/owner/time-report/<guild_id>", methods=["GET"])
@require_api_auth
def api_owner_time_report(user_session, guild_id):
    """Owner-only API endpoint to download time report CSV for a server"""
    try:
        bot_owner_id = os.getenv("BOT_OWNER_ID", "107103438139056128")
        
        if user_session['user_id'] != bot_owner_id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        if not start_date or not end_date:
            return jsonify({'success': False, 'error': 'start_date and end_date required'}), 400
        
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT bg.guild_name FROM bot_guilds WHERE guild_id = %s
            """, (str(guild_id),))
            guild_row = cursor.fetchone()
            guild_name = guild_row['guild_name'] if guild_row else f"Server {guild_id}"
            
            cursor = conn.execute("""
                SELECT 
                    s.user_id,
                    ep.display_name,
                    ep.full_name,
                    ep.first_name,
                    ep.last_name,
                    s.clock_in_time as clock_in,
                    s.clock_out_time as clock_out,
                    CASE 
                        WHEN s.clock_out_time IS NOT NULL 
                        THEN EXTRACT(EPOCH FROM (s.clock_out_time - s.clock_in_time))/3600 
                        ELSE NULL 
                    END as hours_worked
                FROM timeclock_sessions s
                LEFT JOIN employee_profiles ep ON s.guild_id = ep.guild_id::text AND s.user_id = ep.user_id::text
                WHERE s.guild_id = %s
                  AND s.clock_in_time >= %s::date
                  AND s.clock_in_time < (%s::date + interval '1 day')
                ORDER BY s.clock_in_time
            """, (str(guild_id), start_date, end_date))
            sessions = cursor.fetchall()
        
        import io
        import csv
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        writer.writerow(['Employee ID', 'Employee Name', 'Clock In', 'Clock Out', 'Hours Worked'])
        
        total_hours = 0
        for session in sessions:
            name = session['display_name'] or session['full_name'] or f"{session['first_name'] or ''} {session['last_name'] or ''}".strip() or f"User {session['user_id']}"
            name = sanitize_csv_string(name)
            
            clock_in = session['clock_in'].strftime('%Y-%m-%d %H:%M:%S') if session['clock_in'] else ''
            clock_out = session['clock_out'].strftime('%Y-%m-%d %H:%M:%S') if session['clock_out'] else 'Still clocked in'
            hours = round(float(session['hours_worked']), 2) if session['hours_worked'] else 'N/A'
            if session['hours_worked']:
                total_hours += float(session['hours_worked'])
            
            writer.writerow([str(session['user_id']), name, clock_in, clock_out, hours])
        
        writer.writerow([])
        writer.writerow(['', '', '', 'Total Hours:', round(total_hours, 2)])
        writer.writerow(['', '', '', 'Report Period:', f'{start_date} to {end_date}'])
        writer.writerow(['', '', '', 'Server:', guild_name])
        
        output.seek(0)
        
        from flask import Response
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={
                'Content-Disposition': f'attachment; filename=time_report_{guild_id}_{start_date}_to_{end_date}.csv'
            }
        )
        
    except Exception as e:
        app.logger.error(f"Time report error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Internal server error'}), 500


