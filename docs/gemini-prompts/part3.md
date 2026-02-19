Part 3: Dashboard Gating — Free/Expired Server Lockdown
Read GEMINI.md and docs/lessons-learned.md before making any changes.

PREREQUISITE: Parts 1 and 2 must be completed first.

CONTEXT REMINDER
Free trial expired servers should see a limited dashboard with upgrade prompts
Paid servers get full dashboard access
Demo server (1419894879894507661) and owner-granted servers always get full access
Premium servers see ads on dashboard (ad removal is a Pro feature for later)
TASK A: Create a trial/tier check helper for Flask routes
File: app.py

Create a helper function that Flask routes can call to check guild access:

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
TASK B: Gate dashboard API routes
File: app.py

Find all routes that use @require_api_auth (NOT @require_paid_api_access). These are currently accessible by free servers.

For each of these routes that serves employee data, calendar, profiles, reports, or settings — add a trial/tier check at the top of the function body:

access = get_flask_guild_access(guild_id)
if not access['is_exempt'] and access['tier'] == 'free' and not access['trial_active']:
    return jsonify({
        'success': False,
        'error': 'Your free trial has expired. Upgrade to Premium to continue.',
        'code': 'TRIAL_EXPIRED',
        'upgrade_url': f'/dashboard/purchase?guild_id={guild_id}',
        'trial_expired': True
    }), 403
Routes that should ALWAYS work (do NOT add trial check):

Auth routes (/auth/login, /auth/callback, etc.)
Server selection (/api/servers, /api/user)
Purchase/upgrade pages (/dashboard/purchase, /api/checkout)
Health check (/health)
Landing page (/)
Kiosk routes (already gated by @require_kiosk_access)
Routes that SHOULD be gated (add trial check):

/api/server/{guild_id}/employees
/api/server/{guild_id}/calendar
/api/server/{guild_id}/employee/{user_id}/profile
/api/server/{guild_id}/settings
/api/server/{guild_id}/reports
Any other route serving guild-specific employee data
Use your judgment — if a route serves data that a paying customer expects, gate it.

TASK C: Dashboard page-level gating
File: app.py

For the main dashboard page routes that use @require_paid_access (the HTML-serving routes, not API routes):

These already require paid access which is good. But for routes using just @require_api_auth that serve HTML pages (like the employee profile page at /dashboard/server/{guild_id}/profile/{user_id}):

Add a check: if free + trial expired + not exempt, redirect to a purchase/upgrade page instead of showing the content.

TASK D: Trial status in dashboard API responses
File: app.py

For the server info/overview API endpoint (search for routes that return server details to the frontend), include trial information in the response:

# Add to the response data:
'trial_info': {
    'is_trial': access['tier'] == 'free',
    'trial_active': access['trial_active'],
    'days_remaining': access['days_remaining'],
    'is_exempt': access['is_exempt']
}
This allows the frontend to show trial countdown banners and upgrade prompts.

TASK E: Demo server bypass verification
File: app.py

Search for the demo server ID (1419894879894507661) and make sure:

The kiosk route for demo server works (it should since demo is owner-granted)
All dashboard routes work for demo server
No trial checks block the demo server
If get_flask_guild_access() correctly checks is_server_exempt, this should be automatic. But verify by reading through the kiosk access decorator (@require_kiosk_access) and confirming demo server passes.

TASK F: Upgrade page content
File: app.py and relevant templates

Find the purchase/upgrade dashboard page. Make sure it shows:

Premium: $8/month (first month FREE!)
Pro: $15/month — Coming Soon (disabled button, grayed out)
Clear feature comparison
If trial is active: "You have X days left on your free trial"
If trial expired: "Your trial has expired — upgrade now to restore access"
VERIFICATION
After all changes:

grep -n "get_flask_guild_access" app.py — should appear in multiple route functions
grep -n "TRIAL_EXPIRED" app.py — should appear in gated routes
grep -n "is_exempt" app.py — should appear in the helper and route checks
Verify no syntax errors: python -c "from app import app; print('OK')"
Verify demo server ID (1419894879894507661) would pass is_server_exempt check
DO NOT
Do NOT modify bot.py (that was part 2)
Do NOT modify the landing page HTML (that's part 4)
Do NOT modify entitlements.py (that was part 1)
Only modify app.py and dashboard templates in this part
Update docs/lessons-learned.md with what you changed.