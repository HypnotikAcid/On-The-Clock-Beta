Part 1: Database & Entitlements — Trial System Foundation
Read GEMINI.md and docs/lessons-learned.md before making any changes.

CONTEXT
We are overhauling the free tier. New model:

Free: 30-day trial with full features, then HARD LOCK
Premium: $8/month (first month free). Dashboard, full team, reports, 30-day retention.
Pro: $15/month — show as "Coming Soon" everywhere, disable purchase. Kiosk + ad-free.
Three server types need special handling:

DEMO SERVER (ID: 1419894879894507661) — always full access, never locked
OWNER-GRANTED servers (grandfathered=True or manually granted via owner commands) — always full access
ALL OTHER SERVERS — subject to trial and tier gating
TASK A: Database Migration
File: app.py (search for "Database schema" or "migration" section near the top)

Add two columns to guild_settings table (in the migration/schema check section):

trial_start_date TIMESTAMP DEFAULT NULL
trial_expired BOOLEAN DEFAULT FALSE
Use the same pattern as existing column additions (ALTER TABLE ADD COLUMN IF NOT EXISTS).

TASK B: Set trial_start_date on bot join
File: bot.py

Find the on_guild_join event (search for "on_guild_join" or "guild_join"). When the bot joins a new server, set trial_start_date = NOW() in guild_settings if it's not already set.

Also in the bot startup where it syncs guild data (search for "Updated bot_guilds"), backfill trial_start_date for any existing guilds that don't have one set. Use the current timestamp for backfill — this gives existing servers a fresh 30-day window.

TASK C: Entitlements Helper Functions
File: entitlements.py

Add these methods to the Entitlements class:

DEMO_SERVER_ID = 1419894879894507661
@staticmethod
def is_trial_active(trial_start_date) -> bool:
    """Check if 30-day trial is still active"""
    if trial_start_date is None:
        return True
    from datetime import datetime, timedelta
    return (datetime.now() - trial_start_date.replace(tzinfo=None)) < timedelta(days=30)
@staticmethod
def get_trial_days_remaining(trial_start_date) -> int:
    """Get days remaining in trial, 0 if expired"""
    if trial_start_date is None:
        return 30
    from datetime import datetime
    elapsed = (datetime.now() - trial_start_date.replace(tzinfo=None)).days
    return max(0, 30 - elapsed)
@staticmethod
def is_server_exempt(guild_id: int, grandfathered: bool = False, owner_granted: bool = False) -> bool:
    """Check if server bypasses all trial/tier restrictions"""
    return int(guild_id) == Entitlements.DEMO_SERVER_ID or grandfathered or owner_granted
TASK D: Update Tier Definitions
File: entitlements.py

Update get_locked_message():

Change price to '$8/mo'
Change beta_price to 'First month FREE!'
Change cta to 'Start Free Trial' for non-trial servers, 'Upgrade Now' for expired
Add a new method:

@staticmethod
def get_trial_expired_message() -> dict:
    return {
        'title': 'Free Trial Expired',
        'message': 'Your 30-day free trial has ended. Upgrade to Premium to continue using all features.',
        'price': '$8/mo',
        'offer': 'First month FREE!',
        'cta': 'Upgrade Now'
    }
Add 'dashboard_access' to the premium_features set.

Add 'kiosk' to a new pro_only_features set (only accessible by Pro tier).

Update can_access_feature() to handle:

Pro-only features (kiosk)
Trial expiry check (accept trial_active as optional parameter)
TASK E: Helper in bot.py
File: bot.py

Create a new helper function that wraps get_guild_tier_string() to also return trial info:

def get_guild_access_info(guild_id: int) -> dict:
    """Get complete access info for a guild including tier and trial status"""
    tier = get_guild_tier_string(guild_id)
    # Query guild_settings for trial_start_date
    # Query server_subscriptions for grandfathered/owner_granted
    # Use Entitlements.is_trial_active(), get_trial_days_remaining(), is_server_exempt()
    # Return dict with keys: tier, trial_active, days_remaining, is_exempt
VERIFICATION
After completing all tasks:

grep for "trial_start_date" — should appear in app.py (migration), bot.py (guild join + backfill), entitlements.py (helpers)
grep for "DEMO_SERVER_ID" — should appear in entitlements.py
grep for "is_server_exempt" — should appear in entitlements.py
grep for "get_trial_days_remaining" — should appear in entitlements.py
No syntax errors — run: python -c "import entitlements; print('OK')"
DO NOT
Do NOT modify any routes or templates yet (that's parts 3-4)
Do NOT change any bot command behavior yet (that's part 2)
Do NOT touch landing page (that's part 4)
Only build the foundation in this part
Update docs/lessons-learned.md with what you changed.