Part 5: Final Verification — Full System Consistency Check
Read GEMINI.md and docs/lessons-learned.md before making any changes.

PREREQUISITE: Parts 1-4 must ALL be completed first.

PURPOSE
This part makes no new features. It is purely a verification and cleanup pass to ensure everything from Parts 1-4 works together correctly and nothing was missed.

CHECK 1: Old Pricing — Must Be Gone Everywhere
Run each of these commands. Every one should return ZERO results related to pricing:

grep -rn "\\$5" --include="*.py" --include="*.html"
grep -rn "one-time" --include="*.py" --include="*.html"
grep -rn "Dashboard Premium" --include="*.py" --include="*.html"
grep -rn "Pro Retention" --include="*.py" --include="*.html"
grep -rn "~~\\$10~~" --include="*.py" --include="*.html"
grep -rn "bot_access" --include="*.py" --include="*.html" | grep -i "purchase\|price\|upgrade\|buy"
If ANY match is found, fix it to use the new pricing:

Premium: $8/month (first month FREE!)
Pro: $15/month — Coming Soon
CHECK 2: New Pricing — Must Be Present
Run these commands. Each should return at least one match:

grep -rn "\\$8" --include="*.py" --include="*.html"
grep -rn "First month FREE" --include="*.py" --include="*.html"
grep -rn "Coming Soon" --include="*.py" --include="*.html"
grep -rn "\\$15" --include="*.py" --include="*.html"
CHECK 3: Trial System — Must Be Wired Up
grep -rn "trial_start_date" --include="*.py"
grep -rn "get_trial_days_remaining" --include="*.py"
grep -rn "is_trial_active" --include="*.py"
grep -rn "is_server_exempt" --include="*.py"
grep -rn "TRIAL_EXPIRED" --include="*.py"
grep -rn "get_guild_access_info" bot.py
grep -rn "get_flask_guild_access" app.py
Each command should return at least one match. If any returns zero, something from Parts 1-3 is missing — go back and fix it.

CHECK 4: Demo Server Exemption
grep -rn "1419894879894507661" --include="*.py"
This should appear in entitlements.py as the DEMO_SERVER_ID constant. Verify that is_server_exempt() uses this constant.

Trace the logic manually:

A request comes in for guild_id 1419894879894507661
get_flask_guild_access(guild_id) is called
is_server_exempt() returns True
The route allows full access
Do the same trace for bot.py:

A /clock command is used in guild 1419894879894507661
get_guild_access_info(guild_id) is called
access['is_exempt'] is True
Clock in/out proceeds normally
CHECK 5: Owner-Granted Server Exemption
Find where owner_grant command stores its grant (search for "owner_grant" in bot.py). Verify that:

The grant sets bot_access_paid=True or grandfathered=True in server_subscriptions
get_flask_guild_access() picks this up and marks is_exempt=True
get_guild_access_info() in bot.py picks this up and marks is_exempt=True
CHECK 6: /help and /upgrade Always Work
Read the /help command in bot.py. Confirm there is NO trial check that blocks it. It should always respond.

Read the /upgrade command and show_upgrade function in bot.py. Confirm there is NO trial check that blocks it. It should always respond.

CHECK 7: Stripe Checkout Flow
Search for Stripe-related code in app.py:

grep -rn "stripe\|checkout\|payment" app.py | head -30
Verify that:

The checkout creates a subscription for $8/month (not a one-time payment)
There is a mechanism for "first month free" (either a Stripe coupon, trial period on the subscription, or similar)
There is NO checkout flow for Pro tier (it should be disabled/coming soon)
If the Stripe integration needs updating for the new pricing, make the changes. If unsure how to implement "first month free" in Stripe, use Stripe's built-in trial_period_days=30 on the subscription.

CHECK 8: No Syntax Errors
Run these commands to verify nothing is broken:

python -c "import entitlements; print('entitlements OK')"
python -c "from app import app; print('app OK')"
python -c "import bot; print('bot OK')"
Fix any import or syntax errors.

CHECK 9: Consistent Tier Naming
Search for inconsistent tier names that might confuse users:

grep -rn "basic" --include="*.py" --include="*.html" | grep -iv "basic_operations\|basic profile\|basic info"
The word "basic" as a tier name should not exist anymore. We only have Free, Premium, and Pro. If any user-facing text says "basic", change it to "Premium".

CHECK 10: Update Documentation
File: docs/lessons-learned.md

Add an entry documenting the full pricing overhaul:

Date of changes
Old model vs new model
Trial system added (30 days)
Demo server and owner-grant exemptions
Files modified: entitlements.py, bot.py, app.py, templates/landing.html
File: replit.md

Update the Quick Reference section:

Change retention info to: "Free (30-day trial, 24h retention), Premium ($8/mo, 30d), Pro ($15/mo, Coming Soon)"
Add note about trial system
Add note about demo server exemption
FINAL STEP
Restart the application and verify:

Landing page loads with new pricing
Bot responds to /help with new tier info
No errors in console logs
If everything passes, the pricing overhaul is complete.