Part 4: Landing Page & Templates — Pricing Updates & Messaging
Read GEMINI.md and docs/lessons-learned.md before making any changes.

PREREQUISITE: Parts 1-3 must be completed first.

CONTEXT REMINDER
Premium: $8/month (first month FREE!)
Pro: $15/month — Coming Soon (disabled, not purchasable)
Free: 30-day trial, then locked
All public-facing pages and templates must reflect the new pricing model
Remove ALL references to old pricing ($5 one-time, $10, "Dashboard Premium", "bot access")
TASK A: Landing page pricing section
File: templates/landing.html

Find the pricing section (or the section that describes features/tiers). Update or create a clear tier comparison:

Free Trial:

"30 days of full access — no credit card required"
Clock in/out for your whole team
Web dashboard preview
Sample reports
"Start Free" button linking to /invite
Premium — $8/month:

"First month FREE!"
Full team clock in/out (unlimited employees)
Web dashboard with admin controls
CSV reports and exports
Email report automation
Time adjustment workflows
30-day data retention
"Get Started Free" button linking to /invite (starts trial, upgrades later)
Pro — $15/month:

Show as "Coming Soon" with a visual badge/ribbon
Everything in Premium, plus:
Kiosk mode for shared devices
Ad-free dashboard experience
Priority support
Button should be disabled/grayed out, text says "Coming Soon"
TASK B: Remove old pricing references from landing page
File: templates/landing.html

Search for and remove/replace ALL of these:

"$5" (any reference to $5 pricing)
"$10" or any strikethrough pricing
"one-time" (we no longer have one-time payments)
"Dashboard Premium" (rename to just "Premium")
"bot access" as a product name (it's now "Premium")
"Pro Retention" (rename to just "Pro")
Any "beta" pricing language that conflicts with the new model
Keep the beta notice banner but update it if it mentions old pricing.

TASK C: Landing page CTA buttons
File: templates/landing.html

Update the main call-to-action buttons:

Primary button: "Add to Discord — 30 Days Free" linking to /invite
Secondary: "View Demo" linking to the demo server kiosk or Discord
Support: keep the Discord support link (already updated to new URL)
TASK D: Dashboard templates — pricing references
Search all template files for old pricing references:

grep -rn "\$5\|one-time\|Dashboard Premium\|Pro Retention\|\~\~" templates/
Update every match to use the new naming:

"Dashboard Premium" becomes "Premium"
"Pro Retention" becomes "Pro (Coming Soon)"
"$5 one-time" becomes "$8/month (first month FREE!)"
Any Pro pricing becomes "$15/month — Coming Soon"
TASK E: Purchase/checkout page
Find the dashboard purchase or checkout template/route. This is the page users see when they need to upgrade.

Update it to show:

Premium plan card: $8/month, first month FREE, with working Stripe checkout button
Pro plan card: $15/month, Coming Soon, with disabled button
Feature comparison list
If user is on active trial: "You have X days remaining on your free trial"
If trial expired: "Your trial has expired — upgrade now to restore full access"
Clear, compelling copy explaining value
TASK F: Trial countdown banner for dashboard
If there is a base dashboard template or layout that wraps all dashboard pages, add a trial countdown banner:

For free trial active servers: show a top banner "Free Trial — X days remaining | Upgrade to Premium"
For expired trial: show a prominent red banner "Trial Expired — Upgrade to restore access"
For paid servers: no banner
For exempt servers: no banner
This banner should be driven by the trial_info data from the server API (added in Part 3, Task D).

If there's no easy way to add this in the template layer, add it via JavaScript that checks the server info API response for trial_info.

TASK G: Footer and misc references
File: templates/landing.html and any other templates

Update copyright year if it says 2025 to 2025-2026 or just 2026
Make sure footer links are correct (Support Discord link should be https://discord.gg/tMGssTjkUt)
Remove any outdated beta language that conflicts with the new pricing model
VERIFICATION
After all changes:

grep -rn "$5" templates/ — should find ZERO pricing-related matches
grep -rn "one-time" templates/ — should find ZERO matches
grep -rn "Dashboard Premium" templates/ — should find ZERO matches
grep -rn "Pro Retention" templates/ — should find ZERO matches
grep -rn "$8" templates/ — should find matches in pricing sections
grep -rn "Coming Soon" templates/ — should find matches on Pro tier
grep -rn "First month FREE" templates/ — should find matches
Visually check: the landing page at / should load without errors
DO NOT
Do NOT modify bot.py (that was part 2)
Do NOT modify entitlements.py (that was part 1)
Do NOT modify app.py route logic (that was part 3) — only modify templates
Only modify HTML/CSS/JS template files in this part
Update docs/lessons-learned.md with what you changed.