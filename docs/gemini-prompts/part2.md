Part 2: Bot Commands — Trial Enforcement & Pricing Updates
Read GEMINI.md and docs/lessons-learned.md before making any changes.

PREREQUISITE: Part 1 must be completed first (trial system in entitlements.py, get_guild_access_info in bot.py, database migration in app.py).

CONTEXT REMINDER
Free: 30-day trial, then HARD LOCK (only /help and /upgrade work)
Premium: $8/month (first month free)
Pro: $15/month — "Coming Soon" everywhere
Demo server (1419894879894507661) and owner-granted servers: ALWAYS full access
Use get_guild_access_info() from Part 1 to check tier + trial status
TASK A: /clock command — Trial enforcement
File: bot.py (search for the /clock command, around line 4920-4960)

Before allowing clock in/out, use get_guild_access_info():

access = get_guild_access_info(guild_id)
if access['is_exempt']:
    pass  # always allow
elif access['tier'] != 'free':
    pass  # paid, always allow
elif not access['trial_active']:
    # HARD BLOCK
    embed = discord.Embed(
        title="⏰ Free Trial Expired",
        description="Your 30-day free trial has ended.\nUpgrade to Premium to continue using the timeclock!",
        color=discord.Color.red()
    )
    embed.add_field(name="💎 Premium", value="$8/month (first month FREE!)\n✅ Full team clock in/out\n✅ Dashboard & reports\n✅ 30-day data retention", inline=False)
    embed.add_field(name="🚀 Pro", value="$15/month — Coming Soon!\n✅ Everything in Premium\n✅ Kiosk mode\n✅ Ad-free dashboard", inline=False)
    embed.add_field(name="⬆️ Upgrade", value="Use `/upgrade` or visit your dashboard to subscribe!", inline=False)
    await interaction.followup.send(embed=embed, ephemeral=True)
    return
Add graduated trial messaging AFTER successful clock in/out (append to the response):

if access['tier'] == 'free' and access['trial_active'] and not access['is_exempt']:
    days = access['days_remaining']
    if days <= 3:
        # append to response
        trial_msg = f"\n\n🚨 **Trial expires in {days} day{'s' if days != 1 else ''}!** Your team will lose clock access. Use `/upgrade` now!"
    elif days <= 7:
        trial_msg = f"\n\n⚠️ **{days} days left** on your free trial. Use `/upgrade` to keep access!"
    elif days <= 10:
        trial_msg = f"\n\n💡 {days} days left on your free trial."
    else:
        trial_msg = ""
TASK B: Reports button — Trial enforcement
File: bot.py (search for "Free tier: Admin only + fake data" around line 3186)

Replace the existing free tier check. Instead of checking server_tier == "free", use get_guild_access_info():

If exempt: allow full reports
If paid tier: allow full reports
If free + trial active: show sample data WITH trial countdown
If free + trial expired: BLOCK with upgrade embed (same style as Task A)
TASK C: /help command — Always works, show trial status
File: bot.py (search for the help command)

/help must ALWAYS work regardless of tier or trial. Update it to:

Show current tier and trial status in the embed footer or a field
If trial active: "🆓 Free Trial — X days remaining"
If trial expired: "⚠️ Trial Expired — Use /upgrade to continue"
If paid: "💎 Premium Plan Active" or "💜 Pro Plan Active"
If exempt: "⭐ Full Access"
Update the tier features description in /help:

Free Trial: "30-day full access trial"
Premium: "$8/month (first month FREE!) — Full team access, dashboard, reports, 30-day retention"
Pro: "$15/month — Coming Soon! Kiosk mode + ad-free dashboard"
Remove any old pricing references ($5 one-time, $10, etc.)

TASK D: /upgrade command and upgrade buttons — New pricing
File: bot.py (search for "show_upgrade" and "upgrade" button handlers)

Update ALL upgrade messaging:

Premium: "$8/month (first month FREE!)"
Pro: "$15/month — Coming Soon" with no functional purchase button
Remove ALL references to "$5 one-time", "$10 $5", "Dashboard Premium", "bot access"
Use consistent language: "Premium" (not "Dashboard Premium" or "Basic")
The upgrade embed should look like:

embed = discord.Embed(
    title="⬆️ Upgrade Your Server",
    description="Unlock the full power of Time Warden!",
    color=discord.Color.gold()
)
embed.add_field(
    name="💎 Premium — $8/month",
    value="First month FREE!\n✅ Full team clock in/out\n✅ Web dashboard access\n✅ CSV reports & exports\n✅ 30-day data retention\n✅ Email reports\n✅ Time adjustments",
    inline=False
)
embed.add_field(
    name="🚀 Pro — $15/month (Coming Soon!)",
    value="Everything in Premium, plus:\n✅ Kiosk mode for shared devices\n✅ Ad-free dashboard\n✅ Priority support",
    inline=False
)
TASK E: TimeclockHubView — Update persistent buttons
File: bot.py (search for "TimeclockHubView")

Update the upgrade button label to "⬆️ Upgrade — First Month Free!"
When the hub embed is generated, if server is free trial with < 10 days remaining, add a field showing trial countdown
If trial expired, add a prominent "Trial Expired" field with upgrade CTA
TASK F: Welcome/setup DM — Mention trial
File: bot.py (search for welcome DM or setup message sent to new servers)

Update the welcome message to clearly state:

"Welcome! You have a 30-day free trial with full access."
"After your trial, upgrade to Premium ($8/month, first month FREE) to continue."
Remove old pricing references
TASK G: View Hours context menu and other commands
File: bot.py (search for "View Hours", "Force Clock Out", "Ban from Timeclock", "Send Shift Report")

All context menu commands and any remaining slash commands should check get_guild_access_info() and:

If exempt: allow
If paid: allow
If free + trial active: allow
If free + trial expired: block with upgrade embed
VERIFICATION
After all changes:

Search for old pricing: grep -n "\$5" bot.py — should find ZERO matches related to pricing
Search for old terms: grep -n "Dashboard Premium" bot.py — should find ZERO matches
Search for trial checks: grep -n "get_guild_access_info" bot.py — should appear in /clock, reports, /help, /upgrade, context menus
Verify /help has no trial block: read the help command and confirm it always responds
Verify /upgrade has no trial block: read the upgrade command and confirm it always responds
Run: python -c "import bot" — no syntax errors
DO NOT
Do NOT modify app.py routes or templates (that's parts 3-4)
Do NOT change the landing page (that's part 4)
Do NOT modify database schema (that was part 1)
Only modify bot.py in this part
Update docs/lessons-learned.md with what you changed.