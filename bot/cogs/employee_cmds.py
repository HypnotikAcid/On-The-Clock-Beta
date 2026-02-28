import discord
from discord import app_commands
from discord.ext import commands
from bot_core import (
    db, robust_defer, get_guild_access_info, get_guild_tier_string, user_has_clock_access,
    safe_parse_timestamp, build_timeclock_hub_view, send_reply, get_domain, APP_DOMAIN,
    handle_my_data_command, parse_timezone, register_discord_user_timezone, bot
)
import os
from datetime import datetime, timezone
import pytz

class EmployeeCmds(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
    @app_commands.guild_only()
    async def clock_command(self, interaction: discord.Interaction):
        """
        Personal timeclock hub command with bulletproof button persistence.

        Uses the TimeclockHubView with stable custom_ids and fast ACK
        for maximum reliability across bot restarts.

        Buttons: Clock In, Clock Out, My Adjustments, My Hours, Support, Upgrade
        """
        # ACK immediately - fast response is critical
        if not await robust_defer(interaction, ephemeral=True):
            return

        guild_id = interaction.guild_id
        if guild_id is None:
            await interaction.followup.send("âŒ This command must be used in a server.", ephemeral=True)
            return

        access = get_guild_access_info(guild_id)
        if not access['is_exempt'] and access['tier'] == 'free' and not access['trial_active']:
            embed = discord.Embed(
                title="â° Free Trial Expired",
                description="Your 30-day free trial has ended.\nUpgrade to Premium to continue using the timeclock!",
                color=discord.Color.red()
            )
            embed.add_field(name="ðŸ’Ž Premium", value="$8/month (first month FREE!)\nâœ… Full team clock in/out\nâœ… Dashboard & reports\nâœ… 30-day data retention", inline=False)
            embed.add_field(name="ðŸš€ Pro", value="$15/month â€” Coming Soon!\nâœ… Everything in Premium\nâœ… Kiosk mode\nâœ… Ad-free dashboard", inline=False)
            embed.add_field(name="â¬†ï¸ Upgrade", value="Use `/upgrade` or visit your dashboard to subscribe!", inline=False)
            await interaction.followup.send(embed=embed, ephemeral=True)
            return

        # Check Kiosk Only Mode
        try:
            with db() as conn:
                cursor = conn.execute("SELECT kiosk_only_mode FROM guild_settings WHERE guild_id = %s", (guild_id,))
                settings = cursor.fetchone()

            if settings and settings.get('kiosk_only_mode'):
                await interaction.followup.send(
                    "ðŸ–¥ï¸ **Kiosk Only Mode Active**\n\n"
                    "Discord clocking is disabled for this server.\n"
                    f"Please manage your time physically at the terminal: `https://time-warden.com/kiosk/{guild_id}`",
                    ephemeral=True
                )
                return
        except Exception as e:
            print(f"Error checking kiosk mode: {e}")

        # Check permissions
        server_tier = get_guild_tier_string(guild_id)
        if not isinstance(interaction.user, discord.Member):
            await interaction.followup.send("âŒ Unable to verify permissions.", ephemeral=True)
            return

        if not user_has_clock_access(interaction.user, server_tier):
            if server_tier == "free":
                await interaction.followup.send(
                    "âš ï¸ **Free Tier Limitation**\n\n"
                    "Only administrators can use timeclock on the free tier.\n"
                    "Use `/upgrade` to unlock full team access!",
                    ephemeral=True
                )
            else:
                await interaction.followup.send(
                    "âŒ **Access Denied**\n\n"
                    "You need an employee role to use the timeclock.\n"
                    "Ask an administrator to add your role with `/add_employee_role @yourrole`",
                    ephemeral=True
                )
            return

        try:
            user_id = interaction.user.id

            # Check if this is the user's first time using /clock
            is_first_clock_use = False
            with db() as conn:
                cursor = conn.execute(
                    "SELECT first_clock_used FROM employee_profiles WHERE guild_id = %s AND user_id = %s",
                    (guild_id, user_id)
                )
                row = cursor.fetchone()
                if row and not row.get('first_clock_used', True):
                    is_first_clock_use = True
                    # Mark as used
                    conn.execute("""
                        UPDATE employee_profiles 
                        SET first_clock_used = TRUE, first_clock_at = NOW()
                        WHERE guild_id = %s AND user_id = %s
                    """, (guild_id, user_id))

            # Show first-time onboarding guide
            if is_first_clock_use:
                welcome_embed = discord.Embed(
                    title="Welcome to Your Timeclock!",
                    description="This is your personal time management hub. Here's a quick guide:",
                    color=0x57F287
                )
                welcome_embed.add_field(
                    name="How It Works",
                    value=(
                        "**Clock In** - Start tracking your work time\n"
                        "**Clock Out** - End your shift and log your hours\n"
                        "**My Hours** - View your weekly summary\n"
                        "**My Adjustments** - Request time corrections"
                    ),
                    inline=False
                )
                welcome_embed.add_field(
                    name="Tips",
                    value=(
                        "Your timeclock is private - only you see your interface.\n"
                        "Buttons work even if the bot restarts.\n"
                        "Use `/clock` anytime to access your hub."
                    ),
                    inline=False
                )
                welcome_embed.set_footer(text="Click any button below to get started!")

                view = build_timeclock_hub_view(guild_id, welcome_embed)
                await interaction.followup.send(embed=welcome_embed, view=view, ephemeral=True)
                print(f"First-time /clock onboarding sent to {interaction.user} in guild {guild_id}")
                return

            # Get current status
            with db() as conn:
                cursor = conn.execute(
                    "SELECT clock_in_time as clock_in FROM timeclock_sessions WHERE user_id = %s AND guild_id = %s AND clock_out_time IS NULL",
                    (user_id, guild_id)
                )
                active_session = cursor.fetchone()

            # Build status embed
            if active_session:
                clock_in_time = safe_parse_timestamp(active_session['clock_in'])
                if clock_in_time.tzinfo is None:
                    clock_in_time = clock_in_time.replace(tzinfo=timezone.utc)
                elapsed = datetime.now(timezone.utc) - clock_in_time
                hours, remainder = divmod(int(elapsed.total_seconds()), 3600)
                minutes, _ = divmod(remainder, 60)

                embed = discord.Embed(
                    title="â° Timeclock Hub",
                    description="Your personal time management center",
                    color=0x57F287  # Green for clocked in
                )
                embed.add_field(
                    name="ðŸŸ¢ Status: Clocked In",
                    value=f"**Started:** <t:{int(clock_in_time.timestamp())}:f>\n"
                          f"**Elapsed:** {hours}h {minutes}m",
                    inline=False
                )
            else:
                embed = discord.Embed(
                    title="â° Timeclock Hub",
                    description="Your personal time management center",
                    color=0xD4AF37  # Gold
                )
                embed.add_field(
                    name="âšª Status: Not Clocked In",
                    value="Ready to start your shift!",
                    inline=False
                )

            # Get quick stats (last 7 days)
            with db() as conn:
                cursor = conn.execute("""
                    SELECT COALESCE(SUM(
                        EXTRACT(EPOCH FROM (COALESCE(clock_out_time, NOW()) - clock_in_time)) / 3600
                    ), 0) as week_hours
                    FROM timeclock_sessions 
                    WHERE user_id = %s AND guild_id = %s 
                    AND clock_in_time >= NOW() - INTERVAL '7 days'
                """, (user_id, guild_id))
                row = cursor.fetchone()
                week_hours = float(row['week_hours']) if row and row['week_hours'] else 0

            embed.add_field(
                name="ðŸ“Š This Week",
                value=f"**Hours:** {week_hours:.1f}h",
                inline=True
            )

            embed.set_footer(text="Buttons below work even after bot restarts â€¢ On the Clock")

            # Send with bulletproof view
            view = build_timeclock_hub_view(guild_id, embed)
            await interaction.followup.send(embed=embed, view=view, ephemeral=True)
            print(f"âœ… [TC Hub] Sent timeclock hub to {interaction.user} in guild {guild_id}")

        except Exception as e:
            print(f"âŒ [TC Hub] Error creating hub for {interaction.user}: {e}")
            await interaction.followup.send(
                "âŒ **Error**\nCouldn't load timeclock hub. Please try again.",
                ephemeral=True
            )


    # REMOVED: Settings commands moved to dashboard
    # /set_recipient, /set_timezone, /toggle_name_display, /mobile
    # These features are now available in the dashboard under Timezone Settings



    # REMOVED: Role management commands moved to dashboard
    # /add_admin_role, /remove_admin_role, /list_admin_roles
    # /set_main_role, /show_main_role, /clear_main_role
    # /add_employee_role, /remove_employee_role, /list_employee_roles
    # These features are now available in the Dashboard under Admin Roles and Employee Roles


    @app_commands.command(name="upgrade", description="View subscription plans and upgrade your server")
    @app_commands.guild_only()
    async def help_command(self, interaction: discord.Interaction):
        if interaction.guild_id is None:
            await send_reply(interaction, "âŒ This command must be used in a server.", ephemeral=True)
            return

        guild_id = interaction.guild_id
        access = get_guild_access_info(guild_id)

        tier_display = ""
        tier_color = discord.Color.greyple()
        footer_text = ""

        if access['is_exempt']:
            tier_display = "â­ Full Access"
            tier_color = discord.Color.gold()
            footer_text = "â­ Full Access"
        elif access['tier'] == 'pro':
            tier_display = "ðŸš€ PRO PLAN"
            tier_color = discord.Color.purple()
            footer_text = "ðŸš€ Pro Plan Active"
        elif access['tier'] == 'premium':
            tier_display = "ðŸ’Ž PREMIUM PLAN"
            tier_color = discord.Color.blue()
            footer_text = "ðŸ’Ž Premium Plan Active"
        elif access['trial_active']:
            tier_display = "ðŸ†“ FREE TRIAL"
            tier_color = discord.Color.green()
            days = access['days_remaining']
            footer_text = f"ðŸ†“ Free Trial - {days} day{'s' if days != 1 else ''} remaining"
        else:
            tier_display = "âš ï¸ TRIAL EXPIRED"
            tier_color = discord.Color.red()
            footer_text = "âš ï¸ Trial Expired â€” Use /upgrade to continue"

        embed = discord.Embed(
            title="â° On the Clock - Help",
            description=f"**Your Server:** {tier_display}\n\nSimple time tracking for your team, right in Discord.",
            color=tier_color
        )

        embed.add_field(
            name="ðŸ“± Discord Commands",
            value=(
                "`/clock` - Open your timeclock (clock in/out, view hours)\n"
                "`/setup` - View setup instructions\n"
                "`/help` - This help menu"
            ),
            inline=False
        )

        embed.add_field(
            name="ðŸ–±ï¸ Right-Click Actions (Admins)",
            value=(
                "Right-click any user â†’ Apps:\n"
                "â€¢ **View Hours** - See employee's weekly hours\n"
                "â€¢ **View Profile** - Open employee's dashboard profile\n"
                "â€¢ **Send Shift Report** - Email shift report to recipients\n"
                "â€¢ **Force Clock Out** - Clock out an employee\n"
                "â€¢ **Ban from Timeclock** - Temporarily block access"
            ),
            inline=False
        )

        embed.add_field(
            name="ðŸŒ Dashboard Features",
            value=(
                "**[time-warden.com/dashboard](https://time-warden.com/dashboard)**\n\n"
                "â€¢ **Role Management** - Set admin & employee roles\n"
                "â€¢ **Team Management** - Manage your team\n"
                "â€¢ **Time Adjustments** - Review & approve corrections\n"
                "â€¢ ðŸ’Ž **Reports** - Export CSV timesheets\n"
                "â€¢ ðŸ’Ž **Email Automation** - Daily reports & reminders\n"
                "â€¢ ðŸš€ **Kiosk Mode** - Shared device clock-in\n"
                "â€¢ **Calendar View** - Edit time entries"
            ),
            inline=False
        )

        if not access['is_exempt'] and access['tier'] == 'free':
            embed.add_field(
                name="â¬†ï¸ Upgrade to Premium",
                value=(
                    "**Free Trial:** 30-day full access trial\n"
                    "**Premium ($8/month, first month FREE!):** Full team access, dashboard, reports, 30-day retention\n"
                    "**Pro ($15/month â€” Coming Soon!):** Kiosk mode + ad-free dashboard\n\n"
                    "ðŸ‘‰ Visit the dashboard to upgrade!"
                ),
                inline=False
            )
        else:
            embed.add_field(
                name="âœ… Premium Active",
                value="You have full access to all dashboard features!",
                inline=False
            )

        embed.set_footer(text=footer_text)

        await send_reply(interaction, embed=embed, ephemeral=True)

    # =============================================================================
    # PHASE 5: FEEDBACK FUNNEL
    # =============================================================================
    class FeedbackModal(discord.ui.Modal, title="Submit Feedback"):
        feedback = discord.ui.TextInput(
            label="Your Feedback / Bug Report",
            style=discord.TextStyle.paragraph,
            placeholder="Tell us what you love, what needs fixing, or feature requests...",
            required=True,
            max_length=2000
        )

        async def on_submit(self, interaction: discord.Interaction):
            await send_reply(interaction, "âœ… Thank you! Your feedback has been sent directly to our development team.", ephemeral=True)

            webhook_url = os.environ.get('DEVELOPER_WEBHOOK_URL')
            if not webhook_url:
                print("âš ï¸ DEVELOPER_WEBHOOK_URL not configured. Feedback suppressed.")
                return

            embed = discord.Embed(
                title="New User Feedback submitted!",
                description=self.feedback.value,
                color=discord.Color.gold(),
                timestamp=discord.utils.utcnow()
            )
            embed.set_author(name=f"{interaction.user} ({interaction.user.id})", icon_url=interaction.user.display_avatar.url if interaction.user.display_avatar else None)

            if interaction.guild:
                embed.set_footer(text=f"Server: {interaction.guild.name} ({interaction.guild.id})")
            else:
                embed.set_footer(text="Sent via DM")

            def send_webhook():
                try:
                    import requests
                    requests.post(webhook_url, json={"embeds": [embed.to_dict()]}, timeout=5)
                except Exception as e:
                    print(f"âŒ Failed to send feedback webhook: {e}")

            import threading
            t = threading.Thread(target=send_webhook)
            t.daemon = True
            t.start()

            await interaction.response.send_message(
                "ðŸ—„ï¸ **Your Data Summary:**\n"
                "We store your Discord ID, Username, configured Timezone, and Clock-In timestamps required for payroll generation.\n"
                "To request a full JSON export, please email privacy@ontheclock.bot.",
                ephemeral=True
            )
            return

        elif action.value == "delete":
            try:
                with get_db() as conn:
                    # Scramble profile, delete pins, and drop active sessions
                    conn.execute("""
                        UPDATE employee_profiles 
                        SET first_name = 'Deleted', 
                            last_name = 'User', 
                            email = NULL,
                            timesheet_email = NULL,
                            phone = NULL,
                            is_active = FALSE
                        WHERE user_id = %s
                    """, (user_id,))

                    conn.execute("DELETE FROM employee_pins WHERE user_id = %s", (user_id,))
                    conn.execute("DELETE FROM timeclock_sessions WHERE user_id = %s", (user_id,))

                    await interaction.response.send_message(
                        "âš ï¸ **DATA ERASED**\n"
                        "Your personal information (Name, Email, Phone, PINs, and Time Logs) has been wiped from this server's database.\n"
                        "You will no longer appear on payroll exports.", 
                        ephemeral=True
                    )
            except Exception as e:
                await interaction.response.send_message("âŒ Database error during data removal request.", ephemeral=True)



    @app_commands.command(name="timezone", description="Set your personal dashboard and reporting timezone")
    async def timezone_command(self, interaction: discord.Interaction, tz_string: str):
        """Allow employees to set their personal timezone"""
        import pytz
        if tz_string not in pytz.all_timezones:
            await interaction.response.send_message(
                f"âŒ Invalid timezone: `{tz_string}`.\n"
                "Example valid formats: `America/New_York`, `America/Los_Angeles`, `Europe/London`.", 
                ephemeral=True
            )
            return

        try:
            with get_db() as conn:
                conn.execute("""
                    INSERT INTO user_preferences (user_id, dashboard_timezone, timezone_configured)
                    VALUES (%s, %s, TRUE)
                    ON CONFLICT (user_id) DO UPDATE SET 
                    dashboard_timezone = EXCLUDED.dashboard_timezone,
                    timezone_configured = TRUE
                """, (str(interaction.user.id), tz_string))

                await interaction.response.send_message(f"âœ… Your personal timezone is now locked to **{tz_string}**.", ephemeral=True)
        except Exception as e:
            await interaction.response.send_message("âŒ Failed to save timezone preference.", ephemeral=True)



async def setup(bot):
    await bot.add_cog(EmployeeCmds(bot))
    @app_commands.command(name="my_data", description="[PRIVACY] View or delete your personal data (GDPR/CCPA Compliance)")
    @app_commands.choices(action=[
        app_commands.Choice(name="View My Data", value="view"),
        app_commands.Choice(name="Delete My Data (Irreversible)", value="delete")
    ])
    async def my_data_command(self, interaction: discord.Interaction, action: app_commands.Choice[str]):
        """Allow users to view or wipe their dataset from our servers."""
        user_id = str(interaction.user.id)
        guild_id = str(interaction.guild_id)
        
        if action.value == "view":
            await interaction.response.send_message(
                "🗄️ **Your Data Summary:**\n"
                "We store your Discord ID, Username, configured Timezone, and Clock-In timestamps required for payroll generation.\n"
                "To request a full JSON export, please email privacy@ontheclock.bot.",
                ephemeral=True
            )
            return
            
        elif action.value == "delete":
            try:
                with db() as conn:
                    # Scramble profile, delete pins, and drop active sessions
                    conn.execute("""
                        UPDATE employee_profiles 
                        SET first_name = 'Deleted', 
                            last_name = 'User', 
                            email = NULL,
                            timesheet_email = NULL,
                            phone = NULL,
                            is_active = FALSE
                        WHERE user_id = %s
                    """, (user_id,))
                    
                    conn.execute("DELETE FROM employee_pins WHERE user_id = %s", (user_id,))
                    conn.execute("DELETE FROM timeclock_sessions WHERE user_id = %s", (user_id,))
                    
                    await interaction.response.send_message(
                        "⚠️ **DATA ERASED**\n"
                        "Your personal information (Name, Email, Phone, PINs, and Time Logs) has been wiped from this server's database.\n"
                        "You will no longer appear on payroll exports.", 
                        ephemeral=True
                    )
            except Exception as e:
                await interaction.response.send_message("❌ Database error during data removal request.", ephemeral=True)

    @app_commands.command(name="timezone", description="Set your personal dashboard and reporting timezone")
    async def timezone_command(self, interaction: discord.Interaction, tz_string: str):
        """Allow employees to set their personal timezone"""
        import pytz
        if tz_string not in pytz.all_timezones:
            await interaction.response.send_message(
                f"❌ Invalid timezone: `{tz_string}`.\n"
                "Example valid formats: `America/New_York`, `America/Los_Angeles`, `Europe/London`.", 
                ephemeral=True
            )
            return
            
        try:
            with db() as conn:
                conn.execute("""
                    INSERT INTO user_preferences (user_id, dashboard_timezone, timezone_configured)
                    VALUES (%s, %s, TRUE)
                    ON CONFLICT (user_id) DO UPDATE SET 
                    dashboard_timezone = EXCLUDED.dashboard_timezone,
                    timezone_configured = TRUE
                """, (str(interaction.user.id), tz_string))
                
                await interaction.response.send_message(f"✅ Your personal timezone is now locked to **{tz_string}**.", ephemeral=True)
        except Exception as e:
            await interaction.response.send_message("❌ Failed to save timezone preference.", ephemeral=True)

async def setup(bot):
    await bot.add_cog(EmployeeCmds(bot))
