import discord
from discord import app_commands
from discord.ext import commands
from bot_core import (
    db, robust_defer, get_guild_access_info, get_guild_tier_string, user_has_clock_access,
    safe_parse_timestamp, build_timeclock_hub_view, send_reply, get_domain, APP_DOMAIN,
    user_has_admin_access, DEMO_SERVER_ID, send_timeclock_report_email, bot, create_setup_embed
)
import os
from datetime import datetime, timezone
import pytz

class AdminCmds(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
    @app_commands.guild_only()
    async def setup(self, interaction: discord.Interaction):
        """
        Display comprehensive onboarding guide for new users.
        Shows role management, dashboard features, and pricing information.
        """
        # Robust defer with proper fallback
        defer_success = await robust_defer(interaction, ephemeral=True)
        if not defer_success and not interaction.response.is_done():
            return

        guild_id = interaction.guild_id
        if guild_id is None:
            await interaction.edit_original_response(content="âŒ This command must be used in a server.")
            return

        try:
            # Use the same domain detection as other functions
            dashboard_url = f"https://{get_domain()}"
            payment_url = f"https://{get_domain()}/upgrade"

            embed = discord.Embed(
                title="â° Welcome to Time Warden!",
                description="Complete onboarding guide for setting up your timeclock bot",
                color=discord.Color.blue()
            )

            embed.add_field(
                name="ðŸ“š Step 1: Quick Start Wiki",
                value=(
                    f"Read the **[Official Wiki]({dashboard_url}/wiki)** for a step-by-step guide on setting up your server, kiosk mode, and generating reports."
                ),
                inline=False
            )

            embed.add_field(
                name="ðŸŒ Step 2: Dashboard Setup",
                value=(
                    f"Visit **[Your Dashboard]({dashboard_url})** and log in with Discord:\n"
                    "â€¢ **Admin / Employee Roles** - Define who can manage vs clock-in\n"
                    "â€¢ **Timezone** - Set your server's local display time\n"
                    "â€¢ **Email Reports** - Automate PDF timesheets"
                ),
                inline=False
            )

            if guild_id == DEMO_SERVER_ID:
                embed.add_field(
                    name="ðŸš§ Demo Server Notice",
                    value=(
                        "You are currently exploring the **Live Demo**.\n"
                        "â€¢ **PINs:** Kiosk PINs for Demo Employees are auto-generated.\n"
                        "â€¢ **Data:** Dummy data is automatically seeded for testing.\n"
                        "â€¢ **Reset:** Data is pruned periodically."
                    ),
                    inline=False
                )
            else:
                embed.add_field(
                    name="ðŸ’° Step 3: Pricing & Tiers",
                    value=(
                        "**Your server starts with a generous 1-Month Free Trial!**\n\n"
                        "**Premium** - $8/month\n"
                        "â€¢ Full timeclock functionality & 30-day data retention\n\n"
                        "**Pro** - $15/month\n"
                        "â€¢ Premium + Kiosk Mode & Ad-Free Dashboard\n\n"
                        f"ðŸ›’ [Manage Subscription]({payment_url})"
                    ),
                    inline=False
                )

            embed.add_field(
                name="ðŸ†˜ Need Help?",
                value=(
                    "Join our [Support Discord](https://discord.gg/tMGssTjkUt) for help with setup, billing, or custom requests."
                ),
                inline=False
            )

            embed.set_footer(text="Time Warden â€¢ Professional Time Tracking for Discord")

            await interaction.edit_original_response(embed=embed)
            print(f"âœ… Displayed setup information for guild {guild_id}")

        except Exception as e:
            print(f"âŒ Failed to display setup information: {e}")
            await interaction.edit_original_response(
                content="âŒ **Setup Information Error**\n\n"
                       "Could not retrieve setup information.\n"
                       "Please try again or contact support if the issue persists."
            )


    @app_commands.command(name="clock", description="Open your personal timeclock hub")
    @app_commands.context_menu(name="View Hours")
    async def context_view_hours(self, interaction: discord.Interaction, user: discord.Member):
        """Right-click context menu to view a user's hours"""
        await interaction.response.defer(ephemeral=True)

        guild_id = interaction.guild_id
        if not guild_id:
            await interaction.followup.send("âŒ This command must be used in a server.", ephemeral=True)
            return

        access = get_guild_access_info(guild_id)
        if not access['is_exempt'] and access['tier'] == 'free' and not access['trial_active']:
            embed = discord.Embed(
                title="â° Free Trial Expired",
                description="Your 30-day free trial has ended.\nUpgrade to Premium to use this feature!",
                color=discord.Color.red()
            )
            embed.add_field(name="â¬†ï¸ Upgrade", value="Use `/upgrade` or visit your dashboard to subscribe!", inline=False)
            await interaction.followup.send(embed=embed, ephemeral=True)
            return

        # Check if invoker is admin
        if interaction.user and isinstance(interaction.user, discord.Member) and not interaction.user.guild_permissions.administrator:
            await interaction.followup.send("âŒ Only admins can use this.", ephemeral=True)
            return

        # Get user's hours for last 7 days
        with db() as conn:
            cursor = conn.execute("""
                SELECT 
                    SUM(EXTRACT(EPOCH FROM (COALESCE(clock_out_time, NOW()) - clock_in_time))/3600) as total_hours
                FROM timeclock_sessions
                WHERE guild_id = %s AND user_id = %s
                AND clock_in_time > NOW() - INTERVAL '7 days'
            """, (interaction.guild_id, user.id))
            result = cursor.fetchone()
            hours = result['total_hours'] if result and result['total_hours'] else 0

        embed = discord.Embed(
            title=f"ðŸ“Š Hours for {user.display_name}",
            description=f"Last 7 days: **{hours:.1f} hours**",
            color=0xD4AF37
        )

        await interaction.followup.send(embed=embed, ephemeral=True)


    @app_commands.context_menu(name="Force Clock Out")
    async def context_force_clockout(self, interaction: discord.Interaction, user: discord.Member):
        """Right-click context menu to force clock out a user"""
        await interaction.response.defer(ephemeral=True)

        guild_id = interaction.guild_id
        if not guild_id:
            await interaction.followup.send("âŒ This command must be used in a server.", ephemeral=True)
            return

        access = get_guild_access_info(guild_id)
        if not access['is_exempt'] and access['tier'] == 'free' and not access['trial_active']:
            embed = discord.Embed(
                title="â° Free Trial Expired",
                description="Your 30-day free trial has ended.\nUpgrade to Premium to use this feature!",
                color=discord.Color.red()
            )
            embed.add_field(name="â¬†ï¸ Upgrade", value="Use `/upgrade` or visit your dashboard to subscribe!", inline=False)
            await interaction.followup.send(embed=embed, ephemeral=True)
            return

        # Check if invoker is admin
        if interaction.user and isinstance(interaction.user, discord.Member) and not interaction.user.guild_permissions.administrator:
            await interaction.followup.send("âŒ Only admins can use this.", ephemeral=True)
            return

        # Find active session and clock out
        with db() as conn:
            cursor = conn.execute("""
                UPDATE timeclock_sessions 
                SET clock_out_time = NOW()
                WHERE guild_id = %s AND user_id = %s AND clock_out_time IS NULL
                RETURNING session_id
            """, (interaction.guild_id, user.id))
            result = cursor.fetchone()

        if result:
            await interaction.followup.send(f"âœ… Force clocked out {user.display_name}", ephemeral=True)
        else:
            await interaction.followup.send(f"â„¹ï¸ {user.display_name} wasn't clocked in.", ephemeral=True)


    @app_commands.context_menu(name="Ban from Timeclock")
    async def context_ban_user(self, interaction: discord.Interaction, user: discord.Member):
        """Right-click context menu to ban a user from timeclock (24-hour ban)"""
        await interaction.response.defer(ephemeral=True)

        guild_id = interaction.guild_id
        if not guild_id:
            await interaction.followup.send("âŒ This command must be used in a server.", ephemeral=True)
            return

        access = get_guild_access_info(guild_id)
        if not access['is_exempt'] and access['tier'] == 'free' and not access['trial_active']:
            embed = discord.Embed(
                title="â° Free Trial Expired",
                description="Your 30-day free trial has ended.\nUpgrade to Premium to use this feature!",
                color=discord.Color.red()
            )
            embed.add_field(name="â¬†ï¸ Upgrade", value="Use `/upgrade` or visit your dashboard to subscribe!", inline=False)
            await interaction.followup.send(embed=embed, ephemeral=True)
            return

        # Check if invoker is admin
        if interaction.user and isinstance(interaction.user, discord.Member) and not interaction.user.guild_permissions.administrator:
            await interaction.followup.send("âŒ Only admins can use this.", ephemeral=True)
            return

        # Check if user is already banned
        if interaction.guild_id and is_user_banned(interaction.guild_id, user.id):
            await interaction.followup.send(f"â„¹ï¸ {user.display_name} is already banned from the timeclock.", ephemeral=True)
            return

        # Ban user for 24 hours using existing function
        if interaction.guild_id:
            ban_user_24h(interaction.guild_id, user.id, "Banned via admin context menu")
            await interaction.followup.send(f"ðŸš« {user.display_name} has been banned from the timeclock for 24 hours.", ephemeral=True)
        else:
            await interaction.followup.send("âŒ Error: Guild ID not found.", ephemeral=True)


    @app_commands.context_menu(name="View Profile")
    async def context_view_profile(self, interaction: discord.Interaction, user: discord.Member):
        """Right-click context menu to view employee profile in dashboard"""
        await interaction.response.defer(ephemeral=True)

        # Check if invoker is admin or the user themselves
        is_admin = isinstance(interaction.user, discord.Member) and interaction.user.guild_permissions.administrator
        is_self = interaction.user.id == user.id

        if not is_admin and not is_self:
            await interaction.followup.send("âŒ You can only view your own profile or be an admin.", ephemeral=True)
            return

        # Check if user has an employee profile
        from app import get_db
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT user_id FROM employee_profiles
                WHERE guild_id = %s AND user_id = %s AND is_active = TRUE
            """, (interaction.guild_id, user.id))
            profile = cursor.fetchone()

        if not profile:
            await interaction.followup.send(f"â„¹ï¸ {user.display_name} doesn't have an employee profile yet.", ephemeral=True)
            return

        domain = get_domain()
        profile_url = f"https://{domain}/dashboard/server/{interaction.guild_id}/profile/{user.id}"

        embed = discord.Embed(
            title=f"ðŸ“‹ Profile: {user.display_name}",
            description=f"[Click here to view {'your' if is_self else 'their'} profile]({profile_url})",
            color=discord.Color.blue()
        )
        if user.display_avatar:
            embed.set_thumbnail(url=user.display_avatar.url)

        await interaction.followup.send(embed=embed, ephemeral=True)


    @app_commands.context_menu(name="Send Shift Report")
    async def context_send_shift_report(self, interaction: discord.Interaction, user: discord.Member):
        """Right-click context menu to email employee's shift report to configured recipients"""
        await interaction.response.defer(ephemeral=True)

        guild_id = interaction.guild_id
        if not guild_id:
            await interaction.followup.send("âŒ This command must be used in a server.", ephemeral=True)
            return

        access = get_guild_access_info(guild_id)
        if not access['is_exempt'] and access['tier'] == 'free' and not access['trial_active']:
            embed = discord.Embed(
                title="â° Free Trial Expired",
                description="Your 30-day free trial has ended.\nUpgrade to Premium to use this feature!",
                color=discord.Color.red()
            )
            embed.add_field(name="â¬†ï¸ Upgrade", value="Use `/upgrade` or visit your dashboard to subscribe!", inline=False)
            await interaction.followup.send(embed=embed, ephemeral=True)
            return

        if interaction.user and isinstance(interaction.user, discord.Member) and not interaction.user.guild_permissions.administrator:
            await interaction.followup.send("âŒ Only admins can send shift reports.", ephemeral=True)
            return

        guild_id = interaction.guild_id

        # Get verified email recipients
        from app import get_db
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT email FROM email_recipients
                WHERE guild_id = %s AND verified = TRUE
            """, (guild_id,))
            recipients = [row['email'] for row in cursor.fetchall()]

        if not recipients:
            await interaction.followup.send("âŒ No verified email recipients configured. Add emails in Dashboard â†’ Email Settings.", ephemeral=True)
            return

        # Get guild settings for timezone and sessions
        with get_db() as conn:
            tz_cursor = conn.execute("SELECT timezone FROM guild_settings WHERE guild_id = %s", (str(guild_id),))
            tz_row = tz_cursor.fetchone()
            guild_tz = tz_row['timezone'] if tz_row and tz_row.get('timezone') else 'America/Chicago'

async def setup(bot):
    await bot.add_cog(AdminCmds(bot))
