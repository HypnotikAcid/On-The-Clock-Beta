import discord
from discord import app_commands
from discord.ext import commands
from bot_core import (
    db, robust_defer, get_guild_access_info, get_guild_tier_string, user_has_clock_access,
    safe_parse_timestamp, build_timeclock_hub_view, send_reply, get_domain,
    user_has_admin_access, DEMO_SERVER_ID, send_timeclock_report_email, bot, 
    BOT_OWNER_ID, create_setup_embed, DemoRoleSwitcherView
)
import os
from datetime import datetime, timezone

class OwnerCmds(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        
    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != BOT_OWNER_ID:
            await interaction.response.send_message("❌ This command is restricted to the bot developer.", ephemeral=True)
            return False
        return True
    @app_commands.guild_only()
    async def setup_demo_roles_command(self, interaction: discord.Interaction):
        """
        Posts a persistent message with buttons for users to switch between Admin and Employee roles.
        Only works on the demo server. Admins use this to set up the role switcher.
        """
        if interaction.user.id != interaction.guild.owner_id and interaction.user.id != BOT_OWNER_ID:
            await interaction.response.send_message("âŒ This command is strictly locked to the Server Owner.", ephemeral=True)
            return
        import time
        execution_id = f"{interaction.user.id}-{int(time.time() * 1000)}"
        print(f"ðŸŽ­ [SETUP_DEMO_ROLES] Execution ID: {execution_id} - Command invoked by {interaction.user} in guild {interaction.guild_id}")

        # Verify this is the demo server
        if interaction.guild_id != DEMO_SERVER_ID:
            await send_reply(
                interaction,
                "âŒ This command only works on the demo server.",
                ephemeral=True
            )
            return

        await robust_defer(interaction, ephemeral=True)

        # Deduplication check - prevent duplicate execution within 2-second window
        call_key = (interaction.guild_id, interaction.user.id)
        current_time = time.time()

        if call_key in _setup_demo_roles_recent_calls:
            last_call = _setup_demo_roles_recent_calls[call_key]
            if current_time - last_call < 2.0:
                print(f"ðŸŽ­ [SETUP_DEMO_ROLES] {execution_id} - Duplicate call detected (last call {current_time - last_call:.2f}s ago) - ignoring")
                await send_reply(interaction, "â³ Please wait - already processing your request.", ephemeral=True)
                return

        # Record this call
        _setup_demo_roles_recent_calls[call_key] = current_time

        # Clean up old entries (older than 10 seconds)
        for k, v in list(_setup_demo_roles_recent_calls.items()):
            if current_time - v >= 10.0:
                del _setup_demo_roles_recent_calls[k]

        try:
            # Create the embed
            embed = discord.Embed(
                title="ðŸŽ­ Choose Your Role",
                description=(
                    "Welcome to the Time Warden demo! Choose how you'd like to experience our timeclock system.\n\n"
                    "You can switch between roles at any time by clicking the buttons below."
                ),
                color=0x00FFFF  # Cyan
            )

            embed.add_field(
                name="ðŸ‘‘ Admin Mode",
                value=(
                    "Experience the Dashboard as a **Manager**.\n"
                    "â€¢ Approve timesheets and view reports\n"
                    "â€¢ Configure settings and manage roles\n"
                    "â€¢ Access all administrative features"
                ),
                inline=False
            )

            embed.add_field(
                name="ðŸ‘· Employee Mode",
                value=(
                    "Experience the Dashboard as **Staff**.\n"
                    "â€¢ Clock in/out from Discord or Dashboard\n"
                    "â€¢ View your own timesheet history\n"
                    "â€¢ Request time adjustments"
                ),
                inline=False
            )

            embed.set_footer(text="ðŸ’¡ Both roles are safe for testing - choose what you want to explore!")

            # Create the view with buttons
            view = DemoRoleSwitcherView()

            # Send the message
            print(f"ðŸŽ­ [SETUP_DEMO_ROLES] {execution_id} - Sending embed to channel {interaction.channel.id}")
            message = await interaction.channel.send(embed=embed, view=view)
            print(f"ðŸŽ­ [SETUP_DEMO_ROLES] {execution_id} - Message sent successfully with ID {message.id}")

            await send_reply(
                interaction,
                "âœ… Demo role switcher posted! Users can now choose their role.",
                ephemeral=True
            )
            print(f"ðŸŽ­ [SETUP_DEMO_ROLES] {execution_id} - Command completed successfully")

        except Exception as e:
            print(f"âŒ [SETUP_DEMO_ROLES] {execution_id} - Error: {e}")
            await send_reply(
                interaction,
                "âŒ Failed to post role switcher. Please try again.",
                ephemeral=True
            )


    @app_commands.command(name="owner_broadcast", description="[OWNER] Send announcement to all servers")
    @app_commands.describe(
        title="Title of the broadcast message",
        message="The message content to send",
        target="Which servers to send to"
    )
    @app_commands.choices(target=[
        app_commands.Choice(name="All Servers", value="all"),
        app_commands.Choice(name="Paid Servers Only", value="paid"),
        app_commands.Choice(name="Free Tier Only", value="free")
    ])
    async def owner_broadcast_command(self, interaction: discord.Interaction, title: str, message: str, target: str = "all"):
        """Owner-only command to broadcast messages to all servers"""
        if interaction.user.id != BOT_OWNER_ID:
            await send_reply(interaction, "âŒ Access denied.", ephemeral=True)
            return

        await interaction.response.defer(ephemeral=True)

        try:
            # Get guild IDs based on target
            # Note: bot_guilds.guild_id is TEXT, server_subscriptions.guild_id is BIGINT - must cast for JOIN
            with db() as conn:
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
                await interaction.followup.send("âŒ No servers found matching the target filter.", ephemeral=True)
                return

            # Send the broadcast
            result = await send_broadcast_to_guilds(guild_ids, title, message)

            embed = discord.Embed(
                title="ðŸ“¢ Broadcast Complete",
                color=discord.Color.gold() if result['failed_count'] == 0 else discord.Color.orange()
            )
            embed.add_field(name="Target", value=target.title(), inline=True)
            embed.add_field(name="Sent", value=str(result['sent_count']), inline=True)
            embed.add_field(name="Failed", value=str(result['failed_count']), inline=True)
            embed.add_field(name="Title", value=title[:100], inline=False)
            embed.add_field(name="Message Preview", value=message[:200] + ("..." if len(message) > 200 else ""), inline=False)

            await interaction.followup.send(embed=embed, ephemeral=True)

        except Exception as e:
            print(f"Broadcast command error: {e}")
            await interaction.followup.send(f"âŒ Broadcast failed: {str(e)}", ephemeral=True)

    @app_commands.command(name="owner_grant", description="[OWNER] Grant subscription tier to current server")
    @app_commands.describe(tier="Subscription tier to grant")
    @app_commands.choices(tier=[
        app_commands.Choice(name="Premium", value="bot_access"),
        app_commands.Choice(name="Pro Retention (30-day)", value="pro")
    ])
    async def owner_grant_tier(self, interaction: discord.Interaction, tier: str):
        """Owner-only command to grant subscription tiers"""
        if interaction.user.id != BOT_OWNER_ID:
            await send_reply(interaction, "âŒ Access denied.", ephemeral=True)
            return

        # Robust defer with proper fallback
        defer_success = await robust_defer(interaction, ephemeral=True)
        if not defer_success and not interaction.response.is_done():
            # If defer failed and interaction isn't done, we can't proceed
            return

        if interaction.guild is None:
            await interaction.followup.send("âŒ This command must be used in a server.", ephemeral=True)
            return

        guild_id = interaction.guild.id
        guild_name = interaction.guild.name

        try:
            # Handle bot access grant differently
            if tier == "bot_access":
                set_bot_access(guild_id, True)

                embed = discord.Embed(
                    title="ðŸ‘‘ Owner Grant Successful",
                    description=f"Manually granted **Bot Access** to this server",
                    color=discord.Color.gold()
                )

                embed.add_field(name="Server", value=guild_name, inline=True)
                embed.add_field(name="Server ID", value=str(guild_id), inline=True)
                embed.add_field(name="Grant Type", value="Bot Access", inline=True)
                embed.add_field(name="Granted By", value="Bot Owner (Manual)", inline=True)

                embed.add_field(
                    name="Features Unlocked",
                    value="â€¢ Full team access\nâ€¢ CSV Reports\nâ€¢ Role management\nâ€¢ Dashboard access",
                    inline=False
                )
            else:
                # Check current tier
                current_tier = get_guild_tier_string(guild_id)

                # Grant the new tier (no Stripe subscription - manual owner grant)
                set_server_tier(guild_id, tier, subscription_id=f"owner_grant_{int(time.time())}", customer_id="owner_manual")

                # Also ensure bot access is granted (retention requires bot access)
                set_bot_access(guild_id, True)

                tier_display = "7-Day Retention" if tier == "basic" else "30-Day Retention"

                embed = discord.Embed(
                    title="ðŸ‘‘ Owner Grant Successful",
                    description=f"Manually granted **{tier_display}** to this server",
                    color=discord.Color.gold()
                )

                embed.add_field(name="Server", value=guild_name, inline=True)
                embed.add_field(name="Server ID", value=str(guild_id), inline=True)
                embed.add_field(name="Previous Tier", value=current_tier.title(), inline=True)
                embed.add_field(name="New Tier", value=tier.title(), inline=True)
                embed.add_field(name="Granted By", value="Bot Owner (Manual)", inline=True)
                embed.add_field(name="Type", value="Owner Override", inline=True)

                embed.add_field(
                    name="Features Unlocked",
                    value="â€¢ 30-day data retention\nâ€¢ Advanced reporting\nâ€¢ Extended history" if tier == "pro" else "â€¢ 7-day data retention\nâ€¢ Extended reporting",
                    inline=False
                )

            await interaction.followup.send(embed=embed, ephemeral=True)

        except Exception as e:
            await interaction.followup.send(f"âŒ Error granting tier: {str(e)}", ephemeral=True)


    @app_commands.command(name="owner_grant_server", description="[OWNER] Grant subscription to any server by ID")
    @app_commands.describe(
        server_id="Discord server ID to grant subscription to",
        tier="Subscription tier to grant"
    )
    @app_commands.choices(tier=[
        app_commands.Choice(name="Premium", value="bot_access"),
        app_commands.Choice(name="Pro Retention (30-day)", value="pro")
    ])
    async def owner_grant_server_by_id(self, interaction: discord.Interaction, server_id: str, tier: str):
        """Owner-only command to grant subscriptions to any server by ID"""
        if interaction.user.id != BOT_OWNER_ID:
            await send_reply(interaction, "âŒ Access denied.", ephemeral=True)
            return

        # Robust defer with proper fallback
        defer_success = await robust_defer(interaction, ephemeral=True)
        if not defer_success and not interaction.response.is_done():
            # If defer failed and interaction isn't done, we can't proceed
            return

        try:
            # Validate server ID
            try:
                guild_id = int(server_id)
            except ValueError:
                await interaction.followup.send("âŒ Invalid server ID format.", ephemeral=True)
                return

            # Try to get guild info (if bot is in that server)
            guild = bot.get_guild(guild_id)
            guild_name = guild.name if guild else f"Server ID: {guild_id}"

            # Check if bot is in the server
            if not guild:
                await interaction.followup.send(f"âš ï¸ Bot is not in server {guild_id}. Grant will still be applied if server adds bot later.", ephemeral=True)

            # Handle bot access grant differently
            if tier == "bot_access":
                set_bot_access(guild_id, True)

                embed = discord.Embed(
                    title="ðŸŒ Remote Server Grant Successful",
                    description=f"Granted **Bot Access** to remote server",
                    color=discord.Color.purple()
                )

                embed.add_field(name="Target Server", value=guild_name, inline=True)
                embed.add_field(name="Server ID", value=str(guild_id), inline=True)
                embed.add_field(name="Bot Present", value="âœ… Yes" if guild else "âŒ No", inline=True)
                embed.add_field(name="Grant Type", value="Bot Access", inline=True)

                if guild:
                    embed.add_field(name="Member Count", value=str(guild.member_count), inline=True)
                    embed.add_field(name="Server Owner", value=str(guild.owner), inline=True)

                embed.add_field(
                    name="Features Unlocked",
                    value="â€¢ Full team access\nâ€¢ CSV Reports\nâ€¢ Role management\nâ€¢ Dashboard access",
                    inline=False
                )
            else:
                # Check current tier
                current_tier = get_guild_tier_string(guild_id)

                # Grant the tier
                set_server_tier(guild_id, tier, subscription_id=f"owner_remote_{int(time.time())}", customer_id="owner_remote")

                # Also ensure bot access is granted (retention requires bot access)
                set_bot_access(guild_id, True)

                tier_display = "7-Day Retention" if tier == "basic" else "30-Day Retention"

                embed = discord.Embed(
                    title="ðŸŒ Remote Server Grant Successful",
                    description=f"Granted **{tier_display}** to remote server",
                    color=discord.Color.purple()
                )

                embed.add_field(name="Target Server", value=guild_name, inline=True)
                embed.add_field(name="Server ID", value=str(guild_id), inline=True)
                embed.add_field(name="Bot Present", value="âœ… Yes" if guild else "âŒ No", inline=True)
                embed.add_field(name="Previous Tier", value=current_tier.title(), inline=True)
                embed.add_field(name="New Tier", value=tier.title(), inline=True)
                embed.add_field(name="Grant Type", value="Remote Owner Override", inline=True)

                if guild:
                    embed.add_field(name="Member Count", value=str(guild.member_count), inline=True)
                    embed.add_field(name="Server Owner", value=str(guild.owner), inline=True)

                embed.add_field(
                    name="Status",
                    value="âœ… Subscription active immediately" if guild else "â³ Will activate when bot joins server",
                    inline=False
                )

            await interaction.followup.send(embed=embed, ephemeral=True)

        except Exception as e:
            await interaction.followup.send(f"âŒ Error granting remote server subscription: {str(e)}", ephemeral=True)

    # ---------------------------------------------------------
    # LAYER 3: LEGAL, PRIVACY, & COMPLIANCE TOOLS
    # ---------------------------------------------------------

    @bot.event
    async def on_guild_remove(guild):
        """Fires when the bot is kicked from a server. Instantly terminates subscriptions and sets presence flag to False."""
        try:
            print(f"[{datetime.now()}] Bot removed from server: {guild.name} ({guild.id})")
            with get_db() as conn:
                # 1. Mark bot as not present
                conn.execute("""
                    UPDATE bot_guilds 
                    SET is_present = FALSE, left_at = NOW() 
                    WHERE guild_id = %s
                """, (str(guild.id),))

                # 2. Cancel active Stripe subscriptions to prevent phantom billing
                cursor = conn.execute("""
                    SELECT subscription_id FROM server_subscriptions 
                    WHERE guild_id = %s AND status = 'active' AND subscription_id IS NOT NULL
                """, (str(guild.id),))
                sub = cursor.fetchone()

                if sub and sub['subscription_id']:
                    import stripe
                    try:
                        stripe.Subscription.modify(
                            sub['subscription_id'],
                            cancel_at_period_end=True
                        )
                        conn.execute("""
                            UPDATE server_subscriptions 
                            SET cancel_at_period_end = TRUE 
                            WHERE guild_id = %s
                        """, (str(guild.id),))
                        print(f"  -> Successfully issued Stripe cancellation for severed guild {guild.id}")
                    except Exception as stripe_error:
                        print(f"  -> Stripe cancellation failed for severed guild {guild.id}: {stripe_error}")
        except Exception as e:
            print(f"Error handling guild removal for {guild.id}: {e}")

    @app_commands.command(name="owner_server_listings", description="[OWNER] View all servers with employee/admin headcounts")
    async def owner_server_listings(self, interaction: discord.Interaction):
        """Owner-only command to list all servers with employee/admin headcounts"""
        if interaction.user.id != BOT_OWNER_ID:
            await send_reply(interaction, "âŒ Access denied.", ephemeral=True)
            return

        # Robust defer with proper fallback
        defer_success = await robust_defer(interaction, ephemeral=True)
        if not defer_success and not interaction.response.is_done():
            # If defer failed and interaction isn't done, we can't proceed
            return

        try:
            embed = discord.Embed(
                title="ðŸ“Š Server Listings",
                description=f"Bot is active in {len(bot.guilds)} servers",
                color=discord.Color.blue()
            )

            server_data = []

            for guild in bot.guilds:
                # Get bot access and retention tier status
                has_bot_access = check_bot_access(guild.id)
                retention_tier = get_retention_tier(guild.id)

                # Determine paid/free status
                paid_status = "Paid" if has_bot_access else "Free"

                # Format retention tier for display
                retention_display = {
                    'none': 'None',
                    '7day': '7-Day',
                    '30day': '30-Day'
                }.get(retention_tier, 'None')

                # Get server owner (may be None if owner left)
                owner_name = str(guild.owner) if guild.owner else "Unknown"

                # Get bot join date
                joined_at = guild.me.joined_at if guild.me else None
                if joined_at:
                    # Format as MM/DD/YY HH:MM AM/PM
                    joined_date_str = joined_at.strftime("%m/%d/%y %I:%M %p")
                else:
                    joined_date_str = "Unknown"

                server_data.append({
                    'name': guild.name,
                    'id': guild.id,
                    'owner': owner_name,
                    'member_count': guild.member_count,
                    'retention_tier': retention_display,
                    'paid_status': paid_status,
                    'joined_at': joined_date_str
                })

            # Sort by member count (largest first)
            server_data.sort(key=lambda x: x['member_count'], reverse=True)

            # Add server info to embed (limit to prevent message too long)
            for i, server in enumerate(server_data[:15]):  # Show first 15 servers
                status_emoji = "ðŸ’³" if server['paid_status'] == "Paid" else "ðŸ†“"

                embed.add_field(
                    name=f"{status_emoji} {server['name'][:30]}" + ("..." if len(server['name']) > 30 else ""),
                    value=f"**ID:** {server['id']}\n"
                          f"**Joined:** {server['joined_at']}\n"
                          f"**Owner:** {server['owner'][:25]}\n"
                          f"**Users:** {server['member_count']}\n"
                          f"**Retention:** {server['retention_tier']}\n"
                          f"**Status:** {server['paid_status']}",
                    inline=True
                )

            if len(server_data) > 15:
                embed.add_field(
                    name="...",
                    value=f"And {len(server_data) - 15} more servers",
                    inline=False
                )

            await interaction.followup.send(embed=embed, ephemeral=True)

        except Exception as e:
            await interaction.followup.send(f"â Œ Error fetching server listings: {str(e)}", ephemeral=True)

async def setup(bot):
    await bot.add_cog(OwnerCmds(bot))
