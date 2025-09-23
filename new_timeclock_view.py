class TimeClockView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)  # persistent view
        
        # Get server tier to determine button layout
        # We'll determine this dynamically in each interaction since we can't pass guild_id to __init__

    @discord.ui.button(label="On the Clock", style=discord.ButtonStyle.secondary, custom_id="timeclock:onclock", row=0)
    async def on_the_clock(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Show all currently clocked in users with their times"""
        if interaction.guild is None:
            await interaction.response.send_message("Use this in a server.", ephemeral=True)
            return
            
        guild_id = interaction.guild.id
        
        # Get all currently clocked in users
        with db() as conn:
            cursor = conn.execute("""
                SELECT user_id, clock_in 
                FROM sessions 
                WHERE guild_id = ? AND clock_out IS NULL
                ORDER BY clock_in ASC
            """, (guild_id,))
            active_sessions = cursor.fetchall()
        
        if not active_sessions:
            embed = discord.Embed(
                title="⏰ On the Clock",
                description="No one is currently clocked in.",
                color=discord.Color.gold()
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return
        
        # Get timezone setting
        tz_name = get_guild_setting(guild_id, "timezone", DEFAULT_TZ)
        
        try:
            from zoneinfo import ZoneInfo
            guild_tz = ZoneInfo(tz_name)
        except Exception:
            guild_tz = timezone.utc
            tz_name = "UTC"
        
        embed = discord.Embed(
            title="⏰ On the Clock",
            description=f"Currently clocked in users ({len(active_sessions)} total)",
            color=discord.Color.gold()
        )
        
        now_utc = datetime.now(timezone.utc)
        
        clock_in_list = []
        for user_id, clock_in_iso in active_sessions:
            # Get user nickname/username
            user = interaction.guild.get_member(user_id)
            if user:
                display_name = user.display_name
            else:
                display_name = f"User {user_id}"
            
            # Parse clock in time
            clock_in_utc = datetime.fromisoformat(clock_in_iso.replace('Z', '+00:00'))
            clock_in_local = clock_in_utc.astimezone(guild_tz)
            
            # Calculate total time for today in this timezone
            local_date = clock_in_local.date()
            day_start = datetime.combine(local_date, datetime.min.time()).replace(tzinfo=guild_tz)
            day_end = datetime.combine(local_date, datetime.max.time()).replace(tzinfo=guild_tz)
            
            # Get all sessions for today
            day_start_utc = day_start.astimezone(timezone.utc).isoformat()
            day_end_utc = day_end.astimezone(timezone.utc).isoformat()
            
            with db() as conn:
                cursor = conn.execute("""
                    SELECT clock_in, clock_out 
                    FROM sessions 
                    WHERE guild_id = ? AND user_id = ? 
                    AND clock_in >= ? AND clock_in <= ?
                """, (guild_id, user_id, day_start_utc, day_end_utc))
                day_sessions = cursor.fetchall()
            
            # Calculate total day seconds
            total_day_seconds = 0
            for session_in, session_out in day_sessions:
                if session_out:  # Completed session
                    start = datetime.fromisoformat(session_in.replace('Z', '+00:00'))
                    end = datetime.fromisoformat(session_out.replace('Z', '+00:00'))
                    total_day_seconds += (end - start).total_seconds()
                else:  # Current active session
                    start = datetime.fromisoformat(session_in.replace('Z', '+00:00'))
                    total_day_seconds += (now_utc - start).total_seconds()
            
            # Current shift time
            shift_seconds = (now_utc - clock_in_utc).total_seconds()
            
            # Format times
            clock_in_time = clock_in_local.strftime("%I:%M %p")
            total_day_time = format_duration_hhmmss(total_day_seconds)
            shift_time = format_shift_duration(shift_seconds)
            
            clock_in_list.append(f"**{display_name}** - In: {clock_in_time} | {total_day_time} | {shift_time}")
        
        embed.add_field(
            name="Active Users",
            value="\n".join(clock_in_list),
            inline=False
        )
        
        embed.add_field(
            name="Timezone",
            value=tz_name,
            inline=True
        )
        
        await interaction.response.send_message(embed=embed, ephemeral=True)

    @discord.ui.button(label="Clock In", style=discord.ButtonStyle.success, custom_id="timeclock:in", row=0)
    async def clock_in(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.guild is None:
            await interaction.response.send_message("Use this in a server.", ephemeral=True)
            return
        guild_id = interaction.guild.id
        user_id = interaction.user.id
        
        # Check free tier restrictions
        server_tier = get_server_tier(guild_id)
        if server_tier == "free" and not is_server_admin(interaction.user):
            await interaction.response.send_message(
                "🔒 **Free Tier Limitation**\n"
                "Only server administrators can use the timeclock on the free plan.\n"
                "Upgrade to Basic ($5/month) for full team access!",
                ephemeral=True
            )
            return
        
        if get_active_session(guild_id, user_id):
            await interaction.response.send_message("You're already clocked in.", ephemeral=True)
            return
        start_session(guild_id, user_id, now_utc().isoformat())
        await interaction.response.send_message("✅ Clocked in. Have a great shift!", ephemeral=True)

    @discord.ui.button(label="Clock Out", style=discord.ButtonStyle.danger, custom_id="timeclock:out", row=0)
    async def clock_out(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.guild is None:
            await interaction.response.send_message("Use this in a server.", ephemeral=True)
            return
        guild_id = interaction.guild.id
        user_id = interaction.user.id
        
        # Check free tier restrictions
        server_tier = get_server_tier(guild_id)
        if server_tier == "free" and not is_server_admin(interaction.user):
            await interaction.response.send_message(
                "🔒 **Free Tier Limitation**\n"
                "Only server administrators can use the timeclock on the free plan.\n"
                "Upgrade to Basic ($5/month) for full team access!",
                ephemeral=True
            )
            return
        
        active = get_active_session(guild_id, user_id)
        if not active:
            await interaction.response.send_message("You don't have an active session.", ephemeral=True)
            return

        session_id, clock_in_iso = active
        start_dt = datetime.fromisoformat(clock_in_iso)
        end_dt = now_utc()
        elapsed = int((end_dt - start_dt).total_seconds())
        close_session(session_id, end_dt.isoformat(), elapsed)

        tz_name = get_guild_setting(guild_id, "timezone", DEFAULT_TZ)
        await interaction.response.send_message(
            f"🔚 Clocked out.\n**In:** {fmt(start_dt, tz_name)}\n**Out:** {fmt(end_dt, tz_name)}\n**Total:** {human_duration(elapsed)}",
            ephemeral=True
        )

        # DM the designated manager
        recipient_id = get_guild_setting(guild_id, "recipient_user_id")
        if recipient_id:
            try:
                manager = await bot.fetch_user(recipient_id)
                embed = discord.Embed(
                    title="Timeclock Entry",
                    description=f"**Employee:** {interaction.user.mention} (`{interaction.user.id}`)",
                    color=discord.Color.blurple(),
                    timestamp=end_dt
                )
                embed.add_field(name="In", value=fmt(start_dt, tz_name), inline=True)
                embed.add_field(name="Out", value=fmt(end_dt, tz_name), inline=True)
                embed.add_field(name="Duration", value=human_duration(elapsed), inline=True)
                embed.add_field(name="Server", value=interaction.guild.name, inline=False)
                await manager.send(embed=embed)
            except Exception as e:
                print(f"❌ Failed to DM manager {recipient_id}: {e}")

    @discord.ui.button(label="Help", style=discord.ButtonStyle.primary, custom_id="timeclock:help", row=0)
    async def show_help(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Show help commands instead of user time info"""
        embed = discord.Embed(
            title="🛠️ Timeclock Help Commands",
            description="Available slash commands for the timeclock bot:",
            color=discord.Color.blue()
        )
        
        # Basic commands
        embed.add_field(
            name="📊 General Commands",
            value="`/help` - Show all commands\n"
                  "`/subscription_status` - View subscription details\n"
                  "`/cancel_subscription` - Learn how to cancel",
            inline=False
        )
        
        # Admin commands
        embed.add_field(
            name="👑 Admin Commands",
            value="`/setup_timeclock` - Create timeclock interface\n"
                  "`/report @user start-date end-date` - Generate CSV reports\n"
                  "`/data_cleanup` - Clean old data\n"
                  "`/purge` - Delete ALL server data",
            inline=False
        )
        
        # Settings commands
        embed.add_field(
            name="⚙️ Settings Commands",
            value="`/set_timezone` - Set server timezone\n"
                  "`/set_recipient` - Set manager for notifications\n"
                  "`/toggle_name_display` - Switch username/nickname\n"
                  "`/add_info_role` - Authorize roles\n"
                  "`/remove_info_role` - Remove role access",
            inline=False
        )
        
        # Subscription commands
        embed.add_field(
            name="💳 Subscription Commands",
            value="`/upgrade basic` - Upgrade to Basic ($5/month)\n"
                  "`/upgrade pro` - Upgrade to Pro ($10/month)",
            inline=False
        )
        
        await interaction.response.send_message(embed=embed, ephemeral=True)

    @discord.ui.button(label="Upgrade", style=discord.ButtonStyle.secondary, custom_id="timeclock:upgrade", row=1, emoji="🚀")
    async def show_upgrade(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Show upgrade options for free tier servers"""
        guild_id = interaction.guild.id
        server_tier = get_server_tier(guild_id)
        
        # Only show for free tier
        if server_tier != "free":
            await interaction.response.send_message("This server already has a subscription!", ephemeral=True)
            return
        
        embed = discord.Embed(
            title="🚀 Upgrade Your Server",
            description="Choose a plan that fits your team's needs:",
            color=discord.Color.orange()
        )
        
        embed.add_field(
            name="💼 Basic Plan - $5/month",
            value="• Full team access to timeclock\n"
                  "• All admin commands\n"
                  "• CSV Reports\n"
                  "• Role management\n"
                  "• 7 days data retention",
            inline=True
        )
        
        embed.add_field(
            name="⭐ Pro Plan - $10/month",
            value="• Everything in Basic\n"
                  "• Extended CSV reports\n"
                  "• Multiple manager notifications\n"
                  "• 30 days data retention\n"
                  "• Priority support",
            inline=True
        )
        
        embed.add_field(
            name="🔗 How to Upgrade",
            value="Use `/upgrade basic` or `/upgrade pro` commands to get started with secure Stripe checkout!",
            inline=False
        )
        
        await interaction.response.send_message(embed=embed, ephemeral=True)

    @discord.ui.button(label="Reports", style=discord.ButtonStyle.success, custom_id="timeclock:reports", row=1)
    async def generate_reports(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Generate CSV reports - only shown for paid tiers"""
        if interaction.guild is None:
            await interaction.response.send_message("Use this in a server.", ephemeral=True)
            return
        
        guild_id = interaction.guild.id
        server_tier = get_server_tier(guild_id)
        
        # Check if user has administrator permissions
        if not interaction.user.guild_permissions.administrator:
            await interaction.response.send_message("❌ You need administrator permissions to generate reports.", ephemeral=True)
            return
        
        await interaction.response.defer(ephemeral=True)
        
        # Free tier: Admin only + fake data 
        if server_tier == "free":
            fake_csv = "Date,Clock In,Clock Out,Duration\n2024-01-01,09:00,17:00,8.0 hours\nThis is the free version, please upgrade for more options"
            filename = f"sample_report_last_30_days.csv"
            
            file = discord.File(
                io.BytesIO(fake_csv.encode('utf-8')), 
                filename=filename
            )
            
            await interaction.followup.send(
                f"📊 **Free Tier Sample Report**\n"
                f"🎯 This is sample data. Upgrade to Basic ($5/month) or Pro ($10/month) for real reports!\n"
                f"📅 Date Range: Last 30 days",
                file=file,
                ephemeral=True
            )
            return
        
        # Basic and Pro tier: Full reports access with retention limits
        guild_tz_name = get_guild_setting(guild_id, "timezone", DEFAULT_TZ)
        
        # Determine report range based on tier
        if server_tier == "basic":
            report_days = 7  # Basic tier: 7 days max
        else:  # pro tier
            report_days = 30  # Pro tier: 30 days max
        
        # Generate report for tier-appropriate days
        from zoneinfo import ZoneInfo
        from datetime import timedelta
        try:
            guild_tz = ZoneInfo(guild_tz_name)
        except Exception:
            guild_tz = timezone.utc
            guild_tz_name = "UTC"
        
        # Calculate date range based on tier limits
        end_date = datetime.now(guild_tz)
        start_date = end_date - timedelta(days=report_days)
        
        start_boundary = datetime.combine(start_date.date(), datetime.min.time()).replace(tzinfo=guild_tz)
        end_boundary = datetime.combine(end_date.date(), datetime.max.time()).replace(tzinfo=guild_tz)
        
        start_utc = start_boundary.astimezone(timezone.utc).isoformat()
        end_utc = end_boundary.astimezone(timezone.utc).isoformat()
        
        # Get all user sessions
        sessions_data = get_sessions_report(guild_id, None, start_utc, end_utc)
        
        if not sessions_data:
            await interaction.followup.send(
                f"📭 No completed timesheet entries found for the last {report_days} days",
                ephemeral=True
            )
            return
        
        # Group sessions by user
        user_sessions = {}
        for user_id, clock_in_iso, clock_out_iso, duration_seconds in sessions_data:
            if user_id not in user_sessions:
                user_sessions[user_id] = []
            user_sessions[user_id].append((clock_in_iso, clock_out_iso, duration_seconds))
        
        # Generate separate CSV files for each user
        files = []
        total_users = len(user_sessions)
        total_entries = len(sessions_data)
        
        for user_id, sessions in user_sessions.items():
            csv_content, user_display_name = await generate_individual_csv_report(bot, user_id, sessions, guild_id, guild_tz_name)
            
            start_date_str = start_date.strftime("%Y-%m-%d")
            end_date_str = end_date.strftime("%Y-%m-%d")
            filename = f"timesheet_report_{start_date_str}_to_{end_date_str}_{user_display_name}.csv"
            
            file = discord.File(
                io.BytesIO(csv_content.encode('utf-8')), 
                filename=filename
            )
            files.append(file)
        
        # Send all files
        tier_note = f"({server_tier.title()} tier - {report_days} days max)" if server_tier == "basic" else f"({server_tier.title()} tier)"
        await interaction.followup.send(
            f"📊 Generated individual timesheet reports for **{total_users} users** {tier_note}\n"
            f"📅 **Period:** Last {report_days} days ({start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')})\n"
            f"📝 **Total Entries:** {total_entries} completed shifts\n"
            f"🕐 **Timezone:** {guild_tz_name}\n\n"
            f"📁 **Files:** One CSV per employee",
            files=files,
            ephemeral=True
        )


# ============================================================================= 
# Dynamic View Creation to handle conditional buttons
# =============================================================================

def create_timeclock_view(guild_id: int) -> TimeClockView:
    """Create a TimeClockView with conditional buttons based on server tier"""
    server_tier = get_server_tier(guild_id)
    
    view = TimeClockView()
    
    # Clear default buttons and add conditionally
    view.clear_items()
    
    # Always add these core buttons (row 0)
    on_clock_btn = discord.ui.Button(label="On the Clock", style=discord.ButtonStyle.secondary, custom_id="timeclock:onclock", row=0)
    on_clock_btn.callback = view.on_the_clock
    view.add_item(on_clock_btn)
    
    clock_in_btn = discord.ui.Button(label="Clock In", style=discord.ButtonStyle.success, custom_id="timeclock:in", row=0)
    clock_in_btn.callback = view.clock_in
    view.add_item(clock_in_btn)
    
    clock_out_btn = discord.ui.Button(label="Clock Out", style=discord.ButtonStyle.danger, custom_id="timeclock:out", row=0)
    clock_out_btn.callback = view.clock_out
    view.add_item(clock_out_btn)
    
    help_btn = discord.ui.Button(label="Help", style=discord.ButtonStyle.primary, custom_id="timeclock:help", row=0)
    help_btn.callback = view.show_help
    view.add_item(help_btn)
    
    # Conditional buttons (row 1)
    if server_tier == "free":
        # Show upgrade button for free servers
        upgrade_btn = discord.ui.Button(label="Upgrade", style=discord.ButtonStyle.secondary, custom_id="timeclock:upgrade", row=1, emoji="🚀")
        upgrade_btn.callback = view.show_upgrade
        view.add_item(upgrade_btn)
    else:
        # Show reports button for paid servers
        reports_btn = discord.ui.Button(label="Reports", style=discord.ButtonStyle.success, custom_id="timeclock:reports", row=1)
        reports_btn.callback = view.generate_reports
        view.add_item(reports_btn)
    
    return view