import discord
from discord.ext import commands
from bot_core import (
    db, DEMO_SERVER_ID, DemoRoleSwitcherView
)

class PresenceEvents(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @commands.Cog.listener()
    async def on_member_join(self, member):
        """Handle new members joining - special handling for demo server"""
        if member.guild.id != DEMO_SERVER_ID:
            # Check if they are a registered employee in a non-demo server
            try:
                with db() as conn:
                    cursor = conn.execute(
                        "SELECT 1 FROM employee_profiles WHERE guild_id = %s AND user_id = %s",
                        (member.guild.id, member.id)
                    )
                    is_employee = cursor.fetchone()
                    
                    if is_employee:
                        # They are a returning employee, re-apply the role if configured
                        cursor = conn.execute(
                            "SELECT employee_role_id FROM guild_settings WHERE guild_id = %s",
                            (member.guild.id,)
                        )
                        row = cursor.fetchone()
                        if row and row['employee_role_id']:
                            role = member.guild.get_role(int(row['employee_role_id']))
                            if role:
                                await member.add_roles(role, reason="Auto-assigned for returning employee")
                                print(f"✅ Re-assigned employee role to {member.display_name} in {member.guild.name}")
            except Exception as e:
                print(f"❌ Error checking/assigning role for returning member {member.id} in {member.guild.id}: {e}")
            return
        
        print(f"👋 New member joined demo server: {member.display_name}")
        
        try:
            # Use production URL for OAuth compatibility
            dashboard_url = "https://time-warden.com"
            
            embed = discord.Embed(
                title="🎮 Welcome to the Time Warden Demo Server!",
                description="Thanks for checking out our Discord timeclock bot! This demo lets you explore **all features** with live test data.",
                color=0x00FFFF  # Cyan to match branding
            )
            embed.add_field(
                name="🎭 STEP 1: Choose Your Demo Persona",
                value="Click a button below to begin your demo:\n• 👷 **Become Employee** - Test clock in/out features\n• 👑 **Become Admin** - Manage employees and settings",
                inline=False
            )
            embed.add_field(
                name="🖥️ STEP 2: Try the Web Dashboard",
                value=f"[Login to Dashboard]({dashboard_url}/auth/login)\n\nExplore our core product! The full admin dashboard allows you to manage staff, edit timesheets, view reports, and configure server settings.",
                inline=False
            )
            embed.add_field(
                name="📱 STEP 3: Try the Kiosk Mode (BETA)",
                value=f"[Open Demo Kiosk]({dashboard_url}/kiosk/{DEMO_SERVER_ID})\n\nOur upcoming physical workplace solution. Test our tablet-friendly interface with PIN-based clock in/out.",
                inline=False
            )
            embed.add_field(
                name="💬 Discord Commands",
                value="• `/clock` - Open your personal timeclock\n• `/help` - See all available commands\n• `/report` - Generate timesheet reports",
                inline=False
            )
            embed.set_footer(text="Time Warden - Professional Time Tracking for Discord Teams")
            
            # Send Welcome DM as a reference
            try:
                await member.send(embed=embed)
                print(f"✅ Sent welcome DM to {member.display_name}")
            except discord.Forbidden:
                print(f"⚠️ Could not DM {member.display_name} - DMs disabled")
                
            # Send Interactive Onboarding directly in the server
            channel = member.guild.system_channel
            if not channel:
                # Fallback to the first available text channel we can send in
                for c in member.guild.text_channels:
                    if c.permissions_for(member.guild.me).send_messages:
                        channel = c
                        break
                        
            if channel:
                view = DemoRoleSwitcherView()
                await channel.send(
                    content=f"👋 Welcome {member.mention}! Please select your demo experience below:",
                    embed=embed,
                    view=view
                )
                print(f"✅ Sent interactive role selector to #{channel.name} for {member.display_name}")
                
        except Exception as e:
            print(f"❌ Error sending welcome messages: {e}")

async def setup(bot):
    await bot.add_cog(PresenceEvents(bot))
