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
                title="⚡ Welcome to the Time Warden Playground",
                description="Experience the ultimate Discord-native Timeclock solution. This server is heavily sandboxed with automatically refreshing test data to provide a flawless demonstration environment.",
                color=0x00FFFF
            )
            embed.add_field(
                name="🎭 1. Choose Your Persona",
                value="Did you skip Server Onboarding? No problem! Use the buttons attached below to instantly assign yourself as a **Demo Admin** (Manager Control Panel) or a **Demo Employee** (Clock In/Out). You can freely hot-swap your role at any time to explore both sides of the product.",
                inline=False
            )
            embed.add_field(
                name="🖥️ 2. Enter the Dashboard",
                value=f"[Launch Manager Dashboard]({dashboard_url}/auth/login)\nDive directly into payroll routing, deep analytics, manual timesheet adjustments, and server settings.",
                inline=False
            )
            embed.add_field(
                name="📱 3. Interact with Kiosk Mode (BETA)",
                value=f"[Launch Kiosk Tablet Interface]({dashboard_url}/kiosk/{DEMO_SERVER_ID})\nOpen our physical-workplace tablet solution. Seamlessly clock in utilizing 4-digit PINs (Test PINs available in Dashboard Profiles).",
                inline=False
            )
            embed.set_footer(text="Time Warden • Environment resets completely at Midnight (UTC)")
            
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
