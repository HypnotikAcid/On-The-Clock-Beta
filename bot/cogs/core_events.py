import discord
from discord.ext import commands
from datetime import datetime, timezone
from bot_core import (
    db, create_setup_embed, SetupInstructionsView
)

class CoreEvents(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self._recent_guild_joins = {}

    @commands.Cog.listener()
    async def on_guild_join(self, guild):
        """Send welcome message with setup instructions when bot joins a new server"""
        now = datetime.now(timezone.utc)
        last_join = self._recent_guild_joins.get(guild.id)
        if last_join and (now - last_join).total_seconds() < 60:
            print(f"⚠️ Duplicate on_guild_join for {guild.name} (ID: {guild.id}) — skipping")
            return
        self._recent_guild_joins[guild.id] = now
        
        print(f"🎉 Bot joined new server: {guild.name} (ID: {guild.id})")
        
        inviter = guild.owner
        embed = create_setup_embed()
        
        try:
            if inviter:
                await inviter.send(embed=embed)
                print(f"✅ Sent welcome DM to {inviter} in {guild.name}")
            else:
                print(f"⚠️ Could not find owner for {guild.name}")
        except discord.Forbidden:
            print(f"❌ Could not DM owner of {guild.name} - DMs disabled")
        except Exception as e:
            print(f"❌ Error sending welcome DM for {guild.name}: {e}")
        
        try:
            target_channel = guild.system_channel
            if not target_channel:
                for channel in guild.text_channels:
                    if channel.permissions_for(guild.me).send_messages:
                        target_channel = channel
                        break
            
            if target_channel:
                view = SetupInstructionsView()
                
                welcome_text = f"👋 Welcome! I'm **On the Clock**, your professional Discord timeclock bot.\n\n"
                if inviter:
                    welcome_text += f"{inviter.mention} added me to help manage your team's time tracking.\n\n"
                welcome_text += "Click the button below for setup instructions and getting started guide!"
                
                await target_channel.send(welcome_text, view=view)
                print(f"✅ Sent welcome button to #{target_channel.name} in {guild.name}")
            else:
                print(f"⚠️ Could not find any text channel to send welcome button in {guild.name}")
        except Exception as e:
            print(f"❌ Error sending welcome button to channel in {guild.name}: {e}")
        
        # Add guild to bot_guilds table
        try:
            with db() as conn:
                conn.execute("""
                    INSERT INTO bot_guilds (guild_id, guild_name, joined_at, is_present, left_at)
                    VALUES (%s, %s, NOW(), TRUE, NULL)
                    ON CONFLICT (guild_id) DO UPDATE 
                    SET guild_name = EXCLUDED.guild_name, joined_at = NOW(), is_present = TRUE, left_at = NULL
                """, (str(guild.id), guild.name))
            print(f"✅ Added {guild.name} to bot_guilds table")
        except Exception as e:
            print(f"❌ Error adding guild to bot_guilds table: {e}")

        # Set trial start date
        try:
            with db() as conn:
                conn.execute("""
                    INSERT INTO guild_settings (guild_id, trial_start_date)
                    VALUES (%s, NOW())
                    ON CONFLICT (guild_id) DO NOTHING
                """, (guild.id,))
            print(f"✅ Set trial start date for {guild.name}")
        except Exception as e:
            print(f"❌ Error setting trial start date for {guild.name}: {e}")

    @commands.Cog.listener()
    async def on_guild_remove(self, guild):
        """Handle bot being removed from a server - archive paid servers, delete non-paid server data"""
        print(f"👋 Bot removed from server: {guild.name} (ID: {guild.id})")
        guild_id_str = str(guild.id)
        guild_id_int = guild.id
        
        try:
            with db() as conn:
                # Check if this server has paid access
                cursor = conn.execute(
                    "SELECT bot_access_paid FROM server_subscriptions WHERE guild_id = %s",
                    (guild_id_int,)
                )
                result = cursor.fetchone()
                has_paid_access = result and result.get('bot_access_paid', False)
                
                if has_paid_access:
                    # PAID SERVER: Just mark as not present (archive) - keep all data for potential re-add
                    conn.execute("""
                        UPDATE bot_guilds 
                        SET is_present = FALSE, left_at = NOW() 
                        WHERE guild_id = %s
                    """, (guild_id_str,))
                    print(f"📁 Archived paid server {guild.name} - subscription data preserved")
                else:
                    # NON-PAID SERVER: Delete all server data
                    print(f"🗑️ Cleaning up non-paid server {guild.name}...")
                    
                    # Delete employee profiles
                    conn.execute("DELETE FROM employee_profiles WHERE guild_id = %s", (guild_id_int,))
                    print(f"   - Deleted employee profiles")
                    
                    # Delete time adjustment requests
                    conn.execute("DELETE FROM time_adjustment_requests WHERE guild_id = %s", (guild_id_int,))
                    print(f"   - Deleted time adjustment requests")
                    
                    # Delete admin roles
                    conn.execute("DELETE FROM admin_roles WHERE guild_id = %s", (guild_id_str,))
                    print(f"   - Deleted admin roles")
                    
                    conn.execute("DELETE FROM employee_roles WHERE guild_id = %s", (guild_id_str,))
                    print(f"   - Deleted employee roles")
                    
                    # Delete sessions
                    conn.execute("DELETE FROM timeclock_sessions WHERE guild_id = %s", (guild_id_int,))
                    print(f"   - Deleted sessions")
                    
                    # Delete server subscription record (if any non-paid entry exists)
                    conn.execute("DELETE FROM server_subscriptions WHERE guild_id = %s AND (bot_access_paid = FALSE OR bot_access_paid IS NULL)", (guild_id_int,))
                    
                    # Delete from bot_guilds entirely
                    conn.execute("DELETE FROM bot_guilds WHERE guild_id = %s", (guild_id_str,))
                    print(f"✅ Completely removed non-paid server {guild.name} and all data")
                    
        except Exception as e:
            print(f"❌ Error handling guild removal for {guild.name}: {e}")

async def setup(bot):
    await bot.add_cog(CoreEvents(bot))
