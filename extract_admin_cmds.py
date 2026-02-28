import os

with open("bot_core.py", "r", encoding="utf-8") as f:
    lines = f.readlines()

setup_cmd = lines[4788:4879]
context_menus = lines[5482:5694]

chunk = setup_cmd + context_menus

final_lines = []
for line in chunk:
    if line.strip().startswith("@tree.command"):
        l = line.replace("@tree.command", "@app_commands.command")
    elif line.strip().startswith("@tree.context_menu"):
        l = line.replace("@tree.context_menu", "@app_commands.context_menu")
    # For sub-decorators like @app_commands.default_permissions
    elif line.strip().startswith("@app_commands."):
        l = line
    else:
        l = line
        
    if l.strip().startswith("async def "):
        if "(interaction: discord.Interaction" in l and "self" not in l:
            l = l.replace("(interaction: discord.Interaction", "(self, interaction: discord.Interaction")
    
    final_lines.append("    " + l)

imports = """
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
"""

setup_block = """
async def setup(bot):
    await bot.add_cog(AdminCmds(bot))
"""

with open("bot/cogs/admin_cmds.py", "w", encoding="utf-8") as f:
    f.write(imports.lstrip())
    f.write("".join(final_lines))
    f.write(setup_block)

print("Created bot/cogs/admin_cmds.py successfully")
