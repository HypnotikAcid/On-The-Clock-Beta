import os

with open("bot_core.py", "r", encoding="utf-8") as f:
    lines = f.readlines()

clock = lines[4880:5093]
help_cmd = lines[5186:5291]
feedback_modal = lines[5291:5334]
feedback_cmd = lines[5334:5577]
my_data = lines[5976:6021]
timezone_cmd = lines[6021:6047]

chunk = clock + help_cmd + feedback_modal + feedback_cmd + my_data + timezone_cmd

final_lines = []
for line in chunk:
    l = line.replace("@tree.command", "@app_commands.command")
    if l.strip().startswith("async def "):
        if "(interaction: discord.Interaction" in l and "self" not in l:
            l = l.replace("(interaction: discord.Interaction", "(self, interaction: discord.Interaction")
    # For nested commands or modal methods that don't need self twice
    if "def on_submit(interaction" in l:
        l = l.replace("def on_submit(interaction", "def on_submit(self, interaction")
    final_lines.append("    " + l)

imports = """
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
"""

setup_block = """
async def setup(bot):
    await bot.add_cog(EmployeeCmds(bot))
"""

with open("bot/cogs/employee_cmds.py", "w", encoding="utf-8") as f:
    f.write(imports.lstrip())
    f.write("".join(final_lines))
    f.write(setup_block)

print("Created bot/cogs/employee_cmds.py successfully")
