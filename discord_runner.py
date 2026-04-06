import asyncio
from bot_core import (
    bot,
    TOKEN,
    run_migrations,
    init_db,
    schedule_daily_cleanup,
    start_bot_api_server
)

async def run_bot_with_api():
    # Load core cogs
    await bot.load_extension("bot.cogs.core_events")
    await bot.load_extension("bot.cogs.presence_events")
    await bot.load_extension("bot.cogs.employee_cmds")
    await bot.load_extension("bot.cogs.admin_cmds")
    await bot.load_extension("bot.cogs.owner_cmds")
    
    # ⚠️ CRITICAL WIRING: Launches the bot's internal HTTP API on port 8081.
    # Without this line, all Flask→Bot calls fail with ConnectionError.
    # See: docs/lessons-learned.md "Refactoring Safety Protocol"
    asyncio.create_task(start_bot_api_server())
    
    # Start Discord bot (will block until disconnected)
    await bot.start(TOKEN)

if __name__ == "__main__":
    print("🔧 Running database migrations...")
    run_migrations()
    
    print("✅ Initializing DB Tables...")
    init_db()
    
    if not TOKEN:
        raise SystemExit("Set DISCORD_TOKEN in your environment.")
        
    print(f"✅ Health check server disabled (Flask app handles web server)")
    schedule_daily_cleanup()
    
    print(f"🤖 Starting Discord bot with API server...")
    asyncio.run(run_bot_with_api())
