# Multi-Agent Coordination Protocol

**Purpose**: This document defines how different AI agents (Claude Code, Gemini CLI, Replit Agent) coordinate to prevent file corruption and ensure the right tool is used for each task.

---

## 🚀 Routing Guide
When you receive a request, check if it matches your specialty. If not, suggest the correct agent.

| Task Category | Primary Agent | Why |
|---------------|---------------|-----|
| **Backend / Logic** | Claude Code | Complex reasoning, database ops, bot commands |
| **Frontend / UI** | Gemini CLI | Design, CSS, templates, visual identity |
| **Ops / Publish** | Replit Agent | Deployment tools, workflow management |
| **Hotfixes** | Any | Quick debugging, minor text edits |

---

## 🔒 File Locking Protocol
To prevent corruption, only one agent should edit a file at a time.

### Step 1: Check Locks
Before editing any file, read `WORKING_FILES.md`. If your target file is listed:
- **STOP** and alert the user.
- Wait until the file is released.

### Step 2: Acquire Lock
Before you start making changes:
1. Add the file path to `WORKING_FILES.md` under "Currently Locked".
2. Include your Agent ID (Claude/Gemini/Replit) and a brief task summary.

### Step 3: Release Lock
When you finish the task and verify the changes:
1. Move the entry to "Recently Released" in `WORKING_FILES.md`.
2. Delete the oldest released entries if the list gets too long.

---

## 🛑 FATAL ARCHITECTURE RULES (DO NOT IGNORE)
1. **Architectural Separation**: Web routes strictly go in `web/routes/`, SQL/Business logic in `web/utils/`, and Discord commands in `bot/cogs/`. Never dump raw functionality into `app.py` or `discord_runner.py`.
2. **Demo Server Sandboxing**: Always use `is_demo_server(guild_id)` to sandbox mutations. Return fake success messages and NEVER execute destructive DB queries for the demo server.
3. **No Flask/Bot DB Cross-Contamination**: Flask routes MUST use Flask's `get_db()` pool. NEVER call a `bot_core.py` function from a Flask route if it opens a bot DB connection (causes Gunicorn Worker Timeout).
4. **Discord UI Persistence**: Interactive UI components (Buttons, Dropdowns) MUST use Discord.py Persistent Views registered in `bot.setup_hook()`. NEVER use global `on_interaction` listeners for buttons.
5. **Discord Cog Structure**: Context menus MUST be defined as global async functions outside of the `commands.Cog` class.
6. **Async Email Queue**: NEVER block or wait on email sends in a route. Always use `queue_email()`, handled asynchronously by the scheduler.
7. **Python Namespaces**: NEVER name a script identical to a package directory (e.g. `bot.py` next to `bot/`).
8. **Agent Protocol**: Never skip the lock check (`WORKING_FILES.md`). Update `CURRENT_TASK.md` so the next agent has context. Commit frequently. When switching agents, ask "Give me a briefing on CURRENT_TASK.md".
