# Gemini CLI Project Context

**Purpose**: This file is read by Gemini CLI to understand the project structure and coordination protocol.

---

## 🚀 Workflow Quick-Ref

1. **Check Locks**: `Read WORKING_FILES.md`
2. **Lock Files**: `Update WORKING_FILES.md` with your task
3. **Briefing**: `Give me a briefing on CURRENT_TASK.md`
4. **Handoff**: `Update CURRENT_TASK.md` before stopping
5. **Release**: `Update WORKING_FILES.md` when done

---

## 🚀 Agent Roles
- **Gemini**: You are the primary **UI/Frontend & Backend/Logic Specialist**.
- **Claude**: Currently inactive.
- **Replit Agent**: Handles Deployment/Publishing.

---

## 🛑 FATAL ARCHITECTURE RULES (DO NOT IGNORE)
1. **Architectural Separation**: Web routes strictly go in `web/routes/`, SQL/Business logic in `web/utils/`, and Discord commands in `bot/cogs/`. Never dump raw functionality into `app.py` or `discord_runner.py`.
2. **Demo Server Sandboxing**: Always use `is_demo_server(guild_id)` to sandbox mutations. Return fake success messages and NEVER execute destructive DB queries for the demo server.
3. **No Flask/Bot DB Cross-Contamination**: Flask routes MUST use Flask's `get_db()` pool. NEVER call a `bot_core.py` function from a Flask route if it opens a bot DB connection (causes Gunicorn Worker Timeout).
4. **Discord UI Persistence**: Interactive UI components (Buttons, Dropdowns) MUST use Discord.py Persistent Views registered in `bot.setup_hook()`. NEVER use global `on_interaction` listeners for buttons.
5. **Discord Cog Structure**: Context menus MUST be defined as global async functions outside of the `commands.Cog` class.
6. **Async Email Queue**: NEVER block or wait on email sends in a route. Always use `queue_email()`, handled asynchronously by the scheduler.
7. **Python Namespaces**: NEVER name a script identical to a package directory (e.g. `bot.py` next to `bot/`).
8. **Frontend Protocol**: Follow "Neon Cyber" theme (Cyan #00FFFF, Matrix rain). Always verify accessibility (`aria-hidden="true"` on decor). Commit after significant changes.

---

## 📂 Key Locations
- UI Templates: `templates/*.html`
- Visual Assets: `attached_assets/*`
- Branding: `docs/rebrand-notes.md`
