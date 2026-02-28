# Claude Code Project Instructions

**Project**: Time Warden - Discord Timeclock Bot & Dashboard

---

## Mandatory Pre-Work (Every Session)
1. Read `replit.md` for project overview
2. Read `docs/lessons-learned.md` for coding patterns and rules
3. Read `WORKING_FILES.md` to check file locks
4. Read `CURRENT_TASK.md` for session context

---

## Your Role
You are the **Backend / Logic Specialist**:
- Bot commands (`bot.py`)
- Database operations
- API routes (`app.py`)
- Scheduler jobs (`scheduler.py`)
- Tier/entitlements logic (`entitlements.py`)

**Not your role** (suggest Gemini for these):
- HTML templates, CSS styling
- UI/UX design work
- Visual identity changes

---

## File Locking Protocol
Before editing ANY file:
1. Check `WORKING_FILES.md` for locks
2. If locked → STOP and alert user
3. If clear → Add your lock, then work
4. When done → Release lock in `WORKING_FILES.md`

---

## 🛑 FATAL ARCHITECTURE RULES (DO NOT IGNORE)
1. **Architectural Separation**: Web routes strictly go in `web/routes/`, SQL/Business logic in `web/utils/`, and Discord commands in `bot/cogs/`. Never dump raw functionality into `app.py` or `discord_runner.py`.
2. **Demo Server Sandboxing**: Always use `is_demo_server(guild_id)` to sandbox mutations. Return fake success messages and NEVER execute destructive DB queries for the demo server.
3. **No Flask/Bot DB Cross-Contamination**: Flask routes MUST use Flask's `get_db()` pool. NEVER call a `bot_core.py` function from a Flask route if it opens a bot DB connection (causes Gunicorn Worker Timeout).
4. **Discord UI Persistence**: Interactive UI components (Buttons, Dropdowns) MUST use Discord.py Persistent Views registered in `bot.setup_hook()`. NEVER use global `on_interaction` listeners for buttons.
5. **Discord Cog Structure**: Context menus MUST be defined as global async functions outside of the `commands.Cog` class.
6. **Async Email Queue**: NEVER block or wait on email sends in a route. Always use `queue_email()`, handled asynchronously by the scheduler.
7. **Python Namespaces**: NEVER name a script identical to a package directory (e.g. `bot.py` next to `bot/`).
8. **General Protocol**: Never delete code without explaining why. Always use parameterized SQL. Commit frequently. Update `CURRENT_TASK.md` for handoffs.


## Quick Reference
| Item | Value |
|------|-------|
| Demo Server ID | `1419894879894507661` |
| Primary Color | Cyan (#00FFFF) |
| Theme | Neon Cyber |
| Free Retention | 24 hours |
| Premium Retention | 30 days |

---

## Commands
- `/project:quick` - Show workflow checklist
