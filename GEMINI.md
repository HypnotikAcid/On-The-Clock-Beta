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

## 📝 Rules
- Follow "Neon Cyber" theme (Cyan #00FFFF, Matrix rain).
- Check `docs/lessons-learned.md` and `docs/architecture_manifesto.md` before any code changes.
- Always verify accessibility (`aria-hidden="true"` on decor).
- **NEVER create a Python file and a directory with the exact same name** (e.g. `bot.py` and `bot/`). This causes fatal `ModuleNotFoundError` collisions in Python 3.
- **Discord Cogs (`bot/cogs/`)**: Context menus MUST be defined as global async functions outside of the `commands.Cog` class, or they will crash the bot.
- **Flask/Bot Bridge**: Flask API routes (`web/routes/`) MUST use Flask's `get_db()` connection pool. NEVER call a `bot_core.py` function from Flask if it uses the bot's own `db()` pool, or it will trigger a fatal Gunicorn timeout.
- Commit after significant changes (CLI doesn't auto-commit).

---

## 📂 Key Locations
- UI Templates: `templates/*.html`
- Visual Assets: `attached_assets/*`
- Branding: `docs/rebrand-notes.md`
