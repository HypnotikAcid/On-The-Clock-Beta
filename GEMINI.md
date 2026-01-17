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
- **Gemini**: You are the primary **UI/Frontend Specialist**.
- **Claude**: Handles Backend/Database/Logic.
- **Replit Agent**: Handles Deployment/Publishing.

---

## 📝 Rules
- Follow "Neon Cyber" theme (Cyan #00FFFF, Matrix rain).
- Check `docs/lessons-learned.md` before any code changes.
- Always verify accessibility (`aria-hidden="true"` on decor).
- Commit after significant changes (CLI doesn't auto-commit).

---

## 📂 Key Locations
- UI Templates: `templates/*.html`
- Visual Assets: `attached_assets/*`
- Branding: `docs/rebrand-notes.md`
