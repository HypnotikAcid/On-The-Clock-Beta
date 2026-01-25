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

## Key Rules
- Never delete code without explaining why and getting approval
- Use `Entitlements.get_guild_tier()` for all tier checks
- Always use parameterized SQL statements
- Manually review any auth logic you write (AI auth bugs are common)
- Update `CURRENT_TASK.md` during complex work for handoff
- Commit frequently with `git add . && git commit -m "message"`
- **Parallel Workflow**: If Gemini can work safely in parallel (UI/templates only, no backend conflicts), ALWAYS provide a handoff prompt for Gemini FIRST so user can start it immediately while you work on backend tasks

---

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
