# File Locks (Multi-Agent Safety)

**Purpose**: Prevents multiple AI agents from editing the same file simultaneously. 
**Rule**: Always check this file before editing. If a file is listed under "Currently Locked", wait or choose a different task.

---

## 🔒 Currently Locked
(Format: `file_path` - Agent - Since - Task)
- `templates/` - Gemini - 2026-01-18 - UI/Frontend Audit
- `app.py` - Claude Code - 2026-01-25 - Kiosk security & performance fixes
- `email_utils.py` - Claude Code - 2026-01-25 - Kiosk security & performance fixes

---

## 🔓 Recently Released
(Format: `file_path` - Released - Agent)
- `bot.py` - 2026-01-18 - Claude Code (dead code removal)
- `docs/audit-report.md` - 2026-01-18 - Claude Code (updated with resolutions)
- `scheduler.py` - 2026-01-18 - Claude Code
- `bot.py` - 2026-01-18 - Claude Code

---

## How to Lock
1. Read this file.
2. If clear, add your entry to "Currently Locked".
3. Save file.
4. Begin work.
5. When done, move entry to "Recently Released".