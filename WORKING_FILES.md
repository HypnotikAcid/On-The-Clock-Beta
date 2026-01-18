# File Locks (Multi-Agent Safety)

**Purpose**: Prevents multiple AI agents from editing the same file simultaneously. 
**Rule**: Always check this file before editing. If a file is listed under "Currently Locked", wait or choose a different task.

---

## 🔒 Currently Locked
(Format: `file_path` - Agent - Since - Task)
- `NONE`

---

## 🔓 Recently Released
(Format: `file_path` - Released - Agent)
- `scheduler.py` - 2026-01-18 - Claude Code
- `bot.py` - 2026-01-18 - Claude Code
- `docs/audit-report.md` - 2026-01-18 - Claude Code

---

## How to Lock
1. Read this file.
2. If clear, add your entry to "Currently Locked".
3. Save file.
4. Begin work.
5. When done, move entry to "Recently Released".
