# File Locks (Multi-Agent Safety)

**Purpose**: Prevents multiple AI agents from editing the same file simultaneously. 
**Rule**: Always check this file before editing. If a file is listed under "Currently Locked", wait or choose a different task.

---

## 🔒 Currently Locked
(Format: `file_path` - Agent - Since - Task)
(No active locks)

---

## 🔓 Recently Released
(Format: `file_path` - Released - Agent)
- `bot.py` - Gemini - 2026-02-23 - Ghost Employee Auto-Prune
- `app.py` - Gemini - 2026-02-23 - Demo Server DB/Theme Unblocking
- `templates/kiosk.html` - Gemini - 2026-02-23 - Kiosk CSS Profile Color Fix
- `app.py` - Gemini - 2026-02-19 - Subscription Cancellation Flow
- `bot.py` - Gemini - 2026-02-19 - Subscription Cancellation Flow
- `templates/dashboard_pages/server_overview.html` - Gemini - 2026-02-19 - Cancel Button
- `bot.py` - 2026-01-26 - Claude Code (Enhanced demo role switcher with auto-timeclock)
- `bot.py` - 2026-01-26 - Claude Code (Add debug logging to setup_demo_roles)
- `templates/kiosk.html` - 2026-01-26 - Claude Code (Revert theme clock-in requirement)
- `bot.py` - 2026-01-26 - Claude Code (Dual command sync + remove auto-role assignment)
- `app.py` - 2026-01-26 - Claude Code (Fix My Info API unit mismatch: seconds→minutes)
- `templates/` - 2026-01-25 - Gemini (Phase 2 complete: UI streamlining, purchase flow, mobile polish)
- `email_utils.py` - 2026-01-25 - Claude Code (kiosk security & performance fixes)
- `bot.py` - 2026-01-18 - Claude Code (dead code removal)
- `docs/audit-report.md` - 2026-01-18 - Claude Code (updated with resolutions)

---

## How to Lock
1. Read this file.
2. If clear, add your entry to "Currently Locked".
3. Save file.
4. Begin work.
5. When done, move entry to "Recently Released".