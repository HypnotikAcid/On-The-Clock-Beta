# Overview
**Time Warden** is the professional Discord timeclock ecosystem, featuring the flagship **"On the Clock"** bot and dashboard.

# Two-Phase Workflow (CRITICAL)
**Trigger Prompt** (use in Plan Mode):
> "Read replit.md first, then plan this request. Split tasks by Quick Edit vs Build. STOP after planning."

1. **Plan Mode**: Create task list (Quick Edit vs Build) -> **STOP & WAIT**.
2. **Quick Edit Mode**: Execute targeted tasks -> **STOP & WAIT**.
3. **Build Mode**: Execute complex tasks -> **FINISH**.

# Documentation Index
| Topic | File | Usage |
|-------|------|-------|
| **Feature Plans** | `docs/plans/*.md` | Read when starting specific feature work. |
| **Lessons Learned** | `docs/lessons-learned.md` | Read before making ANY code changes. |
| **Architecture** | `docs/architecture.md` | System design and database logic. |
| **Rebrand** | `docs/rebrand-notes.md` | Branding and domain strategy. |

# Quick Reference
- **Demo Server ID**: `1419894879894507661` (Auto-resets daily).
- **Primary Color**: Cyan (#00FFFF) | **Theme**: Neon Cyber.
- **Retentions**: Free (24h), Premium (30d), Pro (30d+Kiosk).
- **Core Files**: `app.py` (Web), `bot.py` (Discord), `entitlements.py` (Tiers).

# Building Instructions
- Use `Entitlements.get_guild_tier()` for all gating.
- Allow all hosts (`allowedHosts: true`) in dev configs.
- Bind frontend to `0.0.0.0:5000`.
- Always verify `replit.md` before and after work.
