# Overview
**Time Warden** is the professional Discord timeclock ecosystem, featuring the flagship **"On the Clock"** bot and dashboard.

# Two-Phase Workflow (CRITICAL)
**Trigger Prompt** (use in Plan Mode):
> "Read replit.md first, then plan this request. Split tasks by Fast vs Autonomous. STOP after planning."

## Modes
- **Plan Mode**: Discussion and task planning only. No code changes.
- **Build Mode**: Contains two agent tool settings:
  - **Fast**: Lightweight changes, quickly (simple edits, file moves, small fixes).
  - **Autonomous**: Complex features, multi-file changes, deep logic.

## Execution Flow
1. **Plan Mode** → Read `replit.md` → Read `docs/lessons-learned.md` → Create task list split by Fast vs Autonomous → **STOP & WAIT**.
2. **Build Mode (Fast)** → Execute ONLY Fast tasks → **STOP & SAY**: "Fast tasks complete. Switch to Autonomous when ready."
3. **Build Mode (Autonomous)** → Execute complex tasks → **FINISH**.

## Rules
- ALWAYS check `docs/lessons-learned.md` before editing/adding ANY code.
- NEVER mix Fast and Autonomous tasks in one phase.
- Update `docs/lessons-learned.md` after discovering new patterns or fixing bugs.

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
