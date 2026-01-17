# Multi-Agent Coordination Protocol

**Purpose**: This document defines how different AI agents (Claude Code, Gemini CLI, Replit Agent) coordinate to prevent file corruption and ensure the right tool is used for each task.

---

## 🚀 Routing Guide
When you receive a request, check if it matches your specialty. If not, suggest the correct agent.

| Task Category | Primary Agent | Why |
|---------------|---------------|-----|
| **Backend / Logic** | Claude Code | Complex reasoning, database ops, bot commands |
| **Frontend / UI** | Gemini CLI | Design, CSS, templates, visual identity |
| **Ops / Publish** | Replit Agent | Deployment tools, workflow management |
| **Hotfixes** | Any | Quick debugging, minor text edits |

---

## 🔒 File Locking Protocol
To prevent corruption, only one agent should edit a file at a time.

### Step 1: Check Locks
Before editing any file, read `WORKING_FILES.md`. If your target file is listed:
- **STOP** and alert the user.
- Wait until the file is released.

### Step 2: Acquire Lock
Before you start making changes:
1. Add the file path to `WORKING_FILES.md` under "Currently Locked".
2. Include your Agent ID (Claude/Gemini/Replit) and a brief task summary.

### Step 3: Release Lock
When you finish the task and verify the changes:
1. Move the entry to "Recently Released" in `WORKING_FILES.md`.
2. Delete the oldest released entries if the list gets too long.

---

## 📝 Rules of Engagement
1. **Never skip the lock check.**
2. **Never edit a locked file.**
3. **Always update CURRENT_TASK.md** so the next agent has context.
4. **Commit frequently** - CLI agents don't auto-commit.
5. **Briefing Request**: When switching agents, ask "Give me a briefing on CURRENT_TASK.md".
