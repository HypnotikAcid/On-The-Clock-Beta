# Lessons Learned & Coding Patterns

## Workflow & Discipline
- **Mandatory Pre-Check**: ALWAYS read `docs/lessons-learned.md` before editing or adding ANY code.
- **Plan Mode Workflow**: Split all tasks into **Fast** (lightweight) vs **Autonomous** (complex).
- **Execution Order**: Fast tasks first → STOP → Autonomous tasks after user confirms.
- **Post-Work**: Update this file if new lessons are learned.

## Development & Security
- **Flask Route Uniqueness**: Never define the same route decorator twice.
- **Database Guards**: Use process-level flags for one-time initialization.
- **SQL Injection**: Always use parameterized statements.
- **XSS Prevention**: Use `escapeHtml()` for user data.
- **SSRF Protection**: Strict validation for `guild_id` in Bot API requests.
- **AI Auth Bugs**: AI-generated authentication code often has bypass vulnerabilities - ALWAYS manually review auth logic.

## UI/UX & Identity
- **Visual Identity**: "Neon Cyber" theme with animated CSS clock and cyan matrix rain.
- **Accessibility**: Decorative elements must have `aria-hidden="true"`.
- **Mobile First**: Test interactive components (accordions, kiosks) on mobile viewports.
- **Component Persistence**: Use `localStorage` for visual preferences (theme toggles).
- **Top-Right Stacking**: Matrix Toggle -> Coffee Button -> Demo Panel.

## Features & Logic
- **Tier Terminology**: Always use `Entitlements.get_guild_tier()`.
- **Admin Calendar**: Guard with `{% if active_page == 'calendar' %}`.
- **Demo Server**: ID `1419894879894507661` auto-resets daily at midnight UTC.
- **Kiosk Customization**: Icons/colors only show when clocked in.

## Multi-Agent Coordination
- **Session Continuity**: Update `CURRENT_TASK.md` during complex work for handoff between agents.
- **Git Discipline**: CLI agents (Claude Code, Gemini) don't auto-commit - commit frequently.
- **File Isolation**: Don't have multiple agents edit the same files simultaneously.
- **Briefing Request**: When switching agents, ask "Give me a briefing on CURRENT_TASK.md".
- **Context Files**: All agents should read `replit.md` first, then this file.
- **Progressive Disclosure**: Don't overload context - point to specific docs when needed.
- **Date Awareness**: AI may think it's 2024 - verify current date if time-sensitive.

## CSV Report Usernames
- **Three-tier fallback**: employee_profiles.display_name → employee_profiles.full_name → Discord API fetch → "User [ID]"
- **Sanitize commas**: Replace commas in names with spaces for CSV safety.
- **LEFT JOIN**: Always use LEFT JOIN with employee_profiles to handle missing profiles.
