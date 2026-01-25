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

## Email Queue Pattern (2026-01-25)
- **Never block on email sends**: Use `queue_email()` for all email notifications.
- **Benefits**: Automatic retry (3 attempts, exponential backoff), no UI freezing, consistent architecture.
- **Example**: `queue_adjustment_notification_email()` in email_utils.py.
- **Processing**: Scheduler runs `process_email_outbox` every 30 seconds.
- **When to use**: Any email triggered by user action (adjustments, reports, notifications).

## Demo Server Protection (2026-01-25)
- **Demo ID**: `'1419894879894507661'` (string, not int)
- **Helper function**: Use `is_demo_server(guild_id)` for all checks - handles int/string types.
- **Sandboxing pattern**: Dead-end all mutations with fake success messages + demo_note field.
- **Example**: PIN creation, clock in/out, email updates, adjustment submissions all return success but don't modify DB.
- **Read operations**: Allow normal operation (employee lists, session data).
- **Benefits**: Zero risk to production, users see what would happen, marketing demo remains functional.

## Tier Gating (2026-01-25)
- **Feature-level decorators**: Create specific decorators for feature access (e.g., `@require_kiosk_access`).
- **Pattern**: Check demo server first (always allow), then check tier via `Entitlements.get_guild_tier()`.
- **Error responses**: Include `code`, `current_tier`, `required_tier`, and `upgrade_url` for clear UX.
- **Consistency**: Use same tier checking logic as existing `@require_paid_api_access`.
- **Example**: Kiosk requires Pro tier, 11 routes protected with single decorator.
