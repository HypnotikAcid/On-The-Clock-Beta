# Overview
"On the Clock 2.0" is a professional Discord timeclock bot designed for businesses. It offers a streamlined time tracking solution within Discord, featuring subscription management, robust error handling, and enterprise-grade reliability. Key capabilities include a simplified two-tier subscription model, Stripe payment integration, role-based access control, and an informative landing page. The project aims to provide an easy-to-use and reliable time tracking system for businesses leveraging Discord.

# User Preferences
Preferred communication style: Simple, everyday language.

# Agent Instructions & Workflow
- **Version Update Workflow**: Whenever a task is completed, update `version.json` immediately. Move completed items from the conversation/todo list to `recent_updates` and increment the version number. This ensures the landing page roadmap is always current.
- **Fast Mode Safety**: Only perform operations in Fast mode if they are 100% safe and straightforward (small CSS tweaks, minor copy changes, simple JSON updates). If a task requires complex logic, multi-file refactoring, or deep debugging, STOP and ask the user to switch to Autonomous mode. Never proceed with uncertain changes in Fast mode.

# Lessons Learned & Best Practices
| Mistake | Fix | Rule Going Forward |
|---------|-----|-------------------|
| Bot API auth used wrong header (`X-Bot-API-Secret`) | Changed to `Authorization: Bearer` format | Always use standard Bearer token format for internal APIs |
| Absolute positioned buttons overlapped on mobile | Use flex layout with proper spacing | Avoid absolute positioning for interactive elements |
| Per-row SQL subqueries slow with many employees | Refactored to CTE (Common Table Expression) | Use CTEs or JOINs for aggregate counts, never per-row subqueries |
| `querySelector` grabbed wrong element when multiple exist | Scope to parent: `modal.querySelector('.class')` | Always scope selectors to their container |
| Inactivity timer logged out users while typing email | Pause timer when modals are open | Disable auto-logout during user input |
| Email saved to one column, not found later | Update both `email` and `timesheet_email` columns | Keep related columns in sync |
| Alert badge logic inconsistent between list and detail views | Unified `has_alerts` calculation across all endpoints | Define alert conditions once, reuse everywhere |

# System Architecture
## Bot Framework
- **Technology**: Discord.py (version 2.3+)
- **Language**: Python 3.x
- **Architecture Pattern**: Event-driven bot architecture, integrating the Discord bot and an internal HTTP API server within a Gunicorn-managed Flask application.

## Future Vision
- **Mobile-responsive kiosk improvements**: Optimized layouts for smaller tablets and phones.
- **Shift scheduling integration**: Ability for admins to set expected shifts and track attendance against them.
- **Payroll export features**: Native integrations with common payroll providers.
- **Multi-language support**: Localizing the dashboard and bot for global teams.

## Design Decisions
- **UI/UX**: Features a static landing page and a route-based dashboard architecture secured by Discord OAuth. The dashboard offers role-differentiated views for Admins (full access) and Employees (limited view of personal data).
- **Route-Based Dashboard Architecture**: Dashboard is split into dedicated routes for better performance and deep linking:
  - `/dashboard` - My Servers hub (admin/employee workplaces)
  - `/dashboard/server/<id>` - Server Overview
  - `/dashboard/server/<id>/admin-roles` - Admin role management (admin-only)
  - `/dashboard/server/<id>/employee-roles` - Employee role management (admin-only)
  - `/dashboard/server/<id>/email` - Email settings (admin-only)
  - `/dashboard/server/<id>/timezone` - Timezone/schedule settings (admin-only)
  - `/dashboard/server/<id>/employees` - Employee status cards (admin-only)
  - `/dashboard/server/<id>/profile/<user_id>` - Employee profile with stats (employee can view own, admin can view all)
  - `/dashboard/server/<id>/clock` - On the Clock view (employee)
  - `/dashboard/server/<id>/adjustments` - Time adjustment requests (both roles)
  - `/dashboard/server/<id>/calendar` - Admin calendar for editing entries (admin-only)
  - `/dashboard/server/<id>/bans` - Ban management (admin-only)
  - `/dashboard/server/<id>/beta` - Beta settings
  - `/owner` - Owner dashboard
- **Employee Profile Page**: Individual profile pages for each employee showing hire date, tenure, total/weekly hours, average stats, achievements. Employees can set their email address. Admins can view all employee profiles.
- **Template Inheritance**: All dashboard pages extend `dashboard_base.html` for consistent sidebar, header, and security checks.
- **Shared Utilities**: Common JavaScript functions in `dashboard-common.js` (escapeHtml, fetchWithTimeout, notifications, formatting).
- **Subscription Management**: A simplified two-tier pricing model includes a Free Tier, Dashboard Premium, and an optional Pro Retention add-on.
- **Concurrent Safety**: Achieved through guild-level locking, PostgreSQL connection pooling with SSL validation, and automatic transaction management.
- **Ephemeral Interface System**: Resolves interaction timeout issues by providing new interfaces via the `/clock` command.
- **Bot as Boss Architecture**: All role management changes are routed through the bot's HTTP API, establishing the bot as the single source of truth for Discord roles.
- **Email Automation**: APScheduler handles automated email tasks (e.g., clock-out reminders, scheduled reports, pre-deletion warnings). Uses a reliable **Email Outbox Pattern** with the `email_outbox` table - emails are queued to the database first, then processed by a background worker every 30 seconds with automatic retry (exponential backoff up to 3 attempts). This ensures emails survive process restarts and network failures.
- **Owner Dashboard**: A web-based dashboard (`/owner` route) provides the bot owner with visibility into servers, subscriptions, active sessions, webhook events, and manual subscription management. It also includes an Owner Broadcast System for sending announcements to servers (with target filters: all, paid, or free servers).
- **Bot Access Notification**: When access is granted (via purchase or manual grant), the bot sends a rich embed to the server with setup instructions, available commands (`/setup`, `/clock`, `/help`), dynamic dashboard link, and data retention info.
- **Bulletproof Button Persistence**: A unified `/clock` command interface with stable custom IDs and `timeout=None` ensures button reliability across bot restarts, using a global `on_interaction` fallback.
- **Signed Deep-Link System**: Secure Discord-to-Dashboard navigation using signed URLs with timestamp and SHA256 signatures, preserving user intent through the OAuth flow.
- **Context Menu Commands**: Right-click user actions for admins, including viewing hours, viewing profile, sending shift reports via email, forcing clock-out, and temporarily banning users from clock functions.
- **Employee Onboarding Button**: Premium-only button on Employee Roles page to send onboarding DMs to all employees with links to their profile pages.
- **Pre-Deletion Warning System**: Hourly scheduler job DMs free-tier admins before data deletion with upgrade incentives.
- **Database Migrations**: Automatic schema migrations on startup using `migrations.py`.
- **Employee Status Cards**: Dashboard displays active employees with current hours, including manual clock-out buttons for admins.
- **Time Adjustment Requests**: Employees can submit time correction requests from dashboard, kiosk, or Discord bot. All adjustments use unified `time_adjustment_requests` table with `source` column tracking origin. Admins approve/deny via an interactive, role-based calendar in the dashboard.
- **Kiosk Time Adjustment Modal**: Kiosk users can edit today's sessions, add missing entries, and submit adjustment requests with required reason. Uses dedicated API endpoints (`/api/kiosk/<guild_id>/employee/<user_id>/today-sessions` and `/api/kiosk/<guild_id>/adjustment`) that integrate with the unified adjustment system.
- **Kiosk Notification System**: Employee cards display a red alert badge when: missing email, pending time adjustment requests, or missing punches (forgot to clock out). After PIN entry, the info panel shows a notifications section with pending requests, recently approved/denied requests, and missing punch alerts. Email modal smartly shows "Send to <email>?" if email is saved, or prompts to set email if not.
- **Employee Onboarding System**: Automated welcome DMs and first-time `/clock` guides for new employees detected via role changes.
- **Broadcast Channel Configuration**: Admins can configure which text channel receives bot announcements via the dashboard Timezone Settings section. Falls back to system channel, then first available text channel.

- **Email Verification System**: When admins add email recipients in dashboard settings, a 6-digit verification code is sent. The email must be verified before receiving notifications. Includes attempt limiting (5 max), code expiration (24 hours), and resend rate limiting (1 minute).
- **Adjustment Notification Emails**: When employees submit time adjustment requests, verified email recipients receive an email notification with request type and a link to review in the dashboard. Emails are sent asynchronously via background threads.

## Security Configuration
- **Code Analysis**: Uses Semgrep for static analysis and secret management.
- **Stripe Security**: Webhook signature verification and secure API key management.
- **Data Privacy**: Automated data purging based on subscription tier and cancellation.
- **Input Validation**: Robust validation for roles and timezones.
- **Authorization Checks**: Verification of bot presence and user admin access.
- **Rate Limiting & Spam Detection**: In-memory tracking with temporary bans for repeat offenders.
- **SSRF Protection**: Bot API requests use strict validation for `guild_id`.
- **XSS Prevention**: Dashboard JavaScript uses `escapeHtml()` and `addEventListener` for user data.
- **SQL Injection Prevention**: All database queries use parameterized statements.
- **Environment Variables**: Sensitive configurations like Stripe price IDs are managed via environment variables.

# External Dependencies
## Core Libraries
- **discord.py**: For Discord API interaction.
- **tzdata**: For timezone data handling.
- **psycopg2-binary**: PostgreSQL database adapter.
- **aiohttp**: For the bot's internal HTTP API server.
- **APScheduler**: For asynchronous job scheduling.

## Discord Integration
- **Discord API**: For real-time communication.
- **Discord OAuth 2.0**: For user authentication and dashboard features.

## Payment Integration
- **Stripe**: For subscription and payment processing, including webhook handling.

## Database
- **PostgreSQL**: Production database with persistent connection pooling and SSL connection handling. Queries use `RealDictCursor` and parameterized statements.
- **Unified Timeclock Schema**: All components (Discord bot, web dashboard, kiosk) use the `timeclock_sessions` table with columns: `session_id`, `guild_id`, `user_id`, `clock_in_time`, `clock_out_time`. Duration is calculated on-demand via `EXTRACT(EPOCH FROM (clock_out_time - clock_in_time))`.
- **Legacy Migration Complete**: The old `sessions` table data has been migrated to `timeclock_sessions` (January 2026).