# Overview
"On the Clock 2.0" is a professional Discord timeclock bot designed for businesses. It offers a streamlined time tracking solution within Discord, featuring subscription management, robust error handling, and enterprise-grade reliability. Key capabilities include a simplified two-tier subscription model, Stripe payment integration, role-based access control, and an informative landing page. The project aims to provide an easy-to-use and reliable time tracking system for businesses leveraging Discord.

# User Preferences
Preferred communication style: Simple, everyday language.

# System Architecture
## Bot Framework
- **Technology**: Discord.py (version 2.3+)
- **Language**: Python 3.x
- **Architecture Pattern**: Event-driven bot architecture, integrating the Discord bot and an internal HTTP API server within a Gunicorn-managed Flask application.

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
  - `/dashboard/server/<id>/clock` - On the Clock view (employee)
  - `/dashboard/server/<id>/adjustments` - Time adjustment requests (both roles)
  - `/dashboard/server/<id>/calendar` - Admin calendar for editing entries (admin-only)
  - `/dashboard/server/<id>/bans` - Ban management (admin-only)
  - `/dashboard/server/<id>/beta` - Beta settings
  - `/owner` - Owner dashboard
- **Template Inheritance**: All dashboard pages extend `dashboard_base.html` for consistent sidebar, header, and security checks.
- **Shared Utilities**: Common JavaScript functions in `dashboard-common.js` (escapeHtml, fetchWithTimeout, notifications, formatting).
- **Subscription Management**: A simplified two-tier pricing model includes a Free Tier, Dashboard Premium, and an optional Pro Retention add-on.
- **Concurrent Safety**: Achieved through guild-level locking, PostgreSQL connection pooling with SSL validation, and automatic transaction management.
- **Ephemeral Interface System**: Resolves interaction timeout issues by providing new interfaces via the `/clock` command.
- **Bot as Boss Architecture**: All role management changes are routed through the bot's HTTP API, establishing the bot as the single source of truth for Discord roles.
- **Email Automation**: APScheduler handles automated email tasks (e.g., clock-out reminders, scheduled reports, pre-deletion warnings).
- **Owner Dashboard**: A web-based dashboard (`/owner` route) provides the bot owner with visibility into servers, subscriptions, active sessions, webhook events, and manual subscription management. It also includes an Owner Broadcast System for sending announcements to servers.
- **Bulletproof Button Persistence**: A unified `/clock` command interface with stable custom IDs and `timeout=None` ensures button reliability across bot restarts, using a global `on_interaction` fallback.
- **Signed Deep-Link System**: Secure Discord-to-Dashboard navigation using signed URLs with timestamp and SHA256 signatures, preserving user intent through the OAuth flow.
- **Context Menu Commands**: Right-click user actions for admins, including viewing hours, forcing clock-out, and temporarily banning users from clock functions.
- **Pre-Deletion Warning System**: Hourly scheduler job DMs free-tier admins before data deletion with upgrade incentives.
- **Database Migrations**: Automatic schema migrations on startup using `migrations.py`.
- **Employee Status Cards**: Dashboard displays active employees with current hours, including manual clock-out buttons for admins.
- **Time Adjustment Requests**: Employees can submit time correction requests, which admins can approve/deny via an interactive, role-based calendar in the dashboard.
- **Employee Onboarding System**: Automated welcome DMs and first-time `/clock` guides for new employees detected via role changes.
- **Broadcast Channel Configuration**: Admins can configure which text channel receives bot announcements via the dashboard Timezone Settings section. Falls back to system channel, then first available text channel.

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