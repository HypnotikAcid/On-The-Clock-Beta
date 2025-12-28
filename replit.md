# Overview

"On the Clock 2.0" is a professional Discord timeclock bot for businesses, offering subscription management, robust error handling, and enterprise-grade reliability. It provides an easy-to-use time tracking solution within Discord, featuring a simplified two-tier subscription model (Dashboard Premium + optional Pro Retention), Stripe payment integration, role-based access control, and an informative landing page with pricing comparison. Its primary purpose is to streamline time tracking for businesses using Discord.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Bot Framework
- **Technology**: Discord.py (version 2.3+)
- **Language**: Python 3.x
- **Architecture Pattern**: Event-driven bot architecture, running the Discord bot and an internal HTTP API server within a Gunicorn-managed Flask application.

## Design Decisions
- **Discord.py**: Chosen for features, active development, and community support.
- **Event-Driven Design**: Utilizes async/await for concurrent event processing.
- **Timezone Awareness**: Ensures correct time handling using `tzdata`.
- **UI/UX**: Features a static landing page and a dashboard for server-specific settings with a tile-based layout, secured by Discord OAuth.
- **Role-Differentiated Dashboard**: The dashboard provides different experiences based on user role:
  - **Admin Landing**: Shows "Managed Servers" - servers where user has admin permissions. Full access to all settings.
  - **Employee Landing**: Shows "My Workplaces" - servers where user has been assigned an employee role. Limited view of their own time data.
  - **View Mode Toggle**: Admins see a toggle in the top-right to switch between "Admin" and "Employee" views to preview employee experience.
  - **Access Level Detection**: `verify_guild_access()` function supports `allow_employee=True` flag to permit employee access on specific endpoints.
  - **On the Clock Page**: Employee-only view showing co-worker avatars of who's currently clocked in (simple, privacy-respecting view with minimal data). Admins see full Employee Status with detailed stats and clock-out buttons.
- **Subscription Management**: Simplified two-tier pricing model:
  - **Free Tier**: 24-hour data retention, basic clock in/out, limited dashboard
  - **Dashboard Premium** ($5 one-time): 7-day retention, full dashboard access, CSV reports, time adjustments, email automation
  - **Pro Retention** ($5/month add-on): 30-day retention for long-term tracking
  - Legacy: All existing $5 purchasers automatically upgraded to 7-day retention
- **Concurrent Safety**: Achieved through guild-level locking, PostgreSQL connection pooling with SSL validation, and automatic transaction management.
- **Ephemeral Interface System**: Provides new interfaces via the `/clock` command to resolve interaction timeout issues.
- **Custom Jinja2 Permission Filter**: Addresses Jinja2's lack of bitwise operator support for Discord permission checking.
- **Secure Error Handling**: Employs generic user-facing messages, detailed server-side logging, and redaction of sensitive information.
- **Database-Backed Sessions**: Ensures session persistence across restarts.
- **Bot as Boss Architecture**: All role management changes are routed through the bot's HTTP API, establishing the bot as the single source of truth.
- **Email Automation**: APScheduler handles automated email tasks (clock-out, scheduled reports, pre-deletion warnings).
- **Webhook Monitoring & Owner Notifications**: Comprehensive logging of webhook events (Stripe payments, cancellations, failures) with automatic DM notifications to the bot owner.
- **Owner Dashboard**: A web-based owner-only dashboard (`/owner` route) provides visibility into servers, subscriptions, active sessions, and webhook events, including manual subscription management capabilities.
- **Owner Broadcast System (December 2025)**: Allows bot owner to send announcements to all servers:
  - **Dashboard UI**: Broadcast section in `/owner` dashboard with title, message, and target filter (all/paid/free servers)
  - **Preview Mode**: Preview embed before sending
  - **/owner_broadcast Command**: Discord slash command for direct broadcasting
  - **API Endpoint**: `/api/owner/broadcast` for programmatic access
  - **Smart Channel Selection**: Tries log channel first, then system channel, then first available text channel
  - **Async Bridge Pattern**: Uses `asyncio.run_coroutine_threadsafe` to call bot functions from Flask
- **Mobile Device Restriction**: Server administrators can restrict clock-in/out to desktop/web browser only.
- **Bulletproof Button Persistence (December 2025)**: Enterprise-grade button reliability:
  - **Single `/clock` Command**: Unified timeclock interface with 6 buttons (Clock In, Clock Out, My Adjustments, My Hours, Support, Upgrade)
  - **TimeclockHubView**: Consolidated hub with stable custom_ids (tc:clock_in, tc:clock_out, tc:adjustments, tc:my_hours, tc:support, tc:upgrade)
  - **Stable Custom IDs**: All button custom_ids use "tc:" prefix for consistent routing
  - **timeout=None**: Views never expire
  - **setup_hook() Registration**: Views registered on bot startup via bot.add_view()
  - **Global on_interaction Fallback**: Catches orphaned buttons after restart and routes to correct handlers
  - **Fast ACK Pattern**: All handlers call defer() immediately before database work
- **Signed Deep-Link System**: Secure Discord-to-Dashboard navigation:
  - **generate_dashboard_deeplink()**: Creates signed URLs with timestamp and SHA256 signature
  - **/deeplink Route**: Flask validates signature, checks 24-hour expiry, routes to correct tab
  - **Session Intent Storage**: Preserves user navigation intent through OAuth flow
- **Context Menu Commands**: Right-click user actions for admins:
  - **View Hours**: See user's 7-day hours summary
  - **Force Clock Out**: End user's active session
  - **Ban from Timeclock**: 24-hour ban from clock functions
- **Pre-Deletion Warning System**: Hourly scheduler job sends DMs to free tier admins before 24-hour data deletion with upgrade CTA
- **Database Migrations**: Automatic schema migrations on startup using `migrations.py` with idempotent `CREATE TABLE IF NOT EXISTS` statements.
- **Employee Status Cards**: The dashboard displays active employees with hours worked (today/week/month). Admin view includes manual clock-out buttons to force-end active sessions.
- **Ban Management Tab**: Dedicated sidebar tab (admin-only) for viewing and managing banned users, separate from Server Overview.
- **Beta Settings Tab**: Experimental features section with Admin and Employee sub-sections. Admin settings (like Mobile Device Restriction) are hidden from employees. Includes prominent reliability disclaimer.
- **Time Adjustment Requests**: Employees can request time corrections, which admins can approve/deny via the dashboard with a before/after comparison.
- **Role-Based Interactive Calendar**: The Time Adjustments section features different views based on user role:
  - **Admin View**: Calendar displays pending request counts per day (color intensity: amber for 1-2, red for 3+). Clicking a day opens a modal listing all pending requests with Approve/Deny buttons. Includes collapsible "Past Requests" section showing resolved requests across the guild.
  - **Employee View**: Calendar displays personal work sessions with status indicators. Active sessions show green dot; clicking a day opens edit modal. "Clock Out Now" feature detects active sessions and allows clocking out from dashboard before making adjustments.
- **Calendar Data Persistence**: Adjustment requests are stored in `time_adjustment_requests` table with session_date tracking, ensuring persistence through republishing. Status updates are reflected on the calendar when admin approves/denies.
- **Real-Time Calendar Updates**: After approve/deny actions, both the pending requests list and admin calendar refresh automatically (1-second delay for UI feedback).
- **Encoding Best Practices**: Uses HTML entities (`&rarr;`, `&larr;`) for special characters in templates for cross-platform compatibility.

## Security Configuration
- **Code Analysis**: Semgrep rules for static analysis and secret management.
- **Stripe Security**: Webhook signature verification and secure API key management.
- **Data Privacy**: Automated data purging based on subscription tier and cancellation.
- **Input Validation**: Robust validation for roles and timezones.
- **Authorization Checks**: Verification of bot presence and user admin access.
- **Rate Limiting & Spam Detection**: In-memory tracking with 30-second windows and 24-hour bans for repeat offenders.
- **Purge Command Security**: `/purge` command is restricted to server OWNERS and uses a safe purge function for session data.
- **Employee Role Persistence**: Dashboard role changes are managed through the bot's HTTP API with `BOT_API_SECRET` authentication.
- **SSRF Protection**: Bot API requests use `BOT_API_BASE_URL` constant with strict guild_id validation (digits only, max 20 chars).
- **XSS Prevention**: Dashboard JavaScript uses `escapeHtml()` for user data in HTML context and data attributes with `addEventListener` instead of inline event handlers.
- **SQL Injection Prevention**: All database queries use parameterized statements with `%s` placeholders.
- **Environment Variables**: Stripe price IDs configured via environment variables (`STRIPE_PRICE_BOT_ACCESS`, `STRIPE_PRICE_RETENTION_7DAY`, `STRIPE_PRICE_RETENTION_30DAY`).

# External Dependencies

## Core Libraries
- **discord.py**: Primary library for Discord API interaction.
- **tzdata**: Provides timezone data for Python.
- **psycopg2-binary**: PostgreSQL database adapter with connection pooling.
- **aiohttp**: Used for the bot's internal HTTP API server.
- **APScheduler**: Asynchronous job scheduler.
- **pytz**: Timezone library used by APScheduler.

## Development Tools
- **Semgrep**: Static analysis security scanner.

## Discord Integration
- **Discord API**: For real-time communication and operations.
- **Discord OAuth 2.0**: For secure user authentication and dashboard features.

## Payment Integration
- **Stripe**: Handles subscriptions and payments, processing `checkout.session.completed` and `customer.subscription.deleted` webhooks.

## Database
- **PostgreSQL**: Production database with persistent connection pooling (ThreadedConnectionPool).
- **Connection Management**: Uses `@contextmanager` with `FlaskConnectionWrapper` for automatic commit/rollback.
- **Row Access**: All queries use `RealDictCursor` for named column access (e.g., `row['column']`).
- **SSL Connection Handling**: Includes built-in validation and retry logic for stale SSL connections.
- **Query Syntax**: Utilizes PostgreSQL-specific features like `%s` placeholders, `INSERT ... ON CONFLICT DO UPDATE`, and `NOW()`.

# Known Limitations & Future Improvements

## Documented TODO Items
- **Discord API Member Roles** (app.py line 801): Consider implementing Discord API call to fetch member roles in real-time if role caching becomes stale.
- **Email Table Migration** (app.py line 2148): Email recipient fetch currently returns empty array - email table query implementation may need review.
- **Automatic Refund Logic** (bot.py lines 967, 1047): When certain payment failures occur, automatic refund processing could be implemented instead of manual intervention.

## Code Review Notes (December 2025)
- All onclick handlers now properly exported to window scope for modal functionality
- Calendar day click handlers work for both admin and employee views
- Mobile responsiveness optimized with touch-friendly targets (70px calendar days, 44px minimum interactive elements)
- All database queries use parameterized statements for security

## Email Fail-Safe System (December 2025)
- **Backend Validation**: Email settings API endpoints (`api_update_email_settings`, `api_update_work_day_time`) reject enabling features if no email recipients are configured
- **Auto-Disable Logic**: When the last email recipient is removed via `api_remove_email_recipient`, all email-dependent settings are automatically disabled (auto_send_on_clockout, auto_email_before_delete, work_day_end_time)
- **Frontend State Management**: `updateEmailControlsState()` function disables/enables toggles and time picker based on recipient count
- **Inline Guidance**: Warning banner (`email-settings-guidance`) displayed when no recipients configured, hidden when recipients exist
- **Preload Count**: `email_recipient_count` included in `get_guild_settings()` for initial state synchronization