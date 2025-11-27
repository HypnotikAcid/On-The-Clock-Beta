# Overview

"On the Clock 1.5" is a professional Discord timeclock bot designed for businesses, offering subscription management, robust error handling, and enterprise-grade reliability. The project provides an easy-to-use time tracking solution for Discord communities, featuring a three-tier subscription model (Free/Basic/Pro), Stripe payment integration, role-based access control, and a simple, unauthenticated landing page. Its purpose is to streamline time tracking within Discord, providing a valuable tool for businesses.

# User Preferences

Preferred communication style: Simple, everyday language.

# Recent Fixes (November 27, 2025)

## Critical Encoding Fixes Applied
1. **UTF-16 LE Encoding Corruption (app.py)** - Converted corrupted UTF-16 LE file with 138,000+ null bytes to proper UTF-8 UTF-8
2. **Dashboard Template Recovery** - Restored dashboard.html from git commit 1303f18 (recovered full 704-line version)
3. **SQL Query Table References** - Fixed bot.py queries to use `employee_profiles` table instead of nonexistent `users` table:
   - `get_active_employees_with_stats()` - Updated table join and column references
   - `get_pending_adjustments()` - Updated table join and privacy settings references
4. **UTF-8 BOM Removal** - Removed BOM markers from templates/dashboard.html and static/css/dashboard.css
5. **Unicode Character Encoding** - Replaced literal Unicode arrows with HTML entities for reliable rendering:
   - Right arrow: `→` → `&rarr;` (in dashboard-roles.js)
   - Left arrow: `←` → `&larr;` (in dashboard.html and server_selection.html)

**Status**: ✅ All encoding issues resolved. App fully operational with proper character rendering.

# System Architecture

## Bot Framework
- **Technology**: Discord.py (version 2.3+)
- **Language**: Python 3.x
- **Architecture Pattern**: Event-driven bot architecture.
- **Startup Process**: Gunicorn runs Flask app, Discord bot runs in a daemon thread, starting both the Discord bot and an internal HTTP API server.

## Design Decisions
- **Discord.py**: Chosen for its features, active development, and community support.
- **Event-Driven Design**: Leverages async/await for concurrent event processing.
- **Timezone Awareness**: Ensures correct time handling using `tzdata`.
- **UI/UX**: Static landing page; dashboard provides server-specific settings with a tile-based layout, protected by Discord OAuth and requiring admin access.
- **Subscription Management**: Three-tier model (Free, 7-day retention, 30-day retention) with a $5 one-time bot access payment per server. Dashboard displays subscription status and upgrade prompts.
- **Concurrent Safety**: Utilizes guild-level locking, PostgreSQL connection pooling with SSL validation, and automatic transaction management.
- **Ephemeral Interface System**: Resolves interaction timeout issues by providing new interfaces via the `/clock` command.
- **Custom Jinja2 Permission Filter**: Addresses Jinja2's lack of bitwise operator support for Discord permission checking.
- **Secure Error Handling**: Generic user-facing messages, detailed server-side logging, and redaction of sensitive information.
- **Database-Backed Sessions**: Ensures session persistence across restarts.
- **Bot as Boss Architecture**: All role management changes flow through the bot's HTTP API, making the bot the single source of truth.
- **Email Automation**: APScheduler handles automated email tasks (clock-out, scheduled reports, pre-deletion warnings).
- **Webhook Monitoring & Owner Notifications**: Comprehensive webhook event logging (Stripe payments, cancellations, failures) with automatic DM notifications to the bot owner.
- **Owner Dashboard**: Web-based owner-only dashboard (`/owner` route) provides visibility into servers, subscriptions, active sessions, and webhook events, with manual subscription management capabilities.
- **Mobile Device Restriction**: Server admins can restrict clock-in/out to desktop/web browser only via dashboard toggle or `/mobile` command.
- **Persistent Button Architecture**: Uses `@discord.ui.button` decorators for persistent buttons with `timeout=None` and registration in `setup_hook()` for 100% button reliability across bot restarts.
- **Database Migrations**: Automatic schema migrations run on startup via `migrations.py` with idempotent `CREATE TABLE IF NOT EXISTS` statements.
- **Employee Status Cards**: Dashboard displays active employees with hours worked (today/week/month) via `get_active_employees_with_stats()` function.
- **Time Adjustment Requests**: Employees can request time corrections; admins see before/after comparison and approve/deny via dashboard.
- **Encoding Best Practices**: Uses HTML entities (&rarr;, &larr;) for special characters to ensure cross-platform compatibility.

## Security Configuration
- **Code Analysis**: Semgrep rules for static analysis and secret management.
- **Stripe Security**: Webhook signature verification and secure API key management.
- **Data Privacy**: Automated data purging based on subscription tier and cancellation.
- **Input Validation**: Robust validation for roles and timezones.
- **Authorization Checks**: Bot presence and user admin access verified.
- **Rate Limiting & Spam Detection**: In-memory tracking with 30-second windows and 24-hour bans for repeat offenders.
- **Purge Command Security**: `/purge` command restricted to server OWNERS only; safe purge function deletes only session data.
- **Employee Role Persistence**: Dashboard role changes through bot's HTTP API with `BOT_API_SECRET` authentication.

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
- **PostgreSQL**: Production database with persistent connection pooling (ThreadedConnectionPool with minconn=1, maxconn=10)
- **Connection Management**: Uses @contextmanager pattern with FlaskConnectionWrapper for automatic commit/rollback
- **Row Access**: All queries use RealDictCursor with named column access (row['column']) instead of positional access (row[0])
- **RealDictRow Unpacking**: NEVER use tuple unpacking on database rows (e.g., `id, value = row`). This unpacks KEYS not VALUES. Always use dictionary access: `id = row['id']`
- **SSL Connection Handling**: Built-in validation and retry logic for stale SSL connections (up to 2 attempts)
- **Query Syntax**: PostgreSQL-specific features including %s placeholders, INSERT ... ON CONFLICT DO UPDATE, and NOW() for timestamps
