# Overview

"On the Clock 1.5" is a professional Discord timeclock bot for businesses, offering subscription management, robust error handling, and enterprise-grade reliability. It provides an easy-to-use time tracking solution within Discord, featuring a three-tier subscription model (Free/Basic/Pro), Stripe payment integration, role-based access control, and a simple, unauthenticated landing page. Its primary purpose is to streamline time tracking for businesses using Discord.

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
- **UI/UX**: Features a static landing page and a dashboard for server-specific settings with a tile-based layout, secured by Discord OAuth and requiring admin access.
- **Subscription Management**: Three-tier model (Free, 7-day retention, 30-day retention) with a $5 one-time bot access payment per server. The dashboard displays subscription status and upgrade prompts.
- **Concurrent Safety**: Achieved through guild-level locking, PostgreSQL connection pooling with SSL validation, and automatic transaction management.
- **Ephemeral Interface System**: Provides new interfaces via the `/clock` command to resolve interaction timeout issues.
- **Custom Jinja2 Permission Filter**: Addresses Jinja2's lack of bitwise operator support for Discord permission checking.
- **Secure Error Handling**: Employs generic user-facing messages, detailed server-side logging, and redaction of sensitive information.
- **Database-Backed Sessions**: Ensures session persistence across restarts.
- **Bot as Boss Architecture**: All role management changes are routed through the bot's HTTP API, establishing the bot as the single source of truth.
- **Email Automation**: APScheduler handles automated email tasks (clock-out, scheduled reports, pre-deletion warnings).
- **Webhook Monitoring & Owner Notifications**: Comprehensive logging of webhook events (Stripe payments, cancellations, failures) with automatic DM notifications to the bot owner.
- **Owner Dashboard**: A web-based owner-only dashboard (`/owner` route) provides visibility into servers, subscriptions, active sessions, and webhook events, including manual subscription management capabilities.
- **Mobile Device Restriction**: Server administrators can restrict clock-in/out to desktop/web browser only.
- **Persistent Button Architecture**: Uses `@discord.ui.button` decorators with `timeout=None` and registration in `setup_hook()` for reliable button functionality across bot restarts.
- **Database Migrations**: Automatic schema migrations on startup using `migrations.py` with idempotent `CREATE TABLE IF NOT EXISTS` statements.
- **Employee Status Cards**: The dashboard displays active employees with hours worked (today/week/month).
- **Time Adjustment Requests**: Employees can request time corrections, which admins can approve/deny via the dashboard with a before/after comparison.
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