# Overview

"On the Clock 1.5" is a professional Discord timeclock bot designed for businesses, offering subscription management, robust error handling, and enterprise-grade reliability. The project provides an easy-to-use time tracking solution for Discord communities, featuring a three-tier subscription model (Free/Basic/Pro), Stripe payment integration, role-based access control, and a simple, unauthenticated landing page.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Bot Framework
- **Technology**: Discord.py (version 2.3+)
- **Language**: Python 3.x
- **Architecture Pattern**: Event-driven bot architecture.
- **Startup Process**: Gunicorn runs Flask app as main process, Discord bot runs in daemon thread. The bot module's `run_bot_with_api()` function starts both the Discord bot and internal HTTP API server (port 8081) concurrently.

## Design Decisions
- **Discord.py**: Chosen for its features, active development, and community support.
- **Event-Driven Design**: Leverages async/await for concurrent event processing.
- **Timezone Awareness**: Ensures correct time handling using `tzdata`.
- **UI/UX**: Simple, static landing page; dashboard provides server-specific settings with a tile-based layout for role management, email settings, and timezone controls, protected by Discord OAuth and requiring admin access.
- **Subscription Management**: Restructured monetization model with free tier (employee management, /clock access, 24-hour deletion), $5 one-time bot access payment per server, and optional data retention subscriptions ($5/month for 7-day, $10/month for 30-day retention). Dashboard displays subscription status banner with clear upgrade prompts.
- **Concurrent Safety**: Utilizes guild-level locking, WAL mode for SQLite, and exclusive database migrations.
- **Ephemeral Interface System**: Resolves interaction timeout issues by providing new interfaces via the `/clock` command.
- **Custom Jinja2 Permission Filter**: Addresses Jinja2's lack of bitwise operator support for Discord permission checking.
- **Secure Error Handling**: Generic user-facing messages, detailed server-side logging, and redaction of sensitive information.
- **Database-Backed Sessions**: Ensures session persistence across restarts.
- **Bot as Boss Architecture**: All role management changes flow through the bot's HTTP API, making the bot the single source of truth for both dashboard and Discord command operations, ensuring perfect synchronization and consistency.
- **Email Automation**: APScheduler handles automated email tasks including auto-send on clock-out, scheduled work day end reports, and pre-deletion warnings. Scheduler runs in bot's event loop without circular imports.

## Security Configuration
- **Code Analysis**: Semgrep rules for static analysis and secret management.
- **Stripe Security**: Webhook signature verification and secure API key management.
- **Data Privacy**: Automated data purging based on subscription tier and cancellation.
- **Input Validation**: Robust validation for roles and timezones.
- **Authorization Checks**: Bot presence and user admin access verified before operations.

# External Dependencies

## Core Libraries
- **discord.py**: Primary library for Discord API interaction.
- **tzdata**: Provides timezone data for Python.
- **aiosqlite**: Asynchronous SQLite database interface.
- **aiohttp**: Used for the bot's internal HTTP API server.
- **APScheduler**: Asynchronous job scheduler for automated email tasks.
- **pytz**: Timezone library used by APScheduler for scheduling tasks.

## Development Tools
- **Semgrep**: Static analysis security scanner.

## Discord Integration
- **Discord API**: For real-time communication and operations.
- **Discord OAuth 2.0**: For secure user authentication and dashboard features.

## Payment Integration
- **Stripe**: Handles subscriptions and payments, processing `checkout.session.completed` and `customer.subscription.deleted` webhooks.

## Database
- **SQLite**: Used for data storage with WAL mode enabled. `bot.py` and `app.py` connect to the same `timeclock.db` file defined by `TIMECLOCK_DB` environment variable.