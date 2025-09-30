# Overview

"On the Clock 1.5" is a professional Discord timeclock bot designed for businesses, offering subscription management, robust error handling, and enterprise-grade reliability. The project provides an easy-to-use time tracking solution for Discord communities, featuring a three-tier subscription model (Free/Basic/Pro), Stripe payment integration, role-based access control, and a simple, unauthenticated landing page.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Bot Framework
- **Technology**: Discord.py (version 2.3+)
- **Language**: Python 3.x
- **Architecture Pattern**: Event-driven bot architecture.

## Design Decisions
- **Discord.py**: Chosen for its features, active development, and community support.
- **Event-Driven Design**: Leverages async/await for concurrent event processing.
- **Timezone Awareness**: Ensures correct time handling using `tzdata`.
- **UI/UX**: Simple, static landing page; dashboard provides server-specific settings with a tile-based layout for role management, email settings (placeholder), and timezone controls, protected by Discord OAuth and requiring admin access.
- **Subscription Management**: Three-tier system (Free, Basic, Pro) with varying data retention (0, 7, 30 days).
- **Concurrent Safety**: Utilizes guild-level locking, WAL mode for SQLite, and exclusive database migrations.
- **Ephemeral Interface System**: Resolves interaction timeout issues by providing new interfaces via the `/clock` command.
- **Custom Jinja2 Permission Filter**: Addresses Jinja2's lack of bitwise operator support for Discord permission checking.
- **Secure Error Handling**: Generic user-facing messages, detailed server-side logging, and redaction of sensitive information.
- **Database-Backed Sessions**: Ensures session persistence across restarts.
- **Bot as Boss Architecture**: All role management changes flow through the bot's HTTP API, making the bot the single source of truth for both dashboard and Discord command operations, ensuring perfect synchronization and consistency.

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

## Development Tools
- **Semgrep**: Static analysis security scanner.

## Discord Integration
- **Discord API**: For real-time communication and operations.
- **Discord OAuth 2.0**: For secure user authentication and dashboard features.

## Payment Integration
- **Stripe**: Handles subscriptions and payments, processing `checkout.session.completed` and `customer.subscription.deleted` webhooks.

## Database
- **SQLite**: Used for data storage with WAL mode enabled. `bot.py` and `app.py` connect to the same `timeclock.db` file defined by `TIMECLOCK_DB` environment variable.