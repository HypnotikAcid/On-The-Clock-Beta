# Overview

**On the Clock 1.5** is a professional Discord timeclock bot designed for businesses. It offers complete subscription management, robust error handling, and enterprise-grade reliability. Key features include a three-tier subscription model (Free/Basic/Pro), comprehensive payment integration via Stripe, and role-based access control. The project aims to provide a reliable and easy-to-use time tracking solution for Discord communities, now featuring a clean, unauthenticated landing page.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Bot Framework
- **Technology**: Discord.py (version 2.3+)
- **Language**: Python 3.x
- **Architecture Pattern**: Event-driven bot architecture utilizing Discord.py's command framework.

## Core Components
- **Bot Client**: Manages Discord connections and events.
- **Event Handlers**: Respond to Discord events.
- **Command System**: Handles user commands via Discord.py's built-in framework.
- **Timezone Support**: Integrated `tzdata` for accurate timezone handling.

## Design Decisions
- **Discord.py**: Chosen for its rich features, active development, and community support.
- **Event-Driven Design**: Leverages async/await for concurrent event processing.
- **Timezone Awareness**: Ensures correct time handling across different regions.
- **UI/UX**: Transitioned from a complex dashboard to a simple, static landing page without authentication for ease of access and to eliminate login-related issues.
- **Subscription Management**: Implements a three-tier system (Free, Basic, Pro) with varying data retention policies (0, 7, and 30 days respectively).
- **Concurrent Safety**: Utilizes guild-level locking, WAL mode for SQLite, and exclusive database migrations to prevent race conditions and ensure data integrity.
- **Ephemeral Interface System**: Ensures all bot interactions are fresh and non-expiring by providing new interfaces via the `/clock` command, completely resolving interaction timeout issues.

## Security Configuration
- **Code Analysis**: Semgrep rules configured for static analysis, focusing on sensitive parameter and secret management.
- **Stripe Security**: Webhook signature verification and secure API key management.
- **Data Privacy**: Automated data purging based on subscription tier and cancellation.

# External Dependencies

## Core Libraries
- **discord.py**: Primary library for Discord API interaction.
- **tzdata**: Provides timezone data for Python.

## Development Tools
- **Semgrep**: Static analysis security scanner.

## Discord Integration
- **Discord API**: For real-time communication and operations.

## Payment Integration
- **Stripe**: Handles subscriptions and payments.
    - **Products**: Basic Tier (`prod_T6UoMM5s7PdD8q`), Pro Tier (`prod_T6UpgjUKoIEMtu`).
    - **Test Price IDs**: Basic Monthly (`price_1SALFw3Jrp0J9AdlcSN8Hulc`), Pro Monthly (`price_1SALH13Jrp0J9AdlKVXl2od5`).
    - **Webhooks**: Processes `checkout.session.completed` events for subscription upgrades and `customer.subscription.deleted` for data purging.

## Database
- **SQLite (via `aiosqlite`)**: Used for data storage with WAL mode enabled for concurrency.