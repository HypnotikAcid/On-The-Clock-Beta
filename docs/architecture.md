# System Architecture

## Bot Framework
- **discord.py**: Handles interactions and ephemeral interfaces.
- **Unified `/clock` command**: Stable custom IDs with `timeout=None`.
- **Context Menus**: Admin shortcuts (hours, profile, force clock-out).
- **Onboarding**: Welcome DMs and first-time `/clock` guides.

## Dashboard & Web
- **Flask Backend**: Role-based access control.
- **Discord OAuth 2.0**: User authentication.
- **Route-Based**: Dedicated routes for roles, employees, reports, and kiosk.
- **Signed Deep-Links**: Secure navigation from Discord to Dashboard.

## Data & Automation
- **PostgreSQL**: Production database with connection pooling and SSL.
- **APScheduler**: Automated emails and data purging.
- **Email Outbox Pattern**: Queuing and retries for reliability.
- **Stripe**: Subscription lifecycle management and webhooks.

## Retention Policy
- **Free**: 24-hour retention.
- **Premium**: 30-day retention.
- **Pro**: Advanced retention and kiosk features.
