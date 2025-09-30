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

## Discord OAuth Dashboard
- **Authentication Flow**: Implements Discord OAuth 2.0 for secure user authentication.
- **Session Management**: Database-backed sessions with automatic expiration and cleanup.
- **Dashboard Features**: Shows user profile and Discord servers with role/permission badges.
- **Security**: CSRF protection via state tokens, secure cookie handling, and generic error messages to prevent information leakage.
- **Custom Jinja2 Filters**: `has_permission` filter for Discord permission checking in templates (resolves bitwise operator limitations in Jinja2).

# Discord OAuth Implementation Details

## Architecture Overview

The dashboard uses Discord OAuth 2.0 to authenticate users and display their Discord servers. The implementation consists of:

1. **Flask Web Application** (`app.py`)
   - OAuth routes: `/auth/login`, `/auth/callback`, `/auth/logout`
   - Protected dashboard route with session validation
   - Database-backed session storage for persistence across restarts

2. **Dashboard Template** (`templates/dashboard.html`)
   - Displays user profile (avatar, username, Discord ID)
   - Lists all Discord servers with permission badges (Owner, Administrator, Manage Server)
   - Uses custom Jinja2 filters for permission checking

3. **Combined Deployment** (`start.py`)
   - Runs Discord bot and Flask web server together
   - Proper for VM deployment on Replit

## Key Implementation Patterns

### 1. Custom Jinja2 Permission Filter

**Problem**: Jinja2 doesn't support Python's bitwise `&` operator directly in templates.

**Solution**: Custom template filter in `app.py`:

```python
@app.template_filter('has_permission')
def has_permission(permissions, permission_flag):
    """Check if a permission integer has a specific flag using bitwise AND"""
    try:
        return int(permissions) & permission_flag != 0
    except (ValueError, TypeError):
        return False
```

**Usage in Template**:
```jinja
{% if guild.permissions|has_permission(0x8) %}
    <span class="badge">Administrator</span>
{% endif %}
```

### 2. Secure Error Handling

**Security Principle**: Never expose internal errors to users.

**Implementation**:
- Generic user-facing error messages
- Detailed logging to server logs only
- OAuth state tokens redacted in logs (only first 8 chars logged)
- Exception details captured with traceback for debugging

**Example**:
```python
try:
    # OAuth logic
except Exception as e:
    app.logger.error(f"OAuth callback error: {str(e)}")
    app.logger.error(traceback.format_exc())
    return "An error occurred during authentication. Please try again later.", 500
```

### 3. Database-Backed Sessions

**Why**: In-memory sessions don't persist across Gunicorn worker restarts.

**Implementation**:
- `oauth_states` table: Stores CSRF tokens with expiration
- `user_sessions` table: Stores authenticated sessions with user data
- Automatic cleanup of expired sessions on initialization

### 4. Safe Module Initialization

**Problem**: `app.logger` might not be ready during Gunicorn import.

**Solution**: Wrap initialization with try-except and avoid logger calls:

```python
try:
    init_dashboard_tables()
except Exception as e:
    print(f"⚠️ Dashboard initialization warning: {e}")
```

## Troubleshooting Guide

### Issue: Jinja2 Template Error (line 298)
**Symptom**: "Unable to load dashboard" error  
**Cause**: Template using bitwise operator `guild.permissions|int & 0x8`  
**Solution**: Use custom `has_permission` filter instead

### Issue: Port 5000 Already in Use
**Symptom**: Gunicorn fails to start with "Address already in use"  
**Cause**: Old processes still running  
**Solution**: Kill processes: `pkill -9 gunicorn` or `kill -9 <PID>`

### Issue: Database Initialization Fails
**Symptom**: Deployment errors during startup  
**Cause**: Trying to use app.logger before it's initialized  
**Solution**: Remove logger calls from `init_dashboard_tables()` or wrap in try-except

### Issue: Sessions Not Persisting
**Symptom**: Users logged out after workflow restart  
**Cause**: Using in-memory session storage  
**Solution**: Use database-backed sessions (already implemented)

## Deployment Configuration

**Deployment Target**: VM (not autoscale - needs persistent state for Discord bot)  
**Run Command**: `python start.py`  
**Why**: Runs both Discord bot and Flask web server together

**Key Configuration** (`.replit`):
```toml
[deployment]
deploymentTarget = "vm"
run = ["python", "start.py"]
```

## Environment Variables Required

- `DISCORD_CLIENT_ID`: OAuth application client ID
- `DISCORD_CLIENT_SECRET`: OAuth application secret
- `SECRET_KEY`: Flask session encryption key
- `DISCORD_TOKEN`: Discord bot token (for bot functionality)
- `STRIPE_SECRET_KEY`: Stripe API key (for subscriptions)
- `STRIPE_WEBHOOK_SECRET`: Stripe webhook signing secret

## File Structure

```
/
├── app.py                      # Flask OAuth application
├── bot.py                      # Discord bot
├── start.py                    # Combined startup script
├── templates/
│   ├── landing.html           # Public landing page
│   └── dashboard.html         # Authenticated dashboard
├── timeclock.db               # SQLite database (bot + sessions)
└── replit.md                  # This documentation
```

# Lessons Learned (September 2025)

## Authentication Implementation

**Date**: 2025-09-30

### Challenges Encountered

1. **Jinja2 Bitwise Operator Error**
   - Cannot use Python bitwise operators (`&`, `|`) directly in Jinja2 templates
   - Created custom `has_permission` filter to handle Discord permission checking
   - Filter safely handles type conversions and errors

2. **Port Blocking Issues**
   - Old Gunicorn processes can block port 5000
   - Use `ps aux | grep gunicorn` to find processes
   - Kill with `kill -9 <PID>` or `pkill -9 gunicorn`

3. **Database Initialization Timing**
   - `app.logger` may not be ready during module import
   - Avoid logger calls in functions called at module level
   - Wrap initialization in try-except for safety

4. **Security Best Practices**
   - Never expose exception details to users
   - Log sensitive tokens with redaction (first 8 chars only)
   - Use generic error messages for user-facing responses
   - Keep detailed errors in server logs only

5. **Deployment Configuration**
   - VM deployment required (not autoscale) for Discord bot
   - Use `start.py` to run bot + web server together
   - Gunicorn runs Flask; bot runs in background thread

### Success Patterns

✅ **Custom Jinja2 Filters** - Solve template limitations elegantly  
✅ **Database Sessions** - Persist across worker restarts  
✅ **CSRF Protection** - OAuth state tokens with one-time use  
✅ **Error Logging** - Detailed server logs, generic user messages  
✅ **Combined Deployment** - Single startup script for multiple services