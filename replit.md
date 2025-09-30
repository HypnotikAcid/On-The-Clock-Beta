# Overview

"On the Clock 1.5" is a professional Discord timeclock bot for businesses. It provides subscription management, robust error handling, and enterprise-grade reliability. Key features include a three-tier subscription model (Free/Basic/Pro), Stripe payment integration, role-based access control, and a simple, unauthenticated landing page. The project aims to offer an easy-to-use time tracking solution for Discord communities.

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
- **UI/UX**: Simple, static landing page without authentication; dashboard provides server-specific settings.
- **Subscription Management**: Three-tier system (Free, Basic, Pro) with varying data retention (0, 7, 30 days).
- **Concurrent Safety**: Utilizes guild-level locking, WAL mode for SQLite, and exclusive database migrations.
- **Ephemeral Interface System**: Resolves interaction timeout issues by providing new interfaces via the `/clock` command.
- **Server Settings Page**: Tile-based layout for role management, email settings (placeholder), and timezone controls, protected by Discord OAuth and requiring admin access.
- **Custom Jinja2 Permission Filter**: Addresses Jinja2's lack of bitwise operator support for Discord permission checking.
- **Secure Error Handling**: Generic user-facing messages, detailed server-side logging, and redaction of sensitive information.
- **Database-Backed Sessions**: Ensures session persistence across restarts.

## Security Configuration
- **Code Analysis**: Semgrep rules for static analysis and secret management.
- **Stripe Security**: Webhook signature verification and secure API key management.
- **Data Privacy**: Automated data purging based on subscription tier and cancellation.
- **Input Validation**: Robust validation for roles and timezones to prevent invalid data.
- **Authorization Checks**: Bot presence and user admin access verified before operations.

# External Dependencies

## Core Libraries
- **discord.py**: Primary library for Discord API interaction.
- **tzdata**: Provides timezone data for Python.
- **aiosqlite**: Asynchronous SQLite database interface.

## Development Tools
- **Semgrep**: Static analysis security scanner.

## Discord Integration
- **Discord API**: For real-time communication and operations.
- **Discord OAuth 2.0**: For secure user authentication and dashboard features.

## Payment Integration
- **Stripe**: Handles subscriptions and payments, processing `checkout.session.completed` and `customer.subscription.deleted` webhooks.

## Database
- **SQLite**: Used for data storage with WAL mode enabled.

# Server Settings Page Implementation

**Date**: September 30, 2025  
**Status**: ✅ Implemented and Reviewed

## Overview

The server settings page (`/server/<guild_id>/settings`) provides server admins with a centralized interface to manage server-specific configurations. Features include role management for admins and employees, email notification settings (placeholder), and timezone configuration.

## Architecture

### Flask Route: `/server/<guild_id>/settings`

**Location**: `app.py` starting at line 556

**Security & Authorization**:
1. Bot presence check via `bot_guilds` table (404 if bot not in server)
2. User authorization via `verify_guild_access()` (403 if not Owner/Administrator)
3. Discord OAuth session validation via `@require_auth` decorator

**Data Loading**:
- Fetches guild roles from Discord API using bot token
- Retrieves current settings from database (admin_roles, employee_roles, timezone)
- Gracefully handles API failures with user-friendly error messages

### Helper Functions

**`get_guild_roles_from_bot(guild_id)`** (app.py line 473):
- Fetches roles via Discord API with 5-second timeout
- Handles 403 Forbidden and 404 Not Found errors
- Returns list of role dictionaries or None on failure

**`get_guild_settings(guild_id)`** (app.py line 509):
- Retrieves admin roles, employee roles, timezone, and other settings
- Defaults: timezone = "America/New_York", emails = []
- Returns structured dictionary

**`validate_role_in_guild(guild_id, role_id)`** (app.py line 620):
- Validates role_id belongs to guild (prevents bogus data)
- Uses Discord API to verify role exists in guild
- Returns False on errors or invalid roles

### API Endpoints

**Authentication**: All use `@require_api_auth` decorator (returns JSON 401/403 instead of HTML redirects)

**Admin Role Management**:
- `POST /api/server/<guild_id>/admin-roles/add` (app.py line 631)
  - Validates role belongs to guild before insertion
  - Uses `INSERT OR IGNORE` to prevent duplicates
  - Response: `{success: true, message: "...", role_id: "..."}`

- `POST /api/server/<guild_id>/admin-roles/remove` (app.py line 663)
  - Removes admin role from database
  - Response: `{success: true, message: "...", role_id: "..."}`

**Employee Role Management**:
- `POST /api/server/<guild_id>/employee-roles/add` (app.py line 690)
- `POST /api/server/<guild_id>/employee-roles/remove` (app.py line 722)
- Same validation and response format as admin roles

**Timezone Management**:
- `POST /api/server/<guild_id>/timezone` (app.py line 763)
  - Validates timezone against IANA database (zoneinfo)
  - Handles INSERT and UPDATE cases
  - Response: `{success: true, message: "...", timezone: "..."}`

**Error Responses**: Consistent JSON format
```json
{
  "success": false,
  "error": "Error message"
}
```

### UI Components (server_settings.html)

**Tile 1: Admin Roles Management**
- Dual listbox: Available Roles ↔ Current Admin Roles
- Pre-populated from database
- Transfer buttons call API endpoints

**Tile 2: Employee Roles Management**
- Dual listbox: Available Roles ↔ Current Employee Roles
- Pre-populated from database
- Transfer buttons call API endpoints

**Tile 3: Email Settings**
- Email input and listbox (placeholder - no email table yet)
- Toggle switches: DM notifications, Email notifications
- "Customize Email" button (future feature)

**Tile 4: Timezone Settings**
- Dropdown with all IANA timezones
- Defaults to America/New_York
- Pre-selects current timezone from database
- Save button triggers API call

### JavaScript Integration (server_settings.html, inline script)

**Features**:
- Role selection handlers for both tiles
- Fetch API with async/await and error handling
- Parses JSON responses and checks `response.ok` && `data.success`
- Displays server error messages via alert()
- Page reloads after successful changes

## Security Features

### API Authentication
- `require_api_auth` decorator (app.py line 263)
- Returns JSON 401/403 instead of redirects
- Prevents misleading UX from HTML responses in fetch() calls
- Clears expired sessions automatically

### Input Validation
- **Role Validation**: All role endpoints validate role_id belongs to guild
- **Timezone Validation**: Validates against IANA database (zoneinfo.available_timezones())
- Returns 400 Bad Request for invalid inputs

### Authorization
- Bot presence verified before operations
- User admin access verified for all endpoints
- Consistent 403 responses for unauthorized access

### Error Handling
- Generic user messages (no sensitive info exposed)
- Detailed server logging with tracebacks
- Consistent JSON error responses

## Testing Procedures

**Manual Testing** (requires Discord OAuth login):

1. Navigate to server settings from dashboard
2. Test admin role add/remove operations
3. Test employee role add/remove operations
4. Test timezone update and persistence
5. Verify database changes:
   ```sql
   SELECT * FROM admin_roles WHERE guild_id = '<guild_id>';
   SELECT * FROM employee_roles WHERE guild_id = '<guild_id>';
   SELECT timezone FROM guild_settings WHERE guild_id = '<guild_id>';
   ```
6. Test error cases (invalid role_id, unauthorized access, bot not in server)

## Known Limitations

1. **Email Management**: Email table not yet implemented - Tile 3 is placeholder UI
2. **Real-time Updates**: Role changes require page reload
3. **Discord API Dependency**: Role validation requires live Discord API access

## Future Enhancements

- Email table and storage implementation
- Real-time updates without page reload (WebSocket/AJAX)
- Bulk role management operations
- Role search/filter for large servers
- Subscription tier-based feature gating per tile
- Audit log for settings changes