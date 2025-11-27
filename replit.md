# Overview

"On the Clock 1.5" is a professional Discord timeclock bot designed for businesses, offering subscription management, robust error handling, and enterprise-grade reliability. The project provides an easy-to-use time tracking solution for Discord communities, featuring a three-tier subscription model (Free/Basic/Pro), Stripe payment integration, role-based access control, and a simple, unauthenticated landing page. Its purpose is to streamline time tracking within Discord, providing a valuable tool for businesses.

# User Preferences

Preferred communication style: Simple, everyday language.

# Recent Fixes (November 27, 2025)

## Critical Encoding Fixes Applied
1. **UTF-16 LE Encoding Corruption (app.py)** - Converted corrupted UTF-16 LE file with 138,000+ null bytes to proper UTF-8
2. **Dashboard Template Recovery** - Restored dashboard.html from git commit 1303f18 (recovered full 704-line version)
3. **SQL Query Table References** - Fixed bot.py queries to use `employee_profiles` table instead of nonexistent `users` table:
   - `get_active_employees_with_stats()` - Updated table join and column references
   - `get_pending_adjustments()` - Updated table join and privacy settings references
4. **UTF-8 BOM Removal** - Removed BOM markers from all affected files (dashboard.html, dashboard.css, dashboard-core.js, dashboard-matrix.js, app.py)
5. **Unicode Character Encoding** - Replaced literal Unicode arrows with HTML entities for reliable rendering:
   - Right arrow: `→` → `&rarr;` (in dashboard-roles.js)
   - Left arrow: `←` → `&larr;` (in dashboard.html and server_selection.html)
6. **Mojibake Cleanup** - Fixed 56 corrupted character sequences across app.py (48), dashboard.html (4), and dashboard-core.js (4)
7. **Variable Name Bug Fix** - Fixed `show_last_seen_setting` → `show_last_seen` in `get_active_employees_with_stats()` that caused Employee Status page error
8. **RealDictRow Tuple Unpacking Bugs** - Fixed critical bugs where tuple unpacking of database results returned KEYS instead of VALUES:
   - `get_server_tier()` line 2824: Changed `tier, status = result` → dictionary access
   - `subscription_status` command line 7351: Changed 5-variable tuple unpack → dictionary access
9. **None Check Missing** - Added None check for `current` variable in `approve_adjustment()` before accessing `current['clock_in']`
10. **RealDictRow Tuple Unpacking Bug** - Fixed `handle_api_get_recipients()` at line 2032: Changed tuple unpacking to dictionary key access (was unpacking column NAMES instead of VALUES)
11. **Dashboard Emoji Corruption** - Fixed 3 corrupted emoji characters in dashboard-core.js caused by Antigravity UTF-16 LE encoding:
    - Line 228: Role icons now use Unicode escapes `\u2694` (⚔ for admin) and `\u263A` (☺ for employee)
    - Line 487: Email icon now uses `\u2709` (✉)
    - Line 659: Loading spinner uses `\u21BB` (↻)
12. **Timezone Icon Rendering** - Replaced `🕰️` emoji with HTML entity `&#9200;` (⏰) in dashboard.html for reliable rendering at small sizes

**Status**: ✅ All encoding and variable issues resolved. App fully operational with proper data access.

## Missing Function & Route Fixes (November 27, 2025)
13. **Missing Cache Functions** - Added `get_cached_discord_data()` and `set_cached_discord_data()` to bot.py for Discord API rate limiting
14. **Missing OAuth Functions** - Added to bot.py:
    - `create_oauth_session()` - Creates OAuth state in database for CSRF protection
    - `get_discord_oauth_url()` - Generates Discord OAuth2 authorization URL
    - `get_user_session()` - Retrieves user session from database
    - `delete_user_session()` - Deletes user session from database
    - `get_discord_guild_member()` - Fetches guild member data from Discord API
15. **Missing Adjustment History** - Added `get_user_adjustment_history()` function to bot.py and `/api/guild/{id}/adjustments/history` route to app.py
16. **Windows Line Endings** - Converted app.py from CRLF to LF line endings

## Known Hardcoded Values (Future Refactoring)
- `BOT_OWNER_ID = '107103438139056128'` - Hardcoded in 3 places in app.py (should use env var)
- `bot_id = "1418446753379913809"` - Hardcoded in 2 places in app.py + dashboard_invite.html template

## Outstanding TODOs
- `app.py:727` - TODO: implement Discord API call to get member roles
- `app.py:1685` - TODO: Add email table and fetch emails
- `bot.py:964` - TODO: Consider refunding the payment automatically here
- `bot.py:1044` - TODO: Consider refunding the payment automatically here

# Code Quality & Bug Prevention

## Known Bug Patterns to Audit

### 1. RealDictRow Tuple Unpacking (CRITICAL)
**Pattern**: `a, b, c = cursor.fetchone()` or `for x, y in cursor.fetchall()`
**Problem**: Unpacks column NAMES not VALUES when using psycopg2 RealDictCursor
**Fix**: Always use `row['column_name']` dictionary access
**Search**: `grep -n ", .* = .*row\|, .* = .*result" bot.py app.py`

### 2. Missing None Guards
**Pattern**: `result = cursor.fetchone()` followed by `result['key']` without check
**Problem**: Crashes if query returns no rows
**Fix**: Always check `if result:` or `if result is None: return`
**Search**: `grep -n "fetchone()\[" bot.py app.py`

### 3. Variable Name Mismatches
**Pattern**: Similar variable names with different suffixes (_setting, _status, etc.)
**Problem**: Using wrong variable name causes NameError or wrong data
**Fix**: Verify variable names match between assignment and usage
**Search**: `grep -n "show_last_seen" bot.py` (check for variants)

### 4. Encoding Issues (from Antigravity editor)
**Pattern**: Files saved as UTF-16 LE instead of UTF-8
**Problem**: Null bytes corrupt file, mojibake characters appear
**Fix**: Convert to UTF-8, use HTML entities for special chars
**Check**: `file --mime-encoding *.py`

## Master Audit Prompt
Use this to request a comprehensive audit:
> "Audit bot.py and app.py for: (1) tuple unpacking of database rows - must use dictionary access; (2) variable name mismatches; (3) None checks before accessing fetchone() results; (4) encoding issues. Report exact file/line for each issue."

## Prevention Rules
- **Database rows**: ALWAYS use `row['column']` never `a, b = row`
- **Query results**: ALWAYS check `if result:` before `result['key']`
- **Special characters**: Use HTML entities (`&rarr;`, `&larr;`) in templates
- **File encoding**: Ensure editor saves as UTF-8

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
