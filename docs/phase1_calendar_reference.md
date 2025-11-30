# Phase 1: Calendar-Based Time Adjustment Feature - Codebase Reference

> **Purpose**: Reference document for AI coding assistants implementing the calendar-based time adjustment feature  
> **Project**: On the Clock - Discord Bot + Flask Web Dashboard  
> **Phase**: 1 of 8

---

## Project Architecture Overview

```
User Browser → Flask App (port 5000) → Discord API
                    ↓
              Bot API (port 8081) ← Discord Bot
                    ↓
              PostgreSQL Database (Neon-backed via Replit)
```

### Key Files
- `app.py` - Flask web app (landing page, OAuth, dashboard, API endpoints)
- `bot.py` - Discord bot (slash commands, time tracking, internal API server)
- `templates/dashboard.html` - Dashboard HTML template
- `static/css/dashboard.css` - Dashboard styles
- `email_utils.py` - Replit Mail integration for email sending
- `migrations.py` - Database schema migrations

---

## 1. Database Schema

### Sessions Table (stores clock-in/out records)

```sql
CREATE TABLE sessions (
    id              SERIAL PRIMARY KEY,
    guild_id        BIGINT NOT NULL,
    user_id         BIGINT NOT NULL,
    clock_in        TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    clock_out       TIMESTAMP WITHOUT TIME ZONE,
    duration_seconds INTEGER
);
```

**Important Notes**:
- `clock_in` and `clock_out` are `TIMESTAMP WITHOUT TIME ZONE`
- Timezone conversion happens in Python code using guild's configured timezone
- `duration_seconds` is calculated when `clock_out` is set

### Time Adjustment Requests Table (already exists)

```sql
CREATE TABLE time_adjustment_requests (
    id SERIAL PRIMARY KEY,
    guild_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    request_type TEXT NOT NULL,           -- 'add_session', 'modify_session', 'modify_clockin', 'modify_clockout', 'delete_session'
    original_session_id INTEGER,          -- FK to sessions.id (for modify/delete)
    original_clock_in TIMESTAMPTZ,
    original_clock_out TIMESTAMPTZ,
    original_duration INTEGER,
    requested_clock_in TIMESTAMPTZ,
    requested_clock_out TIMESTAMPTZ,
    reason TEXT,
    status TEXT NOT NULL DEFAULT 'pending', -- 'pending', 'approved', 'denied'
    reviewed_by BIGINT,
    reviewed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    -- Calendar enhancement columns (added for interactive calendar feature)
    session_date DATE,                    -- The date the session occurred (for calendar lookups)
    admin_notes TEXT,                     -- Notes from admin when approving/denying
    calculated_duration INTEGER           -- Pre-calculated duration for requested times
);

-- Indexes for faster lookups
CREATE INDEX idx_adjustment_requests_guild_status 
ON time_adjustment_requests(guild_id, status);

-- Index for calendar date-based queries
CREATE INDEX idx_adjustment_requests_session_date 
ON time_adjustment_requests(guild_id, user_id, session_date);
```

### Employee Profiles Table

```sql
CREATE TABLE employee_profiles (
    id SERIAL PRIMARY KEY,
    guild_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    role_tier VARCHAR(20) DEFAULT 'employee',
    
    -- Profile data
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    full_name VARCHAR(200),          -- Added via migration
    display_name VARCHAR(100),       -- Added via migration
    date_of_birth DATE,
    email VARCHAR(255),
    bio TEXT,
    avatar_choice VARCHAR(50) DEFAULT 'random',
    custom_avatar_url TEXT,
    avatar_url TEXT,                 -- Added via migration
    company_role VARCHAR(100),
    position VARCHAR(100),           -- Added via migration
    department VARCHAR(100),         -- Added via migration
    
    -- Privacy toggles
    show_last_seen BOOLEAN DEFAULT TRUE,
    show_discord_status BOOLEAN DEFAULT TRUE,
    
    -- Employee premium settings
    email_timesheets BOOLEAN DEFAULT FALSE,
    timesheet_email VARCHAR(255),
    
    -- Metadata
    hire_date TIMESTAMPTZ DEFAULT NOW(),
    last_seen_discord TIMESTAMPTZ,
    profile_setup_completed BOOLEAN DEFAULT FALSE,
    profile_sent_on_first_clockin BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    
    UNIQUE(guild_id, user_id)
);

-- Indexes
CREATE INDEX idx_employee_profiles_guild_user ON employee_profiles(guild_id, user_id);
CREATE INDEX idx_employee_profiles_active ON employee_profiles(guild_id, is_active);
```

### Guild Settings Table

```sql
CREATE TABLE guild_settings (
    guild_id BIGINT PRIMARY KEY,
    recipient_user_id BIGINT,
    button_channel_id BIGINT,
    button_message_id BIGINT,
    timezone TEXT DEFAULT 'America/New_York',
    name_display_mode TEXT DEFAULT 'username',
    main_admin_role_id TEXT,
    work_day_end_time TEXT
);
-- Note: Uses direct columns, NOT key-value pairs
```

---

## 2. Existing API Endpoints

### Time Adjustment APIs

| Method | Endpoint | Description | Location |
|--------|----------|-------------|----------|
| POST | `/api/guild/{id}/adjustments` | Create new adjustment request | `bot.py` |
| GET | `/api/guild/{id}/adjustments/pending` | Get pending requests for guild | `bot.py` |
| GET | `/api/guild/{id}/employee/{user_id}/adjustments/recent` | Get user's adjustment history | `bot.py` |
| POST | `/api/guild/{id}/adjustments/{id}/approve` | Approve a request | `bot.py` |
| POST | `/api/guild/{id}/adjustments/{id}/deny` | Deny a request | `bot.py` |
| GET | `/api/guild/{id}/employee/{user_id}/monthly-timecard` | Calendar data with sessions + adjustment status | `app.py` (IMPLEMENTED) |
| POST | `/api/guild/{id}/adjustments/submit-day` | Submit day-level adjustment requests | `app.py` (IMPLEMENTED) |
| GET | `/api/guild/{id}/adjustments/history` | Get user's full adjustment history | `app.py` (IMPLEMENTED) |

### Key Functions in `bot.py`

```python
# Line ~3752: Create adjustment request
def create_adjustment_request(guild_id, user_id, request_type, reason, 
                               original_session_id=None, requested_data=None):
    """
    Create a new time adjustment request.
    
    Args:
        guild_id: Discord guild ID
        user_id: Discord user ID requesting adjustment
        request_type: 'add_session', 'modify_clockin', 'modify_clockout', 'delete_session'
        reason: Text explanation for the adjustment
        original_session_id: ID of session being modified (for modify/delete)
        requested_data: Dict with 'clock_in' and/or 'clock_out' timestamps
    
    Returns:
        request_id (int) or None on error
    """

# Line ~3791: Get pending adjustments
def get_pending_adjustments(guild_id: int):
    """
    Get all pending adjustment requests for a guild.
    Returns: List[Dict] with request details enriched with user info
    """

# Line ~3807: Approve adjustment
def approve_adjustment(request_id: int, guild_id: int, reviewer_user_id: int):
    """
    Approve an adjustment request and apply changes to sessions table.
    Uses PostgreSQL transaction for atomicity.
    Returns: (success: bool, message: str)
    """

# Line ~3914: Get user's adjustment history
def get_user_adjustment_history(guild_id: int, user_id: int, limit: int = 20):
    """
    Get adjustment request history for a specific user.
    Returns all requests (pending, approved, denied) for audit trail.
    """
```

---

## 3. Database Connection Patterns

### In Flask (`app.py`) - Use `get_db()`

```python
from contextlib import contextmanager

# Connection pool initialized at startup
app_db_pool = psycopg2.pool.ThreadedConnectionPool(
    minconn=1, maxconn=10, dsn=DATABASE_URL
)

@contextmanager
def get_db():
    """Context manager for PostgreSQL database connections (Flask app)"""
    conn = app_db_pool.getconn()
    wrapper = FlaskConnectionWrapper(conn)
    try:
        yield wrapper
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        app_db_pool.putconn(conn)

# Usage example:
with get_db() as conn:
    cursor = conn.execute(
        "SELECT * FROM sessions WHERE guild_id = %s AND user_id = %s",
        (guild_id, user_id)
    )
    results = cursor.fetchall()  # Returns list of dict-like rows
```

### In Bot (`bot.py`) - Use `db()`

```python
# Same pattern but different pool
with db() as conn:
    cursor = conn.execute("SELECT * FROM sessions WHERE guild_id = %s", (guild_id,))
    results = cursor.fetchall()
```

---

## 4. Querying Sessions by Date Range

**NOTE: These are IMPLEMENTATION EXAMPLES - not existing code. You need to create these functions.**

```python
# EXAMPLE: Get sessions for a user within a date range
# You will need to implement this function
def get_sessions_by_date_range(guild_id, user_id, start_date, end_date):
    """
    Fetch all sessions for a user within a date range.
    
    Args:
        guild_id: Discord guild ID
        user_id: Discord user ID
        start_date: datetime object for range start
        end_date: datetime object for range end
    
    Returns:
        List of session dicts with id, clock_in, clock_out, duration_seconds
    """
    with db() as conn:
        cursor = conn.execute("""
            SELECT id, clock_in, clock_out, duration_seconds 
            FROM sessions 
            WHERE guild_id = %s 
              AND user_id = %s 
              AND clock_in >= %s 
              AND clock_in < %s
            ORDER BY clock_in DESC
        """, (guild_id, user_id, start_date, end_date))
        return cursor.fetchall()

# EXAMPLE: Group sessions by date for calendar view
# You will need to implement this function
def get_sessions_grouped_by_date(guild_id, user_id, start_date, end_date):
    """Get sessions grouped by date for calendar view"""
    with db() as conn:
        cursor = conn.execute("""
            SELECT 
                DATE(clock_in) as work_date,
                COUNT(*) as session_count,
                SUM(duration_seconds) as total_seconds,
                MIN(clock_in) as first_clock_in,
                MAX(clock_out) as last_clock_out
            FROM sessions 
            WHERE guild_id = %s 
              AND user_id = %s 
              AND clock_in >= %s 
              AND clock_in < %s
            GROUP BY DATE(clock_in)
            ORDER BY work_date DESC
        """, (guild_id, user_id, start_date, end_date))
        return cursor.fetchall()
```

---

## 5. Timezone Handling

```python
from datetime import datetime, timezone, timedelta
import pytz  # For named timezones

# Default timezone
DEFAULT_TZ = "America/New_York"

# Get guild's configured timezone
# NOTE: guild_settings uses direct columns, NOT key-value pairs
def get_guild_timezone(guild_id):
    with db() as conn:
        cursor = conn.execute(
            "SELECT timezone FROM guild_settings WHERE guild_id = %s",
            (guild_id,)
        )
        row = cursor.fetchone()
        return row['timezone'] if row else DEFAULT_TZ

# Convert UTC to guild timezone
def utc_to_guild_tz(utc_dt, guild_id):
    tz = pytz.timezone(get_guild_timezone(guild_id))
    return utc_dt.replace(tzinfo=timezone.utc).astimezone(tz)

# Get current time in UTC
now_utc = datetime.now(timezone.utc)
```

---

## 6. Frontend Structure (IMPLEMENTED)

### Time Adjustments Section - Interactive Calendar

The Time Adjustments section now features an **interactive visual calendar** instead of a basic form:

**Key Components** (in `templates/dashboard.html`):
- `#adjustment-calendar-container` - Main calendar grid with clickable days
- `#day-edit-modal` - Popup modal for editing sessions on a specific day
- Calendar navigation with month/year controls

**JavaScript** (in `static/js/dashboard-adjustments.js`):
```javascript
// Calendar renders worked days with color-coded hours:
// - Green: 8+ hours worked
// - Orange: 4-8 hours worked  
// - Blue: Less than 4 hours worked

// Status indicators on calendar days:
// - Alert icon (yellow): Pending adjustment request
// - Checkmark (green): Approved adjustment
// - X mark (red): Denied adjustment

// Clicking a day with sessions opens the edit modal
// Modal shows pre-filled clock in/out times that can be edited
// Submitting creates a time_adjustment_request with status='pending'
```

**API Endpoints for Calendar**:
- `GET /api/guild/{id}/employee/{user_id}/monthly-timecard` - Gets sessions with adjustment status per day
- `POST /api/guild/{id}/adjustments/submit-day` - Submits day-level adjustment requests

**Access Control**:
- Employees can view/edit their OWN calendar only
- Admins can view any employee's calendar

### CSS Framework (`static/css/dashboard.css`)

**Not using Bootstrap or Tailwind - Custom CSS**

```css
/* Color scheme */
--gold-primary: #D4AF37;
--gold-light: #F4E5A1;
--bg-dark: #0A0F1F;
--bg-medium: #151B2E;
--text-primary: #C9D1D9;
--text-secondary: #8B949E;

/* Calendar-specific styles */
.adjustment-calendar { /* Monthly calendar grid */ }
.calendar-day.has-sessions { /* Days with work data */ }
.calendar-day.has-pending { /* Pending adjustment indicator */ }
.calendar-day.has-approved { /* Approved adjustment indicator */ }
.calendar-day.has-denied { /* Denied adjustment indicator */ }

/* Modal for day editing */
.day-edit-modal { /* Popup overlay */ }
.session-edit-row { /* Individual session editor */ }
```

---

## 7. Email Setup (Replit Mail)

### Using `email_utils.py`

```python
from email_utils import ReplitMailSender

# Initialize sender
mail = ReplitMailSender()

# Send email (async)
async def send_adjustment_notification(to_email, adjustment_details):
    await mail.send_email(
        to=to_email,
        subject="Time Adjustment Request Update",
        html=f"""
        <h2>Your time adjustment request has been processed</h2>
        <p>Status: {adjustment_details['status']}</p>
        <p>Reason: {adjustment_details['reason']}</p>
        """
    )

# Authentication is automatic via REPL_IDENTITY env var
```

---

## 8. Discord Bot Integration (Sending DMs from Flask)

### Pattern for calling async bot functions from sync Flask code

```python
# In app.py - bot is imported from bot.py
from bot import bot
import asyncio

def send_dm_from_flask(user_id: int, message: str):
    """Send Discord DM from Flask (sync context)"""
    async def _send():
        try:
            user = await bot.fetch_user(user_id)
            await user.send(message)
            return True
        except Exception as e:
            print(f"Failed to send DM: {e}")
            return False
    
    # Use the bot's event loop
    future = asyncio.run_coroutine_threadsafe(_send(), bot.loop)
    return future.result(timeout=10)

# Usage:
@app.route('/api/notify-user/<user_id>')
def notify_user(user_id):
    success = send_dm_from_flask(int(user_id), "Your adjustment was approved!")
    return jsonify({'success': success})
```

---

## 9. API Response Patterns

### Standard JSON Response Format

```python
# Success response
return jsonify({
    'success': True,
    'data': result_data
})

# Error response
return jsonify({
    'success': False,
    'error': 'Human readable error message'
}), 400  # or 401, 403, 500
```

### Authentication Decorator Pattern

```python
from functools import wraps

def require_paid_api_access(f):
    """Decorator requiring authentication AND paid bot access"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check session
        session_id = request.cookies.get('session_id')
        if not session_id:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        
        user_session = get_user_session(session_id)
        if not user_session:
            return jsonify({'success': False, 'error': 'Session expired'}), 401
        
        # Pass user_session to the route function
        return f(user_session, *args, **kwargs)
    return decorated_function

# Usage:
@app.route('/api/server/<guild_id>/sessions')
@require_paid_api_access
def get_sessions(user_session, guild_id):
    # user_session is automatically passed
    ...
```

---

## 10. Security Patterns (MUST FOLLOW)

### SSRF Prevention for Bot API Calls

```python
from urllib.parse import urlparse

def validate_bot_api_url(url):
    """Validate URL is safe for server-side requests"""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            return False
        if not parsed.hostname:
            return False
        hostname = parsed.hostname.lower()
        is_local = hostname in ('localhost', '127.0.0.1', '0.0.0.0', '::1')
        if os.environ.get('FLASK_ENV') == 'production' and is_local:
            return False
        if not url.startswith(BOT_API_BASE_URL):
            return False
        return True
    except Exception:
        return False

# Always validate before making requests
bot_api_url = f"{BOT_API_BASE_URL}/api/guild/{guild_id}/sessions"
if not validate_bot_api_url(bot_api_url):
    return jsonify({'error': 'Invalid request'}), 400
```

### SQL Injection Prevention

```python
# ALWAYS use parameterized queries
cursor = conn.execute(
    "SELECT * FROM sessions WHERE guild_id = %s AND user_id = %s",
    (guild_id, user_id)  # Parameters as tuple
)

# NEVER do this:
# cursor = conn.execute(f"SELECT * FROM sessions WHERE guild_id = '{guild_id}'")
```

### Input Validation

```python
# Discord IDs are snowflakes: numeric, max ~20 digits
def validate_discord_id(id_str):
    return id_str.isdigit() and len(id_str) <= 20

# Validate before using
if not validate_discord_id(guild_id):
    return jsonify({'error': 'Invalid guild ID'}), 400
```

---

## 11. Replit-Specific Configuration

### Port Requirements
- Frontend MUST bind to `0.0.0.0:5000` (only exposed port for web preview)
- Bot API runs on port `8081` (internal only)

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `DATABASE_URL` | PostgreSQL connection (auto-set by Replit) |
| `DISCORD_CLIENT_ID` | OAuth app ID |
| `DISCORD_CLIENT_SECRET` | OAuth app secret |
| `DISCORD_TOKEN` | Bot token |
| `STRIPE_SECRET_KEY` | Stripe API key |
| `BOT_API_SECRET` | Internal API authentication |
| `BOT_API_BASE_URL` | Bot API location (default: http://localhost:8081) |
| `FLASK_ENV` | production or development |

### Proxy Configuration

```python
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1, x_for=1)
```

---

## Phase 1 Implementation Checklist (COMPLETED)

- [x] Add interactive calendar UI with custom CSS grid layout
- [x] Create endpoint: `GET /api/guild/{id}/employee/{user_id}/monthly-timecard` - Returns sessions + adjustment status
- [x] Create endpoint: `POST /api/guild/{id}/adjustments/submit-day` - Submit day-level adjustments
- [x] Add calendar view to Time Adjustments section with month navigation
- [x] Display sessions when a date is clicked via modal popup
- [x] Pre-fill modal with editable clock in/out times
- [x] Submit creates adjustment request with session_date for calendar persistence
- [x] Status indicators on calendar (pending/approved/denied)
- [x] Access control: employees see own calendar, admins can view any employee
- [x] Security hardening: validate session ownership before submission

---

## Related Documentation

- `docs/anti_gravity_playbook.md` - Security patterns and coding conventions
- `docs/ai_bootstrap_prompt.txt` - Prompt to use before coding sessions
- `replit.md` - Project overview and architecture decisions
