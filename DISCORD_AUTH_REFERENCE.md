# Discord OAuth 2.0 Implementation Reference

**Version**: 1.0 (September 2025)  
**Framework**: Flask + Discord.py  
**Deployment**: Replit VM

---

## Quick Start

This reference documents a production-ready Discord OAuth 2.0 implementation for Flask applications, including all lessons learned and gotchas encountered during development.

## Core Concept

Discord OAuth allows users to log in with their Discord account and grants your app access to:
- User profile (avatar, username, ID)
- List of Discord servers the user is in
- User's roles and permissions in each server

## Architecture

```
┌─────────────┐     OAuth     ┌──────────────┐
│   Discord   │◄─────────────►│   Flask App  │
│   OAuth     │               │  (app.py)    │
└─────────────┘               └──────┬───────┘
                                     │
                                     ▼
                              ┌─────────────┐
                              │  SQLite DB  │
                              │  Sessions   │
                              └─────────────┘
```

## Implementation Files

### 1. Flask Application (app.py)

Key components:

```python
from flask import Flask, session, redirect, request, render_template
from werkzeug.middleware.proxy_fix import ProxyFix
import logging

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# CRITICAL: Enable ProxyFix for Replit
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1, x_for=1)

# Configure logging for Gunicorn
if __name__ != '__main__':
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)
```

### OAuth Routes

```python
@app.route("/auth/login")
def auth_login():
    """Redirect to Discord OAuth"""
    state = create_oauth_state()  # CSRF token
    redirect_uri = get_redirect_uri()
    
    params = {
        'client_id': DISCORD_CLIENT_ID,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': 'identify guilds',  # Request permissions
        'state': state
    }
    
    auth_url = f'https://discord.com/oauth2/authorize?{urlencode(params)}'
    return redirect(auth_url)

@app.route("/auth/callback")
def auth_callback():
    """Handle Discord OAuth callback"""
    code = request.args.get('code')
    state = request.args.get('state')
    
    # Verify CSRF token
    if not verify_oauth_state(state):
        return "Security validation failed", 400
    
    # Exchange code for token
    token_data = exchange_code_for_token(code, get_redirect_uri())
    access_token = token_data['access_token']
    
    # Get user data
    user_data = get_user_info(access_token)
    guilds_data = get_user_guilds(access_token)
    
    # Create session
    session_id = create_user_session(user_data, access_token, guilds_data)
    session['session_id'] = session_id
    
    return redirect('/dashboard')

@app.route("/dashboard")
@require_auth  # Decorator checks session
def dashboard(user_session):
    return render_template('dashboard.html', user=user_session)
```

### 2. Custom Jinja2 Filter (CRITICAL!)

**Problem**: Jinja2 doesn't support bitwise operators (`&`, `|`, `^`)

**Solution**: Custom filter

```python
@app.template_filter('has_permission')
def has_permission(permissions, permission_flag):
    """Check if a permission integer has a specific flag"""
    try:
        return int(permissions) & permission_flag != 0
    except (ValueError, TypeError):
        return False
```

**Usage in Template**:
```jinja
{% if guild.permissions|has_permission(0x8) %}
    <span class="badge">Administrator</span>
{% elif guild.permissions|has_permission(0x20) %}
    <span class="badge">Manage Server</span>
{% endif %}
```

**Common Discord Permission Flags**:
- `0x8` - Administrator
- `0x20` - Manage Server
- `0x10` - Manage Channels
- `0x2` - Kick Members
- `0x4` - Ban Members

### 3. Database Schema

```sql
-- OAuth CSRF tokens (temporary)
CREATE TABLE oauth_states (
    state TEXT PRIMARY KEY,
    expires_at TEXT NOT NULL
);

-- User sessions (persistent)
CREATE TABLE user_sessions (
    session_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    username TEXT NOT NULL,
    access_token TEXT NOT NULL,
    guilds_data TEXT NOT NULL,  -- JSON string
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
```

### 4. Helper Functions

```python
def create_oauth_state():
    """Generate CSRF protection token"""
    state = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
    
    with get_db() as conn:
        conn.execute(
            "INSERT INTO oauth_states (state, expires_at) VALUES (?, ?)",
            (state, expires_at.isoformat())
        )
    return state

def verify_oauth_state(state):
    """Verify and consume CSRF token (one-time use)"""
    with get_db() as conn:
        cursor = conn.execute(
            "SELECT state FROM oauth_states WHERE state = ? AND expires_at > ?",
            (state, datetime.now(timezone.utc).isoformat())
        )
        result = cursor.fetchone()
        
        if result:
            # Delete after use (one-time)
            conn.execute("DELETE FROM oauth_states WHERE state = ?", (state,))
            return True
    return False

def exchange_code_for_token(code, redirect_uri):
    """Exchange authorization code for access token"""
    data = {
        'client_id': DISCORD_CLIENT_ID,
        'client_secret': DISCORD_CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirect_uri
    }
    
    response = requests.post(
        'https://discord.com/api/v10/oauth2/token',
        data=data,
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )
    response.raise_for_status()
    return response.json()

def get_user_info(access_token):
    """Fetch user profile from Discord"""
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get(
        'https://discord.com/api/v10/users/@me',
        headers=headers
    )
    response.raise_for_status()
    return response.json()

def get_user_guilds(access_token):
    """Fetch user's Discord servers"""
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get(
        'https://discord.com/api/v10/users/@me/guilds',
        headers=headers
    )
    response.raise_for_status()
    return response.json()
```

## Security Best Practices

### 1. Never Expose Internal Errors to Users

❌ **Bad**:
```python
except Exception as e:
    return f"Error: {str(e)}", 500  # Leaks internal details!
```

✅ **Good**:
```python
except Exception as e:
    app.logger.error(f"OAuth callback error: {str(e)}")
    app.logger.error(traceback.format_exc())
    return "An error occurred. Please try again later.", 500
```

### 2. Redact Sensitive Values in Logs

❌ **Bad**:
```python
app.logger.error(f"Invalid OAuth state: {state}")  # Full token logged!
```

✅ **Good**:
```python
app.logger.error(f"Invalid OAuth state: {state[:8]}... (CSRF check failed)")
```

### 3. Use Database Sessions (Not In-Memory)

**Why**: Gunicorn workers can restart, causing in-memory sessions to be lost.

✅ **Good**: Store sessions in SQLite/PostgreSQL

### 4. CSRF Protection

Always use `state` parameter for OAuth to prevent CSRF attacks:
1. Generate random state token before redirecting to Discord
2. Store in database with expiration
3. Verify state when Discord redirects back
4. Delete state after one-time use

## Environment Variables

Required for OAuth:
```bash
DISCORD_CLIENT_ID=your_client_id
DISCORD_CLIENT_SECRET=your_client_secret
SECRET_KEY=random_secret_for_flask_sessions
```

Optional but recommended:
```bash
DISCORD_REDIRECT_URI=https://yourdomain.replit.app/auth/callback
```

## Replit Deployment

### Configuration (.replit)

```toml
[deployment]
deploymentTarget = "vm"  # Use VM, not autoscale
run = ["python", "start.py"]  # If combining with Discord bot
```

### Why VM?

- **Persistent state** required for Discord bot
- **Database** needs to persist
- **Background processes** (bot runs alongside web server)

### start.py Pattern

If you're running a Discord bot + OAuth dashboard:

```python
import subprocess
import threading
import time

def run_discord_bot():
    subprocess.run(["python", "bot.py"])

def run_flask_app():
    subprocess.run([
        "gunicorn", "app:app",
        "--bind", "0.0.0.0:5000",
        "--workers", "2"
    ])

def main():
    # Start bot in background
    bot_thread = threading.Thread(target=run_discord_bot, daemon=True)
    bot_thread.start()
    
    time.sleep(2)  # Let bot initialize
    
    # Run Flask in main thread
    run_flask_app()

if __name__ == "__main__":
    main()
```

## Common Issues & Solutions

### Issue: Jinja2 Template Error

**Symptom**: Template fails to render with "expected token 'end of print statement'"

**Cause**: Using bitwise operator in template:
```jinja
{% if guild.permissions|int & 0x8 %}  {# ❌ Won't work #}
```

**Solution**: Use custom filter:
```jinja
{% if guild.permissions|has_permission(0x8) %}  {# ✅ Works #}
```

### Issue: Port 5000 Already in Use

**Symptom**: `Address already in use` error

**Cause**: Old Gunicorn processes still running

**Solution**:
```bash
# Find processes
ps aux | grep gunicorn

# Kill all
pkill -9 gunicorn

# Or kill specific PID
kill -9 <PID>
```

### Issue: Database Initialization Fails During Deployment

**Symptom**: Deployment errors mentioning app.logger

**Cause**: Using `app.logger` before Gunicorn initializes it

**Solution**: Wrap initialization:
```python
try:
    init_dashboard_tables()
except Exception as e:
    print(f"⚠️ Dashboard initialization warning: {e}")
```

### Issue: Sessions Don't Persist Across Restarts

**Symptom**: Users logged out when workflow restarts

**Cause**: Using Flask's default in-memory sessions

**Solution**: Use database-backed sessions (as shown in this reference)

### Issue: OAuth Callback Shows "Invalid State"

**Symptom**: CSRF validation fails

**Possible Causes**:
1. State token expired (check expiration time)
2. Database connection issue
3. State already used (one-time tokens)

**Debug**:
```python
app.logger.info(f"Received state: {state[:8]}...")
# Check if state exists in database
```

## Dashboard Template Example

```html
<!DOCTYPE html>
<html>
<head>
    <title>Dashboard - {{ user.username }}</title>
</head>
<body>
    <div class="profile">
        <img src="https://cdn.discordapp.com/avatars/{{ user.user_id }}/{{ user.avatar }}.png">
        <h1>{{ user.username }}</h1>
        <p>ID: {{ user.user_id }}</p>
    </div>
    
    <div class="servers">
        <h2>Your Servers ({{ user.guilds|length }})</h2>
        {% for guild in user.guilds %}
        <div class="server">
            <h3>{{ guild.name }}</h3>
            {% if guild.owner %}
                <span class="badge owner">👑 Owner</span>
            {% elif guild.permissions|has_permission(0x8) %}
                <span class="badge admin">⚡ Administrator</span>
            {% elif guild.permissions|has_permission(0x20) %}
                <span class="badge manage">🔧 Manage Server</span>
            {% endif %}
        </div>
        {% endfor %}
    </div>
</body>
</html>
```

## Testing Checklist

Before deploying:

- [ ] OAuth login redirects to Discord correctly
- [ ] Discord redirects back to callback URL
- [ ] State token verification works
- [ ] User session created and stored in database
- [ ] Dashboard displays user profile
- [ ] Server list shows with correct permissions
- [ ] Logout clears session
- [ ] Sessions persist across workflow restarts
- [ ] Error messages are generic (no sensitive data)
- [ ] Logs contain detailed errors for debugging

## References

- [Discord OAuth Documentation](https://discord.com/developers/docs/topics/oauth2)
- [Discord Permissions Calculator](https://discordapi.com/permissions.html)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [Werkzeug ProxyFix](https://werkzeug.palletsprojects.com/en/stable/middleware/proxy_fix/)

---

**Last Updated**: September 30, 2025  
**Tested On**: Replit VM Deployment  
**Status**: Production-Ready ✅
