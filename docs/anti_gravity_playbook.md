# Anti Gravity AI Coding Playbook

> **Purpose**: Learning document for AI coding assistants working on this project  
> **Last Updated**: November 28, 2025  
> **Project**: On the Clock - Discord Bot + Flask Web Dashboard

---

## Project Snapshot

### Architecture Overview
- **Flask Web App** (`app.py`): Landing page, OAuth dashboard, Stripe webhooks, API endpoints
- **Discord Bot** (`bot.py`): Discord.py bot with slash commands, time tracking, role management
- **Database**: PostgreSQL (Neon-backed via Replit)
- **Payments**: Stripe integration for bot access and retention tiers
- **Authentication**: Discord OAuth2 for dashboard access

### Key Services Communication
```
User Browser → Flask (port 5000) → Discord API
                    ↓
              Bot API (port 8081) ← Discord Bot
                    ↓
              PostgreSQL Database
```

---

## Security Fixes & Lessons Learned

### SSRF (Server-Side Request Forgery) Prevention

**The Problem We Fixed (November 2025)**:
Code was making server-side HTTP requests using URLs partially constructed from user input without proper validation.

**Original Vulnerable Pattern** (DO NOT USE):
```python
# BAD: Ineffective validation - always passes
bot_api_url = f"{BOT_API_BASE_URL}/api/guild/{guild_id}/action"
if not bot_api_url.startswith(BOT_API_BASE_URL):  # This ALWAYS passes!
    return error

response = requests.post(bot_api_url, ...)
```

**Fixed Secure Pattern** (USE THIS):
```python
from urllib.parse import urlparse

def validate_bot_api_url(url):
    """Validate URL is safe for server-side requests (SSRF prevention)."""
    try:
        parsed = urlparse(url)
        
        # Ensure scheme is http or https only
        if parsed.scheme not in ('http', 'https'):
            return False
        
        # Ensure hostname exists
        if not parsed.hostname:
            return False
        
        # Block localhost/private IPs in production
        hostname = parsed.hostname.lower()
        is_local = hostname in ('localhost', '127.0.0.1', '0.0.0.0', '::1')
        if os.environ.get('FLASK_ENV') == 'production' and is_local:
            return False
        
        # Verify URL starts with allowed base
        if not url.startswith(BOT_API_BASE_URL):
            return False
            
        return True
    except Exception:
        return False

# Usage
bot_api_url = f"{BOT_API_BASE_URL}/api/guild/{guild_id}/action"
if not validate_bot_api_url(bot_api_url):
    app.logger.error("SSRF protection: Invalid bot API URL rejected")
    return jsonify({'error': 'Invalid request'}), 400

response = requests.post(bot_api_url, ...)
```

**Key Lessons**:
1. Always validate URL scheme (http/https only)
2. Block internal/private IPs in production
3. Validate hostname exists
4. Use a dedicated validation function, not inline checks
5. Log security rejections for monitoring

### SQL Injection Prevention

**Correct Pattern** (Already in use - maintain this):
```python
# GOOD: Parameterized queries with %s placeholders
cursor = conn.execute(
    "SELECT * FROM users WHERE guild_id = %s AND user_id = %s",
    (guild_id, user_id)
)
```

**Never Do This**:
```python
# BAD: String formatting in SQL
cursor = conn.execute(f"SELECT * FROM users WHERE guild_id = '{guild_id}'")
```

### Secret Handling

**Rules**:
1. Never log actual secret values
2. Use environment variables for all secrets
3. Log only error messages about missing secrets, not the values
4. Store secrets in Replit Secrets tab, not in code

**Correct Logging**:
```python
# GOOD: Log that secret is missing, not its value
if not bot_api_secret:
    app.logger.error("BOT_API_SECRET not configured")
    
# BAD: Never do this
app.logger.info(f"Using secret: {bot_api_secret}")
```

---

## Implementation Guardrails

### Input Validation Patterns

**Discord IDs** (guild_id, user_id, role_id):
```python
# Discord IDs are snowflakes: numeric, max ~20 digits
if not guild_id.isdigit() or len(guild_id) > 20:
    return jsonify({'error': 'Invalid guild ID format'}), 400
```

**Role Validation**:
```python
# Always verify role belongs to the guild
def validate_role_in_guild(guild_id, role_id):
    roles = get_guild_roles_from_bot(guild_id)
    return any(str(role['id']) == str(role_id) for role in roles)
```

### Error Handling

**Fail Closed Pattern**:
```python
# When security checks fail, deny access (fail closed)
try:
    result = verify_access(user, resource)
except Exception as e:
    app.logger.error(f"Access check failed: {e}")
    return {'access': False, 'reason': 'check_error'}  # Deny on error
```

### API Response Patterns

**Consistent JSON Responses**:
```python
# Success
return jsonify({'success': True, 'data': result})

# Error
return jsonify({'success': False, 'error': 'Human readable message'}), 400
```

### Database Patterns

**Connection Pool Usage**:
```python
@contextmanager
def get_flask_db():
    conn = app_db_pool.getconn()
    try:
        wrapped = FlaskConnectionWrapper(conn)
        yield wrapped
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        app_db_pool.putconn(conn)
```

---

## Replit Operations Guide

### Critical Port Configuration

**Rule**: Frontend servers MUST bind to `0.0.0.0:5000`
- Port 5000 is the only port automatically exposed for web previews
- Other ports (3000, 8080, etc.) remain internal

```python
# Flask
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

# Gunicorn
gunicorn --bind=0.0.0.0:5000 app:app
```

### Proxy Configuration

**Important**: Replit runs apps behind a reverse proxy. Configure Flask:
```python
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1, x_for=1)
```

### Environment Variables

| Variable | Purpose | Where to Set |
|----------|---------|--------------|
| `DATABASE_URL` | PostgreSQL connection | Auto-set by Replit DB |
| `DISCORD_CLIENT_ID` | OAuth app ID | Secrets tab |
| `DISCORD_CLIENT_SECRET` | OAuth app secret | Secrets tab |
| `DISCORD_TOKEN` | Bot token | Secrets tab |
| `STRIPE_SECRET_KEY` | Stripe API key | Secrets tab |
| `BOT_API_SECRET` | Internal API auth | Secrets tab |
| `BOT_API_BASE_URL` | Bot API location | Environment |
| `FLASK_ENV` | production/development | Environment |

### Deployment Checklist

Before deploying to production:
1. Set `FLASK_ENV=production`
2. Verify all secrets are configured
3. Test OAuth flow works
4. Verify Stripe webhooks are configured
5. Check bot has required Discord permissions
6. Ensure database migrations have run

### Cache Control for Development

When changes aren't visible in the Replit webview:
```python
@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return response
```

---

## Framework-Specific Notes

### Flask + Discord.py Async Coordination

The bot runs in a background thread. For Flask to call bot functions:
```python
# Run async bot functions from Flask
import asyncio
import concurrent.futures

def run_async_bot_function(coro):
    """Run async function from sync Flask context."""
    loop = bot.loop
    future = asyncio.run_coroutine_threadsafe(coro, loop)
    return future.result(timeout=10)
```

### Stripe Webhook Handling

```python
@app.route('/stripe/webhook', methods=['POST'])
def stripe_webhook():
    payload = request.get_data()
    sig_header = request.headers.get('Stripe-Signature')
    
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except SignatureVerificationError:
        return jsonify({'error': 'Invalid signature'}), 400
```

---

## Appendix: Quick Reference

### Validation Utilities

| Function | Purpose |
|----------|---------|
| `validate_bot_api_url(url)` | SSRF prevention for bot API calls |
| `validate_role_in_guild(guild_id, role_id)` | Verify role belongs to guild |
| `verify_guild_access(user_session, guild_id)` | Check user has guild access |
| `check_user_admin_realtime(user_id, guild_id)` | Real-time admin check via bot |

### HTTP Status Codes Used

| Code | Meaning |
|------|---------|
| 200 | Success |
| 400 | Bad request / validation error |
| 401 | Not authenticated |
| 403 | Forbidden / access denied |
| 500 | Server error |

---

## Change Log

| Date | Change | Author |
|------|--------|--------|
| 2025-11-28 | Added SSRF protection with `validate_bot_api_url()` | Agent |
| 2025-11-28 | Created initial playbook | Agent |

---

## How to Update This Document

When fixing bugs or adding features:
1. Add security lessons to "Security Fixes & Lessons"
2. Add new patterns to "Implementation Guardrails"
3. Update the Change Log
4. Keep examples concise and copy-pasteable
