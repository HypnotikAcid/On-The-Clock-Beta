# On the Clock 1.5

A professional Discord timeclock bot designed for businesses, featuring subscription management, Stripe payment integration, role-based access control, and a web-based admin dashboard.

---

## Deployment Environment

**Platform**: Replit (Reserved VM Deployment)
**Production URL**: `https://on-the-clock.replit.app`
**Repository**: `https://github.com/HypnotikAcid/On-The-Clock-Beta`

### Important Infrastructure Notes

1. **No Docker/Containers** - Replit uses Nix environment, not containerization
2. **Port Configuration**:
   - Flask/Gunicorn web server: **Port 5000** (must bind to `0.0.0.0:5000`)
   - Bot internal API server: **Port 8081** (aiohttp, used for Flask ↔ Bot communication)
3. **Database**: PostgreSQL (Replit-hosted Neon backend)
4. **Process Model**: Single Gunicorn worker runs Flask; Discord bot runs in daemon thread

---

## Quick Start (Replit)

```bash
# Start the application (configured in Replit workflow)
gunicorn app:app --bind 0.0.0.0:5000 --workers 1 --timeout 120
```

The startup process:
1. Gunicorn starts Flask app on port 5000
2. Flask spawns Discord bot in daemon thread
3. Bot starts internal HTTP API on port 8081
4. PostgreSQL connection pools are initialized

---

## Project Structure

```
/
├── app.py                  # Flask web app (landing page, dashboard, OAuth, webhooks)
├── bot.py                  # Discord bot (commands, button handlers, internal API)
├── scheduler.py            # APScheduler for automated emails
├── email_utils.py          # Email sending utilities
├── requirements.txt        # Python dependencies
├── replit.md              # Replit-specific documentation (auto-maintained)
├── templates/
│   ├── landing.html        # Public landing page
│   ├── dashboard.html      # Admin dashboard (main UI)
│   ├── server_selection.html
│   ├── dashboard_invite.html
│   ├── dashboard_no_access.html
│   ├── dashboard_purchase.html
│   └── owner_dashboard.html  # Bot owner admin panel
└── attached_assets/        # Static assets
```

---

## Environment Variables (Secrets)

All secrets are stored in Replit's Secrets panel. **Never hardcode these values.**

### Required

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL connection string (auto-provided by Replit) |
| `DISCORD_TOKEN` | Discord bot token |
| `DISCORD_CLIENT_ID` | Discord OAuth application ID |
| `DISCORD_CLIENT_SECRET` | Discord OAuth secret |
| `STRIPE_SECRET_KEY` | Stripe API secret key |
| `STRIPE_WEBHOOK_SECRET` | Stripe webhook signing secret |

### Auto-Generated

| Variable | Description |
|----------|-------------|
| `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGDATABASE` | PostgreSQL connection details |

### Optional

| Variable | Description |
|----------|-------------|
| `GUILD_ID` | For instant command sync to specific guild |
| `BOT_API_SECRET` | Internal API authentication (auto-generated if not set) |
| `SENDGRID_API_KEY` | For email functionality |
| `SENDGRID_FROM_EMAIL` | Sender email address |

---

## Database Schema (PostgreSQL)

### Core Tables

| Table | Purpose |
|-------|---------|
| `sessions` | Active clock-in sessions (user_id, guild_id, clock_in, clock_out) |
| `timeclock_sessions` | Historical time records |
| `server_subscriptions` | Subscription status per guild (tier, bot_access_paid, retention_tier, restrict_mobile_clockin) |
| `guild_settings` | Per-guild configuration (timezone, recipient, display mode) |
| `admin_roles` | Roles with admin access |
| `employee_roles` | Roles that can use timeclock |
| `authorized_roles` | Additional role-based permissions |
| `banned_users` | Spam prevention ban list |
| `email_settings` | Auto-email configuration |
| `report_recipients` | Who receives reports |
| `webhook_events` | Stripe webhook logging |
| `user_sessions` | Discord OAuth sessions |
| `bot_guilds` | All guilds the bot is in |

### Column Types - CRITICAL

- **Boolean columns**: Use `True`/`False` Python values, NOT `int()` conversion
- **Guild/User IDs**: Stored as `BIGINT` or `TEXT` depending on table
- **Timestamps**: Use `timezone.utc` for all datetime operations

---

## AI Coding Guidelines (DOs and DON'Ts)

### Database Operations

```python
# ✅ CORRECT - Dictionary access for RealDictCursor rows
row = cursor.fetchone()
guild_id = row['guild_id']
user_id = row['user_id']

# ❌ WRONG - Tuple unpacking (unpacks KEYS, not VALUES!)
guild_id, user_id = row  # This unpacks dictionary KEYS!
```

```python
# ✅ CORRECT - Boolean values for PostgreSQL
cursor.execute("UPDATE server_subscriptions SET restrict_mobile_clockin = %s WHERE guild_id = %s",
               (True, guild_id))  # Use True/False

# ❌ WRONG - Integer conversion
cursor.execute("UPDATE server_subscriptions SET restrict_mobile_clockin = %s WHERE guild_id = %s",
               (int(value), guild_id))  # Don't use int()!
```

```python
# ✅ CORRECT - PostgreSQL syntax
cursor.execute("INSERT INTO table (col) VALUES (%s) ON CONFLICT (col) DO UPDATE SET col = EXCLUDED.col",
               (value,))

# ❌ WRONG - SQLite syntax
cursor.execute("INSERT OR REPLACE INTO table (col) VALUES (?)", (value,))
```

### Discord Interactions

```python
# ✅ CORRECT - Timezone-aware timestamps
from datetime import datetime, timezone
now = datetime.now(timezone.utc)

# ❌ WRONG - Naive timestamps
now = datetime.now()  # Missing timezone!
```

```python
# ✅ CORRECT - Check if interaction is responded
if interaction.response.is_done():
    await interaction.followup.send(content, ephemeral=True)
else:
    await interaction.response.send_message(content, ephemeral=True)

# ❌ WRONG - Assume interaction state
await interaction.response.send_message(content)  # May fail if already responded
```

### API Calls from Dashboard

```python
# ✅ CORRECT - Use internal localhost for Flask → Bot communication
response = requests.get(f'http://localhost:8081/api/endpoint')

# ❌ WRONG - External URL for internal API
response = requests.get(f'https://on-the-clock.replit.app/api/endpoint')
```

```python
# ✅ CORRECT - For frontend calling backend, use environment domain
# In JavaScript/frontend code:
const domain = window.location.origin;  # Gets the Replit domain
fetch(`${domain}/api/endpoint`)

# ❌ WRONG - Using localhost in frontend
fetch('http://localhost:5000/api/endpoint')  # Won't work for users!
```

### Persistent Discord Buttons

```python
# ✅ CORRECT - Persistent view with custom_id and timeout=None
class MyView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)  # Never timeout
    
    @discord.ui.button(label="Click", custom_id="my_button", style=discord.ButtonStyle.primary)
    async def button_callback(self, interaction, button):
        pass

# Register in setup_hook:
async def setup_hook(self):
    self.add_view(MyView())
```

### Security

```python
# ✅ CORRECT - Webhook signature verification
@app.route('/webhook', methods=['POST'])
def stripe_webhook():
    sig = request.headers.get('Stripe-Signature')
    try:
        event = stripe.Webhook.construct_event(request.data, sig, STRIPE_WEBHOOK_SECRET)
    except SignatureVerificationError:
        return 'Invalid signature', 400

# ❌ WRONG - No signature verification
event = json.loads(request.data)  # Unsafe!
```

### Things to NEVER Do

1. **Never change ID column types** - Don't convert `serial` to `varchar` or vice versa
2. **Never use Docker** - Replit uses Nix, not containers
3. **Never hardcode secrets** - Use environment variables
4. **Never use SQLite syntax** - This is PostgreSQL
5. **Never bind to ports other than 5000** for the web server (Replit requirement)
6. **Never use naive datetimes** - Always use timezone-aware (UTC)
7. **Never call external domain for internal API** - Use localhost:8081

---

## Current Features (v1.5)

### Discord Bot
- 25 slash commands (setup, clock, reports, admin management, etc.)
- Persistent button interface (Clock In, Clock Out, Break, Reports, Upgrade)
- Role-based access control (admin roles, employee roles)
- Mobile device restriction (optional)
- Rate limiting and spam detection with auto-bans
- Data retention tiers (Free, 7-day, 30-day)

### Web Dashboard
- Discord OAuth2 authentication
- Server selection for admins
- Tile-based settings interface:
  - Server Overview
  - Admin Roles management
  - Employee Roles management
  - Email Settings
  - Ban Management
- Owner-only dashboard (`/owner`) for bot owner

### Payment System (Stripe)
- $5 one-time bot access payment per server
- $5/month 7-day data retention
- $10/month 30-day data retention
- Webhook handling for `checkout.session.completed` and `customer.subscription.deleted`

### Email Automation
- Auto-send reports on clock-out
- Pre-deletion warning emails
- Scheduled report delivery (APScheduler)

---

## Future Goals / Roadmap

### Phase 1: Enhanced Employee Experience
- **Employee Name Cards**: Visual cards showing active employees with stats (hours today/week/month)
- **Time Adjustment Requests**: Employees request corrections, admins see visual before/after comparison and approve/deny

### Phase 2: Web Dashboard as Primary
- **Standalone Web Clock-In/Out**: Users can clock in from web dashboard, not just Discord
- **Ad Integration**: Display ads for free tier users
- **Premium Feature Gating**: Lock advanced features behind subscription

### Phase 3: Full SaaS Platform
- **Multi-Company Support**: Single dashboard for managing multiple organizations
- **API Access**: Public API for third-party integrations
- **Custom Branding**: White-label options for enterprise
- **Discord Bot as Add-On**: "Use our timeclock via web OR Discord!" as unique selling point

### Monetization Strategy
- Free tier: Basic dashboard + ads
- Paid tier: No ads, employee cards, time adjustments, reports
- Enterprise: Custom branding, API access, priority support

---

## Bot Owner Information

**Bot Owner Discord ID**: `107103438139056128`

Owner-only commands:
- `/owner_grant` - Grant subscription tier to current server
- `/owner_grant_server` - Grant subscription to any server by ID
- `/owner_server_listings` - View all servers with employee/admin headcounts

Owner dashboard: `https://on-the-clock.replit.app/owner`

---

## Discord Bot Intents Required

Enable these in Discord Developer Portal:
- **Presence Intent** - Required for `is_on_mobile()` detection
- **Server Members Intent** - Required for member information

---

## Testing Locally

If testing changes locally before pushing:
1. Ensure PostgreSQL is accessible
2. Set all required environment variables
3. Run with: `python -m gunicorn app:app --bind 0.0.0.0:5000 --workers 1 --timeout 120`

---

## Deployment Notes

- **Workflow Name**: "Bot & Landing Page"
- **Command**: `gunicorn app:app --bind 0.0.0.0:5000 --workers 1 --timeout 120`
- **Deployment Type**: Reserved VM (required for persistent bot connection)

After making changes:
1. Push to GitHub
2. Pull in Replit
3. Restart the "Bot & Landing Page" workflow
4. Check logs for successful bot login

---

## License

Proprietary - All rights reserved

---

## Contact

For issues with this project, contact the bot owner via Discord.
