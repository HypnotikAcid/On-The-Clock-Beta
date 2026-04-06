# Lessons Learned & Coding Patterns

## Workflow & Discipline
- **Mandatory Pre-Check**: ALWAYS read `docs/lessons-learned.md` before editing or adding ANY code.
- **Plan Mode Workflow**: Split all tasks into **Fast** (lightweight) vs **Autonomous** (complex).
- **Execution Order**: Fast tasks first → STOP → Autonomous tasks after user confirms.
- **Post-Work**: Update this file if new lessons are learned.

## Development & Security
- **Flask Route Uniqueness**: Never define the same route decorator twice.
- **Database Guards**: Use process-level flags for one-time initialization.
- **SQL Injection**: Always use parameterized statements.
- **XSS Prevention**: Use `escapeHtml()` for user data.
- **SSRF Protection**: Strict validation for `guild_id` in Bot API requests.
- **AI Auth Bugs**: AI-generated authentication code often has bypass vulnerabilities - ALWAYS manually review auth logic.

## UI/UX & Identity
- **Visual Identity**: "Neon Cyber" theme with animated CSS clock and cyan matrix rain.
- **Accessibility**: Decorative elements must have `aria-hidden="true"`.
- **Mobile First**: Test interactive components (accordions, kiosks) on mobile viewports.
- **Component Persistence**: Use `localStorage` for visual preferences (theme toggles).
- **Top-Right Stacking**: Matrix Toggle -> Coffee Button -> Demo Panel.

## Features & Logic
- **Tier Terminology**: Always use `Entitlements.get_guild_tier()`.
- **Admin Calendar**: Guard with `{% if active_page == 'calendar' %}`.
- **Demo Server**: ID `1419894879894507661` auto-resets daily at midnight UTC.
- **Kiosk Customization**: Icons/colors only show when clocked in.

## Multi-Agent Coordination
- **Session Continuity**: Update `CURRENT_TASK.md` during complex work for handoff between agents.
- **Git Discipline**: CLI agents (Claude Code, Gemini) don't auto-commit - commit frequently.
- **File Isolation**: Don't have multiple agents edit the same files simultaneously.
- **Briefing Request**: When switching agents, ask "Give me a briefing on CURRENT_TASK.md".

## Refactoring Safety Protocol (MANDATORY — All Agents)
Moving code between files is the #1 source of silent catastrophic breakage in this project. The Antigravity Cog refactor (`706cf69`) is the cautionary example: all handler functions were moved correctly, but the server startup code that *wired them together* was dropped — killing the entire bot API with zero errors at import time.

### Before Any Refactor
1. **Map the wiring, not just the functions.** For every file being refactored, identify:
   - Server/service startup code (e.g., `web.Application()`, `AppRunner`, `TCPSite`, `create_task`)
   - Registration code (e.g., `app.router.add_post(...)`, `app.register_blueprint(...)`)
   - Initialization sequences (e.g., `asyncio.create_task(start_something())`)
   - Background thread launches (e.g., `threading.Thread(target=...).start()`)
   These are the "glue" — they don't look important but without them nothing works.

2. **Run the connection audit before AND after.** Check that every endpoint/handler is still reachable:
   ```bash
   # Bot API server wiring (must show web.Application + all routes + AppRunner + TCPSite):
   grep -n "web\.Application\|app\.router\.add\|AppRunner\|TCPSite\|start_bot_api_server" bot_core.py
   
   # Flask blueprint registration:
   grep -n "register_blueprint" app.py
   
   # Verify startup log markers exist — if these prints are gone, the wiring is gone:
   grep -n "🔌 Bot API server running\|Bot API server" bot_core.py discord_runner.py
   ```

3. **Leave breadcrumb comments at critical wiring points.** Any code that starts a server, registers routes, or launches background tasks MUST have a comment like:
   ```python
   # ⚠️ CRITICAL WIRING: This starts the aiohttp API server on port 8081.
   # All Flask→Bot API calls (broadcast, sync, channels, etc.) depend on this.
   # If this is removed or not called, Flask will get ConnectionError on every bot API call.
   # See: docs/lessons-learned.md "Refactoring Safety Protocol"
   ```

4. **Verify with a smoke test.** After any refactor that moves bot or Flask code:
   - Restart the workflow
   - Confirm `🔌 Bot API server running on http://0.0.0.0:8081` appears in startup logs
   - Confirm `✅ BOT_API_SECRET configured` appears in startup logs
   - Confirm no `ConnectionError` when hitting a bot API endpoint

### Critical Wiring Points in This Project
| What | Where | Startup Log Marker | If Missing |
|------|-------|--------------------|------------|
| Bot API server (aiohttp on :8081) | `bot_core.py:start_bot_api_server()` | `🔌 Bot API server running on http://0.0.0.0:8081` | ALL Flask→Bot calls fail (broadcast, sync, channels, reports, onboarding) |
| Bot API task launch | `discord_runner.py:run_bot_with_api()` | (same as above) | Server function exists but never runs |
| BOT_API_SECRET | Environment variable | `✅ BOT_API_SECRET configured` | Bot API returns 401 on every call |
| Flask blueprints | `app.py:register_blueprint()` | N/A — check route registration | Dashboard/API routes return 404 |
| Discord bot thread | `app.py:start_discord_bot()` | `🤖 Logged in as On the Clock` | Bot offline, no slash commands |
| Email scheduler | `bot_core.py` via `on_ready` | `✅ Email scheduler started` | Scheduled reports stop sending |
- **Context Files**: All agents should read `replit.md` first, then this file.
- **Progressive Disclosure**: Don't overload context - point to specific docs when needed.
- **Date Awareness**: AI may think it's 2024 - verify current date if time-sensitive.

## CSV Report Usernames
- **Three-tier fallback**: employee_profiles.display_name → employee_profiles.full_name → Discord API fetch → "User [ID]"
- **Sanitize commas**: Replace commas in names with spaces for CSV safety.
- **LEFT JOIN**: Always use LEFT JOIN with employee_profiles to handle missing profiles.

## Email Queue Pattern (2026-01-25)
- **Never block on email sends**: Use `queue_email()` for all email notifications.
- **Benefits**: Automatic retry (3 attempts, exponential backoff), no UI freezing, consistent architecture.
- **Example**: `queue_adjustment_notification_email()` in email_utils.py.
- **Processing**: Scheduler runs `process_email_outbox` every 30 seconds.
- **When to use**: Any email triggered by user action (adjustments, reports, notifications).

## Demo Server Protection (2026-01-25)
- **Demo ID**: `'1419894879894507661'` (string, not int)
- **Helper function**: Use `is_demo_server(guild_id)` for all checks - handles int/string types.
- **Sandboxing pattern**: Dead-end all mutations with fake success messages + demo_note field.
- **Example**: PIN creation, clock in/out, email updates, adjustment submissions all return success but don't modify DB.
- **Read operations**: Allow normal operation (employee lists, session data).
- **Benefits**: Zero risk to production, users see what would happen, marketing demo remains functional.

## Tier Gating (2026-01-25)
- **Feature-level decorators**: Create specific decorators for feature access (e.g., `@require_kiosk_access`).
- **Pattern**: Check demo server first (always allow), then check tier via `Entitlements.get_guild_tier()`.
- **Error responses**: Include `code`, `current_tier`, `required_tier`, and `upgrade_url` for clear UX.
- **Consistency**: Use same tier checking logic as existing `@require_paid_api_access`.
- **Example**: Kiosk requires Pro tier, 11 routes protected with single decorator.

## Trial System Foundation (2026-02-09)
- **Database Schema**: Added `trial_start_date` (TIMESTAMP) and `trial_expired` (BOOLEAN) to `guild_settings` table to track 30-day trial periods.
- **Automatic Trial Start**: The bot now automatically sets the `trial_start_date` when it joins a new server (`on_guild_join`) and backfills it for existing servers on startup.
- **Entitlements Helpers**: New functions in `entitlements.py` (`is_trial_active`, `get_trial_days_remaining`, `is_server_exempt`) provide a centralized way to check trial status and exemptions for the demo server and grandfathered guilds.
- **Tier Definitions**: Updated tier definitions and messages in `entitlements.py` to reflect the new trial system and pricing.
- **Access Info Helper**: New `get_guild_access_info` function in `bot.py` consolidates tier and trial status checks.

## Bot Command Trial Enforcement (2026-02-09)
- **Centralized Access Check**: All major bot commands (`/clock`, reports, context menus) now use `get_guild_access_info` to check trial status.
- **Hard Lock**: Commands are blocked with an upgrade message if the server is on the free tier and the trial is expired. Exempt servers (demo, owner-granted) are always allowed.
- **Graduated Messaging**: The `/clock` command now shows increasingly urgent warnings as a trial period nears its end (e.g., at 7 days, 3 days).
- **Consistent Pricing**: All pricing and tier-related messaging in bot commands (`/help`, `/upgrade`, etc.) has been updated to reflect the new model ($8/mo Premium, $15/mo Pro). Old terms like "Dashboard Premium" and "$5 one-time" have been removed.
- **Safe Commands**: `/help` and `/upgrade` are always available, regardless of trial or tier status, to ensure users can always get information and upgrade.

## Dashboard Trial Enforcement (2026-02-09)
- **Flask Access Helper**: Created `get_flask_guild_access` in `app.py` as a centralized function to check a server's tier, trial status, and exemption status (demo server, grandfathered, owner-granted).
- **API Route Gating**: All critical dashboard API routes (employees, calendar, settings, etc.) now call `get_flask_guild_access` and return a `TRIAL_EXPIRED` error if a free, non-exempt server's trial has expired.
- **Page-Level Gating**: HTML-serving dashboard pages (like the employee profile) now redirect to the upgrade page if the trial is expired.
- **Trial Info in APIs**: The main server settings API endpoint now includes a `trial_info` object in its response, allowing the frontend to dynamically display trial status (e.g., "X days remaining") and upgrade prompts.
- **Upgrade Page**: The `/dashboard/purchase` page has been updated to show the correct Premium ($8/mo) and Pro ($15/mo, coming soon) tiers and dynamically displays messages about trial status.

## Stripe Subscription Migration (2026-02-19)
- **Old Model Retired**: Old 3-tier model (bot_access $5 one-time, retention_7day $5/mo, retention_30day $10/mo) replaced with 2-tier subscription model (Premium $8/mo, Pro $15/mo).
- **Price IDs**: Use `STRIPE_PRICE_PREMIUM` and `STRIPE_PRICE_PRO` env vars. Legacy IDs kept in `STRIPE_PRICE_IDS_LEGACY` for backward-compatible webhook handling.
- **All Subscriptions**: Both Premium and Pro use `mode='subscription'` in Stripe checkout. No more one-time payments.
- **Coupon**: `STRIPE_COUPON_FIRST_MONTH` env var (defaults to 'vzRYNZed'). User needs to create a 100% off coupon in Stripe and update this.
- **Subscription Metadata**: `subscription_data.metadata` must include `guild_id` so lifecycle events can find the server even if checkout.completed hasn't fired yet.
- **Purchase Flow**: `/purchase/premium` -> OAuth -> `/purchase/select_server` -> select server -> `/purchase/checkout?guild_id=xxx` -> Stripe checkout.
- **Webhook Events**: `checkout.session.completed`, `customer.subscription.created/updated/deleted`, `invoice.payment_succeeded/failed` all handled.
- **Route Conflict**: `/purchase/<product_type>` (string) and `/purchase/<int:guild_id>` (int) coexist because Flask tries `int` first. Guild-ID purchases redirect to `/dashboard/purchase`.

## Cross-Domain Session Cookie Loss (2026-02-19)
- **Root Cause**: Purchase flow used Flask session cookie to store `purchase_intent` before OAuth redirect. But the purchase link goes to `time-warden.com` (custom domain) while the OAuth callback returns to `on-the-clock.replit.app` (Replit domain). Session cookies are domain-scoped, so the intent was always lost.
- **Fix**: Encode `purchase_intent` into the OAuth `state` parameter metadata (stored in the `oauth_states` DB table). The state token travels as a URL parameter through Discord and back, surviving the cross-domain redirect.
- **Pattern**: Never rely on session cookies to carry data across OAuth redirects when custom domains are involved. Use the OAuth state parameter or database-backed tokens instead.
- **Testing**: Discord OAuth doesn't work in Replit's preview iframe — always test via published deployment logs (`fetch_deployment_logs`).

## Stripe Webhook Reliability (2026-02-23)
- **Root Cause**: `checkout.session.completed` and `customer.subscription.created` both fire for the same purchase. The second webhook redundantly re-processes an already-active subscription, causing unnecessary DB writes and potential worker timeouts.
- **Fix**: Added deduplication in `handle_subscription_change()` — if the subscription is already active with `bot_access_paid=True`, only update period fields and return early.
- **Pattern**: Always deduplicate Stripe webhook handlers. Multiple event types fire for a single action.
- **Alerting**: Added `notify_owner_webhook_failure()` using `queue_email()` to alert the owner on webhook errors and payment failures. Never block on email sends in webhook handlers.

## Column Type Consistency for guild_id (2026-02-23)
- **Root Cause**: `admin_roles` and `employee_roles` tables store `guild_id` as `text`, but the guild removal handler passed `guild_id_int` (bigint), causing `operator does not exist: text = bigint`.
- **Fix**: Use `guild_id_str` for tables that store guild_id as text (`admin_roles`, `employee_roles`, `bot_guilds`), and `guild_id_int` for tables that use bigint (`employee_profiles`, `timeclock_sessions`, `guild_settings`, `server_subscriptions`).
- **Pattern**: Always verify column types before writing DELETE/UPDATE queries. Check the INSERT functions to see what type the table expects.

## Discord Bot Double Messages (2026-02-19)
- **Root Cause**: A global `on_interaction` fallback handler was racing with registered persistent views (`TimeclockHubView`). Both tried to handle the same `tc:` button interactions.
- **Fix**: Removed the `on_interaction` fallback entirely. Persistent views registered in `setup_hook` already handle all button callbacks reliably after restarts.
- **Secondary Bug**: In `TimeClockView.clock_in`, the profile setup code could send a welcome message, then if the DB update failed, the exception handler would fall through and send a second "Clocked in" message. Fixed by tracking `profile_message_sent` flag.
- **Pattern**: Never use `on_interaction` fallback handlers alongside registered persistent views — they will race and cause double responses.

## Jinja2 Template Syntax Causing Auth Loop (2026-02-24)
- **Root Cause**: `dashboard_base.html` line 434 had `{{ 'true' if ... else 'false' }` — missing the closing `}}`. This caused a Jinja2 `TemplateSyntaxError` on every server page render.
- **Why It Looped**: The `require_auth` decorator wraps the entire route handler in a try/except, so template render errors are caught as "Authentication error", the session is cleared, and the user is redirected to `/auth/login` — creating an infinite OAuth loop.
- **Fix**: Added the missing `}}` closing delimiter.
- **Pattern**: The `require_auth` decorator masks non-auth errors as auth failures. Any exception inside a `@require_auth` route (template errors, DB errors, etc.) will appear as an auth loop. Always check deployment logs for the full traceback.

## Undefined `now_utc()` in Owner Dashboard (2026-02-24)
- **Root Cause**: Owner dashboard used `now_utc()` which doesn't exist — should be `datetime.now(timezone.utc)`.
- **Pattern**: Always use `datetime.now(timezone.utc)` for UTC timestamps in Flask routes. The `now_utc()` helper doesn't exist in this codebase.

## Multi-line Strings in Inline JS Failing Due To Auto-Formatters (2026-02-24)
- **Root Cause**: `owner_dashboard.html` contained JavaScript string literals (single quotes `'...'` and template literals `` `...` ``) that were forcefully split across multiple lines by IDE auto-formatters during a Git merge. This causes `SyntaxError: Unterminated string literal` which crashes the entire `<script>` block and disables all downstream UI functions.
- **Fix**: Collapsed multi-line strings to single lines. For template literals that use `${}`, ensure the variable interpolations do not contain raw unescaped line breaks.
- **Pattern**: When building HTML or `confirm()` dialogs in inline JavaScript (`<script>` inside `.html`), **DISABLE auto-formatting** for that block, or aggressively verify that the formatter did not break string literals. Never use single quotes across line breaks, and be highly suspicious of backtick strings after a Git merge.

## ON CONFLICT Requires UNIQUE Constraint (2026-02-24)
- **Root Cause**: `archive_employee()` in bot.py uses `ON CONFLICT (guild_id, user_id) DO UPDATE` but `employee_archive` only had a regular (non-unique) index on `(guild_id, user_id)`. PostgreSQL requires a UNIQUE index or constraint for ON CONFLICT to work.
- **Fix**: Added `CREATE UNIQUE INDEX IF NOT EXISTS idx_employee_archive_guild_user_unique ON employee_archive(guild_id, user_id)` to migrations.py.
- **Pattern**: Whenever using `ON CONFLICT (columns)` in an INSERT, always verify there's a UNIQUE constraint or UNIQUE index on those exact columns. A regular index is not sufficient.

## Missing `get_guild_settings` in bot.py (2026-02-24)
- **Root Cause**: `bot.py` called `get_guild_settings()` (defined in app.py) in 4 places: report export, PDF generation, clock-in log, clock-out log. Function didn't exist in bot.py → `NameError` on any code path that hit it.
- **Fix**: Added `get_guild_settings()` function to bot.py that queries `guild_settings` table directly using the bot's `db()` context manager.
- **Pattern**: Never assume Flask-side utility functions are available in bot.py — they're separate modules. When bot.py needs guild settings, use its own `db()` + direct SQL query.

## Preview Query Using Tuple Indexing on Dict Cursor (2026-02-24)
- **Root Cause**: Preview endpoint used `conn.cursor()` then accessed rows via `row[0]`, `row[1]` — but `FlaskConnectionWrapper.cursor()` returns a `RealDictCursor`, so integer indexing doesn't work as expected.
- **Fix**: Changed to `conn.execute()` with dict-key access (`row['user_id']`, `row['display_name']`, etc.).
- **Pattern**: Always use `conn.execute()` + dict-style access in Flask routes. Never use raw `conn.cursor()` with positional indexing.

## Missing `access` Variable in Reports Template (2026-02-24)
- **Root Cause**: `dashboard_reports.html` references `access.tier`, `access.trial_active`, etc. but `get_server_page_context()` never included an `access` object. Jinja2 throws `'access' is undefined`, caught by `require_auth` as an auth failure → auth loop.
- **Fix**: Added `access = get_flask_guild_access(guild_id)` and `'access': access` into `get_server_page_context()` so ALL server sub-pages automatically receive the tier/trial info.
- **Pattern**: When adding new template variables, add them to `get_server_page_context()` — not individual route handlers — so every server page gets them. Always verify new templates have all required context variables before deploying.

## Missing ALTER TABLE Statements in Migrations Causing INSERT Crashes (2026-02-24)
- **Root Cause**: New columns (e.g. `role_tier`, `profile_setup_completed`) were added to the `CREATE TABLE employee_profiles` definition in `migrations.py`, but were never provisioned via `ALTER TABLE` for existing production databases. When the bot tried to `INSERT` into the table during clock-in, it crashed because the expected columns didn't exist in the remote database.
- **Fix**: Wrote a dynamic loop in `migrations.py` that executes `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` for every new schema column, allowing the script to safely patch existing live databases.
- **Pattern**: Whenever modifying a database schema, updating the `CREATE TABLE` statement is **not enough**. You MUST also provide `ALTER TABLE ADD COLUMN IF NOT EXISTS` statements so that existing legacy databases are successfully patched during the boot migration sequence. Failure to do this will immediately break production on Replit when existing rows are modified or new rows are inserted.

## Duplicate Flask Routes Cause Silent Production Crash Loop (2026-02-27)
- **Root Cause**: Antigravity agent added new `/` and `/wiki` route handlers without removing the originals. Flask throws `AssertionError` at startup for any duplicate route path, which prevents gunicorn from loading the app entirely. This appears as `WORKER TIMEOUT` → crash loop → `crash loop detected` in deployment logs, with the actual Python exception hidden in truncated log output.
- **Fix**: Removed the duplicate route definitions. Merged new behavior (V2 UI feature flag check) into the original `index()` function.
- **Pattern**: Before deploying ANY multi-agent changes that touch `app.py`, always run: `grep "@app.route" app.py | awk -F'"' '{print $2}' | sort | uniq -d` to check for duplicates. The production crash gives no obvious indication of the cause — only raw gunicorn tracebacks ending at `self.callable = self.load()` with the actual Python error truncated by the log system.

## Bot-Bridge DB Calls Cause Worker Timeout (2026-02-27)
- **Root Cause**: Flask API routes that called bot.py functions (via `_get_bot_func()`) which used the bot's own `db()` connection pool caused Gunicorn worker timeouts. Flask's single sync worker blocks when calling into the bot's DB pool from a sync thread, eventually timing out after 120s.
- **Fix**: Rewrote those routes to use Flask's own `get_db()` connection pool with direct SQL queries, bypassing the bot bridge entirely.
- **Pattern**: Flask routes must NEVER call bot.py functions that use `db()`. Flask routes must always use Flask's own `get_db()` directly. The `_get_bot_func()` bridge is only safe for non-DB bot operations (Discord API calls, tier checks that don't open connections).

## Template Errors Masquerade as Auth Loops (2026-02-27)
- **Root Cause**: `require_auth` wraps protected routes and catches ALL exceptions — including Jinja2 template syntax errors. When a template fails to render, the exception is silently swallowed and the user is redirected to Discord login, producing a convincing but misleading "auth loop."
- **Fix**: Check deployment logs for `Authentication error:` entries BEFORE assuming OAuth is broken. The actual exception type and traceback follow immediately in the log. In this case: `Authentication error: unexpected '}'` pointed directly to a missing `}}` in `dashboard_base.html`.
- **Pattern**: After editing any template, validate it with `python3 -c "from jinja2 import Environment; env = Environment(); env.parse(open('templates/YOUR_TEMPLATE.html').read())"`. An exit with no output means the template is valid. Always run this before deploying template changes.
- **Secondary Issue Found**: The same Antigravity commit had a broken `DOMContentLoaded` structure — the `hasCompletedOnboarding` const was declared inside the callback but the `if` block that used it was placed outside, putting a `const` variable out of scope. When adding code inside a `document.addEventListener('DOMContentLoaded', ...)` block, verify the closing `});` is at the very end of the logical block.

## Committed-but-Undeployed Fixes Still Cause Production Outages (2026-02-27)
- **Root Cause**: Antigravity correctly fixed the `resolved` column migration but never published the deployment. The git commit existed but the production environment never received it. A subsequent publish by another session pushed BOTH the column fix AND a new template bug together.
- **Pattern**: After any agent commits a critical fix, explicitly verify a new deployment has been triggered. Compare the timestamp of the last git commit against the timestamp of the last "Published your App" checkpoint. If commit is newer than publish, the fix is not live.

## BOT_API_SECRET Must Be a Fixed Env Var — Never Rely on Runtime Generation (2026-03-21)
- **Root Cause**: `bot_core.py` generates a random `BOT_API_SECRET` at startup via `secrets.token_hex(32)` when the env var is not set. Flask (in `api_owner.py`) tries `os.getenv("BOT_API_SECRET", "")` (gets `""`) then falls back to `_get_bot_module().BOT_API_SECRET`. That fallback calls `import bot` — but the bot module is `bot_core.py`, not `bot.py`, so the import silently fails and the secret stays empty. Flask sends `Authorization: Bearer ` (empty) → bot API returns 401 → Flask propagates "Unauthorized" to the user.
- **Fix**: Set `BOT_API_SECRET` as a fixed shared environment variable. Both `bot_core.py` and `api_owner.py` already read from `os.getenv("BOT_API_SECRET")` — they just need a stable value to agree on.
- **Hardening Added**:
  1. Startup check in `app.py` now logs `✅ BOT_API_SECRET configured` or `⚠️ WARNING: BOT_API_SECRET is not set` — misconfiguration is immediately visible in startup logs instead of silently failing at runtime.
  2. The broadcast endpoint in `api_owner.py` now uses the same fast-fail pattern as every other bot API call: `bot_api_secret = os.getenv('BOT_API_SECRET')` → return 503 if missing. No more silent fallback.
- **Pattern**: All bot-internal API calls must use `get_bot_api_headers()` from `web/utils/auth.py`. This helper generates `Authorization`, `X-Timestamp`, and `X-Signature` headers required by `bot_core.py`'s HMAC replay defense. Never build headers manually or use bare `Authorization: Bearer`:
  ```python
  from web.utils.auth import get_bot_api_headers
  
  bot_api_secret = os.getenv('BOT_API_SECRET')
  if not bot_api_secret:
      return jsonify({'success': False, 'error': 'Bot API not configured.'}), 503
  response = requests.get(url, headers=get_bot_api_headers(bot_api_secret), timeout=5)
  ```
- **Audit (2026-03-22)**: Fixed 12 Flask→Bot API call sites that were missing X-Timestamp/X-Signature replay defense headers: 5 in `api_server.py`, 6 in `api_owner.py`, 1 in `api_kiosk.py`, plus `check_user_admin_realtime` in `web/utils/auth.py` (which gates every dashboard page). Also removed the broken `_get_bot_module()` fallback pattern from all 5 `api_server.py` endpoints.

## Antigravity Refactor Dropped the Bot API Server Startup (2026-03-21)
- **Root Cause**: Antigravity's commit `706cf69` (modularize monolith into Cogs) moved all handler functions from `bot.py` → `bot_core.py` but dropped the `start_bot_api_server()` function and the `asyncio.create_task(start_bot_api_server())` call in `run_bot_with_api()`. The handlers existed but were never registered with an aiohttp Application, so nothing listened on port 8081.
- **Symptom**: Flask → `http://127.0.0.1:8081/api/broadcast` → `ConnectionError` → "Bot is not ready" (503). Also affects employee sync, channel listing, report export, onboarding, and all other bot API calls.
- **Fix**: Restored `start_bot_api_server()` in `bot_core.py` and the `asyncio.create_task()` call in `discord_runner.py:run_bot_with_api()` — exact code from the last working commit (`f2070a9`).
- **Pattern**: When refactoring, always verify that server startup/wiring code is preserved, not just handler definitions. Grep for `web.Application`, `AppRunner`, `TCPSite` to confirm the aiohttp server is still being started.
- **Verification**: Startup logs must show `🔌 Bot API server running on http://0.0.0.0:8081`. If this line is missing, the bot API is broken.

## Antigravity Refactor Stranded send_broadcast_to_guilds in tmp_help.txt (2026-03-22)
- **Root Cause**: The `send_broadcast_to_guilds` function — which `handle_broadcast` calls to actually send Discord messages — was dropped from bot_core.py during the Cog refactor and left in `tmp_help.txt`. Additionally, `bot/cogs/owner_cmds.py` called the function but never imported it from `bot_core`.
- **Symptom**: Broadcast API returns 500 with `NameError: name 'send_broadcast_to_guilds' is not defined`.
- **Fix**: Restored the function into `bot_core.py` (before `handle_broadcast`), added `send_broadcast_to_guilds` to the imports in `bot/cogs/owner_cmds.py`, and added `'success': True` to the return dict to match the contract expected by `handle_broadcast` and `api_owner.py`.
- **Pattern**: When moving functions between files, always grep for ALL call sites and verify each one has the correct import. Use: `grep -rn "function_name" --include="*.py"` to find every reference.

## Atomic Layering vs Monolithic Feature Phases (Architectural Standard)
- **The Problem**: Building an entire vertical feature (Database + Backend + Webhooks + Discord Commands + Javascript UI) in a single massive "Phase" introduces extreme regression risk. If one layer fails, it masks bugs in the others.
- **The Solution (Atomic Slicing)**: Break large feature sets down into horizontal, atomic layers. Build Layer 1 (Security Hooks), test it. Build Layer 2 (Database Migrations), test it. Build Layer 3 (Backend API), test it. Build Layer 4 (Javascript UI), test it.
- **Pattern**: Do not try to execute visual DOM work in the same phase as core SQL schema migrations. Slice the work horizontally to minimize blast radius during coding.

## The 4-Tier Security Hierarchy (Architectural Standard)
- **The Problem**: Previously, code used Discord's `Administrator` permission bitmask to authorize Stripe purchases and server destruction. This allowed rogue managers to hijack or delete the server.
- **The Solution**: Enforce a strict mathematically isolated 4-Tier Hierarchy:
  1. **Bot Owner**: The Developer. (`interaction.user.id == BOT_OWNER_ID`). Unrestricted access to `/owner` global dashboard.
  2. **Server Owner**: The Customer. (`guild.owner == True` via OAuth). **Only** tier allowed to manage Stripe subscriptions or execute destructive DB purges (`/setup_demo_roles`, Reset Data).
  3. **Server Admin**: The Managers. Has the `Administrator` Discord role. Allowed to edit shifts, approve time adjustments, and pull reports. Cannot access billing or destroy the server.
  4. **Employee**: Standard Users. Can only access their own profiles and clock records.

## AI Pre-Flight Architecture Audit
- **The Problem**: Future AIs might start building Javascript UI components or Python `/cogs` without realizing the database is fundamentally broken, or that IDOR exploits exist on the API they are hooking into.
- **The Solution**: Before building ANY new feature, the AI Agent must physically read `docs/architecture_manifesto.md` and `docs/schema_reference.md` to understand the strict Blueprints/Cogs separation of concerns and the database layout.

## Flask to Bot DB Bridge Anti-Pattern (2026-02-26)
- **The Problem**: Flask routes calling `bot.py` functions that use `db()` (the bot's connection pool) cause deadlocks resulting in `[CRITICAL] WORKER TIMEOUT` in Gunicorn.
- **The Solution**: Flask routes must NEVER call `bot.py` functions that use `db()`. Flask routes must use Flask's own DB connection directly via `with get_db() as conn:`.
- **Pattern**: The `_get_bot_func()` bridge is ONLY safe for non-DB bot operations, such as Discord API calls, or simple tier checks that don't open a database connection.

## Python Namespace Collisions (2026-02-28)
- **The Problem**: Naming a script `bot.py` while having a directory named `bot/` causes Python 3 to fail when importing packages from the directory (e.g., `import bot.cogs`). It imports the script instead, resulting in `No module named 'bot.cogs'; 'bot' is not a package`.
- **The Solution**: Never name a root runner script the same as a Python package directory. Renamed `bot.py` to `discord_runner.py` to resolve the collision.

## Discord Context Menus inside Cogs (2026-02-28)
- **The Problem**: App Commands Context Menus (`@app_commands.context_menu()`) throw a `TypeError: context menus cannot be defined inside a class` if they are defined inside a `commands.Cog` class.
- **The Solution**: Define Context Menus as global async functions outside of the Cog class, and manually register them into the bot tree during the `setup(bot)` function using `bot.tree.add_command(context_menu_function)`.

## Legacy Subscription Decorators Blocking Free Trials (2026-04-06)
- **Root Cause**: When migrating to the 30-Day Free Trial system, `get_flask_guild_access()` was injected inside 34+ API routes to grant trial servers access. However, the legacy `@require_paid_api_access` decorator was left on those routes. The decorator explicitly enforced `bot_access_paid == True`, immediately throwing a 403 Forbidden payload *before* the route's trial logic could even execute.
- **Fix**: Refactored `require_paid_api_access` and `require_paid_access` in `web/utils/auth.py` to inherently evaluate `get_flask_guild_access()` natively. This unblocks all free trials without having to rewrite 34 individual fetch routes.
- **Pattern**: When deprecating a security constraint, update the global decorator directly rather than bypassing it sequentially inside the downstream routes.

## Python Console Log Unicode Emulators Crashing Gunicorn (2026-04-06)
- **Root Cause**: Gunicorn crashed in the Windows deployment environment when it attempted to stdout emojis like `🔄` and `❌` from `migrations.py` and `bot_core.py`. The Windows console defaults to `cp1252` encoding which throws a fatal `UnicodeEncodeError`.
- **Fix**: Replaced graphical emojis inside initialization prints with standard bracket strings like `[SYNC]`, `[FAIL]`, and `[OK]`.
- **Pattern**: Python `print()` statements executed during application startup must be scrubbed of non-ASCII characters to maintain portability across rigid Windows terminal mappings.
