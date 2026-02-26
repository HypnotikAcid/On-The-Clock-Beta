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
- **The Solution**: Before building ANY new feature, the AI Agent must physically read `docs/ai_pre_flight_audit.md` and complete the 5 Pillar integrity sweeps against the existing backend.

## Flask to Bot DB Bridge Anti-Pattern (2026-02-26)
- **The Problem**: Flask routes calling `bot.py` functions that use `db()` (the bot's connection pool) cause deadlocks resulting in `[CRITICAL] WORKER TIMEOUT` in Gunicorn.
- **The Solution**: Flask routes must NEVER call `bot.py` functions that use `db()`. Flask routes must use Flask's own DB connection directly via `with get_db() as conn:`.
- **Pattern**: The `_get_bot_func()` bridge is ONLY safe for non-DB bot operations, such as Discord API calls, or simple tier checks that don't open a database connection.
