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

## Discord Bot Double Messages (2026-02-19)
- **Root Cause**: A global `on_interaction` fallback handler was racing with registered persistent views (`TimeclockHubView`). Both tried to handle the same `tc:` button interactions.
- **Fix**: Removed the `on_interaction` fallback entirely. Persistent views registered in `setup_hook` already handle all button callbacks reliably after restarts.
- **Secondary Bug**: In `TimeClockView.clock_in`, the profile setup code could send a welcome message, then if the DB update failed, the exception handler would fall through and send a second "Clocked in" message. Fixed by tracking `profile_message_sent` flag.
- **Pattern**: Never use `on_interaction` fallback handlers alongside registered persistent views — they will race and cause double responses.
