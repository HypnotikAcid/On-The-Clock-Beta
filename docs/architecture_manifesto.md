# Architectural Manifesto: TimeWarden (Flask + Discord.py)

This document outlines the **unbreakable architectural rules** for all future development on the TimeWarden platform. 
**ALL AI AGENTS AND HUMAN DEVELOPERS MUST READ AND ADHERE TO THESE PATTERNS BEFORE WRITING CODE.**

The goal of this architecture is to prevent the project from collapsing into a monolith, eliminate circular imports, and prevent asynchronous deadlocks between the Flask Web Server and the Discord Bot.

---

## 1. The Core Split: Web (Sync) vs. Bot (Async)
TimeWarden is a hybrid application running a synchronous Flask web server (via Gunicorn) and an asynchronous Discord.py bot within the same ecosystem.

**The Golden Rule**: Never cross the streams carelessly.
- **Web DB Pool**: Flask routes must *only* use `with get_db() as conn:`.
- **Bot DB Pool**: Discord commands/cogs must *only* use their own DB context manager (e.g., `with bot.db() as conn:` or direct queries in async wrappers).
- **The Bridge**: If Flask needs to ask Discord for live data (e.g., "What are the roles in this server?"), it MUST use the thread-safe `_get_bot_module` / `_get_bot_func` execution bridge. 
- **The Anti-Pattern**: NEVER call a bot function from Flask if that bot function opens a database connection. This will deadlock the Gunicorn worker and cause a silent `[CRITICAL] WORKER TIMEOUT`.

---

## 2. Web Layer Architecture (Flask Blueprints)
`app.py` is strictly an initialization script and router. **No business logic or raw SQL queries should live in `app.py`.**

### A. Routing (Blueprints)
- All new HTTP routes must be placed in a corresponding Blueprint inside `web/routes/`.
- Routes should be "dumb": They only parse `request.args` / `request.json`, call a utility function, and return `jsonify()` or `render_template()`.
- Example Blueprints: `api_guild.py` (Payroll), `api_kiosk.py` (Clock-ins), `dashboard.py` (UI views).

### B. Utility Services
- All complex business logic, third-party integrations, and raw SQL databases queries must be extracted into `web/utils/`.
- **`web/utils/db.py`**: Connection pooling, basic CRUD helpers.
- **`web/utils/billing.py`**: Stripe integrations, webhooks, Entitlement tier calculations.
- **`web/utils/email_utils.py`**: Async queued email dispatch (SendGrid).
- **`web/utils/auth.py`**: Discord OAuth exchange, session token generation, middleware decorators (`@require_auth`).

---

## 3. Bot Layer Architecture (Discord.py Cogs)
`bot.py` is strictly the bot instantiation and event loop entrypoint. **No command logic or raw SQL queries should live in `bot.py`.**

### A. Domain-Driven Cogs
- Every feature must be its own Cog class in `bot/cogs/`.
- **`timeclock.py`**: Handles `/clock`, `/status`, and Kiosk interactions.
- **`admin.py`**: Handles `/settings`, `/setup`, and manual adjustments.
- **`reports.py`**: Handles report generation, CSV/PDF exports.
- **`onboarding.py`**: Handles `on_guild_join`, welcome DMs.

### B. Cross-Cog Communication
- Cogs should never `import` each other directly to prevent circular dependency crashes.
- If the Admin Cog needs to use a function from the Timeclock Cog, it must use the bot's internal registry: `cog = self.bot.get_cog("TimeclockCog")`.

### C. Persistent Views
- Interactive UI components (Buttons, Dropdowns) must use Discord.py `Persistent Views`.
- These views must be registered in the `bot.setup_hook()` so they survive bot restarts.
- NEVER use global `on_interaction` listeners to hack button clicks. It causes double-firing bugs.

---

## 4. Prompting Guide for Future AI Agents
When starting a new session or issuing a prompt to an AI agent, you must enforce this standard.

### Example Prompt Prefix:
> "We are building a new feature for TimeWarden. Before you write any code, read `docs/architecture_manifesto.md` and `docs/schema_reference.md`. 
> 1. Do not add routes to `app.py`. Create or update a Blueprint in `web/routes/`.
> 2. Do not write raw SQL in the route; put the logic in `web/utils/`.
> 3. Do not add commands to `bot.py`. Create or update a Cog in `bot/cogs/`.
> Execute your plan only after analyzing the schema."
