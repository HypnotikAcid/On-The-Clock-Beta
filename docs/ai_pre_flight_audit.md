# The AI Pre-Flight Architecture Audit

**Purpose**: This document catalogs the exact Deep-Dive Sweeps that must be run by *any* AI Agent before beginning major feature development. This ensures that new features are built on a structurally sound, secure, and fully connected ecosystem without introducing regression bugs or overlooking architectural gaps.

Whenever starting a large horizontal layer or phase, the AI should use `grep_search` and `view_file` to manually verify the codebase against the following 5 Pillars of Integrity.

---

## Pillar 1: Privilege Escalation & IDOR Testing
*Never trust the frontend. Assume malicious employees manipulate JSON payloads before they hit the API.*

-   **Mass Assignment Audit**: 
    -   *Sweep*: Check every `POST`, `PUT`, or `PATCH` endpoint that updates user or profile data (e.g., `/api/.../profile`). 
    -   *Verification*: Does it aggressively filter the incoming JSON payload against a hardcoded `allowed_fields` list? If `data.get('role')` or `data.get('is_admin')` is accepted blindly, the API is vulnerable to horizontal privilege escalation.
-   **BOLA (Broken Object Level Authorization) / IDOR**: 
    -   *Sweep*: Check all `DELETE` or `UPDATE` routes that rely on a URL ID (e.g., `/api/entries/<entry_id>`). 
    -   *Verification*: Does the SQL query explicitly require `AND user_id = %s` or `AND guild_id = %s` tied to the authenticated session? If it only queries `WHERE session_id = %s`, User A can blindly delete User B's data by guessing the ID.

## Pillar 2: Database Race Conditions & Concurrency
*Assume an employee on a laggy tablet will triple-click a submission button in half a second.*

-   **Advisory Locks**: 
    -   *Sweep*: Search for the Postgres function `pg_try_advisory_xact_lock` paired with SQL `FOR UPDATE`.
    -   *Verification*: Are critical insertions (like Clock Interactions, Stripe Checkout creation, or User Deletion) wrapped in this lock? If the web backend lacks this, double-tapping a "Clock In" button will simultaneously write duplicate, infinite shifts to the DB.
-   **Deadlock Prevention**:
    -   *Sweep*: Verify that SQL connections are instantiated via a `ThreadedConnectionPool` using Python `contextlib` (e.g., the `with db() as cursor:` block). Never leave raw cursors open globally.

## Pillar 3: Invisible Data Orphans (The "Reaper" Gap)
*Warnings are not execution. Just because the UI or bot says something will happen, does not mean the backend actually performs the physical SQL execution.*

-   **Data Retention vs Reality**:
    -   *Sweep*: Trace the logical path of "Data Deletion Warning" emails or popups.
    -   *Verification*: Does the codebase actually contain a corresponding Chron job or function that executes `DELETE FROM [table] WHERE date < [expiration]`? If a warning fires but the `DELETE` query doesn't exist, the server will infinitely bloat with orphaned data.
-   **Termination Archival vs Deletion**:
    -   *Sweep*: When an Admin clicks "Remove Employee", trace the endpoint's execution.
    -   *Verification*: Does it physically `DELETE FROM employee_profiles`? (This destroys historical payroll math and breaks foreign keys on past shifts). It *must* run an `UPDATE ... SET is_active = FALSE` or trigger a safe archival function instead.

## Pillar 4: Webhook & Third-Party Connection Timeouts
*If Discord or Stripe goes down, your Web Dashboard should not freeze.*

-   **API Timeout Bounds**:
    -   *Sweep*: Search the codebase for `requests.post`, `requests.get`, or any `aiohttp` outbound API calls.
    -   *Verification*: Every single external call MUST explicitly contain a timeout argument (e.g., `timeout=5`). If missing, a slow response from the Discord API will hang the Flask thread forever, crashing the entire dashboard for all users.
-   **Synchronous I/O Blocks**:
    -   *Sweep*: Search for `send_email()`, file uploads, or `loop.run_until_complete()`.
    -   *Verification*: Are emails sent asynchronously (e.g., `queue_email()`)? If the web server waits for SendGrid's API to physically return a `200 OK` before rendering the HTML page, the UX will feel incredibly sluggish.
-   **Webhook Replay Attacks**:
    -   *Sweep*: Check internal REST API endpoints between `app.py` and `bot.py` (e.g., `verify_api_request`).
    -   *Verification*: Do they just check `BOT_API_SECRET`? If so, an attacker capturing local traffic can infinitely replay the exact same `POST` request. All internal webhooks must enforce Timestamp Validation (rejecting payloads older than 5 seconds).

## Pillar 5: System Key Volatility
*App restarts should be seamless to the end user.*

-   **Session Key Permanence**:
    -   *Sweep*: Find how the Flask `app.secret_key` is generated.
    -   *Verification*: Does it randomly generate `os.urandom()` if the environment variable is missing? This is a critical workflow gap. Every time the host server sleeps, updates, or restarts, a random key will instantly invalidate every active browser cookie, forcing all users to log out. It must be a hardcoded `.env` string.

## Pillar 6: Brute Force & Rate Limiting
*Computers can guess numbers faster than humans can.*

-   **Authentication Endpoints & PINs**:
    -   *Sweep*: Search for `/verify`, `/login`, or `/auth` endpoints that handle user-entered codes (like a Kiosk PIN or 2FA).
    -   *Verification*: Is there a global dictionary or Redis counter (e.g., `failed_attempts[user_id]`) that permanently locks out the user or artificially `sleep()`s the thread after 5 failed attempts? If it just returns `401 Unauthorized` instantly, an attacker can rapid-fire 10,000 requests in 15 seconds to brute-force a 4-digit PIN.
-   **Frontend-Only Authentication Bypasses**:
    -   *Sweep*: Find where the PIN or Password validation returns `success: True` to the Javascript UI. Look at the API endpoints the UI calls *afterward* (e.g., `/clock_in`).
    -   *Verification*: Do the subsequent APIs actually verify a transient session/JWT token proving the PIN was just entered? If the API just trusts that the Frontend UI clicked "Login", an attacker can open Developer Tools on the iPad and `fetch('/clock_in')` directly, bypassing the PIN screen entirely.

## Pillar 7: Spam & Denial of Wallet
*Unbounded loops and third-party APIs cost money.*

-   **Email & Intensive Actions**:
    -   *Sweep*: Check endpoints like `/api/.../send-shift-email` or `/api/.../adjustments` which trigger external APIs (SendGrid) or write multiple Database rows per request.
    -   *Verification*: Do they enforce a Rate Limit (e.g., 1 request per minute per user)? If not, an attacker can write a `while(true)` loop to spam an employee's inbox 10,000 times a minute, instantly exhausting your SMTP quota and potentially racking up massive API billing charges (Denial of Wallet).

## Pillar 8: CSV & Excel Macro Injection (CSV-I)
*Data exports are not inert text files; they are executable programs if opened in Excel.*

-   **Report Generators**:
    -   *Sweep*: Search for `csv.writer` or `/export` features. Look at how user-controlled text (e.g., `display_name` or `reason`) is written.
    -   *Verification*: If a malicious employee sets their name to `=cmd|' /C calc'!A0`, does the server write it physically into the CSV? If so, when the Admin opens the payroll report, Excel will execute a hidden virus. All exported strings must be sanitized by prepending a single quote (`'`) to any string starting with `=`, `+`, `-`, or `@`.

## Pillar 9: Information Disclosure & Verbose Exceptions
*Never tell the user *how* you failed.*

-   **API Error Handling**:
    -   *Sweep*: Search for `except Exception as e:` blocks in the backend router that execute `return jsonify({'error': str(e)})`, 500.
    -   *Verification*: If the database throws a `psycopg2.IntegrityError`, does `str(e)` send the raw SQL table name, column names, and failing constraint names directly to the user's browser? Yes. This maps the entire backend schema for attackers. All API exceptions must be caught, logged internally via `app.logger.error(str(e))`, and returned to the user as a generic string like `"An internal server error occurred."`

## Pillar 10: Resource Exhaustion & APIs (OOM)
*The most resilient servers can still be choked to death.*

-   **Data Exports & Pagination**:
    -   *Sweep*: Check endpoints like `/api/server/.../time-report` or `.fetchall()` queries that retrieve rows based on user-supplied dates.
    -   *Verification*: Is there a maximum allowed duration between `start_date` and `end_date`? If an Admin selects a 10-year span, `.fetchall()` will load 500,000+ session rows blindly into RAM before generating the CSV, causing an Out of Memory (OOM) server crash. All Date Range queries MUST forcefully reject ranges exceeding 60-90 days, returning a 400 Bad Request prompting the user to select a narrower window.

## Pillar 11: Business Logic & Negative Time
*Application logic must mirror the physical laws of the universe.*

-   **Chronological Integrity**:
    -   *Sweep*: Search for endpoints accepting `start_time`, `end_time`, `clock_in`, or `clock_out` parameters.
    -   *Verification*: Is there a mathematical check ensuring `end_time > start_time`? If not, an attacker can submit inverted timestamps. This will physically write "Negative Time" into the database, causing payroll calculation scripts to subtract money from an employee's total check. All time-based API endpoints must formally reject requests where `duration <= 0`.

## Pillar 12: Clickjacking & Frame Control
*UI Transparency is a weapon.*

-   **Iframe Embedding**:
    -   *Sweep*: Check the main web server configuration (e.g., `app.py`) for global response headers dictating `X-Frame-Options` and `Content-Security-Policy`.
    -   *Verification*: If missing, an attacker can create a fake website and invisibly embed your Admin Dashboard underneath a transparent `<iframe>`. When the user tries to click a button on the fake site, they actually click "Delete Guild Data" on your hidden dashboard. You MUST enforce `X-Frame-Options: SAMEORIGIN` via a global `@app.after_request` middleware to block foreign framing.

## Pillar 13: Transaction Race Conditions (TOCTOU)
*Microseconds matter when databases scale.*

-   **Approval Logic**:
    -   *Sweep*: Search for logic that `SELECT`s a row (like a time adjustment request) to check its status, and then later executes an `INSERT` or `UPDATE` based on that status.
    -   *Verification*: Does the initial `SELECT` query end with `FOR UPDATE`? If not, two Admins clicking "Approve" at the exact same millisecond will both read `status = 'pending'` concurrently. They will both proceed to execute the underlying `INSERT`, creating duplicate shifts in the database. All state-dependent read-write flows within a transaction must physically lock the row using `FOR UPDATE`.

## Pillar 14: Broken Function Level Authorization (BFLA)
*Never assume the UI hides administrative buttons.*

-   **Endpoint Authorization**:
    -   *Sweep*: Find every backend API endpoint that performs an administrative action (e.g., `DELETE`, creating roles, modifying settings). 
    -   *Verification*: Is there a hardcoded decorator (like `@require_server_admin`) or explicit `check_admin()` boolean logic before the database is touched? If the API only relies on the frontend UI hiding the "Delete" button from standard employees, an attacker can simply send a raw `POST` request to the URL using Postman to wipe the server.

## Pillar 15: Server-Side Request Forgery (SSRF)
*Do not let the server become an attacker's proxy.*

-   **Outbound Webhooks & URLs**:
    -   *Sweep*: Search for user-configurable webhook URLs or standard `requests.post(url)` calls where the `url` is provided by the user.
    -   *Verification*: Does the application strictly validate the hostname against a whitelist or resolve the IP to ensure it does not point to internal network services (e.g., `localhost`, `169.254.169.254` AWS metadata)? If a user can set their Discord Webhook URL to `http://localhost:8080/admin/delete_all`, the server will attack itself.

## Pillar 16: Cross-Site Scripting (XSS) & Template Injection
*Data is data. Code is code. Never mix the two.*

-   **Raw HTML Rendering**:
    -   *Sweep*: Search all `.html` Jinja templates for the `|safe` filter (e.g., `{{ user_bio | safe }}`).
    -   *Verification*: Is the backend aggressively stripping `<script>` or `onload=` tags before saving the `user_bio` to the database? If not, an employee can write Javascript in their Bio, and when an Admin views their profile, the Admin's browser will execute the Javascript, potentially stealing the Admin's session cookie.

## Pillar 17: CSRF & State-Changing GETs
*A link should never perform an action.*

-   **Actionable URLs**:
    -   *Sweep*: Search for Flask routes defining `@app.route('/.../delete')` or `/remove` that do not explicitly enforce `methods=["POST"]`.
    -   *Verification*: State-changing actions must never occur via a `GET` request. If an Admin is logged in and visits a malicious website containing `<img src="https://timewarden.app/server/123/delete">`, their browser will automatically execute the GET request using their session cookies, destroying the server data silently in the background.

---

### Execution Protocol
When a new AI Agent joins the project and is asked to build a new feature or "Audit the App":
1.  Read this `ai_pre_flight_audit.md` file.
2.  Run `grep_search` across `app.py`, `bot.py`, and `scheduler.py` explicitly hunting for these 5 exact vectors.
3.  Inject any discovered missing links into the project's `implementation_plan.md` before writing a single line of new code.
