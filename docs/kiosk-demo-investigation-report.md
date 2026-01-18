# Kiosk & Demo Server Technical Investigation Report
**Date**: 2026-01-18
**Investigator**: Claude Code (Sonnet 4.5)
**Scope**: Demo server behavior, IBC paid server, Kiosk system, Time adjustment panel, Email delivery

---

## EXECUTIVE SUMMARY

This investigation reviewed the entire kiosk system, demo server implementation, and time adjustment subsystem across ~20,000 lines of code. **Key findings:**

✅ **Working Well:**
- Demo server auto-role assignment functional
- Kiosk system fully implemented with 13 routes
- Email verification and report delivery operational
- Tier gating mostly consistent

⚠️ **Critical Issues Identified:**
1. **Time adjustment panel freezing** - Async email notification creates blocking event loop
2. **Demo server email protection missing** - No safeguards against real emails from demo
3. **Kiosk tier gating incomplete** - Routes lack `@require_paid_api_access` enforcement

🔵 **Recommendations:**
- Add timeout protection to async email notifications
- Implement demo server email sandbox
- Complete tier gating on kiosk routes
- Add diagnostic logging for adjustment submissions

---

## 1. SYSTEM MAP

### A. Demo Mode Toggles

| Component | File:Line | Function/Constant | Behavior |
|-----------|-----------|-------------------|----------|
| **Demo Server ID** | bot.py:54-55 | `DEMO_SERVER_ID = 1419894879894507661` | Integer constant |
| **Demo Server ID** | app.py:60 | `DEMO_SERVER_ID = '1419894879894507661'` | String constant (⚠️ type mismatch) |
| **Auto Admin Grant** | app.py:848-850 | `check_admin_status()` | ALL users get admin on demo |
| **Dashboard Access** | app.py:4392-4406 | `verify_guild_access()` | Returns 'admin' for demo bypassing auth |
| **View Mode Toggle** | app.py:1764-1778 | `dashboard_context_page()` | URL param `?view_as=employee/admin` |
| **Demo Detection** | Throughout | `if str(guild_id) == DEMO_SERVER_ID:` | Comparison pattern (⚠️ string vs int) |

**Security Boundaries:**
- Demo admin bypass is INTENTIONAL and documented
- No demo-specific bypass applies to IBC server (isolated by guild_id)
- Demo role ID (`1460483767050178631`) only valid in demo server

---

### B. Member Join Role Assignment

| Component | File:Line | Function | Trigger |
|-----------|-----------|----------|---------|
| **Join Handler** | bot.py:6876-6915 | `on_member_join(member)` | Discord `on_member_join` event |
| **Demo Role ID** | bot.py:55 | `DEMO_EMPLOYEE_ROLE_ID = 1460483767050178631` | "Test Employee" role |
| **Auto-Assign Logic** | bot.py:6891-6914 | Auto-assign demo role if `member.guild.id == DEMO_SERVER_ID` | ✅ Demo only |
| **Returning Employee** | bot.py:6879-6888 | Re-assign configured role if in `employee_profiles` | ✅ Non-demo servers |
| **Update Handler** | bot.py:4736-4782 | `on_member_update()` | Skip welcome DM for demo (line 4752) |

**Flow for Demo Server:**
1. User joins Time Warden On-The-Clock server (ID: 1419894879894507661)
2. Bot detects guild_id matches DEMO_SERVER_ID
3. Fetches role object with ID 1460483767050178631
4. Adds role to member with reason "Auto-assigned for demo access"
5. Logs: `✅ Assigned Test Employee role to {member.display_name}`

**Dashboard Access Requirements:**
- User must be authenticated (OAuth session)
- Dashboard checks demo server → grants admin access automatically
- Role assignment is cosmetic for demo; access is guild_id-based

---

### C. Dashboard Access Checks

| Check | File:Line | Function | Demo Behavior |
|-------|-----------|----------|---------------|
| **Session Validation** | app.py:740-752 | `get_user_session()` | Normal - checks expiry |
| **Auth Decorator** | app.py:754-776 | `@require_auth` | Normal - requires session |
| **Admin Status** | app.py:848-850 | `check_admin_status()` | ⚠️ BYPASS - returns `is_admin: True` for demo |
| **Guild Access** | app.py:4392-4406 | `verify_guild_access()` | ⚠️ BYPASS - returns `'admin'` for demo |
| **Paid Access** | app.py:890-973 | `@require_paid_access` | Normal for non-demo |
| **Real-Time Admin** | app.py:816-846 | `check_user_admin_realtime()` | Not used for demo (bypass earlier) |

**Critical Security Finding:**
```python
# app.py:848-850
if str(guild_id) == DEMO_SERVER_ID:
    return {'is_member': True, 'is_admin': True, 'reason': 'demo_server'}
```
- **ALL authenticated users** get full admin access to demo server
- Intentional design for public testing
- Does NOT leak to other servers (guild_id scoped)

---

### D. Kiosk Config Load/Render

| Component | File:Line | What Loads |
|-----------|-----------|------------|
| **Main Kiosk Page** | app.py:8854 | `render_template("kiosk.html", guild_id=guild_id)` |
| **Employee List API** | app.py:8859-8935 | Loads from `employee_profiles` with customization |
| **Guild Settings** | app.py:8870 | Checks `allow_kiosk_customization` flag |
| **Customization Fields** | DB: employee_profiles | `accent_color`, `profile_background`, `catchphrase`, `selected_stickers` |
| **Kiosk Mode Flag** | app.py:9589-9639 | Loads `kiosk_mode_only` from `server_subscriptions` |
| **PIN Hashes** | DB: employee_pins | SHA256(guild_id:user_id:pin) |

**Kiosk Template:** `/home/runner/workspace/templates/kiosk.html` (100+ lines, locked by Gemini)

**Config Flow:**
1. Frontend loads `/kiosk/<guild_id>` (no auth required)
2. JavaScript fetches `/api/kiosk/<guild_id>/employees`
3. Backend queries employee_profiles LEFT JOIN employee_pins
4. Returns: user_id, display_name, customization, has_pin, clocked_in, lockout_status
5. Frontend renders employee grid with custom colors (if clocked in + customization enabled)

---

### E. Seeding Logic (Demo Kiosk)

| Component | File:Line | Function | When Runs |
|-----------|-----------|----------|-----------|
| **Seeding Function** | app.py:3215-3304 | `seed_demo_data_internal()` | Manual + scheduled |
| **Manual Endpoint** | app.py:3306-3314 | `POST /debug/seed-demo-data` | Bot owner only |
| **Scheduled Job** | scheduler.py:485-495 | `reset_demo_data_job()` | Daily at midnight UTC |
| **Scheduler Trigger** | scheduler.py:540-546 | CronTrigger(hour=0, minute=0) | ✅ Automated |

**What Gets Seeded:**
1. **5 Employees:** IDs 100000000000000001-005 (Alex, Jordan, Casey, Sam, Taylor)
2. **Employee Profiles:** Full data (position, department, bio, hire_date, avatar_url)
3. **Timeclock Sessions:** 15-25 work days per employee over last 30 days
4. **Active Session:** One employee clocked in at seed time
5. **Time Adjustments:** 4 sample requests (2 pending, 1 approved, 1 denied)
6. **Guild Settings:** Updates `last_demo_reset` timestamp

**Idempotency:** Uses `ON CONFLICT (guild_id, user_id) DO UPDATE` - safe to re-run

**Session Generation Logic (lines 3248-3268):**
- Random shift times: 7-10 AM start
- Random durations: 4-9 hours
- Skips weekends 80% of time
- All sessions closed except one active

---

### F. Email Settings + Send Triggers

| Trigger | File:Line | Function | Frequency | Tier Check |
|---------|-----------|----------|-----------|------------|
| **Clock-Out Reports** | scheduler.py:88-145 | `send_work_day_end_reports()` | Every minute | ✅ Blocks FREE |
| **Deletion Warnings** | scheduler.py:236-303 | `send_deletion_warnings()` | Hourly | ❌ None |
| **Outbox Processor** | scheduler.py:466-514 | `process_outbox_emails()` | Every 30s | N/A |
| **Kiosk Shift Email** | app.py:9415-9580 | `api_kiosk_send_shift_email()` | On clock-out | ❌ None |
| **Test Email** | app.py:5871-5943 | `api_send_test_email()` | Manual | ✅ Requires paid |

**Email Configuration Storage:**
- **email_settings table:** `auto_send_on_clockout`, `auto_email_before_delete`
- **report_recipients table:** Verified email addresses (6-digit code verification)
- **email_outbox table:** Reliable delivery queue with retry logic (max 3 attempts, exponential backoff)

**Email Service:** Replit Mail API at `https://connectors.replit.com/api/v2/mailer/send`

---

### G. Time Report Generation

| Component | File:Line | Function | Username Fallback |
|-----------|-----------|----------|-------------------|
| **Daily Reports** | scheduler.py:147-233 | `send_daily_report_for_guild()` | display_name → full_name → Discord API → User {ID} |
| **Owner Reports** | app.py:4291-4373 | `api_owner_time_report()` | display_name → full_name → first+last → User {ID} |
| **CSV Generation** | scheduler.py:174-212 | Creates CSV with headers | LEFT JOIN employee_profiles |

**Fallback Chain (3-tier per lessons-learned.md:40-42):**
1. `employee_profiles.display_name`
2. `employee_profiles.full_name`
3. Discord API fetch → `discord_user.display_name` or `discord_user.name`
4. `f"User {user_id}"`

**CSV Format:**
```
User ID,Display Name,Clock In,Clock Out,Duration (hours)
123456789,Alex Thompson,2026-01-18 09:00:00,2026-01-18 17:30:00,8.50
```

---

### H. Time Adjustment Endpoints + Panel Flow

| Step | Component | File:Line | Route/Function |
|------|-----------|-----------|----------------|
| **1. Employee Opens** | Frontend JS | dashboard-adjustments.js:693 | `openEmployeeDayModal()` |
| **2. Submit Request** | Frontend JS | dashboard-adjustments.js:899 | `submitDayAdjustment()` → Promise.all() |
| **3. Create Adjustment** | Flask API | app.py:7436 | `POST /api/guild/<guild_id>/adjustments` |
| **4. Submit Day** | Flask API | app.py:7565 | `POST /api/guild/<guild_id>/adjustments/submit-day` |
| **5. Notify Admins** | Async Bot Call | app.py:7477-7480 | `asyncio.run_coroutine_threadsafe()` |
| **6. Send Email** | Daemon Thread | app.py:7483 | `send_adjustment_notification_email()` ⚠️ BLOCKS |
| **7. Store Request** | Bot Function | bot.py:3730-3776 | `create_adjustment_request()` → DB INSERT |
| **8. Admin View** | Flask API | app.py:7767 | `GET /api/guild/<guild_id>/adjustments/admin-calendar` |
| **9. Approve/Deny** | Flask API | app.py:7521/7543 | `POST /approve` or `/deny` |
| **10. Apply Changes** | Bot Function | bot.py:3794-3871 | `approve_adjustment()` → UPDATE sessions |

**Timezone Handling (app.py:7606-7676):**
- Parses HH:MM from frontend
- Combines with date in guild timezone (pytz)
- Converts to UTC for database storage
- Example: "09:30 EST" → "14:30 UTC"

---

## 2. DEMO SERVER CHECKLIST

### Expected Behaviors:

| Feature | Expected Behavior | Verification Method | Status |
|---------|-------------------|---------------------|--------|
| **Auto-Role Assignment** | New members get "Test Employee" role (ID: 1460483767050178631) | Check bot logs: `✅ Assigned Test Employee role` | ✅ Implemented |
| **Dashboard Access** | ANY authenticated user gets admin access | Check app.py:848 returns `is_admin: True` | ✅ Implemented |
| **View Mode Toggle** | URL params `?view_as=employee` or `?view_as=admin` switch views | Test dashboard with URL params | ✅ Implemented |
| **Seeded Employees** | 5 employees with IDs 100000000000000001-005 | Query employee_profiles for demo guild | ✅ Implemented |
| **Seeded Sessions** | 15-25 days of work sessions per employee (last 30 days) | Query timeclock_sessions for demo guild | ✅ Implemented |
| **Active Session** | One employee clocked in at all times | Check for session with NULL clock_out_time | ✅ Implemented |
| **Time Adjustments** | 4 sample requests (2 pending, 1 approved, 1 denied) | Query time_adjustment_requests for demo | ✅ Implemented |
| **Midnight Reset** | Data resets every day at 00:00 UTC | Check scheduler.py:540-546 cron trigger | ✅ Implemented |
| **Last Reset Tracker** | `guild_settings.last_demo_reset` updated after seed | Query guild_settings | ✅ Implemented |
| **Kiosk Access** | Kiosk page loads without auth at `/kiosk/1419894879894507661` | Test route directly | ✅ Implemented |
| **Email Recipients** | Demo should NOT send to real emails | ⚠️ NO PROTECTION FOUND | ❌ MISSING |
| **Tier Override** | Demo server bypasses tier checks | Verify no Premium/Pro gates block demo | ⚠️ PARTIAL |

### Code Verification Points:

**1. Demo Server ID Match:**
```bash
# Check consistency
grep -n "DEMO_SERVER_ID" bot.py app.py
# bot.py:54 = 1419894879894507661 (int)
# app.py:60 = '1419894879894507661' (string)
# ⚠️ Type mismatch requires str() conversion
```

**2. Member Join Handler:**
```bash
# Verify auto-role logic
grep -A 20 "async def on_member_join" bot.py
# Check: if member.guild.id == DEMO_SERVER_ID
```

**3. Admin Bypass:**
```bash
# Verify demo admin grant
grep -B 3 -A 3 "demo_server" app.py | grep -A 3 "check_admin_status"
```

**4. Seeding Schedule:**
```bash
# Verify midnight UTC reset
grep -A 5 "reset_demo_data" scheduler.py
```

---

## 3. IBC SERVER CHECKLIST

### Expected Behaviors:

| Feature | Expected Behavior | Verification Method | Status |
|---------|-------------------|---------------------|--------|
| **Real Data Only** | No seeded/fake employees | employee_profiles has real Discord user IDs (17+ digits) | ✅ Expected |
| **OAuth Access Control** | Users must be server members + have permissions | `check_user_admin_realtime()` verifies via bot API | ✅ Implemented |
| **Tier Gating** | Kiosk features require Pro tier ($15/mo) | Check `bot_access_paid` AND `retention_tier='pro'` | ⚠️ INCOMPLETE |
| **Email Recipients** | Only verified emails via 6-digit code | Query `report_recipients` WHERE `verification_status='verified'` | ✅ Implemented |
| **Clock-Out Reports** | Sent at configured `work_day_end_time` | scheduler.py checks guild timezone + time match | ✅ Implemented |
| **Deletion Warnings** | Sent 1-4 hours before data purge | scheduler.py calculates cutoff based on `Entitlements.get_retention_days()` | ✅ Implemented |
| **Retention Rules** | Free: 1 day, Premium/Pro: 30 days | entitlements.py lines 37-45 | ✅ Implemented |
| **Kiosk Mode Only** | When enabled, disables `/clock` Discord commands | bot.py:5162, 5297 checks `is_kiosk_mode_only()` | ✅ Implemented |
| **Kiosk Customization** | Admin can toggle employee color/theme visibility | `guild_settings.allow_kiosk_customization` | ✅ Implemented |
| **Time Adjustments** | Employees request, admins approve/deny | Full workflow app.py:7436-7767, bot.py:3730-3873 | ✅ Implemented |
| **NO Demo Bypass** | IBC server never gets demo server special treatment | All demo checks use exact guild_id match | ✅ Verified |

### Code Verification Points:

**1. Tier Check for Kiosk:**
```bash
# Find tier gating
grep -n "@require_paid_api_access" app.py | grep kiosk
# Result: Only admin settings routes have decorator
# ⚠️ Main kiosk routes (8854-9729) have NO tier check
```

**2. Email Verification:**
```bash
# Check verification requirement
grep -A 10 "verification_status" app.py
# Confirms: Only 'verified' recipients get emails
```

**3. Retention Days:**
```bash
# Verify tier-based retention
grep -A 10 "get_retention_days" entitlements.py
# Free: 1, Premium/Pro/Grandfathered: 30
```

**4. Real-Time Admin Check:**
```bash
# Verify live admin verification (not stale OAuth)
grep -A 20 "check_user_admin_realtime" app.py
# Calls bot API: /api/guilds/{guild_id}/check-admin/{user_id}
```

---

## 4. POTENTIAL FAILURE POINTS

### Top 5 Issues: Role Not Assigned / Dashboard Access Fails

| Rank | Issue | Root Cause | File:Line | Impact |
|------|-------|------------|-----------|--------|
| **1** | Role ID mismatch | If `DEMO_EMPLOYEE_ROLE_ID` doesn't exist in guild | bot.py:55 | Join handler fails silently |
| **2** | Guild ID type conversion | String vs int comparison bugs | bot.py:54, app.py:60 | Demo detection fails |
| **3** | Bot not ready on join | `on_member_join` fires before bot initialized | bot.py:6876 | No role assigned |
| **4** | Role permissions | Bot lacks "Manage Roles" permission in guild | Discord permissions | Assignment fails |
| **5** | OAuth session expired | User session expires before dashboard access | app.py:740-752 | Redirect to login |

**Diagnostic Logs to Add:**
```python
# bot.py:6891 (in on_member_join)
if not role:
    print(f"❌ DEMO ROLE NOT FOUND: {DEMO_EMPLOYEE_ROLE_ID}")

# bot.py:6913 (after add_roles)
except discord.Forbidden:
    print(f"❌ MISSING PERMISSIONS: Cannot assign role")
```

---

### Top 5 Issues: Kiosk Not Loading Seeded Config

| Rank | Issue | Root Cause | File:Line | Impact |
|------|-------|------------|-----------|--------|
| **1** | Seeding never ran | Scheduler not started or job failed | scheduler.py:540-546 | No demo employees |
| **2** | Guild ID mismatch in seed | Hardcoded `1419894879894507661` doesn't match actual demo server | app.py:3221 | Seed goes to wrong guild |
| **3** | Database connection error | `seed_demo_data_internal()` fails silently | app.py:3215-3304 | No data written |
| **4** | Employee IDs conflict | Real users with IDs 100000000000000001-005 (impossible but possible) | app.py:3226-3230 | CONFLICT error |
| **5** | API returns empty | `/api/kiosk/<guild_id>/employees` query fails | app.py:8870-8932 | Frontend shows no employees |

**Diagnostic Logs to Add:**
```python
# app.py:3225 (in seed_demo_data_internal)
print(f"🌱 SEEDING DEMO DATA for guild {DEMO_SERVER_ID}")

# app.py:3302 (after seeding)
print(f"✅ DEMO DATA SEEDED: {len(employees)} employees, {len(sessions)} sessions")

# scheduler.py:490 (in reset_demo_data_job)
if not success:
    logger.error(f"❌ SEEDING FAILED - check app.py logs")
```

---

### Top 5 Issues: Emails Not Sending or Sending Wrong

| Rank | Issue | Root Cause | File:Line | Impact |
|------|-------|------------|-----------|--------|
| **1** | No verified recipients | Users never verified emails via 6-digit code | DB: report_recipients | No one receives reports |
| **2** | Free tier blocked | `send_work_day_end_reports()` skips free tier | scheduler.py:103-105 | Reports never sent |
| **3** | Replit Mail API auth failure | `REPL_IDENTITY` or `WEB_REPL_RENEWAL` expired | email_utils.py:148-152 | All emails fail |
| **4** | Wrong timezone | `work_day_end_time` doesn't match actual end time | scheduler.py:96-98 | Sent at wrong hour |
| **5** | Outbox retry exhausted | Email failed 3 times, marked 'failed' | email_outbox table | Never retried |

**Diagnostic Logs to Add:**
```python
# scheduler.py:122 (in send_work_day_end_reports)
if not recipients:
    logger.warning(f"❌ NO VERIFIED RECIPIENTS for guild {guild_id}")

# email_utils.py:160 (after send attempt)
if response.status_code != 200:
    logger.error(f"❌ MAIL API ERROR {response.status_code}: {response.text}")
```

---

### Top 5 Issues: Time Adjustment Panel Freezing

| Rank | Issue | Root Cause | File:Line | Impact | Priority |
|------|-------|------------|-----------|--------|----------|
| **1 🔴** | **Async email blocks thread** | `send_adjustment_notification_email()` creates new event loop and blocks | app.py:255-264 | **Frontend appears frozen** | **CRITICAL** |
| **2** | Bot notification hangs | `asyncio.run_coroutine_threadsafe()` no timeout if bot unresponsive | app.py:7477-7480 | Background notification never completes | HIGH |
| **3** | Promise.all() chain failure | Frontend submits multiple requests; one fails → all fail | dashboard-adjustments.js:993 | User sees error, unsure which failed | MEDIUM |
| **4** | No timeout on fetch | Browser waits indefinitely for Flask response | dashboard-adjustments.js:965, 979 | Request appears stuck | MEDIUM |
| **5** | Timezone conversion error | Invalid time format crashes `pytz.localize()` | app.py:7664 | 500 error, no user feedback | LOW |

**Critical Code Path (⚠️ BLOCKING ISSUE):**
```python
# app.py:255-264 in send_adjustment_notification_email()
loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)
try:
    result = loop.run_until_complete(send_email(...))  # ⚠️ BLOCKS THREAD
finally:
    loop.close()
```

**Why This Freezes:**
1. Flask thread calls this function in daemon thread
2. Creates NEW event loop (not using bot's loop)
3. `run_until_complete()` **BLOCKS** until email send finishes
4. If email service slow or network issue → thread stuck indefinitely
5. User sees "Submitting..." forever on frontend

**Fix Required:**
- Add timeout to `loop.run_until_complete(send_email(...), timeout=10.0)`
- OR: Move to background task queue (celery, redis queue, or email_outbox table)
- OR: Remove email notification on submit (only notify on approval/denial)

---

## 5. TASK LIST (FAST vs AUTONOMOUS)

### FAST TASKS (Lightweight fixes, small edits, diagnostic additions)

#### Task F1: Add Timeout to Email Notification ⚡ HIGH PRIORITY
**File:** `app.py:255-264`
**Changes:**
```python
# Add timeout wrapper
try:
    result = asyncio.wait_for(
        loop.run_until_complete(send_email(...)),
        timeout=10.0  # 10 second max
    )
except asyncio.TimeoutError:
    logger.warning(f"Email notification timeout for guild {guild_id}")
    # Continue without blocking
```
**Impact:** Prevents adjustment panel freezing
**Risk:** Low - adds safety timeout
**Test:** Submit adjustment, verify no freeze if email slow

---

#### Task F2: Add Demo Server Email Sandbox ⚡ MEDIUM PRIORITY
**File:** `app.py` (multiple locations)
**Changes:**
```python
# In api_add_email_recipient() line 5560
if str(guild_id) == DEMO_SERVER_ID:
    return jsonify({
        'success': False,
        'error': 'Email recipients cannot be added to demo server'
    }), 400

# In send_work_day_end_reports() scheduler.py:103
if guild_id == int(DEMO_SERVER_ID):
    logger.info(f"Skipping email for demo server {guild_id}")
    continue
```
**Impact:** Prevents real emails from demo server
**Risk:** Low - demo-only change
**Test:** Try adding email to demo, verify rejection

---

#### Task F3: Add Diagnostic Logging for Adjustments ⚡ LOW PRIORITY
**Files:** `app.py`, `bot.py`, `dashboard-adjustments.js`
**Changes:**
- Log adjustment submission start/end timestamps
- Log email notification status (sent/timeout/failed)
- Log bot notification status
- Console.log frontend submission steps
**Impact:** Easier debugging of freezing issues
**Risk:** None - logging only
**Test:** Submit adjustment, review logs

---

#### Task F4: Fix Guild ID Type Consistency ⚡ LOW PRIORITY
**Files:** `bot.py:54`, `app.py:60`
**Changes:**
```python
# Standardize to string in app.py, int in bot.py
# Add conversion function:
def is_demo_server(guild_id):
    """Check if guild is demo server (handles int/str)"""
    return str(guild_id) == '1419894879894507661'
```
**Impact:** Consistent demo detection
**Risk:** Low - isolated utility function
**Test:** Verify demo detection works

---

#### Task F5: Add Kiosk Route Tier Gating ⚡ MEDIUM PRIORITY
**File:** `app.py:8854-9729`
**Changes:**
```python
# Add decorator to kiosk routes
@app.route("/kiosk/<guild_id>")
@require_paid_access  # OR new @require_pro_tier decorator
def kiosk_page(user_session, guild_id):
    # ... existing code
```
**Impact:** Enforces Pro tier requirement for kiosk
**Risk:** Medium - could break free tier testing
**Test:** Verify free tier blocked, Pro tier allowed

---

### AUTONOMOUS TASKS (Complex, multi-file, deep logic changes)

#### Task A1: Refactor Email Notification to Background Queue 🤖 HIGH PRIORITY
**Scope:** app.py, email_utils.py, scheduler.py
**Changes:**
1. Move adjustment notification to `email_outbox` table
2. Remove blocking `send_adjustment_notification_email()` call
3. Let `process_outbox_emails()` handle async
4. Update `create_adjustment_request()` to queue instead of send
**Impact:** Eliminates blocking; reliable delivery with retries
**Risk:** HIGH - changes critical email path
**Files Modified:** 3+ files
**Testing Required:** Full email flow end-to-end
**Estimated Complexity:** 3-5 hours

---

#### Task A2: Implement Kiosk-Only Employees System 🤖 MEDIUM PRIORITY
**Scope:** migrations.py, app.py, bot.py, templates/
**Changes:**
1. Create `kiosk_employees` table (per kiosk-overhaul.md line 164-175)
2. Add admin UI to create/deactivate kiosk employees
3. Modify kiosk APIs to support system-generated IDs (KIOSK-001, etc.)
4. Update report generation to include kiosk-only employees
5. Ensure time tracking works without Discord user_id
**Impact:** Enables employees without Discord accounts
**Risk:** HIGH - new employee type, data model change
**Files Modified:** 5+ files
**Testing Required:** Full kiosk flow + reports
**Estimated Complexity:** 8-12 hours

---

#### Task A3: Time Adjustment History View 🤖 LOW PRIORITY
**Scope:** app.py, templates/, static/js/
**Changes:**
1. Add endpoint to fetch employee's adjustment history
2. Update adjustment panel to show last 3-4 punches (not just clock out)
3. Display previous adjustments with status badges (Approved/Denied/Pending)
4. Sync profile customization to adjustment modal
**Impact:** Better UX per kiosk-overhaul.md line 59-63
**Risk:** LOW - UI enhancement only
**Files Modified:** 3 files
**Testing Required:** Visual QA of adjustment panel
**Estimated Complexity:** 4-6 hours

---

#### Task A4: Implement Comprehensive Kiosk Testing Suite 🤖 LOW PRIORITY
**Scope:** New test files, CI/CD integration
**Changes:**
1. Create `tests/test_kiosk.py` with pytest
2. Test PIN verification, clock in/out, adjustments
3. Test demo seeding idempotency
4. Test email delivery paths
5. Add integration tests for adjustment workflow
**Impact:** Prevents regressions in kiosk system
**Risk:** None - testing only
**Files Created:** 3+ test files
**Estimated Complexity:** 6-10 hours

---

## 6. COMPARISON: DEMO vs IBC SERVER

| Aspect | Demo Server (1419894879894507661) | IBC Server (Paid) |
|--------|-----------------------------------|-------------------|
| **Guild ID** | Hardcoded: 1419894879894507661 | Real Discord guild ID |
| **Access Control** | ALL users get admin bypass | OAuth + real-time admin check |
| **Employees** | 5 seeded fake (IDs: 100000000000000001-005) | Real Discord members |
| **Timeclock Data** | 30 days seeded, resets daily | Real sessions, retained per tier |
| **Auto-Role** | "Test Employee" (1460483767050178631) auto-assigned | Configured employee role (if returning) |
| **Dashboard View** | Toggle admin/employee via URL param | Based on real permissions |
| **Email Recipients** | ⚠️ Can add real emails (NO PROTECTION) | Verified emails via 6-digit code |
| **Email Sending** | ⚠️ No sandbox (could send real emails) | Production emails to verified recipients |
| **Tier Enforcement** | Bypasses most paid checks | Enforced: Free/Premium/Pro |
| **Kiosk Access** | Open (no tier gate on routes) | ⚠️ Also open (INCOMPLETE GATING) |
| **Kiosk Customization** | Enabled (seeded profiles have colors) | Admin-controlled toggle |
| **Data Retention** | N/A (resets daily) | 1 day (free) or 30 days (paid) |
| **Deletion Warnings** | Not applicable | Sent 1-4 hours before purge |
| **Time Adjustments** | Seeded samples (4 requests) | Real employee submissions |
| **Reports** | Can generate (fake data) | Real CSV reports |
| **Kiosk Mode Only** | Not typically used | Forces kiosk-only clocking if enabled |

---

## 7. SECURITY & ISOLATION REVIEW

### ✅ SECURE (Properly Isolated):

1. **Guild ID scoping** - All demo checks use exact `guild_id == DEMO_SERVER_ID` match
2. **No cross-contamination** - Demo server ID will never match IBC server ID
3. **Fake employee IDs** - IDs 100000000000000001-005 will never conflict with real Discord IDs (which are 17-18 digits)
4. **Role isolation** - Demo role (1460483767050178631) only valid in demo guild
5. **Database isolation** - Same DB but guild_id prevents cross-access
6. **Session management** - OAuth sessions tied to Discord user, can't impersonate

### ⚠️ RISKS IDENTIFIED:

1. **Demo email sending** - No protection against adding real emails to demo server
2. **Type inconsistency** - String vs int for DEMO_SERVER_ID could cause bugs
3. **Kiosk tier gating** - Main kiosk routes lack `@require_paid_access` decorator
4. **Adjustment freezing** - Blocking async email notification can hang UI
5. **No rate limiting** - Demo server has no special rate limits; could be abused

---

## 8. RECOMMENDED IMMEDIATE ACTIONS

### Critical (Fix Immediately):
1. ✅ **Add timeout to adjustment email notification** (Task F1) - Prevents freezing
2. ✅ **Implement demo server email sandbox** (Task F2) - Prevents real email spam

### High Priority (Fix This Week):
3. **Complete kiosk route tier gating** (Task F5) - Enforces Pro tier requirement
4. **Add diagnostic logging** (Task F3) - Easier debugging

### Medium Priority (Next Sprint):
5. **Refactor email to background queue** (Task A1) - Proper async handling
6. **Standardize guild ID types** (Task F4) - Prevent comparison bugs

### Low Priority (Backlog):
7. **Implement kiosk-only employees** (Task A2) - Feature enhancement
8. **Add adjustment history view** (Task A3) - UX improvement
9. **Create kiosk test suite** (Task A4) - Prevent regressions

---

## 9. FILES REQUIRING CHANGES

### FAST Tasks:
- `app.py` (email timeout, demo sandbox, logging)
- `bot.py` (logging)
- `scheduler.py` (demo email skip)
- `dashboard-adjustments.js` (frontend logging)

### AUTONOMOUS Tasks:
- `app.py` (background queue refactor)
- `email_utils.py` (queue integration)
- `scheduler.py` (queue processor)
- `migrations.py` (kiosk_employees table)
- `templates/` (adjustment history UI) - ⚠️ LOCKED BY GEMINI
- `static/js/` (frontend enhancements)

---

## 10. TESTING CHECKLIST

### Demo Server Verification:
- [ ] Join demo server → verify "Test Employee" role assigned
- [ ] Login to dashboard → verify auto-admin access
- [ ] Test URL params `?view_as=employee` and `?view_as=admin`
- [ ] Verify 5 seeded employees appear in kiosk
- [ ] Verify 30 days of historical sessions exist
- [ ] Check one employee is clocked in
- [ ] Submit time adjustment → verify no freeze
- [ ] Wait for midnight UTC → verify data reset

### IBC Server Verification:
- [ ] Verify OAuth access control (non-members blocked)
- [ ] Verify real-time admin check via bot API
- [ ] Verify tier gating on premium features
- [ ] Test email recipient verification (6-digit code)
- [ ] Test clock-out daily reports at configured time
- [ ] Test deletion warnings 1-4 hours before purge
- [ ] Verify retention: Free=1 day, Premium/Pro=30 days
- [ ] Test kiosk mode only (Discord `/clock` disabled)
- [ ] Test time adjustment full workflow (submit → approve/deny)

### Email System Verification:
- [ ] Add email recipient → verify 6-digit code sent
- [ ] Verify email → confirm verification_status='verified'
- [ ] Trigger clock-out report → verify CSV received
- [ ] Trigger deletion warning → verify email received
- [ ] Test email with outbox queue → verify retry logic
- [ ] Check email audit log for all events

### Time Adjustment Panel Verification:
- [ ] Submit adjustment → verify no frontend freeze
- [ ] Verify admin notification sent to Discord
- [ ] Verify email notification sent to recipients
- [ ] Admin approve → verify session updated in DB
- [ ] Admin deny → verify status='denied' in DB
- [ ] Test timezone conversion (EST/PST/UTC)

---

## APPENDIX: Key Constants & IDs

```
DEMO_SERVER_ID = 1419894879894507661 (Time Warden On-The-Clock)
DEMO_EMPLOYEE_ROLE_ID = 1460483767050178631 ("Test Employee" role)
DEMO_EMPLOYEE_IDS = 100000000000000001-005 (fake user IDs)

IBC_SERVER_ID = <unknown> (not in codebase, real production server)

RETENTION_FREE_DAYS = 1 (24 hours)
RETENTION_PREMIUM_DAYS = 30
RETENTION_PRO_DAYS = 30

FREE_TIER = "free" (24h retention, no paid features)
PREMIUM_TIER = "premium" ($8/mo, 30d retention)
PRO_TIER = "pro" ($15/mo, 30d retention + kiosk)
GRANDFATHERED_TIER = "grandfathered" (legacy $5 lifetime, premium access)
```

---

**END OF INVESTIGATION REPORT**
**Next Step:** User review + approval before implementing FAST tasks
