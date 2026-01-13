# Overview
"On the Clock 2.0" is a professional Discord timeclock bot for businesses, offering streamlined time tracking, subscription management, robust error handling, and enterprise-grade reliability. It features a two-tier subscription model, Stripe integration, role-based access control, and an informative landing page. The project aims to provide an easy-to-use and reliable time tracking solution within Discord.

# User Preferences
Preferred communication style: Simple, everyday language.

# Lessons Learned
- **Workflow Rule**: ALWAYS read `replit.md` before making any code alterations or additions to ensure precise alignment with project vision and past learnings.
- **Visual Identity**: The "Neon Cyber" theme with animated pure CSS clock and cyan matrix rain is the primary visual identity.
- **Component Persistence**: Theme toggles or visual preferences must persist using `localStorage` to ensure a fluent experience across landing and dashboard pages.
- **Accessibility**: Decorative visual elements like the background clock and matrix rain should always include `aria-hidden="true"`.
- **Mobile First**: Interactive components like the roadmap accordion must be explicitly tested for auto-collapse behavior on mobile viewports.
- **Matrix Animation Guards**: Canvas/ctx must have null checks before any operations. Use `matrixRunning` flag to prevent duplicate animation loops. Check `localStorage` hidden state before starting animation on page load.
- **Dashboard Matrix**: Uses `window.startDashboardMatrix()` exposed by `dashboard-matrix.js` so `dashboard-common.js` toggle can restart animation when re-enabled.
- **Flask Route Uniqueness**: Never define the same route decorator twice in `app.py`. Flask raises `AssertionError` on startup if endpoint names collide. Always grep for existing route definitions before adding new ones.
- **Database Initialization Guards**: Use process-level flags (e.g., `_db_pool_initialized`, `_migrations_run`) to ensure database pool creation and migrations only execute once per process, not on every connection request.
- **Orphaned Code Detection**: Code blocks placed after a function's `finally:` clause but not inside any function definition will execute at module import time, causing repeated side effects. Always verify indentation after editing context managers.
- **Fast Mode Review**: Quick edits can introduce duplicate definitions or orphaned code blocks. Always run the server and check logs after fast-mode changes before considering work complete.
- **Orphaned Code Caution**: Before removing "orphaned" code blocks that seem to have wrong indentation, verify if they were intentionally placed to execute at module import time (e.g., for startup verification).
- **Dashboard Component Guarding**: Use specific page identifiers (like `active_page` in Jinja2 or `data-page` in HTML) to ensure components like the Admin Calendar or specific JS initializations only load on their intended routes.
- **Admin Calendar Leak Prevention**: The Admin Calendar must be explicitly guarded with `{% if active_page == 'calendar' %}` in templates to prevent it from appearing on the server selection or other overview pages.
- **Demo Server View Toggle**: Demo server (ID: 1419894879894507661) allows visitors to toggle between Admin and Employee views via query parameter (`?view_as=admin` or `?view_as=employee`) stored in session for persistence across navigation.
- **Demo Data Seeding**: Owner-only endpoint `/debug/seed-demo-data` (POST) seeds sample employees, timeclock sessions, and adjustment requests for the demo server. All IDs must use integer types to match BIGINT database columns.
- **Demo Auto-Reset**: APScheduler job resets demo server data daily at midnight UTC. `last_demo_reset` timestamp stored in `guild_settings` and displayed in demo mode toggle panel.
- **Guided Tour System**: `dashboard-tour.js` provides spotlight/tooltip onboarding walkthrough. Uses localStorage to track completion status. Auto-starts for new users, manual trigger via "Take the Tour" sidebar button.

# System Architecture
## Bot Framework
... (existing content)
- **Visual Identity**: Full-screen "Neon Cyber" theme centered around an animated, transparent CSS clock overlay (500px, 80% opacity) with cyan matrix rain background effects.
- **Theme Palette**:
    - Primary: Cyan (#00FFFF)
    - Background: Deep Dark Blue (#0a0f1f)
    - Accents: Gold (#D4AF37)
    - Secondary: Neon Red (#FF4757)
- **Matrix Toggle**: A persistent "Enter/Exit The Matrix" toggle in the top-right corner allows users to enable/disable the background effects project-wide.
... (rest of existing content)
- **Onboarding System**: Interactive dashboard guide (spotlight effects, speech bubbles) and automated welcome DMs for new employees, with first-time `/clock` guides.
- **Route-Based Dashboard**: Dedicated routes for server overview, role management, email settings, timezone/schedule, employee status cards, individual employee profiles, clock interface, time adjustments, calendar, bans, and owner dashboard.
- **Subscription Management**:
    - **Free Tier**: $0/mo, basic profile management, 24-hour data retention.
    - **Premium Tier**: $8/mo, full dashboard, time adjustments, employee management, CSV reports, email notifications, 30-day retention.
    - **Pro Tier**: $15/mo, includes Kiosk mode, payroll integrations, advanced CSV, shift scheduling.
    - **Grandfathered Tier**: Legacy servers retain Premium access.
- **Trial Tracking**: Tracks one-time $5 first-month trial per server.
- **Concurrent Safety**: Guild-level locking, PostgreSQL connection pooling, SSL validation, and automatic transaction management.
- **Ephemeral Interface System**: Resolves interaction timeout issues via `/clock` command.
- **Bot as Boss Architecture**: All role management changes routed through the bot's HTTP API.
- **Email Automation**: APScheduler handles automated email tasks (e.g., clock-out reminders, reports) using an Email Outbox Pattern with `email_outbox` table for queuing and retries.
- **Owner Dashboard**: Web-based dashboard (`/owner` route) for monitoring servers, subscriptions, and broadcasting announcements.
- **Bot Access Notification**: Rich embed sent to server upon access grant with setup instructions and dashboard link.
- **Bulletproof Button Persistence**: Unified `/clock` command interface with stable custom IDs and `timeout=None` for button reliability.
- **Signed Deep-Link System**: Secure Discord-to-Dashboard navigation using signed URLs.
- **Context Menu Commands**: Right-click user actions for admins (view hours, profile, force clock-out, ban).
- **Employee Onboarding Button**: Premium-only button to send onboarding DMs.
- **Pre-Deletion Warning System**: Hourly DMs to free-tier admins before data deletion.
- **Database Migrations**: Automatic schema migrations on startup.
- **Employee Status Cards**: Dashboard displays active employees with current hours and manual clock-out buttons for admins.
- **Time Adjustment Requests**: Employees submit requests via dashboard, kiosk, or bot; admins approve/deny via dashboard calendar. Kiosk users can edit today's sessions and add missing entries with reasons.
- **Kiosk Notification System**: Employee cards and info panel show alerts for missing email, pending adjustments, or missing punches.
- **Broadcast Channel Configuration**: Admins configure bot announcement channel via dashboard.
- **Profile & Kiosk Customization**: Employees can personalize their profiles with background themes and accent colors. These customizations sync to their kiosk buttons if the server-level `allow_kiosk_customization` setting is enabled.
- **Theme Presets**: Multiple Neon Cyber themed gradients and accent colors available for profiles.
- **Admin Control**: Admins can toggle employee customization on/off via the dashboard to maintain a uniform look if desired.

## Security Configuration
- **Code Analysis**: Semgrep for static analysis and secret management.
- **Stripe Security**: Webhook signature verification, secure API key management.
- **Data Privacy**: Automated data purging based on subscription tier.
- **Input Validation**: Robust validation for roles and timezones.
- **Authorization Checks**: Verification of bot presence and user admin access.
- **Rate Limiting & Spam Detection**: In-memory tracking with temporary bans.
- **SSRF Protection**: Strict validation for `guild_id` in Bot API requests.
- **XSS Prevention**: `escapeHtml()` and `addEventListener` for user data in dashboard.
- **SQL Injection Prevention**: Parameterized statements for all database queries.
- **Environment Variables**: Sensitive configurations managed via environment variables.

# External Dependencies
- **discord.py**: Discord API interaction.
- **tzdata**: Timezone data handling.
- **psycopg2-binary**: PostgreSQL database adapter.
- **aiohttp**: Bot's internal HTTP API server.
- **APScheduler**: Asynchronous job scheduling.
- **Discord API**: Real-time communication.
- **Discord OAuth 2.0**: User authentication and dashboard features.
- **Stripe**: Subscription and payment processing, webhook handling.
- **PostgreSQL**: Production database with persistent connection pooling, SSL, `RealDictCursor`, and parameterized statements. Utilizes a unified `timeclock_sessions` table for all components.