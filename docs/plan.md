# Feature Planning Document

**Purpose**: Store current feature plans for handoff between agents (Replit Agent, Claude Code, Gemini CLI). Each agent should read this before starting complex work.

---

## Current Plan
**Feature**: None active
**Priority**: -
**Target**: -

### Requirements
(What needs to be built)

### Approach
(How to implement it)

### Files to Modify
(List of files that will be touched)

### Testing Strategy
(How to verify it works)

---

## Future Plan: Project Streamlining & Onboarding Refactor

**IMPORTANT**: This plan was generated on 2026-01-25. The project's codebase is expected to change. A full code review must be conducted to re-validate this plan's assumptions before any work begins.

**Feature**: A comprehensive refactor to streamline the architecture, simplify the user interface, and improve the new user onboarding experience.

**Priority**: High

**Target**: New and existing server administrators.

### Requirements

1.  **Consolidate Web Logic**: All HTTP traffic, including Stripe webhooks, must be handled exclusively by the `app.py` Flask application. The internal web server in `bot.py` must be removed.
2.  **Simplify Admin Onboarding**: Create a guided, step-by-step setup wizard for new server owners to configure essential settings (e.g., roles, timezone) upon their first visit to the dashboard.
3.  **Streamline UI**:
    *   De-clutter the main dashboard by grouping advanced or less-frequently used features under a dedicated "Advanced Settings" section.
    *   Increase the visibility of the "Demo Server" feature to encourage new users to explore the application's capabilities in a safe environment.
4.  **Simplify Purchase Flow**: Refactor the `/upgrade` command to pass the `guild_id` directly to the Stripe checkout process, removing the intermediate server selection web page.

### Approach

1.  **Phase 1: Web Logic Consolidation**
    *   Analyze all routes and webhook handlers in `bot.py`'s internal web server.
    *   Re-implement the necessary endpoints and logic within `app.py`.
    *   Create a new internal API client in `bot.py` to make outbound requests to `app.py` for any required web-related actions (e.g., generating payment links).
    *   Remove the web server code from `bot.py`.
2.  **Phase 2: UI/UX Refactor**
    *   **Guided Setup Wizard**:
        *   Create a new set of templates for a multi-step wizard.
        *   Implement a new route in `app.py` that checks if a new admin has completed the setup. If not, redirect them to the wizard.
    *   **Dashboard Streamlining**:
        *   Audit all templates in `templates/`.
        *   Create a new `dashboard_advanced.html` template.
        *   Move the HTML and corresponding routes for non-essential features from the main dashboard templates to the new advanced section.
    *   **Purchase Flow**:
        *   Modify the `/upgrade` command in `bot.py` to generate a Stripe checkout session URL that includes the `guild_id` in its metadata or as a parameter.
        *   Update the `purchase_checkout` logic in `app.py` to handle this direct flow.

### Files to Modify

*   `app.py`: Major changes to consolidate all web routes, add the setup wizard logic, and handle the streamlined purchase flow.
*   `bot.py`: Major changes to remove the internal web server and update the `/upgrade` command.
*   `templates/`: Significant changes. New templates for the setup wizard will be created. Existing dashboard templates will be modified to streamline the UI.
*   `entitlements.py`: May require minor changes to support the new UI structure (e.g., hiding/showing advanced features based on tier).

### Testing Strategy

1.  **Unit & Integration Testing**:
    *   Write unit tests for the new API endpoints in `app.py`.
    *   Create integration tests to ensure the bot can successfully communicate with the refactored `app.py` API.
2.  **End-to-End (E2E) Testing**:
    *   Manually test the entire new user onboarding flow, from inviting the bot to completing the setup wizard.
    *   Manually test the new, streamlined purchase flow.
    *   Perform regression testing on all existing dashboard features to ensure they still function correctly after the UI refactor.

---

## Completed Plans
| Date | Feature | Outcome |
|------|---------|---------|
| - | - | - |

---

## Plan Archive
For detailed historical plans, see `docs/plans/*.md`