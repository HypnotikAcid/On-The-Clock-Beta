# UI/Frontend Audit Report
**Date**: 2026-01-18
**Auditor**: Gemini

---

## Executive Summary

This audit reviewed all HTML templates for XSS vulnerabilities, visual identity consistency, accessibility, mobile responsiveness, and CSS organization.

**Priority Levels:**
- 🔴 **CRITICAL**: Must fix - security risk or breaks core functionality.
- 🟡 **MEDIUM**: Should fix - UI inconsistency, accessibility issue, or technical debt.
- 🔵 **LOW**: Nice to have - minor cleanup or cosmetic issue.

---

## File: `templates/dashboard_base.html`

###  Findings

1.  **XSS Vulnerabilities**: 🟢 **PASS**
    - No significant XSS vulnerabilities were found. User-provided data (`server.name`, `user.username`) is rendered in non-executable contexts and should be handled by Jinja2's default auto-escaping. No unsafe uses of the `|safe` filter were detected.

2.  **Visual Identity**: 🟢 **PASS**
    - The file correctly implements the "Neon Cyber" theme, including the matrix rain effect container, an animated clock, and the primary cyan color (`#00FFFF`).

3.  **Accessibility**: 🟡 **MEDIUM**
    - **Generic Alt Text**: The user avatar image uses a generic `alt="Avatar"`. It should be more descriptive, like `alt="{{ user.username }}'s avatar"`.
    - **Missing `aria-hidden`**: Multiple decorative `<span>` elements used for icons (e.g., `⚙️`, `📊`, `🚪`) are missing `aria-hidden="true"`, adding unnecessary noise for screen reader users.
    - **Vague Link Text**: The logout link only contains an emoji (`🚪`). It should have a proper `aria-label` or more descriptive text like "Logout".
    - **Non-standard Controls**: The mobile hamburger menu is a `<span>` element. It should be a `<button>` to be semantically correct and accessible to keyboard users.

4.  **Mobile Responsiveness**: 🟢 **PASS**
    - The template includes specific JavaScript logic and CSS media queries to handle mobile viewports, including a collapsible sidebar and adjustments for ad containers.

5.  **CSS Organization**: 🟡 **MEDIUM**
    - **Excessive Inline Styles**: There is a heavy reliance on inline `style` attributes for major components like the matrix toggle, coffee button, and demo mode panel. This makes the code hard to maintain and violates the separation of concerns.
    - **Embedded CSS**: Multiple `<style>` blocks are present. This CSS should be moved to an external stylesheet (e.g., `dashboard.css`) to improve caching and maintainability.

---

## File: `templates/dashboard_employee_profile.html`

### Findings

1.  **XSS Vulnerabilities**: 🔴 **CRITICAL**
    - **DOM XSS**: The JavaScript on this page fetches user profile data from an API and uses `container.innerHTML` to render it. Data fields like `p.display_name`, `p.bio`, and `p.department` are inserted directly into the DOM. If any of this data contains malicious HTML (e.g., a user sets their bio to `<script>alert('XSS')</script>`), it will be executed in the browser of anyone viewing the profile. This is a severe DOM-based XSS vulnerability.
    - **Mitigation**: The code must be refactored to avoid `innerHTML`. Instead, it should safely create DOM elements and set their content using `textContent` or `innerText`.
    - **Claude Task**: The backend API at `/api/server/{guildId}/employee/{userId}/profile` should be reviewed to ensure it properly sanitizes and escapes user-provided data before storing it.

2.  **Visual Identity**: 🟢 **PASS**
    - The page uses the `neon-text` class and a color scheme consistent with the "Neon Cyber" theme.

3.  **Accessibility**: 🟡 **MEDIUM**
    - **Missing Alt Text**: The dynamically generated `<img>` tag for the user's avatar is missing an `alt` attribute. It should be set to `p.display_name` to be descriptive.

4.  **Mobile Responsiveness**: 🟢 **PASS**
    - The page uses a media query to correctly reflow the profile grid into a single column on smaller screens.

5.  **CSS Organization**: 🟡 **MEDIUM**
    - **Embedded CSS**: A large `<style>` block is embedded in the template. This should be moved to an external stylesheet.

---

## File: `templates/dashboard.html`

This file appears to be a newer, single-page application (SPA) version of the dashboard, intended to replace `dashboard_base.html` and other pages.

### Findings

1.  **XSS Vulnerabilities**: 🟡 **MEDIUM**
    - **Inconsistent Escaping**: The template includes a JavaScript `escapeHtml` function, indicating awareness of XSS. However, its use is inconsistent. For example, it is used for employee names in the master calendar view, but not for error messages from the API which are directly injected via `innerHTML` (e.g., `grid.innerHTML = \`<div ...>Error: ${data.error}</div>\`;`). This could allow for XSS if an error message can be manipulated to contain HTML.
    - **`innerHTML` with API Data**: `innerHTML` is used frequently to build dynamic content from API responses (e.g., calendar, session details). While some data is safe (like counts), other parts come directly from the database and pose a risk if not sanitized on the backend or escaped on the frontend.
    - **Claude Task**: Review all dashboard-related API endpoints to ensure they return sanitized data, especially for error messages.

2.  **Visual Identity**: 🟡 **MEDIUM**
    - **Mixed Themes**: While the "Neon Cyber" theme is present (matrix background, cyan highlights), other visual styles are creeping in. The use of a `manila-folder` class for the employee detail modal is a significant deviation from the established theme.

3.  **Accessibility**: 🟡 **MEDIUM**
    - **Non-semantic Clickable Elements**: Many `<div>` elements are made clickable with `onclick` attributes (e.g., `.server-item`, `#pending-adjustments-tile`). These are not keyboard accessible and are not identified as interactive elements by screen readers. They should be `<button>` elements.
    - **Improper Modals**: The modals (`session-edit-modal`, `employee-detail-overlay`) are missing key ARIA attributes (`role="dialog"`, `aria-modal="true"`, `aria-labelledby`). Focus is not trapped within them, meaning a keyboard user can tab to elements behind the modal.
    - **Missing `aria-hidden`**: The issue of decorative icons missing `aria-hidden="true"` persists throughout this file.

4.  **Mobile Responsiveness**: 🟢 **PASS**
    - The file includes the same mobile-aware sidebar logic as `dashboard_base.html` and uses responsive layout techniques.

5.  **CSS Organization**: 🟡 **MEDIUM**
    - **State Management via Inline Styles**: The application logic heavily relies on toggling `style.display`. A more robust and maintainable approach would be to toggle CSS classes (e.g., `is-hidden`, `is-visible`).
            - **Cosmetic Inline Styles**: Numerous cosmetic styles (colors, backgrounds, gradients) are applied inline, making the HTML bloated and difficult to maintain. These should be moved to a CSS file.
    
    ---
    
    ## File: `templates/dashboard_invite.html`
    
    ### Findings
    
    1.  **XSS Vulnerabilities**: 🟢 **PASS**
        - No significant XSS vulnerabilities were found. The `invite_url` variable in the `href` attribute is the only user-influenced data, and it is in a safe context.
    
    2.  **Visual Identity**: 🟢 **PASS**
        - The page uses a gold (`#D4AF37`) and dark blue theme. While this deviates from the primary cyan "Neon Cyber" theme, it is applied consistently and professionally for this specific landing page.
    
    3.  **Accessibility**: 🟡 **MEDIUM**
        - **Missing `aria-hidden`**: The main icon (`<div class="icon">🤖</div>`) is decorative but is not hidden from screen readers. It should have `aria-hidden="true"`.
    
    4.  **Mobile Responsiveness**: 🟢 **PASS**
        - The layout is simple, centered, and uses flexbox with wrapping, making it fully responsive.
    
    5.  **CSS Organization**: 🔵 **LOW**
        - **Embedded CSS**: All page styles are in a `<style>` block in the head. While acceptable for a small, standalone page, moving this to an external CSS file would be better for consistency and caching.

---

## File: `templates/dashboard_no_access.html`

### Findings

1.  **XSS Vulnerabilities**: 🟢 **PASS**
    - The page is static and does not render any user-provided data, so there is no risk of XSS.

2.  **Visual Identity**: 🟢 **PASS**
    - The page uses the same gold and dark blue theme as `dashboard_invite.html`, maintaining a consistent look for informational pages.

3.  **Accessibility**: 🟡 **MEDIUM**
    - **Missing `aria-hidden`**: The main icon (`<div class="icon">🛡️</div>`) is decorative but is not hidden from screen readers. It should have `aria-hidden="true"`.

4.  **Mobile Responsiveness**: 🟢 **PASS**
    - The simple, centered layout is fully responsive.

5.  **CSS Organization**: 🔵 **LOW**
    - **Embedded CSS**: All page styles are in a `<style>` block.
    - **Duplicated CSS**: The CSS in this file is nearly identical to the CSS in `dashboard_invite.html`. This code should be extracted into a shared external stylesheet to reduce duplication.

---

## File: `templates/dashboard_purchase.html`

### Findings

1.  **XSS Vulnerabilities**: 🟢 **PASS**
    - The page is static and does not render any user-provided data, so there is no risk of XSS.

2.  **Visual Identity**: 🟢 **PASS**
    - The page uses the same gold and dark blue theme as other informational pages, maintaining consistency.

3.  **Accessibility**: 🟡 **MEDIUM**
    - **Missing `aria-hidden`**: The main lock icon (`<div class="icon">🔒</div>`) and the checkmark icons (`<span class="feature-icon">✓</span>`) are decorative but are not hidden from screen readers. They should have `aria-hidden="true"`.

4.  **Mobile Responsiveness**: 🟢 **PASS**
    - The simple, centered layout is fully responsive.

5.  **CSS Organization**: 🔵 **LOW**
    - **Embedded CSS**: All page styles are in a `<style>` block.
    - **Duplicated CSS**: The CSS in this file is very similar to the CSS in `dashboard_invite.html` and `dashboard_no_access.html`. This highlights a need for a shared stylesheet for these static/informational pages to reduce code duplication.

---

## File: `templates/debug.html`

This is an internal-facing control center for testing and diagnostics. While not user-facing, it should still follow good practices.

### Findings

1.  **XSS Vulnerabilities**: 🟡 **MEDIUM**
    - **Potential DOM XSS in Logger**: The `logMessage` JavaScript function uses `innerHTML` to render messages. Some of these messages include error details fetched from API endpoints (e.g., `/debug/api-test/*`). If any of these error messages could be influenced by external data to contain malicious HTML, it would be executed on this page. Best practice is to use `textContent` even for debug pages.

2.  **Visual Identity**: 🟢 **PASS**
    - The page has a clean, consistent, and well-organized visual design appropriate for a debug tool, using the same gold/dark-blue theme as the other informational pages.

3.  **Accessibility**: 🟡 **MEDIUM**
    - **Missing `aria-hidden`**: The decorative icons in the card headers are missing `aria-hidden="true"`.
    - **Inaccessible Modal**: A modal element exists in the HTML, but it lacks the necessary ARIA attributes (`role="dialog"`, `aria-modal`, etc.) and focus trapping to be accessible.

4.  **Mobile Responsiveness**: 🟢 **PASS**
    - The page uses a responsive grid layout (`repeat(auto-fit, ...)`) that adapts well to different screen sizes.

5.  **CSS Organization**: 🟡 **MEDIUM**
    - **Embedded CSS**: A very large block of CSS is embedded directly in the HTML file. For a page this complex, the CSS should be in a separate file to improve readability and caching.

---

## File: `templates/error.html`

### Findings

1.  **XSS Vulnerabilities**: 🟢 **PASS**
    - The `message` variable is rendered, but is subject to Jinja2's auto-escaping. The risk is low as no `|safe` filter is used.

2.  **Visual Identity**: 🔴 **CRITICAL**
    - **Inconsistent Theme**: This page uses a light-on-dark color scheme that mimics the Discord UI (`#36393f`, `#5865F2`). This is a major inconsistency and breaks completely from the established "Neon Cyber" (cyan) and informational (gold) themes of the application. All UI, including error pages, should share a consistent visual identity.

3.  **Accessibility**: 🔵 **LOW**
    - **Decorative Icon in Heading**: The `⚠️` emoji inside the `<h1>` tag is not hidden from screen readers, which can be disruptive. It should be moved to a separate span with `aria-hidden="true"`.

4.  **Mobile Responsiveness**: 🟢 **PASS**
    - The simple, centered layout is fully responsive.

5.  **CSS Organization**: 🔵 **LOW**
    - **Embedded CSS**: All page styles are in a `<style>` block. This should be moved to an external stylesheet.

---

## File: `templates/kiosk.html`

This is a complex, single-page application designed for a touch-screen kiosk environment.

### Findings

1.  **XSS Vulnerabilities**: 🟢 **PASS**
    - The developers have correctly identified the need for escaping user-provided data and have implemented and used an `escapeHtml` function in the JavaScript for all dynamic data from the API, such as employee names, roles, and emails. This effectively mitigates the risk of DOM-based XSS.

2.  **Visual Identity**: 🟢 **PASS**
    - The page uses the consistent gold/dark-blue theme and correctly implements the user-configurable profile customizations (accent colors, backgrounds) mentioned in `docs/lessons-learned.md`.

3.  **Accessibility**: 🔴 **CRITICAL**
    - **Zoom Disabled**: The viewport meta tag includes `user-scalable=no`. This prevents users with low vision from zooming in to read content, failing WCAG 1.4.4 (Resize text) and creating a major accessibility barrier. This should be removed immediately.
    - **Inaccessible Modals**: The page features several modals (time adjustment, email, forgot PIN) that are not accessible. They lack ARIA roles (`dialog`, `aria-modal`) and do not trap keyboard focus, making them unusable for keyboard and screen reader users.
    - **Un-hidden Decorative Icons**: Numerous decorative icons (emojis, symbols) are not hidden from screen readers via `aria-hidden="true"`, adding clutter and confusion.

4.  **Mobile Responsiveness**: 🟡 **MEDIUM**
    - **Responsiveness is Implemented**: The layout uses media queries and responsive grids, and it clearly attempts to adapt to smaller screens.
    - **Negative Impact of `user-scalable=no`**: While the layout is responsive, the disabling of zoom functionality is a severe detriment to usability on mobile devices for many users. The layout should be robust enough to not require this.

5.  **CSS Organization**: 🔴 **CRITICAL**
    - **Massive Embedded Stylesheet**: The file contains a `<style>` block with over 1000 lines of CSS. This makes the file extremely difficult to read and maintain. This massive block of CSS **must** be moved to an external stylesheet to allow for caching and improve separation of concerns.

---

## Folder: `templates/dashboard_pages/`

Files in this directory appear to be part of an older, multi-page version of the dashboard that used `dashboard_base.html` as a template. Much of their functionality seems to be consolidated into the newer, SPA-style `dashboard.html`.

---

## File: `templates/dashboard_pages/adjustments.html`

### Findings

1.  **Code Redundancy**: 🟡 **MEDIUM**
    - **Obsolete File**: This file's entire functionality (admin and employee views for time adjustments) is duplicated in the "Time Adjustments" section of `templates/dashboard.html`. This indicates that this file is likely obsolete and part of a legacy architecture. Maintaining both versions creates unnecessary overhead and risk of inconsistencies.
    - **Claude Task**: Determine if the Flask routes still serve this page. If not, it should be deleted. If they do, they should be updated to point to the new dashboard's relevant section.

2.  **XSS Vulnerabilities**: 🟢 **PASS**
    - The page's JavaScript correctly uses a `DashboardUtils.escapeHtml` utility function before rendering data from the API, preventing DOM XSS.

3.  **Visual Identity**: 🟢 **PASS**
    - The page correctly inherits and uses the "Neon Cyber" theme from `dashboard_base.html`.

4.  **Accessibility**: 🟡 **MEDIUM**
    - **Vague Button Text**: The help button contains only a `?`. It should have an `aria-label` for screen readers.
    - **Missing `aria-hidden`**: Decorative icons (e.g., `📅`) are not hidden from screen readers.

5.  **Mobile Responsiveness**: 🟢 **PASS**
    - The page inherits its responsive structure from the base template and should work well on mobile.

6.  **CSS Organization**: 🟢 **PASS**
    - This page correctly links to external JavaScript files and does not contain embedded CSS, following good practices.

---

## File: `templates/dashboard_pages/admin_calendar.html`

### Findings

1.  **Code Redundancy**: 🟡 **MEDIUM**
    - **Obsolete File**: This file's functionality is entirely duplicated by the "Admin Calendar" section within `templates/dashboard.html`. It should be considered obsolete and removed to reduce code duplication.

2.  **XSS Vulnerabilities**: 🟢 **PASS**
    - The code correctly uses an `escapeHtml` utility function when rendering all dynamic data from the API.

3.  **Accessibility**: 🟡 **MEDIUM**
    - **Inaccessible Modals**: The modals used for viewing day details and editing entries are missing necessary ARIA attributes and focus management.
    - **Vague Button Text**: The help button (`?`) is not descriptive for screen reader users.

4.  **Mobile Responsiveness**: 🟢 **PASS**
    - The template includes media queries to adapt the calendar grid for smaller viewports.

5.  **CSS Organization**: 🟡 **MEDIUM**
    - **Embedded CSS**: A large `<style>` block is appended at the end of the file. This CSS should be moved to a shared external stylesheet.

---

## Files: `admin_roles.html`, `employee_roles.html`, `email_settings.html`, `timezone_settings.html`

### Consolidated Findings

These files are simple settings pages and share the same core audit findings.

1.  **Code Redundancy**: 🟡 **MEDIUM**
    - **Obsolete Files**: The functionality of all these pages is duplicated within the SPA `dashboard.html`. They appear to be part of a legacy multi-page architecture and should be removed.
    - **Claude Task**: Confirm these pages are no longer served and can be deleted.

2.  **XSS Vulnerabilities**: 🟢 **PASS**
    - All four files consistently and correctly use an `escapeHtml` utility function for rendering API data, mitigating XSS risks.

3.  **Visual Identity**: 🟢 **PASS**
    - All pages correctly inherit and use the "Neon Cyber" theme from `dashboard_base.html`.

4.  **Accessibility**: 🟡 **MEDIUM**
    - **Missing `aria-hidden`**: A common issue across all files is the use of decorative emoji icons in headings (e.g., `👥`, `⚙️`) that are not hidden from screen readers.

5.  **Mobile Responsiveness**: 🟢 **PASS**
    - All pages are simple and inherit a responsive layout from the base template.

6.  **CSS Organization**: 🟢 **PASS**
    - All pages correctly use external stylesheets and do not contain embedded CSS.
    
