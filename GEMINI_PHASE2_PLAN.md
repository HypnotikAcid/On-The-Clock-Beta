# Gemini: Phase 2 - Safe Improvements Plan

**Date**: 2026-01-25
**Agent**: Gemini (UI/Frontend Specialist)
**Prerequisites**: Claude must complete Phase 1 (dead code cleanup + DB column) first

---

## Your Tasks (No Backend Changes Needed!)

All tasks are **frontend-only** (templates/, CSS, JavaScript). No `app.py` or `bot.py` edits needed.

---

## Task 1: Guided Setup Wizard (3-5 days) ✅ COMPLETE

### Status
✅ **COMPLETED** - Commit `3cef46c`
- Created setup_wizard.html and 5 step templates
- Implemented JavaScript for multi-step navigation
- Integrated trigger logic into dashboard_base.html
- Mobile responsive with Neon Cyber styling

### Goal
Create a step-by-step onboarding wizard for first-time server admins.

### Implementation

#### Step 1: Create Wizard Templates
**New Files to Create**:
- `templates/setup_wizard.html` - Main wizard container
- `templates/setup_wizard_steps/` - Directory for step partials:
  - `step1_welcome.html` - Welcome + intro
  - `step2_timezone.html` - Timezone selection
  - `step3_roles.html` - Admin/employee role setup
  - `step4_settings.html` - Basic settings (clock format, notifications)
  - `step5_complete.html` - Setup complete + next steps

#### Step 2: Wizard Logic (JavaScript)
**In `setup_wizard.html`**:
```javascript
// Multi-step wizard state management
let currentStep = 1;
const totalSteps = 5;

function nextStep() {
    if (validateCurrentStep()) {
        currentStep++;
        renderStep(currentStep);
    }
}

function prevStep() {
    currentStep--;
    renderStep(currentStep);
}

function skipWizard() {
    localStorage.setItem('setup_wizard_skipped', 'true');
    window.location.href = '/dashboard/main';
}
```

#### Step 3: Backend Integration (Already Exists!)
**No new backend needed** - use existing routes:
- Timezone: `POST /api/server/<guild_id>/settings` (already exists)
- Roles: `POST /api/guild/<guild_id>/admin-roles/add` (already exists)
- Settings: `POST /api/server/<guild_id>/settings` (already exists)

#### Step 4: Trigger Logic
**In `templates/server_dashboard.html`** (or main dashboard):
```javascript
// Check if user has completed wizard
window.onload = function() {
    const wizardCompleted = localStorage.getItem('setup_wizard_completed');
    const wizardSkipped = localStorage.getItem('setup_wizard_skipped');
    const isFirstVisit = !wizardCompleted && !wizardSkipped;

    if (isFirstVisit) {
        window.location.href = '/setup-wizard?guild_id={{ guild_id }}';
    }
};
```

### Design Guidelines
- **Theme**: Neon Cyber (Cyan #00FFFF)
- **Style**: Match existing dashboard
- **Mobile**: Must work on tablets/phones
- **Accessibility**: Use `aria-label` for all inputs

---

## Task 2: UI Streamlining (1 week) 🚧 IN PROGRESS

### Status
🚧 **IN PROGRESS** - Starting now
- Previous attempt reverted due to power loss
- Restarting with Task 2A

### Goal
Declutter the main dashboard by grouping settings and improving layout.

### Implementation

#### 2A: Create "Advanced Settings" Section
**File**: `templates/server_dashboard.html`

**Before** (scattered settings):
```html
<!-- Settings all over the place -->
<div>Role Management</div>
<div>Email Recipients</div>
<div>Kiosk Settings</div>
<div>Retention Settings</div>
```

**After** (grouped):
```html
<!-- Main Dashboard (simplified) -->
<section class="dashboard-overview">
    <div class="quick-stats">...</div>
    <div class="recent-activity">...</div>
</section>

<!-- Advanced Settings (collapsible) -->
<details class="advanced-settings">
    <summary>⚙️ Advanced Settings</summary>
    <div class="settings-grid">
        <section class="role-settings">...</section>
        <section class="email-settings">...</section>
        <section class="kiosk-settings">...</section>
        <section class="retention-settings">...</section>
    </div>
</details>
```

#### 2B: Make Demo Server More Visible
**File**: `templates/index.html` or landing page

**Add prominent demo button**:
```html
<div class="hero-section">
    <h1>On the Clock - Discord Timeclock Bot</h1>
    <div class="cta-buttons">
        <a href="/dashboard" class="btn-primary">Get Started</a>
        <a href="/kiosk/1419894879894507661" class="btn-demo">
            🎮 Try Live Demo
        </a>
    </div>
</div>

<style>
.btn-demo {
    background: linear-gradient(135deg, #00FFFF, #0099FF);
    color: #0a0e1a;
    padding: 15px 30px;
    border-radius: 10px;
    font-weight: bold;
    animation: pulse 2s infinite;
}

@keyframes pulse {
    0%, 100% { box-shadow: 0 0 20px rgba(0, 255, 255, 0.5); }
    50% { box-shadow: 0 0 40px rgba(0, 255, 255, 0.8); }
}
</style>
```

#### 2C: Dashboard Layout Improvements
**File**: `templates/server_dashboard.html`

**Improvements**:
1. **Card-based layout** for sections
2. **Responsive grid** (mobile-first)
3. **Loading states** for async operations
4. **Empty states** with helpful guidance

```css
/* Responsive dashboard grid */
.dashboard-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 20px;
    padding: 20px;
}

.dashboard-card {
    background: rgba(30, 35, 45, 0.7);
    border: 1px solid rgba(0, 255, 255, 0.2);
    border-radius: 12px;
    padding: 20px;
    transition: transform 0.2s, box-shadow 0.2s;
}

.dashboard-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 20px rgba(0, 255, 255, 0.3);
}
```

---

## Task 3: Purchase Flow Streamlining (2-3 days)

### Goal
Make the upgrade process smoother - **NO BACKEND CHANGES NEEDED**.

### Implementation

#### 3A: Improve Purchase Page UI
**File**: `templates/purchase.html`

**Enhancements**:
1. **Comparison table** showing Free vs Pro features
2. **Highlighted Pro benefits** (kiosk mode, retention, etc.)
3. **Clear pricing** with annual discount option
4. **Trust signals** (secure checkout, cancel anytime)

```html
<div class="pricing-comparison">
    <div class="pricing-card free-tier">
        <h3>Free</h3>
        <p class="price">$0/month</p>
        <ul class="features">
            <li>✅ Basic clock in/out</li>
            <li>✅ 24-hour retention</li>
            <li>❌ Kiosk mode</li>
            <li>❌ Extended retention</li>
        </ul>
    </div>

    <div class="pricing-card pro-tier featured">
        <div class="badge">RECOMMENDED</div>
        <h3>Pro</h3>
        <p class="price">$15/month</p>
        <ul class="features">
            <li>✅ Everything in Free</li>
            <li>✅ 30-day retention</li>
            <li>✅ Kiosk mode</li>
            <li>✅ Priority support</li>
        </ul>
        <button class="upgrade-btn">Upgrade Now</button>
    </div>
</div>
```

#### 3B: Add Loading States
**During Stripe redirect**:
```javascript
function handleUpgrade() {
    // Show loading state
    const btn = document.querySelector('.upgrade-btn');
    btn.innerHTML = '<span class="spinner"></span> Redirecting to checkout...';
    btn.disabled = true;

    // Existing upgrade logic continues...
}
```

---

## Task 4: Mobile Responsiveness (Throughout)

### Goal
Ensure all improvements work on mobile/tablet.

### Testing Checklist
- [ ] Setup wizard: Works on phones (320px+)
- [ ] Advanced settings: Collapse properly on mobile
- [ ] Pricing cards: Stack vertically on small screens
- [ ] Demo button: Visible and accessible on mobile
- [ ] Dashboard grid: Responsive breakpoints

### CSS Pattern
```css
/* Mobile-first responsive design */
@media (max-width: 768px) {
    .dashboard-grid {
        grid-template-columns: 1fr;
    }

    .pricing-comparison {
        flex-direction: column;
    }

    .advanced-settings {
        padding: 10px;
    }
}
```

---

## What NOT to Touch ❌

1. **Backend Files**:
   - ❌ Don't edit `app.py`
   - ❌ Don't edit `bot.py`
   - ❌ Don't edit `email_utils.py`
   - ❌ Don't edit `entitlements.py`

2. **Routes**:
   - ❌ Don't create new backend routes
   - ✅ Use existing API endpoints only

3. **Database**:
   - ❌ Don't modify database schema
   - ❌ Don't add migrations

---

## File Lock Protocol

**Before Starting**:
1. Read `WORKING_FILES.md`
2. Add lock: `templates/` - Gemini - 2026-01-25 - Phase 2 improvements
3. Verify Claude has released `app.py` and `bot.py`

**When Done**:
1. Release lock in `WORKING_FILES.md`
2. Update `CURRENT_TASK.md` with what was completed

---

## Commit Strategy

Commit after each major task:

```bash
# After setup wizard
git add templates/setup_wizard*
git commit -m "Add guided setup wizard for first-time admins

- Created multi-step wizard with 5 steps
- Welcome, timezone, roles, settings, complete
- Uses localStorage for state
- Mobile responsive design

Co-Authored-By: Gemini <noreply@google.com>"

# After UI streamlining
git add templates/server_dashboard.html
git commit -m "Streamline dashboard UI with advanced settings

- Grouped settings into collapsible section
- Added card-based layout
- Improved mobile responsiveness
- Made demo server more visible

Co-Authored-By: Gemini <noreply@google.com>"

# After purchase flow
git add templates/purchase.html
git commit -m "Improve purchase flow UI

- Added feature comparison table
- Enhanced pricing card design
- Added loading states for checkout
- Improved mobile layout

Co-Authored-By: Gemini <noreply@google.com>"
```

---

## Success Criteria

### Setup Wizard
- [ ] All 5 steps render correctly
- [ ] Can navigate forward/backward
- [ ] Can skip wizard
- [ ] Wizard triggers on first visit
- [ ] Settings save via existing API
- [ ] Mobile friendly

### UI Streamlining
- [ ] Main dashboard less cluttered
- [ ] Advanced settings grouped
- [ ] Demo button prominent
- [ ] Responsive on all screen sizes

### Purchase Flow
- [ ] Feature comparison clear
- [ ] Pro benefits highlighted
- [ ] Loading states work
- [ ] Checkout process smooth

---

## Timeline Estimate

| Task | Days | Priority |
|------|------|----------|
| Setup Wizard | 3-5 | High |
| UI Streamlining | 2-3 | High |
| Purchase Flow | 1-2 | Medium |
| Mobile Polish | 1-2 | Medium |
| **Total** | **7-12 days** | |

---

## Questions?

If you need:
- **API endpoints**: Check existing routes in `app.py` (don't edit it, just reference)
- **Data structure**: Check API responses with browser DevTools
- **Styling**: Follow "Neon Cyber" theme (Cyan #00FFFF, dark backgrounds)
- **Patterns**: Reference existing templates for consistency

---

**Ready to start!** Begin with the setup wizard (highest value, clearly scoped).

**Don't wait for Claude** - you can start on templates right away since they're independent.
