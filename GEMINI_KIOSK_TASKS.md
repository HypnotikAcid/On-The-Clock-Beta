# Gemini: Kiosk Frontend Fixes

**Date**: 2026-01-25
**File Lock**: `templates/` already locked to you (see WORKING_FILES.md)
**Safe to proceed**: Claude is working on `app.py` and `email_utils.py` only

---

## Your Mission

Fix the kiosk frontend UI/UX issues in `templates/kiosk.html`. Claude just finished backend fixes, so the API now returns NEW data fields you can use.

---

## NEW API Data Available (Backend Complete)

The `/api/kiosk/<guild_id>/employees` endpoint NOW includes:

```javascript
{
  user_id: "123456789",
  display_name: "John Doe",
  avatar_url: "https://...",
  is_clocked_in: true,          // Clock status
  has_alerts: false,

  // NEW FIELDS (just added):
  catchphrase: "Ready to work!", // Employee catchphrase
  selected_stickers: ["fire", "star"], // Array of sticker IDs

  // Theming (already existed, but now working):
  accent_color: "cyan",          // Use for button border/glow
  profile_background: "default"  // Use for button background
}
```

---

## Frontend Issues to Fix

### Issue 1: Number Pad Problems ⚠️
**File**: `templates/kiosk.html` (JavaScript)

**Problems**:
- Buttons stick/don't register clicks
- Visual feedback is delayed
- Layout breaks on mobile/tablet
- Backspace/Clear buttons not working properly

**Fix**:
- Add debouncing to click handlers (prevent double-clicks)
- Add immediate visual feedback BEFORE API call (button press animation)
- Improve responsive CSS for number pad grid
- Ensure backspace/clear are visible and functional

---

### Issue 2: Icon State Management ⚠️
**File**: `templates/kiosk.html` (JavaScript + HTML)

**Problems**:
- Clock status icons don't update based on `is_clocked_in`
- Avatar fallback not working correctly
- Lockout badge (red "!") not showing for PIN lockouts

**Fix**:
- Update clock icon based on `is_clocked_in` from API response
- Show Discord avatar if custom avatar not set
- Add red "!" badge when employee has PIN lockout status

---

### Issue 3: Employee Button Theming (HIGH PRIORITY) 🎨
**File**: `templates/kiosk.html` (CSS)

**Problems**:
- Custom accent colors NOT showing on employee buttons
- Default theme is overriding custom `accent_color`
- Custom themes should only show when employee is clocked in

**Fix Pattern**:

```css
/* Default theme (not clocked in or customization disabled) */
.employee-btn {
    border: 2px solid rgba(212, 175, 55, 0.3);
    background: rgba(30, 35, 45, 0.7);
}

/* Custom theme (clocked in + customization enabled) */
.employee-btn.clocked-in[data-accent="cyan"] {
    border: 2px solid cyan !important;  /* Higher specificity */
    box-shadow: 0 0 20px rgba(0, 255, 255, 0.4);
}

.employee-btn.clocked-in[data-accent="magenta"] {
    border: 2px solid magenta !important;
    box-shadow: 0 0 20px rgba(255, 0, 255, 0.4);
}

/* Add patterns for: gold, lime, purple, orange, pink */
```

**When to show custom theme**:
- `allow_kiosk_customization === true` (from API)
- AND employee `is_clocked_in === true`
- Fallback to default cyan theme when clocked out

---

### Issue 4: Real-Time State Updates ⚠️
**File**: `templates/kiosk.html` (JavaScript)

**Problems**:
- After clock in/out: Button state doesn't update
- After PIN entry: Auth state not reflected
- After email save: No visual confirmation

**Fix**:
- After successful clock in/out: Update button state immediately
- After PIN verify: Update authentication state
- After email save: Show success message
- Re-fetch employee data after state-changing operations

---

## Implementation Notes

1. **CSS Specificity**: Custom colors need `!important` to override defaults
2. **Stickers**: Use `selected_stickers` array to show badges on employee buttons
3. **Catchphrase**: Show on hover or below employee name
4. **Demo Server**: Test with `/kiosk/1419894879894507661`
5. **Mobile**: Number pad must work on tablets (primary use case)

---

## Testing Checklist

- [ ] Number pad buttons respond immediately
- [ ] Custom accent colors show when clocked in
- [ ] Default theme shows when clocked out
- [ ] Catchphrase displays correctly
- [ ] Stickers appear as badges
- [ ] Clock icons update after clock in/out
- [ ] Alert badges show for employees with issues
- [ ] Layout works on mobile/tablet viewports
- [ ] Demo kiosk loads and functions properly

---

## Commit Message Format

When done, commit with:

```bash
git add templates/kiosk.html
git commit -m "Fix kiosk frontend UI issues

- Add number pad debouncing and visual feedback
- Fix employee button custom theming (CSS specificity)
- Add real-time state updates after user actions
- Display catchphrase and stickers from new API fields
- Improve mobile/tablet responsive layout

Co-Authored-By: Gemini <noreply@google.com>"
```

---

## Questions?

If you need clarification on:
- API response format: Check `/api/kiosk/<guild_id>/employees`
- Demo data: Use guild_id `1419894879894507661`
- Backend logic: Ask Claude (but don't edit `app.py`!)

**You're good to go!** No file conflicts. 🚀
