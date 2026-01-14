# Kiosk System Overhaul Plan

## Overview
Complete overhaul of the kiosk system for Time Warden, including the Demo Kiosk for public preview and the production kiosk.

## Environment Isolation

| Kiosk | Server | Data | Purpose |
|-------|--------|------|---------|
| **Demo Kiosk** | Time Warden On-The-Clock (ID: `1419894879894507661`) | Fake seeded data | Public preview & testing |
| **Production Kiosk** | IBC Server | Live real data | Actual employee use - DO NOT TOUCH until approved |

**Development Rule**: All changes go to Demo first → Test → Get approval → Then update production.

---

## 1. Main Screen Redesign
- Compact grid layout (smaller, well-spaced buttons)
- Cleaner visual design optimized for tablet use
- Large, readable fonts with high contrast

## 2. Dynamic Theming (Clock Status)
| Status | Button Appearance |
|--------|-------------------|
| **Clocked OUT** | Default neutral theme (matches server default) |
| **Clocked IN** | Custom colors/theme from employee profile |

## 3. Profile Sync
- **Main grid**: Custom theme only when clocked in
- **After-login pages**: Always show customization (theme, banner, stickers)

## 4. Discord Nitro Integration (Future)
- Investigate Discord API for avatar decorations, banners, accent colors
- Pull Nitro customizations if available

## 5. PIN Pad Fixes
- Fix number button sticking (debounce)
- Responsive layout - no scrolling to see all numbers

## 6. Forgot PIN Feature
**Flow:**
1. "Forgot PIN?" link above PIN pad
2. Sends PIN to email on file
3. If no email → Sends to admin emails from Email Settings
4. Returns to kiosk home after

## 7. Lockout System
- **Trigger**: 5 incorrect PIN attempts
- **Duration**: 5 minutes
- **Display**: Red "LOCKED OUT" text + countdown timer under their button
- **Badge**: Red ! warning on name button

## 8. Clock In/Out Page Fixes
- Fix button overlap issues
- Fix visibility state bugs (buttons not appearing correctly)

## 9. Time Adjustment Page Overhaul
| Issue | Fix |
|-------|-----|
| Submit freezes | Debug API call, add loading state |
| Only shows clock out | Show last 3-4 punches (in & out) |
| No history | Show previous adjustments with Approved/Denied/Pending status |
| No styling | Sync profile theme/banner/stickers here too |

## 10. Kiosk-Only Employees
Employees without Discord accounts who only use the kiosk.

| Feature | Discord Employee | Kiosk-Only Employee |
|---------|------------------|---------------------|
| ID Source | Discord User ID | System-generated ID (e.g., KIOSK-001) |
| Kiosk Access | ✅ | ✅ |
| Dashboard | ✅ | ❌ |
| Profile Customization | ✅ | ❌ (default theme only) |
| Time Tracking | ✅ | ✅ |
| Reports | ✅ | ✅ |
| Time Adjustments | ✅ | ✅ (kiosk only) |

**Admin Controls:**
- Add kiosk-only employee (Name, PIN, optional email)
- Deactivate employee (soft delete preserves records)
- View in same reports as Discord employees

## 11. Future: Flair System
- Stickers, badges, unlockables for profiles/kiosk buttons

---

## Research-Based Ideas to Consider

### UI/UX Enhancements
- [ ] **Photo capture at punch** - Visual verification to prevent buddy punching
- [ ] **Audio/visual feedback** - Confirmation sound + animation on successful punch
- [ ] **Auto clock-out** - Automatic end of shift if employee forgets to clock out
- [ ] **Dark mode option** - Reduce eye strain for 24/7 operations
- [ ] **High-contrast mode** - Accessibility for visually impaired users
- [ ] **Multi-language support** - Language selector at startup (flag icons)
- [ ] **Progress indicators** - Show where user is in the flow
- [ ] **Clear error states** - Explain what went wrong and how to fix

### Advanced Features
- [ ] **Geofencing** - Restrict clock-ins to specific locations
- [ ] **IP address restriction** - Limit to approved network
- [ ] **Universal admin PIN** - Manager override for clock-ins
- [ ] **Offline mode** - Store punches locally, sync when connected
- [ ] **Job/project assignment** - Track time against specific jobs or tasks
- [ ] **Break tracking** - Separate logging for breaks
- [ ] **Voice commands (NLP)** - "Clock me in" functionality

### Hardware Considerations
- [ ] **Tablet kiosk mode** - iPad Guided Access or Android kiosk mode
- [ ] **Wall mount support** - Secure mounting options
- [ ] **Stateless sessions** - Auto-logout after each punch for privacy

### Design Principles (2025 Best Practices)
- Clock in/out in 2-3 taps max
- Large, well-spaced buttons for high-traffic use
- Avoid feature overload - workers see only what they need
- Support screen readers with descriptive labels
- Avoid confusing AM/PM toggles

---

## Status
**Planning Phase** - Not yet in development.
Demo kiosk remains hidden until build begins.
