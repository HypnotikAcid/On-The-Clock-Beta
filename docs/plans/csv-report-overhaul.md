# CSV Report Overhaul Plan

## Overview
Reforming the CSV reporting system to provide professional, tier-gated reports for Discord servers.

## Report Formats

### DAILY REPORT (Free Tier)
- **Goal**: Basic daily snapshot.
- **Content**:
    - Employee Name (Display Name), Username, and ID.
    - Indented shift details (Clock In/Out, Duration).
    - Daily total per employee.
    - Daily grand total for the server.

### WEEKLY REPORT (Premium Tier - $8/mo)
- **Goal**: Payroll-ready weekly summary.
- **Content**:
    - Employee sections.
    - Daily totals for each day of the week.
    - Weekly grand total per employee.
    - Weekly server grand total and average.

### MONTHLY REPORT (Pro Tier - $15/mo)
- **Goal**: Enterprise-grade monthly analytics.
- **Content**:
    - Employee sections.
    - Weekly subtotals with date ranges.
    - Monthly grand total per employee.
    - Monthly server analytics (Busiest week, etc.).

## Time Adjustments Integration
- **Accepted**: Count of adjustments shown; totals already reflect these.
- **Denied**: Count of denied requests shown for tracking.
- **Pending**: **ALERT** banner with date/time details.
- **Projected Totals**: "If Pending Approved" total shown for clarity.

## New Features
- **DM Delivery**: Toggle in Email Settings (default ON). Failsafe to server owner if no admins configured.
- **Admin Quick Access**: "Generate Report" buttons on Employee Profiles and Status Cards.
- **Kiosk Self-Service**: Employee report buttons after PIN entry (tier-gated).
- **Discord Alerts**: DM alerts for pending adjustments 1 hour before scheduled reports.
- **Kiosk Inactivity**: Timer only starts after a period of no user interaction.

## Technical Tasks
1. Audit database for `time_adjustments` fields.
2. Verify tier checks in `entitlements.py`.
3. Create `report_generator.py` for shared logic.
4. Update `app.py`, `bot.py`, `email_utils.py`, and `scheduler.py` to use new formats.
5. Add settings to Email Settings UI.
6. Implement Kiosk and Profile UI buttons.

---

## Cross-Connections to Other Plans

### Kiosk Overhaul
- Quick report buttons in kiosk (after PIN entry) must use the same `report_generator.py` module.
- Kiosk-only employees need to appear in reports with system-generated IDs (e.g., `KIOSK-001`).

### Nitro Customization / Gamification
- Consider adding report-based badges: "Timesheet Titan" (30 on-time submissions), "Perfect Week" (no missed punches).

### Pricing Strategy
- Report tier gating (Daily/Weekly/Monthly) is a key differentiator. Consider including "PDF reports" as a Pro perk.

---

## Research Findings (January 2026)

### Industry Best Practices
- **Standard CSV columns**: Employee ID, Employee Name, Clock In, Clock Out, Duration, Notes/Adjustments.
- **Professional payroll exports**: Include department, job code, pay rate columns for enterprise.
- **Report delivery**: Email + Discord DM combo increases visibility (redundancy is good).

### Competitor Analysis
| Competitor | Report Features | Price Point |
|------------|----------------|-------------|
| Clockify | CSV/PDF, project breakdown | Free + $4.99/user |
| Buddy Punch | Custom reports, overtime flags | $3.49/user |
| Connecteam | Team reports, location data | $35/mo (30 users) |
| QuickBooks Time | Payroll integration, auto-export | Included with payroll |

### Potential Enhancements
- [ ] PDF report option (Pro tier) - more professional for payroll submission
- [ ] Overtime flagging - highlight shifts over 8 hours
- [ ] Department/role grouping - organize by team
- [ ] Export directly to payroll integrations (future: QuickBooks, Gusto, ADP)
- [ ] Scheduled auto-email reports (already planned)

### Risks & Mitigations
| Risk | Mitigation |
|------|------------|
| Large servers = huge reports | Pagination, employee filters |
| Time zone confusion | Always include TZ in timestamps |
| Pending adjustments change totals | "Projected if approved" column |
