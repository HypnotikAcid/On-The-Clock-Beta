# Current Task: Phase 3 - The Universal Export & Dispatch Engine

## Objective
Build the `@app.route("/api/server/<guild_id>/reports/export", methods=["POST"])` handler in `app.py`.
Implement the `generate_timesheet_export` in `reports.py` using `csv` or `reportlab`.
Enforce Pro tier gating for PDF/Payroll formats.
Add the Dashboard Request UI in `settings.html` (or a new `reports.html` if it exists).

## Status
- Locking `app.py`, `bot.py`, `reports.py`, and the relevant frontend templates.
- Investigating the existing reports structure.
