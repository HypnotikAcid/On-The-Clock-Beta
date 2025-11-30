# Script to insert calendar HTML into dashboard.html
import sys

# Read the dashboard.html file
with open('templates/dashboard.html', 'r', encoding='utf-8') as f:
    lines = f.readlines()

# HTML to insert (after line 602, which is index 602 in the list)
calendar_html = '''
                <!-- Calendar View (Phase 1) -->
                <div class="tile" id="adjustments-calendar-container" style="margin-bottom: 30px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                        <h2><span class="tile-icon">📅</span>My Work Calendar</h2>
                        <div style="display: flex; align-items: center; gap: 10px;">
                            <button id="calendar-prev-month" class="calendar-nav-btn" title="Previous Month">
                                ← Prev
                            </button>
                            <span id="calendar-month-year" style="color: #D4AF37; font-weight: 600; min-width: 150px; text-align: center;">
                                Loading...
                            </span>
                            <button id="calendar-next-month" class="calendar-nav-btn" title="Next Month">
                                Next →
                            </button>
                        </div>
                    </div>
                    
                    <div id="calendar-grid" class="calendar-grid">
                        <div style="grid-column: 1 / -1; text-align: center; padding: 40px; color: #8B949E;">
                            Loading calendar...
                        </div>
                    </div>
                    
                    <div style="margin-top: 20px; padding: 15px; background: rgba(212, 175, 55, 0.1); border-radius: 8px; border-left: 3px solid #D4AF37;">
                        <div style="font-size: 13px; color: #C9D1D9;">
                            <strong>💡 How to use:</strong> Click on any day with work sessions to view details.
                        </div>
                    </div>
                </div>

'''

# Insert after line 602 (index 602, so insert at 603)
lines.insert(603, calendar_html)

# Write back
with open('templates/dashboard.html', 'w', encoding='utf-8') as f:
    f.writelines(lines)

print('✅ Calendar HTML inserted successfully at line 603')
