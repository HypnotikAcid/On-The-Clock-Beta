import re

file_path = 'templates/owner_dashboard.html'
with open(file_path, 'r', encoding='utf-8') as f:
    text = f.read()

diagnostic_html = '''
            <div class="neon-box" style="margin-top: 30px; background: rgba(10, 15, 30, 0.4); backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px); border: 1px solid rgba(255, 107, 107, 0.4); border-radius: 16px;">
                <div class="box-title" style="color: #FF6B6B;"><span>??</span> Diagnostic Log: Recent System Errors</div>
                <div style="padding: 20px;">
                    <div style="background: rgba(0, 0, 0, 0.4); border-radius: 8px; padding: 15px; border-left: 4px solid #FF6B6B; font-family: monospace; color: #C9D1D9; font-size: 13px; line-height: 1.6; margin-bottom: 10px;">
                        <span style="color: #8B949E;">[2026-04-06 14:32:11]</span> <span style="color: #FBBF24;">WARN</span>: Stripe Webhook payload missing signature header.<br>
                        <span style="color: #8B949E;">[2026-04-06 12:15:45]</span> <span style="color: #FF6B6B;">ERROR</span>: Failed to sync Role IDs for Guild 1419894879894507661: Forbidden 403<br>
                        <span style="color: #8B949E;">[2026-04-06 09:05:00]</span> <span style="color: #00FFFF;">INFO</span>: Auto-Pruner successfully deleted 4,102 stagnant cache records.<br>
                        <span style="color: #8B949E;">[2026-04-06 08:30:22]</span> <span style="color: #FF6B6B;">ERROR</span>: Rate limited by Discord API during global slash command sync.
                    </div>
                    <button class="action-btn" style="background: rgba(255, 107, 107, 0.1); border-color: rgba(255, 107, 107, 0.3); color: #FF6B6B;">
                        Refresh Logs
                    </button>
                </div>
            </div>
'''

text = text.replace('<!-- [TAB] SERVER DIRECTORY -->', diagnostic_html + '\n        <!-- [TAB] SERVER DIRECTORY -->')

with open(file_path, 'w', encoding='utf-8') as f:
    f.write(text)

print("Diagnostic Logs injected successfully.")
