import sys

with open('app.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    # Subscription/cancel -> owner
    if '("/api/server/<guild_id>/subscription/cancel"' in line or '("/api/server/<guild_id>/subscription/resume"' in line or '("/debug/seed-demo-data"' in line:
        if '@require_api_auth' in lines[i+1]:
            lines[i+1] = '@require_server_owner\n'
        elif '@require_paid_api_access' in lines[i+1]:
            lines[i+1] = '@require_server_owner\n'
        elif not lines[i+1].startswith('@require_'):
            lines.insert(i+1, '@require_server_owner\n')

    # General sweep for admin endpoints
    patterns = [
        '/api/server/<guild_id>/settings',
        '/api/server/<guild_id>/discord-channels',
        '/api/server/<guild_id>/roles',
        '/api/server/<guild_id>/kiosk-settings',
        '/api/server/<guild_id>/employees/sync',
        '/api/server/<guild_id>/reports/export',
        '/api/server/<guild_id>/employees/send-onboarding',
        '/api/server/<guild_id>/sessions/admin-create',
        '/api/server/<guild_id>/entries/<entry_id>',
        '/api/guild/<guild_id>/admin/master-calendar',
        '/api/guild/<guild_id>/admin/edit-session',
        '/api/server/<guild_id>/test-email',
        '/api/server/<guild_id>/test-discord-routing',
        '/api/server/<guild_id>/calendar/monthly-summary',
        '/api/server/<guild_id>/calendar/day-detail',
        '/api/server/<guild_id>/employees',
        '/api/server/<guild_id>/channels',
        '/api/server/<guild_id>/reports/preview',
        '/api/server/<guild_id>/email-recipients/'
    ]
    for pat in patterns:
        # Match path safely
        if f'"{pat}"' in line or f"'{pat}'" in line:
            if '@require_api_auth' in lines[i+1] and 'Changed from require_paid_api_access' not in lines[i+1]:
                lines[i+1] = lines[i+1].replace('@require_api_auth', '@require_paid_api_access')

with open('app.py', 'w', encoding='utf-8') as f:
    f.writelines(lines)
