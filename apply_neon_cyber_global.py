import re

# Update Landing HTML
landing_path = 'templates/landing.html'
with open(landing_path, 'r', encoding='utf-8') as f:
    landing = f.read()

# Make feature cards neon frosted
landing = re.sub(
    r'(\.feature-card\s*\{[^}]*?)background:\s*rgba\(30, 35, 45, 0\.6\);',
    r'\1background: rgba(10, 15, 30, 0.4);\n            backdrop-filter: blur(10px);\n            -webkit-backdrop-filter: blur(10px);',
    landing, flags=re.DOTALL
)
# Change gold borders to cyan
landing = landing.replace('rgba(212, 175, 55, 0.2)', 'rgba(0, 255, 255, 0.3)')
landing = landing.replace('rgba(212, 175, 55, 0.4)', 'rgba(0, 255, 255, 0.6)')
# Ensure Matrix Script is loaded before </body>
if 'dashboard-matrix.js' not in landing:
    landing = landing.replace('</body>', '    <script src="/static/js/dashboard-matrix.js"></script>\n</body>')

with open(landing_path, 'w', encoding='utf-8') as f:
    f.write(landing)

print("landing.html updated.")

# Update Dashboard CSS
css_path = 'static/css/dashboard.css'
with open(css_path, 'r', encoding='utf-8') as f:
    css = f.read()

# Make all cards highly rounded glassmorphism
css = re.sub(
    r'(background:\s*var\(--card-bg\);[^}]*)',
    r'\1\n    backdrop-filter: blur(12px);\n    -webkit-backdrop-filter: blur(12px);',
    css, flags=re.DOTALL
)

with open(css_path, 'w', encoding='utf-8') as f:
    f.write(css)
print("dashboard.css updated.")

# Update Owner Dashboard Stat Bubbles
owner_path = 'templates/owner_dashboard.html'
with open(owner_path, 'r', encoding='utf-8') as f:
    owner = f.read()

owner = owner.replace('border-radius: 12px;', 'border-radius: 16px;')
owner = owner.replace('background: rgba(15, 20, 35, 0.6);', 'background: rgba(10, 15, 30, 0.4);')
owner = owner.replace('border: 1px solid rgba(0, 255, 255, 0.2);', 'border: 1px solid rgba(0, 255, 255, 0.4);')
with open(owner_path, 'w', encoding='utf-8') as f:
    f.write(owner)
print("owner_dashboard.html updated.")

