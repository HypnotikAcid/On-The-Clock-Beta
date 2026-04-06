import re

file_path = 'templates/owner_dashboard.html'
with open(file_path, 'r', encoding='utf-8') as f:
    content = f.read()

content = re.sub(
    r'(body\s*\{[^}]*?)background:\s*#0A0F1F;',
    r'\1background: transparent;',
    content,
    flags=re.DOTALL
)

content = re.sub(
    r'(\.main-content\s*\{[^}]*?)background:\s*radial-gradient[^\;]+;',
    r'\1background: rgba(0, 0, 0, 0.2);\n            backdrop-filter: blur(5px);\n            -webkit-backdrop-filter: blur(5px);',
    content,
    flags=re.DOTALL
)

content = re.sub(
    r'(\.owner-sidebar\s*\{[^}]*?)background:\s*rgba\(15, 20, 35, 0\.95\);',
    r'\1background: rgba(10, 15, 31, 0.7);\n            backdrop-filter: blur(15px);\n            -webkit-backdrop-filter: blur(15px);',
    content,
    flags=re.DOTALL
)

matrix_html = '''<body data-user-id="{{ user_session.user_id if user_session else '' }}">
    <!-- Neon Cyber Matrix Background -->
    <div id="matrix-container" aria-hidden="true" style="position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; z-index: -1;">
        <canvas id="matrix-canvas"></canvas>
        <div class="clock-fade-mask" style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; background: radial-gradient(circle at center, transparent 0%, #0a0a12 80%);"></div>
    </div>'''
content = re.sub(r'<body[^>]*>', matrix_html, content, count=1)

js_html = '''    <script src="/static/js/dashboard-matrix.js"></script>\n</body>'''
content = content.replace('</body>', js_html)

feature_flag_pattern = r'<!-- FEATURE FLAGS PANEL -->.*?</div>\s*</div>\s*</div>'
content = re.sub(feature_flag_pattern, '', content, flags=re.DOTALL)

with open(file_path, 'w', encoding='utf-8') as f:
    f.write(content)
print("owner_dashboard.html successfully overhauled with Neon Cyber UI.")
