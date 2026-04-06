import os
import re

# 1. Inject Matrix script into dashboard_base.html
base_path = 'templates/dashboard_base.html'
with open(base_path, 'r', encoding='utf-8') as f:
    base_text = f.read()

matrix_js = '''
<script>
    // Embedded Global Matrix Rain Animation (Neon Cyber)
    const canvas = document.getElementById('matrix-canvas');
    if(canvas) {
        const ctx = canvas.getContext('2d');
        let width = canvas.width = window.innerWidth;
        let height = canvas.height = window.innerHeight;
        const chars = '01ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$+-*/=%\"''#&_(),.;:?!\\\\|{}<>[]^~'.split('');
        const fontSize = 14;
        let columns = width / fontSize;
        let drops = [];
        for(let x = 0; x < columns; x++) drops[x] = 1;
        
        window.addEventListener('resize', () => {
            width = canvas.width = window.innerWidth;
            height = canvas.height = window.innerHeight;
            columns = width / fontSize;
            drops = [];
            for(let x = 0; x < columns; x++) drops[x] = 1;
        });

        function draw() {
            ctx.fillStyle = 'rgba(10, 15, 31, 0.08)';
            ctx.fillRect(0, 0, width, height);
            ctx.fillStyle = '#00FFFF';
            ctx.font = fontSize + 'px monospace';
            for(let i = 0; i < drops.length; i++) {
                const text = chars[Math.floor(Math.random() * chars.length)];
                ctx.fillText(text, i * fontSize, drops[i] * fontSize);
                if(drops[i] * fontSize > height && Math.random() > 0.975) drops[i] = 0;
                drops[i]++;
            }
        }
        let matrixInterval = setInterval(draw, 33);
        
        window.toggleMatrix = function() {
            const container = document.getElementById('matrix-container');
            const text = document.getElementById('matrix-toggle-text');
            const knob = document.getElementById('matrix-toggle-knob');
            if (container.style.opacity === '0') {
                container.style.opacity = '1';
                text.innerText = 'Exit The Matrix';
                knob.style.right = '3px';
                knob.style.left = 'auto';
                knob.style.background = '#00FFFF';
                knob.style.boxShadow = '0 0 8px #00FFFF';
            } else {
                container.style.opacity = '0';
                text.innerText = 'Enter The Matrix';
                knob.style.left = '3px';
                knob.style.right = 'auto';
                knob.style.background = '#8B949E';
                knob.style.boxShadow = 'none';
            }
        }
    }
</script>
'''

if 'toggleMatrix' not in base_text:
    base_text = base_text.replace('</body>', matrix_js + '\n</body>')
    with open(base_path, 'w', encoding='utf-8') as f:
        f.write(base_text)
    print("Matrix engine injected into dashboard_base.html")
else:
    print("Matrix engine already embedded in dashboard_base.html")

# 2. Upgrade all dashboard_pages inline backgrounds
pages_dir = 'templates/dashboard_pages'
glass_style = 'background: rgba(10, 15, 30, 0.4); backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px); border: 1px solid rgba(0, 255, 255, 0.2);'

count = 0
for file_name in os.listdir(pages_dir):
    if file_name.endswith('.html'):
        path = os.path.join(pages_dir, file_name)
        with open(path, 'r', encoding='utf-8') as f:
            text = f.read()

        original_text = text
        # Regex to nuke explicit backgrounds blocking glassmorphism
        text = re.sub(r'background:\s*var\(--card-bg[^;]+;', glass_style, text)
        text = re.sub(r'background:\s*#161b22\b[^;]*;', glass_style, text)
        text = re.sub(r'background:\s*#1c2128\b[^;]*;', glass_style, text)
        text = re.sub(r'background-color:\s*#161b22\b[^;]*;', glass_style, text)
        text = re.sub(r'background:\s*rgba\(22,\s*27,\s*34,\s*0\.95\)[^;]*;', glass_style, text)

        if text != original_text:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(text)
            count += 1

print(f"Purged flat backgrounds and injected glass styling in {count} subpage files.")
