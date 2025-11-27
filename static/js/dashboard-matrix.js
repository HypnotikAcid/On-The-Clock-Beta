        const canvas = document.getElementById('matrix-canvas');
        const ctx = canvas.getContext('2d');

        const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*()_+-=[]{}|;:,.<>?';
        const fontSize = 14;
        let columns, drops;

        function initMatrix() {
            const dpr = window.devicePixelRatio || 1;
            canvas.width = window.innerWidth * dpr;
            canvas.height = window.innerHeight * dpr;
            canvas.style.width = window.innerWidth + 'px';
            canvas.style.height = window.innerHeight + 'px';
            ctx.scale(dpr, dpr);

            columns = Math.floor(window.innerWidth / fontSize);
            drops = [];
            for (let i = 0; i < columns; i++) {
                drops[i] = Math.random() * -100;
            }
        }

        function drawMatrix() {
            ctx.fillStyle = 'rgba(10, 15, 31, 0.05)';
            ctx.fillRect(0, 0, canvas.width, canvas.height);

            ctx.font = fontSize + 'px monospace';

            for (let i = 0; i < drops.length; i++) {
                const text = characters.charAt(Math.floor(Math.random() * characters.length));

                const gradient = ctx.createLinearGradient(
                    i * fontSize, drops[i] * fontSize - 20,
                    i * fontSize, drops[i] * fontSize + 20
                );
                gradient.addColorStop(0, 'rgba(212, 175, 55, 0)');
                gradient.addColorStop(0.5, 'rgba(212, 175, 55, 0.9)');
                gradient.addColorStop(1, 'rgba(212, 175, 55, 0)');

                ctx.fillStyle = gradient;

                if (i % 3 === 0) {
                    ctx.shadowColor = 'rgba(212, 175, 55, 0.8)';
                    ctx.shadowBlur = 12;
                }

                ctx.fillText(text, i * fontSize, drops[i] * fontSize);
                ctx.shadowBlur = 0;

                if (drops[i] * fontSize > window.innerHeight && Math.random() > 0.975) {
                    drops[i] = 0;
                }
                drops[i]++;
            }

            requestAnimationFrame(drawMatrix);
        }

        initMatrix();
        requestAnimationFrame(drawMatrix);

        let resizeTimeout;
        window.addEventListener('resize', () => {
            clearTimeout(resizeTimeout);
            resizeTimeout = setTimeout(() => {
                initMatrix();
            }, 250);
        });

        if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
            canvas.style.display = 'none';
        }
