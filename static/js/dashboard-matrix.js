        const canvas = document.getElementById('matrix-canvas');
        const ctx = canvas ? canvas.getContext('2d') : null;
        const hourHand = document.getElementById('hourHand');
        const minuteHand = document.getElementById('minuteHand');
        const secondHand = document.getElementById('secondHand');

        const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*()_+-=[]{}|;:,.<>?';
        const fontSize = 14;
        let columns, drops;
        let matrixRunning = false;

        function updateClock() {
            if (!hourHand || !minuteHand || !secondHand) return;
            const now = new Date();
            const hours = now.getHours() % 12;
            const minutes = now.getMinutes();
            const seconds = now.getSeconds();

            const hourDeg = (hours * 30) + (minutes * 0.5);
            const minuteDeg = (minutes * 6) + (seconds * 0.1);
            const secondDeg = seconds * 6;

            hourHand.style.transform = `rotate(${hourDeg}deg)`;
            minuteHand.style.transform = `rotate(${minuteDeg}deg)`;
            secondHand.style.transform = `rotate(${secondDeg}deg)`;
        }

        if (hourHand && minuteHand && secondHand) {
            updateClock();
            setInterval(updateClock, 1000);
        }

        function initMatrix() {
            if (!canvas || !ctx) return;
            const dpr = window.devicePixelRatio || 1;
            canvas.width = window.innerWidth * dpr;
            canvas.height = window.innerHeight * dpr;
            canvas.style.width = window.innerWidth + 'px';
            canvas.style.height = window.innerHeight + 'px';
            ctx.setTransform(1, 0, 0, 1, 0, 0);
            ctx.scale(dpr, dpr);

            columns = Math.floor(window.innerWidth / fontSize);
            drops = [];
            for (let i = 0; i < columns; i++) {
                drops[i] = Math.random() * -100;
            }
        }

        function drawMatrix() {
            if (!canvas || !ctx) return;
            ctx.fillStyle = 'rgba(10, 15, 31, 0.05)';
            ctx.fillRect(0, 0, canvas.width, canvas.height);

            ctx.font = fontSize + 'px monospace';

            for (let i = 0; i < drops.length; i++) {
                const text = characters.charAt(Math.floor(Math.random() * characters.length));

                const gradient = ctx.createLinearGradient(
                    i * fontSize, drops[i] * fontSize - 20,
                    i * fontSize, drops[i] * fontSize + 20
                );
                gradient.addColorStop(0, 'rgba(0, 255, 255, 0)');
                gradient.addColorStop(0.5, 'rgba(0, 255, 255, 0.9)');
                gradient.addColorStop(1, 'rgba(0, 255, 255, 0)');

                ctx.fillStyle = gradient;

                if (i % 3 === 0) {
                    ctx.shadowColor = 'rgba(0, 255, 255, 0.8)';
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

        function startMatrix() {
            if (!canvas || !ctx || matrixRunning) return;
            matrixRunning = true;
            initMatrix();
            requestAnimationFrame(drawMatrix);
        }

        // Expose startMatrix globally for toggle
        window.startDashboardMatrix = startMatrix;

        // Only start matrix if not hidden and not reduced motion
        if (!window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
            const isHiddenOnLoad = localStorage.getItem('matrixHidden') === 'true';
            if (!isHiddenOnLoad) {
                startMatrix();
            }
        }

        let resizeTimeout;
        window.addEventListener('resize', () => {
            if (!matrixRunning) return;
            clearTimeout(resizeTimeout);
            resizeTimeout = setTimeout(() => {
                initMatrix();
            }, 250);
        });
