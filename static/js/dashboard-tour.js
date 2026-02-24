const DashboardTour = {
    currentStep: 0,
    steps: [],
    overlay: null,
    tooltip: null,
    spotlight: null,
    isActive: false,
    currentRole: null,
    guildId: null,
    userId: null,

    keys: {
        admin: 'otcTour_admin_completed',
        employee: 'otcTour_employee_completed'
    },

    stateKey: 'otcTour_state',
    lightbox: null,

    adminSteps: [
        {
            page: '',
            target: '.tiles-grid',
            title: 'Welcome to Your Dashboard',
            content: 'This is your server command center. Let\'s get your workspace configured in just a few clicks.',
            position: 'bottom'
        },
        {
            page: 'admin-roles',
            target: '.tiles-grid',
            title: '1. Role Mapping',
            content: 'Crucial Step! First, define which Discord roles act as Admins and which act as Employees. The bot cannot track time without this.',
            position: 'bottom'
        },
        {
            page: 'employees',
            target: '.content-header',
            title: '2. The Employee Table',
            content: 'Once roles are set, your staff will appear here. You can filter by Active/Archived status, edit wages, or terminate members.',
            position: 'bottom'
        },
        {
            page: 'adjustments',
            target: '.tabs',
            title: '3. Time Adjustments',
            content: 'When employees forget to clock out, they request adjustments. You approve or deny them here.',
            position: 'bottom',
            preview: 'adjustments'
        },
        {
            page: 'email',
            target: '.content-header',
            title: '4. Shift Reports',
            content: 'Configure daily and weekly automatic email reports so you never have to log in to check hours.',
            position: 'bottom'
        },
        {
            page: 'reports',
            target: '.content-header',
            title: '5. Payroll & Exports',
            content: 'Generate clean CSV spreadsheets formatted perfectly for your payroll software.',
            position: 'bottom',
            dynamicFeature: 'payroll' // Used to alter text based on tier
        },
        {
            page: 'kiosk',
            target: '.content-header',
            title: '6. Tablet Kiosk Mode',
            content: 'Mount an iPad at your workplace! Employees can clock in using a 4-digit PIN instead of Discord.',
            position: 'bottom',
            dynamicFeature: 'kiosk' // Used to alter text based on tier
        }
    ],

    employeeSteps: [
        {
            page: 'clock',
            target: '.content-header',
            title: 'Clock In/Out',
            content: 'This is where you manage your shift. Clock in when you start work, and clock out when you finish.',
            position: 'bottom',
            preview: 'clock'
        },
        {
            page: 'adjustments',
            target: '.content-header',
            title: 'Request Time Changes',
            content: 'Forgot to clock in or out? Submit a request here and your admin will review it.',
            position: 'bottom'
        },
        {
            page: 'profile',
            target: '.content-header',
            title: 'Your Profile',
            content: 'View your work history, total hours, and customize your profile with themes and colors.',
            position: 'bottom'
        }
    ],

    previews: {
        clock: {
            title: 'Discord /clock Command',
            img: '/static/previews/discord_clock.png',
            desc: 'You can also clock in/out directly from Discord using the /clock command.'
        },
        adjustments: {
            title: 'Discord Notifications',
            img: '/static/previews/discord_notif.png',
            desc: 'When you approve a request, the employee receives a notification in Discord.'
        }
    },

    init() {
        this.extractGuildId();
        this.createElements();
        this.bindEvents();
        this.checkResume();
    },

    extractGuildId() {
        this.guildId = document.body.dataset.guildId || null;
        if (!this.guildId) {
            const match = window.location.pathname.match(/\/dashboard\/server\/(\d+)/);
            if (match) {
                this.guildId = match[1];
            }
        }
        this.userId = document.body.dataset.userId || null;
    },

    getPageUrl(page) {
        if (!this.guildId) return null;
        if (!page) return `/dashboard/server/${this.guildId}`;
        if (page === 'profile') {
            if (this.userId) return `/dashboard/server/${this.guildId}/profile/${this.userId}`;
            return null;
        }
        return `/dashboard/server/${this.guildId}/${page}`;
    },

    isOnCorrectPage(page) {
        const expectedPath = this.getPageUrl(page);
        if (!expectedPath) return false;
        return window.location.pathname === expectedPath ||
            window.location.pathname === expectedPath + '/';
    },

    checkResume() {
        const saved = sessionStorage.getItem(this.stateKey);
        if (saved) {
            try {
                const state = JSON.parse(saved);
                if (state.role && state.step >= 0 && state.guildId === this.guildId) {
                    setTimeout(() => {
                        this.currentRole = state.role;
                        this.steps = state.role === 'admin' ? this.adminSteps : this.employeeSteps;
                        this.currentStep = state.step;
                        this.isActive = true;
                        this.overlay.classList.add('active');
                        this.showStep();
                    }, 800);
                    return;
                }
            } catch (e) { }
        }
        this.checkAutoStart();
    },

    saveState() {
        if (this.isActive && this.currentRole && this.guildId) {
            sessionStorage.setItem(this.stateKey, JSON.stringify({
                role: this.currentRole,
                step: this.currentStep,
                guildId: this.guildId
            }));
        }
    },

    clearState() {
        sessionStorage.removeItem(this.stateKey);
    },

    checkAutoStart() {
        if (!this.guildId) return;

        const urlParams = new URLSearchParams(window.location.search);
        const viewAs = urlParams.get('view_as');
        const detectedRole = viewAs || (window.location.pathname.includes('/server/') ? 'admin' : null);

        if (detectedRole && !localStorage.getItem(this.keys[detectedRole])) {
            if (localStorage.getItem('tourCompleted')) {
                localStorage.setItem(this.keys.admin, 'true');
                localStorage.setItem(this.keys.employee, 'true');
                localStorage.removeItem('tourCompleted');
                return;
            }
            setTimeout(() => this.start(detectedRole), 1500);
        }
    },

    createElements() {
        this.overlay = document.createElement('div');
        this.overlay.className = 'tour-overlay';
        this.overlay.innerHTML = '<div class="tour-backdrop"></div>';

        this.spotlight = document.createElement('div');
        this.spotlight.className = 'tour-spotlight';

        this.tooltip = document.createElement('div');
        this.tooltip.className = 'tour-tooltip';
        this.tooltip.innerHTML = `
            <div class="tour-tooltip-header">
                <span class="tour-step-indicator"></span>
                <button class="tour-close">&times;</button>
            </div>
            <h4 class="tour-title"></h4>
            <p class="tour-content"></p>
            <div class="tour-preview-link" style="display:none; margin: 10px 0; color: #00FFFF; cursor: pointer; font-size: 0.85rem; text-decoration: underline;">
                See how it looks in Discord
            </div>
            <div class="tour-actions">
                <button class="tour-btn tour-btn-skip">Skip Tour</button>
                <div class="tour-nav">
                    <button class="tour-btn tour-btn-prev">Back</button>
                    <button class="tour-btn tour-btn-next">Next</button>
                </div>
            </div>
        `;

        this.lightbox = document.createElement('div');
        this.lightbox.className = 'tour-lightbox';
        this.lightbox.style.cssText = 'display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.9); z-index:2000; align-items:center; justify-content:center; flex-direction:column; padding:20px;';
        this.lightbox.innerHTML = `
            <div style="max-width:800px; width:100%; border: 2px solid #00FFFF; box-shadow: 0 0 20px #00FFFF; border-radius:12px; overflow:hidden; background:#0a0f1f;">
                <div style="padding:15px; border-bottom:1px solid rgba(0,255,255,0.2); display:flex; justify-content:space-between; align-items:center;">
                    <h3 class="lightbox-title" style="margin:0; color:#00FFFF;"></h3>
                    <button class="lightbox-close" style="background:none; border:none; color:#fff; font-size:24px; cursor:pointer;">&times;</button>
                </div>
                <img class="lightbox-img" style="width:100%; display:block;" src="">
                <div class="lightbox-desc" style="padding:15px; color:#8B949E; font-size:0.9rem;"></div>
            </div>
        `;

        document.body.appendChild(this.overlay);
        document.body.appendChild(this.spotlight);
        document.body.appendChild(this.tooltip);
        document.body.appendChild(this.lightbox);
    },

    bindEvents() {
        this.tooltip.querySelector('.tour-close').addEventListener('click', (e) => {
            e.stopPropagation();
            this.skip();
        });
        this.tooltip.querySelector('.tour-btn-skip').addEventListener('click', (e) => {
            e.stopPropagation();
            this.skip();
        });
        this.tooltip.querySelector('.tour-btn-prev').addEventListener('click', (e) => {
            e.stopPropagation();
            this.prev();
        });
        this.tooltip.querySelector('.tour-btn-next').addEventListener('click', (e) => {
            e.stopPropagation();
            this.next();
        });
        this.tooltip.querySelector('.tour-preview-link').addEventListener('click', (e) => {
            e.stopPropagation();
            this.showLightbox();
        });

        this.tooltip.addEventListener('click', (e) => e.stopPropagation());
        this.spotlight.addEventListener('click', (e) => e.stopPropagation());

        this.lightbox.querySelector('.lightbox-close').addEventListener('click', () => this.hideLightbox());
        this.lightbox.addEventListener('click', (e) => {
            if (e.target === this.lightbox) this.hideLightbox();
        });

        document.addEventListener('keydown', (e) => {
            if (!this.isActive) return;

            if (e.key === 'Escape') {
                if (this.lightbox.style.display === 'flex') {
                    this.hideLightbox();
                } else {
                    this.skip();
                }
                return;
            }

            if (this.lightbox.style.display === 'flex') return;

            if (e.key === 'ArrowRight' || e.key === 'Enter') {
                this.next();
            } else if (e.key === 'ArrowLeft') {
                this.prev();
            }
        });
    },

    start(role = 'admin') {
        if (!this.guildId) {
            console.warn('Tour: No guild ID found');
            return;
        }
        this.currentRole = role;
        this.steps = role === 'admin' ? this.adminSteps : this.employeeSteps;
        this.currentStep = 0;
        this.isActive = true;
        this.overlay.classList.add('active');
        this.saveState();
        this.showStep();
    },

    showStep() {
        const step = this.steps[this.currentStep];
        if (!step) return this.complete();

        if (!this.isOnCorrectPage(step.page)) {
            const targetUrl = this.getPageUrl(step.page);
            if (targetUrl) {
                this.saveState();
                window.location.href = targetUrl;
                return;
            } else {
                this.currentStep++;
                this.saveState();
                return this.showStep();
            }
        }

        this.waitForElement(step.target, (target) => {
            if (!target) {
                this.currentStep++;
                this.saveState();
                return this.showStep();
            }

            target.scrollIntoView({ behavior: 'smooth', block: 'center' });

            setTimeout(() => {
                this.positionElements(target, step);
            }, 300);
        });
    },

    waitForElement(selector, callback, attempts = 0) {
        const target = document.querySelector(selector);
        if (target) {
            callback(target);
        } else if (attempts < 20) {
            setTimeout(() => this.waitForElement(selector, callback, attempts + 1), 100);
        } else {
            callback(null);
        }
    },

    positionElements(target, step) {
        const rect = target.getBoundingClientRect();
        const viewportHeight = window.innerHeight;
        const viewportWidth = window.innerWidth;

        this.spotlight.style.display = 'block';
        this.spotlight.style.position = 'fixed';
        this.spotlight.style.top = `${rect.top - 10}px`;
        this.spotlight.style.left = `${rect.left - 10}px`;
        this.spotlight.style.width = `${rect.width + 20}px`;
        this.spotlight.style.height = `${rect.height + 20}px`;

        this.tooltip.querySelector('.tour-step-indicator').textContent = `Step ${this.currentStep + 1} of ${this.steps.length}`;
        this.tooltip.querySelector('.tour-title').textContent = step.title;

        // Dynamically append tier warnings if required
        let contentText = step.content;

        // Ensure serverSettings was injected from Jinja onto the page (usually we can check via a global var or DOM dataset)
        // Check if the current user lacks the required tier for the advertised feature
        const isFreeTier = document.body.dataset.tier === 'free';

        if (step.dynamicFeature === 'payroll' && isFreeTier) {
            contentText += " (Requires Pro Tier)";
        } else if (step.dynamicFeature === 'kiosk' && isFreeTier) {
            contentText += " (Requires Business Tier)";
        }

        this.tooltip.querySelector('.tour-content').textContent = contentText;

        const prevBtn = this.tooltip.querySelector('.tour-btn-prev');
        prevBtn.style.display = this.currentStep === 0 ? 'none' : 'inline-block';

        const nextBtn = this.tooltip.querySelector('.tour-btn-next');
        nextBtn.textContent = this.currentStep === this.steps.length - 1 ? 'Finish' : 'Next';

        const previewLink = this.tooltip.querySelector('.tour-preview-link');
        if (step.preview) {
            previewLink.style.display = 'block';
            this.currentPreview = step.preview;
        } else {
            previewLink.style.display = 'none';
        }

        this.tooltip.style.display = 'block';
        this.tooltip.style.position = 'fixed';

        const tooltipHeight = this.tooltip.offsetHeight || 200;
        const tooltipWidth = this.tooltip.offsetWidth || 320;
        const spaceBelow = viewportHeight - rect.bottom;

        if (step.position === 'top' || spaceBelow < tooltipHeight + 40) {
            this.tooltip.style.top = `${Math.max(10, rect.top - tooltipHeight - 20)}px`;
        } else {
            this.tooltip.style.top = `${rect.bottom + 20}px`;
        }

        let leftPos = rect.left + (rect.width / 2) - (tooltipWidth / 2);
        if (leftPos + tooltipWidth > viewportWidth - 20) {
            leftPos = viewportWidth - tooltipWidth - 20;
        }
        if (leftPos < 20) leftPos = 20;
        this.tooltip.style.left = `${leftPos}px`;

        this.saveState();
    },

    showLightbox() {
        const data = this.previews[this.currentPreview];
        if (!data) return;
        this.lightbox.querySelector('.lightbox-title').textContent = data.title;
        this.lightbox.querySelector('.lightbox-img').src = data.img;
        this.lightbox.querySelector('.lightbox-desc').textContent = data.desc;
        this.lightbox.style.display = 'flex';
    },

    hideLightbox() {
        this.lightbox.style.display = 'none';
    },

    prev() {
        if (this.currentStep > 0) {
            this.currentStep--;
            this.saveState();
            this.showStep();
        }
    },

    next() {
        if (this.currentStep < this.steps.length - 1) {
            this.currentStep++;
            this.saveState();
            this.showStep();
        } else {
            this.complete();
        }
    },

    complete() {
        localStorage.setItem(this.keys[this.currentRole], 'true');
        this.clearState();
        this.end();
    },

    skip() {
        localStorage.setItem(this.keys[this.currentRole], 'true');
        this.clearState();
        this.end();
    },

    end() {
        this.isActive = false;
        this.overlay.classList.remove('active');
        this.spotlight.style.display = 'none';
        this.tooltip.style.display = 'none';
    },

    reset(role) {
        this.clearState();
        if (role) {
            localStorage.removeItem(this.keys[role]);
        } else {
            localStorage.removeItem(this.keys.admin);
            localStorage.removeItem(this.keys.employee);
        }

        if (this.guildId) {
            fetch(`/api/server/${this.guildId}/settings`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ has_completed_onboarding: false })
            }).then(() => {
                window.location.href = `/dashboard/server/${this.guildId}`;
            }).catch(err => {
                console.error("Failed to reset onboarding in DB", err);
                window.location.href = `/dashboard/server/${this.guildId}`;
            });
        } else {
            location.reload();
        }
    }
};

document.addEventListener('DOMContentLoaded', () => DashboardTour.init());
window.DashboardTour = DashboardTour;
