const DashboardTour = {
    currentStep: 0,
    steps: [],
    overlay: null,
    tooltip: null,
    spotlight: null,
    isActive: false,
    
    // Role-specific completion keys
    keys: {
        admin: 'otcTour_admin_completed',
        employee: 'otcTour_employee_completed'
    },

    // Lightbox for Discord Previews
    lightbox: null,

    adminSteps: [
        {
            target: '.sidebar-user',
            title: 'Admin Profile',
            content: 'As an admin, you have full control over your server settings.',
            position: 'right'
        },
        {
            target: '[data-section="admin-roles"]',
            title: 'Admin Roles',
            content: 'Configure which Discord roles have access to this dashboard.',
            position: 'right'
        },
        {
            target: '[data-section="employee-roles"]',
            title: 'Employee Roles',
            content: 'Define which roles are allowed to clock in and out.',
            position: 'right'
        },
        {
            target: '[data-section="adjustments"]',
            title: 'Time Adjustments',
            content: 'Review and approve/deny employee time modification requests.',
            position: 'right',
            preview: 'adjustments' // Link to Discord preview
        },
        {
            target: '[data-section="admin-calendar"]',
            title: 'Admin Calendar',
            content: 'A master view of all employee shifts and history.',
            position: 'right'
        }
    ],

    employeeSteps: [
        {
            target: '.sidebar-user',
            title: 'Your Profile',
            content: 'Customize your personal profile with avatars and themes.',
            position: 'right'
        },
        {
            target: '[data-section="on-the-clock"]',
            title: 'Clock In/Out',
            content: 'This is where you manage your active shift.',
            position: 'right',
            preview: 'clock'
        },
        {
            target: '[data-section="adjustments"]',
            title: 'Request Changes',
            content: 'Submit requests to fix missing or incorrect punches.',
            position: 'right'
        }
    ],
    
    previews: {
        clock: {
            title: 'Discord /clock Command',
            img: '/static/previews/discord_clock.webp',
            desc: 'Employees can also clock in/out directly from Discord using the /clock command.'
        },
        adjustments: {
            title: 'Discord Notifications',
            img: '/static/previews/discord_notif.webp',
            desc: 'When you approve a request, the employee receives a notification in Discord.'
        }
    },

    init() {
        this.createElements();
        this.bindEvents();
        
        // Check for role and auto-start
        this.checkAutoStart();
    },
    
    checkAutoStart() {
        const urlParams = new URLSearchParams(window.location.search);
        const viewAs = urlParams.get('view_as') || (window.location.pathname.includes('/server/') ? 'admin' : null);
        
        if (viewAs && !localStorage.getItem(this.keys[viewAs])) {
            setTimeout(() => this.start(viewAs), 1500);
        }
    },

    createElements() {
        // Overlay, Spotlight, Tooltip logic remains but updated with preview support
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
            <div class="tour-preview-link" style="display:none; margin: 10px 0; color: #00FFFF; cursor: pointer; font-size: 0.8rem; text-decoration: underline;">
                See in Discord
            </div>
            <div class="tour-actions">
                <button class="tour-btn tour-btn-skip">Skip</button>
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
                    <button onclick="DashboardTour.hideLightbox()" style="background:none; border:none; color:#fff; font-size:24px; cursor:pointer;">&times;</button>
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
        this.tooltip.querySelector('.tour-close').addEventListener('click', () => this.end());
        this.tooltip.querySelector('.tour-btn-skip').addEventListener('click', () => this.skip());
        this.tooltip.querySelector('.tour-btn-prev').addEventListener('click', () => this.prev());
        this.tooltip.querySelector('.tour-btn-next').addEventListener('click', () => this.next());
        this.tooltip.querySelector('.tour-preview-link').addEventListener('click', () => this.showLightbox());
        
        this.overlay.addEventListener('click', (e) => {
            if (e.target === this.overlay.querySelector('.tour-backdrop')) this.end();
        });
    },
    
    start(role = 'admin') {
        this.currentRole = role;
        this.steps = role === 'admin' ? this.adminSteps : this.employeeSteps;
        this.currentStep = 0;
        this.isActive = true;
        this.overlay.classList.add('active');
        this.showStep();
    },
    
    showStep() {
        const step = this.steps[this.currentStep];
        if (!step) return this.end();
        
        const target = document.querySelector(step.target);
        if (!target) {
            this.currentStep++;
            return this.showStep();
        }

        // Positioning logic (similar to old version)
        const rect = target.getBoundingClientRect();
        this.spotlight.style.display = 'block';
        this.spotlight.style.top = `${rect.top - 8 + window.scrollY}px`;
        this.spotlight.style.left = `${rect.left - 8}px`;
        this.spotlight.style.width = `${rect.width + 16}px`;
        this.spotlight.style.height = `${rect.height + 16}px`;
        
        this.tooltip.querySelector('.tour-title').textContent = step.title;
        this.tooltip.querySelector('.tour-content').textContent = step.content;
        
        const previewLink = this.tooltip.querySelector('.tour-preview-link');
        if (step.preview) {
            previewLink.style.display = 'block';
            this.currentPreview = step.preview;
        } else {
            previewLink.style.display = 'none';
        }

        this.tooltip.style.display = 'block';
        this.tooltip.style.top = `${rect.bottom + 20 + window.scrollY}px`;
        this.tooltip.style.left = `${rect.left}px`;
        
        target.scrollIntoView({ behavior: 'smooth', block: 'center' });
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

    next() {
        if (this.currentStep < this.steps.length - 1) {
            this.currentStep++;
            this.showStep();
        } else {
            this.complete();
        }
    },

    complete() {
        localStorage.setItem(this.keys[this.currentRole], 'true');
        this.end();
    },

    skip() {
        localStorage.setItem(this.keys[this.currentRole], 'true');
        this.end();
    },

    end() {
        this.isActive = false;
        this.overlay.classList.remove('active');
        this.spotlight.style.display = 'none';
        this.tooltip.style.display = 'none';
    },

    reset(role) {
        if (role) {
            localStorage.removeItem(this.keys[role]);
        } else {
            localStorage.removeItem(this.keys.admin);
            localStorage.removeItem(this.keys.employee);
        }
        location.reload();
    }
};

document.addEventListener('DOMContentLoaded', () => DashboardTour.init());
window.DashboardTour = DashboardTour;