const DashboardTour = {
    currentStep: 0,
    steps: [],
    overlay: null,
    tooltip: null,
    spotlight: null,
    isActive: false,
    
    tourSteps: [
        {
            target: '.sidebar-user',
            title: 'Your Profile',
            content: 'This is you! Your Discord avatar and username appear here. Click logout when you\'re done.',
            position: 'right',
            page: 'my-servers'
        },
        {
            target: '.server-list, .server-grid',
            title: 'Your Servers',
            content: 'These are all the Discord servers you have access to with On the Clock. Click any server to manage it.',
            position: 'top',
            page: 'my-servers'
        },
        {
            target: '#start-tour-nav',
            title: 'Need Help Again?',
            content: 'You can restart this tour anytime by clicking here. Now let\'s explore a server!',
            position: 'right',
            page: 'my-servers'
        }
    ],
    
    serverTourSteps: [
        {
            target: '[href*="/employees"]',
            findByText: 'Employees',
            title: 'Employee Management',
            content: 'View and manage all your employees. See who\'s clocked in, edit profiles, and track hours.',
            position: 'right',
            page: 'server'
        },
        {
            target: '[href*="/roles"]',
            findByText: 'Role',
            title: 'Role Assignment',
            content: 'Assign Discord roles that can clock in. Only members with these roles can use the timeclock.',
            position: 'right',
            page: 'server'
        },
        {
            target: '[href*="/timezone"]',
            findByText: 'Timezone',
            title: 'Timezone & Schedule',
            content: 'Set your business timezone and work schedule. This affects how hours are calculated.',
            position: 'right',
            page: 'server'
        },
        {
            target: '[href*="/settings"]',
            findByText: 'Settings',
            title: 'Server Settings',
            content: 'Configure email notifications, reports, and other server-specific options.',
            position: 'right',
            page: 'server'
        },
        {
            target: '[href*="/adjustments"]',
            findByText: 'Time Adjustment',
            title: 'Time Adjustments',
            content: 'Review and approve employee requests to modify their clock times. Keep accurate records!',
            position: 'right',
            page: 'server'
        },
        {
            target: '.content-area',
            title: 'Main Dashboard',
            content: 'This is your main work area. It shows different content based on which section you\'re viewing.',
            position: 'top',
            page: 'server'
        }
    ],
    
    init() {
        this.createElements();
        this.bindEvents();
        
        const tourBtn = document.getElementById('start-tour-nav');
        if (tourBtn) {
            tourBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.start();
            });
        }
        
        if (!localStorage.getItem('tourCompleted') && !localStorage.getItem('tourSkipped')) {
            const isServerPage = window.location.pathname.includes('/server/');
            if (!isServerPage) {
                setTimeout(() => this.start(), 1000);
            }
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
            <div class="tour-actions">
                <button class="tour-btn tour-btn-skip">Skip Tour</button>
                <div class="tour-nav">
                    <button class="tour-btn tour-btn-prev">Back</button>
                    <button class="tour-btn tour-btn-next">Next</button>
                </div>
            </div>
        `;
        
        document.body.appendChild(this.overlay);
        document.body.appendChild(this.spotlight);
        document.body.appendChild(this.tooltip);
    },
    
    bindEvents() {
        this.tooltip.querySelector('.tour-close').addEventListener('click', () => this.end());
        this.tooltip.querySelector('.tour-btn-skip').addEventListener('click', () => this.skip());
        this.tooltip.querySelector('.tour-btn-prev').addEventListener('click', () => this.prev());
        this.tooltip.querySelector('.tour-btn-next').addEventListener('click', () => this.next());
        this.overlay.addEventListener('click', (e) => {
            if (e.target === this.overlay.querySelector('.tour-backdrop')) {
                this.end();
            }
        });
        
        document.addEventListener('keydown', (e) => {
            if (!this.isActive) return;
            if (e.key === 'Escape') this.end();
            if (e.key === 'ArrowRight') this.next();
            if (e.key === 'ArrowLeft') this.prev();
        });
    },
    
    start() {
        const isServerPage = window.location.pathname.includes('/server/');
        this.steps = isServerPage ? this.serverTourSteps : this.tourSteps;
        this.currentStep = 0;
        this.isActive = true;
        this.overlay.classList.add('active');
        this.showStep();
    },
    
    showStep() {
        const step = this.steps[this.currentStep];
        if (!step) {
            this.end();
            return;
        }
        
        let target = null;
        
        try {
            target = document.querySelector(step.target);
        } catch (e) {
            target = null;
        }
        
        if (!target && step.findByText) {
            const navItems = document.querySelectorAll('.nav-item');
            target = Array.from(navItems).find(el => el.textContent.includes(step.findByText));
        }
        
        if (!target) {
            if (this.currentStep < this.steps.length - 1) {
                this.currentStep++;
                this.showStep();
                return;
            } else {
                this.end();
                return;
            }
        }
        
        const rect = target.getBoundingClientRect();
        const padding = 8;
        
        this.spotlight.style.display = 'block';
        this.spotlight.style.top = `${rect.top - padding + window.scrollY}px`;
        this.spotlight.style.left = `${rect.left - padding}px`;
        this.spotlight.style.width = `${rect.width + padding * 2}px`;
        this.spotlight.style.height = `${rect.height + padding * 2}px`;
        
        this.tooltip.querySelector('.tour-step-indicator').textContent = 
            `Step ${this.currentStep + 1} of ${this.steps.length}`;
        this.tooltip.querySelector('.tour-title').textContent = step.title;
        this.tooltip.querySelector('.tour-content').textContent = step.content;
        
        this.tooltip.style.display = 'block';
        const tooltipRect = this.tooltip.getBoundingClientRect();
        
        let top, left;
        switch (step.position) {
            case 'right':
                top = rect.top + (rect.height / 2) - (tooltipRect.height / 2) + window.scrollY;
                left = rect.right + padding + 16;
                break;
            case 'left':
                top = rect.top + (rect.height / 2) - (tooltipRect.height / 2) + window.scrollY;
                left = rect.left - tooltipRect.width - padding - 16;
                break;
            case 'top':
                top = rect.top - tooltipRect.height - padding - 16 + window.scrollY;
                left = rect.left + (rect.width / 2) - (tooltipRect.width / 2);
                break;
            case 'bottom':
            default:
                top = rect.bottom + padding + 16 + window.scrollY;
                left = rect.left + (rect.width / 2) - (tooltipRect.width / 2);
        }
        
        if (left < 16) left = 16;
        if (left + tooltipRect.width > window.innerWidth - 16) {
            left = window.innerWidth - tooltipRect.width - 16;
        }
        if (top < 16) top = rect.bottom + padding + 16 + window.scrollY;
        
        this.tooltip.style.top = `${top}px`;
        this.tooltip.style.left = `${left}px`;
        
        const prevBtn = this.tooltip.querySelector('.tour-btn-prev');
        const nextBtn = this.tooltip.querySelector('.tour-btn-next');
        
        prevBtn.style.display = this.currentStep === 0 ? 'none' : 'inline-block';
        nextBtn.textContent = this.currentStep === this.steps.length - 1 ? 'Finish' : 'Next';
        
        target.scrollIntoView({ behavior: 'smooth', block: 'center' });
    },
    
    next() {
        if (this.currentStep < this.steps.length - 1) {
            this.currentStep++;
            this.showStep();
        } else {
            this.complete();
        }
    },
    
    prev() {
        if (this.currentStep > 0) {
            this.currentStep--;
            this.showStep();
        }
    },
    
    skip() {
        localStorage.setItem('tourSkipped', 'true');
        this.end();
    },
    
    complete() {
        localStorage.setItem('tourCompleted', 'true');
        this.end();
        this.showCompletionMessage();
    },
    
    end() {
        this.isActive = false;
        this.overlay.classList.remove('active');
        this.spotlight.style.display = 'none';
        this.tooltip.style.display = 'none';
    },
    
    showCompletionMessage() {
        const toast = document.createElement('div');
        toast.className = 'tour-completion-toast';
        toast.innerHTML = `
            <span class="tour-completion-icon">🎉</span>
            <span>Tour complete! You're ready to start managing time.</span>
        `;
        document.body.appendChild(toast);
        
        setTimeout(() => toast.classList.add('show'), 100);
        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => toast.remove(), 300);
        }, 4000);
    },
    
    reset() {
        localStorage.removeItem('tourCompleted');
        localStorage.removeItem('tourSkipped');
    }
};

document.addEventListener('DOMContentLoaded', () => {
    DashboardTour.init();
});

window.DashboardTour = DashboardTour;
