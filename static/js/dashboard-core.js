// Security: HTML escape utility to prevent XSS
function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}

// View Mode Toggle Functions
function initViewModeToggle() {
    const toggle = document.getElementById('view-mode-toggle');
    if (!toggle) return;
    
    // Check access level first - if employee access, force employee mode
    const accessLevel = window.currentServerData && window.currentServerData.access_level;
    
    if (accessLevel === 'employee') {
        toggle.style.display = 'none';
        setViewMode('employee');
        return;
    }
    
    // Only show toggle for admin/owner with admin access level
    const isAdmin = window.currentServerData && 
        ['owner', 'admin'].includes(window.currentServerData.user_role_tier);
    
    if (!isAdmin) {
        toggle.style.display = 'none';
        return;
    }
    
    toggle.style.display = 'flex';
    
    // Restore saved mode
    const savedMode = localStorage.getItem('dashboard_view_mode') || 'admin';
    setViewMode(savedMode);
    
    // Add click handlers
    toggle.querySelectorAll('.view-mode-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            setViewMode(btn.dataset.mode);
        });
    });
}

function setViewMode(mode) {
    localStorage.setItem('dashboard_view_mode', mode);
    
    // Update button states
    document.querySelectorAll('.view-mode-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.mode === mode);
    });
    
    // Update body class
    if (mode === 'employee') {
        document.body.classList.add('employee-view-mode');
    } else {
        document.body.classList.remove('employee-view-mode');
    }
    
    // Store in window for other scripts
    window.currentViewMode = mode;
    
    // Dispatch event for other scripts to react
    window.dispatchEvent(new CustomEvent('viewModeChanged', { detail: { mode } }));
}

function getViewMode() {
    return localStorage.getItem('dashboard_view_mode') || 'admin';
}

function hideViewModeToggle() {
    const toggle = document.getElementById('view-mode-toggle');
    if (toggle) {
        toggle.style.display = 'none';
    }
    // Reset to admin mode when hiding
    document.body.classList.remove('employee-view-mode');
    window.currentViewMode = 'admin';
}

// Premium Feature Locked Overlays
function applyLockedOverlays() {
    // tier and bot_access_paid are inside current_settings
    const settings = window.currentServerData?.current_settings || {};
    const tier = settings.tier || 'free';
    const botAccessPaid = settings.bot_access_paid || false;
    
    // Remove any existing locked overlays first
    removeLockedOverlays();
    
    // Paid users get full access (tier not 'free', or botAccessPaid flag is true)
    if (tier !== 'free' || botAccessPaid) return;
    
    // Section IDs that require premium
    const premiumSections = [
        'section-adjustments',
        'section-email-settings',
        'section-employees',
        'section-ban-management'
    ];
    
    premiumSections.forEach(sectionId => {
        const section = document.getElementById(sectionId);
        if (section && !section.classList.contains('feature-locked')) {
            section.classList.add('feature-locked');
            
            const overlay = document.createElement('div');
            overlay.className = 'locked-overlay';
            overlay.innerHTML = `
                <h3>🔒 Dashboard Premium Required</h3>
                <p>Unlock this feature with Dashboard Premium</p>
                <p><span class="price-strike">$10</span> <span class="price-beta">$5 One-Time (Beta!)</span></p>
                <p style="color: #888; font-size: 0.9em;">Includes 7-day data retention!</p>
                <a href="/purchase/bot_access" class="upgrade-btn">Upgrade Now</a>
            `;
            section.appendChild(overlay);
        }
    });
}

function removeLockedOverlays() {
    // Remove locked class and overlays from all sections
    document.querySelectorAll('.feature-locked').forEach(section => {
        section.classList.remove('feature-locked');
        const overlay = section.querySelector('.locked-overlay');
        if (overlay) {
            overlay.remove();
        }
    });
}

// Loading overlay functions
function showLoading(message = 'Loading...') {
    const overlay = document.getElementById('loadingOverlay');
    const textEl = overlay.querySelector('.loading-text');
    if (textEl) textEl.textContent = message;
    overlay.classList.add('active');
}

function hideLoading() {
    const overlay = document.getElementById('loadingOverlay');
    overlay.classList.remove('active');
}

// Server Settings State
let currentGuildId = null;
let currentServerData = null;
let selectedAvailableAdminRole = null;
let selectedCurrentAdminRole = null;
let selectedAvailableRole = null;
let selectedCurrentRole = null;

// Navigation handler function (called by event delegation)
async function handleNavigation(sectionId) {
    if (!sectionId) return;

    const navItems = document.querySelectorAll('.nav-item');
    const contentSections = document.querySelectorAll('.content-section');

    // Show loading for sections that fetch data
    const loadingSections = ['employees', 'email-settings', 'adjustments', 'server-overview', 'admin-roles', 'employee-roles', 'ban-management', 'on-the-clock'];
    if (loadingSections.includes(sectionId)) {
        showLoading();
    }

    // Update active states
    navItems.forEach(nav => nav.classList.remove('active'));
    const activeNav = document.querySelector(`[data-section="${sectionId}"]`);
    if (activeNav) activeNav.classList.add('active');

    contentSections.forEach(section => section.classList.remove('active'));
    const targetSection = document.getElementById('section-' + sectionId);
    if (targetSection) {
        targetSection.classList.add('active');
    }

    try {
        // Load section-specific data
        if (sectionId === 'email-settings') {
            await loadEmailRecipients();
        }

        if (sectionId === 'employees') {
            await loadEmployeeStatus(currentGuildId);
        }

        if (sectionId === 'on-the-clock') {
            await loadOnTheClock(currentGuildId);
        }

        if (sectionId === 'adjustments') {
            if (typeof loadUserAdjustmentHistory === 'function') {
                await loadUserAdjustmentHistory(currentGuildId);
            }
            if (currentServerData && (currentServerData.user_role_tier === 'admin' || currentServerData.user_role_tier === 'owner')) {
                await loadPendingAdjustments(currentGuildId);
            }
            // Initialize calendar if function exists and we have user ID
            if (typeof initializeAdjustmentsCalendar === 'function' && currentServerData && currentServerData.current_user_id) {
                initializeAdjustmentsCalendar(currentGuildId, currentServerData.current_user_id);
            }
        }

        if (sectionId === 'ban-management') {
            await loadBannedUsers();
        }
    } finally {
        // Always hide loading when done
        hideLoading();
    }
}

// Set up navigation using event delegation (only once)
document.querySelector('.sidebar-nav').addEventListener('click', (e) => {
    const navItem = e.target.closest('.nav-item');
    if (navItem) {
        const sectionId = navItem.getAttribute('data-section');
        handleNavigation(sectionId);
    }
});

// Update navigation items visibility based on access level
function updateNavigationForAccessLevel(accessLevel) {
    const adminOnlyNavItems = [
        'admin-roles',
        'employee-roles', 
        'email-settings',
        'timezone',
        'ban-management',
        'employees'
    ];
    
    const employeeAllowedNavItems = [
        'server-overview',
        'on-the-clock',
        'adjustments',
        'beta-settings'
    ];
    
    // Get all nav items in server nav
    const serverNav = document.getElementById('server-nav');
    if (!serverNav) return;
    
    const navItems = serverNav.querySelectorAll('.nav-item[data-section]');
    
    navItems.forEach(item => {
        const section = item.getAttribute('data-section');
        
        if (accessLevel === 'employee') {
            if (adminOnlyNavItems.includes(section)) {
                item.style.display = 'none';
            } else if (employeeAllowedNavItems.includes(section)) {
                item.style.display = 'flex';
            }
        } else {
            item.style.display = 'flex';
        }
    });
}

// Server Selection Handler
document.querySelectorAll('.server-item').forEach(item => {
    item.addEventListener('click', async function () {
        const guildId = this.dataset.guildId;
        const guildName = this.dataset.guildName;
        const guildIcon = this.dataset.guildIcon;
        const accessLevel = this.dataset.accessLevel || 'admin';

        // Show loading overlay
        showLoading('Loading server...');

        currentGuildId = guildId;

        // Update server navigation header
        document.getElementById('serverNavName').textContent = guildName;
        const serverNavIcon = document.getElementById('serverNavIcon');
        if (guildIcon) {
            const img = document.createElement('img');
            img.src = guildIcon;
            img.alt = guildName;
            serverNavIcon.innerHTML = '';
            serverNavIcon.appendChild(img);
        } else {
            serverNavIcon.textContent = guildName.charAt(0).toUpperCase();
        }

        // Switch to server navigation
        document.getElementById('main-nav').style.display = 'none';
        document.getElementById('server-nav').style.display = 'block';

        try {
            // Load server data and pass access level
            await loadServerData(guildId, accessLevel);

            // Update navigation visibility based on access level
            updateNavigationForAccessLevel(accessLevel);

            // Load pending count (only if admin access)
            if (accessLevel === 'admin') {
                await loadPendingAdjustments(guildId);
            }

            // Initialize view mode toggle (handles access level internally)
            initViewModeToggle();

            // Navigate to server overview
            document.querySelectorAll('.nav-item').forEach(nav => nav.classList.remove('active'));
            document.querySelector('[data-section="server-overview"]').classList.add('active');
            document.querySelectorAll('.content-section').forEach(section => section.classList.remove('active'));
            document.getElementById('section-server-overview').classList.add('active');
        } finally {
            hideLoading();
        }
    });
});

// Back to Servers Handler
document.getElementById('backToServers').addEventListener('click', () => {
    currentGuildId = null;
    currentServerData = null;
    window.currentServerData = null;

    // Hide view mode toggle when returning to My Servers
    hideViewModeToggle();
    
    // Remove locked overlays when leaving server view
    removeLockedOverlays();
    
    // Reset navigation visibility (show all nav items)
    updateNavigationForAccessLevel('admin');

    // Switch back to main navigation
    document.getElementById('main-nav').style.display = 'block';
    document.getElementById('server-nav').style.display = 'none';

    // Navigate to My Servers
    document.querySelectorAll('.nav-item').forEach(nav => nav.classList.remove('active'));
    document.querySelector('[data-section="my-servers"]').classList.add('active');
    document.querySelectorAll('.content-section').forEach(section => section.classList.remove('active'));
    document.getElementById('section-my-servers').classList.add('active');
});

// Load Server Data
async function loadServerData(guildId, accessLevel = 'admin') {
    try {
        const response = await fetch(`/api/server/${guildId}/data`);
        const data = await response.json();

        if (!response.ok || !data.success) {
            alert(data.error || 'Error loading server data');
            return;
        }

        currentServerData = data;
        
        // Store access level in currentServerData and window
        currentServerData.access_level = accessLevel;
        window.currentServerData = currentServerData;

        // Only populate admin-level settings if admin access
        if (accessLevel === 'admin') {
            populateAdminRoles(data.roles, data.current_settings.admin_roles);
            populateEmployeeRoles(data.roles, data.current_settings.employee_roles);
            populateTimezoneSettings(data.current_settings.timezone);
            populateBroadcastChannelSettings(data.text_channels, data.current_settings.broadcast_channel_id);
            loadBannedUsers();
        }

        // Update UI based on user role
        if (data.user_role_tier && typeof updateSidebarForRole === 'function') {
            updateSidebarForRole(data.user_role_tier);
        }
        
        // Apply locked overlays for free tier users
        applyLockedOverlays();

    } catch (error) {
        console.error('Error loading server data:', error);
        alert('Error loading server data');
    }
}

// Populate Admin Roles
function populateAdminRoles(allRoles, currentAdminRoles) {
    const availableContainer = document.getElementById('available-admin-roles');
    const currentContainer = document.getElementById('current-admin-roles');

    availableContainer.innerHTML = '';
    currentContainer.innerHTML = '';

    // Filter out @everyone role
    const roles = allRoles.filter(role => role.name !== '@everyone');

    // Available roles (not in admin roles)
    roles.filter(role => !currentAdminRoles.includes(role.id)).forEach(role => {
        const roleItem = createRoleItem(role, 'admin');
        availableContainer.appendChild(roleItem);
    });

    // Current admin roles
    roles.filter(role => currentAdminRoles.includes(role.id)).forEach(role => {
        const roleItem = createRoleItem(role, 'admin', true);
        currentContainer.appendChild(roleItem);
    });

    if (availableContainer.children.length === 0) {
        availableContainer.innerHTML = '<div class="empty-state">No available roles</div>';
    }
    if (currentContainer.children.length === 0) {
        currentContainer.innerHTML = '<div class="empty-state">No admin roles configured</div>';
    }

    setupAdminRoleListeners();
}

// Populate Employee Roles
function populateEmployeeRoles(allRoles, currentEmployeeRoles) {
    const availableContainer = document.getElementById('available-roles');
    const currentContainer = document.getElementById('current-roles');

    availableContainer.innerHTML = '';
    currentContainer.innerHTML = '';

    // Filter out @everyone role
    const roles = allRoles.filter(role => role.name !== '@everyone');

    // Available roles (not in employee roles)
    roles.filter(role => !currentEmployeeRoles.includes(role.id)).forEach(role => {
        const roleItem = createRoleItem(role, 'employee');
        availableContainer.appendChild(roleItem);
    });

    // Current employee roles
    roles.filter(role => currentEmployeeRoles.includes(role.id)).forEach(role => {
        const roleItem = createRoleItem(role, 'employee', true);
        currentContainer.appendChild(roleItem);
    });

    if (availableContainer.children.length === 0) {
        availableContainer.innerHTML = '<div class="empty-state">No available roles</div>';
    }
    if (currentContainer.children.length === 0) {
        currentContainer.innerHTML = '<div class="empty-state">No employee roles configured</div>';
    }

    setupEmployeeRoleListeners();
}

// Populate Timezone Settings
function populateTimezoneSettings(currentTimezone) {
    document.getElementById('timezone-select').value = currentTimezone || 'America/New_York';
}

// Create Role Item
function createRoleItem(role, type, isCurrent = false) {
    const div = document.createElement('div');
    div.className = 'listbox-item';
    div.dataset.roleId = role.id;
    div.dataset.roleName = role.name;

    // Get role color or default gray
    const roleColor = role.color ? role.color.toString(16).padStart(6, '0') : '99aab5';

    // Choose emoji based on type
    const emoji = type === 'admin' ? '\u2694' : '\u263A';

    div.innerHTML = `
                <div class="listbox-item-icon" style="background-color: #${escapeHtml(roleColor)};">
                    ${emoji}
                </div>
                <div class="listbox-item-info">
                    <div class="listbox-item-name">${escapeHtml(role.name)}</div>
                    <div class="listbox-item-meta">Role ID: ${escapeHtml(role.id)}</div>
                </div>
            `;

    return div;
}

// Setup Admin Role Listeners (using event delegation)
function setupAdminRoleListeners() {
    // Available admin roles - event delegation on parent container
    const availableContainer = document.getElementById('available-admin-roles');
    availableContainer.addEventListener('click', function (e) {
        const item = e.target.closest('.listbox-item');
        if (item) {
            document.querySelectorAll('#available-admin-roles .listbox-item').forEach(i => i.classList.remove('selected'));
            item.classList.add('selected');
            selectedAvailableAdminRole = {
                id: item.dataset.roleId,
                name: item.dataset.roleName
            };
            selectedCurrentAdminRole = null;
            document.querySelectorAll('#current-admin-roles .listbox-item').forEach(i => i.classList.remove('selected'));
            document.getElementById('add-admin-role-btn').disabled = false;
            document.getElementById('remove-admin-role-btn').disabled = true;
        }
    });

    // Current admin roles - event delegation on parent container
    const currentContainer = document.getElementById('current-admin-roles');
    currentContainer.addEventListener('click', function (e) {
        const item = e.target.closest('.listbox-item');
        if (item) {
            document.querySelectorAll('#current-admin-roles .listbox-item').forEach(i => i.classList.remove('selected'));
            item.classList.add('selected');
            selectedCurrentAdminRole = {
                id: item.dataset.roleId,
                name: item.dataset.roleName
            };
            selectedAvailableAdminRole = null;
            document.querySelectorAll('#available-admin-roles .listbox-item').forEach(i => i.classList.remove('selected'));
            document.getElementById('remove-admin-role-btn').disabled = false;
            document.getElementById('add-admin-role-btn').disabled = true;
        }
    });
}

// Setup Employee Role Listeners (using event delegation)
function setupEmployeeRoleListeners() {
    // Available employee roles - event delegation on parent container
    const availableContainer = document.getElementById('available-roles');
    availableContainer.addEventListener('click', function (e) {
        const item = e.target.closest('.listbox-item');
        if (item) {
            document.querySelectorAll('#available-roles .listbox-item').forEach(i => i.classList.remove('selected'));
            item.classList.add('selected');
            selectedAvailableRole = {
                id: item.dataset.roleId,
                name: item.dataset.roleName
            };
            selectedCurrentRole = null;
            document.querySelectorAll('#current-roles .listbox-item').forEach(i => i.classList.remove('selected'));
            document.getElementById('add-role-btn').disabled = false;
            document.getElementById('remove-role-btn').disabled = true;
        }
    });

    // Current employee roles - event delegation on parent container
    const currentContainer = document.getElementById('current-roles');
    currentContainer.addEventListener('click', function (e) {
        const item = e.target.closest('.listbox-item');
        if (item) {
            document.querySelectorAll('#current-roles .listbox-item').forEach(i => i.classList.remove('selected'));
            item.classList.add('selected');
            selectedCurrentRole = {
                id: item.dataset.roleId,
                name: item.dataset.roleName
            };
            selectedAvailableRole = null;
            document.querySelectorAll('#available-roles .listbox-item').forEach(i => i.classList.remove('selected'));
            document.getElementById('remove-role-btn').disabled = false;
            document.getElementById('add-role-btn').disabled = true;
        }
    });
}

// Admin Role API Handlers
document.getElementById('add-admin-role-btn').addEventListener('click', async function () {
    if (!selectedAvailableAdminRole || !currentGuildId) return;

    try {
        const response = await fetch(`/api/server/${currentGuildId}/admin-roles/add`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ role_id: selectedAvailableAdminRole.id })
        });

        const data = await response.json();
        if (response.ok && data.success) {
            await loadServerData(currentGuildId);
        } else {
            alert(data.error || 'Error adding admin role');
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Error adding admin role');
    }
});

document.getElementById('remove-admin-role-btn').addEventListener('click', async function () {
    if (!selectedCurrentAdminRole || !currentGuildId) return;

    try {
        const response = await fetch(`/api/server/${currentGuildId}/admin-roles/remove`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ role_id: selectedCurrentAdminRole.id })
        });

        const data = await response.json();
        if (response.ok && data.success) {
            await loadServerData(currentGuildId);
        } else {
            alert(data.error || 'Error removing admin role');
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Error removing admin role');
    }
});

// Employee Role API Handlers
document.getElementById('add-role-btn').addEventListener('click', async function () {
    if (!selectedAvailableRole || !currentGuildId) return;

    try {
        const response = await fetch(`/api/server/${currentGuildId}/employee-roles/add`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ role_id: selectedAvailableRole.id })
        });

        const data = await response.json();
        if (response.ok && data.success) {
            await loadServerData(currentGuildId);
        } else {
            alert(data.error || 'Error adding employee role');
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Error adding employee role');
    }
});

document.getElementById('remove-role-btn').addEventListener('click', async function () {
    if (!selectedCurrentRole || !currentGuildId) return;

    try {
        const response = await fetch(`/api/server/${currentGuildId}/employee-roles/remove`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ role_id: selectedCurrentRole.id })
        });

        const data = await response.json();
        if (response.ok && data.success) {
            await loadServerData(currentGuildId);
        } else {
            alert(data.error || 'Error removing employee role');
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Error removing employee role');
    }
});

// Timezone Save Handler
document.getElementById('save-timezone-btn').addEventListener('click', async function () {
    if (!currentGuildId) return;

    const timezone = document.getElementById('timezone-select').value;

    try {
        const response = await fetch(`/api/server/${currentGuildId}/timezone`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ timezone: timezone })
        });

        const data = await response.json();
        if (response.ok && data.success) {
            alert(data.message || 'Timezone updated successfully!');
        } else {
            alert(data.error || 'Error updating timezone');
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Error updating timezone');
    }
});

// Populate Broadcast Channel Selector
function populateBroadcastChannelSettings(channels, currentChannelId) {
    const select = document.getElementById('broadcast-channel-select');
    if (!select) return;
    
    select.innerHTML = '<option value="">Use default (system channel)</option>';
    
    if (channels && channels.length > 0) {
        channels.forEach(channel => {
            const option = document.createElement('option');
            option.value = channel.id;
            option.textContent = '#' + escapeHtml(channel.name);
            if (currentChannelId && channel.id === currentChannelId) {
                option.selected = true;
            }
            select.appendChild(option);
        });
    }
}

// Broadcast Channel Save Handler
document.getElementById('save-broadcast-channel-btn').addEventListener('click', async function () {
    if (!currentGuildId) return;

    const channelId = document.getElementById('broadcast-channel-select').value;

    try {
        const response = await fetch(`/api/server/${currentGuildId}/broadcast-channel`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ channel_id: channelId || null })
        });

        const data = await response.json();
        if (response.ok && data.success) {
            alert(data.message || 'Broadcast channel updated successfully!');
        } else {
            alert(data.error || 'Error updating broadcast channel');
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Error updating broadcast channel');
    }
});

// Track email recipient count for fail-safe validation
let emailRecipientCount = 0;

// Update email-dependent controls based on recipient availability
function updateEmailControlsState(count) {
    emailRecipientCount = count;
    const hasRecipients = count > 0;
    
    const toggleAutoSendClockout = document.getElementById('toggle-auto-send-clockout');
    const toggleAutoEmailDelete = document.getElementById('toggle-auto-email-delete');
    const workDayEndTime = document.getElementById('work-day-end-time');
    const saveWorkdayBtn = document.getElementById('save-workday-time-btn');
    
    // Update toggle disabled states
    if (toggleAutoSendClockout) {
        toggleAutoSendClockout.disabled = !hasRecipients;
        toggleAutoSendClockout.parentElement.style.opacity = hasRecipients ? '1' : '0.5';
    }
    if (toggleAutoEmailDelete) {
        toggleAutoEmailDelete.disabled = !hasRecipients;
        toggleAutoEmailDelete.parentElement.style.opacity = hasRecipients ? '1' : '0.5';
    }
    if (workDayEndTime) {
        workDayEndTime.disabled = !hasRecipients;
        workDayEndTime.style.opacity = hasRecipients ? '1' : '0.5';
    }
    if (saveWorkdayBtn) {
        saveWorkdayBtn.disabled = !hasRecipients;
        saveWorkdayBtn.style.opacity = hasRecipients ? '1' : '0.5';
    }
    
    // Show/hide inline guidance
    const emailGuidance = document.getElementById('email-settings-guidance');
    if (emailGuidance) {
        emailGuidance.style.display = hasRecipients ? 'none' : 'block';
    }
}

// Email Management Functions
async function loadEmailRecipients() {
    if (!currentGuildId) return;

    try {
        const response = await fetch(`/api/server/${currentGuildId}/email-recipients`);
        const data = await response.json();

        if (response.ok && data.success) {
            renderEmailList(data.emails);
            updateEmailControlsState(data.emails ? data.emails.length : 0);
        } else {
            console.error('Error loading emails:', data.error);
            updateEmailControlsState(0);
        }
    } catch (error) {
        console.error('Error:', error);
        updateEmailControlsState(0);
    }

    // Also load current email settings (toggles and work day time)
    if (currentServerData && currentServerData.current_settings) {
        const settings = currentServerData.current_settings;

        // Set toggle states
        const toggleAutoSendClockout = document.getElementById('toggle-auto-send-clockout');
        const toggleAutoEmailDelete = document.getElementById('toggle-auto-email-delete');
        if (toggleAutoSendClockout) toggleAutoSendClockout.checked = settings.auto_send_on_clockout || false;
        if (toggleAutoEmailDelete) toggleAutoEmailDelete.checked = settings.auto_email_before_delete || false;

        // Set work day end time
        const workDayEndTime = document.getElementById('work-day-end-time');
        if (workDayEndTime && settings.work_day_end_time) {
            workDayEndTime.value = settings.work_day_end_time;
        }

        // Set mobile restriction toggle
        const restrictMobileToggle = document.getElementById('restrict-mobile-toggle');
        if (restrictMobileToggle) {
            restrictMobileToggle.checked = settings.restrict_mobile_clockin || false;
        }
        
        // Initialize email controls state from preloaded count if available
        if (typeof settings.email_recipient_count === 'number') {
            updateEmailControlsState(settings.email_recipient_count);
        }
    }
}

function renderEmailList(emails) {
    const emailList = document.getElementById('email-list');

    if (!emails || emails.length === 0) {
        emailList.innerHTML = '<div class="empty-state" style="text-align: center; padding: 40px 20px; color: #8B949E; font-size: 13px;">No email addresses configured</div>';
        return;
    }

    emailList.innerHTML = emails.map(email => `
                <div class="email-item" data-email-id="${escapeHtml(email.id)}" style="display: flex; align-items: center; justify-content: space-between; padding: 10px 12px; background: rgba(30, 35, 45, 0.6); border: 1px solid rgba(212, 175, 55, 0.1); border-radius: 6px; margin-bottom: 8px; transition: all 0.2s ease;">
                    <span class="email-address" style="color: #C9D1D9; font-size: 14px; flex: 1;">\u2709 ${escapeHtml(email.email)}</span>
                    <button class="email-remove-btn" data-email-id="${escapeHtml(email.id)}" style="background: linear-gradient(135deg, #DC2626, #B91C1C); color: white; border: none; padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; transition: all 0.2s ease;">Remove</button>
                </div>
            `).join('');

    // Attach event listeners safely using data attributes
    emailList.querySelectorAll('.email-remove-btn').forEach(btn => {
        btn.addEventListener('click', function () {
            const emailId = parseInt(this.dataset.emailId, 10);
            if (!isNaN(emailId)) {
                removeEmail(emailId);
            }
        });
    });
}

async function addEmail() {
    if (!currentGuildId) return;

    const emailInput = document.getElementById('email-input');
    const email = emailInput.value.trim();

    if (!email) {
        alert('Please enter an email address');
        return;
    }

    try {
        const response = await fetch(`/api/server/${currentGuildId}/email-recipients/add`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: email })
        });

        const data = await response.json();
        if (response.ok && data.success) {
            emailInput.value = '';
            await loadEmailRecipients();
        } else {
            alert(data.error || 'Error adding email');
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Error adding email');
    }
}

async function removeEmail(emailId) {
    if (!currentGuildId) return;
    if (!confirm('Are you sure you want to remove this email recipient?')) {
        return;
    }

    try {
        const response = await fetch(`/api/server/${currentGuildId}/email-recipients/remove`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: emailId })
        });

        const data = await response.json();
        if (response.ok && data.success) {
            await loadEmailRecipients();
            
            // Handle auto-disable when last recipient is removed
            if (data.email_settings_disabled) {
                // Reset toggle states in UI
                const toggleAutoSendClockout = document.getElementById('toggle-auto-send-clockout');
                const toggleAutoEmailDelete = document.getElementById('toggle-auto-email-delete');
                const workDayEndTime = document.getElementById('work-day-end-time');
                
                if (toggleAutoSendClockout) toggleAutoSendClockout.checked = false;
                if (toggleAutoEmailDelete) toggleAutoEmailDelete.checked = false;
                if (workDayEndTime) workDayEndTime.value = '';
                
                alert('Email automation settings have been disabled because there are no email recipients configured.');
            }
            
            // Update controls state
            updateEmailControlsState(data.remaining_count || 0);
        } else {
            alert(data.error || 'Error removing email');
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Error removing email');
    }
}

// Email Settings Toggle Handling
async function updateEmailSettings() {
    if (!currentGuildId) return;

    const toggleAutoSendClockout = document.getElementById('toggle-auto-send-clockout');
    const toggleAutoEmailDelete = document.getElementById('toggle-auto-email-delete');
    
    // Store previous states for rollback
    const prevAutoSend = toggleAutoSendClockout.checked;
    const prevAutoDelete = toggleAutoEmailDelete.checked;

    try {
        const response = await fetch(`/api/server/${currentGuildId}/email-settings`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                auto_send_on_clockout: toggleAutoSendClockout.checked,
                auto_email_before_delete: toggleAutoEmailDelete.checked
            })
        });

        const data = await response.json();
        if (response.ok && data.success) {
            console.log('Email settings updated:', data);
        } else {
            console.error('Error updating email settings:', data.error);
            
            // Revert toggles on fail-safe error
            if (data.requires_recipients) {
                toggleAutoSendClockout.checked = false;
                toggleAutoEmailDelete.checked = false;
            }
            
            alert(data.error || 'Error updating email settings');
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Error updating email settings');
    }
}

// Work Day End Time Save Handler
async function saveWorkDayTime() {
    if (!currentGuildId) return;

    const workDayEndTimeInput = document.getElementById('work-day-end-time');
    const workDayEndTime = workDayEndTimeInput.value;

    try {
        const response = await fetch(`/api/server/${currentGuildId}/work-day-time`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ work_day_end_time: workDayEndTime })
        });

        const data = await response.json();
        if (response.ok && data.success) {
            alert(data.message || 'Work day end time updated successfully!');
        } else {
            // Clear input on fail-safe error
            if (data.requires_recipients) {
                workDayEndTimeInput.value = '';
            }
            alert(data.error || 'Error updating work day end time');
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Error updating work day end time');
    }
}

// Add Email Button Handler
document.getElementById('add-email-btn').addEventListener('click', addEmail);

// Allow Enter key to add email
document.getElementById('email-input').addEventListener('keypress', function (e) {
    if (e.key === 'Enter') {
        addEmail();
    }
});

// Email toggles event listeners  
document.getElementById('toggle-auto-send-clockout').addEventListener('change', updateEmailSettings);
document.getElementById('toggle-auto-email-delete').addEventListener('change', updateEmailSettings);

// Work day end time save button
document.getElementById('save-workday-time-btn').addEventListener('click', saveWorkDayTime);

// Mobile restriction toggle handling
async function updateMobileRestriction() {
    if (!currentGuildId) return;

    const restrictMobileToggle = document.getElementById('restrict-mobile-toggle');

    try {
        const response = await fetch(`/api/server/${currentGuildId}/mobile-restriction`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                restrict_mobile: restrictMobileToggle.checked
            })
        });

        const data = await response.json();
        if (response.ok && data.success) {
            console.log('Mobile restriction updated:', data);
        } else {
            console.error('Error updating mobile restriction:', data.error);
            alert('Error updating mobile restriction: ' + (data.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Error updating mobile restriction');
    }
}

// Mobile restriction toggle event listener
document.getElementById('restrict-mobile-toggle').addEventListener('change', updateMobileRestriction);

// Load banned users function
async function loadBannedUsers() {
    if (!currentGuildId) return;

    const bannedUsersList = document.getElementById('banned-users-list');
    bannedUsersList.innerHTML = `
                <div style="text-align: center; color: #8B949E; padding: 20px;">
                    <div style="font-size: 24px; margin-bottom: 8px;">\u21BB</div>
                    <div>Loading banned users...</div>
                </div>
            `;

    try {
        const response = await fetch(`/api/server/${currentGuildId}/bans`);
        const data = await response.json();

        if (response.ok && data.success) {
            const bans = data.bans;

            if (bans.length === 0) {
                bannedUsersList.innerHTML = `
                            <div style="text-align: center; color: #10B981; padding: 20px;">
                                <div style="font-size: 24px; margin-bottom: 8px;">✅</div>
                                <div>No banned users</div>
                            </div>
                        `;
            } else {
                let tableHTML = `
                            <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
                                <thead>
                                    <tr style="border-bottom: 1px solid rgba(75, 85, 99, 0.4);">
                                        <th style="text-align: left; padding: 10px; color: #9CA3AF;">User ID</th>
                                        <th style="text-align: left; padding: 10px; color: #9CA3AF;">Banned At</th>
                                        <th style="text-align: left; padding: 10px; color: #9CA3AF;">Expires At</th>
                                        <th style="text-align: center; padding: 10px; color: #9CA3AF;">Warnings</th>
                                        <th style="text-align: left; padding: 10px; color: #9CA3AF;">Reason</th>
                                    </tr>
                                </thead>
                                <tbody>
                        `;

                bans.forEach(ban => {
                    const bannedAt = new Date(ban.banned_at).toLocaleDateString();
                    const expiresAt = ban.ban_expires_at ? new Date(ban.ban_expires_at).toLocaleDateString() : 'Never';
                    const isExpired = ban.ban_expires_at && new Date(ban.ban_expires_at) < new Date();

                    tableHTML += `
                                <tr style="border-bottom: 1px solid rgba(75, 85, 99, 0.2);">
                                    <td style="padding: 10px; color: #C9D1D9; font-family: monospace;">${escapeHtml(ban.user_id)}</td>
                                    <td style="padding: 10px; color: #8B949E;">${escapeHtml(bannedAt)}</td>
                                    <td style="padding: 10px; color: ${isExpired ? '#10B981' : '#C9D1D9'};">
                                        ${escapeHtml(expiresAt)}${isExpired ? ' (Expired)' : ''}
                                    </td>
                                    <td style="padding: 10px; text-align: center; color: #F59E0B; font-weight: 600;">${escapeHtml(ban.warning_count)}</td>
                                    <td style="padding: 10px; color: #8B949E;">${escapeHtml(ban.reason)}</td>
                                </tr>
                            `;
                });

                tableHTML += `
                                </tbody>
                            </table>
                        `;

                bannedUsersList.innerHTML = tableHTML;
            }
        } else {
            bannedUsersList.innerHTML = `
                        <div style="text-align: center; color: #EF4444; padding: 20px;">
                            <div style="font-size: 24px; margin-bottom: 8px;">\u274C</div>
                            <div>Error loading banned users</div>
                        </div>
                    `;
        }
    } catch (error) {
        console.error('Error loading banned users:', error);
        // Safe DOM manipulation to prevent XSS
        bannedUsersList.innerHTML = '';
        const outerDiv = document.createElement('div');
        outerDiv.style.cssText = 'text-align: center; color: #EF4444; padding: 20px;';

        const iconDiv = document.createElement('div');
        iconDiv.style.cssText = 'font-size: 24px; margin-bottom: 8px;';
        iconDiv.textContent = '\u274C';

        const errorDiv = document.createElement('div');
        errorDiv.textContent = 'Error: ' + error.message;

        outerDiv.appendChild(iconDiv);
        outerDiv.appendChild(errorDiv);
        bannedUsersList.appendChild(outerDiv);
    }
}

// Mobile menu functionality
const mobileHamburger = document.getElementById('mobileHamburger');
const sidebar = document.getElementById('sidebar');
const mobileOverlay = document.getElementById('mobileOverlay');

function openMobileSidebar() {
    sidebar.classList.remove('mobile-hidden');
    mobileOverlay.classList.add('active');
}

function closeMobileSidebar() {
    sidebar.classList.add('mobile-hidden');
    mobileOverlay.classList.remove('active');
}

mobileHamburger.addEventListener('click', openMobileSidebar);
mobileOverlay.addEventListener('click', closeMobileSidebar);

// Handle window resize
window.addEventListener('resize', () => {
    if (window.innerWidth > 768) {
        sidebar.classList.remove('mobile-hidden');
        mobileOverlay.classList.remove('active');
    } else {
        sidebar.classList.add('mobile-hidden');
    }
});

// Initialize mobile state
if (window.innerWidth <= 768) {
    sidebar.classList.add('mobile-hidden');
}
// On the Clock Functionality (Employee View)
async function loadOnTheClock(guildId) {
    if (!guildId) return;
    
    const container = document.getElementById('coworkers-on-clock-container');
    if (!container) return;
    
    container.innerHTML = '<div class="empty-state">Loading...</div>';
    
    try {
        const response = await fetch(`/api/guild/${guildId}/on-the-clock`);
        const data = await response.json();
        
        if (data.success) {
            const clockedIn = data.coworkers.filter(c => c.is_clocked_in);
            
            if (clockedIn.length === 0) {
                container.innerHTML = '<div class="empty-state">No co-workers currently on the clock</div>';
                return;
            }
            
            container.innerHTML = '';
            clockedIn.forEach(emp => {
                const card = document.createElement('div');
                card.className = 'coworker-card';
                
                const avatar = document.createElement('div');
                avatar.className = 'coworker-avatar';
                avatar.textContent = (emp.display_name || '?').charAt(0).toUpperCase();
                
                const name = document.createElement('div');
                name.className = 'coworker-name';
                name.textContent = emp.display_name || 'Unknown';
                
                const status = document.createElement('div');
                status.className = 'coworker-status';
                status.textContent = '● On the Clock';
                
                card.appendChild(avatar);
                card.appendChild(name);
                card.appendChild(status);
                container.appendChild(card);
            });
        } else {
            container.innerHTML = `<div class="empty-state" style="color: #EF4444;">Error: ${escapeHtml(data.error)}</div>`;
        }
    } catch (error) {
        console.error('Error loading on-the-clock:', error);
        container.innerHTML = '<div class="empty-state" style="color: #EF4444;">Failed to load data</div>';
    }
}

// Employee Status Functionality
async function loadEmployeeStatus(guildId) {
    if (!guildId) return;

    const container = document.getElementById('employee-cards-container');
    container.innerHTML = '<div class="empty-state">Loading employees...</div>';

    try {
        // Get timezone preference
        const timezoneSelect = document.getElementById('dashboard-timezone');
        const timezone = timezoneSelect.value;

        const response = await fetch(`/api/guild/${guildId}/employees/active?timezone=${timezone}`);
        const data = await response.json();

        if (data.success) {
            if (data.employees.length === 0) {
                container.innerHTML = '<div class="empty-state">No employees with time records found.</div>';
                return;
            }

            // Clear container and build employee cards using safe DOM methods
            container.innerHTML = '';

            data.employees.forEach(emp => {
                // Calculate duration only if clocked in
                let durationStr = '';
                if (emp.is_clocked_in && emp.clock_in) {
                    const clockInTime = new Date(emp.clock_in);
                    const now = new Date();
                    const durationMs = now - clockInTime;
                    const hours = Math.floor(durationMs / 3600000);
                    const minutes = Math.floor((durationMs % 3600000) / 60000);
                    durationStr = `${hours}h ${minutes}m`;
                }

                // Format hours stats
                const formatHours = (seconds) => {
                    const h = Math.floor(seconds / 3600);
                    const m = Math.floor((seconds % 3600) / 60);
                    return `${h}h ${m}m`;
                };

                // Create employee card using safe DOM methods
                const card = document.createElement('div');
                card.className = 'employee-card clickable';
                card.dataset.userId = emp.user_id;
                card.dataset.guildId = guildId;
                card.onclick = function () {
                    openEmployeeDetailView(emp.user_id, guildId);
                };

                const cardHeader = document.createElement('div');
                cardHeader.className = 'employee-card-header';

                const avatar = document.createElement('div');
                avatar.className = 'employee-avatar';
                avatar.textContent = emp.display_name ? emp.display_name.charAt(0).toUpperCase() : '?';

                const info = document.createElement('div');
                info.className = 'employee-info';

                const nameH3 = document.createElement('h3');
                nameH3.textContent = emp.display_name || 'Unknown User';

                const status = document.createElement('div');
                status.className = 'employee-status';
                const statusDot = document.createElement('span');
                
                if (emp.is_clocked_in) {
                    statusDot.style.cssText = 'width: 8px; height: 8px; background: #57F287; border-radius: 50%; display: inline-block;';
                    status.appendChild(statusDot);
                    status.appendChild(document.createTextNode(` Clocked in for ${durationStr}`));
                } else {
                    statusDot.style.cssText = 'width: 8px; height: 8px; background: #8B949E; border-radius: 50%; display: inline-block;';
                    status.appendChild(statusDot);
                    const lastSeen = emp.last_clock_out ? new Date(emp.last_clock_out).toLocaleDateString() : 'Unknown';
                    status.appendChild(document.createTextNode(` Last seen: ${lastSeen}`));
                }

                info.appendChild(nameH3);
                info.appendChild(status);
                cardHeader.appendChild(avatar);
                cardHeader.appendChild(info);

                const stats = document.createElement('div');
                stats.className = 'employee-stats';

                // Create stat rows
                const createStatRow = (label, value) => {
                    const row = document.createElement('div');
                    row.className = 'stat-row';

                    const labelSpan = document.createElement('span');
                    labelSpan.className = 'stat-label';
                    labelSpan.textContent = label;

                    const valueSpan = document.createElement('span');
                    valueSpan.className = 'stat-value';
                    valueSpan.textContent = value;

                    row.appendChild(labelSpan);
                    row.appendChild(valueSpan);
                    return row;
                };

                stats.appendChild(createStatRow('Today', formatHours(emp.hours_today)));
                stats.appendChild(createStatRow('This Week', formatHours(emp.hours_week)));
                stats.appendChild(createStatRow('This Month', formatHours(emp.hours_month)));

                card.appendChild(cardHeader);
                card.appendChild(stats);

                // Add clock-out button for admin view mode (only if employee IS clocked in)
                const clockOutBtn = document.createElement('button');
                clockOutBtn.className = 'admin-clock-out-btn';
                clockOutBtn.textContent = 'Clock Out';
                clockOutBtn.style.cssText = 'display: none; width: 100%; margin-top: 12px; padding: 8px 12px; background: rgba(239, 68, 68, 0.2); border: 1px solid rgba(239, 68, 68, 0.4); color: #EF4444; border-radius: 6px; cursor: pointer; font-size: 13px; font-weight: 500; transition: all 0.2s ease;';
                clockOutBtn.dataset.userId = emp.user_id;
                clockOutBtn.dataset.displayName = emp.display_name || 'Unknown User';
                clockOutBtn.dataset.isClockedIn = emp.is_clocked_in ? 'true' : 'false';

                // Show button only in admin mode AND if employee is clocked in
                if (emp.is_clocked_in && window.currentViewMode === 'admin') {
                    clockOutBtn.style.display = 'block';
                }

                clockOutBtn.onmouseover = function() {
                    this.style.background = 'rgba(239, 68, 68, 0.35)';
                    this.style.borderColor = 'rgba(239, 68, 68, 0.6)';
                };
                clockOutBtn.onmouseout = function() {
                    this.style.background = 'rgba(239, 68, 68, 0.2)';
                    this.style.borderColor = 'rgba(239, 68, 68, 0.4)';
                };

                clockOutBtn.onclick = async function(event) {
                    event.stopPropagation();
                    const userId = this.dataset.userId;
                    const displayName = this.dataset.displayName;
                    
                    if (!confirm(`Are you sure you want to clock out ${displayName}?`)) {
                        return;
                    }
                    
                    try {
                        const response = await fetch(`/api/guild/${guildId}/employees/${userId}/clock-out`, {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json'
                            }
                        });
                        
                        const data = await response.json();
                        
                        if (data.success) {
                            // Add small delay to ensure backend has processed the change
                            setTimeout(() => {
                                loadEmployeeStatus(guildId);
                            }, 300);
                        } else {
                            alert('Error: ' + (data.error || 'Failed to clock out employee'));
                        }
                    } catch (error) {
                        console.error('Clock out error:', error);
                        alert('Failed to clock out employee. Please try again.');
                    }
                };

                card.appendChild(clockOutBtn);
                container.appendChild(card);
            });
        } else {
            container.innerHTML = `<div class="empty-state" style="color: #EF4444;">Error: ${escapeHtml(data.error)}</div>`;
        }
    } catch (error) {
        console.error('Error loading employees:', error);
        container.innerHTML = '<div class="empty-state" style="color: #EF4444;">Failed to load employee data.</div>';
    }
}

// Listen for view mode changes to update clock-out button visibility
window.addEventListener('viewModeChanged', function(event) {
    const clockOutButtons = document.querySelectorAll('.admin-clock-out-btn');
    const isAdmin = event.detail.mode === 'admin';
    
    clockOutButtons.forEach(btn => {
        // Only show button if admin mode AND employee is clocked in
        const isClockedIn = btn.dataset.isClockedIn === 'true';
        btn.style.display = (isAdmin && isClockedIn) ? 'block' : 'none';
    });
});

// Timezone reminder badge logic
function updateTimezoneReminder() {
    const tz = localStorage.getItem('dashboard_timezone');
    const badge = document.getElementById('tz-reminder-badge');
    if (!badge) return;
    if (tz && tz.trim()) {
        badge.style.display = 'none';
    } else {
        badge.style.display = 'inline-block';
    }
}

// Timezone selector change handler
document.getElementById('dashboard-timezone').addEventListener('change', () => {
    if (currentGuildId) {
        loadEmployeeStatus(currentGuildId);
        // Save preference to localStorage
        localStorage.setItem('dashboard_timezone', document.getElementById('dashboard-timezone').value);
        // Hide sidebar reminder badge
        updateTimezoneReminder();
    }
});

// Load saved timezone on startup
const savedTimezone = localStorage.getItem('dashboard_timezone');
if (savedTimezone) {
    document.getElementById('dashboard-timezone').value = savedTimezone;
}
// Update sidebar reminder badge on startup
updateTimezoneReminder();

// Time Adjustment Functionality
async function loadPendingAdjustments(guildId) {
    const container = document.getElementById('pending-adjustments-list');
    // Only show loading if empty
    if (!container.children.length) {
        container.innerHTML = '<div class="empty-state">Loading requests...</div>';
    }

    try {
        const response = await fetch(`/api/guild/${guildId}/adjustments/pending`);
        const data = await response.json();

        if (data.success) {
            const countBadge = document.getElementById('pending-count');
            if (data.requests.length > 0) {
                countBadge.textContent = data.requests.length;
                countBadge.style.display = 'inline-block';

                container.innerHTML = data.requests.map(req => {
                    const safeUsername = escapeHtml(req.username || '');
                    const safeDisplayName = escapeHtml(req.display_name || req.username || 'Unknown');
                    const safeInitial = safeUsername ? escapeHtml(req.username.charAt(0).toUpperCase()) : '?';
                    const safeReason = escapeHtml(req.reason || '');
                    const safeRequestType = escapeHtml(req.request_type.replace('_', ' ').toUpperCase());
                    return `
                            <div class="adjustment-card" id="req-${escapeHtml(req.id)}">
                                <div class="adjustment-header">
                                    <div class="employee-avatar" style="width: 40px; height: 40px; font-size: 16px;">
                                        ${safeInitial}
                                    </div>
                                    <div class="employee-info">
                                        <h3 style="font-size: 15px;">${safeDisplayName}</h3>
                                        <div style="font-size: 12px; color: #8B949E;">Requested ${new Date(req.created_at).toLocaleString()}</div>
                                    </div>
                                    <div style="margin-left: auto; font-size: 12px; background: rgba(212, 175, 55, 0.1); color: #D4AF37; padding: 4px 8px; border-radius: 4px;">
                                        ${safeRequestType}
                                    </div>
                                </div>
                                
                                <div style="margin-bottom: 15px; color: #C9D1D9; font-size: 14px;">
                                    <strong>Reason:</strong> ${safeReason}
                                </div>
                                
                                <div class="before-after-grid">
                                    <div class="before">
                                        <h5 style="color: #8B949E; margin-bottom: 8px;">Original</h5>
                                        <div style="font-size: 13px;">
                                            ${req.original_clock_in ? new Date(req.original_clock_in).toLocaleString() : 'None'}
                                        </div>
                                    </div>
                                    <div class="arrow">\u2192</div>
                                    <div class="after">
                                        <h5 style="color: #D4AF37; margin-bottom: 8px;">Requested</h5>
                                        <div style="font-size: 13px;">
                                            ${req.requested_clock_in ? new Date(req.requested_clock_in).toLocaleString() : 'No Change'}
                                        </div>
                                    </div>
                                </div>
                                
                                <div class="adjustment-actions">
                                    <button class="approve-btn" data-guild-id="${escapeHtml(guildId)}" data-request-id="${escapeHtml(req.id)}" data-action="approve">✅ Approve</button>
                                    <button class="deny-btn" data-guild-id="${escapeHtml(guildId)}" data-request-id="${escapeHtml(req.id)}" data-action="deny">\u274C Deny</button>
                                </div>
                            </div>
                        `;
                }).join('');

                // Attach event listeners safely using data attributes
                container.querySelectorAll('.approve-btn, .deny-btn').forEach(btn => {
                    btn.addEventListener('click', function () {
                        const gId = parseInt(this.dataset.guildId, 10);
                        const rId = parseInt(this.dataset.requestId, 10);
                        const action = this.dataset.action;
                        if (!isNaN(gId) && !isNaN(rId) && (action === 'approve' || action === 'deny')) {
                            handleAdjustment(gId, rId, action);
                        }
                    });
                });
            } else {
                countBadge.style.display = 'none';
                container.innerHTML = '<div class="empty-state">No pending requests.</div>';
            }
        }
    } catch (error) {
        console.error('Error loading adjustments:', error);
        container.innerHTML = '<div class="empty-state" style="color: #EF4444;">Failed to load requests.</div>';
    }
}

async function handleAdjustment(guildId, requestId, action) {
    if (!confirm(`Are you sure you want to ${action} this request?`)) return;

    try {
        const response = await fetch(`/api/guild/${guildId}/adjustments/${requestId}/${action}`, {
            method: 'POST'
        });
        const data = await response.json();

        if (data.success) {
            // Remove card from UI
            const card = document.getElementById(`req-${requestId}`);
            if (card) {
                card.style.opacity = '0.5';
                card.innerHTML = `<div style="text-align: center; padding: 20px; color: ${action === 'approve' ? '#10B981' : '#EF4444'};">Request ${action}d!</div>`;
                setTimeout(() => loadPendingAdjustments(guildId), 1000);
            }
        } else {
            alert(`Error: ${data.error}`);
        }
    } catch (error) {
        console.error(`Error ${action}ing adjustment:`, error);
        alert('An error occurred.');
    }
}

// Handle form submission
document.getElementById('adjustment-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!currentGuildId) return;

    const type = document.getElementById('adj-type').value;
    const time = document.getElementById('adj-time').value;
    const reason = document.getElementById('adj-reason').value;

    // Basic validation
    if (!time) {
        alert('Please select a date and time');
        return;
    }

    const payload = {
        request_type: type,
        reason: reason,
        requested_clock_in: type === 'modify_clockin' || type === 'add_session' ? new Date(time).toISOString() : null,
        requested_clock_out: type === 'modify_clockout' ? new Date(time).toISOString() : null
    };

    try {
        const response = await fetch(`/api/guild/${currentGuildId}/adjustments`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await response.json();

        if (data.success) {
            alert('Request submitted successfully!');
            document.getElementById('adjustment-form').reset();
            // Reload user history
            if (typeof loadUserAdjustmentHistory === 'function') {
                loadUserAdjustmentHistory(currentGuildId);
            }

            // Reload pending requests to show the new one (if user is also admin)
            if (currentServerData && (currentServerData.user_role_tier === 'admin' || currentServerData.user_role_tier === 'owner')) {
                loadPendingAdjustments(currentGuildId);
            }
        } else {
            alert(`Error: ${data.error}`);
        }
    } catch (error) {
        console.error('Error submitting adjustment:', error);
        alert('Failed to submit request.');
    }
});

// User Adjustment History (shows only completed requests - approved/denied)
async function loadUserAdjustmentHistory(guildId) {
    const container = document.getElementById('user-adjustments-list');
    if (!container) return;

    // Only show loading if empty
    if (!container.children.length) {
        container.innerHTML = '<div class="empty-state">Loading history...</div>';
    }

    try {
        const response = await fetch(`/api/guild/${guildId}/adjustments/history`);
        const data = await response.json();

        if (data.success) {
            // Filter out pending requests - those show in "Awaiting Review" section
            const completedRequests = data.history.filter(req => req.status !== 'pending');
            
            if (completedRequests.length > 0) {
                container.innerHTML = completedRequests.map(req => {
                    const safeReason = escapeHtml(req.reason || '');
                    const safeRequestType = escapeHtml(req.request_type.replace('_', ' ').toUpperCase());
                    const statusColors = {
                        'pending': '#F59E0B',
                        'approved': '#10B981',
                        'denied': '#EF4444'
                    };
                    const statusColor = statusColors[req.status] || '#8B949E';
                    const statusIcon = req.status === 'approved' ? '✅' : (req.status === 'denied' ? '❌' : '⏳');

                    return `
                        <div class="adjustment-card" style="border-left: 4px solid ${statusColor};">
                            <div class="adjustment-header">
                                <div style="font-weight: 600; color: ${statusColor}; display: flex; align-items: center; gap: 6px;">
                                    <span>${statusIcon}</span>
                                    <span>${escapeHtml(req.status.toUpperCase())}</span>
                                </div>
                                <div style="margin-left: auto; font-size: 12px; color: #8B949E;">
                                    ${new Date(req.created_at).toLocaleString()}
                                </div>
                            </div>
                            
                            <div style="margin-top: 8px; font-size: 13px; color: #C9D1D9;">
                                <span style="background: rgba(255,255,255,0.1); padding: 2px 6px; border-radius: 4px; font-size: 11px; margin-right: 8px;">
                                    ${safeRequestType}
                                </span>
                                ${safeReason}
                            </div>
                            
                            ${req.reviewed_by ? `
                                <div style="margin-top: 10px; padding-top: 10px; border-top: 1px solid rgba(255,255,255,0.05); font-size: 12px; color: #8B949E;">
                                    Reviewed by Admin on ${new Date(req.reviewed_at).toLocaleString()}
                                </div>
                            ` : ''}
                        </div>
                    `;
                }).join('');
            } else {
                container.innerHTML = '<div class="empty-state">No past requests. Submit a request above and it will appear here once reviewed.</div>';
            }
        } else {
            container.innerHTML = `<div class="empty-state" style="color: #EF4444;">Error: ${escapeHtml(data.error)}</div>`;
        }
    } catch (error) {
        console.error('Error loading history:', error);
        container.innerHTML = '<div class="empty-state" style="color: #EF4444;">Failed to load history.</div>';
    }
}

// ===========================
// Employee Detail View Functions
// ===========================

// Open employee detail modal
async function openEmployeeDetailView(userId, guildId) {
    const overlay = document.getElementById('employee-detail-overlay');
    if (!overlay) {
        console.error('Employee detail overlay not found');
        return;
    }

    overlay.style.display = 'flex';

    // Set loading state
    document.getElementById('detail-name').textContent = 'Loading...';
    document.getElementById('detail-status').textContent = 'Status: Loading...';
    document.getElementById('weekly-timecard-grid').innerHTML = '<div style="grid-column: 1/-1; text-align: center; padding: 20px; color: rgba(0,0,0,0.5);">Loading...</div>';
    document.getElementById('recent-requests-list').innerHTML = '<div style="text-align: center; padding: 20px; color: rgba(0,0,0,0.5);">Loading...</div>';

    try {
        // Fetch employee detail
        const detailResponse = await fetch(`/api/guild/${guildId}/employee/${userId}/detail`);
        const detailData = await detailResponse.json();

        if (!detailData.success) {
            throw new Error(detailData.error || 'Failed to load employee details');
        }

        // Fetch timecard
        const timecardResponse = await fetch(`/api/guild/${guildId}/employee/${userId}/timecard`);
        const timecardData = await timecardResponse.json();

        if (!timecardData.success) {
            throw new Error(timecardData.error || 'Failed to load timecard');
        }

        // Fetch recent requests
        const requestsResponse = await fetch(`/api/guild/${guildId}/employee/${userId}/adjustments/recent`);
        const requestsData = await requestsResponse.json();

        if (!requestsData.success) {
            throw new Error(requestsData.error || 'Failed to load requests');
        }

        // Render data
        renderEmployeeHeader(detailData.employee);
        renderWeeklyTimecard(timecardData);
        renderRecentRequests(requestsData.requests || [], guildId);

    } catch (error) {
        console.error('Error loading employee detail:', error);
        document.getElementById('detail-name').textContent = 'Error';
        document.getElementById('detail-status').textContent = 'Failed to load employee data';
        document.getElementById('weekly-timecard-grid').innerHTML = `<div style="grid-column: 1/-1; text-align: center; padding: 20px; color: var(--stamp-denied);">${escapeHtml(error.message)}</div>`;
        document.getElementById('recent-requests-list').innerHTML = `<div style="text-align: center; padding: 20px; color: var(--stamp-denied);">${escapeHtml(error.message)}</div>`;
    }
}

// Close modal
function closeEmployeeDetailView() {
    const overlay = document.getElementById('employee-detail-overlay');
    if (overlay) {
        overlay.style.display = 'none';
    }
}

// Render employee header
function renderEmployeeHeader(employee) {
    const nameEl = document.getElementById('detail-name');
    const statusEl = document.getElementById('detail-status');
    const avatarEl = document.getElementById('detail-avatar');

    if (nameEl) {
        nameEl.textContent = employee.display_name || 'Unknown User';
    }

    if (statusEl) {
        const status = employee.is_clocked_in ? `🟢 Clocked In` : `🔴 Clocked Out`;
        const totalHours = employee.total_hours_week ? ` • ${Math.floor(employee.total_hours_week / 3600)}h this week` : '';
        statusEl.textContent = `${status}${totalHours}`;
    }

    if (avatarEl) {
        avatarEl.textContent = employee.display_name ? employee.display_name.charAt(0).toUpperCase() : '?';
    }
}

// Render weekly timecard
function renderWeeklyTimecard(data) {
    const container = document.getElementById('weekly-timecard-grid');
    if (!container) return;

    if (!data.days || data.days.length === 0) {
        container.innerHTML = '<div style="grid-column: 1/-1; text-align: center; padding: 20px; color: rgba(0,0,0,0.5);">No timecard data available</div>';
        return;
    }

    container.innerHTML = data.days.map(day => {
        const hours = day.duration_hours || 0;
        const barHeight = Math.min(hours * 10, 100); // Cap at 100px
        const isComplete = day.status === 'complete';
        const barColor = isComplete ? '#10B981' : '#8B949E';

        return `
            <div class="timecard-day">
                <div class="day-name">${escapeHtml(day.day_name || 'N/A')}</div>
                <div class="day-hours">${hours.toFixed(1)}h</div>
                <div class="time-bar" style="height: ${barHeight}px; background: ${barColor}"></div>
            </div>
        `;
    }).join('');
}

// Render recent requests
function renderRecentRequests(requests, guildId) {
    const container = document.getElementById('recent-requests-list');
    if (!container) return;

    if (!requests || requests.length === 0) {
        container.innerHTML = '<div class="empty-state" style="text-align: center; padding: 30px; color: rgba(0,0,0,0.5);">No recent adjustment requests</div>';
        return;
    }

    container.innerHTML = requests.map(req => {
        const statusClass = req.status || 'pending';
        const requestType = (req.request_type || 'unknown').replace(/_/g, ' ').toUpperCase();
        const reason = escapeHtml(req.reason || 'No reason provided');

        let actionButtons = '';
        if (req.status === 'pending' && currentServerData && (currentServerData.user_role_tier === 'admin' || currentServerData.user_role_tier === 'owner')) {
            actionButtons = `
                <div class="request-actions" style="margin-top: 12px; display: flex; gap: 8px;">
                    <button onclick="handleQuickApproval(${req.id}, ${guildId}, 'approve')" style="background: rgba(16, 185, 129, 0.2); color: #10B981; border: 1px solid rgba(16, 185, 129, 0.4);">✅ Approve</button>
                    <button onclick="handleQuickApproval(${req.id}, ${guildId}, 'deny')" style="background: rgba(220, 38, 38, 0.2); color: #DC2626; border: 1px solid rgba(220, 38, 38, 0.4);">❌ Deny</button>
                </div>
            `;
        }

        return `
            <div class="request-card">
                <div class="stamp ${statusClass}">${statusClass.toUpperCase()}</div>
                <div class="request-type">${requestType}</div>
                <div class="request-reason">Reason: ${reason}</div>
                <div style="font-size: 11px; color: rgba(0,0,0,0.5); margin-top: 8px;">
                    Requested: ${new Date(req.created_at).toLocaleString()}
                </div>
                ${actionButtons}
            </div>
        `;
    }).join('');
}

// Quick approval handler
async function handleQuickApproval(requestId, guildId, action) {
    if (!requestId || !guildId || !action) {
        alert('Invalid parameters');
        return;
    }

    try {
        const response = await fetch(`/api/guild/${guildId}/adjustments/${requestId}/${action}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });

        const data = await response.json();

        if (data.success) {
            // Refresh the employee detail view
            // Get the current employee user ID (we'll need to track this)
            const overlay = document.getElementById('employee-detail-overlay');
            if (overlay && overlay.style.display !== 'none') {
                // For now, just reload the page section
                alert(`Request ${action}ed successfully!`);
                closeEmployeeDetailView();
            }
        } else {
            alert(`Error: ${data.error || 'Failed to process request'}`);
        }
    } catch (error) {
        console.error('Error handling approval:', error);
        alert('Failed to process request. Please try again.');
    }
}

// Close modal when clicking overlay (outside the modal)
document.addEventListener('DOMContentLoaded', function () {
    const overlay = document.getElementById('employee-detail-overlay');
    if (overlay) {
        overlay.addEventListener('click', function (e) {
            if (e.target === overlay) {
                closeEmployeeDetailView();
            }
        });
    }
});

// Export functions to window scope for onclick handlers
window.openEmployeeDetailView = openEmployeeDetailView;
window.closeEmployeeDetailView = closeEmployeeDetailView;
window.handleQuickApproval = handleQuickApproval;
