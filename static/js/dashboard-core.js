// Server Settings State
let currentGuildId = null;
let currentServerData = null;
let selectedAvailableAdminRole = null;
let selectedCurrentAdminRole = null;
let selectedAvailableRole = null;
let selectedCurrentRole = null;

// Navigation functionality
function updateNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    const contentSections = document.querySelectorAll('.content-section');

    navItems.forEach(item => {
        item.addEventListener('click', () => {
            const sectionId = item.getAttribute('data-section');

            navItems.forEach(nav => nav.classList.remove('active'));
            item.classList.add('active');

            contentSections.forEach(section => section.classList.remove('active'));
            const targetSection = document.getElementById('section-' + sectionId);
            if (targetSection) {
                targetSection.classList.add('active');
            }

            // Load email recipients when email settings section is shown
            if (sectionId === 'email-settings') {
                loadEmailRecipients();
            }

            // Load employee status when section is shown
            if (sectionId === 'employees') {
                loadEmployeeStatus(currentGuildId);
            }

            // Load adjustments when section is shown
            if (sectionId === 'adjustments') {
                // Always load user history
                if (typeof loadUserAdjustmentHistory === 'function') {
                    loadUserAdjustmentHistory(currentGuildId);
                }

                // Only load pending if admin/owner
                if (currentServerData && (currentServerData.user_role_tier === 'admin' || currentServerData.user_role_tier === 'owner')) {
                    loadPendingAdjustments(currentGuildId);
                }
            }

            // Don't auto-close sidebar on mobile - let user navigate freely
            // They can close it by tapping the overlay or back button
        });
    });
}

updateNavigation();

// Server Selection Handler
document.querySelectorAll('.server-item').forEach(item => {
    item.addEventListener('click', async function () {
        const guildId = this.dataset.guildId;
        const guildName = this.dataset.guildName;
        const guildIcon = this.dataset.guildIcon;

        currentGuildId = guildId;

        // Update server navigation header
        document.getElementById('serverNavName').textContent = guildName;
        const serverNavIcon = document.getElementById('serverNavIcon');
        if (guildIcon) {
            serverNavIcon.innerHTML = `<img src="${guildIcon}" alt="${guildName}">`;
        } else {
            serverNavIcon.textContent = guildName.charAt(0).toUpperCase();
        }

        // Switch to server navigation
        document.getElementById('main-nav').style.display = 'none';
        document.getElementById('server-nav').style.display = 'block';

        // Load server data
        await loadServerData(guildId);

        // Load pending count
        loadPendingAdjustments(guildId);

        // Navigate to server overview
        document.querySelectorAll('.nav-item').forEach(nav => nav.classList.remove('active'));
        document.querySelector('[data-section="server-overview"]').classList.add('active');
        document.querySelectorAll('.content-section').forEach(section => section.classList.remove('active'));
        document.getElementById('section-server-overview').classList.add('active');

        updateNavigation();
    });
});

// Back to Servers Handler
document.getElementById('backToServers').addEventListener('click', () => {
    currentGuildId = null;
    currentServerData = null;

    // Switch back to main navigation
    document.getElementById('main-nav').style.display = 'block';
    document.getElementById('server-nav').style.display = 'none';

    // Navigate to My Servers
    document.querySelectorAll('.nav-item').forEach(nav => nav.classList.remove('active'));
    document.querySelector('[data-section="my-servers"]').classList.add('active');
    document.querySelectorAll('.content-section').forEach(section => section.classList.remove('active'));
    document.getElementById('section-my-servers').classList.add('active');

    updateNavigation();
});

// Load Server Data
async function loadServerData(guildId) {
    try {
        const response = await fetch(`/api/server/${guildId}/data`);
        const data = await response.json();

        if (!response.ok || !data.success) {
            alert(data.error || 'Error loading server data');
            return;
        }

        currentServerData = data;

        // Populate roles and settings
        populateAdminRoles(data.roles, data.current_settings.admin_roles);
        populateEmployeeRoles(data.roles, data.current_settings.employee_roles);
        populateTimezoneSettings(data.current_settings.timezone);

        // Load banned users
        loadBannedUsers();

        // Update UI based on user role
        if (data.user_role_tier && typeof updateSidebarForRole === 'function') {
            updateSidebarForRole(data.user_role_tier);
        }

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
    const emoji = type === 'admin' ? 'ðŸ›¡ï¸' : 'ðŸŽ­';

    div.innerHTML = `
                <div class="listbox-item-icon" style="background-color: #${roleColor};">
                    ${emoji}
                </div>
                <div class="listbox-item-info">
                    <div class="listbox-item-name">${role.name}</div>
                    <div class="listbox-item-meta">Role ID: ${role.id}</div>
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

// Email Management Functions
async function loadEmailRecipients() {
    if (!currentGuildId) return;

    try {
        const response = await fetch(`/api/server/${currentGuildId}/email-recipients`);
        const data = await response.json();

        if (response.ok && data.success) {
            renderEmailList(data.emails);
        } else {
            console.error('Error loading emails:', data.error);
        }
    } catch (error) {
        console.error('Error:', error);
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
    }
}

function renderEmailList(emails) {
    const emailList = document.getElementById('email-list');

    if (!emails || emails.length === 0) {
        emailList.innerHTML = '<div class="empty-state" style="text-align: center; padding: 40px 20px; color: #8B949E; font-size: 13px;">No email addresses configured</div>';
        return;
    }

    emailList.innerHTML = emails.map(email => `
                <div class="email-item" data-email-id="${email.id}" style="display: flex; align-items: center; justify-content: space-between; padding: 10px 12px; background: rgba(30, 35, 45, 0.6); border: 1px solid rgba(212, 175, 55, 0.1); border-radius: 6px; margin-bottom: 8px; transition: all 0.2s ease;">
                    <span class="email-address" style="color: #C9D1D9; font-size: 14px; flex: 1;">ðŸ“§ ${email.email}</span>
                    <button class="email-remove-btn" onclick="removeEmail(${email.id})" style="background: linear-gradient(135deg, #DC2626, #B91C1C); color: white; border: none; padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; transition: all 0.2s ease;">Remove</button>
                </div>
            `).join('');
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
            alert('Error updating email settings: ' + (data.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Error updating email settings');
    }
}

// Work Day End Time Save Handler
async function saveWorkDayTime() {
    if (!currentGuildId) return;

    const workDayEndTime = document.getElementById('work-day-end-time').value;

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
                    <div style="font-size: 24px; margin-bottom: 8px;">ðŸ”„</div>
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
                                    <td style="padding: 10px; color: #C9D1D9; font-family: monospace;">${ban.user_id}</td>
                                    <td style="padding: 10px; color: #8B949E;">${bannedAt}</td>
                                    <td style="padding: 10px; color: ${isExpired ? '#10B981' : '#C9D1D9'};">
                                        ${expiresAt}${isExpired ? ' (Expired)' : ''}
                                    </td>
                                    <td style="padding: 10px; text-align: center; color: #F59E0B; font-weight: 600;">${ban.warning_count}</td>
                                    <td style="padding: 10px; color: #8B949E;">${ban.reason}</td>
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
                            <div style="font-size: 24px; margin-bottom: 8px;">aŒ</div>
                            <div>Error loading banned users</div>
                        </div>
                    `;
        }
    } catch (error) {
        console.error('Error loading banned users:', error);
        bannedUsersList.innerHTML = `
                    <div style="text-align: center; color: #EF4444; padding: 20px;">
                        <div style="font-size: 24px; margin-bottom: 8px;">aŒ</div>
                        <div>Error: ${error.message}</div>
                    </div>
                `;
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
                container.innerHTML = '<div class="empty-state">No employees currently clocked in.</div>';
                return;
            }

            container.innerHTML = data.employees.map(emp => {
                // Calculate duration
                const clockInTime = new Date(emp.clock_in);
                const now = new Date();
                const durationMs = now - clockInTime;

                // Format duration
                const hours = Math.floor(durationMs / 3600000);
                const minutes = Math.floor((durationMs % 3600000) / 60000);
                const durationStr = `${hours}h ${minutes}m`;

                // Format hours stats
                const formatHours = (seconds) => {
                    const h = Math.floor(seconds / 3600);
                    const m = Math.floor((seconds % 3600) / 60);
                    return `${h}h ${m}m`;
                };

                return `
                        <div class="employee-card">
                            <div class="employee-card-header">
                                <div class="employee-avatar">
                                    ${emp.display_name ? emp.display_name.charAt(0).toUpperCase() : '?'}
                                </div>
                                <div class="employee-info">
                                    <h3>${emp.display_name || 'Unknown User'}</h3>
                                    <div class="employee-status">
                                        <span style="width: 8px; height: 8px; background: #57F287; border-radius: 50%; display: inline-block;"></span>
                                        Clocked in for ${durationStr}
                                    </div>
                                </div>
                            </div>
                            <div class="employee-stats">
                                <div class="stat-row">
                                    <span class="stat-label">Today</span>
                                    <span class="stat-value">${formatHours(emp.hours_today)}</span>
                                </div>
                                <div class="stat-row">
                                    <span class="stat-label">This Week</span>
                                    <span class="stat-value">${formatHours(emp.hours_week)}</span>
                                </div>
                                <div class="stat-row">
                                    <span class="stat-label">This Month</span>
                                    <span class="stat-value">${formatHours(emp.hours_month)}</span>
                                </div>
                            </div>
                        </div>
                        `;
            }).join('');
        } else {
            container.innerHTML = `<div class="empty-state" style="color: #EF4444;">Error: ${data.error}</div>`;
        }
    } catch (error) {
        console.error('Error loading employees:', error);
        container.innerHTML = '<div class="empty-state" style="color: #EF4444;">Failed to load employee data.</div>';
    }
}

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

                container.innerHTML = data.requests.map(req => `
                            <div class="adjustment-card" id="req-${req.id}">
                                <div class="adjustment-header">
                                    <div class="employee-avatar" style="width: 40px; height: 40px; font-size: 16px;">
                                        ${req.username ? req.username.charAt(0).toUpperCase() : '?'}
                                    </div>
                                    <div class="employee-info">
                                        <h3 style="font-size: 15px;">${req.display_name || req.username}</h3>
                                        <div style="font-size: 12px; color: #8B949E;">Requested ${new Date(req.created_at).toLocaleString()}</div>
                                    </div>
                                    <div style="margin-left: auto; font-size: 12px; background: rgba(212, 175, 55, 0.1); color: #D4AF37; padding: 4px 8px; border-radius: 4px;">
                                        ${req.request_type.replace('_', ' ').toUpperCase()}
                                    </div>
                                </div>
                                
                                <div style="margin-bottom: 15px; color: #C9D1D9; font-size: 14px;">
                                    <strong>Reason:</strong> ${req.reason}
                                </div>
                                
                                <div class="before-after-grid">
                                    <div class="before">
                                        <h5 style="color: #8B949E; margin-bottom: 8px;">Original</h5>
                                        <div style="font-size: 13px;">
                                            ${req.original_clock_in ? new Date(req.original_clock_in).toLocaleString() : 'None'}
                                        </div>
                                    </div>
                                    <div class="arrow">a†’</div>
                                    <div class="after">
                                        <h5 style="color: #D4AF37; margin-bottom: 8px;">Requested</h5>
                                        <div style="font-size: 13px;">
                                            ${req.requested_clock_in ? new Date(req.requested_clock_in).toLocaleString() : 'No Change'}
                                        </div>
                                    </div>
                                </div>
                                
                                <div class="adjustment-actions">
                                    <button class="approve-btn" onclick="handleAdjustment(${guildId}, ${req.id}, 'approve')">✅ Approve</button>
                                    <button class="deny-btn" onclick="handleAdjustment(${guildId}, ${req.id}, 'deny')">aŒ Deny</button>
                                </div>
                            </div>
                        `).join('');
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
