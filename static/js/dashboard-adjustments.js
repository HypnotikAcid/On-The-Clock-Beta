/**
 * Time Adjustments Calendar - Role-Based Interactive Calendar
 * Admin: View pending requests across all employees by date
 * Employee: View own work sessions and submit adjustment requests
 */

let currentCalendarData = {
    year: new Date().getFullYear(),
    month: new Date().getMonth() + 1,
    guildId: null,
    userId: null,
    timezone: null,
    days: [],
    isAdminMode: false,
    activeSession: null
};

function initializeAdjustments(guildId, userId) {
    if (!guildId) {
        console.error('Calendar initialization requires guildId');
        return;
    }

    currentCalendarData.guildId = guildId;
    currentCalendarData.userId = userId;

    const isAdmin = ['owner', 'admin'].includes(window.currentServerData?.user_role_tier);
    currentCalendarData.isAdminMode = isAdmin;

    setupCalendarEventListeners();
    updateUIForRole(isAdmin);

    if (isAdmin) {
        initializeAdminCalendar(guildId);
    } else {
        initializeEmployeeCalendar(guildId, userId);
    }

    loadPendingRequestsList(guildId, isAdmin);
    loadPastRequests(guildId, isAdmin);
}

function initializeAdjustmentsCalendar(guildId, userId) {
    initializeAdjustments(guildId, userId);
}

function updateUIForRole(isAdmin) {
    const calendarTitleText = document.getElementById('calendar-title-text');
    const calendarHelpContent = document.getElementById('calendar-help-content');
    const pendingSectionTitle = document.getElementById('pending-section-title');
    const pendingSectionDesc = document.getElementById('pending-section-desc');

    if (isAdmin) {
        if (calendarTitleText) calendarTitleText.textContent = 'Pending Requests Calendar';
        if (calendarHelpContent) calendarHelpContent.textContent = 'Click on any day to review and approve/deny pending requests.';
        if (pendingSectionTitle) pendingSectionTitle.textContent = 'All Pending Requests';
        if (pendingSectionDesc) pendingSectionDesc.textContent = 'Review and manage time adjustment requests from all employees.';
    } else {
        if (calendarTitleText) calendarTitleText.textContent = 'My Work Calendar';
        if (calendarHelpContent) calendarHelpContent.textContent = 'Click on any day to view your work sessions or add missing time for days you forgot to clock in.';
        if (pendingSectionTitle) pendingSectionTitle.textContent = 'My Pending Requests';
        if (pendingSectionDesc) pendingSectionDesc.textContent = 'Your submitted requests awaiting admin review.';
    }
}

function initializeAdminCalendar(guildId) {
    loadAdminCalendarMonth(currentCalendarData.year, currentCalendarData.month);
}

function initializeEmployeeCalendar(guildId, userId) {
    loadEmployeeCalendarMonth(currentCalendarData.year, currentCalendarData.month);
    checkActiveSession(guildId, userId);
}

function setupCalendarEventListeners() {
    const prevBtn = document.getElementById('calendar-prev-month');
    const nextBtn = document.getElementById('calendar-next-month');
    const clockOutBtn = document.getElementById('clock-out-now-btn');

    if (prevBtn) {
        prevBtn.removeEventListener('click', handlePrevMonth);
        prevBtn.addEventListener('click', handlePrevMonth);
    }
    if (nextBtn) {
        nextBtn.removeEventListener('click', handleNextMonth);
        nextBtn.addEventListener('click', handleNextMonth);
    }
    if (clockOutBtn) {
        clockOutBtn.removeEventListener('click', handleClockOut);
        clockOutBtn.addEventListener('click', handleClockOut);
    }
}

function handlePrevMonth() {
    navigateMonth(-1);
}

function handleNextMonth() {
    navigateMonth(1);
}

function navigateMonth(direction) {
    let newMonth = currentCalendarData.month + direction;
    let newYear = currentCalendarData.year;

    if (newMonth < 1) {
        newMonth = 12;
        newYear--;
    } else if (newMonth > 12) {
        newMonth = 1;
        newYear++;
    }

    if (currentCalendarData.isAdminMode) {
        loadAdminCalendarMonth(newYear, newMonth);
    } else {
        loadEmployeeCalendarMonth(newYear, newMonth);
    }
}

async function loadAdminCalendarMonth(year, month) {
    const { guildId } = currentCalendarData;

    if (!guildId) {
        console.error('Cannot load admin calendar: missing guildId');
        return;
    }

    const calendarContainer = document.getElementById('calendar-grid');
    if (calendarContainer) {
        calendarContainer.innerHTML = `
            <div style="grid-column: 1 / -1; text-align: center; padding: 40px;">
                <div style="font-size: 24px; margin-bottom: 10px;">&#8987;</div>
                <div style="color: #8B949E;">Loading pending requests...</div>
            </div>
        `;
    }

    try {
        const response = await fetch(
            `/api/guild/${guildId}/adjustments/admin-calendar?year=${year}&month=${month}`
        );

        const result = await response.json();

        if (!result.success) {
            throw new Error(result.error || 'Failed to load admin calendar data');
        }

        currentCalendarData.year = result.data.year;
        currentCalendarData.month = result.data.month;
        currentCalendarData.days = result.data.days;

        renderAdminCalendar();

    } catch (error) {
        console.error('Error loading admin calendar:', error);
        if (calendarContainer) {
            calendarContainer.innerHTML = `
                <div style="grid-column: 1 / -1; text-align: center; padding: 40px;">
                    <div style="font-size: 24px; margin-bottom: 10px; color: #EF4444;">&#10060;</div>
                    <div style="color: #EF4444;">Failed to load calendar</div>
                    <div style="color: #8B949E; font-size: 12px; margin-top: 8px;">${escapeHtml(error.message)}</div>
                </div>
            `;
        }
    }
}

async function loadEmployeeCalendarMonth(year, month) {
    const { guildId, userId } = currentCalendarData;

    if (!guildId || !userId) {
        console.error('Cannot load employee calendar: missing guildId or userId');
        return;
    }

    const calendarContainer = document.getElementById('calendar-grid');
    if (calendarContainer) {
        calendarContainer.innerHTML = `
            <div style="grid-column: 1 / -1; text-align: center; padding: 40px;">
                <div style="font-size: 24px; margin-bottom: 10px;">&#8987;</div>
                <div style="color: #8B949E;">Loading calendar...</div>
            </div>
        `;
    }

    try {
        const response = await fetch(
            `/api/guild/${guildId}/employee/${userId}/monthly-timecard?year=${year}&month=${month}`
        );

        const result = await response.json();

        if (!result.success) {
            throw new Error(result.error || 'Failed to load calendar data');
        }

        currentCalendarData.year = result.data.year;
        currentCalendarData.month = result.data.month;
        currentCalendarData.timezone = result.data.timezone;
        currentCalendarData.days = result.data.days;

        checkForActiveSessionInData(result.data.days);
        renderEmployeeCalendar();

    } catch (error) {
        console.error('Error loading employee calendar:', error);
        if (calendarContainer) {
            calendarContainer.innerHTML = `
                <div style="grid-column: 1 / -1; text-align: center; padding: 40px;">
                    <div style="font-size: 24px; margin-bottom: 10px; color: #EF4444;">&#10060;</div>
                    <div style="color: #EF4444;">Failed to load calendar</div>
                    <div style="color: #8B949E; font-size: 12px; margin-top: 8px;">${escapeHtml(error.message)}</div>
                </div>
            `;
        }
    }
}

function checkForActiveSessionInData(days) {
    for (const day of days) {
        if (day.sessions) {
            for (const session of day.sessions) {
                if (session.clock_in && !session.clock_out) {
                    showActiveSessionAlert(session);
                    currentCalendarData.activeSession = session;
                    return;
                }
            }
        }
    }
    hideActiveSessionAlert();
    currentCalendarData.activeSession = null;
}

async function checkActiveSession(guildId, userId) {
    try {
        const now = new Date();
        const response = await fetch(
            `/api/guild/${guildId}/employee/${userId}/monthly-timecard?year=${now.getFullYear()}&month=${now.getMonth() + 1}`
        );
        const result = await response.json();

        if (result.success && result.data.days) {
            checkForActiveSessionInData(result.data.days);
        }
    } catch (error) {
        console.error('Error checking active session:', error);
    }
}

function showActiveSessionAlert(session) {
    const alert = document.getElementById('active-session-alert');
    const timeDisplay = document.getElementById('active-session-time');

    if (alert) {
        alert.style.display = 'block';
        if (timeDisplay && session.clock_in) {
            const clockInTime = new Date(session.clock_in).toLocaleString('en-US', {
                hour: '2-digit',
                minute: '2-digit',
                hour12: true
            });
            timeDisplay.textContent = `Since: ${clockInTime}`;
        }
    }
}

function hideActiveSessionAlert() {
    const alert = document.getElementById('active-session-alert');
    if (alert) {
        alert.style.display = 'none';
    }
}

async function handleClockOut() {
    const { guildId, userId } = currentCalendarData;

    if (!guildId) {
        showToast('Unable to clock out - missing guild information', 'error');
        return;
    }

    const clockOutBtn = document.getElementById('clock-out-now-btn');
    if (clockOutBtn) {
        clockOutBtn.disabled = true;
        clockOutBtn.textContent = 'Clocking out...';
    }

    try {
        const response = await fetch(`/api/guild/${guildId}/clock-out`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        const result = await response.json();

        if (result.success) {
            showToast('Successfully clocked out!', 'success');
            hideActiveSessionAlert();
            currentCalendarData.activeSession = null;

            loadEmployeeCalendarMonth(currentCalendarData.year, currentCalendarData.month);
        } else {
            throw new Error(result.error || 'Failed to clock out');
        }
    } catch (error) {
        console.error('Error clocking out:', error);
        showToast('Failed to clock out: ' + error.message, 'error');
    } finally {
        if (clockOutBtn) {
            clockOutBtn.disabled = false;
            clockOutBtn.textContent = 'Clock Out Now';
        }
    }
}

function renderAdminCalendar() {
    const { year, month, days } = currentCalendarData;

    updateCalendarHeader(year, month);

    const calendarContainer = document.getElementById('calendar-grid');
    if (!calendarContainer) {
        console.error('Calendar grid container not found');
        return;
    }

    const firstDay = new Date(year, month - 1, 1);
    const lastDay = new Date(year, month, 0);
    const daysInMonth = lastDay.getDate();
    const startingDayOfWeek = firstDay.getDay();

    const daysMap = {};
    days.forEach(day => {
        daysMap[day.date] = day;
    });

    let html = '';

    const dayHeaders = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
    dayHeaders.forEach(header => {
        html += `<div class="calendar-day-header">${header}</div>`;
    });

    for (let i = 0; i < startingDayOfWeek; i++) {
        html += '<div class="calendar-day empty"></div>';
    }

    for (let day = 1; day <= daysInMonth; day++) {
        const date = new Date(year, month - 1, day);
        const dateStr = date.toISOString().split('T')[0];
        const dayData = daysMap[dateStr];

        html += renderAdminDayCell(day, dayData, dateStr);
    }

    calendarContainer.innerHTML = html;
    attachAdminDayCellHandlers();
}

function renderAdminDayCell(dayNumber, dayData, dateStr) {
    const pendingCount = dayData?.pending_count || 0;
    const hasPending = pendingCount > 0;

    let cellClass = 'calendar-day';
    let badgeHtml = '';
    let warningStyle = '';

    if (hasPending) {
        cellClass += ' has-pending';

        if (pendingCount >= 3) {
            warningStyle = 'background: rgba(239, 68, 68, 0.2); border-color: #EF4444;';
            cellClass += ' high-pending';
        } else {
            warningStyle = 'background: rgba(245, 158, 11, 0.15); border-color: #F59E0B;';
            cellClass += ' low-pending';
        }

        badgeHtml = `<div class="pending-badge" style="font-size: 11px; color: ${pendingCount >= 3 ? '#EF4444' : '#F59E0B'}; margin-top: 4px;">${pendingCount} pending</div>`;
    }

    const clickable = hasPending ? 'style="cursor: pointer;' + warningStyle + '"' : '';

    return `
        <div class="${cellClass}" data-date="${dateStr}" data-has-pending="${hasPending}" ${clickable}>
            <div class="day-number">${dayNumber}</div>
            ${badgeHtml}
        </div>
    `;
}

function attachAdminDayCellHandlers() {
    // Allow clicking ALL days in admin calendar (with data-date attribute)
    const dayCells = document.querySelectorAll('.calendar-day[data-date]');

    dayCells.forEach(cell => {
        cell.addEventListener('click', () => {
            const dateStr = cell.getAttribute('data-date');
            if (dateStr) {
                openAdminDayModal(dateStr);
            }
        });
        cell.style.cursor = 'pointer';
    });
}

function openAdminDayModal(dateStr) {
    const dayData = currentCalendarData.days.find(d => d.date === dateStr);

    const dateObj = new Date(dateStr + 'T12:00:00');
    const formattedDate = dateObj.toLocaleDateString('en-US', {
        weekday: 'long',
        year: 'numeric',
        month: 'long',
        day: 'numeric'
    });

    if (!dayData || !dayData.requests || dayData.requests.length === 0) {
        const modalHtml = `
            <div id="admin-day-overlay" class="modal-overlay">
                <div class="modal-content day-edit-modal" style="max-width: 400px;">
                    <div class="modal-header">
                        <h3>&#128197; ${formattedDate}</h3>
                        <button class="close-modal" onclick="closeAdminDayModal()">&times;</button>
                    </div>
                    <div class="modal-body" style="text-align: center; padding: 40px 24px;">
                        <div style="font-size: 48px; margin-bottom: 16px;">&#9989;</div>
                        <div style="color: #10B981; font-size: 18px; font-weight: 600; margin-bottom: 8px;">All Clear!</div>
                        <div style="color: #8B949E; font-size: 14px;">No pending adjustment requests for this day.</div>
                    </div>
                </div>
            </div>
        `;
        
        const existingModal = document.getElementById('admin-day-overlay');
        if (existingModal) existingModal.remove();
        document.body.insertAdjacentHTML('beforeend', modalHtml);
        return;
    }

    let requestsHtml = dayData.requests.map(req => {
        const reqTypeDisplay = (req.request_type || '').replace(/_/g, ' ').toUpperCase();
        const originalIn = req.original_clock_in ? new Date(req.original_clock_in).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }) : 'N/A';
        const originalOut = req.original_clock_out ? new Date(req.original_clock_out).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }) : 'N/A';
        const requestedIn = req.requested_clock_in ? new Date(req.requested_clock_in).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }) : 'N/A';
        const requestedOut = req.requested_clock_out ? new Date(req.requested_clock_out).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }) : 'N/A';

        return `
            <div class="admin-request-card" data-request-id="${req.id}" style="background: rgba(30, 35, 45, 0.8); border: 1px solid rgba(75, 85, 99, 0.4); border-radius: 8px; padding: 15px; margin-bottom: 12px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                    <div style="font-weight: 600; color: #C9D1D9;">${escapeHtml(req.user_name || 'Unknown User')}</div>
                    <div style="font-size: 11px; background: rgba(212, 175, 55, 0.2); color: #D4AF37; padding: 3px 8px; border-radius: 4px;">${escapeHtml(reqTypeDisplay)}</div>
                </div>
                
                ${req.reason ? `<div style="margin-bottom: 10px; color: #8B949E; font-size: 13px;"><strong>Reason:</strong> ${escapeHtml(req.reason)}</div>` : ''}
                
                <div style="display: grid; grid-template-columns: 1fr auto 1fr; gap: 10px; align-items: center; margin-bottom: 15px;">
                    <div style="text-align: center;">
                        <div style="font-size: 11px; color: #8B949E; margin-bottom: 4px;">Original</div>
                        <div style="font-size: 12px; color: #C9D1D9;">${originalIn} - ${originalOut}</div>
                    </div>
                    <div style="color: #D4AF37;">→</div>
                    <div style="text-align: center;">
                        <div style="font-size: 11px; color: #D4AF37; margin-bottom: 4px;">Requested</div>
                        <div style="font-size: 12px; color: #C9D1D9;">${requestedIn} - ${requestedOut}</div>
                    </div>
                </div>
                
                <div style="display: flex; gap: 10px;">
                    <button class="approve-btn-modal" data-request-id="${req.id}" style="flex: 1; padding: 8px; background: rgba(16, 185, 129, 0.2); border: 1px solid #10B981; color: #10B981; border-radius: 6px; cursor: pointer; font-size: 12px;">✅ Approve</button>
                    <button class="deny-btn-modal" data-request-id="${req.id}" style="flex: 1; padding: 8px; background: rgba(239, 68, 68, 0.2); border: 1px solid #EF4444; color: #EF4444; border-radius: 6px; cursor: pointer; font-size: 12px;">❌ Deny</button>
                </div>
            </div>
        `;
    }).join('');

    const modalHtml = `
        <div id="admin-day-overlay" class="modal-overlay">
            <div class="modal-content day-edit-modal" style="max-width: 500px;">
                <div class="modal-header">
                    <h3>&#128197; ${formattedDate}</h3>
                    <button class="close-modal" onclick="closeAdminDayModal()">&times;</button>
                </div>
                <div class="modal-body" style="max-height: 400px; overflow-y: auto;">
                    <div style="margin-bottom: 15px; padding: 10px; background: rgba(245, 158, 11, 0.1); border-radius: 6px; border-left: 3px solid #F59E0B;">
                        <span style="color: #F59E0B; font-weight: 600;">${dayData.pending_count} Pending Request${dayData.pending_count !== 1 ? 's' : ''}</span>
                    </div>
                    ${requestsHtml}
                </div>
            </div>
        </div>
    `;

    const existingModal = document.getElementById('admin-day-overlay');
    if (existingModal) existingModal.remove();

    document.body.insertAdjacentHTML('beforeend', modalHtml);

    document.querySelectorAll('.approve-btn-modal, .deny-btn-modal').forEach(btn => {
        btn.addEventListener('click', async function () {
            const requestId = this.dataset.requestId;
            const action = this.classList.contains('approve-btn-modal') ? 'approve' : 'deny';
            await handleAdminAction(requestId, action, this);
        });
    });
}

async function handleAdminAction(requestId, action, buttonEl) {
    const { guildId } = currentCalendarData;

    if (!confirm(`Are you sure you want to ${action} this request?`)) return;

    buttonEl.disabled = true;
    buttonEl.textContent = action === 'approve' ? 'Approving...' : 'Denying...';

    try {
        const response = await fetch(`/api/guild/${guildId}/adjustments/${requestId}/${action}`, {
            method: 'POST'
        });
        const result = await response.json();

        if (result.success) {
            const card = buttonEl.closest('.admin-request-card');
            if (card) {
                card.style.opacity = '0.5';
                card.innerHTML = `<div style="text-align: center; padding: 15px; color: ${action === 'approve' ? '#10B981' : '#EF4444'};">Request ${action}d!</div>`;
            }

            showToast(`Request ${action}d successfully!`, 'success');

            setTimeout(() => {
                loadAdminCalendarMonth(currentCalendarData.year, currentCalendarData.month);
                loadPendingRequestsList(guildId, true);
            }, 1000);
        } else {
            throw new Error(result.error || `Failed to ${action} request`);
        }
    } catch (error) {
        console.error(`Error ${action}ing adjustment:`, error);
        showToast(`Failed to ${action}: ${error.message}`, 'error');
        buttonEl.disabled = false;
        buttonEl.textContent = action === 'approve' ? '✅ Approve' : '❌ Deny';
    }
}

function closeAdminDayModal() {
    const modal = document.getElementById('admin-day-overlay');
    if (modal) modal.remove();
}

function renderEmployeeCalendar() {
    const { year, month, days } = currentCalendarData;

    updateCalendarHeader(year, month);

    const calendarContainer = document.getElementById('calendar-grid');
    if (!calendarContainer) {
        console.error('Calendar grid container not found');
        return;
    }

    const firstDay = new Date(year, month - 1, 1);
    const lastDay = new Date(year, month, 0);
    const daysInMonth = lastDay.getDate();
    const startingDayOfWeek = firstDay.getDay();

    const daysMap = {};
    days.forEach(day => {
        daysMap[day.date] = day;
    });

    let html = '';

    const dayHeaders = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
    dayHeaders.forEach(header => {
        html += `<div class="calendar-day-header">${header}</div>`;
    });

    for (let i = 0; i < startingDayOfWeek; i++) {
        html += '<div class="calendar-day empty"></div>';
    }

    for (let day = 1; day <= daysInMonth; day++) {
        const date = new Date(year, month - 1, day);
        const dateStr = date.toISOString().split('T')[0];
        const dayData = daysMap[dateStr];

        html += renderEmployeeDayCell(day, dayData, dateStr);
    }

    calendarContainer.innerHTML = html;
    attachEmployeeDayCellHandlers();
}

function renderEmployeeDayCell(dayNumber, dayData, dateStr) {
    const hasData = dayData && dayData.sessions && dayData.sessions.length > 0;
    const hours = hasData ? dayData.total_hours : 0;
    const sessionCount = hasData ? dayData.sessions.length : 0;
    const adjustmentStatus = dayData?.adjustment_status || null;
    const hasActiveSession = hasData && dayData.sessions.some(s => s.clock_in && !s.clock_out);

    let cellClass = 'calendar-day';
    let statusIndicator = '';
    let statusBorder = '';

    if (hasData) {
        cellClass += ' has-sessions';

        if (hours >= 8) {
            cellClass += ' full-day';
        } else if (hours >= 4) {
            cellClass += ' half-day';
        } else {
            cellClass += ' partial-day';
        }
    }

    if (hasActiveSession) {
        statusIndicator = '<span class="status-indicator active" title="Currently clocked in" style="color: #10B981;">&#9679;</span>';
        statusBorder = 'border-color: #10B981 !important;';
    } else if (adjustmentStatus === 'pending') {
        statusIndicator = '<span class="status-indicator pending" title="Adjustment pending review">&#9888;</span>';
        statusBorder = 'border-color: #F59E0B !important;';
    } else if (adjustmentStatus === 'approved') {
        statusIndicator = '<span class="status-indicator approved" title="Adjustment approved">&#10003;</span>';
        statusBorder = 'border-color: #10B981 !important;';
    } else if (adjustmentStatus === 'denied') {
        statusIndicator = '<span class="status-indicator denied" title="Adjustment denied">&#10007;</span>';
        statusBorder = 'border-color: #EF4444 !important;';
    }

    // All days are clickable now (not just ones with data)
    const clickable = 'style="' + statusBorder + '"';

    return `
        <div class="calendar-day ${cellClass}" data-date="${dateStr}" data-has-sessions="${hasData}" ${clickable}>
            <div class="day-number">${dayNumber}${statusIndicator}</div>
            ${hasData ? `
                <div class="day-hours">${hours}h</div>
                <div class="day-sessions">${sessionCount} session${sessionCount !== 1 ? 's' : ''}</div>
            ` : '<div class="day-no-work" style="color: #6B7280; font-size: 11px;">+ Add time</div>'}
        </div>
    `;
}

function attachEmployeeDayCellHandlers() {
    // Allow clicking ALL days (with or without sessions) to add/edit time
    // Use [data-date] selector to target actual calendar days, excluding placeholder cells
    const dayCells = document.querySelectorAll('.calendar-day[data-date]');

    dayCells.forEach(cell => {
        cell.addEventListener('click', () => {
            const dateStr = cell.getAttribute('data-date');
            if (dateStr) {
                openEmployeeDayModal(dateStr);
            }
        });
        // Add visual indicator that ALL days are clickable
        cell.style.cursor = 'pointer';
    });
}

function openEmployeeDayModal(dateStr) {
    const dayData = currentCalendarData.days.find(d => d.date === dateStr);

    // If no data, create empty structure for adding new sessions
    if (!dayData) {
        openAddMissingTimeModal(dateStr);
        return;
    }

    const dateObj = new Date(dateStr + 'T12:00:00');
    const formattedDate = dateObj.toLocaleDateString('en-US', {
        weekday: 'long',
        year: 'numeric',
        month: 'long',
        day: 'numeric'
    });

    let sessionsHtml = '';
    dayData.sessions.forEach((session, index) => {
        const clockInTime = session.clock_in ? new Date(session.clock_in).toLocaleTimeString('en-US', {
            hour: '2-digit', minute: '2-digit', hour12: false
        }) : '';
        const clockOutTime = session.clock_out ? new Date(session.clock_out).toLocaleTimeString('en-US', {
            hour: '2-digit', minute: '2-digit', hour12: false
        }) : '';
        const duration = session.duration_seconds ? `${(session.duration_seconds / 3600).toFixed(2)}h` : 'Active';
        const isActive = session.clock_in && !session.clock_out;

        sessionsHtml += `
            <div class="edit-session-row" data-session-id="${session.id}" ${isActive ? 'style="border-left: 3px solid #10B981; padding-left: 12px;"' : ''}>
                <div class="session-label">Session ${index + 1}${isActive ? ' <span style="color: #10B981; font-size: 11px;">(ACTIVE)</span>' : ''}</div>
                <div class="session-times">
                    <label>
                        Clock In:
                        <input type="time" class="time-input clock-in" value="${clockInTime}" data-original="${clockInTime}">
                    </label>
                    <label>
                        Clock Out:
                        <input type="time" class="time-input clock-out" value="${clockOutTime}" data-original="${clockOutTime}" ${isActive ? 'disabled placeholder="Still active"' : ''}>
                    </label>
                    <span class="duration-display">${duration}</span>
                </div>
            </div>
        `;
    });

    let existingAdjustmentsHtml = '';
    if (dayData.adjustments && dayData.adjustments.length > 0) {
        existingAdjustmentsHtml = '<div class="existing-adjustments"><h4>Previous Requests</h4>';
        dayData.adjustments.forEach(adj => {
            const statusClass = adj.status === 'pending' ? 'pending' : (adj.status === 'approved' ? 'approved' : 'denied');
            const statusIcon = adj.status === 'pending' ? '&#9888;' : (adj.status === 'approved' ? '&#10003;' : '&#10007;');
            existingAdjustmentsHtml += `
                <div class="adjustment-item ${statusClass}">
                    <span class="status-badge">${statusIcon} ${adj.status.toUpperCase()}</span>
                    <span class="adjustment-type">${adj.request_type.replace('_', ' ')}</span>
                    ${adj.reason ? `<span class="adjustment-reason">"${escapeHtml(adj.reason)}"</span>` : ''}
                </div>
            `;
        });
        existingAdjustmentsHtml += '</div>';
    }

    const modalHtml = `
        <div id="day-edit-overlay" class="modal-overlay">
            <div class="modal-content day-edit-modal">
                <div class="modal-header">
                    <h3>&#128197; ${formattedDate}</h3>
                    <button class="close-modal" onclick="closeDayEditModal()">&times;</button>
                </div>
                <div class="modal-body">
                    <div class="day-summary">
                        <span><strong>Total Hours:</strong> ${dayData.total_hours}h</span>
                        <span><strong>Sessions:</strong> ${dayData.sessions.length}</span>
                    </div>
                    
                    ${existingAdjustmentsHtml}
                    
                    <div class="sessions-edit-container">
                        <h4>Edit Time Entries</h4>
                        <p class="edit-hint">Modify times below and provide a reason to submit an adjustment request.</p>
                        ${sessionsHtml}
                    </div>
                    
                    <div class="adjustment-reason-section">
                        <label for="adjustment-reason">Reason for Adjustment:</label>
                        <textarea id="adjustment-reason" placeholder="Explain why you need this time adjustment..." rows="3"></textarea>
                    </div>
                </div>
                <div class="modal-footer">
                    <button class="btn-secondary" onclick="closeDayEditModal()">Cancel</button>
                    <button class="btn-primary" onclick="submitDayAdjustment('${dateStr}')">Submit Request</button>
                </div>
            </div>
        </div>
    `;

    const existingModal = document.getElementById('day-edit-overlay');
    if (existingModal) existingModal.remove();

    document.body.insertAdjacentHTML('beforeend', modalHtml);

    document.querySelectorAll('.time-input').forEach(input => {
        input.addEventListener('change', updateDurationDisplay);
    });
}

function closeDayEditModal() {
    const modal = document.getElementById('day-edit-overlay');
    if (modal) modal.remove();
}

function updateDurationDisplay(event) {
    const row = event.target.closest('.edit-session-row');
    const clockIn = row.querySelector('.clock-in').value;
    const clockOut = row.querySelector('.clock-out').value;
    const durationDisplay = row.querySelector('.duration-display');

    if (clockIn && clockOut) {
        const [inH, inM] = clockIn.split(':').map(Number);
        const [outH, outM] = clockOut.split(':').map(Number);
        const inMinutes = inH * 60 + inM;
        const outMinutes = outH * 60 + outM;
        const diff = outMinutes - inMinutes;

        if (diff > 0) {
            durationDisplay.textContent = `${(diff / 60).toFixed(2)}h`;
            durationDisplay.style.color = '#10B981';
        } else {
            durationDisplay.textContent = 'Invalid';
            durationDisplay.style.color = '#EF4444';
        }
    }
}

async function submitDayAdjustment(dateStr) {
    const reason = document.getElementById('adjustment-reason').value.trim();

    if (!reason) {
        alert('Please provide a reason for the adjustment.');
        return;
    }

    const dayData = currentCalendarData.days.find(d => d.date === dateStr);
    if (!dayData) return;

    const changedSessions = [];
    document.querySelectorAll('.edit-session-row').forEach(row => {
        const sessionId = row.dataset.sessionId;
        const clockInInput = row.querySelector('.clock-in');
        const clockOutInput = row.querySelector('.clock-out');

        const newClockIn = clockInInput.value;
        const originalClockIn = clockInInput.dataset.original;
        const newClockOut = clockOutInput.value;
        const originalClockOut = clockOutInput.dataset.original;

        if (newClockIn !== originalClockIn || newClockOut !== originalClockOut) {
            changedSessions.push({
                session_id: parseInt(sessionId),
                new_clock_in: newClockIn,
                new_clock_out: newClockOut,
                original_clock_in: originalClockIn,
                original_clock_out: originalClockOut
            });
        }
    });

    if (changedSessions.length === 0) {
        alert('No changes detected. Modify at least one time entry.');
        return;
    }

    const submitBtn = document.querySelector('.modal-footer .btn-primary');
    submitBtn.disabled = true;
    submitBtn.textContent = 'Submitting...';

    try {
        const response = await fetch(`/api/guild/${currentCalendarData.guildId}/adjustments/submit-day`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                session_date: dateStr,
                reason: reason,
                changes: changedSessions
            })
        });

        const result = await response.json();

        if (result.success) {
            closeDayEditModal();
            loadEmployeeCalendarMonth(currentCalendarData.year, currentCalendarData.month);
            loadPendingRequestsList(currentCalendarData.guildId, false);

            showToast('Adjustment request submitted successfully!', 'success');
        } else {
            throw new Error(result.error || 'Failed to submit request');
        }
    } catch (error) {
        console.error('Error submitting adjustment:', error);
        alert('Failed to submit adjustment: ' + error.message);
        submitBtn.disabled = false;
        submitBtn.textContent = 'Submit Request';
    }
}

function openAddMissingTimeModal(dateStr) {
    const dateObj = new Date(dateStr + 'T12:00:00');
    const formattedDate = dateObj.toLocaleDateString('en-US', {
        weekday: 'long',
        year: 'numeric',
        month: 'long',
        day: 'numeric'
    });

    const modalHtml = `
        <div id="day-edit-overlay" class="modal-overlay">
            <div class="modal-content day-edit-modal">
                <div class="modal-header">
                    <h3>&#128197; ${formattedDate}</h3>
                    <button class="close-modal" onclick="closeDayEditModal()">&times;</button>
                </div>
                <div class="modal-body">
                    <div style="padding: 20px; text-align: center; background: rgba(212, 175, 55, 0.1); border-radius: 8px; margin-bottom: 20px;">
                        <div style="color: #D4AF37; margin-bottom: 10px;">&#128712; No work recorded for this day</div>
                        <div style="color: #8B949E; font-size: 13px;">Add a missing time entry by filling in the times below</div>
                    </div>
                    
                    <div class="sessions-edit-container">
                        <h4>Add Missing Time Entry</h4>
                        <div class="edit-session-row">
                            <div class="session-label">New Session</div>
                            <div class="session-times">
                                <label>
                                    Clock In:
                                    <input type="time" class="time-input clock-in" required>
                                </label>
                                <label>
                                    Clock Out:
                                    <input type="time" class="time-input clock-out" required>
                                </label>
                                <span class="duration-display">--</span>
                            </div>
                        </div>
                    </div>
                    
                    <div class="adjustment-reason-section">
                        <label for="adjustment-reason">Reason for Adding This Entry:</label>
                        <textarea id="adjustment-reason" placeholder="Explain why this time wasn't recorded (e.g., 'Forgot to clock in', 'System was offline')..." rows="3" required></textarea>
                    </div>
                </div>
                <div class="modal-footer">
                    <button class="btn-secondary" onclick="closeDayEditModal()">Cancel</button>
                    <button class="btn-primary" onclick="submitMissingTimeRequest('${dateStr}')">Submit Request</button>
                </div>
            </div>
        </div>
    `;

    const existingModal = document.getElementById('day-edit-overlay');
    if (existingModal) existingModal.remove();

    document.body.insertAdjacentHTML('beforeend', modalHtml);

    document.querySelectorAll('.time-input').forEach(input => {
        input.addEventListener('change', updateDurationDisplay);
    });
}

async function submitMissingTimeRequest(dateStr) {
    const reason = document.getElementById('adjustment-reason').value.trim();
    const clockInInput = document.querySelector('.clock-in');
    const clockOutInput = document.querySelector('.clock-out');

    if (!reason) {
        alert('Please provide a reason for adding this time entry.');
        return;
    }

    if (!clockInInput.value || !clockOutInput.value) {
        alert('Please fill in both clock in and clock out times.');
        return;
    }

    const submitBtn = document.querySelector('.modal-footer .btn-primary');
    submitBtn.disabled = true;
    submitBtn.textContent = 'Submitting...';

    try {
        const response = await fetch(`/api/guild/${currentCalendarData.guildId}/adjustments`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                request_type: 'add_session',
                reason: reason,
                session_date: dateStr,
                requested_clock_in: `${dateStr}T${clockInInput.value}:00`,
                requested_clock_out: `${dateStr}T${clockOutInput.value}:00`
            })
        });

        const result = await response.json();

        if (result.success) {
            closeDayEditModal();
            loadEmployeeCalendarMonth(currentCalendarData.year, currentCalendarData.month);
            loadPendingRequestsList(currentCalendarData.guildId, false);

            showToast('Missing time request submitted successfully!', 'success');
        } else {
            throw new Error(result.error || 'Failed to submit request');
        }
    } catch (error) {
        console.error('Error submitting missing time:', error);
        alert('Failed to submit request: ' + error.message);
        submitBtn.disabled = false;
        submitBtn.textContent = 'Submit Request';
    }
}

function updateCalendarHeader(year, month) {
    const monthNames = ['January', 'February', 'March', 'April', 'May', 'June',
        'July', 'August', 'September', 'October', 'November', 'December'];
    const monthHeader = document.getElementById('calendar-month-year');
    if (monthHeader) {
        monthHeader.textContent = `${monthNames[month - 1]} ${year}`;
    }

    currentCalendarData.year = year;
    currentCalendarData.month = month;
}

async function loadPendingRequestsList(guildId, isAdmin) {
    const container = document.getElementById('pending-adjustments-list');
    if (!container) return;

    container.innerHTML = '<div class="empty-state">Loading pending requests...</div>';

    try {
        let url;
        if (isAdmin) {
            url = `/api/guild/${guildId}/adjustments/pending`;
        } else {
            url = `/api/guild/${guildId}/adjustments/history`;
        }

        const response = await fetch(url);
        const data = await response.json();

        if (!data.success) {
            throw new Error(data.error || 'Failed to load requests');
        }

        let requests;
        if (isAdmin) {
            requests = data.requests || [];
        } else {
            requests = (data.history || []).filter(r => r.status === 'pending');
        }

        const countBadge = document.getElementById('pending-count');
        if (requests.length > 0) {
            if (countBadge) {
                countBadge.textContent = requests.length;
                countBadge.style.display = 'inline-block';
            }

            container.innerHTML = requests.map(req => {
                const safeReason = escapeHtml(req.reason || '');
                const safeRequestType = escapeHtml((req.request_type || '').replace(/_/g, ' ').toUpperCase());
                const safeDisplayName = escapeHtml(req.display_name || req.username || req.user_name || 'Unknown');

                if (isAdmin) {
                    return `
                        <div class="adjustment-card" id="req-${escapeHtml(String(req.id))}" style="border-left: 4px solid #F59E0B;">
                            <div class="adjustment-header">
                                <div class="employee-avatar" style="width: 40px; height: 40px; font-size: 16px;">
                                    ${safeDisplayName.charAt(0).toUpperCase()}
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
                                <div class="arrow">→</div>
                                <div class="after">
                                    <h5 style="color: #D4AF37; margin-bottom: 8px;">Requested</h5>
                                    <div style="font-size: 13px;">
                                        ${req.requested_clock_in ? new Date(req.requested_clock_in).toLocaleString() : 'No Change'}
                                    </div>
                                </div>
                            </div>
                            
                            <div class="adjustment-actions" style="margin-top: 15px; display: flex; gap: 10px;">
                                <button class="approve-btn" data-guild-id="${guildId}" data-request-id="${req.id}" data-action="approve" style="flex: 1; padding: 10px; background: rgba(16, 185, 129, 0.2); border: 1px solid #10B981; color: #10B981; border-radius: 6px; cursor: pointer;">✅ Approve</button>
                                <button class="deny-btn" data-guild-id="${guildId}" data-request-id="${req.id}" data-action="deny" style="flex: 1; padding: 10px; background: rgba(239, 68, 68, 0.2); border: 1px solid #EF4444; color: #EF4444; border-radius: 6px; cursor: pointer;">❌ Deny</button>
                            </div>
                        </div>
                    `;
                } else {
                    return `
                        <div class="adjustment-card" style="border-left: 4px solid #F59E0B;">
                            <div class="adjustment-header">
                                <div style="font-weight: 600; color: #F59E0B; display: flex; align-items: center; gap: 6px;">
                                    <span>⏳</span>
                                    <span>PENDING</span>
                                </div>
                                <div style="margin-left: auto; font-size: 12px; color: #8B949E;">
                                    ${new Date(req.created_at).toLocaleString()}
                                </div>
                            </div>
                            <div style="margin-top: 8px; margin-bottom: 10px; font-size: 12px; background: rgba(212, 175, 55, 0.1); color: #D4AF37; padding: 4px 8px; border-radius: 4px; display: inline-block;">
                                ${safeRequestType}
                            </div>
                            <div style="color: #C9D1D9; font-size: 14px;">
                                <strong>Reason:</strong> ${safeReason}
                            </div>
                        </div>
                    `;
                }
            }).join('');

            if (isAdmin) {
                container.querySelectorAll('.approve-btn, .deny-btn').forEach(btn => {
                    btn.addEventListener('click', async function () {
                        const gId = this.dataset.guildId;
                        const rId = this.dataset.requestId;
                        const action = this.dataset.action;
                        await handleListAdjustmentAction(gId, rId, action, this);
                    });
                });
            }
        } else {
            if (countBadge) countBadge.style.display = 'none';
            container.innerHTML = '<div class="empty-state">No pending requests.</div>';
        }
    } catch (error) {
        console.error('Error loading pending requests:', error);
        container.innerHTML = `<div class="empty-state" style="color: #EF4444;">Failed to load requests: ${escapeHtml(error.message)}</div>`;
    }
}

async function handleListAdjustmentAction(guildId, requestId, action, buttonEl) {
    if (!confirm(`Are you sure you want to ${action} this request?`)) return;

    buttonEl.disabled = true;
    const originalText = buttonEl.textContent;
    buttonEl.textContent = action === 'approve' ? 'Approving...' : 'Denying...';

    try {
        const response = await fetch(`/api/guild/${guildId}/adjustments/${requestId}/${action}`, {
            method: 'POST'
        });
        const data = await response.json();

        if (data.success) {
            const card = document.getElementById(`req-${requestId}`);
            if (card) {
                card.style.opacity = '0.5';
                card.innerHTML = `<div style="text-align: center; padding: 20px; color: ${action === 'approve' ? '#10B981' : '#EF4444'};">Request ${action}d!</div>`;
            }

            showToast(`Request ${action}d successfully!`, 'success');

            setTimeout(() => {
                loadPendingRequestsList(guildId, true);
                if (currentCalendarData.isAdminMode) {
                    loadAdminCalendarMonth(currentCalendarData.year, currentCalendarData.month);
                }
            }, 1000);
        } else {
            throw new Error(data.error || `Failed to ${action}`);
        }
    } catch (error) {
        console.error(`Error ${action}ing adjustment:`, error);
        showToast(`Error: ${error.message}`, 'error');
        buttonEl.disabled = false;
        buttonEl.textContent = originalText;
    }
}

async function loadPastRequests(guildId, isAdmin) {
    const container = document.getElementById('past-adjustments-list');
    const countBadge = document.getElementById('past-requests-count');
    if (!container) return;

    container.innerHTML = '<div class="empty-state">Loading past requests...</div>';

    try {
        let url;
        if (isAdmin) {
            url = `/api/guild/${guildId}/adjustments/resolved`;
        } else {
            url = `/api/guild/${guildId}/adjustments/history`;
        }

        const response = await fetch(url);
        const data = await response.json();

        if (!data.success) {
            url = `/api/guild/${guildId}/adjustments/history`;
            const fallbackResponse = await fetch(url);
            const fallbackData = await fallbackResponse.json();
            if (fallbackData.success) {
                renderPastRequests(container, countBadge, fallbackData.history || [], isAdmin);
                return;
            }
            throw new Error(data.error || 'Failed to load past requests');
        }

        const requests = data.requests || data.history || [];
        renderPastRequests(container, countBadge, requests, isAdmin);

    } catch (error) {
        console.error('Error loading past requests:', error);
        container.innerHTML = '<div class="empty-state">No past requests found.</div>';
        if (countBadge) countBadge.textContent = '(0)';
    }
}

function renderPastRequests(container, countBadge, allRequests, isAdmin) {
    const resolvedRequests = allRequests.filter(r => r.status === 'approved' || r.status === 'denied');

    if (countBadge) {
        countBadge.textContent = `(${resolvedRequests.length})`;
    }

    if (resolvedRequests.length === 0) {
        container.innerHTML = '<div class="empty-state">No past requests.</div>';
        return;
    }

    container.innerHTML = resolvedRequests.map(req => {
        const statusColors = {
            'approved': '#10B981',
            'denied': '#EF4444'
        };
        const statusColor = statusColors[req.status] || '#8B949E';
        const statusIcon = req.status === 'approved' ? '✅' : '❌';
        const safeReason = escapeHtml(req.reason || '');
        const safeRequestType = escapeHtml((req.request_type || '').replace(/_/g, ' ').toUpperCase());
        const safeDisplayName = escapeHtml(req.display_name || req.username || req.user_name || '');

        return `
            <div class="adjustment-card" style="border-left: 4px solid ${statusColor}; opacity: 0.9;">
                <div class="adjustment-header">
                    <div style="font-weight: 600; color: ${statusColor}; display: flex; align-items: center; gap: 6px;">
                        <span>${statusIcon}</span>
                        <span>${req.status.toUpperCase()}</span>
                    </div>
                    <div style="margin-left: auto; font-size: 12px; color: #8B949E;">
                        ${new Date(req.created_at).toLocaleString()}
                    </div>
                </div>
                ${isAdmin && safeDisplayName ? `<div style="margin-top: 4px; font-size: 13px; color: #C9D1D9;"><strong>Employee:</strong> ${safeDisplayName}</div>` : ''}
                <div style="margin-top: 8px; font-size: 12px; background: rgba(139, 148, 158, 0.1); color: #8B949E; padding: 4px 8px; border-radius: 4px; display: inline-block;">
                    ${safeRequestType}
                </div>
                ${safeReason ? `<div style="margin-top: 8px; color: #8B949E; font-size: 13px;"><strong>Reason:</strong> ${safeReason}</div>` : ''}
                ${req.reviewed_at ? `<div style="margin-top: 6px; font-size: 11px; color: #6B7280;">Reviewed: ${new Date(req.reviewed_at).toLocaleString()}</div>` : ''}
            </div>
        `;
    }).join('');
}

function togglePastRequests() {
    const content = document.getElementById('past-requests-content');
    const toggle = document.getElementById('past-requests-toggle');

    if (content && toggle) {
        const isHidden = content.style.display === 'none';
        content.style.display = isHidden ? 'block' : 'none';
        toggle.style.transform = isHidden ? 'rotate(90deg)' : 'rotate(0deg)';
    }
}

function showToast(message, type = 'info') {
    const existing = document.querySelector('.toast');
    if (existing) existing.remove();

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    toast.style.cssText = `
        position: fixed;
        bottom: 20px;
        right: 20px;
        padding: 12px 24px;
        border-radius: 8px;
        color: white;
        font-weight: 500;
        z-index: 10000;
        animation: slideIn 0.3s ease-out;
        background: ${type === 'success' ? '#10B981' : type === 'error' ? '#EF4444' : '#3B82F6'};
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
    `;
    document.body.appendChild(toast);

    setTimeout(() => {
        toast.style.animation = 'fadeOut 0.3s ease-out';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}

function loadCalendarMonth(year, month) {
    if (currentCalendarData.isAdminMode) {
        loadAdminCalendarMonth(year, month);
    } else {
        loadEmployeeCalendarMonth(year, month);
    }
}

window.initializeAdjustments = initializeAdjustments;
window.initializeAdjustmentsCalendar = initializeAdjustmentsCalendar;
window.loadCalendarMonth = loadCalendarMonth;
window.closeDayEditModal = closeDayEditModal;
window.closeAdminDayModal = closeAdminDayModal;
window.togglePastRequests = togglePastRequests;
window.submitDayAdjustment = submitDayAdjustment;
window.submitMissingTimeRequest = submitMissingTimeRequest;
window.openEmployeeDayModal = openEmployeeDayModal;
window.openAddMissingTimeModal = openAddMissingTimeModal;
