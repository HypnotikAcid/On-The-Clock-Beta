/**
 * Time Adjustments Calendar - Interactive Visual Calendar
 * Click days to view/edit timestamps with status indicators
 * Pending = alert icon, Approved = green, Denied = red
 */

let currentCalendarData = {
    year: new Date().getFullYear(),
    month: new Date().getMonth() + 1,
    guildId: null,
    userId: null,
    timezone: null,
    days: []
};

function initializeAdjustmentsCalendar(guildId, userId) {
    if (!guildId || !userId) {
        console.error('Calendar initialization requires guildId and userId');
        return;
    }

    currentCalendarData.guildId = guildId;
    currentCalendarData.userId = userId;

    setupCalendarEventListeners();
    loadCalendarMonth(currentCalendarData.year, currentCalendarData.month);
}

function setupCalendarEventListeners() {
    const prevBtn = document.getElementById('calendar-prev-month');
    const nextBtn = document.getElementById('calendar-next-month');

    if (prevBtn) {
        prevBtn.addEventListener('click', () => navigateMonth(-1));
    }
    if (nextBtn) {
        nextBtn.addEventListener('click', () => navigateMonth(1));
    }
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

    loadCalendarMonth(newYear, newMonth);
}

async function loadCalendarMonth(year, month) {
    const { guildId, userId } = currentCalendarData;

    if (!guildId || !userId) {
        console.error('Cannot load calendar: missing guildId or userId');
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

        renderCalendar();

    } catch (error) {
        console.error('Error loading calendar:', error);
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

function renderCalendar() {
    const { year, month, days } = currentCalendarData;

    const monthNames = ['January', 'February', 'March', 'April', 'May', 'June',
        'July', 'August', 'September', 'October', 'November', 'December'];
    const monthHeader = document.getElementById('calendar-month-year');
    if (monthHeader) {
        monthHeader.textContent = `${monthNames[month - 1]} ${year}`;
    }

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

        html += renderDayCell(day, dayData, dateStr);
    }

    calendarContainer.innerHTML = html;
    attachDayCellHandlers();
}

function renderDayCell(dayNumber, dayData, dateStr) {
    const hasData = dayData && dayData.sessions && dayData.sessions.length > 0;
    const hours = hasData ? dayData.total_hours : 0;
    const sessionCount = hasData ? dayData.sessions.length : 0;
    const adjustmentStatus = dayData?.adjustment_status || null;

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

    if (adjustmentStatus === 'pending') {
        statusIndicator = '<span class="status-indicator pending" title="Adjustment pending review">&#9888;</span>';
        statusBorder = 'border-color: #F59E0B !important;';
    } else if (adjustmentStatus === 'approved') {
        statusIndicator = '<span class="status-indicator approved" title="Adjustment approved">&#10003;</span>';
        statusBorder = 'border-color: #10B981 !important;';
    } else if (adjustmentStatus === 'denied') {
        statusIndicator = '<span class="status-indicator denied" title="Adjustment denied">&#10007;</span>';
        statusBorder = 'border-color: #EF4444 !important;';
    }

    const clickable = hasData ? 'style="cursor: pointer;' + statusBorder + '"' : 'style="' + statusBorder + '"';

    return `
        <div class="calendar-day ${cellClass}" data-date="${dateStr}" data-has-sessions="${hasData}" ${clickable}>
            <div class="day-number">${dayNumber}${statusIndicator}</div>
            ${hasData ? `
                <div class="day-hours">${hours}h</div>
                <div class="day-sessions">${sessionCount} session${sessionCount !== 1 ? 's' : ''}</div>
            ` : '<div class="day-no-work"></div>'}
        </div>
    `;
}

function attachDayCellHandlers() {
    const dayCells = document.querySelectorAll('.calendar-day[data-has-sessions="true"]');

    dayCells.forEach(cell => {
        cell.addEventListener('click', () => {
            const dateStr = cell.getAttribute('data-date');
            openDayEditModal(dateStr);
        });
    });
}

function openDayEditModal(dateStr) {
    const dayData = currentCalendarData.days.find(d => d.date === dateStr);

    if (!dayData) {
        console.log('No data for selected day');
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

        sessionsHtml += `
            <div class="edit-session-row" data-session-id="${session.id}">
                <div class="session-label">Session ${index + 1}</div>
                <div class="session-times">
                    <label>
                        Clock In:
                        <input type="time" class="time-input clock-in" value="${clockInTime}" data-original="${clockInTime}">
                    </label>
                    <label>
                        Clock Out:
                        <input type="time" class="time-input clock-out" value="${clockOutTime}" data-original="${clockOutTime}" ${!session.clock_out ? 'disabled placeholder="Still active"' : ''}>
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
    if (existingModal) {
        existingModal.remove();
    }

    document.body.insertAdjacentHTML('beforeend', modalHtml);

    document.querySelectorAll('.time-input').forEach(input => {
        input.addEventListener('change', updateDurationDisplay);
    });
}

function closeDayEditModal() {
    const modal = document.getElementById('day-edit-overlay');
    if (modal) {
        modal.remove();
    }
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
            loadCalendarMonth(currentCalendarData.year, currentCalendarData.month);
            
            if (typeof loadUserAdjustmentHistory === 'function') {
                loadUserAdjustmentHistory(currentCalendarData.guildId);
            }
            
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

function showToast(message, type = 'info') {
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
    `;
    document.body.appendChild(toast);

    setTimeout(() => {
        toast.style.animation = 'fadeOut 0.3s ease-out';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

window.initializeAdjustmentsCalendar = initializeAdjustmentsCalendar;
window.loadCalendarMonth = loadCalendarMonth;
window.closeDayEditModal = closeDayEditModal;
