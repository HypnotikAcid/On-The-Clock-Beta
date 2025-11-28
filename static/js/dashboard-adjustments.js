/**
 * Time Adjustments Calendar - Phase 1
 * Interactive calendar view for time tracking sessions
 */

// Global state
let currentCalendarData = {
    year: new Date().getFullYear(),
    month: new Date().getMonth() + 1, // JavaScript months are 0-indexed
    guildId: null,
    userId: null,
    timezone: null,
    days: []
};

/**
 * Initialize the calendar when page loads
 */
function initializeAdjustmentsCalendar(guildId, userId) {
    if (!guildId || !userId) {
        console.error('Calendar initialization requires guildId and userId');
        return;
    }

    currentCalendarData.guildId = guildId;
    currentCalendarData.userId = userId;

    // Set up event listeners
    setupCalendarEventListeners();

    // Load current month's data
    loadCalendarMonth(currentCalendarData.year, currentCalendarData.month);
}

/**
 * Set up event listeners for calendar navigation
 */
function setupCalendarEventListeners() {
    const prevBtn = document.getElementById('calendar-prev-month');
    const nextBtn = document.getElementById('calendar-next-month');

    if (prevBtn) {
        prevBtn.addEventListener('click', () => {
            navigateMonth(-1);
        });
    }

    if (nextBtn) {
        nextBtn.addEventListener('click', () => {
            navigateMonth(1);
        });
    }
}

/**
 * Navigate to previous/next month
 * @param {number} direction - -1 for previous, 1 for next
 */
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

/**
 * Load calendar data for a specific month
 * @param {number} year - Target year
 * @param {number} month - Target month (1-12)
 */
async function loadCalendarMonth(year, month) {
    const { guildId, userId } = currentCalendarData;

    if (!guildId || !userId) {
        console.error('Cannot load calendar: missing guildId or userId');
        return;
    }

    // Show loading state
    const calendarContainer = document.getElementById('calendar-grid');
    if (calendarContainer) {
        calendarContainer.innerHTML = `
            <div style="grid-column: 1 / -1; text-align: center; padding: 40px;">
                <div style="font-size: 24px; margin-bottom: 10px;">⏳</div>
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

        // Update global state
        currentCalendarData.year = result.data.year;
        currentCalendarData.month = result.data.month;
        currentCalendarData.timezone = result.data.timezone;
        currentCalendarData.days = result.data.days;

        // Render the calendar
        renderCalendar();

    } catch (error) {
        console.error('Error loading calendar:', error);
        if (calendarContainer) {
            calendarContainer.innerHTML = `
                <div style="grid-column: 1 / -1; text-align: center; padding: 40px;">
                    <div style="font-size: 24px; margin-bottom: 10px; color: #EF4444;">❌</div>
                    <div style="color: #EF4444;">Failed to load calendar</div>
                    <div style="color: #8B949E; font-size: 12px; margin-top: 8px;">${escapeHtml(error.message)}</div>
                </div>
            `;
        }
    }
}

/**
 * Render the full calendar grid
 */
function renderCalendar() {
    const { year, month, days } = currentCalendarData;

    // Update month/year header
    const monthNames = ['January', 'February', 'March', 'April', 'May', 'June',
        'July', 'August', 'September', 'October', 'November', 'December'];
    const monthHeader = document.getElementById('calendar-month-year');
    if (monthHeader) {
        monthHeader.textContent = `${monthNames[month - 1]} ${year}`;
    }

    // Get calendar container
    const calendarContainer = document.getElementById('calendar-grid');
    if (!calendarContainer) {
        console.error('Calendar grid container not found');
        return;
    }

    // Calculate calendar grid
    const firstDay = new Date(year, month - 1, 1);
    const lastDay = new Date(year, month, 0);
    const daysInMonth = lastDay.getDate();
    const startingDayOfWeek = firstDay.getDay(); // 0 = Sunday

    // Create days map for quick lookup
    const daysMap = {};
    days.forEach(day => {
        daysMap[day.date] = day;
    });

    // Build calendar HTML
    let html = '';

    // Day headers
    const dayHeaders = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
    dayHeaders.forEach(header => {
        html += `<div class="calendar-day-header">${header}</div>`;
    });

    // Empty cells before the first day of the month
    for (let i = 0; i < startingDayOfWeek; i++) {
        html += '<div class="calendar-day empty"></div>';
    }

    // Render each day of the month
    for (let day = 1; day <= daysInMonth; day++) {
        const date = new Date(year, month - 1, day);
        const dateStr = date.toISOString().split('T')[0]; // YYYY-MM-DD format
        const dayData = daysMap[dateStr];

        html += renderDayCell(day, dayData, dateStr);
    }

    calendarContainer.innerHTML = html;

    // Add click handlers to day cells
    attachDayCellHandlers();
}

/**
 * Render a single day cell
 * @param {number} dayNumber - Day of month (1-31)
 * @param {object} dayData - Session data for this day (or null)
 * @param {string} dateStr - ISO date string (YYYY-MM-DD)
 * @returns {string} HTML for the day cell
 */
function renderDayCell(dayNumber, dayData, dateStr) {
    const hasData = dayData && dayData.sessions && dayData.sessions.length > 0;
    const hours = hasData ? dayData.total_hours : 0;
    const sessionCount = hasData ? dayData.sessions.length : 0;

    let cellClass = 'calendar-day';
    if (hasData) {
        cellClass += ' has-sessions';
    }

    // Color coding based on hours worked
    let colorClass = '';
    if (hours > 0) {
        if (hours >= 8) {
            colorClass = 'full-day'; // 8+ hours = full day
        } else if (hours >= 4) {
            colorClass = 'half-day'; // 4-7.99 hours = half day
        } else {
            colorClass = 'partial-day'; // < 4 hours = partial
        }
    }

    return `
        <div class="calendar-day ${cellClass} ${colorClass}" data-date="${dateStr}" data-has-sessions="${hasData}">
            <div class="day-number">${dayNumber}</div>
            ${hasData ? `
                <div class="day-hours">${hours}h</div>
                <div class="day-sessions">${sessionCount} session${sessionCount !== 1 ? 's' : ''}</div>
            ` : '<div class="day-no-work">No work</div>'}
        </div>
    `;
}

/**
 * Attach click event handlers to day cells
 */
function attachDayCellHandlers() {
    const dayCells = document.querySelectorAll('.calendar-day[data-has-sessions="true"]');

    dayCells.forEach(cell => {
        cell.addEventListener('click', () => {
            const dateStr = cell.getAttribute('data-date');
            handleDayClick(dateStr);
        });

        // Add hover effect cursor
        cell.style.cursor = 'pointer';
    });
}

/**
 * Handle clicking on a calendar day
 * @param {string} dateStr - ISO date string (YYYY-MM-DD)
 */
function handleDayClick(dateStr) {
    const dayData = currentCalendarData.days.find(d => d.date === dateStr);

    if (!dayData) {
        console.log('No data for selected day');
        return;
    }

    console.log('Day clicked:', dateStr, dayData);

    // TODO Phase 2: Open edit modal for this day's sessions
    // For now, just show an alert
    showDayDetailsPreview(dateStr, dayData);
}

/**
 * Show a preview of the day's sessions (placeholder for Phase 2)
 * @param {string} dateStr - ISO date string
 * @param {object} dayData - Session data
 */
function showDayDetailsPreview(dateStr, dayData) {
    const dateObj = new Date(dateStr + 'T12:00:00'); // Noon to avoid timezone issues
    const formattedDate = dateObj.toLocaleDateString('en-US', {
        weekday: 'long',
        year: 'numeric',
        month: 'long',
        day: 'numeric'
    });

    let message = `📅 ${formattedDate}\n\n`;
    message += `Total Hours: ${dayData.total_hours}\n`;
    message += `Sessions: ${dayData.sessions.length}\n\n`;

    dayData.sessions.forEach((session, index) => {
        const clockIn = session.clock_in ? new Date(session.clock_in).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }) : 'N/A';
        const clockOut = session.clock_out ? new Date(session.clock_out).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }) : 'Still clocked in';
        const duration = session.duration_seconds ? `${(session.duration_seconds / 3600).toFixed(2)}h` : 'N/A';

        message += `Session ${index + 1}:\n`;
        message += `  In: ${clockIn}\n`;
        message += `  Out: ${clockOut}\n`;
        message += `  Duration: ${duration}\n\n`;
    });

    message += '\n[Phase 2 will add editing functionality here]';

    alert(message);
}

// Export functions for global access
window.initializeAdjustmentsCalendar = initializeAdjustmentsCalendar;
window.loadCalendarMonth = loadCalendarMonth;
