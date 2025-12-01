/**
 * Server Adjustments Review Page - Admin time adjustment management
 */

let currentDenyRequestId = null;

function initializeAdjustmentsReview(guildId) {
    loadPendingRequests(guildId);
    loadPastRequests(guildId);
}

async function loadPendingRequests(guildId) {
    const container = document.getElementById('pending-requests-container');
    const badge = document.getElementById('pending-count-badge');

    try {
        const response = await fetch(`/api/guild/${guildId}/adjustments/pending`);
        const data = await response.json();

        if (!data.success) {
            throw new Error(data.error || 'Failed to load pending requests');
        }

        const requests = data.requests || [];

        if (requests.length > 0) {
            badge.textContent = requests.length;
            badge.style.display = 'inline-block';

            container.innerHTML = requests.map(renderRequestCard).join('');
            attachRequestHandlers();
        } else {
            badge.style.display = 'none';
            container.innerHTML = `
                <div style="text-align: center; padding: 40px; color: #10B981;">
                    <div style="font-size: 48px; margin-bottom: 10px;">✅</div>
                    <div style="font-size: 16px; font-weight: 600; margin-bottom: 5px;">All caught up!</div>
                    <div style="font-size: 13px; color: #8B949E;">No pending time adjustment requests</div>
                </div>
            `;
        }
    } catch (error) {
        console.error('Error loading pending requests:', error);
        container.innerHTML = `
            <div style="text-align: center; padding: 40px; color: #EF4444;">
                <div style="font-size: 24px; margin-bottom: 10px;">❌</div>
                <div>Failed to load requests</div>
                <div style="font-size: 12px; color: #8B949E; margin-top: 8px;">${escapeHtml(error.message)}</div>
            </div>
        `;
    }
}

async function loadPastRequests(guildId) {
    const container = document.getElementById('past-requests-container');

    try {
        const response = await fetch(`/api/guild/${guildId}/adjustments/resolved`);
        const data = await response.json();

        if (!data.success) {
            // Fallback to history endpoint
            const histResponse = await fetch(`/api/guild/${guildId}/adjustments/history`);
            const histData = await histResponse.json();
            if (histData.success) {
                const resolved = (histData.history || []).filter(r => r.status !== 'pending').slice(0, 10);
                renderPastRequests(container, resolved);
                return;
            }
            throw new Error(data.error || 'Failed to load past requests');
        }

        const requests = (data.requests || []).slice(0, 10); // Show last 10
        renderPastRequests(container, requests);

    } catch (error) {
        console.error('Error loading past requests:', error);
        container.innerHTML = `
            <div style="text-align: center; padding: 20px; color: #8B949E;">
                <div>No recent requests</div>
            </div>
        `;
    }
}

function renderPastRequests(container, requests) {
    if (requests.length === 0) {
        container.innerHTML = '<div style="text-align: center; padding: 20px; color: #8B949E;">No recent requests</div>';
        return;
    }

    container.innerHTML = requests.map(req => {
        const status = req.status || 'unknown';
        const statusColor = status === 'approved' ? '#10B981' : '#EF4444';
        const statusIcon = status === 'approved' ? '✅' : '❌';
        const date = new Date(req.created_at).toLocaleDateString();

        return `
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 12px; background: rgba(0,0,0,0.2); border-radius: 6px; margin-bottom: 8px;">
                <div>
                    <div style="font-weight: 600; color: #C9D1D9;">${escapeHtml(req.display_name || req.user_name || 'Unknown')}</div>
                    <div style="font-size: 12px; color: #8B949E;">${date} • ${escapeHtml((req.request_type || '').replace(/_/g, ' '))}</div>
                </div>
                <div style="color: ${statusColor}; font-weight: 600;">${statusIcon} ${status.toUpperCase()}</div>
            </div>
        `;
    }).join('');
}

function renderRequestCard(req) {
    const employeeName = req.display_name || req.user_name || 'Unknown Employee';
    const requestType = (req.request_type || '').replace(/_/g, ' ').toUpperCase();
    const reason = req.reason || 'No reason provided';

    const originalIn = req.original_clock_in ? new Date(req.original_clock_in).toLocaleString('en-US', {
        month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
    }) : 'N/A';
    const originalOut = req.original_clock_out ? new Date(req.original_clock_out).toLocaleString('en-US', {
        month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
    }) : 'N/A';
    const requestedIn = req.requested_clock_in ? new Date(req.requested_clock_in).toLocaleString('en-US', {
        month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
    }) : 'N/A';
    const requestedOut = req.requested_clock_out ? new Date(req.requested_clock_out).toLocaleString('en-US', {
        month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
    }) : 'N/A';

    const createdDate = new Date(req.created_at).toLocaleString();

    // Calculate time durations
    const calculateDuration = (clockIn, clockOut) => {
        if (!clockIn || !clockOut) return 0;
        const diff = new Date(clockOut) - new Date(clockIn);
        return diff / (1000 * 60 * 60); // Convert to hours
    };

    const originalDuration = calculateDuration(req.original_clock_in, req.original_clock_out);
    const requestedDuration = calculateDuration(req.requested_clock_in, req.requested_clock_out);
    const adjustment = requestedDuration - originalDuration;

    const adjustmentText = adjustment > 0 ? `+${adjustment.toFixed(2)}h` : `${adjustment.toFixed(2)}h`;
    const adjustmentColor = adjustment > 0 ? '#10B981' : (adjustment < 0 ? '#EF4444' : '#8B949E');

    // Format times as "HH:MM AM/PM"
    const formatTime = (dateStr) => {
        if (!dateStr) return 'None';
        return new Date(dateStr).toLocaleTimeString('en-US', {
            hour: '2-digit',
            minute: '2-digit',
            hour12: true
        });
    };

    const formatDate = (dateStr) => {
        if (!dateStr) return '';
        return new Date(dateStr).toLocaleDateString('en-US', {
            month: 'short',
            day: 'numeric'
        });
    };

    return `
        <div class="request-card" data-request-id="${req.id}">
            <div class="request-header">
                <div class="employee-avatar">${employeeName.charAt(0).toUpperCase()}</div>
                <div class="employee-info">
                    <h3>${escapeHtml(employeeName)}</h3>
                    <div class="request-date">Submitted ${createdDate}</div>
                </div>
                <div class="request-type-badge">${escapeHtml(requestType)}</div>
            </div>
            
            <div class="request-reason">
                <strong>Reason:</strong> ${escapeHtml(reason)}
            </div>
            
            <div class="time-comparison">
                <div class="time-before">
                    <h5>Original</h5>
                    <div style="font-size: 13px; color: #8B949E; margin-bottom: 4px;">${formatDate(req.original_clock_in) || 'None'}</div>
                    ${req.original_clock_in ? `
                        <div><strong>In:</strong> ${formatTime(req.original_clock_in)}</div>
                        <div><strong>Out:</strong> ${formatTime(req.original_clock_out)}</div>
                        <div style="margin-top: 6px; color: #D4AF37; font-weight: 600;">${originalDuration.toFixed(2)}h</div>
                    ` : '<div style="color: #8B949E;">No session</div>'}
                </div>
                <div class="arrow">→</div>
                <div class="time-after">
                    <h5>Requested</h5>
                    <div style="font-size: 13px; color: #8B949E; margin-bottom: 4px;">${formatDate(req.requested_clock_in)}</div>
                    <div><strong>In:</strong> ${formatTime(req.requested_clock_in)}</div>
                    <div><strong>Out:</strong> ${formatTime(req.requested_clock_out)}</div>
                    <div style="margin-top: 6px; color: #D4AF37; font-weight: 600;">${requestedDuration.toFixed(2)}h</div>
                </div>
            </div>
            
            <div style="text-align: center; padding: 12px; margin: 12px 0; background: rgba(0,0,0,0.3); border-radius: 8px; border-left: 3px solid ${adjustmentColor};">
                <div style="font-size: 12px; color: #8B949E; margin-bottom: 4px;">Total Adjustment</div>
                <div style="font-size: 24px; font-weight: 600; color: ${adjustmentColor};">${adjustmentText}</div>
            </div>
            
            <div class="request-actions">
                <button class="btn-approve" data-request-id="${req.id}">✅ Approve</button>
                <button class="btn-deny" data-request-id="${req.id}">❌ Deny</button>
            </div>
        </div>
    `;
}

function attachRequestHandlers() {
    document.querySelectorAll('.btn-approve').forEach(btn => {
        btn.addEventListener('click', () => handleApprove(btn.dataset.requestId));
    });

    document.querySelectorAll('.btn-deny').forEach(btn => {
        btn.addEventListener('click', () => handleDeny(btn.dataset.requestId));
    });
}

async function handleApprove(requestId) {
    if (!confirm('Are you sure you want to approve this request?')) return;

    const card = document.querySelector(`.request-card[data-request-id="${requestId}"]`);
    const button = card.querySelector('.btn-approve');

    button.disabled = true;
    button.textContent = 'Approving...';

    try {
        const response = await fetch(`/api/guild/${guildId}/adjustments/${requestId}/approve`, {
            method: 'POST'
        });
        const data = await response.json();

        if (data.success) {
            card.style.opacity = '0.5';
            card.innerHTML = `
                <div style="text-align: center; padding: 30px; color: #10B981;">
                    <div style="font-size: 48px; margin-bottom: 10px;">✅</div>
                    <div style="font-size: 16px; font-weight: 600;">Request Approved!</div>
                </div>
            `;

            showToast('Request approved successfully!', 'success');

            setTimeout(() => {
                loadPendingRequests(guildId);
                loadPastRequests(guildId);
            }, 1500);
        } else {
            throw new Error(data.error || 'Failed to approve');
        }
    } catch (error) {
        console.error('Error approving request:', error);
        showToast('Failed to approve: ' + error.message, 'error');
        button.disabled = false;
        button.textContent = '✅ Approve';
    }
}

function handleDeny(requestId) {
    currentDenyRequestId = requestId;
    document.getElementById('denial-reason').value = '';
    document.getElementById('deny-modal').style.display = 'flex';
}

function closeDenyModal() {
    currentDenyRequestId = null;
    document.getElementById('deny-modal').style.display = 'none';
}

async function submitDenial() {
    const reason = document.getElementById('denial-reason').value.trim();

    if (!reason) {
        alert('Please provide a reason for the denial');
        return;
    }

    if (reason.length > 500) {
        alert('Denial reason must be less than 500 characters');
        return;
    }

    const card = document.querySelector(`.request-card[data-request-id="${currentDenyRequestId}"]`);

    closeDenyModal();

    const button = card.querySelector('.btn-deny');
    button.disabled = true;
    button.textContent = 'Denying...';

    try {
        const response = await fetch(`/api/guild/${guildId}/adjustments/${currentDenyRequestId}/deny`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ reason: reason })
        });
        const data = await response.json();

        if (data.success) {
            card.style.opacity = '0.5';
            card.innerHTML = `
                <div style="text-align: center; padding: 30px; color: #EF4444;">
                    <div style="font-size: 48px; margin-bottom: 10px;">❌</div>
                    <div style="font-size: 16px; font-weight: 600;">Request Denied</div>
                </div>
            `;

            showToast('Request denied', 'success');

            setTimeout(() => {
                loadPendingRequests(guildId);
                loadPastRequests(guildId);
            }, 1500);
        } else {
            throw new Error(data.error || 'Failed to deny');
        }
    } catch (error) {
        console.error('Error denying request:', error);
        showToast('Failed to deny: ' + error.message, 'error');
        button.disabled = false;
        button.textContent = '❌ Deny';
    }
}

function showToast(message, type = 'info') {
    // Reuse existing toast if available, or create simple alert
    if (typeof window.showToast === 'function') {
        window.showToast(message, type);
    } else {
        console.log(`[${type.toUpperCase()}] ${message}`);
    }
}

function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}
