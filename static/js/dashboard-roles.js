/**
 * Dashboard Role-Based Access Control
 * Handles UI visibility and data loading based on user role tier
 */

// Security: HTML escape utility to prevent XSS (duplicate for safety if loaded before dashboard-core.js)
if (typeof escapeHtml !== 'function') {
    function escapeHtml(text) {
        if (text === null || text === undefined) return '';
        const div = document.createElement('div');
        div.textContent = String(text);
        return div.innerHTML;
    }
}

// Update Sidebar and UI based on Role
function updateSidebarForRole(roleTier) {
    const adminItems = document.querySelectorAll('.admin-only');
    const employeeItems = document.querySelectorAll('.employee-only');

    // Sections to toggle
    const adminReviewSection = document.getElementById('admin-adjustment-review');
    const employeeHistorySection = document.getElementById('employee-adjustment-history');
    const employeeFormSection = document.getElementById('employee-adjustment-form-container');

    if (roleTier === 'owner' || roleTier === 'admin') {
        // Show admin items
        adminItems.forEach(item => item.style.display = 'block');
        if (adminReviewSection) adminReviewSection.style.display = 'block';

        // Admins are also employees, so show employee stuff too
        employeeItems.forEach(item => item.style.display = 'block');
        if (employeeHistorySection) employeeHistorySection.style.display = 'block';
        if (employeeFormSection) employeeFormSection.style.display = 'block';

        document.body.classList.add('role-admin');
    } else if (roleTier === 'employee') {
        // Hide admin items
        adminItems.forEach(item => item.style.display = 'none');
        if (adminReviewSection) adminReviewSection.style.display = 'none';

        // Show employee items
        employeeItems.forEach(item => item.style.display = 'block');
        if (employeeHistorySection) employeeHistorySection.style.display = 'block';
        if (employeeFormSection) employeeFormSection.style.display = 'block';

        document.body.classList.remove('role-admin');
    } else {
        // No access or basic user
        adminItems.forEach(item => item.style.display = 'none');
        employeeItems.forEach(item => item.style.display = 'none');
        if (adminReviewSection) adminReviewSection.style.display = 'none';
        if (employeeHistorySection) employeeHistorySection.style.display = 'none';
        if (employeeFormSection) employeeFormSection.style.display = 'none';
    }
}

// Load User Adjustment History
async function loadUserAdjustmentHistory(guildId) {
    const container = document.getElementById('user-adjustments-list');
    if (!container) return;

    container.innerHTML = '<div class="empty-state">Loading history...</div>';

    try {
        const response = await fetch(`/api/guild/${guildId}/adjustments/history`);
        const data = await response.json();

        if (data.success) {
            if (data.requests.length > 0) {
                container.innerHTML = data.requests.map(req => {
                    let statusColor = '#8B949E';
                    if (req.status === 'approved') statusColor = '#10B981';
                    if (req.status === 'denied') statusColor = '#EF4444';
                    if (req.status === 'pending') statusColor = '#F59E0B';

                    return `
                    <div class="adjustment-card" style="border-left: 4px solid ${statusColor};">
                        <div class="adjustment-header">
                            <div style="font-weight: 600; color: #C9D1D9;">
                                ${req.request_type.replace('_', ' ').toUpperCase()}
                            </div>
                            <div style="font-size: 12px; color: ${statusColor}; border: 1px solid ${statusColor}; padding: 2px 8px; border-radius: 12px;">
                                ${req.status.toUpperCase()}
                            </div>
                        </div>
                        
                        <div style="margin-bottom: 10px; color: #8B949E; font-size: 13px;">
                            ${new Date(req.created_at).toLocaleString()}
                        </div>
                        
                        <div style="margin-bottom: 10px; color: #C9D1D9; font-size: 14px;">
                            <strong>Reason:</strong> ${escapeHtml(req.reason)}
                        </div>
                        
                        <div class="before-after-grid">
                            <div class="before">
                                <h5 style="color: #8B949E; margin-bottom: 4px;">Original</h5>
                                <div style="font-size: 12px;">
                                    ${req.original_clock_in ? new Date(req.original_clock_in).toLocaleString() : 'None'}
                                </div>
                            </div>
                            <div class="arrow">&rarr;</div>
                            <div class="after">
                                <h5 style="color: #D4AF37; margin-bottom: 4px;">Requested</h5>
                                <div style="font-size: 12px;">
                                    ${req.requested_clock_in ? new Date(req.requested_clock_in).toLocaleString() : 'No Change'}
                                </div>
                            </div>
                        </div>
                    </div>
                `}).join('');
            } else {
                container.innerHTML = '<div class="empty-state">No adjustment history found.</div>';
            }
        } else {
            container.innerHTML = `<div class="empty-state" style="color: #EF4444;">Error: ${escapeHtml(data.error)}</div>`;
        }
    } catch (error) {
        console.error('Error loading history:', error);
        container.innerHTML = '<div class="empty-state" style="color: #EF4444;">Failed to load history.</div>';
    }
}
