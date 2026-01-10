function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 15000) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
    
    try {
        const response = await fetch(url, {
            ...options,
            signal: controller.signal
        });
        clearTimeout(timeoutId);
        return response;
    } catch (error) {
        clearTimeout(timeoutId);
        if (error.name === 'AbortError') {
            throw new Error('Request timed out - please try again');
        }
        throw error;
    }
}

let loadingTimeoutId = null;
let slowLoadingTimeoutId = null;
let loadingSafetyTimeoutId = null;

function clearLoadingTimeouts() {
    if (loadingTimeoutId) clearTimeout(loadingTimeoutId);
    if (slowLoadingTimeoutId) clearTimeout(slowLoadingTimeoutId);
    if (loadingSafetyTimeoutId) clearTimeout(loadingSafetyTimeoutId);
    loadingTimeoutId = null;
    slowLoadingTimeoutId = null;
    loadingSafetyTimeoutId = null;
}

function showLoading(message = 'Loading...') {
    const overlay = document.getElementById('loadingOverlay');
    if (!overlay) return;
    const textEl = overlay.querySelector('.loading-text');
    if (textEl) textEl.textContent = message;
    overlay.style.display = 'flex';
    overlay.classList.add('active');
    
    clearLoadingTimeouts();
    
    slowLoadingTimeoutId = setTimeout(() => {
        if (textEl && overlay.classList.contains('active')) {
            textEl.textContent = 'Taking longer than expected...';
        }
    }, 5000);
    
    loadingSafetyTimeoutId = setTimeout(() => {
        hideLoading();
        console.warn('Loading overlay auto-hidden after 30 seconds');
    }, 30000);
}

function hideLoading() {
    const overlay = document.getElementById('loadingOverlay');
    if (overlay) {
        overlay.classList.remove('active');
        overlay.style.display = 'none';
    }
    clearLoadingTimeouts();
}

function showNotification(message, type = 'info') {
    const existing = document.querySelector('.notification-toast');
    if (existing) existing.remove();
    
    const toast = document.createElement('div');
    toast.className = `notification-toast notification-${type}`;
    toast.textContent = message;
    toast.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px 25px;
        border-radius: 8px;
        color: white;
        font-weight: 500;
        z-index: 10000;
        animation: slideIn 0.3s ease;
        max-width: 400px;
        box-shadow: 0 4px 15px rgba(0,0,0,0.3);
    `;
    
    if (type === 'success') {
        toast.style.background = 'linear-gradient(135deg, #10B981, #059669)';
    } else if (type === 'error') {
        toast.style.background = 'linear-gradient(135deg, #EF4444, #DC2626)';
    } else {
        toast.style.background = 'linear-gradient(135deg, #3B82F6, #2563EB)';
    }
    
    document.body.appendChild(toast);
    
    setTimeout(() => {
        toast.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

async function apiCall(url, options = {}) {
    try {
        const response = await fetchWithTimeout(url, {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Request failed');
        }
        
        return data;
    } catch (error) {
        console.error('API call failed:', error);
        throw error;
    }
}

function formatDuration(minutes) {
    if (!minutes && minutes !== 0) return '--';
    const hours = Math.floor(minutes / 60);
    const mins = Math.round(minutes % 60);
    if (hours === 0) return `${mins}m`;
    return `${hours}h ${mins}m`;
}

function formatTime(dateString) {
    if (!dateString) return '--';
    const date = new Date(dateString);
    return date.toLocaleTimeString('en-US', { 
        hour: 'numeric', 
        minute: '2-digit',
        hour12: true 
    });
}

function formatDate(dateString) {
    if (!dateString) return '--';
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', { 
        month: 'short', 
        day: 'numeric',
        year: 'numeric'
    });
}

window.DashboardUtils = {
    escapeHtml,
    fetchWithTimeout,
    showLoading,
    hideLoading,
    showNotification,
    apiCall,
    formatDuration,
    formatTime,
    formatDate
};
