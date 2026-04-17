// WathiqNet Main JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Initialize Socket.IO connection
    initializeSocket();
    
    // Initialize sidebar toggle
    initializeSidebar();
    
    // Update current time
    updateTime();
    setInterval(updateTime, 1000);
    
    // Load alert count
    updateAlertCount();
    setInterval(updateAlertCount, 30000);
});

// Socket.IO Connection
let socket = null;

function initializeSocket() {
    try {
        socket = io();
        
        socket.on('connect', function() {
            console.log('WebSocket connected');
            updateConnectionStatus(true);
        });
        
        socket.on('disconnect', function() {
            console.log('WebSocket disconnected');
            updateConnectionStatus(false);
        });
        
        socket.on('new_log', function(log) {
            console.log('New log received:', log);
            // Trigger page-specific handlers
            if (typeof handleNewLog === 'function') {
                handleNewLog(log);
            }
        });
        
        socket.on('new_alert', function(alert) {
            console.log('New alert received:', alert);
            showAlertNotification(alert);
            updateAlertCount();
            
            if (typeof handleNewAlert === 'function') {
                handleNewAlert(alert);
            }
        });
        
        socket.on('device_update', function(device) {
            console.log('Device update:', device);
            if (typeof handleDeviceUpdate === 'function') {
                handleDeviceUpdate(device);
            }
        });
        
        socket.on('stats_update', function(stats) {
            if (typeof handleStatsUpdate === 'function') {
                handleStatsUpdate(stats);
            }
        });
        
    } catch (error) {
        console.error('Socket.IO initialization failed:', error);
    }
}

function updateConnectionStatus(connected) {
    const statusEl = document.getElementById('connection-status');
    if (statusEl) {
        if (connected) {
            statusEl.innerHTML = '<i class="bi bi-wifi"></i> Connected';
            statusEl.className = 'badge bg-success';
        } else {
            statusEl.innerHTML = '<i class="bi bi-wifi-off"></i> Disconnected';
            statusEl.className = 'badge bg-danger';
        }
    }
}

// Sidebar Toggle
function initializeSidebar() {
    const sidebar = document.getElementById('sidebar');
    const toggleBtn = document.getElementById('sidebarToggle');
    
    if (toggleBtn && sidebar) {
        toggleBtn.addEventListener('click', function() {
            if (window.innerWidth <= 768) {
                sidebar.classList.toggle('show');
            } else {
                sidebar.classList.toggle('collapsed');
                const mainContent = document.querySelector('.main-content');
                if (mainContent) {
                    if (sidebar.classList.contains('collapsed')) {
                        mainContent.style.marginLeft = '70px';
                    } else {
                        mainContent.style.marginLeft = '250px';
                    }
                }
            }
        });
    }
    
    // Close sidebar on click outside (mobile)
    document.addEventListener('click', function(e) {
        if (window.innerWidth <= 768 && sidebar && sidebar.classList.contains('show')) {
            if (!sidebar.contains(e.target) && !toggleBtn.contains(e.target)) {
                sidebar.classList.remove('show');
            }
        }
    });
}

// Update time display
function updateTime() {
    const timeEl = document.getElementById('current-time');
    if (timeEl) {
        const now = new Date();
        timeEl.textContent = now.toLocaleTimeString();
    }
}

// Update alert count in sidebar
function updateAlertCount() {
    fetch('/api/alerts')
        .then(response => response.json())
        .then(alerts => {
            const countEl = document.getElementById('alert-count');
            if (countEl) {
                const count = alerts.length;
                if (count > 0) {
                    countEl.textContent = count > 99 ? '99+' : count;
                    countEl.style.display = 'inline';
                } else {
                    countEl.style.display = 'none';
                }
            }
        })
        .catch(error => console.error('Error fetching alerts:', error));
}

// Show alert notification
function showAlertNotification(alert) {
    // Create toast notification
    const toastContainer = document.getElementById('toast-container') || createToastContainer();
    
    const severityColors = {
        'critical': 'bg-danger',
        'high': 'bg-warning',
        'medium': 'bg-info',
        'low': 'bg-success'
    };
    
    const toastHtml = `
        <div class="toast show" role="alert" aria-live="assertive" aria-atomic="true">
            <div class="toast-header ${severityColors[alert.severity] || 'bg-secondary'} text-white">
                <i class="bi bi-exclamation-triangle me-2"></i>
                <strong class="me-auto">${alert.alert_type.replace('_', ' ').toUpperCase()}</strong>
                <small>Just now</small>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="toast"></button>
            </div>
            <div class="toast-body">
                ${alert.description.substring(0, 100)}...
            </div>
        </div>
    `;
    
    const toastElement = document.createElement('div');
    toastElement.innerHTML = toastHtml;
    toastContainer.appendChild(toastElement.firstElementChild);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        const toast = toastContainer.querySelector('.toast');
        if (toast) {
            toast.remove();
        }
    }, 5000);
}

function createToastContainer() {
    const container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'toast-container position-fixed top-0 end-0 p-3';
    container.style.zIndex = '9999';
    document.body.appendChild(container);
    return container;
}

// Utility Functions
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString();
}

function getSeverityBadge(severity) {
    const badges = {
        'critical': '<span class="badge bg-danger">Critical</span>',
        'high': '<span class="badge bg-warning text-dark">High</span>',
        'medium': '<span class="badge bg-info">Medium</span>',
        'low': '<span class="badge bg-success">Low</span>'
    };
    return badges[severity] || '<span class="badge bg-secondary">Unknown</span>';
}
