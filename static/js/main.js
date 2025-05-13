// Main JavaScript file for the network security testing tool

// Toggle proxy scanning
function toggleProxyScanning(btn) {
    fetch('/api/toggle-proxy-scanning', {
        method: 'POST'
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'enabled') {
            document.getElementById('proxy-status-text').textContent = 'Active';
            document.getElementById('proxy-status').classList.remove('bg-info');
            document.getElementById('proxy-status').classList.add('bg-success');
            if (btn) {
                btn.textContent = 'Stop Scanning';
                btn.classList.remove('btn-success');
                btn.classList.add('btn-danger');
            }
        } else {
            document.getElementById('proxy-status-text').textContent = 'Inactive';
            document.getElementById('proxy-status').classList.remove('bg-success');
            document.getElementById('proxy-status').classList.add('bg-info');
            if (btn) {
                btn.textContent = 'Start Scanning';
                btn.classList.remove('btn-danger');
                btn.classList.add('btn-success');
            }
        }
    })
    .catch(error => {
        console.error('Error toggling proxy scanning:', error);
        alert('Failed to toggle proxy scanning. Please try again.');
    });
}

// Toggle amplification scanning
function toggleAmpScanning(btn) {
    fetch('/api/toggle-amp-scanning', {
        method: 'POST'
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'enabled') {
            document.getElementById('amp-status-text').textContent = 'Active';
            document.getElementById('amp-status').classList.remove('bg-info');
            document.getElementById('amp-status').classList.add('bg-success');
            if (btn) {
                btn.textContent = 'Stop Scanning';
                btn.classList.remove('btn-success');
                btn.classList.add('btn-danger');
            }
        } else {
            document.getElementById('amp-status-text').textContent = 'Inactive';
            document.getElementById('amp-status').classList.remove('bg-success');
            document.getElementById('amp-status').classList.add('bg-info');
            if (btn) {
                btn.textContent = 'Start Scanning';
                btn.classList.remove('btn-danger');
                btn.classList.add('btn-success');
            }
        }
    })
    .catch(error => {
        console.error('Error toggling amplification scanning:', error);
        alert('Failed to toggle amplification scanning. Please try again.');
    });
}

// Update status to reflect current state
function updateStatus() {
    fetch('/api/stats')
    .then(response => response.json())
    .then(data => {
        // Update proxy status
        if (data.proxy_scanning) {
            document.getElementById('proxy-status-text').textContent = 'Active';
            document.getElementById('proxy-status').classList.remove('bg-info');
            document.getElementById('proxy-status').classList.add('bg-success');
            const btns = document.querySelectorAll('.toggle-proxy-btn');
            btns.forEach(btn => {
                btn.textContent = 'Stop Scanning';
                btn.classList.remove('btn-success');
                btn.classList.add('btn-danger');
            });
        } else {
            document.getElementById('proxy-status-text').textContent = 'Inactive';
            document.getElementById('proxy-status').classList.remove('bg-success');
            document.getElementById('proxy-status').classList.add('bg-info');
            const btns = document.querySelectorAll('.toggle-proxy-btn');
            btns.forEach(btn => {
                btn.textContent = 'Start Scanning';
                btn.classList.remove('btn-danger');
                btn.classList.add('btn-success');
            });
        }

        // Update amplification status
        if (data.amp_scanning) {
            document.getElementById('amp-status-text').textContent = 'Active';
            document.getElementById('amp-status').classList.remove('bg-info');
            document.getElementById('amp-status').classList.add('bg-success');
            const btns = document.querySelectorAll('.toggle-amp-btn');
            btns.forEach(btn => {
                btn.textContent = 'Stop Scanning';
                btn.classList.remove('btn-success');
                btn.classList.add('btn-danger');
            });
        } else {
            document.getElementById('amp-status-text').textContent = 'Inactive';
            document.getElementById('amp-status').classList.remove('bg-success');
            document.getElementById('amp-status').classList.add('bg-info');
            const btns = document.querySelectorAll('.toggle-amp-btn');
            btns.forEach(btn => {
                btn.textContent = 'Start Scanning';
                btn.classList.remove('btn-danger');
                btn.classList.add('btn-success');
            });
        }

        // Update stats counts
        updateCounters(data);
    })
    .catch(error => {
        console.error('Error getting status:', error);
    });
}

// Update counters based on stats data
function updateCounters(data) {
    // Update counters if they exist on the page
    if (document.getElementById('proxy-total-count')) {
        document.getElementById('proxy-total-count').textContent = data.proxies_total || 0;
        document.getElementById('proxy-working-count').textContent = data.proxies_working || 0;
        
        const percentage = data.proxies_total > 0 ? Math.round((data.proxies_working / data.proxies_total) * 100) : 0;
        const progressBar = document.getElementById('proxy-progress');
        if (progressBar) {
            progressBar.style.width = `${percentage}%`;
            progressBar.textContent = `${percentage}%`;
            progressBar.setAttribute('aria-valuenow', percentage);
        }
    }
    
    if (document.getElementById('amp-total-count')) {
        document.getElementById('amp-total-count').textContent = data.amp_servers_total || 0;
        document.getElementById('amp-working-count').textContent = data.amp_servers_working || 0;
        
        const percentage = data.amp_servers_total > 0 ? Math.round((data.amp_servers_working / data.amp_servers_total) * 100) : 0;
        const progressBar = document.getElementById('amp-progress');
        if (progressBar) {
            progressBar.style.width = `${percentage}%`;
            progressBar.textContent = `${percentage}%`;
            progressBar.setAttribute('aria-valuenow', percentage);
        }
    }
    
    if (document.getElementById('attacks-count')) {
        document.getElementById('attacks-count').textContent = data.attacks_running || 0;
    }
}

// Test proxies
function testProxies() {
    fetch('/api/test-proxies', {
        method: 'POST'
    })
    .then(response => response.json())
    .then(data => {
        alert(data.status);
    })
    .catch(error => {
        console.error('Error testing proxies:', error);
        alert('Failed to test proxies. Please try again.');
    });
}

// Test amplification servers
function testAmplification() {
    fetch('/api/test-amplification', {
        method: 'POST'
    })
    .then(response => response.json())
    .then(data => {
        alert(data.status);
    })
    .catch(error => {
        console.error('Error testing amplification servers:', error);
        alert('Failed to test amplification servers. Please try again.');
    });
}

// Clear proxies
function clearProxies() {
    if (confirm('Are you sure you want to clear all proxies?')) {
        fetch('/api/clear-proxies', {
            method: 'POST'
        })
        .then(response => response.json())
        .then(data => {
            alert(data.status);
            updateStatus();
        })
        .catch(error => {
            console.error('Error clearing proxies:', error);
            alert('Failed to clear proxies. Please try again.');
        });
    }
}

// Clear amplification servers
function clearAmplification() {
    if (confirm('Are you sure you want to clear all amplification servers?')) {
        fetch('/api/clear-amplification', {
            method: 'POST'
        })
        .then(response => response.json())
        .then(data => {
            alert(data.status);
            updateStatus();
        })
        .catch(error => {
            console.error('Error clearing amplification servers:', error);
            alert('Failed to clear amplification servers. Please try again.');
        });
    }
}

// Update the UI periodically
function startAutoUpdates() {
    updateStatus();
    setInterval(updateStatus, 5000);
}

// Initialize when the DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    // Set up event listeners for buttons if they exist
    const proxyToggleButtons = document.querySelectorAll('.toggle-proxy-btn');
    proxyToggleButtons.forEach(btn => {
        btn.addEventListener('click', function() {
            toggleProxyScanning(this);
        });
    });
    
    const ampToggleButtons = document.querySelectorAll('.toggle-amp-btn');
    ampToggleButtons.forEach(btn => {
        btn.addEventListener('click', function() {
            toggleAmpScanning(this);
        });
    });
    
    const testProxyButtons = document.querySelectorAll('.test-proxies-btn');
    testProxyButtons.forEach(btn => {
        btn.addEventListener('click', testProxies);
    });
    
    const testAmpButtons = document.querySelectorAll('.test-amp-btn');
    testAmpButtons.forEach(btn => {
        btn.addEventListener('click', testAmplification);
    });
    
    const clearProxyButtons = document.querySelectorAll('.clear-proxies-btn');
    clearProxyButtons.forEach(btn => {
        btn.addEventListener('click', clearProxies);
    });
    
    const clearAmpButtons = document.querySelectorAll('.clear-amp-btn');
    clearAmpButtons.forEach(btn => {
        btn.addEventListener('click', clearAmplification);
    });
    
    // Start auto-updates
    startAutoUpdates();
});