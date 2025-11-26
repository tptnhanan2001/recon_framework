// API Base URL - Auto-detect based on current location
const API_BASE = (() => {
    // If running from file:// protocol, use localhost
    if (window.location.protocol === 'file:') {
        return 'http://localhost:5000/api';
    }
    // If running from server, use relative path
    return '/api';
})();

// State Management
const state = {
    authenticated: false,
    activeTarget: null,
    targets: [],
    lastRun: null,
    currentScanId: null,
    logsPollingInterval: null,
    statusPollingInterval: null,
    isScanning: false
};

const NUCLEI_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info', 'generic'];
let nucleiFiltersInitialized = false;
let currentNucleiLines = null;
let currentFileLines = null;
const nucleiFilterState = {
    activeSeverities: new Set(NUCLEI_SEVERITIES),
    searchTerm: ''
};
const fileFilterState = {
    searchTerm: ''
};

// Helper function to handle API responses and check for auth errors
async function apiFetch(url, options = {}) {
    const response = await fetch(url, options);
    
    // If unauthorized, redirect to login
    if (response.status === 401) {
        state.authenticated = false;
        showLogin();
        throw new Error('Authentication required');
    }
    
    return response;
}

// Initialize App
document.addEventListener('DOMContentLoaded', () => {
    // Ensure dashboard is hidden and login is shown by default
    const dashboard = document.getElementById('dashboard');
    const loginModal = document.getElementById('loginModal');
    if (dashboard) {
        dashboard.classList.add('hidden');
        dashboard.style.display = 'none';
    }
    if (loginModal) {
        loginModal.classList.remove('hidden');
    }
    
    // Check authentication before loading anything
    checkAuth().then((authenticated) => {
        setupEventListeners(); // Always setup event listeners (including login form)
        // Only load targets if authenticated
        if (authenticated) {
            loadTargets();
        }
    }).catch(() => {
        // If auth check fails, show login
        showLogin();
        setupEventListeners(); // Setup login form listener
    });
});

// Authentication
async function checkAuth() {
    // Always start with login shown and dashboard hidden
    showLogin();
    
    try {
        const response = await fetch(`${API_BASE}/auth/check`);
        const data = await response.json();
        if (data.authenticated) {
            state.authenticated = true;
            showDashboard();
            return true;
        } else {
            state.authenticated = false;
            showLogin();
            return false;
        }
    } catch (error) {
        console.error('Auth check failed:', error);
        state.authenticated = false;
        showLogin();
        return false;
    }
}

function showLogin() {
    const loginModal = document.getElementById('loginModal');
    const dashboard = document.getElementById('dashboard');
    if (loginModal) {
        loginModal.classList.remove('hidden');
        loginModal.style.display = 'flex';
    }
    if (dashboard) {
        dashboard.classList.add('hidden');
        dashboard.style.display = 'none';
    }
    state.authenticated = false;
}

function showDashboard() {
    const loginModal = document.getElementById('loginModal');
    const dashboard = document.getElementById('dashboard');
    if (loginModal) {
        loginModal.classList.add('hidden');
        loginModal.style.display = 'none';
    }
    if (dashboard) {
        dashboard.classList.remove('hidden');
        dashboard.style.display = '';
    }
    state.authenticated = true;
}

// Event Listeners
function setupEventListeners() {
    // Login Form
    document.getElementById('loginForm').addEventListener('submit', handleLogin);
    
    // Target Type Radio
    document.querySelectorAll('input[name="targetType"]').forEach(radio => {
        radio.addEventListener('change', handleTargetTypeChange);
    });
    
    // Domain and Output Folder inputs
    document.getElementById('domainField').addEventListener('input', updateCommandPreview);
    document.getElementById('outputFolder').addEventListener('input', updateCommandPreview);
    
    // File Upload
    document.getElementById('fileInput').addEventListener('change', handleFileUpload);
    
    // Scan Form
    document.getElementById('scanForm').addEventListener('submit', handleScanSubmit);
    
    // Tabs
    document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', handleTabSwitch);
    });
}

// Login Handler
async function handleLogin(e) {
    e.preventDefault();
    const password = document.getElementById('passwordInput').value;
    const errorDiv = document.getElementById('loginError');
    
    try {
        const response = await fetch(`${API_BASE}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password })
        });
        
        const data = await response.json();
        if (data.success) {
            state.authenticated = true;
            showDashboard();
            errorDiv.classList.remove('show');
            // Clear password field
            document.getElementById('passwordInput').value = '';
            // Load targets after successful login
            loadTargets();
        } else {
            state.authenticated = false;
            errorDiv.textContent = data.error || 'Incorrect password';
            errorDiv.classList.add('show');
        }
    } catch (error) {
        errorDiv.textContent = 'Login failed. Please try again.';
        errorDiv.classList.add('show');
    }
}

// Logout Handler
async function handleLogout() {
    try {
        const response = await fetch(`${API_BASE}/auth/logout`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        
        const data = await response.json();
        if (data.success) {
            state.authenticated = false;
            showLogin();
        }
    } catch (error) {
        console.error('Logout failed:', error);
        // Still show login even if logout API fails
        state.authenticated = false;
        showLogin();
    }
}

// Target Type Change
function handleTargetTypeChange(e) {
    const isDomain = e.target.value === 'domain';
    document.getElementById('domainInput').classList.toggle('hidden', !isDomain);
    document.getElementById('domainListInput').classList.toggle('hidden', isDomain);
    updateCommandPreview();
}

// Update Command Preview
function updateCommandPreview() {
    const targetType = document.querySelector('input[name="targetType"]:checked')?.value || 'domain';
    const domain = document.getElementById('domainField').value || 'example.com';
    const outputFolder = document.getElementById('outputFolder').value || 'example_com';
    
    // Detect platform for Python command (python on Windows, python3 on Linux/Mac)
    const isWindows = navigator.platform.toLowerCase().includes('win');
    const pythonCmd = isWindows ? 'python' : 'python3';
    let command = `${pythonCmd} recon_tool.py`;
    
    if (targetType === 'domain') {
        command += ` -d ${domain}`;
    } else {
        command += ` -dL <domain_list_file>`;
    }
    
    command += ` -o recon_${outputFolder}`;
    
    document.getElementById('commandText').textContent = command;
}

// File Upload Handler
function handleFileUpload(e) {
    const file = e.target.files[0];
    if (!file) return;
    
    const preview = document.getElementById('filePreview');
    const reader = new FileReader();
    
    reader.onload = (event) => {
        const content = event.target.result;
        const lines = content.split('\n').slice(0, 5);
        
        preview.innerHTML = `
            <h4>✅ File uploaded successfully!</h4>
            <p><strong>Filename:</strong> ${file.name}</p>
            <p><strong>Size:</strong> ${file.size.toLocaleString()} bytes</p>
            <details>
                <summary>Preview (first 5 lines)</summary>
                <pre>${lines.join('\n')}</pre>
            </details>
        `;
        preview.classList.remove('hidden');
    };
    
    reader.readAsText(file);
}

// Scan Form Handler
async function handleScanSubmit(e) {
    e.preventDefault();
    
    const formData = new FormData(e.target);
    const targetType = formData.get('targetType');
    const domain = document.getElementById('domainField').value;
    const outputFolder = document.getElementById('outputFolder').value || 'example_com';
    
    // Validate
    if (targetType === 'domain' && !domain) {
        showMessage('Please enter a domain', 'error');
        return;
    }
    
    if (targetType === 'domainList') {
        const fileInput = document.getElementById('fileInput');
        if (!fileInput.files[0]) {
            showMessage('Please upload a domain list', 'error');
            return;
        }
    }
    
    // Prepare request
    const requestData = {
        targetType,
        domain: targetType === 'domain' ? domain : null,
        outputFolder
    };
    
    // Upload file if needed
    if (targetType === 'domainList') {
        const fileInput = document.getElementById('fileInput');
        const fileFormData = new FormData();
        fileFormData.append('file', fileInput.files[0]);
        
        try {
            const uploadResponse = await fetch(`${API_BASE}/upload`, {
                method: 'POST',
                body: fileFormData
            });
            const uploadData = await uploadResponse.json();
            requestData.domainList = uploadData.filename;
        } catch (error) {
            showMessage('File upload failed', 'error');
            return;
        }
    }
    
    // Check if run in background
    const runInBackground = document.getElementById('runInBackground').checked;
    
    // Show loading only if not running in background
    if (!runInBackground) {
        document.getElementById('loadingOverlay').classList.remove('hidden');
    } else {
        showMessage('Scan started in background. Check "Last run summary" for progress.', 'success');
    }
    
    try {
        const response = await fetch(`${API_BASE}/scan/run`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(requestData)
        });
        
        const data = await response.json();
        
        if (data.success) {
            // Store scan ID for logs
            state.currentScanId = data.scan_id;
            state.isScanning = true;
            
            // Update UI to show scanning status
            updateScanStatusUI(true);
            
            // Start polling scan status
            startStatusPolling(data.scan_id);
            
            showMessage('Scan started! Check "Scan Logs" tab for real-time output.', 'success');
            
            // If not running in background, switch to logs tab
            if (!runInBackground) {
                // Switch to logs tab after a short delay
                setTimeout(() => {
                    const logsTab = document.querySelector('.tab[data-tab="logs"]');
                    if (logsTab) {
                        logsTab.click();
                    }
                }, 500);
            }
            
            loadTargets();
        } else {
            showMessage(`Scan failed: ${data.error || 'Unknown error'}`, 'error');
        }
    } catch (error) {
        showMessage('Scan failed: ' + error.message, 'error');
    } finally {
        // Hide loading overlay if it was shown
        if (!runInBackground) {
            document.getElementById('loadingOverlay').classList.add('hidden');
        }
    }
}

// Update Scan Status UI
function updateScanStatusUI(isScanning) {
    const indicator = document.getElementById('scanStatusIndicator');
    const banner = document.getElementById('scanStatusBanner');
    const runBtn = document.getElementById('runScanBtn');
    
    if (isScanning) {
        indicator?.classList.remove('hidden');
        banner?.classList.remove('hidden');
        if (runBtn) runBtn.disabled = true;
    } else {
        indicator?.classList.add('hidden');
        banner?.classList.add('hidden');
        if (runBtn) runBtn.disabled = false;
    }
}

// Start polling scan status
function startStatusPolling(scanId) {
    // Clear existing polling if any
    if (state.statusPollingInterval) {
        clearInterval(state.statusPollingInterval);
    }
    
    // Poll every 2 seconds
    state.statusPollingInterval = setInterval(async () => {
        try {
            const response = await fetch(`${API_BASE}/scan/status/${scanId}`);
            if (response.ok) {
                const data = await response.json();
                const status = data.status || 'unknown';
                
                // Update UI based on status
                if (status === 'running') {
                    state.isScanning = true;
                    updateScanStatusUI(true);
                } else if (status === 'completed' || status === 'stopped' || status === 'error') {
                    state.isScanning = false;
                    state.currentScanId = null;
                    updateScanStatusUI(false);
                    stopStatusPolling();
                    loadTargets(); // Refresh targets list
                }
            } else {
                // Scan not found, might be completed
                state.isScanning = false;
                state.currentScanId = null;
                updateScanStatusUI(false);
                stopStatusPolling();
            }
        } catch (error) {
            console.error('Error polling scan status:', error);
        }
    }, 2000);
}

// Stop polling scan status
function stopStatusPolling() {
    if (state.statusPollingInterval) {
        clearInterval(state.statusPollingInterval);
        state.statusPollingInterval = null;
    }
}

// Stop Scan Handler
async function handleStopScan() {
    // Disable button to prevent multiple clicks
    const stopBtn = document.getElementById('stopScanBtn');
    const originalText = stopBtn ? stopBtn.textContent : 'Stop running scan';
    if (stopBtn) {
        stopBtn.disabled = true;
        stopBtn.textContent = 'Stopping...';
    }
    
    let stopSuccess = false;
    let errorMessage = null;
    
    // First, try to get running scans from server if we don't have currentScanId
    if (!state.currentScanId) {
        try {
            const runningResponse = await fetch(`${API_BASE}/scan/running`);
            if (runningResponse.ok) {
                const runningData = await runningResponse.json();
                if (runningData.running_scans && runningData.running_scans.length > 0) {
                    // Use the first running scan
                    state.currentScanId = runningData.running_scans[0].scan_id;
                    console.log('Found running scan:', state.currentScanId);
                }
            }
        } catch (err) {
            console.warn('Could not fetch running scans:', err);
        }
    }
    
    // Try to stop current scan by scan_id
    if (state.currentScanId) {
        try {
            console.log('Stopping scan:', state.currentScanId);
            const response = await fetch(`${API_BASE}/scan/stop`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ scan_id: state.currentScanId })
            });
            
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ error: `HTTP ${response.status}` }));
                throw new Error(errorData.error || `HTTP ${response.status}`);
            }
            
            const data = await response.json();
            console.log('Stop scan response:', data);
            
            if (data.success) {
                stopSuccess = true;
                showMessage(data.message || 'Scan stopped successfully.', 'success');
                
                // Update state immediately
                state.isScanning = false;
                updateScanStatusUI(false);
                
                // Continue polling for a short time to confirm stop
                // This ensures we catch the final status update
                let confirmAttempts = 0;
                const maxConfirmAttempts = 3;
                const confirmInterval = setInterval(async () => {
                    try {
                        const statusResponse = await fetch(`${API_BASE}/scan/status/${state.currentScanId}`);
                        if (statusResponse.ok) {
                            const statusData = await statusResponse.json();
                            const status = statusData.status || 'unknown';
                            
                            if (status === 'stopped' || status === 'completed' || status === 'error') {
                                clearInterval(confirmInterval);
                                state.currentScanId = null;
                                stopStatusPolling();
                                loadTargets(); // Refresh targets list
                                
                                // Refresh logs to show stopped status
                                if (document.getElementById('logsTab') && !document.getElementById('logsTab').classList.contains('hidden')) {
                                    refreshLogs();
                                }
                            } else if (confirmAttempts >= maxConfirmAttempts) {
                                clearInterval(confirmInterval);
                                state.currentScanId = null;
                                stopStatusPolling();
                                loadTargets();
                            }
                        } else {
                            // Scan not found, assume stopped
                            clearInterval(confirmInterval);
                            state.currentScanId = null;
                            stopStatusPolling();
                            loadTargets();
                        }
                        confirmAttempts++;
                    } catch (err) {
                        console.error('Error confirming stop:', err);
                        clearInterval(confirmInterval);
                        state.currentScanId = null;
                        stopStatusPolling();
                    }
                }, 1000);
                
                // Fallback: clear after max time
                setTimeout(() => {
                    clearInterval(confirmInterval);
                    if (state.currentScanId) {
                        state.currentScanId = null;
                        stopStatusPolling();
                        loadTargets();
                    }
                }, 5000);
                
            } else {
                errorMessage = data.error || 'Failed to stop scan';
                showMessage(errorMessage, 'error');
            }
        } catch (error) {
            console.error('Error stopping scan:', error);
            errorMessage = 'Failed to stop scan: ' + error.message;
            showMessage(errorMessage, 'error');
        }
        
        // Re-enable button if stop failed
        if (!stopSuccess && stopBtn) {
            stopBtn.disabled = false;
            stopBtn.textContent = originalText;
        } else if (stopBtn) {
            // Keep button disabled but update text
            stopBtn.textContent = 'Stopped';
            setTimeout(() => {
                if (stopBtn) {
                    stopBtn.textContent = originalText;
                }
            }, 2000);
        }
        return;
    }
    
    // Fallback: try to stop all running scans
    if (!stopSuccess) {
        try {
            console.log('No currentScanId, trying to stop all running scans...');
            // Try to stop without scan_id (will stop all running scans)
            const response = await fetch(`${API_BASE}/scan/stop`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({})
            });
            
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ error: `HTTP ${response.status}` }));
                throw new Error(errorData.error || `HTTP ${response.status}`);
            }
            
            const data = await response.json();
            console.log('Stop all scans response:', data);
            
            if (data.success) {
                stopSuccess = true;
                showMessage(data.message || 'All scans stopped successfully.', 'success');
                // Update state immediately
                state.isScanning = false;
                state.currentScanId = null;
                updateScanStatusUI(false);
                stopStatusPolling();
                loadTargets();
            } else {
                errorMessage = data.error || 'Failed to stop scans';
                showMessage(errorMessage, 'error');
            }
        } catch (error) {
            console.error('Error stopping all scans:', error);
            errorMessage = 'Failed to stop scans: ' + error.message;
            showMessage(errorMessage, 'error');
        }
    }
    
    // Re-enable button if stop failed
    if (!stopSuccess && stopBtn) {
        stopBtn.disabled = false;
        stopBtn.textContent = originalText;
    } else if (stopBtn && stopSuccess) {
        // Keep button disabled but update text
        stopBtn.textContent = 'Stopped';
        setTimeout(() => {
            if (stopBtn) {
                stopBtn.disabled = false;
                stopBtn.textContent = originalText;
            }
        }, 2000);
    }
    
    // If still no success, show error
    if (!stopSuccess) {
        showMessage('No active scan found to stop. Please check if a scan is running.', 'error');
    }
}

// Tab Switch Handler
function handleTabSwitch(e) {
    const tabName = e.target.dataset.tab;
    
    // Update tab buttons
    document.querySelectorAll('.tab').forEach(tab => {
        tab.classList.remove('active');
    });
    e.target.classList.add('active');
    
    // Update tab content
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
        content.classList.add('hidden');
    });
    
    if (tabName === 'dashboard') {
        document.getElementById('dashboardTab').classList.remove('hidden');
        document.getElementById('dashboardTab').classList.add('active');
        // Close overlay if open when switching to dashboard
        if (!document.getElementById('fileViewerOverlay').classList.contains('hidden')) {
            closeFileViewer();
        }
    } else if (tabName === 'targets') {
        document.getElementById('targetsTab').classList.remove('hidden');
        document.getElementById('targetsTab').classList.add('active');
        // Close overlay if open when switching tabs
        if (!document.getElementById('fileViewerOverlay').classList.contains('hidden')) {
            closeFileViewer();
        }
        renderTargetsManagement();
    } else if (tabName === 'logs') {
        document.getElementById('logsTab').classList.remove('hidden');
        document.getElementById('logsTab').classList.add('active');
        // Close overlay if open when switching tabs
        if (!document.getElementById('fileViewerOverlay').classList.contains('hidden')) {
            closeFileViewer();
        }
        startLogsPolling();
    } else if (tabName === 'output') {
        document.getElementById('outputTab').classList.remove('hidden');
        document.getElementById('outputTab').classList.add('active');
        // Close overlay if open when switching tabs
        if (!document.getElementById('fileViewerOverlay').classList.contains('hidden')) {
            closeFileViewer();
        }
        renderOutputViewer();
    } else if (tabName === 'config') {
        document.getElementById('configTab').classList.remove('hidden');
        document.getElementById('configTab').classList.add('active');
        // Close overlay if open when switching tabs
        if (!document.getElementById('fileViewerOverlay').classList.contains('hidden')) {
            closeFileViewer();
        }
        // Only load if not already loaded
        if (!configLoaded || !document.getElementById('settingsEditor')) {
            loadConfig();
        }
    }
}

// Load Targets
async function loadTargets() {
    // Don't load targets if not authenticated
    if (!state.authenticated) {
        return;
    }
    try {
        const response = await fetch(`${API_BASE}/targets`);
        const data = await response.json();
        state.targets = data.targets || [];
        renderTargetsList();
    } catch (error) {
        console.error('Failed to load targets:', error);
    }
}

// Render Targets List
function renderTargetsList() {
    const container = document.getElementById('targetsList');
    
    if (state.targets.length === 0) {
        container.innerHTML = '<div class="info-box"><p>No recon results yet.</p></div>';
        return;
    }
    
    container.innerHTML = state.targets.map((target, index) => `
        <div class="target-item ${target.path === state.activeTarget ? 'selected' : ''}" 
             data-target="${target.path}" onclick="selectTarget('${target.path}')">
            <h3>${target.label}</h3>
            <p>${escapeHtml(target.display_path || target.path)}</p>
            <div class="target-actions">
                <button class="btn btn-primary" onclick="event.stopPropagation(); downloadTarget('${target.path}')">
                    Download ZIP
                </button>
                <button class="btn btn-secondary" onclick="event.stopPropagation(); deleteTarget('${target.path}')">
                    Delete output
                </button>
            </div>
        </div>
    `).join('');
}

// Select Target
function selectTarget(targetPath) {
    state.activeTarget = targetPath;
    renderTargetsList();
}

// Render Targets Management
async function renderTargetsManagement() {
    const container = document.getElementById('targetsManagement');
    
    // Reload targets first
    await loadTargets();
    
    if (state.targets.length === 0) {
        container.innerHTML = '<div class="info-box"><p>No recon results yet.</p></div>';
        return;
    }
    
    // Get list of running scans
    let runningScans = [];
    try {
        const runningResponse = await fetch(`${API_BASE}/scan/running`);
        if (runningResponse.ok) {
            const runningData = await runningResponse.json();
            runningScans = runningData.running_scans || [];
        }
    } catch (error) {
        console.warn('Could not fetch running scans:', error);
    }
    
    // Helper function to normalize paths for comparison
    const normalizePath = (path) => {
        if (!path) return '';
        return String(path).replace(/\\/g, '/');
    };
    
    // Create a map of target_dir to scan_id for quick lookup
    // Normalize paths to handle Windows backslashes vs forward slashes
    const targetToScanId = {};
    console.log('Running scans:', runningScans);
    for (const scan of runningScans) {
        if (scan.target_dir) {
            // Normalize path: convert backslashes to forward slashes for comparison
            const normalizedTargetDir = normalizePath(scan.target_dir);
            targetToScanId[normalizedTargetDir] = scan.scan_id;
            console.log(`Mapped: ${normalizedTargetDir} -> ${scan.scan_id}`);
        }
    }
    console.log('Target to ScanId map:', targetToScanId);
    
    // Create table
    let tableHTML = `
        <div class="targets-table-container">
            <table class="targets-table">
                <thead>
                    <tr>
                        <th>Target</th>
                        <th>Path</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
    `;
    
    // Load summary for each target to show status
    for (const target of state.targets) {
        try {
            const response = await fetch(`${API_BASE}/targets/${encodeURIComponent(target.path)}/summary`);
            const data = await response.json();
            const summary = data.summary || {};
            
            const fileCount = summary.files || 0;
            const subdomainCount = summary.subdomains || 0;
            const status = fileCount > 0 ? '✅ Complete' : '⏳ Processing';
            const targetDisplayPath = target.display_path || target.path;
            const normalizedDisplayPath = normalizePath(targetDisplayPath);
            const isRunningInScans = targetToScanId[normalizedDisplayPath] !== undefined;
            const scanId = targetToScanId[normalizedDisplayPath];
            // Show Stop Scan button if: 1) in running_scans, OR 2) status is Processing (fileCount = 0)
            const isProcessing = fileCount === 0;
            const shouldShowStopButton = isRunningInScans || isProcessing;
            console.log(`Target: ${target.path} -> Normalized: ${normalizedDisplayPath}, IsRunning: ${isRunningInScans}, IsProcessing: ${isProcessing}, ScanId: ${scanId}`);
            
            // Build action buttons
            let actionButtons = `
                <button class="btn btn-primary btn-sm" onclick="viewTargetInOutput('${target.path.replace(/'/g, "\\'")}')">
                    📄 View
                </button>
                <button class="btn btn-secondary btn-sm" onclick="downloadTarget('${target.path.replace(/'/g, "\\'")}')">
                    ⬇️ Download
                </button>
            `;
            
            // Add Stop Scan button if target is running or processing
            if (shouldShowStopButton) {
                actionButtons += `
                    <button class="btn btn-warning btn-sm" onclick="stopTargetScan('${target.path.replace(/'/g, "\\'")}', '${scanId || ''}')" title="Stop running scan">
                        ⏹️ Stop Scan
                    </button>
                `;
            }
            
            actionButtons += `
                <button class="btn btn-danger btn-sm" onclick="confirmDeleteTarget('${target.path.replace(/'/g, "\\'")}')">
                    🗑️ Delete
                </button>
            `;
            
            tableHTML += `
                <tr>
                    <td><strong>${escapeHtml(target.label)}</strong></td>
                    <td><code class="path-code">${escapeHtml(targetDisplayPath)}</code></td>
                    <td>
                        <span class="status-badge ${fileCount > 0 ? 'status-complete' : 'status-processing'}">${status}</span>
                        <div class="status-details">
                            <small>${fileCount} files, ${subdomainCount} subdomains</small>
                            ${shouldShowStopButton ? '<br><small style="color: var(--accent-yellow);">🔄 Scan in progress...</small>' : ''}
                        </div>
                    </td>
                    <td>
                        <div class="action-buttons">
                            ${actionButtons}
                        </div>
                    </td>
                </tr>
            `;
        } catch (error) {
            // If summary fails, still show the target
            const targetDisplayPath = target.display_path || target.path;
            const normalizedDisplayPath = normalizePath(targetDisplayPath);
            const isRunningInScans = targetToScanId[normalizedDisplayPath] !== undefined;
            const scanId = targetToScanId[normalizedDisplayPath];
            // If we can't get summary, assume it might be processing if it's in running_scans
            const shouldShowStopButton = isRunningInScans;
            
            let actionButtons = `
                <button class="btn btn-primary btn-sm" onclick="viewTargetInOutput('${target.path.replace(/'/g, "\\'")}')">
                    📄 View
                </button>
                <button class="btn btn-secondary btn-sm" onclick="downloadTarget('${target.path.replace(/'/g, "\\'")}')">
                    ⬇️ Download
                </button>
            `;
            
            if (shouldShowStopButton) {
                actionButtons += `
                    <button class="btn btn-warning btn-sm" onclick="stopTargetScan('${target.path.replace(/'/g, "\\'")}', '${scanId || ''}')" title="Stop running scan">
                        ⏹️ Stop Scan
                    </button>
                `;
            }
            
            actionButtons += `
                <button class="btn btn-danger btn-sm" onclick="confirmDeleteTarget('${target.path.replace(/'/g, "\\'")}')">
                    🗑️ Delete
                </button>
            `;
            
            tableHTML += `
                <tr>
                    <td><strong>${escapeHtml(target.label)}</strong></td>
                    <td><code class="path-code">${escapeHtml(targetDisplayPath)}</code></td>
                    <td><span class="status-badge status-unknown">❓ Unknown</span></td>
                    <td>
                        <div class="action-buttons">
                            ${actionButtons}
                        </div>
                    </td>
                </tr>
            `;
        }
    }
    
    tableHTML += `
                </tbody>
            </table>
        </div>
    `;
    
    container.innerHTML = tableHTML;
}

// Refresh Targets
async function refreshTargets() {
    await loadTargets();
    renderTargetsManagement();
    showMessage('Targets refreshed', 'success');
}

// Stop Scan for Specific Target
async function stopTargetScan(targetPath, scanId) {
    if (!confirm('Are you sure you want to stop this scan?')) {
        return;
    }
    
    try {
        showMessage('Stopping scan...', 'info');
        
        // Try to stop by scan_id first if available
        let stopData = {};
        if (scanId) {
            stopData = { scan_id: scanId };
        } else {
            stopData = { target: targetPath };
        }
        
        const response = await fetch(`${API_BASE}/scan/stop`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(stopData)
        });
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({ error: `HTTP ${response.status}` }));
            throw new Error(errorData.error || `HTTP ${response.status}`);
        }
        
        const data = await response.json();
        
        if (data.success) {
            showMessage(data.message || 'Scan stopped successfully.', 'success');
            
            // Update state if this was the current scan
            if (state.currentScanId === scanId) {
                state.isScanning = false;
                state.currentScanId = null;
                updateScanStatusUI(false);
                stopStatusPolling();
            }
            
            // Refresh targets to update status
            setTimeout(() => {
                renderTargetsManagement();
                loadTargets();
            }, 1000);
        } else {
            showMessage(data.error || 'Failed to stop scan', 'error');
        }
    } catch (error) {
        console.error('Error stopping target scan:', error);
        showMessage('Failed to stop scan: ' + error.message, 'error');
    }
}

// View Target in Output Viewer
function viewTargetInOutput(targetPath) {
    // Switch to output tab
    document.querySelectorAll('.tab').forEach(tab => {
        tab.classList.remove('active');
        if (tab.dataset.tab === 'output') {
            tab.classList.add('active');
        }
    });
    
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
        content.classList.add('hidden');
    });
    
    document.getElementById('outputTab').classList.remove('hidden');
    document.getElementById('outputTab').classList.add('active');
    
    // Render output viewer and select the target
    renderOutputViewer();
    
    // Select the target in the dropdown
    setTimeout(() => {
        const targetSelect = document.querySelector('#outputViewer select');
        if (targetSelect) {
            // Find option with matching path
            for (let option of targetSelect.options) {
                if (option.value === targetPath) {
                    targetSelect.value = targetPath;
                    targetSelect.dispatchEvent(new Event('change'));
                    break;
                }
            }
        }
    }, 100);
}

// Confirm Delete Target
async function confirmDeleteTarget(targetPath) {
    if (confirm('Are you sure you want to delete this target? This action cannot be undone.')) {
        await deleteTarget(targetPath);
        renderTargetsManagement();
    }
}

// Download Target
async function downloadTarget(targetPath) {
    try {
        const response = await fetch(`${API_BASE}/targets/${encodeURIComponent(targetPath)}/download`);
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${targetPath.split('/').pop()}.zip`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
    } catch (error) {
        showMessage('Download failed', 'error');
    }
}

// Delete Target
async function deleteTarget(targetPath) {
    if (!confirm('Are you sure you want to delete this output?')) {
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/targets/${encodeURIComponent(targetPath)}`, {
            method: 'DELETE'
        });
        
        const data = await response.json();
        if (data.success) {
            showMessage('Output deleted', 'success');
            if (state.activeTarget === targetPath) {
                state.activeTarget = null;
            }
            loadTargets();
        }
    } catch (error) {
        showMessage('Delete failed', 'error');
    }
}

// Update Last Run Summary
function updateLastRunSummary(result) {
    const container = document.getElementById('lastRunSummary');
    
    if (!result) {
        container.innerHTML = '<div class="info-box"><p>No runs yet.</p></div>';
        return;
    }
    
    container.innerHTML = `
        <div>
            <p><strong>Return code:</strong> ${result.returncode}</p>
            <p><strong>Output directory:</strong> <code>${result.target}</code></p>
            ${result.stdout ? `<div class="code-block">${escapeHtml(result.stdout)}</div>` : ''}
            ${result.stderr ? `<div class="code-block">${escapeHtml(result.stderr)}</div>` : ''}
        </div>
    `;
}

// Render Output Viewer
async function renderOutputViewer() {
    const container = document.getElementById('outputViewer');
    
    // Create tabs for Target Files and Scan Logs
    const tabsContainer = document.createElement('div');
    tabsContainer.className = 'output-viewer-tabs';
    tabsContainer.innerHTML = `
        <button class="output-tab active" data-view="targets">📁 Target Files</button>
        <button class="output-tab" data-view="logs">📋 Scan Logs</button>
    `;
    
    const contentContainer = document.createElement('div');
    contentContainer.id = 'outputViewerContent';
    
    container.innerHTML = '';
    container.appendChild(tabsContainer);
    container.appendChild(contentContainer);
    
    // Handle tab clicks
    tabsContainer.querySelectorAll('.output-tab').forEach(tab => {
        tab.addEventListener('click', (e) => {
            tabsContainer.querySelectorAll('.output-tab').forEach(t => t.classList.remove('active'));
            e.target.classList.add('active');
            
            const view = e.target.dataset.view;
            if (view === 'targets') {
                renderTargetFilesView();
            } else if (view === 'logs') {
                renderScanLogsView();
            }
        });
    });
    
    // Load default view
    renderTargetFilesView();
}

// Render Target Files View
async function renderTargetFilesView() {
    const container = document.getElementById('outputViewerContent');
    
    if (state.targets.length === 0) {
        container.innerHTML = '<div class="info-box"><p>No recon results yet.</p></div>';
        return;
    }
    
    // Create target selector
    const targetSelect = document.createElement('select');
    targetSelect.innerHTML = state.targets.map((target, index) => 
        `<option value="${target.path}">${target.label}</option>`
    ).join('');
    targetSelect.addEventListener('change', async (e) => {
        await loadOutputFiles(e.target.value);
    });
    
    container.innerHTML = '';
    container.appendChild(targetSelect);
    const filesContainer = document.createElement('div');
    filesContainer.id = 'outputFilesContainer';
    container.appendChild(filesContainer);
    
    if (state.targets.length > 0) {
        await loadOutputFiles(state.targets[0].path);
    }
}

// Render Scan Logs View
async function renderScanLogsView() {
    const container = document.getElementById('outputViewerContent');
    if (!container) {
        console.error('outputViewerContent container not found');
        return;
    }
    
    container.innerHTML = '<div class="info-box"><p>Loading scan logs...</p></div>';
    
    try {
        const response = await fetch(`${API_BASE}/scan-logs`);
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(`HTTP ${response.status}: ${errorData.error || response.statusText}`);
        }
        
        const data = await response.json();
        
        if (!data.logs || data.logs.length === 0) {
            container.innerHTML = '<div class="info-box"><p>No scan logs found.</p></div>';
            return;
        }
        
        // Create log files list
        const logListContainer = document.createElement('div');
        logListContainer.className = 'file-list-container';
        
        const logList = document.createElement('div');
        logList.className = 'file-list';
        
        data.logs.forEach((logFile) => {
            const logItem = document.createElement('div');
            logItem.className = 'file-list-item';
            
            const logInfo = document.createElement('div');
            logInfo.className = 'file-item-info';
            const modifiedDate = new Date(logFile.modified).toLocaleString();
            logInfo.innerHTML = `
                <span class="file-item-name">${escapeHtml(logFile.name)}</span>
                <span class="file-item-size">${(logFile.size / 1024).toFixed(2)} KB</span>
                <span class="file-item-date" style="font-size: 0.75rem; color: var(--text-secondary);">${modifiedDate}</span>
            `;
            
            const viewButton = document.createElement('button');
            viewButton.className = 'btn btn-secondary btn-sm';
            viewButton.textContent = 'View';
            viewButton.addEventListener('click', () => {
                loadScanLogInOverlay(logFile.name);
            });
            
            logItem.appendChild(logInfo);
            logItem.appendChild(viewButton);
            logList.appendChild(logItem);
        });
        
        logListContainer.appendChild(logList);
        
        container.innerHTML = '';
        container.appendChild(logListContainer);
    } catch (error) {
        console.error('Error loading scan logs:', error);
        const errorMsg = error.message || 'Unknown error';
        container.innerHTML = `<div class="info-box"><p>Failed to load scan logs: ${errorMsg}</p><p style="font-size: 0.85rem; color: var(--text-secondary); margin-top: 0.5rem;">Check browser console for details.</p></div>`;
    }
}

// Load scan log in overlay
async function loadScanLogInOverlay(logName) {
    try {
        const response = await fetch(`${API_BASE}/scan-logs/${encodeURIComponent(logName)}`);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        const data = await response.json();
        
        if (!data) {
            throw new Error('Invalid response from server');
        }
        
        const content = data.content || '';
        const size = data.size || 0;
        
        showFileInOverlay(logName, content, size, null);
    } catch (error) {
        console.error('Error loading scan log:', error);
        showMessage('Failed to load log: ' + (error.message || 'Unknown error'), 'error');
    }
}

// Load Output Files
async function loadOutputFiles(targetPath) {
    const container = document.getElementById('outputFilesContainer');
    
    try {
        const response = await fetch(`${API_BASE}/targets/${encodeURIComponent(targetPath)}/files`);
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            console.error('Failed to load files:', response.status, errorData);
            container.innerHTML = `<div class="info-box"><p>Failed to load files: ${errorData.error || response.statusText}</p></div>`;
            return;
        }
        
        const data = await response.json();
        
        if (data.files && data.files.length > 0) {
            const fileSelect = document.createElement('select');
            fileSelect.className = 'output-selector';
            fileSelect.innerHTML = data.files.map((file, index) => 
                `<option value="${file.path}">${file.path} (${(file.size / 1024).toFixed(2)} KB)</option>`
            ).join('');
            fileSelect.addEventListener('change', async (e) => {
                await loadFileContent(targetPath, e.target.value);
            });
            
            const fileListContainer = document.createElement('div');
            fileListContainer.className = 'file-list-container';
            
            // Create file list with clickable items
            const fileList = document.createElement('div');
            fileList.className = 'file-list';
            
            data.files.forEach((file) => {
                const fileItem = document.createElement('div');
                fileItem.className = 'file-list-item';
                
                // Create file info
                const fileInfo = document.createElement('div');
                fileInfo.className = 'file-item-info';
                fileInfo.innerHTML = `
                    <span class="file-item-name">${escapeHtml(file.path)}</span>
                    <span class="file-item-size">${(file.size / 1024).toFixed(2)} KB</span>
                `;
                
                // Create view button with event listener to avoid escape issues
                const viewButton = document.createElement('button');
                viewButton.className = 'btn btn-secondary btn-sm';
                viewButton.textContent = 'View';
                viewButton.addEventListener('click', () => {
                    loadFileInOverlay(targetPath, file.path);
                });
                
                fileItem.appendChild(fileInfo);
                fileItem.appendChild(viewButton);
                fileList.appendChild(fileItem);
            });
            
            fileListContainer.appendChild(fileList);
            
            container.innerHTML = '';
            container.appendChild(fileSelect);
            container.appendChild(fileListContainer);
            
            // Don't auto-load first file - let user choose
        } else {
            container.innerHTML = '<div class="info-box"><p>Target has no output files yet.</p></div>';
        }
    } catch (error) {
        console.error('Error loading files:', error);
        container.innerHTML = `<div class="info-box"><p>Failed to load files: ${error.message}</p></div>`;
    }
}

// Load file directly in overlay
async function loadFileInOverlay(targetPath, filePath) {
    try {
        const response = await fetch(`${API_BASE}/targets/${encodeURIComponent(targetPath)}/files/${encodeURIComponent(filePath)}`);
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        const data = await response.json();
        
        // Validate response data
        if (!data) {
            throw new Error('Invalid response from server');
        }
        
        const content = data.content || '';
        const size = data.size || 0;
        
        showFileInOverlay(filePath, content, size, targetPath);
    } catch (error) {
        console.error('Error loading file:', error);
        showMessage('Failed to load file: ' + (error.message || 'Unknown error'), 'error');
    }
}

// Load File Content
async function loadFileContent(targetPath, filePath) {
    const container = document.getElementById('fileContent');
    
    try {
        const response = await fetch(`${API_BASE}/targets/${encodeURIComponent(targetPath)}/files/${encodeURIComponent(filePath)}`);
        const data = await response.json();
        
        // Show in overlay instead of inline
        showFileInOverlay(filePath, data.content, data.size, targetPath);
        
        // Also update container for backward compatibility
        container.innerHTML = `
            <p><strong>File:</strong> <code>${filePath}</code> (${data.size} bytes)</p>
            <div class="code-block">${escapeHtml(data.content)}</div>
            <button class="btn btn-primary" onclick="showFileInOverlay('${filePath}', ${JSON.stringify(data.content)}, ${data.size}, '${targetPath}')">
                View in overlay
            </button>
        `;
    } catch (error) {
        container.innerHTML = '<div class="info-box"><p>Failed to load file content.</p></div>';
    }
}

// Show file in overlay
function showFileInOverlay(filePath, content, size, targetPath) {
    const overlay = document.getElementById('fileViewerOverlay');
    const title = document.getElementById('fileViewerTitle');
    const pathEl = document.getElementById('fileViewerPath');
    const sizeEl = document.getElementById('fileViewerSize');
    const contentEl = document.getElementById('fileViewerContent');
    const filtersEl = document.getElementById('fileViewerFilters');
    const severityRow = document.getElementById('nucleiSeverityRow');
    const searchInput = document.getElementById('fileSearchInput');
    const statsEl = document.getElementById('fileFilterStats');
    
    // Validate and handle size
    const fileSize = size || 0;
    const sizeKB = fileSize > 0 ? (fileSize / 1024).toFixed(2) : '0.00';
    const sizeBytes = fileSize > 0 ? fileSize.toLocaleString() : '0';
    
    title.textContent = `File: ${filePath.split('/').pop()}`;
    pathEl.textContent = filePath;
    sizeEl.textContent = `${sizeKB} KB (${sizeBytes} bytes)`;
    
    const isNucleiOutput = shouldFormatAsNuclei(filePath, targetPath, content);
    contentEl.classList.toggle('nuclei-output', isNucleiOutput);
    
    if (filtersEl) {
        filtersEl.classList.remove('hidden');
    }
    
    if (searchInput) {
        searchInput.value = '';
    }
    if (statsEl) {
        statsEl.textContent = '';
    }
    
    if (isNucleiOutput) {
        ensureNucleiFiltersInitialized();
        currentNucleiLines = parseNucleiContent(content || '');
        currentFileLines = null;
        resetNucleiFilters();
        updateNucleiFilterUI();
        handleGlobalSearchInput('');
        renderNucleiFilteredContent();
        if (severityRow) {
            severityRow.classList.remove('hidden');
        }
    } else {
        currentNucleiLines = null;
        currentFileLines = splitFileLines(content || '');
        fileFilterState.searchTerm = '';
        renderFileFilteredContent();
        if (severityRow) {
            severityRow.classList.add('hidden');
        }
    }
    
    // Store current file info for download
    window.currentFileInfo = { targetPath, filePath };
    
    overlay.classList.remove('hidden');
    
    // Close on Escape key
    document.addEventListener('keydown', handleOverlayEscape);
}

// Close file viewer overlay
function closeFileViewer() {
    const overlay = document.getElementById('fileViewerOverlay');
    overlay.classList.add('hidden');
    document.removeEventListener('keydown', handleOverlayEscape);
    window.currentFileInfo = null;
}

// Handle Escape key to close overlay
function handleOverlayEscape(e) {
    if (e.key === 'Escape') {
        closeFileViewer();
    }
}

// Download current file from overlay
function downloadCurrentFile() {
    if (window.currentFileInfo) {
        downloadFile(window.currentFileInfo.targetPath, window.currentFileInfo.filePath);
    }
}

// Download File
async function downloadFile(targetPath, filePath) {
    try {
        const response = await fetch(`${API_BASE}/targets/${encodeURIComponent(targetPath)}/files/${encodeURIComponent(filePath)}/download`);
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filePath.split('/').pop();
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
    } catch (error) {
        showMessage('Download failed', 'error');
    }
}

// Utility Functions
function showMessage(message, type = 'info') {
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${type}`;
    messageDiv.textContent = message;
    
    const dashboard = document.getElementById('dashboard');
    dashboard.insertBefore(messageDiv, dashboard.firstChild);
    
    setTimeout(() => {
        messageDiv.remove();
    }, 5000);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function shouldFormatAsNuclei(filePath, targetPath, content) {
    const combinedPath = `${targetPath || ''}/${filePath || ''}`.toLowerCase();
    if (combinedPath.includes('nuclei')) {
        return true;
    }
    
    if (!content) {
        return false;
    }
    
    const sampleLines = content.split(/\r?\n/).slice(0, 20);
    return sampleLines.some((line) => /^\s*\[[^\]]+\]\s+\[[^\]]+\]\s+\[(info|low|medium|high|critical)\]/i.test(line));
}

function parseNucleiContent(content) {
    return content.split(/\r?\n/).map(buildNucleiLineData);
}

function buildNucleiLineData(line) {
    const rawLine = line || '';
    if (!rawLine.trim()) {
        return {
            severity: 'generic',
            text: '',
            html: `<span class="nuclei-line nuclei-generic"><span class="nuclei-text">&nbsp;</span></span>`
        };
    }
    
    const pattern = /^\s*(\[[^\]]+\])\s+(\[[^\]]+\])\s+(\[(info|low|medium|high|critical)\])\s+(.*)$/i;
    const match = pattern.exec(rawLine);
    
    let severityValue = 'generic';
    let metaHtml = '';
    let textHtml = highlightUrls(rawLine);
    
    if (match) {
        const ruleToken = match[1];
        const protoToken = match[2];
        const severityToken = match[3];
        severityValue = match[4].toLowerCase();
        const details = match[5];
        
        metaHtml = `
            ${createNucleiChip(ruleToken, 'nuclei-rule')}
            ${createNucleiChip(protoToken, 'nuclei-proto')}
            ${createNucleiChip(severityToken, `nuclei-severity nuclei-${severityValue}`)}
        `;
        textHtml = highlightUrls(details);
    } else {
        const severityMatch = /\[(info|low|medium|high|critical)\]/i.exec(rawLine);
        if (severityMatch) {
            severityValue = severityMatch[1].toLowerCase();
        }
    }
    
    const severityClass = `nuclei-${severityValue}`;
    return {
        severity: severityValue,
        text: rawLine,
        html: `
            <span class="nuclei-line ${severityClass}">
                <span class="nuclei-meta">${metaHtml}</span>
                <span class="nuclei-text">${textHtml}</span>
            </span>
        `
    };
}

function createNucleiChip(text, className = '') {
    if (!text) {
        return '';
    }
    return `<span class="nuclei-chip ${className}">${escapeHtml(text)}</span>`;
}

function highlightUrls(text) {
    if (!text) {
        return '';
    }
    const urlRegex = /([a-z]+:\/\/[^\s]+|https?:\/\/[^\s]+)/gi;
    let lastIndex = 0;
    let result = '';
    let match;
    
    while ((match = urlRegex.exec(text)) !== null) {
        result += escapeHtml(text.slice(lastIndex, match.index));
        result += `<span class="nuclei-url">${escapeHtml(match[0])}</span>`;
        lastIndex = match.index + match[0].length;
    }
    
    result += escapeHtml(text.slice(lastIndex));
    return result || '&nbsp;';
}

function ensureNucleiFiltersInitialized() {
    if (nucleiFiltersInitialized) {
        return;
    }
    nucleiFiltersInitialized = true;
    
    const severityButtons = document.querySelectorAll('[data-severity-filter]');
    severityButtons.forEach((button) => {
        button.addEventListener('click', () => {
            const severity = button.dataset.severityFilter;
            if (severity === 'all') {
                resetNucleiFilters();
            } else {
                toggleSeverityFilter(severity);
            }
            updateNucleiFilterUI();
            renderNucleiFilteredContent();
        });
    });
    
    const searchInput = document.getElementById('nucleiSearchInput');
    const globalSearchInput = document.getElementById('fileSearchInput');
    [searchInput, globalSearchInput].forEach((input) => {
        if (!input) {
            return;
        }
        input.addEventListener('input', (event) => {
            handleGlobalSearchInput(event.target.value || '');
        });
    });
}

function resetNucleiFilters() {
    nucleiFilterState.activeSeverities = new Set(NUCLEI_SEVERITIES);
    nucleiFilterState.searchTerm = '';
    const searchInput = document.getElementById('nucleiSearchInput');
    if (searchInput) {
        searchInput.value = '';
    }
}

function toggleSeverityFilter(severity) {
    if (!nucleiFilterState.activeSeverities.has(severity)) {
        nucleiFilterState.activeSeverities.add(severity);
        return;
    }
    
    if (nucleiFilterState.activeSeverities.size > 1) {
        nucleiFilterState.activeSeverities.delete(severity);
    }
}

function updateNucleiFilterUI() {
    const buttons = document.querySelectorAll('[data-severity-filter]');
    const activeCount = nucleiFilterState.activeSeverities.size;
    buttons.forEach((button) => {
        const severity = button.dataset.severityFilter;
        if (severity === 'all') {
            button.classList.toggle('active', activeCount === NUCLEI_SEVERITIES.length);
        } else {
            button.classList.toggle('active', nucleiFilterState.activeSeverities.has(severity));
        }
    });
}

function renderNucleiFilteredContent() {
    const contentEl = document.getElementById('fileViewerContent');
    if (!contentEl || !currentNucleiLines) {
        return;
    }
    
    const searchTerm = nucleiFilterState.searchTerm.trim().toLowerCase();
    const filtered = currentNucleiLines.filter((line) => {
        if (!nucleiFilterState.activeSeverities.has(line.severity)) {
            return false;
        }
        if (!searchTerm) {
            return true;
        }
        return (line.text || '').toLowerCase().includes(searchTerm);
    });
    
    if (filtered.length === 0) {
        contentEl.innerHTML = '<div class="nuclei-empty">No matching findings.</div>';
    } else {
        contentEl.innerHTML = filtered.map((line) => line.html).join('');
    }
    
    updateFilterStats(filtered.length, currentNucleiLines.length);
}

function handleGlobalSearchInput(value) {
    nucleiFilterState.searchTerm = (value || '').toLowerCase();
    fileFilterState.searchTerm = nucleiFilterState.searchTerm;
    if (currentNucleiLines) {
        renderNucleiFilteredContent();
    } else {
        renderFileFilteredContent();
    }
}

function splitFileLines(content) {
    const lines = content.split(/\r?\n/);
    return lines.map((line, index) => ({
        raw: line,
        lower: line.toLowerCase(),
        html: `<span class="file-line"><span class="file-line-number">${index + 1}</span><span class="file-line-text">${escapeHtml(line || '') || '&nbsp;'}</span></span>`
    }));
}

function renderFileFilteredContent() {
    const contentEl = document.getElementById('fileViewerContent');
    if (!contentEl || !currentFileLines) {
        return;
    }
    
    const searchTerm = fileFilterState.searchTerm.trim();
    let filtered = currentFileLines;
    
    if (searchTerm) {
        filtered = currentFileLines.filter((line) => line.lower.includes(searchTerm));
    }
    
    if (filtered.length === 0) {
        contentEl.innerHTML = '<div class="nuclei-empty">No matching lines.</div>';
    } else {
        contentEl.innerHTML = filtered.map((line) => line.html).join('');
    }
    
    contentEl.classList.toggle('filtered-output', !!searchTerm);
    updateFilterStats(filtered.length, currentFileLines.length);
}

function updateFilterStats(visible, total) {
    const statsEl = document.getElementById('fileFilterStats');
    if (statsEl) {
        statsEl.textContent = `${visible} / ${total} lines`;
    }
}

// Make functions globally available
window.selectTarget = selectTarget;
window.handleLogout = handleLogout;
window.downloadTarget = downloadTarget;
window.deleteTarget = deleteTarget;
window.downloadFile = downloadFile;
window.closeFileViewer = closeFileViewer;
window.downloadCurrentFile = downloadCurrentFile;
window.showFileInOverlay = showFileInOverlay;
window.loadFileInOverlay = loadFileInOverlay;
window.refreshTargets = refreshTargets;
window.loadConfig = loadConfig;
window.saveConfig = saveConfig;
window.restoreBackup = restoreBackup;
window.stopTargetScan = stopTargetScan;
window.viewTargetInOutput = viewTargetInOutput;
window.confirmDeleteTarget = confirmDeleteTarget;

// Config Editor
let currentSettingsContent = null;
let isLoadingConfig = false;
let configLoaded = false;

async function loadConfig() {
    // Prevent multiple simultaneous loads
    if (isLoadingConfig) {
        console.log('Config is already loading, skipping...');
        return;
    }
    
    const container = document.getElementById('configEditor');
    if (!container) {
        console.error('configEditor container not found');
        return;
    }
    
    // Check if already loaded and not empty
    if (container.innerHTML && !container.innerHTML.includes('Loading') && !container.innerHTML.includes('Error')) {
        const editor = document.getElementById('settingsEditor');
        if (editor) {
            console.log('Config already loaded, skipping...');
            return;
        }
    }
    
    isLoadingConfig = true;
    container.innerHTML = '<div class="info-box"><p>Loading settings.py...</p></div>';
    
    try {
        const response = await fetch(`${API_BASE}/config`);
        
        // Try to parse JSON response
        let data;
        try {
            data = await response.json();
        } catch (jsonError) {
            const text = await response.text();
            console.error('Failed to parse JSON response:', text);
            throw new Error(`Invalid JSON response: ${text.substring(0, 100)}`);
        }
        
        console.log('Config response status:', response.status);
        
        if (!response.ok) {
            const errorMsg = data.error || data.message || `HTTP ${response.status}`;
            throw new Error(errorMsg);
        }
        
        // Check if response has success field
        if (data.success === false || (data.success === undefined && data.error)) {
            throw new Error(data.error || data.message || 'Failed to load settings.py');
        }
        
        // Check if content exists
        if (!data.content) {
            throw new Error('No content received from server. Response: ' + JSON.stringify(data));
        }
        
        currentSettingsContent = data.content;
        renderConfigEditorContent(data.content);
        configLoaded = true;
    } catch (error) {
        console.error('Error loading settings.py:', error);
        container.innerHTML = `
            <div class="info-box">
                <p style="color: var(--accent-red);">
                    <strong>Error loading settings.py:</strong><br>
                    ${escapeHtml(error.message)}<br>
                    <small>Please check server logs for more details.</small>
                </p>
                <button class="btn btn-secondary btn-sm" onclick="loadConfig()" style="margin-top: 1rem;">
                    🔄 Retry
                </button>
            </div>
        `;
    } finally {
        isLoadingConfig = false;
    }
}

function renderConfigEditorContent(content) {
    const container = document.getElementById('configEditor');
    
    let html = `
        <div class="config-editor-wrapper">
            <div class="config-editor-header">
                <p class="config-note">
                    <strong>⚠️ Warning:</strong> Editing settings.py directly. Make sure Python syntax is correct.
                    A backup will be created automatically before saving.
                </p>
                <div class="config-editor-actions">
                    <button class="btn btn-secondary btn-sm" onclick="restoreBackup()">📥 Restore Backup</button>
                    <button class="btn btn-primary btn-sm" onclick="saveConfig()">💾 Save settings.py</button>
                </div>
            </div>
            <textarea id="settingsEditor" class="config-editor-textarea" spellcheck="false">${escapeHtml(content)}</textarea>
            <div id="configError" class="config-error hidden"></div>
        </div>
    `;
    
    container.innerHTML = html;
}

async function saveConfig() {
    const editor = document.getElementById('settingsEditor');
    const errorDiv = document.getElementById('configError');
    
    if (!editor) {
        showMessage('Editor not found', 'error');
        return;
    }
    
    const content = editor.value;
    
    if (!content || content.trim() === '') {
        showMessage('Content cannot be empty', 'error');
        return;
    }
    
    try {
        errorDiv.classList.add('hidden');
        showMessage('Saving settings.py...', 'info');
        
        const response = await fetch(`${API_BASE}/config`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content })
        });
        
        const data = await response.json();
        
        if (!response.ok || !data.success) {
            // Show syntax error if any
            if (data.line) {
                errorDiv.innerHTML = `
                    <strong>Syntax Error:</strong> ${data.error}<br>
                    <small>Line ${data.line}${data.offset ? `, column ${data.offset}` : ''}</small>
                `;
                errorDiv.classList.remove('hidden');
                editor.focus();
                // Try to scroll to error line (approximate)
                const lines = content.split('\n');
                const lineHeight = 20; // Approximate line height
                editor.scrollTop = (data.line - 1) * lineHeight;
            }
            throw new Error(data.error || 'Failed to save settings.py');
        }
        
        currentSettingsContent = content;
        showMessage(`settings.py saved successfully! Backup created: ${data.backup}`, 'success');
        errorDiv.classList.add('hidden');
    } catch (error) {
        console.error('Error saving settings.py:', error);
        showMessage('Error saving settings.py: ' + error.message, 'error');
    }
}

async function restoreBackup() {
    if (!confirm('Are you sure you want to restore from backup? This will replace current content.')) {
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/config/backup`);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        
        const data = await response.json();
        if (!data.success) {
            throw new Error(data.error || 'Failed to load backup');
        }
        
        if (!data.exists) {
            showMessage('No backup file found', 'error');
            return;
        }
        
        const editor = document.getElementById('settingsEditor');
        if (editor) {
            editor.value = data.content;
            currentSettingsContent = data.content;
            showMessage('Backup restored to editor. Click Save to apply.', 'success');
        }
    } catch (error) {
        console.error('Error restoring backup:', error);
        showMessage('Error restoring backup: ' + error.message, 'error');
    }
}

// This function is kept for backward compatibility but should use loadConfig() directly
async function renderConfigEditor() {
    await loadConfig();
}
window.viewTargetInOutput = viewTargetInOutput;
window.confirmDeleteTarget = confirmDeleteTarget;

