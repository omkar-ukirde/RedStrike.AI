/**
 * RedStrike.AI - Main Application
 */

// State
let currentProject = null;
let unsubscribe = null;

// DOM Elements
const loginScreen = document.getElementById('login-screen');
const dashboardScreen = document.getElementById('dashboard-screen');
const loginForm = document.getElementById('login-form');
const loginError = document.getElementById('login-error');
const userEmail = document.getElementById('user-email');
const logoutBtn = document.getElementById('logout-btn');

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    checkAuth();
    setupEventListeners();
});

function checkAuth() {
    const token = localStorage.getItem('token');
    if (token) {
        showDashboard();
        loadProjects();
    } else {
        showLogin();
    }
}

function showLogin() {
    loginScreen.classList.add('active');
    dashboardScreen.classList.remove('active');
}

function showDashboard() {
    loginScreen.classList.remove('active');
    dashboardScreen.classList.add('active');

    api.getCurrentUser().then(user => {
        userEmail.textContent = user.email;
    }).catch(() => { });
}

// Event Listeners
function setupEventListeners() {
    // Login
    loginForm.addEventListener('submit', handleLogin);
    logoutBtn.addEventListener('click', () => api.logout());

    // Navigation
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const view = item.dataset.view;
            switchView(view);
        });
    });

    // New Project
    document.getElementById('new-project-btn').addEventListener('click', () => {
        openModal('new-project-modal');
    });

    document.getElementById('new-project-form').addEventListener('submit', handleCreateProject);

    // Back button
    document.getElementById('back-to-projects').addEventListener('click', () => {
        switchView('projects');
        currentProject = null;
        if (unsubscribe) unsubscribe();
    });

    // Scan controls
    document.getElementById('start-scan-btn').addEventListener('click', handleStartScan);
    document.getElementById('pause-scan-btn').addEventListener('click', handlePauseScan);
    document.getElementById('export-btn').addEventListener('click', handleExport);

    // Tabs
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const tab = btn.dataset.tab;
            switchTab(tab);
        });
    });

    // Modal close
    document.querySelectorAll('.modal-close').forEach(btn => {
        btn.addEventListener('click', () => {
            closeAllModals();
        });
    });

    // Site view project select
    document.getElementById('site-view-project-select').addEventListener('change', (e) => {
        if (e.target.value) {
            loadSitemap(e.target.value);
        }
    });
}

// Login
async function handleLogin(e) {
    e.preventDefault();
    loginError.textContent = '';

    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    try {
        await api.login(email, password);
        showDashboard();
        loadProjects();
    } catch (error) {
        loginError.textContent = error.message;
    }
}

// Views
function switchView(view) {
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    document.querySelector(`#${view}-view`)?.classList.add('active');

    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.toggle('active', item.dataset.view === view);
    });

    // Load data for specific views
    if (view === 'site-view') {
        loadProjectsForSiteView();
    }
}

function switchTab(tab) {
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === tab);
    });
    document.querySelectorAll('.tab-pane').forEach(pane => {
        pane.classList.toggle('active', pane.id === tab);
    });
}

// Projects
async function loadProjects() {
    try {
        const projects = await api.getProjects();
        renderProjects(projects);
    } catch (error) {
        console.error('Failed to load projects:', error);
    }
}

function renderProjects(projects) {
    const container = document.getElementById('projects-list');

    if (projects.length === 0) {
        container.innerHTML = `
            <div class="placeholder-text">
                No projects yet. Click "New Project" to create one.
            </div>
        `;
        return;
    }

    container.innerHTML = projects.map(p => `
        <div class="project-card" data-id="${p.id}">
            <h3>${escapeHtml(p.name)}</h3>
            <code>${escapeHtml(p.target_url || 'No target')}</code>
            <div class="project-card-meta">
                <span class="status-badge status-${p.status}">${p.status}</span>
                <span>${p.findings_count || 0} findings</span>
            </div>
        </div>
    `).join('');

    // Add click handlers
    container.querySelectorAll('.project-card').forEach(card => {
        card.addEventListener('click', () => openProject(card.dataset.id));
    });
}

async function openProject(projectId) {
    try {
        currentProject = await api.getProject(projectId);
        renderProjectDetail(currentProject);

        // Connect WebSocket
        wsClient.connect(projectId);
        unsubscribe = wsClient.subscribe(projectId, {
            onScanUpdate: handleScanUpdate,
            onNewFinding: handleNewFinding,
            onScanComplete: handleScanComplete,
        });

        // Load findings
        loadProjectFindings(projectId);

        // Switch view
        document.getElementById('projects-view').classList.remove('active');
        document.getElementById('project-detail-view').classList.add('active');
    } catch (error) {
        console.error('Failed to open project:', error);
    }
}

function renderProjectDetail(project) {
    document.getElementById('project-name').textContent = project.name;
    document.getElementById('project-target').textContent = project.target_url || 'No target';

    const statusEl = document.getElementById('project-status');
    statusEl.textContent = project.status;
    statusEl.className = `status-badge status-${project.status}`;

    // Update buttons
    const startBtn = document.getElementById('start-scan-btn');
    const pauseBtn = document.getElementById('pause-scan-btn');

    if (project.status === 'running') {
        startBtn.style.display = 'none';
        pauseBtn.style.display = 'block';
    } else {
        startBtn.style.display = 'block';
        pauseBtn.style.display = 'none';
        startBtn.textContent = project.status === 'paused' ? '▶ Resume' : '▶ Start Scan';
    }
}

async function loadProjectFindings(projectId) {
    try {
        const findings = await api.getFindings(projectId);
        renderFindings(findings);
    } catch (error) {
        console.error('Failed to load findings:', error);
    }
}

function renderFindings(findings) {
    const container = document.getElementById('findings-list');

    if (findings.length === 0) {
        container.innerHTML = '<div class="placeholder-text">No findings yet</div>';
        return;
    }

    container.innerHTML = findings.map(f => `
        <div class="finding-row" data-id="${f.id}">
            <span class="severity-badge severity-${f.severity}">${f.severity}</span>
            <span class="finding-title">${escapeHtml(f.title)}</span>
            <span class="finding-type">${f.vulnerability_type}</span>
            <span class="finding-verified">${f.verified ? '✓ Verified' : ''}</span>
        </div>
    `).join('');

    container.querySelectorAll('.finding-row').forEach(row => {
        row.addEventListener('click', () => openFinding(row.dataset.id));
    });
}

// Create Project
async function handleCreateProject(e) {
    e.preventDefault();

    const name = document.getElementById('project-name-input').value;
    const prompt = document.getElementById('project-prompt').value;
    const model = document.getElementById('model-select').value || null;

    try {
        await api.createProject(name, prompt, model);
        closeAllModals();
        loadProjects();

        // Clear form
        document.getElementById('project-name-input').value = '';
        document.getElementById('project-prompt').value = '';
    } catch (error) {
        alert('Failed to create project: ' + error.message);
    }
}

// Scan Controls
async function handleStartScan() {
    if (!currentProject) return;
    try {
        await api.startProject(currentProject.id);
        currentProject.status = 'running';
        renderProjectDetail(currentProject);
        addLogEntry('system', 'Scan started...');
    } catch (error) {
        alert('Failed to start scan: ' + error.message);
    }
}

async function handlePauseScan() {
    if (!currentProject) return;
    try {
        await api.pauseProject(currentProject.id);
        currentProject.status = 'paused';
        renderProjectDetail(currentProject);
        addLogEntry('system', 'Scan paused');
    } catch (error) {
        alert('Failed to pause scan: ' + error.message);
    }
}

async function handleExport() {
    if (!currentProject) return;
    try {
        await api.exportFindings(currentProject.id);
    } catch (error) {
        alert('Failed to export: ' + error.message);
    }
}

// WebSocket Handlers
function handleScanUpdate(data) {
    addLogEntry(data.phase, data.message);

    // Update status if changed
    if (data.status === 'completed' || data.status === 'failed') {
        currentProject.status = data.status;
        renderProjectDetail(currentProject);
    }
}

function handleNewFinding(finding) {
    addLogEntry('finding', `New finding: ${finding.title} [${finding.severity}]`);
    loadProjectFindings(currentProject.id);
}

function handleScanComplete(summary) {
    addLogEntry('system', `Scan complete! Found ${summary.findings} vulnerabilities.`);
    currentProject.status = 'completed';
    renderProjectDetail(currentProject);
}

function addLogEntry(phase, message) {
    const container = document.getElementById('scan-log-content');

    // Remove empty placeholder
    const empty = container.querySelector('.log-empty');
    if (empty) empty.remove();

    const time = new Date().toLocaleTimeString();
    const entry = document.createElement('div');
    entry.className = 'log-entry';
    entry.innerHTML = `
        <span class="log-time">${time}</span>
        <span class="log-phase">[${phase}]</span>
        <span class="log-message">${escapeHtml(message)}</span>
    `;
    container.appendChild(entry);
    container.scrollTop = container.scrollHeight;
}

// Finding Detail
async function openFinding(findingId) {
    try {
        const finding = await api.getFinding(findingId);
        renderFindingDetail(finding);
        openModal('finding-modal');
    } catch (error) {
        console.error('Failed to load finding:', error);
    }
}

function renderFindingDetail(finding) {
    document.getElementById('finding-title').textContent = finding.title;

    const severityEl = document.getElementById('finding-severity');
    severityEl.textContent = finding.severity;
    severityEl.className = `severity-badge severity-${finding.severity}`;

    document.getElementById('finding-type').textContent = finding.vulnerability_type;
    document.getElementById('finding-verified').textContent = finding.verified ? '✓ Verified' : 'Unverified';
    document.getElementById('finding-url').textContent = finding.affected_url;
    document.getElementById('finding-description').textContent = finding.description;

    const reproEl = document.getElementById('finding-repro');
    if (finding.reproduction_steps) {
        reproEl.innerHTML = finding.reproduction_steps;
    } else {
        reproEl.innerHTML = '<em>No reproduction steps available</em>';
    }

    const pocEl = document.getElementById('finding-poc');
    if (finding.poc_code) {
        pocEl.textContent = finding.poc_code;
    } else {
        pocEl.textContent = '# No PoC code available';
    }

    // Bind buttons
    document.getElementById('mark-verified-btn').onclick = () => markFinding(finding.id, { verified: true });
    document.getElementById('mark-fp-btn').onclick = () => markFinding(finding.id, { false_positive: true });
}

async function markFinding(findingId, data) {
    try {
        await api.updateFinding(findingId, data);
        closeAllModals();
        loadProjectFindings(currentProject.id);
    } catch (error) {
        alert('Failed to update finding: ' + error.message);
    }
}

// Site View
async function loadProjectsForSiteView() {
    try {
        const projects = await api.getProjects();
        const select = document.getElementById('site-view-project-select');

        select.innerHTML = '<option value="">Select a project...</option>' +
            projects.map(p => `<option value="${p.id}">${escapeHtml(p.name)}</option>`).join('');
    } catch (error) {
        console.error('Failed to load projects for site view:', error);
    }
}

async function loadSitemap(projectId) {
    try {
        const data = await api.getSitemap(projectId);
        renderSitemap(data.sitemap);
    } catch (error) {
        console.error('Failed to load sitemap:', error);
    }
}

function renderSitemap(sitemap) {
    const container = document.getElementById('site-tree');
    container.innerHTML = renderSitemapNode(sitemap);
}

function renderSitemapNode(node, level = 0) {
    let html = '';

    // Render endpoints at this node
    for (const endpoint of (node.endpoints || [])) {
        const methodClass = `method-${endpoint.method.toLowerCase()}`;
        const findings = node.findings || [];
        const findingBadges = findings.map(f =>
            `<span class="tree-finding-badge" style="background:var(--severity-${f.severity})"></span>`
        ).join('');

        html += `
            <div class="tree-endpoint" style="padding-left:${level * 20}px">
                <span class="method ${methodClass}">${endpoint.method}</span>
                ${escapeHtml(endpoint.url)}
                ${findingBadges}
            </div>
        `;
    }

    // Render children
    for (const [name, child] of Object.entries(node.children || {})) {
        html += `
            <div class="tree-node" style="padding-left:${level * 20}px">
                <div class="tree-folder">${escapeHtml(name)}/</div>
                ${renderSitemapNode(child, level + 1)}
            </div>
        `;
    }

    return html;
}

// Modal
function openModal(modalId) {
    document.getElementById(modalId).classList.add('active');
}

function closeAllModals() {
    document.querySelectorAll('.modal').forEach(m => m.classList.remove('active'));
}

// Utilities
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
