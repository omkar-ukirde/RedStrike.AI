/**
 * RedStrike.AI - API Client
 * Enterprise-grade API client with async scan support
 */

const API_BASE = '/api';
const POLL_INTERVAL = 2000; // 2 seconds

class RedStrikeAPI {
    constructor() {
        this.token = localStorage.getItem('token');
        this._pollTimers = {};
    }

    async request(endpoint, options = {}) {
        const url = `${API_BASE}${endpoint}`;
        const headers = {
            'Content-Type': 'application/json',
            ...options.headers,
        };

        if (this.token) {
            headers['Authorization'] = `Bearer ${this.token}`;
        }

        const response = await fetch(url, {
            ...options,
            headers,
        });

        if (response.status === 401) {
            this.logout();
            throw new Error('Session expired');
        }

        if (!response.ok) {
            const error = await response.json().catch(() => ({}));
            throw new Error(error.detail || 'Request failed');
        }

        return response.json();
    }

    // Auth
    async login(email, password) {
        const data = await this.request('/auth/login', {
            method: 'POST',
            body: JSON.stringify({ email, password }),
        });

        this.token = data.access_token;
        localStorage.setItem('token', data.access_token);
        localStorage.setItem('refreshToken', data.refresh_token);

        return data;
    }

    logout() {
        this.token = null;
        localStorage.removeItem('token');
        localStorage.removeItem('refreshToken');
        this.stopAllPolling();
        window.location.reload();
    }

    async getCurrentUser() {
        return this.request('/auth/me');
    }

    // Projects
    async getProjects() {
        return this.request('/projects');
    }

    async getProject(id) {
        return this.request(`/projects/${id}`);
    }

    async createProject(name, prompt, model_name = null) {
        return this.request('/projects/', {
            method: 'POST',
            body: JSON.stringify({ name, prompt, model_name }),
        });
    }

    async startProject(id) {
        return this.request(`/projects/${id}/start`, { method: 'POST' });
    }

    async pauseProject(id) {
        return this.request(`/projects/${id}/pause`, { method: 'POST' });
    }

    async cancelScan(id) {
        return this.request(`/projects/${id}/cancel`, { method: 'POST' });
    }

    async deleteProject(id) {
        return this.request(`/projects/${id}`, { method: 'DELETE' });
    }

    async deleteScanLogs(id) {
        return this.request(`/projects/${id}/logs`, { method: 'DELETE' });
    }

    // Scan Status & Progress
    async getScanStatus(id) {
        return this.request(`/projects/${id}/status`);
    }

    /**
     * Start polling scan status with callback
     * @param {number} projectId - Project ID
     * @param {function} callback - Called with status on each poll
     * @returns {function} Stop polling function
     */
    startStatusPolling(projectId, callback) {
        // Stop any existing polling for this project
        this.stopPolling(projectId);

        const poll = async () => {
            try {
                const status = await this.getScanStatus(projectId);
                callback(null, status);

                // Stop polling if scan is complete or failed
                if (['completed', 'failed', 'pending'].includes(status.project_status)) {
                    this.stopPolling(projectId);
                }
            } catch (error) {
                callback(error, null);
            }
        };

        // Poll immediately, then at interval
        poll();
        this._pollTimers[projectId] = setInterval(poll, POLL_INTERVAL);

        // Return stop function
        return () => this.stopPolling(projectId);
    }

    stopPolling(projectId) {
        if (this._pollTimers[projectId]) {
            clearInterval(this._pollTimers[projectId]);
            delete this._pollTimers[projectId];
        }
    }

    stopAllPolling() {
        Object.keys(this._pollTimers).forEach(id => this.stopPolling(id));
    }

    // Findings
    async getFindings(projectId) {
        return this.request(`/projects/${projectId}/findings`);
    }

    async getFinding(id) {
        return this.request(`/findings/${id}`);
    }

    async updateFinding(id, data) {
        return this.request(`/findings/${id}`, {
            method: 'PATCH',
            body: JSON.stringify(data),
        });
    }

    async exportFindings(projectId) {
        const response = await fetch(`${API_BASE}/projects/${projectId}/export`, {
            headers: {
                'Authorization': `Bearer ${this.token}`,
            },
        });

        if (!response.ok) throw new Error('Export failed');

        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `findings_${projectId}.csv`;
        a.click();
        window.URL.revokeObjectURL(url);
    }

    // Endpoints / Sitemap
    async getEndpoints(projectId) {
        return this.request(`/projects/${projectId}/endpoints`);
    }

    async getSitemap(projectId) {
        return this.request(`/projects/${projectId}/sitemap`);
    }

    async getEndpointHistory(endpointId) {
        return this.request(`/endpoints/${endpointId}/history`);
    }

    async getEndpointFindings(endpointId) {
        return this.request(`/endpoints/${endpointId}/findings`);
    }

    // Health
    async healthCheck() {
        return this.request('/health');
    }
}

// Global API instance
const api = new RedStrikeAPI();
