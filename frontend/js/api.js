/**
 * RedStrike.AI - API Client
 */

const API_BASE = '/api';

class RedStrikeAPI {
    constructor() {
        this.token = localStorage.getItem('token');
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

    async deleteProject(id) {
        return this.request(`/projects/${id}`, { method: 'DELETE' });
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
