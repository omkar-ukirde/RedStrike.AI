/**
 * RedStrike.AI - WebSocket Client
 */

class RedStrikeWebSocket {
    constructor() {
        this.connections = new Map();
        this.listeners = new Map();
    }

    connect(projectId) {
        if (this.connections.has(projectId)) {
            return this.connections.get(projectId);
        }

        const token = localStorage.getItem('token');
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/projects/${projectId}?token=${token}`;

        const ws = new WebSocket(wsUrl);

        ws.onopen = () => {
            console.log(`WebSocket connected for project ${projectId}`);
        };

        ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                this.handleMessage(projectId, data);
            } catch (e) {
                console.error('WebSocket message parse error:', e);
            }
        };

        ws.onclose = () => {
            console.log(`WebSocket disconnected for project ${projectId}`);
            this.connections.delete(projectId);
        };

        ws.onerror = (error) => {
            console.error('WebSocket error:', error);
        };

        this.connections.set(projectId, ws);
        return ws;
    }

    disconnect(projectId) {
        const ws = this.connections.get(projectId);
        if (ws) {
            ws.close();
            this.connections.delete(projectId);
        }
    }

    disconnectAll() {
        this.connections.forEach((ws, projectId) => {
            ws.close();
        });
        this.connections.clear();
    }

    handleMessage(projectId, data) {
        const listeners = this.listeners.get(projectId) || [];

        switch (data.type) {
            case 'scan_update':
                listeners.forEach(l => l.onScanUpdate?.(data));
                break;
            case 'new_finding':
                listeners.forEach(l => l.onNewFinding?.(data.finding));
                break;
            case 'new_endpoint':
                listeners.forEach(l => l.onNewEndpoint?.(data.endpoint));
                break;
            case 'scan_complete':
                listeners.forEach(l => l.onScanComplete?.(data.summary));
                break;
            case 'pong':
                // Heartbeat response
                break;
            default:
                console.log('Unknown message type:', data.type);
        }
    }

    subscribe(projectId, listener) {
        if (!this.listeners.has(projectId)) {
            this.listeners.set(projectId, []);
        }
        this.listeners.get(projectId).push(listener);

        // Return unsubscribe function
        return () => {
            const listeners = this.listeners.get(projectId);
            const index = listeners.indexOf(listener);
            if (index > -1) {
                listeners.splice(index, 1);
            }
        };
    }

    sendPing(projectId) {
        const ws = this.connections.get(projectId);
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'ping' }));
        }
    }
}

// Global WebSocket instance
const wsClient = new RedStrikeWebSocket();
