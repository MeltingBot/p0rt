// P0rt Admin JavaScript
class P0rtAdmin {
    constructor() {
        this.apiKey = this.getApiKey();
        this.refreshInterval = null;
        this.currentSection = 'dashboard';
        this.currentAbuseFilter = 'pending';
        
        this.init();
    }

    init() {
        this.setupNavigation();
        this.setupModals();
        this.setupAbuseFilters();
        this.loadDashboard();
        this.startAutoRefresh();
    }

    // API Configuration
    getApiKey() {
        // Try to get API key from URL params, localStorage, or prompt
        const urlParams = new URLSearchParams(window.location.search);
        let apiKey = urlParams.get('api_key') || localStorage.getItem('p0rt_api_key');
        
        if (!apiKey) {
            apiKey = prompt('Clé API P0rt requise:');
            if (apiKey) {
                localStorage.setItem('p0rt_api_key', apiKey);
            }
        }
        return apiKey;
    }

    async apiCall(endpoint, options = {}) {
        const headers = {
            'Content-Type': 'application/json',
            ...options.headers
        };

        if (this.apiKey) {
            headers['X-API-Key'] = this.apiKey;
        }

        try {
            const response = await fetch(endpoint, {
                ...options,
                headers
            });

            if (!response.ok) {
                // Try to parse error response body
                let errorMessage = `HTTP ${response.status}: ${response.statusText}`;
                let errorData = null;
                
                try {
                    const contentType = response.headers.get('content-type');
                    if (contentType && contentType.includes('application/json')) {
                        errorData = await response.json();
                        if (errorData.message) {
                            errorMessage = errorData.message;
                        } else if (errorData.error && typeof errorData.error === 'string') {
                            errorMessage = errorData.error;
                        }
                    }
                } catch (parseError) {
                    // If we can't parse the error response, use the status text
                    console.warn('Could not parse error response:', parseError);
                }

                // Handle specific status codes
                switch (response.status) {
                    case 401:
                        this.showToast('🔐 Authentification échouée. Vérifiez votre clé API.', 'error');
                        localStorage.removeItem('p0rt_api_key');
                        this.apiKey = this.getApiKey();
                        throw new Error('Authentication failed');
                        
                    case 403:
                        this.showToast('🚫 Accès refusé. Permissions insuffisantes.', 'error');
                        break;
                        
                    case 404:
                        this.showToast('❓ Ressource non trouvée.', 'error');
                        break;
                        
                    case 409:
                        this.showToast(`⚠️ Conflit: ${errorMessage}`, 'error');
                        break;
                        
                    case 422:
                        this.showToast(`📝 Données invalides: ${errorMessage}`, 'error');
                        break;
                        
                    case 429:
                        this.showToast('⏳ Trop de requêtes. Veuillez patienter.', 'warning');
                        break;
                        
                    case 500:
                        this.showToast('💥 Erreur serveur interne. Contactez l\'administrateur.', 'error');
                        break;
                        
                    case 503:
                        this.showToast('🔧 Service temporairement indisponible.', 'warning');
                        break;
                        
                    default:
                        this.showToast(`❌ Erreur ${response.status}: ${errorMessage}`, 'error');
                }
                
                const error = new Error(errorMessage);
                error.status = response.status;
                error.data = errorData;
                throw error;
            }

            return await response.json();
        } catch (error) {
            // Network errors or other fetch errors
            if (error.name === 'TypeError' && error.message.includes('fetch')) {
                this.showToast('🌐 Erreur de connexion. Vérifiez votre réseau.', 'error');
            } else if (!error.status) {
                // Only show generic error if we haven't already shown a specific one
                this.showToast(`⚠️ Erreur: ${error.message}`, 'error');
            }
            
            console.error('API Call failed:', error);
            throw error;
        }
    }

    // Navigation
    setupNavigation() {
        document.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const section = link.dataset.section;
                this.showSection(section);
            });
        });
    }

    showSection(section) {
        // Update navigation
        document.querySelectorAll('.nav-link').forEach(link => {
            link.classList.toggle('active', link.dataset.section === section);
        });

        // Update sections
        document.querySelectorAll('.section').forEach(sec => {
            sec.classList.toggle('active', sec.id === section);
        });

        this.currentSection = section;

        // Load section data
        switch(section) {
            case 'dashboard':
                this.loadDashboard();
                break;
            case 'connections':
                this.loadConnections();
                break;
            case 'domains':
                this.loadDomains();
                break;
            case 'security':
                this.loadSecurity();
                break;
            case 'abuse':
                this.loadAbuseReports();
                break;
            case 'keys':
                this.loadKeys();
                break;
        }
    }

    // Dashboard
    async loadDashboard() {
        try {
            const [stats, serverStatus, connections] = await Promise.all([
                this.apiCall('/api/v1/stats'),
                this.apiCall('/api/v1/server/status'),
                this.apiCall('/api/v1/connections').catch(() => ({connections: []}))
            ]);

            // Update stat cards
            this.updateElement('active-tunnels', stats.global_stats?.active_tunnels || connections.connections?.length || 0);
            this.updateElement('total-connections', stats.global_stats?.total_connections || '-');
            
            // Get security stats
            const securityStats = await this.apiCall('/api/v1/security/stats').catch(() => ({security_stats: {}}));
            this.updateElement('banned-ips', securityStats.security_stats?.blocked_ips_count || 0);
            
            // Get abuse stats
            const abuseStats = await this.apiCall('/api/v1/abuse/stats').catch(() => ({stats: {}}));
            this.updateElement('abuse-reports', abuseStats.stats?.pending || 0);

            // Update server status
            this.updateServerStatus(serverStatus.server);
            
            // Update recent activity
            this.updateRecentActivity(connections.connections?.slice(0, 5) || []);

        } catch (error) {
            console.error('Failed to load dashboard:', error);
        }
    }

    updateServerStatus(server) {
        const statusHtml = `
            <div class="status-grid">
                <div class="status-item">
                    <strong>Status:</strong> 
                    <span class="status-badge status-online">${server.status}</span>
                </div>
                <div class="status-item">
                    <strong>Version:</strong> ${server.version}
                </div>
                <div class="status-item">
                    <strong>SSH Port:</strong> ${server.ssh.port}
                </div>
                <div class="status-item">
                    <strong>HTTP Port:</strong> ${server.http.port}
                </div>
                <div class="status-item">
                    <strong>Storage:</strong> ${server.storage.type}
                </div>
                <div class="status-item">
                    <strong>Access Mode:</strong> ${server.security.access_mode}
                </div>
            </div>
        `;
        this.updateElement('server-status', statusHtml);
    }

    updateRecentActivity(connections) {
        const activityHtml = connections.length > 0 ? 
            connections.map(conn => `
                <div class="activity-item">
                    <strong>${conn.domain}</strong> - ${conn.client_ip}
                    <span class="text-muted">${this.formatDate(conn.connected_at)}</span>
                </div>
            `).join('') :
            '<div class="text-muted">Aucune activité récente</div>';
        
        this.updateElement('recent-activity', activityHtml);
    }

    // Connections
    async loadConnections() {
        try {
            const response = await this.apiCall('/api/v1/connections');
            const tbody = document.getElementById('connections-table');
            
            if (response.connections.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">Aucune connexion active</td></tr>';
                return;
            }

            tbody.innerHTML = response.connections.map(conn => `
                <tr>
                    <td><strong>${conn.domain}</strong></td>
                    <td>${conn.client_ip}</td>
                    <td>${this.formatDate(conn.connected_at)}</td>
                    <td>${this.formatBytes(conn.bytes_sent || 0)} / ${this.formatBytes(conn.bytes_received || 0)}</td>
                    <td><span class="status-badge status-online">Actif</span></td>
                </tr>
            `).join('');
        } catch (error) {
            document.getElementById('connections-table').innerHTML = 
                '<tr><td colspan="5" class="text-center text-danger">Erreur de chargement</td></tr>';
        }
    }

    // Domains
    async loadDomains() {
        try {
            const response = await this.apiCall('/api/v1/reservations');
            const tbody = document.getElementById('domains-table');
            
            if (response.reservations.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">Aucune réservation</td></tr>';
                return;
            }

            tbody.innerHTML = response.reservations.map(res => `
                <tr>
                    <td><strong>${res.domain}</strong></td>
                    <td><code>${res.fingerprint.substring(0, 16)}...</code></td>
                    <td>${res.comment || '-'}</td>
                    <td>${this.formatDate(res.created_at)}</td>
                    <td>
                        <button class="btn btn-danger btn-sm" onclick="p0rtAdmin.deleteDomain('${res.domain}')">
                            Supprimer
                        </button>
                    </td>
                </tr>
            `).join('');
        } catch (error) {
            document.getElementById('domains-table').innerHTML = 
                '<tr><td colspan="5" class="text-center text-danger">Erreur de chargement</td></tr>';
        }
    }

    async deleteDomain(domain) {
        if (!confirm(`Supprimer la réservation pour ${domain} ?`)) return;

        try {
            await this.apiCall(`/api/v1/reservations/${domain}`, { method: 'DELETE' });
            this.showToast(`Réservation ${domain} supprimée`, 'success');
            this.loadDomains();
        } catch (error) {
            // Error already handled by apiCall
        }
    }

    // Security
    async loadSecurity() {
        try {
            const [securityStats, bannedIPs] = await Promise.all([
                this.apiCall('/api/v1/security/stats'),
                this.apiCall('/api/v1/security/bans')
            ]);

            // Update security stats
            this.updateElement('auth-failures', securityStats.security_stats?.last_24h_failures || 0);
            this.updateElement('scan-attempts', securityStats.security_stats?.scanning_attempts || 0);

            // Update banned IPs table
            const tbody = document.getElementById('banned-ips-table');
            
            if (bannedIPs.banned_ips.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">Aucune IP bannie</td></tr>';
                return;
            }

            tbody.innerHTML = bannedIPs.banned_ips.map(ban => `
                <tr>
                    <td><code>${ban.ip}</code></td>
                    <td>${ban.reason}</td>
                    <td>${this.formatDate(ban.banned_at)}</td>
                    <td>${ban.expires_at ? this.formatDate(ban.expires_at) : 'Permanent'}</td>
                    <td>
                        <button class="btn btn-success btn-sm" onclick="p0rtAdmin.unbanIP('${ban.ip}')">
                            Débannir
                        </button>
                    </td>
                </tr>
            `).join('');
        } catch (error) {
            document.getElementById('banned-ips-table').innerHTML = 
                '<tr><td colspan="5" class="text-center text-danger">Erreur de chargement</td></tr>';
        }
    }

    async unbanIP(ip) {
        if (!confirm(`Débannir l'IP ${ip} ?`)) return;

        try {
            await this.apiCall('/api/v1/security/unban', {
                method: 'POST',
                body: JSON.stringify({ ip })
            });
            this.showToast(`IP ${ip} débannie`, 'success');
            this.loadSecurity();
        } catch (error) {
            // Error already handled by apiCall
        }
    }

    // Abuse Reports
    setupAbuseFilters() {
        document.querySelectorAll('.filter-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('.filter-tab').forEach(t => t.classList.remove('active'));
                tab.classList.add('active');
                this.currentAbuseFilter = tab.dataset.status;
                this.loadAbuseReports();
            });
        });
    }

    async loadAbuseReports() {
        try {
            const url = this.currentAbuseFilter ? 
                `/api/v1/abuse/reports?status=${this.currentAbuseFilter}` :
                '/api/v1/abuse/reports?all=true';
            
            const response = await this.apiCall(url);
            const tbody = document.getElementById('abuse-reports-table');
            
            if (response.reports.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">Aucun report d\'abus</td></tr>';
                return;
            }

            tbody.innerHTML = response.reports.map(report => `
                <tr>
                    <td><code>${report.id.substring(0, 8)}</code></td>
                    <td><strong>${report.domain}</strong></td>
                    <td>${report.type}</td>
                    <td>${report.reporter_email}</td>
                    <td>${this.formatDate(report.created_at)}</td>
                    <td><span class="status-badge status-${report.status}">${report.status}</span></td>
                    <td>
                        ${report.status === 'pending' ? `
                            <button class="btn btn-danger btn-sm" onclick="p0rtAdmin.processAbuseReport('${report.id}', 'ban')">
                                Bannir
                            </button>
                            <button class="btn btn-success btn-sm" onclick="p0rtAdmin.processAbuseReport('${report.id}', 'accept')">
                                Accepter
                            </button>
                        ` : `
                            <button class="btn btn-secondary btn-sm" onclick="p0rtAdmin.viewAbuseReport('${report.id}')">
                                Voir
                            </button>
                        `}
                    </td>
                </tr>
            `).join('');
        } catch (error) {
            document.getElementById('abuse-reports-table').innerHTML = 
                '<tr><td colspan="7" class="text-center text-danger">Erreur de chargement</td></tr>';
        }
    }

    async processAbuseReport(reportId, action) {
        const actionText = action === 'ban' ? 'bannir' : 'accepter';
        if (!confirm(`${actionText} ce report d'abus ?`)) return;

        try {
            await this.apiCall(`/api/v1/abuse/reports/${reportId}`, {
                method: 'POST',
                body: JSON.stringify({ action })
            });
            this.showToast(`Report ${actionText === 'bannir' ? 'banni' : 'accepté'}`, 'success');
            this.loadAbuseReports();
        } catch (error) {
            // Error already handled by apiCall
        }
    }

    async viewAbuseReport(reportId) {
        try {
            const response = await this.apiCall(`/api/v1/abuse/reports/${reportId}`);
            const report = response.report;
            
            this.showModal('Détails du Report', `
                <div class="form-group">
                    <label class="form-label">ID:</label>
                    <p><code>${report.id}</code></p>
                </div>
                <div class="form-group">
                    <label class="form-label">Domaine:</label>
                    <p><strong>${report.domain}</strong></p>
                </div>
                <div class="form-group">
                    <label class="form-label">Type:</label>
                    <p>${report.type}</p>
                </div>
                <div class="form-group">
                    <label class="form-label">Reporter:</label>
                    <p>${report.reporter_email}</p>
                </div>
                <div class="form-group">
                    <label class="form-label">Description:</label>
                    <p>${report.description}</p>
                </div>
                <div class="form-group">
                    <label class="form-label">Status:</label>
                    <p><span class="status-badge status-${report.status}">${report.status}</span></p>
                </div>
                <div class="form-group">
                    <label class="form-label">Date:</label>
                    <p>${this.formatDate(report.created_at)}</p>
                </div>
            `);
        } catch (error) {
            // Error already handled by apiCall
        }
    }

    // SSH Keys
    async loadKeys() {
        try {
            const response = await this.apiCall('/api/v1/keys');
            const tbody = document.getElementById('keys-table');
            
            if (response.keys.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">Aucune clé SSH</td></tr>';
                return;
            }

            tbody.innerHTML = response.keys.map(key => `
                <tr>
                    <td><code>${key.fingerprint.substring(0, 16)}...</code></td>
                    <td>${key.type}</td>
                    <td>${key.comment || '-'}</td>
                    <td><span class="status-badge status-${key.active ? 'online' : 'offline'}">${key.active ? 'Actif' : 'Inactif'}</span></td>
                    <td>${this.formatDate(key.created_at)}</td>
                    <td>
                        <button class="btn btn-${key.active ? 'warning' : 'success'} btn-sm" 
                                onclick="p0rtAdmin.toggleKey('${key.fingerprint}', ${!key.active})">
                            ${key.active ? 'Désactiver' : 'Activer'}
                        </button>
                        <button class="btn btn-danger btn-sm" onclick="p0rtAdmin.deleteKey('${key.fingerprint}')">
                            Supprimer
                        </button>
                    </td>
                </tr>
            `).join('');
        } catch (error) {
            document.getElementById('keys-table').innerHTML = 
                '<tr><td colspan="6" class="text-center text-danger">Erreur de chargement</td></tr>';
        }
    }

    async toggleKey(fingerprint, activate) {
        try {
            await this.apiCall(`/api/v1/keys/${fingerprint}`, {
                method: 'PATCH',
                body: JSON.stringify({ active: activate })
            });
            this.showToast(`Clé ${activate ? 'activée' : 'désactivée'}`, 'success');
            this.loadKeys();
        } catch (error) {
            // Error already handled by apiCall
        }
    }

    async deleteKey(fingerprint) {
        if (!confirm('Supprimer cette clé SSH ?')) return;

        try {
            await this.apiCall(`/api/v1/keys/${fingerprint}`, { method: 'DELETE' });
            this.showToast('Clé supprimée', 'success');
            this.loadKeys();
        } catch (error) {
            // Error already handled by apiCall
        }
    }

    // Modals
    setupModals() {
        window.closeModal = () => {
            document.getElementById('modal-overlay').classList.remove('active');
        };

        window.showAddDomainModal = () => {
            this.showModal('Nouvelle Réservation de Domaine', `
                <form onsubmit="p0rtAdmin.addDomain(event)">
                    <div class="form-group">
                        <label class="form-label">Domaine:</label>
                        <input type="text" class="form-input" name="domain" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Empreinte SSH:</label>
                        <input type="text" class="form-input" name="fingerprint" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Commentaire:</label>
                        <input type="text" class="form-input" name="comment">
                    </div>
                    <div class="form-actions">
                        <button type="button" class="btn" onclick="closeModal()">Annuler</button>
                        <button type="submit" class="btn btn-primary">Créer</button>
                    </div>
                </form>
            `);
        };

        window.showAddKeyModal = () => {
            this.showModal('Ajouter Clé SSH', `
                <form onsubmit="p0rtAdmin.addKey(event)">
                    <div class="form-group">
                        <label class="form-label">Clé SSH publique:</label>
                        <textarea class="form-textarea" name="key" rows="4" required placeholder="ssh-rsa AAAAB3NzaC1yc2E..."></textarea>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Commentaire:</label>
                        <input type="text" class="form-input" name="comment">
                    </div>
                    <div class="form-actions">
                        <button type="button" class="btn" onclick="closeModal()">Annuler</button>
                        <button type="submit" class="btn btn-primary">Ajouter</button>
                    </div>
                </form>
            `);
        };
    }

    showModal(title, content) {
        document.getElementById('modal-title').textContent = title;
        document.getElementById('modal-body').innerHTML = content;
        document.getElementById('modal-overlay').classList.add('active');
    }

    async addDomain(event) {
        event.preventDefault();
        const formData = new FormData(event.target);
        
        try {
            await this.apiCall('/api/v1/reservations', {
                method: 'POST',
                body: JSON.stringify({
                    domain: formData.get('domain'),
                    fingerprint: formData.get('fingerprint'),
                    comment: formData.get('comment')
                })
            });
            this.showToast('Réservation créée', 'success');
            closeModal();
            this.loadDomains();
        } catch (error) {
            // Error already handled by apiCall
        }
    }

    async addKey(event) {
        event.preventDefault();
        const formData = new FormData(event.target);
        
        try {
            await this.apiCall('/api/v1/keys', {
                method: 'POST',
                body: JSON.stringify({
                    key: formData.get('key'),
                    comment: formData.get('comment')
                })
            });
            this.showToast('Clé ajoutée', 'success');
            closeModal();
            this.loadKeys();
        } catch (error) {
            // Error already handled by apiCall
        }
    }

    // Toast notifications
    showToast(message, type = 'success') {
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        
        const icon = type === 'success' ? '✓' : type === 'error' ? '✗' : '⚠';
        
        toast.innerHTML = `
            <span class="toast-icon">${icon}</span>
            <span class="toast-message">${message}</span>
            <button class="toast-close" onclick="this.parentElement.remove()">×</button>
        `;
        
        document.getElementById('toast-container').appendChild(toast);
        
        setTimeout(() => {
            if (toast.parentElement) {
                toast.remove();
            }
        }, 5000);
    }

    // Auto refresh
    startAutoRefresh() {
        this.refreshInterval = setInterval(() => {
            if (this.currentSection === 'dashboard') {
                this.loadDashboard();
            } else if (this.currentSection === 'connections') {
                this.loadConnections();
            }
        }, 30000); // Refresh every 30 seconds
    }

    stopAutoRefresh() {
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
            this.refreshInterval = null;
        }
    }

    // Utility functions
    updateElement(id, content) {
        const element = document.getElementById(id);
        if (element) {
            element.innerHTML = content;
        }
    }

    formatDate(dateString) {
        if (!dateString) return '-';
        return new Date(dateString).toLocaleString('fr-FR');
    }

    formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
}

// Global functions for window scope
window.refreshData = () => {
    if (window.p0rtAdmin) {
        window.p0rtAdmin.loadDashboard();
    }
};

window.loadConnections = () => {
    if (window.p0rtAdmin) {
        window.p0rtAdmin.loadConnections();
    }
};

window.loadSecurity = () => {
    if (window.p0rtAdmin) {
        window.p0rtAdmin.loadSecurity();
    }
};

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.p0rtAdmin = new P0rtAdmin();
});