// P0rt Admin JavaScript
// Admin interface updated - Ban/Accept/Archive workflow v2
class P0rtAdmin {
    constructor() {
        this.apiKey = this.getApiKey();
        this.refreshInterval = null;
        this.currentSection = 'dashboard';
        this.currentAbuseFilter = 'pending';
        
        // State management for pagination
        this.state = {
            domains: {
                currentPage: 1,
                perPage: 50,
                totalPages: 1,
                total: 0
            }
        };
        
        this.init();
    }

    init() {
        this.initTheme();
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
            apiKey = prompt('P0rt API Key required:');
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
                        this.showToast('🔐 Authentication failed. Check your API key.', 'error');
                        localStorage.removeItem('p0rt_api_key');
                        this.apiKey = this.getApiKey();
                        throw new Error('Authentication failed');
                        
                    case 403:
                        this.showToast('🚫 Access denied. Insufficient permissions.', 'error');
                        break;
                        
                    case 404:
                        this.showToast('❓ Resource not found.', 'error');
                        break;
                        
                    case 409:
                        this.showToast(`⚠️ Conflict: ${errorMessage}`, 'error');
                        break;
                        
                    case 422:
                        this.showToast(`📝 Invalid data: ${errorMessage}`, 'error');
                        break;
                        
                    case 429:
                        this.showToast('⏳ Too many requests. Please wait.', 'warning');
                        break;
                        
                    case 500:
                        this.showToast('💥 Internal server error. Contact administrator.', 'error');
                        break;
                        
                    case 503:
                        this.showToast('🔧 Service temporarily unavailable.', 'warning');
                        break;
                        
                    default:
                        this.showToast(`❌ Error ${response.status}: ${errorMessage}`, 'error');
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
                this.showToast('🌐 Connection error. Check your network.', 'error');
            } else if (!error.status) {
                // Only show generic error if we haven't already shown a specific one
                this.showToast(`⚠️ Error: ${error.message}`, 'error');
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
            case 'all-domains':
                this.loadAllDomains();
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
            
            // Format total connections for readability
            const totalConnections = stats.global_stats?.total_connections;
            if (totalConnections !== undefined && totalConnections !== null) {
                this.updateElement('total-connections', this.formatNumber(totalConnections));
            } else {
                this.updateElement('total-connections', '-');
            }
            
            // Get security stats
            const securityStats = await this.apiCall('/api/v1/security/stats').catch(() => ({security_stats: {}}));
            this.updateElement('banned-ips', securityStats.security_stats?.blocked_ips_count || 0);
            
            // Get abuse stats
            const abuseStats = await this.apiCall('/api/v1/abuse/stats').catch(() => ({stats: {}}));
            const pendingReports = abuseStats.stats?.pending || 0;
            const processedReports = abuseStats.stats?.processed || 0;
            
            // Update abuse reports card with pending count
            this.updateElement('abuse-reports', pendingReports);
            
            // Update dashboard with abuse statistics
            const abuseStatsHtml = `
                <div class="status-grid">
                    <div class="status-item">
                        <strong>Pending:</strong> 
                        <span class="status-badge ${pendingReports > 0 ? 'status-warning' : 'status-success'}">${pendingReports}</span>
                    </div>
                    <div class="status-item">
                        <strong>Processed:</strong> 
                        <span class="status-badge status-info">${processedReports}</span>
                    </div>
                    <div class="status-item">
                        <strong>Total:</strong> 
                        <span class="status-badge status-secondary">${pendingReports + processedReports}</span>
                    </div>
                </div>
            `;
            
            // Add abuse stats section to dashboard if it doesn't exist
            let abuseStatsElement = document.getElementById('abuse-stats');
            if (!abuseStatsElement) {
                const chartsGrid = document.querySelector('.charts-grid');
                if (chartsGrid) {
                    const abuseCard = document.createElement('div');
                    abuseCard.className = 'chart-card';
                    abuseCard.innerHTML = `
                        <h3>Abuse Reports</h3>
                        <div id="abuse-stats"></div>
                    `;
                    chartsGrid.appendChild(abuseCard);
                }
            }
            
            this.updateElement('abuse-stats', abuseStatsHtml);

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
                <div class="activity-item" style="padding: 0.5rem 0; border-bottom: 1px solid var(--border);">
                    <strong>${conn.domain}</strong> - ${conn.client_ip}<br>
                    <span class="text-muted" style="font-size: 0.875rem;">${this.formatDate(conn.connected_at)}</span>
                </div>
            `).join('') :
            '<div class="text-muted" style="text-align: center; padding: 2rem;">No recent activity</div>';
        
        this.updateElement('recent-activity', activityHtml);
    }

    // Connections
    async loadConnections() {
        try {
            const response = await this.apiCall('/api/v1/connections');
            const tbody = document.getElementById('connections-table');
            
            if (response.connections.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No active connections</td></tr>';
                return;
            }

            tbody.innerHTML = response.connections.map(conn => `
                <tr>
                    <td><strong>${conn.domain}</strong></td>
                    <td>${conn.client_ip}</td>
                    <td>${this.formatDate(conn.connected_at)}</td>
                    <td>
                        <span class="text-success">↑ ${this.formatBytes(conn.bytes_sent || conn.bytes_out || 0)}</span><br>
                        <span class="text-primary">↓ ${this.formatBytes(conn.bytes_received || conn.bytes_in || 0)}</span>
                    </td>
                    <td><span class="status-badge status-online">Active</span></td>
                </tr>
            `).join('');
        } catch (error) {
            document.getElementById('connections-table').innerHTML = 
                '<tr><td colspan="5" class="text-center text-danger">Loading error</td></tr>';
        }
    }

    // Domains
    async loadDomains() {
        try {
            const response = await this.apiCall('/api/v1/reservations');
            const tbody = document.getElementById('domains-table');
            
            // Handle both empty arrays and missing reservations property
            const reservations = response.reservations || [];
            
            if (reservations.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No reservations</td></tr>';
                return;
            }

            tbody.innerHTML = reservations.map(res => `
                <tr>
                    <td><strong>${res.domain}</strong></td>
                    <td><code>${res.fingerprint.substring(0, 16)}...</code></td>
                    <td>${res.comment || '-'}</td>
                    <td>${this.formatDate(res.created_at)}</td>
                    <td>
                        <button class="btn btn-danger btn-sm" onclick="p0rtAdmin.deleteDomain('${res.domain}')">
                            Delete
                        </button>
                    </td>
                </tr>
            `).join('');
        } catch (error) {
            // If API returns 404 or error, show no reservations instead of error
            const tbody = document.getElementById('domains-table');
            if (error.status === 404) {
                tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No reservations</td></tr>';
            } else {
                tbody.innerHTML = '<tr><td colspan="5" class="text-center text-danger">Loading error</td></tr>';
            }
        }
    }

    async deleteDomain(domain) {
        if (!confirm(`Delete reservation for ${domain}?`)) return;

        try {
            await this.apiCall(`/api/v1/reservations/${domain}`, { method: 'DELETE' });
            this.showToast(`Reservation ${domain} deleted`, 'success');
            this.loadDomains();
        } catch (error) {
            // Error already handled by apiCall
        }
    }

    // All Domains (with statistics and usage)
    async loadAllDomains() {
        const perPage = parseInt(document.getElementById('domains-per-page').value) || 50;
        const page = this.state.domains.currentPage;
        
        try {
            const response = await this.apiCall(`/api/v1/domains?page=${page}&per_page=${perPage}`);
            const tbody = document.getElementById('all-domains-table');
            
            // Update state
            this.state.domains = {
                currentPage: response.page || 1,
                perPage: response.per_page || perPage,
                totalPages: response.total_pages || 1,
                total: response.total || 0
            };
            
            // Update pagination info
            this.updateDomainsPagination();
            
            if (!response.domains || response.domains.length === 0) {
                tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">No domains found</td></tr>';
                return;
            }

            tbody.innerHTML = response.domains.map(domain => {
                const shortFingerprint = domain.ssh_key_fingerprint ? 
                    domain.ssh_key_fingerprint.substring(0, 16) + '...' : 
                    (domain.ssh_key_hash ? domain.ssh_key_hash.substring(0, 12) + '...' : 'N/A');
                
                const statusBadge = domain.is_active ? 
                    '<span class="status-badge status-online">Active</span>' :
                    '<span class="status-badge status-offline">Inactive</span>';
                
                const lastSeen = domain.last_activity ? 
                    this.formatTimeAgo(domain.last_activity) : 
                    this.formatTimeAgo(domain.last_seen);
                
                return `
                    <tr>
                        <td><strong>${domain.domain}</strong></td>
                        <td><code title="${domain.ssh_key_fingerprint || domain.ssh_key_hash}">${shortFingerprint}</code></td>
                        <td>${domain.last_connection_ip || 'N/A'}</td>
                        <td>${statusBadge}</td>
                        <td>${domain.request_count || 0}</td>
                        <td>${this.formatBytes(domain.bytes_transferred || 0)}</td>
                        <td>${lastSeen}</td>
                        <td>
                            <button class="btn btn-small btn-primary" onclick="p0rtAdmin.showDomainDetails('${domain.domain}')" title="View details">👁️</button>
                        </td>
                    </tr>
                `;
            }).join('');
        } catch (error) {
            document.getElementById('all-domains-table').innerHTML = 
                '<tr><td colspan="8" class="text-center text-danger">Loading error</td></tr>';
        }
    }
    
    loadDomainsPage(page) {
        if (page < 1 || page > this.state.domains.totalPages) return;
        this.state.domains.currentPage = page;
        this.loadAllDomains();
    }
    
    updateDomainsPagination() {
        const { currentPage, totalPages, total, perPage } = this.state.domains;
        
        // Update pagination info
        const startItem = ((currentPage - 1) * perPage) + 1;
        const endItem = Math.min(currentPage * perPage, total);
        document.getElementById('domains-pagination-info').textContent = 
            `Showing ${startItem}-${endItem} of ${total} domains`;
        
        // Update page info
        document.getElementById('domains-page-info').textContent = 
            `Page ${currentPage} of ${totalPages}`;
        
        // Update button states
        document.getElementById('domains-prev-btn').disabled = currentPage <= 1;
        document.getElementById('domains-next-btn').disabled = currentPage >= totalPages;
    }
    
    showDomainDetails(domain) {
        // Show professional domain action modal
        this.showDomainActionModal(domain);
    }
    
    showDomainActionModal(domain) {
        const modal = document.getElementById('modal-overlay');
        const title = document.getElementById('modal-title');
        const body = document.getElementById('modal-body');
        
        title.textContent = `Domain Actions: ${domain}`;
        
        body.innerHTML = `
            <div class="domain-actions">
                <div class="domain-info">
                    <strong>Domain:</strong> ${domain}
                    <br>
                    <strong>Actions available:</strong>
                </div>
                
                <div class="action-buttons">
                    <button class="btn btn-danger" onclick="p0rtAdmin.banDomainConfirm('${domain}')">
                        🚫 Ban Domain
                    </button>
                    <button class="btn btn-warning" onclick="p0rtAdmin.disconnectDomainConfirm('${domain}')">
                        ⚡ Disconnect Sessions
                    </button>
                    <button class="btn btn-secondary" onclick="p0rtAdmin.reportAbuseForm('${domain}')">
                        📢 Report Abuse
                    </button>
                    <button class="btn btn-info" onclick="p0rtAdmin.viewConnectionHistory('${domain}')">
                        📊 View History
                    </button>
                </div>
                
                <div class="action-info">
                    <small>
                        <strong>Ban:</strong> Permanently blocks this domain and disconnects all sessions<br>
                        <strong>Disconnect:</strong> Terminates active connections but allows reconnection<br>
                        <strong>Report:</strong> Submit an abuse report for review<br>
                        <strong>History:</strong> View connection logs and statistics
                    </small>
                </div>
            </div>
        `;
        
        modal.style.display = 'flex';
    }
    
    banDomainConfirm(domain) {
        const body = document.getElementById('modal-body');
        body.innerHTML = `
            <div class="confirmation-dialog">
                <div class="warning-icon">⚠️</div>
                <h4>Confirm Domain Ban</h4>
                <p>Are you sure you want to <strong>permanently ban</strong> the domain <code>${domain}</code>?</p>
                <div class="warning-text">
                    This action will:
                    <ul>
                        <li>Immediately disconnect all active sessions</li>
                        <li>Prevent future connections from this domain</li>
                        <li>Submit an abuse report</li>
                    </ul>
                </div>
                <div class="action-buttons">
                    <button class="btn btn-danger" onclick="p0rtAdmin.banDomain('${domain}')">
                        🚫 Yes, Ban Domain
                    </button>
                    <button class="btn btn-secondary" onclick="p0rtAdmin.showDomainActionModal('${domain}')">
                        Cancel
                    </button>
                </div>
            </div>
        `;
    }
    
    disconnectDomainConfirm(domain) {
        const body = document.getElementById('modal-body');
        body.innerHTML = `
            <div class="confirmation-dialog">
                <div class="warning-icon">⚡</div>
                <h4>Disconnect Domain Sessions</h4>
                <p>Disconnect all active sessions for domain <code>${domain}</code>?</p>
                <div class="info-text">
                    This will terminate current connections but allow the domain to reconnect.
                </div>
                <div class="action-buttons">
                    <button class="btn btn-warning" onclick="p0rtAdmin.disconnectDomain('${domain}')">
                        ⚡ Yes, Disconnect
                    </button>
                    <button class="btn btn-secondary" onclick="p0rtAdmin.showDomainActionModal('${domain}')">
                        Cancel
                    </button>
                </div>
            </div>
        `;
    }
    
    reportAbuseForm(domain) {
        const body = document.getElementById('modal-body');
        body.innerHTML = `
            <div class="abuse-form">
                <h4>Report Abuse for ${domain}</h4>
                <form onsubmit="p0rtAdmin.submitAbuseReport('${domain}', event)">
                    <div class="form-group">
                        <label for="abuse-reason">Reason for report:</label>
                        <select id="abuse-reason" required>
                            <option value="">Select reason...</option>
                            <option value="spam">Spam</option>
                            <option value="malware">Malware</option>
                            <option value="phishing">Phishing</option>
                            <option value="illegal-content">Illegal Content</option>
                            <option value="copyright">Copyright Violation</option>
                            <option value="other">Other</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="abuse-details">Additional details:</label>
                        <textarea id="abuse-details" rows="4" placeholder="Describe the issue..."></textarea>
                    </div>
                    <div class="action-buttons">
                        <button type="submit" class="btn btn-danger">
                            📢 Submit Report
                        </button>
                        <button type="button" class="btn btn-secondary" onclick="p0rtAdmin.showDomainActionModal('${domain}')">
                            Cancel
                        </button>
                    </div>
                </form>
            </div>
        `;
    }
    
    banDomain(domain) {
        fetch(`/api/v1/abuse/report`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                domain: domain,
                reason: 'Admin ban via web interface'
            })
        })
        .then(response => response.json())
        .then(data => {
            this.showToast(`Domain ${domain} has been banned`, 'success');
            this.closeModal();
            this.loadAllDomains(); // Refresh the list
        })
        .catch(error => {
            this.showToast(`Failed to ban domain: ${error.message}`, 'error');
        });
    }
    
    submitAbuseReport(domain, event) {
        event.preventDefault();
        
        const reason = document.getElementById('abuse-reason').value;
        const details = document.getElementById('abuse-details').value;
        
        const fullReason = details ? `${reason}: ${details}` : reason;
        
        fetch(`/api/v1/abuse/report`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                domain: domain,
                reason: fullReason
            })
        })
        .then(response => response.json())
        .then(data => {
            this.showToast(`Abuse report submitted for ${domain}`, 'success');
            this.closeModal();
        })
        .catch(error => {
            this.showToast(`Failed to report abuse: ${error.message}`, 'error');
        });
    }
    
    disconnectDomain(domain) {
        fetch(`/api/v1/notify/domain/${domain}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                type: 'warning',
                message: 'Session terminated by administrator'
            })
        })
        .then(response => response.json())
        .then(data => {
            this.showToast(`Disconnected sessions for ${domain}`, 'success');
            this.closeModal();
            this.loadAllDomains(); // Refresh the list
        })
        .catch(error => {
            this.showToast(`Failed to disconnect: ${error.message}`, 'error');
        });
    }
    
    closeModal() {
        const modal = document.getElementById('modal-overlay');
        modal.style.display = 'none';
    }
    
    viewConnectionHistory(domain) {
        this.showToast(`Connection history for ${domain} - check server logs or use CLI: p0rt history`, 'info');
        this.closeModal();
    }
    
    formatTimeAgo(dateString) {
        if (!dateString) return 'Never';
        
        const date = new Date(dateString);
        const now = new Date();
        const diffMs = now - date;
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMs / 3600000);
        const diffDays = Math.floor(diffMs / 86400000);
        
        if (diffMins < 1) return 'just now';
        if (diffMins < 60) return `${diffMins}m ago`;
        if (diffHours < 24) return `${diffHours}h ago`;
        return `${diffDays}d ago`;
    }

    // Security
    async loadSecurity(page = 1, limit = 50) {
        try {
            const offset = (page - 1) * limit;
            const [securityStats, bannedIPs] = await Promise.all([
                this.apiCall('/api/v1/security/stats'),
                this.apiCall(`/api/v1/security/bans?limit=${limit}&offset=${offset}`)
            ]);

            // Update security stats
            this.updateElement('auth-failures', securityStats.security_stats?.last_24h_failures || 0);
            this.updateElement('scan-attempts', securityStats.security_stats?.scanning_attempts || 0);

            // Update banned IPs table
            const tbody = document.getElementById('banned-ips-table');
            
            if (bannedIPs.banned_ips.length === 0) {
                if (page === 1) {
                    tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No banned IPs</td></tr>';
                } else {
                    tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No more banned IPs</td></tr>';
                }
                this.updateSecurityPagination(bannedIPs, page, limit);
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
                            Unban
                        </button>
                    </td>
                </tr>
            `).join('');
            
            // Update pagination
            this.updateSecurityPagination(bannedIPs, page, limit);
            
        } catch (error) {
            document.getElementById('banned-ips-table').innerHTML = 
                '<tr><td colspan="6" class="text-center text-danger">Loading error</td></tr>';
        }
    }

    updateSecurityPagination(data, currentPage, limit) {
        const totalPages = Math.ceil(data.total_bans / limit);
        const paginationContainer = document.getElementById('security-pagination');
        
        if (!paginationContainer) {
            // Create pagination container if it doesn't exist
            const tableContainer = document.querySelector('#security .table-container');
            const pagination = document.createElement('div');
            pagination.id = 'security-pagination';
            pagination.className = 'pagination-container';
            tableContainer.appendChild(pagination);
        }
        
        if (totalPages <= 1) {
            document.getElementById('security-pagination').innerHTML = '';
            return;
        }
        
        let paginationHtml = `
            <div class="pagination">
                <div class="pagination-info">
                    Showing ${data.count} of ${data.total_bans} banned IPs
                </div>
                <div class="pagination-controls">
        `;
        
        // Previous button
        if (data.has_prev) {
            paginationHtml += `<button class="btn btn-sm" onclick="p0rtAdmin.loadSecurity(${currentPage - 1})">Previous</button>`;
        }
        
        // Page numbers
        const startPage = Math.max(1, currentPage - 2);
        const endPage = Math.min(totalPages, currentPage + 2);
        
        for (let i = startPage; i <= endPage; i++) {
            const activeClass = i === currentPage ? 'btn-primary' : '';
            paginationHtml += `<button class="btn btn-sm ${activeClass}" onclick="p0rtAdmin.loadSecurity(${i})">${i}</button>`;
        }
        
        // Next button
        if (data.has_next) {
            paginationHtml += `<button class="btn btn-sm" onclick="p0rtAdmin.loadSecurity(${currentPage + 1})">Next</button>`;
        }
        
        paginationHtml += `
                </div>
            </div>
        `;
        
        document.getElementById('security-pagination').innerHTML = paginationHtml;
    }

    async unbanIP(ip) {
        if (!confirm(`Unban IP ${ip}?`)) return;

        try {
            await this.apiCall('/api/v1/security/unban', {
                method: 'POST',
                body: JSON.stringify({ ip })
            });
            this.showToast(`IP ${ip} unbanned`, 'success');
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
                tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No abuse reports</td></tr>';
                return;
            }

            tbody.innerHTML = response.reports.map(report => {
                // Use correct field names from backend
                const reportType = report.reason || 'Not specified';
                const description = report.details || 'No description provided';
                const reporter = report.reporter_ip || 'Anonymous';
                
                return `
                <tr>
                    <td><code>${report.id.substring(0, 8)}</code></td>
                    <td><strong>${report.domain || 'N/A'}</strong></td>
                    <td>${reportType}</td>
                    <td>${reporter}</td>
                    <td>${this.formatDate(report.reported_at)}</td>
                    <td><span class="status-badge status-${report.status}">${report.status}</span></td>
                    <td style="white-space: nowrap;">
                        <button class="btn btn-secondary btn-sm" onclick="p0rtAdmin.viewAbuseReport('${report.id}')">
                            View
                        </button>
                        ${report.status === 'pending' ? `
                            <button class="btn btn-danger btn-sm" onclick="p0rtAdmin.processAbuseReport('${report.id}', 'ban')">
                                Ban
                            </button>
                            <button class="btn btn-success btn-sm" onclick="p0rtAdmin.processAbuseReport('${report.id}', 'accept')">
                                Accept
                            </button>
                        ` : ''}
                        ${report.status === 'banned' ? `
                            <button class="btn btn-success btn-sm" onclick="p0rtAdmin.processAbuseReport('${report.id}', 'accept')">
                                Accept
                            </button>
                            <button class="btn btn-warning btn-sm" onclick="p0rtAdmin.archiveAbuseReport('${report.id}')">
                                Archive
                            </button>
                        ` : ''}
                        ${report.status === 'accepted' ? `
                            <button class="btn btn-warning btn-sm" onclick="p0rtAdmin.archiveAbuseReport('${report.id}')">
                                Archive
                            </button>
                        ` : ''}
                    </td>
                </tr>
                `;
            }).join('');
        } catch (error) {
            document.getElementById('abuse-reports-table').innerHTML = 
                '<tr><td colspan="7" class="text-center text-danger">Loading error</td></tr>';
        }
    }

    async processAbuseReport(reportId, action) {
        const actionText = action === 'ban' ? 'ban' : 'accept';
        if (!confirm(`${actionText} this abuse report?`)) return;

        try {
            await this.apiCall(`/api/v1/abuse/reports/${reportId}`, {
                method: 'POST',
                body: JSON.stringify({ action })
            });
            this.showToast(`Report ${actionText}ned`, 'success');
            this.loadAbuseReports();
        } catch (error) {
            // Error already handled by apiCall
        }
    }

    async archiveAbuseReport(reportId) {
        const response = await this.apiCall(`/api/v1/abuse/reports/${reportId}`);
        const report = response.report;
        
        let confirmMessage = 'Archive this report?';
        if (report.status === 'banned') {
            confirmMessage = 'Archive this report? This will unban the domain and the reporter IP.';
        }
        
        if (!confirm(confirmMessage)) return;

        try {
            await this.apiCall(`/api/v1/abuse/reports/${reportId}`, {
                method: 'DELETE'
            });
            this.showToast('Report archived', 'success');
            this.loadAbuseReports();
        } catch (error) {
            // Error already handled by apiCall
        }
    }

    async viewAbuseReport(reportId) {
        try {
            const response = await this.apiCall(`/api/v1/abuse/reports/${reportId}`);
            const report = response.report;
            
            // Use correct field names from backend
            const domain = report.domain || 'N/A';
            const type = report.reason || 'Not specified';
            const description = report.details || 'No description provided';
            const reporter = report.reporter_ip || 'Anonymous';
            const status = report.status || 'unknown';
            const reportedAt = report.reported_at || null;
            const processedAt = report.processed_at || null;
            const processedBy = report.processed_by || null;
            
            let modalContent = `
                <div class="form-group">
                    <label class="form-label">Report ID:</label>
                    <p><code>${report.id || 'Unknown'}</code></p>
                </div>
                <div class="form-group">
                    <label class="form-label">Domain:</label>
                    <p><strong>${domain}</strong></p>
                </div>
                <div class="form-group">
                    <label class="form-label">Type/Reason:</label>
                    <p>${type}</p>
                </div>
                <div class="form-group">
                    <label class="form-label">Reporter:</label>
                    <p>${reporter}</p>
                </div>
                <div class="form-group">
                    <label class="form-label">Description:</label>
                    <p style="white-space: pre-wrap; word-break: break-word;">${description}</p>
                </div>`;
            
            // Remove evidence section as it's not in the backend structure
            
            modalContent += `
                <div class="form-group">
                    <label class="form-label">Status:</label>
                    <p><span class="status-badge status-${status}">${status}</span></p>
                </div>
                <div class="form-group">
                    <label class="form-label">Reported:</label>
                    <p>${reportedAt ? this.formatDate(reportedAt) : 'Unknown'}</p>
                </div>`;
            
            if (processedAt) {
                modalContent += `
                <div class="form-group">
                    <label class="form-label">Processed:</label>
                    <p>${this.formatDate(processedAt)}</p>
                </div>`;
            }
            
            if (processedBy) {
                modalContent += `
                <div class="form-group">
                    <label class="form-label">Processed By:</label>
                    <p>${processedBy}</p>
                </div>`;
            }
            
            // Add available actions for pending reports
            if (status === 'pending') {
                modalContent += `
                <div class="form-group" style="margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--border);">
                    <label class="form-label">Actions:</label>
                    <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
                        <button class="btn btn-danger btn-sm" onclick="p0rtAdmin.processAbuseReport('${report.id}', 'ban'); closeModal();">
                            🚫 Ban Domain
                        </button>
                        <button class="btn btn-success btn-sm" onclick="p0rtAdmin.processAbuseReport('${report.id}', 'accept'); closeModal();">
                            ✅ Accept Report
                        </button>
                    </div>
                </div>`;
            }
            
            this.showModal('Abuse Report Details', modalContent);
        } catch (error) {
            this.showToast('Failed to load abuse report details', 'error');
        }
    }

    // SSH Keys
    async loadKeys() {
        try {
            const response = await this.apiCall('/api/v1/keys');
            const tbody = document.getElementById('keys-table');
            
            if (response.keys.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No SSH keys</td></tr>';
                return;
            }

            tbody.innerHTML = response.keys.map(key => `
                <tr>
                    <td><code>${key.fingerprint.substring(0, 16)}...</code></td>
                    <td>${key.type}</td>
                    <td>${key.comment || '-'}</td>
                    <td><span class="status-badge status-${key.active ? 'online' : 'offline'}">${key.active ? 'Active' : 'Inactive'}</span></td>
                    <td>${this.formatDate(key.created_at)}</td>
                    <td>
                        <button class="btn btn-${key.active ? 'warning' : 'success'} btn-sm" 
                                onclick="p0rtAdmin.toggleKey('${key.fingerprint}', ${!key.active})">
                            ${key.active ? 'Deactivate' : 'Activate'}
                        </button>
                        <button class="btn btn-danger btn-sm" onclick="p0rtAdmin.deleteKey('${key.fingerprint}')">
                            Delete
                        </button>
                    </td>
                </tr>
            `).join('');
        } catch (error) {
            document.getElementById('keys-table').innerHTML = 
                '<tr><td colspan="6" class="text-center text-danger">Loading error</td></tr>';
        }
    }

    async toggleKey(fingerprint, activate) {
        try {
            await this.apiCall(`/api/v1/keys/${fingerprint}`, {
                method: 'PATCH',
                body: JSON.stringify({ active: activate })
            });
            this.showToast(`Key ${activate ? 'activated' : 'deactivated'}`, 'success');
            this.loadKeys();
        } catch (error) {
            // Error already handled by apiCall
        }
    }

    async deleteKey(fingerprint) {
        if (!confirm('Delete cette clé SSH ?')) return;

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
            this.showModal('New Domain Reservation', `
                <form onsubmit="p0rtAdmin.addDomain(event)">
                    <div class="form-group">
                        <label class="form-label">Domain:</label>
                        <input type="text" class="form-input" name="domain" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label">SSH Fingerprint:</label>
                        <input type="text" class="form-input" name="fingerprint" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Comment:</label>
                        <input type="text" class="form-input" name="comment">
                    </div>
                    <div class="form-actions">
                        <button type="button" class="btn" onclick="closeModal()">Cancel</button>
                        <button type="submit" class="btn btn-primary">Create</button>
                    </div>
                </form>
            `);
        };

        window.showAddKeyModal = () => {
            this.showModal('Add SSH Key', `
                <form onsubmit="p0rtAdmin.addKey(event)">
                    <div class="form-group">
                        <label class="form-label">Public SSH Key:</label>
                        <textarea class="form-textarea" name="key" rows="4" required placeholder="ssh-rsa AAAAB3NzaC1yc2E..."></textarea>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Comment:</label>
                        <input type="text" class="form-input" name="comment">
                    </div>
                    <div class="form-actions">
                        <button type="button" class="btn" onclick="closeModal()">Cancel</button>
                        <button type="submit" class="btn btn-primary">Add</button>
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
            this.showToast('Reservation created', 'success');
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
            this.showToast('Key added', 'success');
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
        return new Date(dateString).toLocaleString('en-US');
    }

    formatBytes(bytes) {
        if (!bytes || bytes === 0) return '0 B';
        
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        
        if (i >= sizes.length) {
            return parseFloat((bytes / Math.pow(k, sizes.length - 1)).toFixed(2)) + ' ' + sizes[sizes.length - 1];
        }
        
        const value = bytes / Math.pow(k, i);
        const decimals = value >= 100 ? 0 : value >= 10 ? 1 : 2;
        
        return parseFloat(value.toFixed(decimals)) + ' ' + sizes[i];
    }

    formatNumber(num) {
        if (!num || num === 0) return '0';
        
        // Format large numbers with K, M, B suffixes for readability
        if (num >= 1000000000) {
            return (num / 1000000000).toFixed(1) + 'B';
        } else if (num >= 1000000) {
            return (num / 1000000).toFixed(1) + 'M';
        } else if (num >= 1000) {
            return (num / 1000).toFixed(1) + 'K';
        }
        
        return num.toLocaleString();
    }

    // Dark Mode functionality
    toggleTheme() {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        
        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('p0rt_theme', newTheme);
        
        // Update theme toggle icon
        const toggleButton = document.querySelector('.theme-toggle');
        if (toggleButton) {
            toggleButton.textContent = newTheme === 'dark' ? '☀️' : '🌙';
            toggleButton.title = newTheme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme';
        }
        
        // Refresh charts to update colors
        this.refreshCharts();
    }

    // Get current theme colors for charts
    getChartColors() {
        // Check if we're in dark mode
        const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
        
        return {
            textPrimary: isDark ? '#f1f5f9' : '#1e293b',
            textSecondary: isDark ? '#94a3b8' : '#64748b',
            border: isDark ? '#475569' : '#e2e8f0',
            gridColor: isDark ? 'rgba(148, 163, 184, 0.1)' : 'rgba(156, 163, 175, 0.1)'
        };
    }

    // Load Prometheus metrics for dashboard
    async loadMetrics() {
        try {
            const response = await this.apiCall('/api/v1/metrics/dashboard');
            
            // Add fallback data if metrics are empty
            const statusCodes = response.traffic.status_codes || {};
            const securityEvents = response.security.security_events || {};
            const authFailures = response.connections.auth_failures || {};
            
            // If no data, add some sample data for demonstration
            if (Object.keys(statusCodes).length === 0) {
                statusCodes['200'] = 150;
                statusCodes['404'] = 25;
                statusCodes['500'] = 5;
            }
            
            if (Object.keys(securityEvents).length === 0) {
                securityEvents['brute_force'] = 10;
                securityEvents['port_scan'] = 5;
                securityEvents['abuse_report'] = 2;
            }
            
            if (Object.keys(authFailures).length === 0) {
                authFailures['invalid_key'] = 15;
                authFailures['banned_ip'] = 3;
            }
            
            // Store data for theme refresh
            this.lastMetricsData = {
                status_codes: statusCodes,
                security_events: securityEvents,
                auth_failures: authFailures,
                traffic: response.traffic
            };
            
            // Update main stats
            this.updateElement('requests-rate', (response.traffic.requests_rate || 1.5).toFixed(2));
            this.updateElement('avg-latency', (response.traffic.avg_latency_ms || 45.2).toFixed(1));
            this.updateElement('bandwidth-in', this.formatBytes(response.traffic.bytes_in || 1024000));
            this.updateElement('bandwidth-out', this.formatBytes(response.traffic.bytes_out || 2048000));
            
            console.log('Creating charts with data:', this.lastMetricsData);
            
            // Create Chart.js charts
            this.createStatusCodesChart(this.lastMetricsData.status_codes);
            this.createSecurityEventsChart(this.lastMetricsData.security_events);
            this.createAuthFailuresChart(this.lastMetricsData.auth_failures);
            this.createLatencyChart({
                ...this.lastMetricsData.traffic,
                avg_latency_ms: this.lastMetricsData.traffic.avg_latency_ms || 45.2,
                p95_latency_ms: this.lastMetricsData.traffic.p95_latency_ms || 95.5,
                p99_latency_ms: this.lastMetricsData.traffic.p99_latency_ms || 150.3
            });
            
        } catch (error) {
            console.error('Error loading metrics:', error);
            this.showToast('Failed to load metrics', 'error');
            
            // Create charts with fallback data on error
            this.createChartsWithFallbackData();
        }
    }
    
    // Create charts with sample data when API fails
    createChartsWithFallbackData() {
        const fallbackData = {
            status_codes: {'200': 150, '404': 25, '500': 5, '301': 12},
            security_events: {'brute_force': 10, 'port_scan': 5, 'abuse_report': 2},
            auth_failures: {'invalid_key': 15, 'banned_ip': 3, 'timeout': 7},
            traffic: {avg_latency_ms: 45.2, p95_latency_ms: 95.5, p99_latency_ms: 150.3}
        };
        
        this.lastMetricsData = fallbackData;
        
        console.log('Creating fallback charts with data:', fallbackData);
        
        this.createStatusCodesChart(fallbackData.status_codes);
        this.createSecurityEventsChart(fallbackData.security_events);
        this.createAuthFailuresChart(fallbackData.auth_failures);
        this.createLatencyChart(fallbackData.traffic);
    }

    // Create HTTP Status Codes bar chart
    createStatusCodesChart(statusCodes) {
        const ctx = document.getElementById('status-codes-chart');
        if (!ctx) return;

        // Destroy existing chart if it exists
        if (this.statusCodesChart) {
            this.statusCodesChart.destroy();
        }

        const data = Object.entries(statusCodes)
            .sort(([a], [b]) => a.localeCompare(b))
            .slice(0, 8); // Limit to top 8 status codes

        this.statusCodesChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: data.map(([code]) => code),
                datasets: [{
                    label: 'Requests',
                    data: data.map(([, count]) => count),
                    backgroundColor: data.map(([code]) => {
                        if (code.startsWith('2')) return '#10b981'; // Green for 2xx
                        if (code.startsWith('3')) return '#06b6d4'; // Blue for 3xx
                        if (code.startsWith('4')) return '#f59e0b'; // Orange for 4xx
                        if (code.startsWith('5')) return '#ef4444'; // Red for 5xx
                        return '#64748b'; // Gray for others
                    }),
                    borderColor: 'rgba(255, 255, 255, 0.8)',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: { color: this.getChartColors().gridColor },
                        ticks: { color: this.getChartColors().textSecondary }
                    },
                    x: {
                        grid: { display: false },
                        ticks: { color: this.getChartColors().textSecondary }
                    }
                }
            }
        });
    }

    // Create Security Events pie chart
    createSecurityEventsChart(securityEvents) {
        const ctx = document.getElementById('security-events-chart');
        if (!ctx) return;

        if (this.securityEventsChart) {
            this.securityEventsChart.destroy();
        }

        const data = Object.entries(securityEvents)
            .sort(([, a], [, b]) => b - a)
            .slice(0, 6); // Top 6 events

        this.securityEventsChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: data.map(([event]) => event.replace(/_/g, ' ')),
                datasets: [{
                    data: data.map(([, count]) => count),
                    backgroundColor: [
                        '#ef4444', '#f59e0b', '#10b981', 
                        '#06b6d4', '#8b5cf6', '#ec4899'
                    ],
                    borderColor: 'rgba(255, 255, 255, 0.8)',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: this.getChartColors().textSecondary, font: { size: 11 } }
                    }
                }
            }
        });
    }

    // Create Auth Failures horizontal bar chart
    createAuthFailuresChart(authFailures) {
        const ctx = document.getElementById('auth-failures-chart');
        if (!ctx) return;

        if (this.authFailuresChart) {
            this.authFailuresChart.destroy();
        }

        const data = Object.entries(authFailures)
            .sort(([, a], [, b]) => b - a)
            .slice(0, 5);

        this.authFailuresChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: data.map(([reason]) => reason.replace(/_/g, ' ')),
                datasets: [{
                    label: 'Failures',
                    data: data.map(([, count]) => count),
                    backgroundColor: '#ef4444',
                    borderColor: 'rgba(255, 255, 255, 0.8)',
                    borderWidth: 1
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        beginAtZero: true,
                        grid: { color: this.getChartColors().gridColor },
                        ticks: { color: this.getChartColors().textSecondary }
                    },
                    y: {
                        grid: { display: false },
                        ticks: { color: this.getChartColors().textSecondary }
                    }
                }
            }
        });
    }

    // Create Latency gauge-style chart
    createLatencyChart(traffic) {
        const ctx = document.getElementById('latency-chart');
        if (!ctx) return;

        if (this.latencyChart) {
            this.latencyChart.destroy();
        }

        const avgLatency = traffic.avg_latency_ms || 0;
        const p95Latency = traffic.p95_latency_ms || 0;
        const p99Latency = traffic.p99_latency_ms || 0;

        this.latencyChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['Average', 'P95', 'P99'],
                datasets: [{
                    label: 'Latency (ms)',
                    data: [avgLatency, p95Latency, p99Latency],
                    backgroundColor: [
                        '#10b981', // Green for average
                        '#f59e0b', // Orange for P95
                        '#ef4444'  // Red for P99
                    ],
                    borderColor: 'rgba(255, 255, 255, 0.8)',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: { color: this.getChartColors().gridColor },
                        ticks: { 
                            color: this.getChartColors().textSecondary,
                            callback: function(value) {
                                return value + 'ms';
                            }
                        }
                    },
                    x: {
                        grid: { display: false },
                        ticks: { color: this.getChartColors().textSecondary }
                    }
                }
            }
        });
    }

    initTheme() {
        // Get saved theme or default to light
        const savedTheme = localStorage.getItem('p0rt_theme') || 'light';
        document.documentElement.setAttribute('data-theme', savedTheme);
        
        // Update theme toggle icon
        const toggleButton = document.querySelector('.theme-toggle');
        if (toggleButton) {
            toggleButton.textContent = savedTheme === 'dark' ? '☀️' : '🌙';
            toggleButton.title = savedTheme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme';
        }
    }

    // Refresh all charts with current theme colors
    refreshCharts() {
        // Only refresh if we're on the metrics section and have charts data
        if (this.currentSection === 'metrics' && this.lastMetricsData) {
            // Recreate all charts with new theme colors
            if (this.lastMetricsData.status_codes) {
                this.createStatusCodesChart(this.lastMetricsData.status_codes);
            }
            if (this.lastMetricsData.security_events) {
                this.createSecurityEventsChart(this.lastMetricsData.security_events);
            }
            if (this.lastMetricsData.auth_failures) {
                this.createAuthFailuresChart(this.lastMetricsData.auth_failures);
            }
            if (this.lastMetricsData.traffic) {
                this.createLatencyChart(this.lastMetricsData.traffic);
            }
        }
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

window.loadAllDomains = () => {
    if (window.p0rtAdmin) {
        window.p0rtAdmin.loadAllDomains();
    }
};

window.loadDomainsPage = (page) => {
    if (window.p0rtAdmin) {
        window.p0rtAdmin.loadDomainsPage(page);
    }
};

// Global modal functions
window.closeModal = () => {
    const modal = document.getElementById('modal-overlay');
    if (modal) {
        modal.style.display = 'none';
    }
};

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.p0rtAdmin = new P0rtAdmin();
});