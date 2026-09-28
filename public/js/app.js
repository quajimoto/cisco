// public/js/app.js
// Cisco Catalyst 2960-S Series PoE+ 실시간 연동 및 L2 스위치 웹 콘솔 메인 로직

document.addEventListener('DOMContentLoaded', () => {
    App.init();
});

const App = {
    currentTab: 'dashboard',
    ports: [],
    vlans: [],
    systemInfo: {},
    poeSummary: {},
    currentUser: null,
    ciscoConnected: null,
    stackFilter: 'all',
    statusFilter: 'all',
    searchQuery: '',
    macStackFilter: 'all',
    macVlanFilter: 'all',
    macTypeFilter: 'all',
    macSearchQuery: '',
    devices: [],
    activeDeviceId: null,
    powerAlerts: [],
    activePowerOutage: null,

    async init() {
        this.bindGlobalEvents();
        this.bindCiscoEvents();
        this.bindAlertEvents();
        this.bindDeviceEvents();
        this.bindPowerEvents();
        await this.checkAuth();
    },

    async checkAuth() {
        try {
            const data = await API.request('/api/auth/me');
            if (data.authenticated) {
                this.currentUser = data.user;
                API.setUser(data.user);
                API.setCsrfToken(data.csrfToken);
                this.updateUserUI(data.user);
                this.hideLoginModal();
                await this.loadAllData();
                this.switchTab('dashboard');
            } else {
                this.showLoginModal();
            }
        } catch (err) {
            this.showLoginModal();
        }
    },

    onStackSwitchChange(sNum) {
        // 전면 패널에서 스택 스위치 탭을 클릭했을 때 포트 관리 탭 필터 동기화
        const pills = document.querySelectorAll('#ports-stack-filter-group .filter-pill');
        pills.forEach(p => {
            if (p.getAttribute('data-stack') === String(sNum)) {
                p.classList.add('active');
            } else {
                p.classList.remove('active');
            }
        });
        this.stackFilter = String(sNum);
        if (this.currentTab === 'ports') {
            this.renderPortsTable();
        }
    },

    bindGlobalEvents() {
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const tab = item.getAttribute('data-tab');
                if (tab) this.switchTab(tab);
            });
        });

        // 포트 탭: 스택 스위치 필터 버튼 이벤트
        const stackPills = document.querySelectorAll('#ports-stack-filter-group .filter-pill');
        stackPills.forEach(pill => {
            pill.addEventListener('click', () => {
                stackPills.forEach(p => p.classList.remove('active'));
                pill.classList.add('active');
                this.stackFilter = pill.getAttribute('data-stack');
                this.renderPortsTable();
            });
        });

        // 포트 탭: 링크 및 PoE 상태 필터 버튼 이벤트
        const statusPills = document.querySelectorAll('#ports-status-filter-group .filter-pill');
        statusPills.forEach(pill => {
            pill.addEventListener('click', () => {
                statusPills.forEach(p => p.classList.remove('active'));
                pill.classList.add('active');
                this.statusFilter = pill.getAttribute('data-status');
                this.renderPortsTable();
            });
        });

        // 포트 탭: 검색어 입력 이벤트
        const searchInput = document.getElementById('ports-search-input');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                this.searchQuery = (e.target.value || '').toLowerCase().trim();
                this.renderPortsTable();
            });
        }

        // 클라이언트 MAC/IP 탭: 스택 스위치 필터 버튼 이벤트
        const macStackPills = document.querySelectorAll('#mac-stack-filter-group .filter-pill');
        macStackPills.forEach(pill => {
            pill.addEventListener('click', () => {
                macStackPills.forEach(p => p.classList.remove('active'));
                pill.classList.add('active');
                this.macStackFilter = pill.getAttribute('data-stack');
                this.renderMacTab();
            });
        });

        // 클라이언트 MAC/IP 탭: VLAN 필터 드롭다운
        const macVlanSelect = document.getElementById('mac-vlan-filter-select');
        if (macVlanSelect) {
            macVlanSelect.addEventListener('change', (e) => {
                this.macVlanFilter = e.target.value;
                this.renderMacTab();
            });
        }

        // 클라이언트 MAC/IP 탭: 연결 모드 필터 드롭다운
        const macTypeSelect = document.getElementById('mac-type-filter-select');
        if (macTypeSelect) {
            macTypeSelect.addEventListener('change', (e) => {
                this.macTypeFilter = e.target.value;
                this.renderMacTab();
            });
        }

        // 클라이언트 MAC/IP 탭: 검색어 입력 이벤트
        const macSearch = document.getElementById('mac-search-input');
        if (macSearch) {
            macSearch.addEventListener('input', (e) => {
                this.macSearchQuery = (e.target.value || '').toLowerCase().trim();
                this.renderMacTab();
            });
        }

        const logoutBtn = document.getElementById('btn-logout');
        if (logoutBtn) logoutBtn.addEventListener('click', () => this.handleLogout());

        const loginForm = document.getElementById('login-form');
        if (loginForm) loginForm.addEventListener('submit', (e) => this.handleLogin(e));

        document.querySelectorAll('.modal-close').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.modal-overlay').forEach(m => m.classList.remove('active'));
            });
        });

        window.addEventListener('auth:required', () => {
            API.showToast('세션이 만료되었습니다. 다시 로그인해주세요.', 'error');
            this.showLoginModal();
        });
    },

    /**
     * Cisco Catalyst 2960-S 장비 연동 이벤트 바인딩
     */
    bindCiscoEvents() {
        // [Cisco 장비 연동 / 설정 가져오기] 모달 열기
        const openConnectBtn = document.getElementById('btn-open-cisco-connect');
        const connectModal = document.getElementById('cisco-connect-modal');
        if (openConnectBtn && connectModal) {
            openConnectBtn.onclick = () => {
                connectModal.classList.add('active');
            };
        }

        // 모달 내 탭 전환 (SSH 실시간 vs 오프라인 수동)
        const tabBtnSsh = document.getElementById('tab-btn-ssh');
        const tabBtnManual = document.getElementById('tab-btn-manual');
        const panelSsh = document.getElementById('panel-cisco-ssh');
        const panelManual = document.getElementById('panel-cisco-manual');

        if (tabBtnSsh && tabBtnManual) {
            tabBtnSsh.onclick = () => {
                tabBtnSsh.className = 'btn btn-primary btn-sm';
                tabBtnManual.className = 'btn btn-secondary btn-sm';
                panelSsh.style.display = 'block';
                panelManual.style.display = 'none';
            };
            tabBtnManual.onclick = () => {
                tabBtnManual.className = 'btn btn-primary btn-sm';
                tabBtnSsh.className = 'btn btn-secondary btn-sm';
                panelManual.style.display = 'block';
                panelSsh.style.display = 'none';
            };
        }

        // 프로토콜 변경 시 포트 자동 변경
        const protocolSelect = document.getElementById('cisco-ssh-protocol');
        const portHidden = document.getElementById('cisco-ssh-port');
        if (protocolSelect && portHidden) {
            protocolSelect.onchange = () => {
                portHidden.value = protocolSelect.value;
            };
        }

        // 1. 실시간 SSH/Telnet 접속 및 설정 가져오기 폼
        const sshForm = document.getElementById('cisco-ssh-form');
        if (sshForm) {
            sshForm.onsubmit = async (e) => {
                e.preventDefault();
                const host = document.getElementById('cisco-ssh-ip').value.trim();
                const port = Number(document.getElementById('cisco-ssh-port').value || (protocolSelect ? protocolSelect.value : 22));
                const username = document.getElementById('cisco-ssh-user').value.trim();
                const password = document.getElementById('cisco-ssh-pass').value;
                const enableSecret = document.getElementById('cisco-ssh-enable').value;
                const pullBtn = document.getElementById('btn-cisco-pull-live');

                pullBtn.disabled = true;
                pullBtn.textContent = '스위치 접속 및 설정 수집 중 (최대 15초)...';

                const saveModeRadio = document.querySelector('input[name="cisco-ssh-save-mode"]:checked');
                const saveMode = saveModeRadio ? saveModeRadio.value : 'create';

                try {
                    const res = await API.request('/api/cisco/sync', {
                        method: 'POST',
                        body: JSON.stringify({ host, port, username, password, enableSecret, saveMode })
                    });
                    API.showToast(res.message, 'success');
                    connectModal.classList.remove('active');
                    await this.loadAllData();
                    this.switchTab('dashboard');
                } catch (err) {
                    API.showToast(err.message, 'error');
                } finally {
                    pullBtn.disabled = false;
                    pullBtn.textContent = '스위치 접속 및 실시간 설정 가져오기';
                }
            };
        }

        // 2. 오프라인 샘플 프리셋 불러오기
        const loadSampleBtn = document.getElementById('btn-load-sample-cfg');
        const manualTextarea = document.getElementById('cisco-manual-textarea');
        if (loadSampleBtn && manualTextarea) {
            loadSampleBtn.onclick = async () => {
                try {
                    const res = await API.request('/api/cisco/sample-preset');
                    manualTextarea.value = res.sampleConfig;
                    API.showToast('실제 Cisco 2960-S PoE+ 샘플 설정이 로드되었습니다.', 'info');
                } catch (err) {
                    API.showToast(err.message, 'error');
                }
            };
        }

        // 3. 수동 텍스트 파싱 및 적용
        const importTextBtn = document.getElementById('btn-cisco-import-text');
        if (importTextBtn && manualTextarea) {
            importTextBtn.onclick = async () => {
                const text = manualTextarea.value.trim();
                if (!text) {
                    API.showToast('Running-Config 텍스트를 입력해주세요.', 'error');
                    return;
                }
                const createNewCheck = document.getElementById('cisco-manual-create-new');
                const createAsNew = createNewCheck ? createNewCheck.checked : true;

                try {
                    const res = await API.request('/api/cisco/import', {
                        method: 'POST',
                        body: JSON.stringify({ rawConfig: text, createAsNew })
                    });
                    API.showToast(res.message, 'success');
                    connectModal.classList.remove('active');
                    await this.loadAllData();
                    this.switchTab('dashboard');
                } catch (err) {
                    API.showToast(err.message, 'error');
                }
            };
        }

        // [장비에 설정 반영 (Commit)] 모달 열기
        const openCommitBtn = document.getElementById('btn-open-cisco-commit');
        const commitModal = document.getElementById('cisco-commit-modal');
        const commitPreview = document.getElementById('cisco-commit-cmds-preview');
        const commitIpInput = document.getElementById('commit-ssh-ip');

        if (openCommitBtn && commitModal) {
            openCommitBtn.onclick = async () => {
                if (this.currentUser && this.currentUser.role === 'viewer') {
                    API.showToast('Viewer 권한은 장비 설정을 반영할 수 없습니다.', 'error');
                    return;
                }

                // 차분 명령어 생성 조회
                try {
                    const diffRes = await API.request('/api/cisco/generate-diff', { method: 'POST' });
                    commitPreview.textContent = diffRes.commands.join('\n');
                    commitIpInput.value = this.systemInfo.ipAddress || '192.168.10.254';
                    commitModal.classList.add('active');
                } catch (err) {
                    API.showToast(err.message, 'error');
                }
            };
        }

        // 실제 스위치에 Commit 반영 폼
        const commitForm = document.getElementById('cisco-commit-form');
        if (commitForm) {
            commitForm.onsubmit = async (e) => {
                e.preventDefault();
                const host = commitIpInput.value.trim();
                const username = document.getElementById('commit-ssh-user').value.trim();
                const password = document.getElementById('commit-ssh-pass').value;
                const enableSecret = document.getElementById('commit-ssh-enable').value;
                const commands = commitPreview.textContent.split('\n').map(c => c.trim()).filter(Boolean);

                try {
                    const res = await API.request('/api/cisco/commit', {
                        method: 'POST',
                        body: JSON.stringify({ host, username, password, enableSecret, commands })
                    });
                    API.showToast(res.message, 'success');
                    commitModal.classList.remove('active');
                    await this.loadAllData();
                } catch (err) {
                    API.showToast(err.message, 'error');
                }
            };
        }
    },

    updateUserUI(user) {
        const usernameEl = document.getElementById('header-username');
        const roleEl = document.getElementById('header-role');
        if (usernameEl) usernameEl.textContent = user.username;
        if (roleEl) {
            roleEl.textContent = user.role;
            roleEl.className = `role-badge ${user.role}`;
        }
    },

    showLoginModal() {
        const modal = document.getElementById('login-modal');
        if (modal) modal.classList.add('active');
    },

    hideLoginModal() {
        const modal = document.getElementById('login-modal');
        if (modal) modal.classList.remove('active');
    },

    async handleLogin(e) {
        e.preventDefault();
        const usernameInput = document.getElementById('login-username');
        const passwordInput = document.getElementById('login-password');
        const errorEl = document.getElementById('login-error');

        errorEl.textContent = '';
        errorEl.style.display = 'none';

        try {
            const res = await API.request('/api/auth/login', {
                method: 'POST',
                body: JSON.stringify({
                    username: usernameInput.value,
                    password: passwordInput.value
                })
            });

            if (res.success) {
                API.setCsrfToken(res.csrfToken);
                this.currentUser = res.user;
                API.setUser(res.user);
                this.updateUserUI(res.user);
                this.hideLoginModal();
                passwordInput.value = '';
                API.showToast(`환영합니다, ${res.user.username}님!`, 'success');
                await this.loadAllData();
                this.switchTab('dashboard');
            }
        } catch (err) {
            errorEl.textContent = err.message;
            errorEl.style.display = 'block';
        }
    },

    async handleLogout() {
        try {
            await API.request('/api/auth/logout', { method: 'POST' });
        } catch (err) {}
        this.currentUser = null;
        API.setCsrfToken(null);
        API.showToast('성공적으로 로그아웃되었습니다.', 'info');
        this.showLoginModal();
    },

    switchTab(tabName) {
        this.currentTab = tabName;

        document.querySelectorAll('.nav-item').forEach(item => {
            if (item.getAttribute('data-tab') === tabName) {
                item.classList.add('active');
            } else {
                item.classList.remove('active');
            }
        });

        document.querySelectorAll('.tab-content').forEach(content => {
            content.style.display = 'none';
        });

        const activeContent = document.getElementById(`tab-${tabName}`);
        if (activeContent) activeContent.style.display = 'block';

        switch (tabName) {
            case 'dashboard': this.renderDashboard(); break;
            case 'ports': this.renderPortsTable(); break;
            case 'vlans': this.renderVlansTab(); break;
            case 'mac': this.renderMacTab(); break;
            case 'security': this.renderSecurityTab(); break;
            case 'stp': this.renderStpTab(); break;
            case 'lacp': this.renderLacpTab(); break;
            case 'system': this.renderSystemTab(); break;
            case 'alerts': this.renderAlertsTab(); break;
            case 'devices': this.renderDevicesTab(); break;
            case 'cli': this.renderCliTab(); break;
            case 'logs': this.renderLogsTab(); break;
        }
    },

    async loadAllData() {
        try {
            const [statusRes, portsRes, vlansRes] = await Promise.all([
                API.request('/api/switch/status'),
                API.request('/api/switch/ports'),
                API.request('/api/switch/vlans')
            ]);

            this.devices = statusRes.devices || [];
            this.activeDeviceId = statusRes.activeDeviceId;
            this.powerAlerts = statusRes.powerAlerts || [];
            this.renderHeaderDeviceSelector();
            this.renderPowerAlerts(this.powerAlerts);

            this.systemInfo = statusRes.system;
            this.poeSummary = statusRes.poeSummary || { availableWatts: 370.0, usedWatts: 98.4, remainingWatts: 271.6 };
            this.ports = portsRes.ports;
            this.vlans = vlansRes.vlans;
            this.ciscoConnected = statusRes.ciscoConnected;

            this.updateHeaderQuickInfo(statusRes);
            SwitchUI.renderFaceplate('switch-faceplate-container', this.ports, (port) => {
                this.openPortModal(port);
            });
        } catch (err) {
            API.showToast('장비 데이터 로드 실패: ' + err.message, 'error');
        }
    },

    updateHeaderQuickInfo(statusRes) {
        const sys = statusRes.system;
        const hostEl = document.getElementById('info-hostname');
        const ipEl = document.getElementById('info-ip');
        const modelEl = document.getElementById('chassis-model-name');
        const activePortsEl = document.getElementById('info-active-ports');
        const poeUsageEl = document.getElementById('info-poe-usage');

        if (hostEl) hostEl.textContent = sys.hostname;
        if (ipEl) ipEl.textContent = sys.ipAddress;
        if (modelEl) modelEl.textContent = sys.model || 'Catalyst 2960-S PoE+';
        if (activePortsEl) activePortsEl.textContent = `${statusRes.activePorts} / ${statusRes.totalPorts}`;

        // PoE 전력 게이지
        const poe = this.poeSummary;
        if (poeUsageEl) poeUsageEl.textContent = `${poe.usedWatts}W / ${poe.availableWatts}W`;
    },

    /* ============================================================ */
    /* 1. Dashboard 탭                                               */
    /* ============================================================ */
    renderDashboard() {
        this.renderFleetPowerMonitor();

        const upCount = this.ports.filter(p => (p.linkState === 'up' || p.status === 'up')).length;
        const totalCount = this.ports.length;

        const portVal = document.getElementById('metric-active-ports');
        if (portVal) portVal.textContent = `${upCount} / ${totalCount}`;

        const vlanVal = document.getElementById('metric-total-vlans');
        if (vlanVal) vlanVal.textContent = this.vlans.length;

        // PoE+ Power Budget 렌더링
        const poe = this.poeSummary;
        const poeWattsEl = document.getElementById('metric-poe-watts');
        const poeSubEl = document.getElementById('metric-poe-sub');
        const poeProgressEl = document.getElementById('metric-poe-progress');

        if (poeWattsEl && poe.availableWatts) {
            const percent = Math.min(100, Math.round((poe.usedWatts / poe.availableWatts) * 100));
            poeWattsEl.textContent = `${poe.usedWatts.toFixed(1)} W`;
            poeSubEl.textContent = `/ ${poe.availableWatts.toFixed(1)} W (${percent}%)`;
            if (poeProgressEl) poeProgressEl.style.width = `${percent}%`;
        }

        // 실시간 포트 & PoE+ 테이블 렌더링
        const tbody = document.getElementById('dashboard-active-ports-tbody');
        if (!tbody) return;

        SafeDOM.clearElement(tbody);
        const activeList = this.ports.filter(p => (p.linkState === 'up' || p.status === 'up') || (p.poe && p.poe.status === 'on'));

        if (activeList.length === 0) {
            tbody.appendChild(SafeDOM.createElement('tr', {
                children: [
                    SafeDOM.createElement('td', {
                        attrs: { colspan: 7, style: 'text-align: center; color: var(--text-muted);' },
                        text: '현재 연결된 활성 포트가 없습니다.'
                    })
                ]
            }));
            return;
        }

        activeList.forEach(p => {
            const isLinkUp = p.linkState === 'up' || p.status === 'up';
            const poe = p.poe || { status: 'off', powerWatts: 0, device: 'n/a' };
            const tr = SafeDOM.createElement('tr', {
                children: [
                    SafeDOM.createElement('td', {
                        children: [
                            SafeDOM.createElement('strong', { text: p.name }),
                            SafeDOM.createElement('span', { className: 'badge-tag gray', text: p.type || 'RJ45-1G', attrs: { style: 'margin-left: 6px;' } })
                        ]
                    }),
                    SafeDOM.createElement('td', {
                        children: [
                            SafeDOM.createElement('span', {
                                className: `badge-tag ${isLinkUp ? 'green' : 'gray'}`,
                                text: isLinkUp ? 'CONNECTED' : 'DISCONNECTED'
                            })
                        ]
                    }),
                    SafeDOM.createElement('td', { text: `${p.speed || '1G'} / ${p.duplex || 'full'}` }),
                    SafeDOM.createElement('td', { text: `VLAN ${p.pvid || 1} (${p.mode || 'access'})` }),
                    SafeDOM.createElement('td', {
                        children: [
                            SafeDOM.createElement('span', {
                                className: `badge-tag ${poe.status === 'on' ? 'amber' : 'gray'}`,
                                text: poe.status === 'on' ? `${poe.powerWatts} W (ON)` : 'OFF'
                            })
                        ]
                    }),
                    SafeDOM.createElement('td', { text: poe.device || '-' }),
                    SafeDOM.createElement('td', { text: p.description || '-' })
                ]
            });
            tbody.appendChild(tr);
        });
    },

    /* ============================================================ */
    /* 2. Ports 탭                                                  */
    /* ============================================================ */
    renderPortsTable() {
        const tbody = document.getElementById('ports-table-tbody');
        if (!tbody) return;

        SafeDOM.clearElement(tbody);
        const isViewer = this.currentUser && this.currentUser.role === 'viewer';

        // 1. 포트 데이터 정규화 및 필터링
        const filteredPorts = this.ports.filter(port => {
            const switchNum = port.switchNum || 1;
            const linkState = port.linkState || port.status || 'down';
            // 스택 필터
            if (this.stackFilter && this.stackFilter !== 'all') {
                if (String(switchNum) !== String(this.stackFilter)) return false;
            }
            // 상태 필터
            if (this.statusFilter === 'up' && linkState !== 'up') return false;
            if (this.statusFilter === 'down' && linkState !== 'down') return false;
            if (this.statusFilter === 'poe' && (!port.poe || port.poe.status !== 'on')) return false;

            // 검색어 필터
            if (this.searchQuery) {
                const matchName = (port.name || '').toLowerCase().includes(this.searchQuery);
                const matchDesc = (port.description || '').toLowerCase().includes(this.searchQuery);
                const matchVlan = String(port.pvid || '').includes(this.searchQuery);
                if (!matchName && !matchDesc && !matchVlan) return false;
            }
            return true;
        });

        if (filteredPorts.length === 0) {
            tbody.appendChild(SafeDOM.createElement('tr', {
                children: [
                    SafeDOM.createElement('td', {
                        attrs: { colspan: 10, style: 'text-align: center; color: var(--text-muted); padding: 24px;' },
                        text: '해당 조건과 일치하는 포트가 없습니다.'
                    })
                ]
            }));
            return;
        }

        filteredPorts.forEach(port => {
            const poe = port.poe || { mode: 'auto', status: 'off', powerWatts: 0, device: 'n/a' };
            const switchNum = port.switchNum || 1;
            const adminState = port.adminState || (port.admin === false ? 'down' : 'up');
            const linkState = port.linkState || port.status || 'down';
            const mode = (port.mode || 'access').toUpperCase();
            const pvid = port.pvid !== undefined ? port.pvid : 1;

            const tr = SafeDOM.createElement('tr', {
                children: [
                    SafeDOM.createElement('td', { text: port.id, attrs: { style: 'font-family: monospace; font-weight: 700;' } }),
                    SafeDOM.createElement('td', {
                        children: [
                            SafeDOM.createElement('strong', { text: port.name }),
                            SafeDOM.createElement('span', { className: 'badge-tag cyan', text: `SW#${switchNum}`, attrs: { style: 'margin-left: 6px;' } }),
                            SafeDOM.createElement('span', { className: 'badge-tag gray', text: port.type || 'RJ45-1G', attrs: { style: 'margin-left: 4px;' } })
                        ]
                    }),
                    SafeDOM.createElement('td', {
                        children: [
                            SafeDOM.createElement('span', {
                                className: `badge-tag ${adminState === 'up' ? 'green' : 'red'}`,
                                text: adminState.toUpperCase()
                            })
                        ]
                    }),
                    SafeDOM.createElement('td', {
                        children: [
                            SafeDOM.createElement('span', {
                                className: `badge-tag ${linkState === 'up' ? 'green' : 'gray'}`,
                                text: linkState === 'up' ? `${port.speed || '1G'}` : 'Down'
                            })
                        ]
                    }),
                    SafeDOM.createElement('td', { text: `${mode} (${pvid})` }),
                    SafeDOM.createElement('td', {
                        children: [
                            SafeDOM.createElement('span', {
                                className: `badge-tag ${(poe.mode || 'auto') === 'auto' ? 'blue' : 'gray'}`,
                                text: (poe.mode || 'auto').toUpperCase()
                            })
                        ]
                    }),
                    SafeDOM.createElement('td', {
                        text: poe.status === 'on' ? `${poe.powerWatts} W` : '0.0 W',
                        attrs: { style: poe.status === 'on' ? 'color: var(--amber-warning); font-weight: 600;' : '' }
                    }),
                    SafeDOM.createElement('td', {
                        children: [
                            port.connectedClient ? SafeDOM.createElement('div', {
                                children: [
                                    SafeDOM.createElement('span', {
                                        className: 'badge-tag cyan',
                                        text: port.connectedClient.ipAddress || port.connectedClient.mac.slice(-8),
                                        attrs: { style: 'font-family: monospace; font-weight: 600;' }
                                    }),
                                    SafeDOM.createElement('span', {
                                        text: port.connectedClient.deviceName ? ` ${port.connectedClient.deviceName.split(' ')[0]}` : '',
                                        attrs: { style: 'font-size: 0.78rem; color: var(--text-secondary); margin-left: 4px;' }
                                    })
                                ]
                            }) : (port.clientCount > 1 ? SafeDOM.createElement('span', {
                                className: 'badge-tag purple',
                                text: `Trunk (${port.clientCount}대 감지)`
                            }) : SafeDOM.createElement('span', { text: poe.device || '-', attrs: { style: 'color: var(--text-muted);' } }))
                        ]
                    }),
                    SafeDOM.createElement('td', { text: port.description || '-' }),
                    SafeDOM.createElement('td', {
                        children: [
                            SafeDOM.createElement('button', {
                                className: 'btn btn-secondary btn-sm',
                                text: '설정',
                                attrs: isViewer ? { disabled: 'true' } : {},
                                events: {
                                    click: () => this.openPortModal(port)
                                }
                            })
                        ]
                    })
                ]
            });
            tbody.appendChild(tr);
        });
    },

    openPortModal(port) {
        if (this.currentUser && this.currentUser.role === 'viewer') {
            API.showToast('Viewer 권한은 포트 설정을 변경할 수 없습니다.', 'info');
            return;
        }

        const modal = document.getElementById('port-edit-modal');
        if (!modal) return;

        document.getElementById('modal-port-id').value = port.id;
        document.getElementById('modal-port-title').textContent = `${port.name} (${port.type || 'RJ45-1G'}) 상세 설정`;
        document.getElementById('modal-port-admin').value = port.adminState || (port.admin === false ? 'down' : 'up');
        document.getElementById('modal-port-speed').value = port.speed || 'auto';
        document.getElementById('modal-port-duplex').value = port.duplex || 'auto';
        document.getElementById('modal-port-mode').value = port.mode || 'access';
        document.getElementById('modal-port-pvid').value = port.pvid !== undefined ? port.pvid : 1;
        document.getElementById('modal-port-desc').value = port.description || '';

        // 연결된 클라이언트 정보 렌더링
        const clientEl = document.getElementById('modal-port-client-details');
        if (clientEl) {
            SafeDOM.clearElement(clientEl);
            if (port.connectedClient) {
                clientEl.appendChild(SafeDOM.createElement('div', {
                    children: [
                        SafeDOM.createElement('div', { text: `• IP 주소: ${port.connectedClient.ipAddress || '미할당'}`, attrs: { style: 'color: var(--cyan-accent); font-weight: 600;' } }),
                        SafeDOM.createElement('div', { text: `• MAC 주소: ${port.connectedClient.mac} (${port.connectedClient.vendor || 'Unknown'})`, attrs: { style: 'color: var(--text-secondary); margin-top: 3px;' } }),
                        SafeDOM.createElement('div', { text: `• 단말 장치명: ${port.connectedClient.deviceName || port.description || '-'}`, attrs: { style: 'color: var(--emerald-green); margin-top: 3px;' } })
                    ]
                }));
            } else if (port.clientCount > 1) {
                clientEl.appendChild(SafeDOM.createElement('div', {
                    text: `• 다중 단말 감지: 총 ${port.clientCount}개의 MAC 주소가 이 포트(Trunk/업링크)를 통해 통신 중입니다.`,
                    attrs: { style: 'color: #a78bfa;' }
                }));
            } else {
                clientEl.appendChild(SafeDOM.createElement('div', {
                    text: '현재 이 포트에 연결된 활성 클라이언트 단말이 없습니다.',
                    attrs: { style: 'color: var(--text-muted);' }
                }));
            }
        }

        // PoE+ 모드 제어
        const poeSelect = document.getElementById('modal-port-poe');
        const poeInfo = document.getElementById('modal-port-poe-info');
        if (port.poe) {
            poeSelect.value = port.poe.mode || 'auto';
            poeInfo.textContent = `현재 상태: ${port.poe.status.toUpperCase()} (${port.poe.powerWatts}W 사용 중, 장치: ${port.poe.device || 'None'})`;
        } else {
            poeSelect.value = 'never';
            poeInfo.textContent = '광 포트(SFP+)는 PoE를 지원하지 않습니다.';
        }

        modal.classList.add('active');

        const form = document.getElementById('port-edit-form');
        form.onsubmit = async (e) => {
            e.preventDefault();
            const portId = Number(document.getElementById('modal-port-id').value);
            const payload = {
                adminState: document.getElementById('modal-port-admin').value,
                speed: document.getElementById('modal-port-speed').value,
                duplex: document.getElementById('modal-port-duplex').value,
                mode: document.getElementById('modal-port-mode').value,
                pvid: Number(document.getElementById('modal-port-pvid').value),
                description: document.getElementById('modal-port-desc').value,
                poeMode: poeSelect.value
            };

            try {
                const res = await API.request(`/api/switch/ports/${portId}`, {
                    method: 'PUT',
                    body: JSON.stringify(payload)
                });
                if (res.success) {
                    API.showToast(`포트 ${res.port.name} 설정이 저장되었습니다.`, 'success');
                    modal.classList.remove('active');
                    await this.loadAllData();
                    if (this.currentTab === 'ports') this.renderPortsTable();
                }
            } catch (err) {
                API.showToast(err.message, 'error');
            }
        };
    },

    /* ============================================================ */
    /* 3. VLANs 탭                                                 */
    /* ============================================================ */
    renderVlansTab() {
        const grid = document.getElementById('vlan-subnets-grid');
        const tbody = document.getElementById('vlans-table-tbody');
        const isViewer = this.currentUser && this.currentUser.role === 'viewer';

        // 1. VLAN별 IP 대역 카드 그리드 렌더링
        if (grid) {
            SafeDOM.clearElement(grid);
            this.vlans.forEach(v => {
                const memberPorts = this.ports.filter(p => p.pvid === v.id || (p.taggedVlans && p.taggedVlans.includes(v.id)));
                const portCount = memberPorts.length;

                let cardClass = 'vlan-subnet-card';
                let typeBadge = 'L3 서브넷 대역';
                let typeBadgeColor = 'blue';

                if (v.isSvi) {
                    cardClass += ' is-svi';
                    typeBadge = '⚡ SVI 관리망 (L3)';
                    typeBadgeColor = 'purple';
                } else if (v.isSystem) {
                    cardClass += ' is-default';
                    typeBadge = '기본 L2 VLAN';
                    typeBadgeColor = 'gray';
                }

                const netDisplay = v.network || (v.ipAddress ? `${v.ipAddress}${v.cidr ? '/' + v.cidr : ''}` : 'L2 스위칭 전용 (IP 미할당)');
                const rangeDisplay = v.usableRange || (v.network ? 'IP 대역 계산 중' : 'L2 전용 (호스트 IP 미사용)');
                const gwDisplay = v.gateway ? `${v.gateway} (Gateway)` : (v.isSvi ? `${v.ipAddress} (SVI IP)` : '-');
                const hostsDisplay = v.totalHosts !== undefined ? `${v.totalHosts} 개` : (v.network ? '-' : 'N/A');

                const card = SafeDOM.createElement('div', {
                    className: cardClass,
                    children: [
                        SafeDOM.createElement('div', {
                            className: 'vlan-card-header',
                            children: [
                                SafeDOM.createElement('span', { className: 'vlan-badge-pill', text: `VLAN ${v.id}` }),
                                SafeDOM.createElement('span', { className: `badge-tag ${typeBadgeColor}`, text: typeBadge })
                            ]
                        }),
                        SafeDOM.createElement('div', { className: 'vlan-card-title', text: v.name }),
                        SafeDOM.createElement('div', { className: 'vlan-card-desc', text: v.description || '설명 없음' }),
                        
                        SafeDOM.createElement('div', {
                            className: 'vlan-card-ip-box',
                            children: [
                                SafeDOM.createElement('div', {
                                    className: 'vlan-card-net-label',
                                    children: [
                                        SafeDOM.createElement('span', { text: 'IP NETWORK / CIDR' }),
                                        SafeDOM.createElement('span', { text: v.subnetMask ? `Mask: ${v.subnetMask}` : '' })
                                    ]
                                }),
                                SafeDOM.createElement('div', { className: 'vlan-card-net-val', text: netDisplay })
                            ]
                        }),

                        SafeDOM.createElement('div', {
                            className: 'vlan-card-stats',
                            children: [
                                SafeDOM.createElement('div', {
                                    className: 'vlan-card-stat-row',
                                    children: [
                                        SafeDOM.createElement('span', { className: 'vlan-stat-key', text: '가용 IP 대역' }),
                                        SafeDOM.createElement('span', { className: 'vlan-stat-val highlight', text: rangeDisplay })
                                    ]
                                }),
                                SafeDOM.createElement('div', {
                                    className: 'vlan-card-stat-row',
                                    children: [
                                        SafeDOM.createElement('span', { className: 'vlan-stat-key', text: '디폴트 게이트웨이' }),
                                        SafeDOM.createElement('span', { className: 'vlan-stat-val', text: gwDisplay })
                                    ]
                                }),
                                SafeDOM.createElement('div', {
                                    className: 'vlan-card-stat-row',
                                    children: [
                                        SafeDOM.createElement('span', { className: 'vlan-stat-key', text: '가용 호스트 수' }),
                                        SafeDOM.createElement('span', { className: 'vlan-stat-val', text: hostsDisplay })
                                    ]
                                }),
                                SafeDOM.createElement('div', {
                                    className: 'vlan-card-stat-row',
                                    children: [
                                        SafeDOM.createElement('span', { className: 'vlan-stat-key', text: '소속 인터페이스' }),
                                        SafeDOM.createElement('span', { className: 'vlan-stat-val', text: `${portCount}개 포트` })
                                    ]
                                })
                            ]
                        }),

                        SafeDOM.createElement('div', {
                            className: 'vlan-card-footer',
                            children: [
                                SafeDOM.createElement('span', {
                                    attrs: { style: 'font-size: 0.75rem; color: var(--text-muted);' },
                                    text: v.isSvi ? '★ Switch Virtual Interface' : (v.isSystem ? '시스템 기본' : 'Enterprise VLAN')
                                }),
                                SafeDOM.createElement('button', {
                                    className: 'btn btn-secondary btn-sm',
                                    text: 'IP 대역 설정 / 수정',
                                    attrs: isViewer ? { disabled: 'true' } : {},
                                    events: {
                                        click: () => this.openVlanModal(v)
                                    }
                                })
                            ]
                        })
                    ]
                });
                grid.appendChild(card);
            });
        }

        // 2. VLAN 상세 테이블 렌더링
        if (tbody) {
            SafeDOM.clearElement(tbody);
            this.vlans.forEach(v => {
                const memberPorts = this.ports
                    .filter(p => p.pvid === v.id || (p.taggedVlans && p.taggedVlans.includes(v.id)))
                    .map(p => p.name);
                
                const portsDisplay = memberPorts.length > 0 
                    ? `${memberPorts.slice(0, 4).join(', ')}${memberPorts.length > 4 ? ` 외 ${memberPorts.length - 4}개 (${memberPorts.length}개 포트)` : ` (${memberPorts.length}개 포트)`}`
                    : '소속 포트 없음';

                const netStr = v.network || (v.ipAddress ? `${v.ipAddress}${v.cidr ? '/' + v.cidr : ''}` : '-');
                const rangeStr = v.usableRange || (v.network ? 'IP 대역 계산 중' : 'L2 전용 (호스트 IP 미사용)');
                const gwStr = v.gateway ? v.gateway : (v.isSvi ? `${v.ipAddress} (SVI)` : '-');

                const tr = SafeDOM.createElement('tr', {
                    children: [
                        SafeDOM.createElement('td', {
                            children: [
                                SafeDOM.createElement('span', { className: 'badge-tag blue', text: `VLAN ${v.id}` })
                            ]
                        }),
                        SafeDOM.createElement('td', { text: v.name, attrs: { style: 'font-weight: 600;' } }),
                        SafeDOM.createElement('td', {
                            children: [
                                SafeDOM.createElement('span', {
                                    text: netStr,
                                    attrs: { style: 'font-family: monospace; font-weight: 600; color: var(--cyan-accent);' }
                                })
                            ]
                        }),
                        SafeDOM.createElement('td', {
                            children: [
                                SafeDOM.createElement('span', {
                                    text: rangeStr,
                                    attrs: { style: 'font-family: monospace; color: var(--emerald-green); font-size: 0.85rem;' }
                                })
                            ]
                        }),
                        SafeDOM.createElement('td', {
                            children: [
                                SafeDOM.createElement('span', {
                                    text: gwStr,
                                    attrs: { style: 'font-family: monospace; color: var(--text-primary);' }
                                })
                            ]
                        }),
                        SafeDOM.createElement('td', { text: portsDisplay, attrs: { style: 'color: var(--text-secondary); font-size: 0.82rem;' } }),
                        SafeDOM.createElement('td', { text: v.description || '-', attrs: { style: 'color: var(--text-muted); font-size: 0.82rem;' } }),
                        SafeDOM.createElement('td', {
                            children: [
                                SafeDOM.createElement('div', {
                                    attrs: { style: 'display: flex; gap: 6px;' },
                                    children: [
                                        SafeDOM.createElement('button', {
                                            className: 'btn btn-secondary btn-sm',
                                            text: '수정',
                                            attrs: isViewer ? { disabled: 'true' } : {},
                                            events: {
                                                click: () => this.openVlanModal(v)
                                            }
                                        }),
                                        v.isSystem ? SafeDOM.createElement('span', { className: 'badge-tag gray', text: '기본' }) :
                                        SafeDOM.createElement('button', {
                                            className: 'btn btn-danger btn-sm',
                                            text: '삭제',
                                            attrs: isViewer ? { disabled: 'true' } : {},
                                            events: {
                                                click: () => this.handleDeleteVlan(v.id)
                                            }
                                        })
                                    ]
                                })
                            ]
                        })
                    ]
                });
                tbody.appendChild(tr);
            });
        }

        const createBtn = document.getElementById('btn-create-vlan');
        if (createBtn) {
            createBtn.disabled = isViewer;
            createBtn.onclick = () => {
                this.openVlanModal(null);
            };
        }

        this.renderVlanPortMatrix();
    },

    /**
     * VLAN 생성 및 IP 서브넷 대역 설정 모달 열기
     */
    openVlanModal(vlan = null) {
        const modal = document.getElementById('vlan-modal');
        if (!modal) return;

        const titleEl = document.getElementById('vlan-modal-title');
        const modeEl = document.getElementById('vlan-modal-mode');
        const idInput = document.getElementById('vlan-modal-id');
        const nameInput = document.getElementById('vlan-modal-name');
        const ipInput = document.getElementById('vlan-modal-ip');
        const subnetInput = document.getElementById('vlan-modal-subnet');
        const gatewayInput = document.getElementById('vlan-modal-gateway');
        const descInput = document.getElementById('vlan-modal-desc');
        const submitBtn = document.getElementById('btn-vlan-submit');

        const updateCalcPreview = () => {
            const ip = ipInput.value.trim();
            const mask = subnetInput.value.trim();
            const calc = this.calculateSubnetPreview(ip, mask);

            const cidrEl = document.getElementById('vlan-calc-cidr');
            const netEl = document.getElementById('vlan-calc-network');
            const hostsEl = document.getElementById('vlan-calc-hosts');
            const bcastEl = document.getElementById('vlan-calc-broadcast');
            const rangeEl = document.getElementById('vlan-calc-range');

            if (calc) {
                if (cidrEl) cidrEl.textContent = `/${calc.cidr}`;
                if (netEl) netEl.textContent = calc.network;
                if (hostsEl) hostsEl.textContent = `${calc.totalHosts.toLocaleString()} 개`;
                if (bcastEl) bcastEl.textContent = calc.broadcast;
                if (rangeEl) rangeEl.textContent = calc.usableRange;
            } else {
                if (cidrEl) cidrEl.textContent = '-';
                if (netEl) netEl.textContent = '-';
                if (hostsEl) hostsEl.textContent = '-';
                if (bcastEl) bcastEl.textContent = '-';
                if (rangeEl) rangeEl.textContent = 'L2 전용 (미설정 또는 유효하지 않은 IP/마스크)';
            }
        };

        ipInput.oninput = updateCalcPreview;
        subnetInput.oninput = updateCalcPreview;

        if (vlan) {
            // 수정 모드
            modeEl.value = 'edit';
            titleEl.textContent = `VLAN ${vlan.id} (${vlan.name}) IP 대역 및 설정 수정`;
            idInput.value = vlan.id;
            idInput.disabled = true;
            nameInput.value = vlan.name;
            ipInput.value = vlan.ipAddress || '';
            subnetInput.value = vlan.subnetMask || '255.255.255.0';
            gatewayInput.value = vlan.gateway || '';
            descInput.value = vlan.description || '';
            submitBtn.textContent = '변경사항 저장';
        } else {
            // 생성 모드
            modeEl.value = 'create';
            titleEl.textContent = '새 802.1Q VLAN 및 IP 대역 생성';
            idInput.value = '';
            idInput.disabled = false;
            nameInput.value = '';
            ipInput.value = '';
            subnetInput.value = '255.255.255.0';
            gatewayInput.value = '';
            descInput.value = '';
            submitBtn.textContent = 'VLAN 생성';
        }

        updateCalcPreview();
        modal.classList.add('active');

        const form = document.getElementById('vlan-form');
        form.onsubmit = async (e) => {
            e.preventDefault();
            const mode = modeEl.value;
            const vlanId = Number(idInput.value);
            const name = nameInput.value.trim();
            const ipAddress = ipInput.value.trim() || null;
            const subnetMask = subnetInput.value.trim() || null;
            const gateway = gatewayInput.value.trim() || null;
            const description = descInput.value.trim();

            if (!name) {
                API.showToast('VLAN 이름을 입력해주세요.', 'error');
                return;
            }

            try {
                if (mode === 'create') {
                    if (!vlanId || vlanId < 1 || vlanId > 4094) {
                        API.showToast('VLAN ID는 1 ~ 4094 사이의 숫자여야 합니다.', 'error');
                        return;
                    }
                    const res = await API.request('/api/switch/vlans', {
                        method: 'POST',
                        body: JSON.stringify({ id: vlanId, name, description, ipAddress, subnetMask, gateway })
                    });
                    API.showToast(res.message, 'success');
                } else {
                    const res = await API.request(`/api/switch/vlans/${vlanId}`, {
                        method: 'PUT',
                        body: JSON.stringify({ name, description, ipAddress, subnetMask, gateway })
                    });
                    API.showToast(res.message, 'success');
                }

                modal.classList.remove('active');
                await this.loadAllData();
                this.renderVlansTab();
            } catch (err) {
                API.showToast(err.message, 'error');
            }
        };
    },

    /**
     * 클라이언트 측 서브넷 분석 및 가용 IP 범위 실시간 계산
     */
    calculateSubnetPreview(ip, mask) {
        if (!ip || !mask) return null;
        const ipParts = ip.trim().split('.').map(Number);
        const maskParts = mask.trim().split('.').map(Number);
        if (ipParts.length !== 4 || maskParts.length !== 4) return null;
        for (let i = 0; i < 4; i++) {
            if (isNaN(ipParts[i]) || ipParts[i] < 0 || ipParts[i] > 255) return null;
            if (isNaN(maskParts[i]) || maskParts[i] < 0 || maskParts[i] > 255) return null;
        }

        const ipInt = ((ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3]) >>> 0;
        const maskInt = ((maskParts[0] << 24) | (maskParts[1] << 16) | (maskParts[2] << 8) | maskParts[3]) >>> 0;

        let bits = 0;
        for (let i = 31; i >= 0; i--) {
            if ((maskInt >>> i) & 1) bits++;
        }

        const netInt = (ipInt & maskInt) >>> 0;
        const bcastInt = (netInt | (~maskInt >>> 0)) >>> 0;

        const intToIp = (num) => [
            (num >>> 24) & 255,
            (num >>> 16) & 255,
            (num >>> 8) & 255,
            num & 255
        ].join('.');

        const network = intToIp(netInt);
        const broadcast = intToIp(bcastInt);
        const totalHosts = Math.max(0, Math.pow(2, 32 - bits) - 2);

        let firstHost = 'N/A';
        let lastHost = 'N/A';
        if (bits < 31 && totalHosts > 0) {
            firstHost = intToIp(netInt + 1);
            lastHost = intToIp(bcastInt - 1);
        }

        return {
            cidr: bits,
            network: `${network}/${bits}`,
            broadcast,
            usableRange: totalHosts > 0 ? `${firstHost} ~ ${lastHost}` : '호스트 없음',
            totalHosts
        };
    },

    renderVlanPortMatrix() {
        const tbody = document.getElementById('vlan-matrix-tbody');
        if (!tbody) return;
        SafeDOM.clearElement(tbody);

        this.ports.forEach(p => {
            const tr = SafeDOM.createElement('tr', {
                children: [
                    SafeDOM.createElement('td', { text: p.name, attrs: { style: 'font-weight: 600;' } }),
                    SafeDOM.createElement('td', {
                        children: [
                            SafeDOM.createElement('span', {
                                className: `badge-tag ${p.mode === 'trunk' ? 'amber' : 'blue'}`,
                                text: p.mode.toUpperCase()
                            })
                        ]
                    }),
                    SafeDOM.createElement('td', { text: `VLAN ${p.pvid}` }),
                    SafeDOM.createElement('td', {
                        text: p.mode === 'trunk' ? (p.taggedVlans && p.taggedVlans.length ? p.taggedVlans.join(', ') : 'All') : 'None (Access)'
                    }),
                    SafeDOM.createElement('td', {
                        children: [
                            SafeDOM.createElement('button', {
                                className: 'btn btn-secondary btn-sm',
                                text: '설정',
                                events: {
                                    click: () => this.openPortModal(p)
                                }
                            })
                        ]
                    })
                ]
            });
            tbody.appendChild(tr);
        });
    },

    async handleDeleteVlan(vlanId) {
        if (!confirm(`VLAN ${vlanId}을(를) 삭제하시겠습니까?`)) return;
        try {
            const res = await API.request(`/api/switch/vlans/${vlanId}`, { method: 'DELETE' });
            API.showToast(res.message, 'success');
            await this.loadAllData();
            this.renderVlansTab();
        } catch (err) {
            API.showToast(err.message, 'error');
        }
    },

    /* ============================================================ */
    /* 4. 장비별 연결 클라이언트 & MAC/IP 테이블 탭                */
    /* ============================================================ */
    async renderMacTab() {
        const queryParams = new URLSearchParams({
            search: this.macSearchQuery || '',
            switch: this.macStackFilter || 'all',
            vlan: this.macVlanFilter || 'all',
            type: this.macTypeFilter || 'all'
        });

        try {
            const res = await API.request(`/api/switch/mac-table?${queryParams.toString()}`);
            const tbody = document.getElementById('mac-table-tbody');
            if (!tbody) return;

            // 1. 요약 통계 지표 업데이트
            if (res.summary) {
                const totalEl = document.getElementById('mac-stat-total');
                const directEl = document.getElementById('mac-stat-direct');
                const bySwEl = document.getElementById('mac-stat-by-switch');
                const byVlanEl = document.getElementById('mac-stat-by-vlan');

                if (totalEl) totalEl.textContent = res.summary.totalClients.toLocaleString();
                if (directEl) directEl.textContent = res.summary.directClients.toLocaleString();
                if (bySwEl && res.summary.bySwitch) {
                    bySwEl.textContent = `SW1: ${res.summary.bySwitch[1]} | SW2: ${res.summary.bySwitch[2]} | SW3: ${res.summary.bySwitch[3]} | SW4: ${res.summary.bySwitch[4]}`;
                }
                if (byVlanEl && res.summary.byVlan) {
                    byVlanEl.textContent = `V2: ${res.summary.byVlan[2] || 0} | V228: ${res.summary.byVlan[228] || 0} | V241: ${res.summary.byVlan[241] || 0} | V1: ${res.summary.byVlan[1] || 0}`;
                }
            }

            SafeDOM.clearElement(tbody);
            const isViewer = this.currentUser && this.currentUser.role === 'viewer';

            if (!res.macTable || res.macTable.length === 0) {
                tbody.appendChild(SafeDOM.createElement('tr', {
                    children: [
                        SafeDOM.createElement('td', {
                            attrs: { colspan: 10, style: 'text-align: center; color: var(--text-muted); padding: 30px;' },
                            text: '선택한 조건(장비/VLAN/검색어)에 해당하는 연결 클라이언트가 없습니다.'
                        })
                    ]
                }));
                return;
            }

            res.macTable.forEach((m, idx) => {
                const port = this.ports.find(p => p.id === m.portId || p.name === m.portName);
                const portName = port ? port.name : (m.portName || `Port ${m.portId}`);
                const swNum = m.switchNum || (port ? port.switchNum : 1);

                const tr = SafeDOM.createElement('tr', {
                    children: [
                        SafeDOM.createElement('td', { text: idx + 1, attrs: { style: 'color: var(--text-muted); font-size: 0.78rem;' } }),
                        SafeDOM.createElement('td', {
                            children: [
                                SafeDOM.createElement('span', { className: 'badge-tag cyan', text: `SW#${swNum}` }),
                                SafeDOM.createElement('button', {
                                    className: 'btn btn-secondary btn-sm',
                                    text: portName,
                                    attrs: { style: 'margin-left: 6px; font-weight: 600; padding: 2px 8px; font-size: 0.78rem;' },
                                    events: {
                                        click: () => {
                                            if (port) this.openPortModal(port);
                                        }
                                    }
                                })
                            ]
                        }),
                        SafeDOM.createElement('td', {
                            children: [
                                m.ipAddress ? SafeDOM.createElement('span', {
                                    className: 'badge-tag cyan',
                                    text: m.ipAddress,
                                    attrs: { style: 'font-family: monospace; font-weight: 700; font-size: 0.85rem;' }
                                }) : SafeDOM.createElement('span', {
                                    text: '(IP 미할당)',
                                    attrs: { style: 'color: var(--text-muted); font-size: 0.8rem;' }
                                })
                            ]
                        }),
                        SafeDOM.createElement('td', {
                            children: [
                                SafeDOM.createElement('span', {
                                    text: m.mac,
                                    attrs: { style: 'font-family: monospace; font-weight: 600; color: var(--text-primary);' }
                                })
                            ]
                        }),
                        SafeDOM.createElement('td', {
                            children: [
                                SafeDOM.createElement('span', {
                                    className: 'badge-tag gray',
                                    text: m.vendor || 'Network Device'
                                })
                            ]
                        }),
                        SafeDOM.createElement('td', {
                            children: [
                                SafeDOM.createElement('span', { className: 'badge-tag blue', text: `VLAN ${m.vlanId}` })
                            ]
                        }),
                        SafeDOM.createElement('td', {
                            children: [
                                SafeDOM.createElement('span', {
                                    text: m.deviceName || '-',
                                    attrs: { style: 'font-weight: 600; color: var(--text-primary); font-size: 0.84rem;' }
                                })
                            ]
                        }),
                        SafeDOM.createElement('td', {
                            children: [
                                SafeDOM.createElement('span', {
                                    className: `badge-tag ${m.interfaceType === 'access' ? 'green' : 'purple'}`,
                                    text: m.interfaceType === 'access' ? '단말 (Access)' : '업링크 / Trunk'
                                })
                            ]
                        }),
                        SafeDOM.createElement('td', {
                            children: [
                                m.type === 'static' ? SafeDOM.createElement('span', { className: 'badge-tag amber', text: 'STATIC' }) :
                                SafeDOM.createElement('span', { text: `${m.age}s (Active)`, attrs: { style: 'font-size: 0.8rem; color: var(--text-secondary);' } })
                            ]
                        }),
                        SafeDOM.createElement('td', {
                            children: [
                                SafeDOM.createElement('div', {
                                    attrs: { style: 'display: flex; gap: 6px;' },
                                    children: [
                                        SafeDOM.createElement('button', {
                                            className: 'btn btn-secondary btn-sm',
                                            text: '수정',
                                            attrs: isViewer ? { disabled: 'true' } : {},
                                            events: {
                                                click: () => this.openClientEditModal(m)
                                            }
                                        }),
                                        m.type === 'static' ? SafeDOM.createElement('button', {
                                            className: 'btn btn-danger btn-sm',
                                            text: '삭제',
                                            attrs: isViewer ? { disabled: 'true' } : {},
                                            events: {
                                                click: () => this.handleDeleteStaticMac(m.mac, m.vlanId)
                                            }
                                        }) : null
                                    ].filter(Boolean)
                                })
                            ]
                        })
                    ]
                });
                tbody.appendChild(tr);
            });
        } catch (err) {
            API.showToast(err.message, 'error');
        }

        // 정적 MAC/IP 등록 버튼 이벤트
        const addBtn = document.getElementById('btn-add-static-mac');
        if (addBtn) {
            addBtn.onclick = () => {
                const modal = document.getElementById('mac-add-modal');
                const portSelect = document.getElementById('static-mac-port');
                SafeDOM.clearElement(portSelect);
                this.ports.forEach(p => {
                    portSelect.appendChild(SafeDOM.createElement('option', {
                        attrs: { value: p.id },
                        text: `[SW#${p.switchNum || 1}] ${p.name} (${p.type})`
                    }));
                });
                if (modal) modal.classList.add('active');
            };
        }

        // 정적 MAC/IP 등록 폼 처리
        const macForm = document.getElementById('mac-add-form');
        if (macForm) {
            macForm.onsubmit = async (e) => {
                e.preventDefault();
                const mac = document.getElementById('static-mac-input').value.trim();
                const ipAddress = document.getElementById('static-mac-ip').value.trim() || null;
                const deviceName = document.getElementById('static-mac-name').value.trim() || null;
                const vlanId = Number(document.getElementById('static-mac-vlan').value);
                const portId = Number(document.getElementById('static-mac-port').value);

                try {
                    const res = await API.request('/api/switch/mac-table/static', {
                        method: 'POST',
                        body: JSON.stringify({ mac, vlanId, portId, ipAddress, deviceName })
                    });
                    API.showToast(res.message, 'success');
                    document.getElementById('mac-add-modal').classList.remove('active');
                    await this.loadAllData();
                    this.renderMacTab();
                } catch (err) {
                    API.showToast(err.message, 'error');
                }
            };
        }

        // 동적 MAC 테이블 플러시
        const flushBtn = document.getElementById('btn-flush-mac');
        if (flushBtn) {
            flushBtn.onclick = async () => {
                if (!confirm('동적 학습된 MAC 주소 및 클라이언트 테이블을 플러시하시겠습니까?')) return;
                try {
                    const res = await API.request('/api/switch/mac-table/flush', { method: 'POST' });
                    API.showToast(res.message, 'success');
                    await this.loadAllData();
                    this.renderMacTab();
                } catch (err) {
                    API.showToast(err.message, 'error');
                }
            };
        }
    },

    /**
     * 클라이언트 IP / 단말 장치명 수정 모달 열기
     */
    openClientEditModal(client) {
        const modal = document.getElementById('client-edit-modal');
        if (!modal) return;

        document.getElementById('edit-client-mac').value = client.mac;
        document.getElementById('edit-client-mac-display').textContent = client.mac;
        document.getElementById('edit-client-port-display').textContent = `${client.portName || '-'} (VLAN ${client.vlanId})`;
        document.getElementById('edit-client-vendor-display').textContent = client.vendor || 'Network Device';
        document.getElementById('edit-client-ip').value = client.ipAddress || '';
        document.getElementById('edit-client-name').value = client.deviceName || '';

        modal.classList.add('active');

        const form = document.getElementById('client-edit-form');
        form.onsubmit = async (e) => {
            e.preventDefault();
            const mac = document.getElementById('edit-client-mac').value;
            const ipAddress = document.getElementById('edit-client-ip').value.trim() || null;
            const deviceName = document.getElementById('edit-client-name').value.trim() || null;

            try {
                const res = await API.request('/api/switch/mac-table/client', {
                    method: 'PUT',
                    body: JSON.stringify({ mac, ipAddress, deviceName })
                });
                API.showToast(res.message, 'success');
                modal.classList.remove('active');
                await this.loadAllData();
                this.renderMacTab();
            } catch (err) {
                API.showToast(err.message, 'error');
            }
        };
    },

    async handleDeleteStaticMac(mac, vlanId) {
        if (!confirm(`정적 MAC ${mac}을(를) 삭제하시겠습니까?`)) return;
        try {
            const res = await API.request('/api/switch/mac-table/static', {
                method: 'DELETE',
                body: JSON.stringify({ mac, vlanId })
            });
            API.showToast(res.message, 'success');
            await this.loadAllData();
            this.renderMacTab();
        } catch (err) {
            API.showToast(err.message, 'error');
        }
    },

    /* ============================================================ */
    /* 5. Port Security 탭                                          */
    /* ============================================================ */
    renderSecurityTab() {
        const tbody = document.getElementById('port-security-tbody');
        if (!tbody) return;

        SafeDOM.clearElement(tbody);
        this.ports.forEach(p => {
            const sec = p.portSecurity || { enabled: false, maxMac: 1, violationAction: 'shutdown', sticky: false };

            const tr = SafeDOM.createElement('tr', {
                children: [
                    SafeDOM.createElement('td', { text: p.name, attrs: { style: 'font-weight: 600;' } }),
                    SafeDOM.createElement('td', {
                        children: [
                            SafeDOM.createElement('span', {
                                className: `badge-tag ${sec.enabled ? 'green' : 'gray'}`,
                                text: sec.enabled ? 'ENABLED' : 'DISABLED'
                            })
                        ]
                    }),
                    SafeDOM.createElement('td', { text: sec.maxMac }),
                    SafeDOM.createElement('td', {
                        children: [
                            SafeDOM.createElement('span', {
                                className: `badge-tag ${sec.violationAction === 'shutdown' ? 'red' : 'amber'}`,
                                text: sec.violationAction.toUpperCase()
                            })
                        ]
                    }),
                    SafeDOM.createElement('td', { text: sec.sticky ? 'Active' : 'Off' }),
                    SafeDOM.createElement('td', {
                        children: [
                            SafeDOM.createElement('button', {
                                className: 'btn btn-secondary btn-sm',
                                text: '설정',
                                events: {
                                    click: () => this.openPortModal(p)
                                }
                            })
                        ]
                    })
                ]
            });
            tbody.appendChild(tr);
        });
    },

    /* ============================================================ */
    /* 6. STP / Rapid-PVST 탭                                       */
    /* ============================================================ */
    async renderStpTab() {
        try {
            const res = await API.request('/api/switch/stp');
            const stp = res.stp;

            document.getElementById('stp-mode-select').value = stp.mode;
            document.getElementById('stp-priority-select').value = stp.priority;
            document.getElementById('stp-hello-time').value = stp.helloTime;
            document.getElementById('stp-max-age').value = stp.maxAge;
            document.getElementById('stp-forward-delay').value = stp.forwardDelay;

            const form = document.getElementById('stp-form');
            form.onsubmit = async (e) => {
                e.preventDefault();
                const payload = {
                    mode: document.getElementById('stp-mode-select').value,
                    priority: Number(document.getElementById('stp-priority-select').value),
                    helloTime: Number(document.getElementById('stp-hello-time').value),
                    maxAge: Number(document.getElementById('stp-max-age').value),
                    forwardDelay: Number(document.getElementById('stp-forward-delay').value)
                };

                try {
                    await API.request('/api/switch/stp', { method: 'PUT', body: JSON.stringify(payload) });
                    API.showToast('Cisco STP 설정이 저장되었습니다.', 'success');
                } catch (err) {
                    API.showToast(err.message, 'error');
                }
            };
        } catch (err) {
            API.showToast(err.message, 'error');
        }
    },

    /* ============================================================ */
    /* 7. LACP / EtherChannel 탭                                    */
    /* ============================================================ */
    async renderLacpTab() {
        try {
            const res = await API.request('/api/switch/lacp');
            const tbody = document.getElementById('lacp-table-tbody');
            if (!tbody) return;

            SafeDOM.clearElement(tbody);
            res.lagGroups.forEach(lag => {
                const memberNames = lag.members.map(m => {
                    const p = this.ports.find(x => x.id === m);
                    return p ? p.name : `Gi1/0/${m}`;
                }).join(', ');

                const tr = SafeDOM.createElement('tr', {
                    children: [
                        SafeDOM.createElement('td', { text: lag.name, attrs: { style: 'font-weight: 700;' } }),
                        SafeDOM.createElement('td', {
                            children: [
                                SafeDOM.createElement('span', { className: 'badge-tag cyan', text: lag.mode.toUpperCase() })
                            ]
                        }),
                        SafeDOM.createElement('td', { text: memberNames }),
                        SafeDOM.createElement('td', { text: lag.description || '-' }),
                        SafeDOM.createElement('td', { text: '-' })
                    ]
                });
                tbody.appendChild(tr);
            });
        } catch (err) {
            API.showToast(err.message, 'error');
        }
    },

    /* ============================================================ */
    /* 8. System 탭                                                 */
    /* ============================================================ */
    renderSystemTab() {
        const sys = this.systemInfo;
        document.getElementById('sys-hostname').value = sys.hostname || '';
        document.getElementById('sys-ip').value = sys.ipAddress || '';
        document.getElementById('sys-subnet').value = sys.subnetMask || '';
        document.getElementById('sys-gateway').value = sys.defaultGateway || '';
        document.getElementById('sys-ntp').value = sys.ntpServer || '';

        const form = document.getElementById('system-info-form');
        form.onsubmit = async (e) => {
            e.preventDefault();
            const payload = {
                hostname: document.getElementById('sys-hostname').value,
                ipAddress: document.getElementById('sys-ip').value,
                subnetMask: document.getElementById('sys-subnet').value,
                defaultGateway: document.getElementById('sys-gateway').value,
                ntpServer: document.getElementById('sys-ntp').value
            };

            try {
                await API.request('/api/switch/system', { method: 'PUT', body: JSON.stringify(payload) });
                API.showToast('시스템 네트워크 설정이 저장되었습니다.', 'success');
                await this.loadAllData();
            } catch (err) {
                API.showToast(err.message, 'error');
            }
        };

        const passForm = document.getElementById('change-password-form');
        passForm.onsubmit = async (e) => {
            e.preventDefault();
            const curPass = document.getElementById('pass-current').value;
            const newPass = document.getElementById('pass-new').value;
            const confirmPass = document.getElementById('pass-confirm').value;

            if (newPass !== confirmPass) {
                API.showToast('새 비밀번호가 일치하지 않습니다.', 'error');
                return;
            }

            try {
                const res = await API.request('/api/auth/password', {
                    method: 'POST',
                    body: JSON.stringify({ currentPassword: curPass, newPassword: newPass })
                });
                API.showToast(res.message, 'success');
                passForm.reset();
            } catch (err) {
                API.showToast(err.message, 'error');
            }
        };
    },

    /* ============================================================ */
    /* 9. Cisco CLI Script & Terminal 탭                            */
    /* ============================================================ */
    async renderCliTab() {
        try {
            const res = await API.request('/api/switch/cli/running-config');
            const codeEl = document.getElementById('cisco-cli-script');
            if (codeEl) codeEl.textContent = res.configText;

            const copyBtn = document.getElementById('btn-copy-cli');
            if (copyBtn) {
                copyBtn.onclick = () => {
                    navigator.clipboard.writeText(res.configText).then(() => {
                        API.showToast('Cisco Running-Config가 클립보드에 복사되었습니다.', 'success');
                    });
                };
            }

            const termInput = document.getElementById('terminal-input');
            const termBody = document.getElementById('terminal-body');
            const termPrompt = document.getElementById('terminal-prompt-label');

            if (termPrompt) termPrompt.textContent = `${this.systemInfo.hostname || 'Switch'}#`;

            if (termInput && !termInput._bound) {
                termInput._bound = true;
                termInput.addEventListener('keydown', async (e) => {
                    if (e.key === 'Enter') {
                        const cmd = termInput.value.trim();
                        termInput.value = '';
                        if (!cmd) return;

                        termBody.textContent += `${termPrompt.textContent} ${cmd}\n`;
                        if (cmd.toLowerCase() === 'clear') {
                            termBody.textContent = '';
                            return;
                        }

                        try {
                            const cmdRes = await API.request('/api/switch/cli/execute', {
                                method: 'POST',
                                body: JSON.stringify({ command: cmd })
                            });
                            termBody.textContent += `${cmdRes.output}\n\n`;
                            termPrompt.textContent = cmdRes.prompt;
                        } catch (err) {
                            termBody.textContent += `% Error: ${err.message}\n\n`;
                        }

                        termBody.scrollTop = termBody.scrollHeight;
                    }
                });
            }
        } catch (err) {
            API.showToast(err.message, 'error');
        }
    },

    /* ============================================================ */
    /* 10. Audit Logs 탭                                            */
    /* ============================================================ */
    async renderLogsTab() {
        const categorySelect = document.getElementById('log-category-filter');
        const searchInput = document.getElementById('log-search-input');

        const cat = categorySelect ? categorySelect.value : '';
        const q = searchInput ? searchInput.value.trim() : '';

        try {
            const res = await API.request(`/api/audit-logs?category=${encodeURIComponent(cat)}&search=${encodeURIComponent(q)}`);
            const tbody = document.getElementById('logs-table-tbody');
            if (!tbody) return;

            SafeDOM.clearElement(tbody);
            res.logs.forEach(l => {
                const tr = SafeDOM.createElement('tr', {
                    children: [
                        SafeDOM.createElement('td', { text: new Date(l.timestamp).toLocaleString(), attrs: { style: 'font-family: monospace;' } }),
                        SafeDOM.createElement('td', {
                            children: [
                                SafeDOM.createElement('span', { className: 'badge-tag blue', text: l.category })
                            ]
                        }),
                        SafeDOM.createElement('td', { text: l.username, attrs: { style: 'font-weight: 600;' } }),
                        SafeDOM.createElement('td', { text: l.ip, attrs: { style: 'font-family: monospace; color: var(--text-secondary);' } }),
                        SafeDOM.createElement('td', { text: l.action }),
                        SafeDOM.createElement('td', {
                            children: [
                                SafeDOM.createElement('span', {
                                    className: `badge-tag ${l.status === 'SUCCESS' ? 'green' : 'red'}`,
                                    text: l.status
                                })
                            ]
                        })
                    ]
                });
                tbody.appendChild(tr);
            });

            if (categorySelect) categorySelect.onchange = () => this.renderLogsTab();
            if (searchInput) searchInput.oninput = () => this.renderLogsTab();
        } catch (err) {
            API.showToast(err.message, 'error');
        }
    },

    /* ============================================================ */
    /* 11. 장애 경보 및 담당자 이메일 보고서 관리                   */
    /* ============================================================ */
    alertSettings: null,
    incidentReports: [],

    bindAlertEvents() {
        const settingsForm = document.getElementById('alert-settings-form');
        if (settingsForm) {
            settingsForm.onsubmit = async (e) => {
                e.preventDefault();
                await this.handleSaveAlertSettings();
            };
        }

        const simForm = document.getElementById('incident-simulation-form');
        if (simForm) {
            simForm.onsubmit = async (e) => {
                e.preventDefault();
                await this.handleRunSimulation(false);
            };
        }

        const btnQuickTest = document.getElementById('btn-quick-test-report');
        if (btnQuickTest) {
            btnQuickTest.onclick = async () => {
                await this.handleRunSimulation(true);
            };
        }

        const btnRefresh = document.getElementById('btn-refresh-alerts');
        if (btnRefresh) {
            btnRefresh.onclick = () => this.renderAlertsTab();
        }

        const portSelect = document.getElementById('sim-port-select');
        if (portSelect) {
            portSelect.onchange = () => this.updateSimClientPreview();
        }

        const btnPrint = document.getElementById('btn-print-report');
        if (btnPrint) {
            btnPrint.onclick = () => window.print();
        }
    },

    async renderAlertsTab() {
        try {
            const [cfgRes, repRes] = await Promise.all([
                API.request('/api/switch/alerts/config'),
                API.request('/api/switch/alerts/reports')
            ]);

            this.alertSettings = cfgRes.alertSettings;
            this.incidentReports = repRes.reports || [];

            this.renderAlertSettingsForm(this.alertSettings);
            this.populateSimPortSelect();
            this.renderIncidentReportsTable(this.incidentReports);
        } catch (err) {
            API.showToast('경보 설정 및 보고서 조회 실패: ' + err.message, 'error');
        }
    },

    renderAlertSettingsForm(settings) {
        if (!settings) return;
        const enabledCheck = document.getElementById('alert-enabled');
        const managerEmail = document.getElementById('alert-manager-email');
        const managerName = document.getElementById('alert-manager-name');
        const senderEmail = document.getElementById('alert-sender-email');
        const senderName = document.getElementById('alert-sender-name');
        const smtpHost = document.getElementById('alert-smtp-host');
        const smtpPort = document.getElementById('alert-smtp-port');
        const smtpSecure = document.getElementById('alert-smtp-secure');
        const smtpUser = document.getElementById('alert-smtp-user');
        const smtpPass = document.getElementById('alert-smtp-pass');

        const notifyLinkDown = document.getElementById('notify-link-down');
        const notifySecurity = document.getElementById('notify-security');
        const notifyPoe = document.getElementById('notify-poe');
        const notifyStack = document.getElementById('notify-stack');

        const statusBadge = document.getElementById('alert-status-badge');

        if (enabledCheck) enabledCheck.checked = Boolean(settings.enabled);
        if (managerEmail) managerEmail.value = settings.managerEmail || '';
        if (managerName) managerName.value = settings.managerName || '';
        if (senderEmail) senderEmail.value = settings.senderEmail || '';
        if (senderName) senderName.value = settings.senderName || '';
        if (smtpHost) smtpHost.value = settings.smtpHost || '';
        if (smtpPort) smtpPort.value = settings.smtpPort || 587;
        if (smtpSecure) smtpSecure.value = String(Boolean(settings.smtpSecure));
        if (smtpUser) smtpUser.value = settings.smtpUser || '';
        if (smtpPass) smtpPass.value = settings.smtpPass || '';

        if (notifyLinkDown) notifyLinkDown.checked = settings.notifyOnLinkDown !== false;
        if (notifySecurity) notifySecurity.checked = settings.notifyOnSecurityViolation !== false;
        if (notifyPoe) notifyPoe.checked = settings.notifyOnPoeFault !== false;
        if (notifyStack) notifyStack.checked = settings.notifyOnStackChange !== false;

        if (statusBadge) {
            if (settings.enabled && settings.managerEmail) {
                statusBadge.className = 'badge-tag green';
                statusBadge.textContent = '발송 활성 (' + settings.managerEmail + ')';
            } else {
                statusBadge.className = 'badge-tag amber';
                statusBadge.textContent = '발송 비활성 또는 이메일 미지정';
            }
        }
    },

    populateSimPortSelect() {
        const select = document.getElementById('sim-port-select');
        if (!select) return;
        SafeDOM.clearElement(select);

        const defaultOpt = document.createElement('option');
        defaultOpt.value = '';
        defaultOpt.textContent = '-- 장애 발생 대상 포트를 선택하세요 --';
        select.appendChild(defaultOpt);

        (this.ports || []).forEach(port => {
            const opt = document.createElement('option');
            opt.value = port.name;
            const client = port.connectedClient;
            const clientText = client ? ` [${client.deviceName || '단말'} / IP: ${client.ipAddress || '-'}]` : '';
            opt.textContent = `스택 #${port.switchNum || 1} - ${port.name} (${port.status === 'up' ? 'UP' : 'DOWN'})${clientText}`;
            select.appendChild(opt);
        });

        // 2번 스택 Gi2/0/14 등 유의미한 포트 기본 선택
        const defaultTarget = this.ports.find(p => p.name === 'Gi2/0/14') || this.ports.find(p => p.status === 'up') || this.ports[0];
        if (defaultTarget) {
            select.value = defaultTarget.name;
            this.updateSimClientPreview();
        }
    },

    updateSimClientPreview() {
        const select = document.getElementById('sim-port-select');
        const previewEl = document.getElementById('sim-client-info-text');
        if (!select || !previewEl) return;

        const portName = select.value;
        const port = (this.ports || []).find(p => p.name === portName);
        if (!port) {
            previewEl.textContent = '포트를 선택해주세요.';
            return;
        }

        const client = port.connectedClient;
        if (client) {
            previewEl.innerHTML = `
                <div style="display: flex; gap: 16px; flex-wrap: wrap;">
                    <span><b>단말기명:</b> <span style="color: var(--cyan-accent);">${SafeDOM.escape(client.deviceName || '-')}</span></span>
                    <span><b>IP 주소:</b> <span style="color: var(--emerald-green); font-weight: 600;">${SafeDOM.escape(client.ipAddress || '미할당')}</span></span>
                    <span><b>MAC:</b> <span style="color: #cbd5e1;">${SafeDOM.escape(client.mac || '-')}</span></span>
                    <span><b>VLAN:</b> PVID ${port.pvid}</span>
                </div>
            `;
        } else {
            previewEl.textContent = `포트: ${port.name} (PVID: ${port.pvid}) - 직접 연결된 단말 정보 없음`;
        }
    },

    async handleSaveAlertSettings() {
        const managerEmail = document.getElementById('alert-manager-email').value.trim();
        const managerName = document.getElementById('alert-manager-name').value.trim();
        const senderEmail = document.getElementById('alert-sender-email').value.trim();
        const senderName = document.getElementById('alert-sender-name').value.trim();
        const smtpHost = document.getElementById('alert-smtp-host').value.trim();
        const smtpPort = Number(document.getElementById('alert-smtp-port').value) || 587;
        const smtpSecure = document.getElementById('alert-smtp-secure').value === 'true';
        const smtpUser = document.getElementById('alert-smtp-user').value.trim();
        const smtpPass = document.getElementById('alert-smtp-pass').value;

        const enabled = document.getElementById('alert-enabled').checked;
        const notifyOnLinkDown = document.getElementById('notify-link-down').checked;
        const notifyOnSecurityViolation = document.getElementById('notify-security').checked;
        const notifyOnPoeFault = document.getElementById('notify-poe').checked;
        const notifyOnStackChange = document.getElementById('notify-stack').checked;

        try {
            const res = await API.request('/api/switch/alerts/config', {
                method: 'PUT',
                body: JSON.stringify({
                    enabled,
                    managerEmail,
                    managerName,
                    senderEmail,
                    senderName,
                    smtpHost,
                    smtpPort,
                    smtpSecure,
                    smtpUser,
                    smtpPass,
                    notifyOnLinkDown,
                    notifyOnSecurityViolation,
                    notifyOnPoeFault,
                    notifyOnStackChange
                })
            });

            this.alertSettings = res.alertSettings;
            this.renderAlertSettingsForm(this.alertSettings);
            API.showToast(res.message, 'success');
        } catch (err) {
            API.showToast(err.message, 'error');
        }
    },

    async handleRunSimulation(reportOnly = false) {
        const portSelect = document.getElementById('sim-port-select');
        const portName = portSelect ? portSelect.value : '';
        if (!portName) {
            API.showToast('장애 대상 포트를 선택해주세요.', 'error');
            return;
        }

        const incidentType = document.getElementById('sim-incident-type').value;
        const severity = document.getElementById('sim-severity').value;
        const customMessage = document.getElementById('sim-custom-message').value.trim();

        // [신규] 전원 장애 유형 처리 (스위치 섀시 전원 꺼짐 또는 PoE 단말 전원 차단)
        if (incidentType === 'SWITCH_POWER_OFF') {
            await this.handlePowerSimulate(this.activeDeviceId, 'switch_power_off', null, customMessage || 'AC 주전원 차단 / 전원 공급 중단');
            await this.renderAlertsTab();
            return;
        }
        if (incidentType === 'POE_DEVICE_POWER_OFF') {
            await this.handlePowerSimulate(this.activeDeviceId, 'poe_power_off', portName, customMessage || '수전 단말 PoE 전원 공급 차단 / 단말 꺼짐');
            await this.renderAlertsTab();
            return;
        }

        const endpoint = reportOnly ? '/api/switch/alerts/trigger-test' : '/api/switch/alerts/simulate-incident';
        
        try {
            API.showToast('보고서 생성 및 담당자 이메일 발송 중...', 'info');
            const res = await API.request(endpoint, {
                method: 'POST',
                body: JSON.stringify({
                    portName,
                    incidentType,
                    severity,
                    customMessage
                })
            });

            API.showToast(res.message, 'success');
            await this.loadAllData(); // 포트 상태 갱신
            await this.renderAlertsTab();
            if (res.report && res.report.id) {
                this.openIncidentReportModal(res.report.id);
            }
        } catch (err) {
            API.showToast('장애 보고서 발송 실패: ' + err.message, 'error');
        }
    },

    renderIncidentReportsTable(reports) {
        const tbody = document.getElementById('incident-reports-tbody');
        const badgeEl = document.getElementById('reports-count-badge');
        if (!tbody) return;

        if (badgeEl) badgeEl.textContent = `${reports.length}건 보관 중`;
        SafeDOM.clearElement(tbody);

        if (!reports || reports.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 24px;">등록된 장애 보고서가 없습니다.</td></tr>';
            return;
        }

        reports.forEach(rep => {
            const tr = document.createElement('tr');
            
            // 심각도 배지
            let sevBadgeClass = 'blue';
            if (rep.severity === 'CRITICAL') sevBadgeClass = 'red';
            else if (rep.severity === 'HIGH') sevBadgeClass = 'amber';

            // 전송 상태 배지
            let delivBadgeClass = 'green';
            let delivText = '발송 완료 (SMTP)';
            if (rep.deliveryMethod === 'simulated_delivery') {
                delivBadgeClass = 'cyan';
                delivText = '발송 완료 (로컬 아카이브)';
            } else if (rep.deliveryMethod === 'smtp_failed_fallback') {
                delivBadgeClass = 'amber';
                delivText = '로컬 보관 (SMTP 오류 백업)';
            } else if (!rep.sent) {
                delivBadgeClass = 'red';
                delivText = '미발송 (비활성)';
            }

            // 장애 유형 한글명
            let typeName = rep.incidentType;
            if (rep.incidentType === 'LINK_DOWN') typeName = 'Link DOWN';
            else if (rep.incidentType === 'PORT_SECURITY_VIOLATION') typeName = '포트 보안 차단';
            else if (rep.incidentType === 'POE_FAULT') typeName = 'PoE+ 전원 이상';

            tr.innerHTML = `
                <td style="font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; font-weight: 600; color: var(--cyan-accent);">${SafeDOM.escape(rep.id)}</td>
                <td style="font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; color: var(--text-secondary);">${SafeDOM.escape(rep.timeKst || rep.timestamp)}</td>
                <td style="font-family: 'JetBrains Mono', monospace; font-weight: 600;">${SafeDOM.escape(rep.portName || '-')}</td>
                <td><span class="badge-tag ${sevBadgeClass}">${SafeDOM.escape(typeName)}</span></td>
                <td style="font-size: 0.78rem;">
                    <div><b style="color: var(--emerald-green);">${SafeDOM.escape(rep.clientIp || 'IP 미확인')}</b></div>
                    <div style="color: var(--text-muted); font-size: 0.72rem;">${SafeDOM.escape(rep.clientDevice || '-')}</div>
                </td>
                <td style="font-size: 0.78rem; color: var(--text-secondary);">${SafeDOM.escape(rep.recipient || '-')}</td>
                <td><span class="badge-tag ${delivBadgeClass}" style="font-size: 0.7rem;">${delivText}</span></td>
                <td style="text-align: center;">
                    <button type="button" class="btn btn-secondary btn-sm" onclick="App.openIncidentReportModal('${SafeDOM.escape(rep.id)}')">
                        상세 보고서 열람
                    </button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    },

    async openIncidentReportModal(reportId) {
        const modal = document.getElementById('incident-report-modal');
        const bodyEl = document.getElementById('modal-report-body');
        const titleEl = document.getElementById('modal-report-title');
        const timeEl = document.getElementById('modal-report-time');
        const sevEl = document.getElementById('modal-report-severity');
        const delivInfoEl = document.getElementById('modal-report-delivery-info');

        if (!modal || !bodyEl) return;

        try {
            const res = await API.request(`/api/switch/alerts/reports/${encodeURIComponent(reportId)}`);
            const rep = res.report;

            if (titleEl) titleEl.textContent = rep.title;
            if (timeEl) timeEl.textContent = `${rep.id} | 발생시각: ${rep.timeKst}`;
            if (sevEl) {
                sevEl.textContent = rep.severity;
                sevEl.className = `badge-tag ${rep.severity === 'CRITICAL' ? 'red' : (rep.severity === 'HIGH' ? 'amber' : 'blue')}`;
            }
            if (delivInfoEl && rep.deliveryResult) {
                delivInfoEl.textContent = `수신: ${rep.deliveryResult.recipient} (${rep.deliveryResult.message || rep.deliveryResult.method})`;
            }

            const client = rep.clientInfo || {};
            const timelineRows = (rep.timeline || []).map(item => `
                <tr style="border-bottom: 1px solid #1e293b;">
                    <td style="padding: 8px 12px; font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; color: var(--cyan-accent);">${SafeDOM.escape(item.time)}</td>
                    <td style="padding: 8px 12px; font-weight: 500; font-size: 0.8rem;">${SafeDOM.escape(item.event)}</td>
                    <td style="padding: 8px 12px; font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; color: #f87171; background: rgba(239, 68, 68, 0.05);">${SafeDOM.escape(item.syslog || item.ciscoSyslog || '-')}</td>
                </tr>
            `).join('');

            const remediationList = (rep.remediation || []).map(r => `
                <li style="margin-bottom: 6px; color: #cbd5e1;">${SafeDOM.escape(r)}</li>
            `).join('');

            bodyEl.innerHTML = `
                <!-- 상단 핵심 메트릭 카드 -->
                <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 18px;">
                    <div style="background: #090c13; border: 1px solid #1e293b; border-radius: 8px; padding: 12px;">
                        <div style="font-size: 0.7rem; color: var(--text-muted); margin-bottom: 4px;">발생 스위치 / 스택</div>
                        <div style="font-weight: 600; color: var(--text-primary); font-size: 0.85rem;">스택 #${rep.switchNum || 1} (${SafeDOM.escape(rep.hostname)})</div>
                    </div>
                    <div style="background: #090c13; border: 1px solid #1e293b; border-radius: 8px; padding: 12px;">
                        <div style="font-size: 0.7rem; color: var(--text-muted); margin-bottom: 4px;">장애 인터페이스 포트</div>
                        <div style="font-weight: 700; color: var(--cyan-accent); font-family: 'JetBrains Mono', monospace; font-size: 0.95rem;">${SafeDOM.escape(rep.portName)}</div>
                    </div>
                    <div style="background: #090c13; border: 1px solid #1e293b; border-radius: 8px; padding: 12px;">
                        <div style="font-size: 0.7rem; color: var(--text-muted); margin-bottom: 4px;">연결 단말 IP 주소</div>
                        <div style="font-weight: 700; color: var(--emerald-green); font-family: 'JetBrains Mono', monospace; font-size: 0.95rem;">${SafeDOM.escape(client.ipAddress || '미할당')}</div>
                    </div>
                    <div style="background: #090c13; border: 1px solid #1e293b; border-radius: 8px; padding: 12px;">
                        <div style="font-size: 0.7rem; color: var(--text-muted); margin-bottom: 4px;">단말 물리 MAC / 제조사</div>
                        <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; color: #cbd5e1;">${SafeDOM.escape(client.mac || '-')}</div>
                        <div style="font-size: 0.7rem; color: var(--text-muted);">${SafeDOM.escape(client.vendor || client.deviceName || '')}</div>
                    </div>
                </div>

                <!-- 1. 시간대별 상세 타임라인 (Chronological Timeline) -->
                <div style="margin-bottom: 20px;">
                    <h4 style="font-size: 0.9rem; color: var(--cyan-accent); margin-bottom: 8px; display: flex; align-items: center; gap: 6px;">
                        <span>⏱️</span> 시간대별 장애 진행 타임라인 및 Cisco IOS 시스로그
                    </h4>
                    <div style="background: #090c13; border: 1px solid #1e293b; border-radius: 8px; overflow: hidden;">
                        <table style="width: 100%; border-collapse: collapse; text-align: left;">
                            <thead>
                                <tr style="background: #0f172a; border-bottom: 1px solid #1e293b; font-size: 0.75rem; color: var(--text-muted);">
                                    <th style="padding: 8px 12px; width: 100px;">타임스탬프</th>
                                    <th style="padding: 8px 12px; width: 220px;">단계별 감지 상태</th>
                                    <th style="padding: 8px 12px;">Cisco Catalyst Syslog 메시지</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${timelineRows}
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- 2. 원인 분석 및 조치 권고사항 -->
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 20px;">
                    <div style="background: rgba(239, 68, 68, 0.05); border: 1px solid rgba(239, 68, 68, 0.25); border-radius: 8px; padding: 14px;">
                        <h4 style="font-size: 0.85rem; color: var(--rose-danger); margin-bottom: 8px;">🚨 장애 추정 원인 (Root Cause)</h4>
                        <p style="font-size: 0.8rem; color: #cbd5e1; line-height: 1.5; margin: 0;">${SafeDOM.escape(rep.rootCause)}</p>
                    </div>
                    <div style="background: rgba(16, 185, 129, 0.05); border: 1px solid rgba(16, 185, 129, 0.25); border-radius: 8px; padding: 14px;">
                        <h4 style="font-size: 0.85rem; color: var(--emerald-green); margin-bottom: 8px;">📋 현장 점검 및 복구 권고 절차</h4>
                        <ul style="font-size: 0.8rem; padding-left: 18px; margin: 0;">
                            ${remediationList}
                        </ul>
                    </div>
                </div>

                <!-- 3. 발송된 HTML 이메일 본문 원본 미리보기 토글 -->
                <details style="background: #090c13; border: 1px solid #1e293b; border-radius: 8px; padding: 12px;">
                    <summary style="cursor: pointer; font-size: 0.8rem; font-weight: 600; color: var(--text-secondary);">
                        📧 담당자에게 발송된 HTML 이메일 보고서 원본 보기
                    </summary>
                    <div style="margin-top: 12px; border-top: 1px solid #1e293b; padding-top: 12px; background: #0f172a; border-radius: 6px; padding: 12px; max-height: 380px; overflow-y: auto;">
                        <iframe srcdoc="${SafeDOM.escape(rep.htmlContent || '')}" style="width: 100%; height: 350px; border: none; background: #ffffff; border-radius: 4px;"></iframe>
                    </div>
                </details>
            `;

            modal.classList.add('active');
        } catch (err) {
            API.showToast('보고서 상세 조회 실패: ' + err.message, 'error');
        }
    },

    /* ============================================================ */
    /* 12. 다중 장비(스위치) 관리 및 선택/전환 로직                */
    /* ============================================================ */
    bindDeviceEvents() {
        // 상단 헤더 장비 선택 드롭다운 체인지 이벤트
        const headerSelector = document.getElementById('header-device-selector');
        if (headerSelector) {
            headerSelector.addEventListener('change', async (e) => {
                const targetId = e.target.value;
                if (targetId) await this.handleSwitchDevice(targetId);
            });
        }

        // [신규] 좌측 사이드바 장비 선택 드롭다운 체인지 이벤트
        const sidebarSelector = document.getElementById('sidebar-device-selector');
        if (sidebarSelector) {
            sidebarSelector.addEventListener('change', async (e) => {
                const targetId = e.target.value;
                if (targetId) await this.handleSwitchDevice(targetId);
            });
        }

        // 장비 추가 모달 열기 버튼들 (헤더, 사이드바, 배너, 탭 내부)
        const openAddBtn1 = document.getElementById('btn-open-device-add');
        const openAddBtn2 = document.getElementById('btn-device-tab-add');
        const openAddBtn3 = document.getElementById('btn-sidebar-add-device');
        const openAddBtn4 = document.getElementById('btn-banner-add-device');
        const addModal = document.getElementById('device-add-modal');

        [openAddBtn1, openAddBtn2, openAddBtn3, openAddBtn4].forEach(btn => {
            if (btn && addModal) {
                btn.onclick = () => addModal.classList.add('active');
            }
        });

        // 장비 관리 탭으로 이동 버튼들
        const openManageBtn1 = document.getElementById('btn-open-device-manage');
        const openManageBtn2 = document.getElementById('btn-sidebar-manage-devices');
        [openManageBtn1, openManageBtn2].forEach(btn => {
            if (btn) {
                btn.onclick = () => this.switchTab('devices');
            }
        });

        // 장비 목록 새로고침 버튼
        const refreshBtn = document.getElementById('btn-refresh-devices');
        if (refreshBtn) {
            refreshBtn.onclick = async () => {
                await this.loadAllData();
                this.renderDevicesTab();
            };
        }

        // 신규 장비 등록 폼 제출
        const addForm = document.getElementById('device-add-form');
        if (addForm) {
            addForm.onsubmit = async (e) => {
                e.preventDefault();
                await this.handleCreateDevice();
            };
        }

        // 장비 정보 수정 폼 제출
        const editForm = document.getElementById('device-edit-form');
        if (editForm) {
            editForm.onsubmit = async (e) => {
                e.preventDefault();
                await this.handleUpdateDevice();
            };
        }
    },

    renderAllDeviceSelectors() {
        const headerSelector = document.getElementById('header-device-selector');
        const sidebarSelector = document.getElementById('sidebar-device-selector');
        const bannerContainer = document.getElementById('dashboard-quick-device-bar');
        const sidebarCountBadge = document.getElementById('sidebar-device-count-badge');
        const navCountBadge = document.getElementById('nav-devices-count-badge');

        const deviceCount = (this.devices && this.devices.length) || 0;
        if (sidebarCountBadge) sidebarCountBadge.textContent = `${deviceCount}대 등록`;
        if (navCountBadge) navCountBadge.textContent = `${deviceCount}대`;

        // 1. 헤더 드롭다운 렌더링
        if (headerSelector) {
            SafeDOM.clearElement(headerSelector);
            if (!this.devices || this.devices.length === 0) {
                const opt = document.createElement('option');
                opt.value = '';
                opt.textContent = '등록된 장비 없음';
                headerSelector.appendChild(opt);
            } else {
                this.devices.forEach(dev => {
                    const opt = document.createElement('option');
                    opt.value = dev.id;
                    const isCur = dev.id === this.activeDeviceId;
                    opt.textContent = `${isCur ? '● ' : '○ '}${dev.name} (${dev.ipAddress})${isCur ? ' [활성]' : ''}`;
                    if (isCur) opt.selected = true;
                    headerSelector.appendChild(opt);
                });
                headerSelector.value = this.activeDeviceId;
            }
        }

        // 2. 사이드바 드롭다운 렌더링
        if (sidebarSelector) {
            SafeDOM.clearElement(sidebarSelector);
            if (!this.devices || this.devices.length === 0) {
                const opt = document.createElement('option');
                opt.value = '';
                opt.textContent = '등록된 장비 없음';
                sidebarSelector.appendChild(opt);
            } else {
                this.devices.forEach(dev => {
                    const opt = document.createElement('option');
                    opt.value = dev.id;
                    const isCur = dev.id === this.activeDeviceId;
                    opt.textContent = `${isCur ? '▶ ' : '  '}${dev.name} (${dev.ipAddress})`;
                    if (isCur) opt.selected = true;
                    sidebarSelector.appendChild(opt);
                });
                sidebarSelector.value = this.activeDeviceId;
            }
        }

        // 3. 메인 배너 칩 버튼 목록 렌더링
        if (bannerContainer) {
            SafeDOM.clearElement(bannerContainer);
            if (this.devices && this.devices.length > 0) {
                this.devices.forEach(dev => {
                    const isCur = dev.id === this.activeDeviceId;
                    const chip = document.createElement('button');
                    chip.type = 'button';
                    chip.className = `quick-device-chip ${isCur ? 'active' : ''}`;
                    chip.title = `클릭 시 [${dev.name} (${dev.ipAddress})] 장비로 즉시 전환`;
                    chip.innerHTML = `
                        <span class="status-led-dot ${isCur ? 'green' : ''}" style="width: 8px; height: 8px; ${isCur ? 'box-shadow: 0 0 8px rgba(16,185,129,0.8);' : 'background: #64748b;'}"></span>
                        <span class="chip-name">${SafeDOM.escape(dev.name)}</span>
                        <span class="chip-ip">${SafeDOM.escape(dev.ipAddress)}</span>
                        <span class="chip-ports">${dev.portCount || 28}P</span>
                        ${isCur ? '<span style="color: var(--cyan-accent); font-size: 0.7rem; font-weight: 700; margin-left: 2px;">[현재 관리 중]</span>' : ''}
                    `;
                    chip.onclick = () => this.handleSwitchDevice(dev.id);
                    bannerContainer.appendChild(chip);
                });
            }
        }
    },

    renderHeaderDeviceSelector() {
        this.renderAllDeviceSelectors();
    },

    async handleSwitchDevice(deviceId) {
        if (!deviceId || deviceId === this.activeDeviceId) return;

        try {
            API.showToast('장비 설정 전환 중...', 'info');
            const res = await API.request('/api/devices/active', {
                method: 'POST',
                body: JSON.stringify({ deviceId })
            });

            this.activeDeviceId = res.activeDeviceId;
            API.showToast(res.message, 'success');

            // 장비가 변경되었으므로 전체 UI 상태 즉시 재로드
            await this.loadAllData();

            // 현재 탭 렌더링 갱신
            if (this.currentTab === 'devices') {
                this.renderDevicesTab();
            } else if (this.currentTab === 'ports') {
                this.renderPortsTable();
            } else if (this.currentTab === 'dashboard') {
                this.renderDashboard();
            } else if (this.currentTab === 'mac') {
                this.renderMacTab();
            }
        } catch (err) {
            API.showToast('장비 전환 실패: ' + err.message, 'error');
            this.renderHeaderDeviceSelector();
        }
    },

    async handleCreateDevice() {
        const name = document.getElementById('add-device-name').value.trim();
        const ipAddress = document.getElementById('add-device-ip').value.trim();
        const model = document.getElementById('add-device-model').value.trim();
        const templateType = document.getElementById('add-device-template').value;
        const location = document.getElementById('add-device-location').value.trim();
        const description = document.getElementById('add-device-desc').value.trim();
        const makeActive = document.getElementById('add-device-active').checked;

        if (!name || !ipAddress) {
            API.showToast('장비명과 IP 주소를 입력해주세요.', 'error');
            return;
        }

        try {
            API.showToast('새 장비 생성 및 설정 적용 중...', 'info');
            const res = await API.request('/api/devices', {
                method: 'POST',
                body: JSON.stringify({
                    name,
                    ipAddress,
                    model: model || 'Cisco Catalyst 2960-S PoE+',
                    templateType,
                    location,
                    description,
                    makeActive
                })
            });

            API.showToast(res.message, 'success');
            document.getElementById('device-add-modal').classList.remove('active');
            document.getElementById('device-add-form').reset();

            await this.loadAllData();
            if (this.currentTab === 'devices') {
                this.renderDevicesTab();
            }
        } catch (err) {
            API.showToast('장비 추가 실패: ' + err.message, 'error');
        }
    },

    renderDevicesTab() {
        const tbody = document.getElementById('devices-table-tbody');
        const totalEl = document.getElementById('metric-devices-total');
        const activeNameEl = document.getElementById('metric-devices-active-name');
        const activeIpEl = document.getElementById('metric-devices-active-ip');
        const totalPortsEl = document.getElementById('metric-devices-total-ports');
        const powerStatEl = document.getElementById('metric-devices-power-stat');
        const powerSubEl = document.getElementById('metric-devices-power-sub');
        const badgeCount = document.getElementById('devices-badge-count');

        const activeDev = this.devices.find(d => d.id === this.activeDeviceId) || this.devices[0];
        const outageCount = (this.devices || []).filter(d => d.powerStatus === 'power_off').length;
        const normalCount = (this.devices || []).length - outageCount;

        if (totalEl) totalEl.textContent = this.devices.length;
        if (activeNameEl) activeNameEl.textContent = activeDev ? activeDev.name : '-';
        if (activeIpEl) activeIpEl.textContent = activeDev ? `${activeDev.ipAddress} (${activeDev.model || ''})` : '-';
        if (totalPortsEl) {
            const sumPorts = this.devices.reduce((acc, d) => acc + (d.portCount || 0), 0);
            totalPortsEl.textContent = `${sumPorts} Ports`;
        }
        if (powerStatEl) {
            powerStatEl.textContent = outageCount > 0 ? `${outageCount}대 꺼짐` : '전체 정상';
            powerStatEl.style.color = outageCount > 0 ? '#ef4444' : '#10b981';
        }
        if (powerSubEl) {
            powerSubEl.textContent = outageCount > 0 ? `${normalCount}대 정상 가동 중` : '0대 전원 장애';
        }
        if (badgeCount) badgeCount.textContent = `${this.devices.length}대 장비 등록됨`;

        if (!tbody) return;
        SafeDOM.clearElement(tbody);

        if (!this.devices || this.devices.length === 0) {
            tbody.innerHTML = '<tr><td colspan="9" style="text-align: center; color: var(--text-muted); padding: 24px;">등록된 네트워크 장비가 없습니다.</td></tr>';
            return;
        }

        this.devices.forEach((dev) => {
            const tr = document.createElement('tr');
            const isCur = dev.id === this.activeDeviceId;
            const isPowerOff = dev.powerStatus === 'power_off';

            if (isCur) {
                tr.style.backgroundColor = 'rgba(0, 242, 254, 0.05)';
            }

            const statusDot = isCur ? `
                <div style="display: flex; align-items: center; gap: 6px;">
                    <span class="status-led-dot green" style="width: 10px; height: 10px; box-shadow: 0 0 8px rgba(16,185,129,0.8);"></span>
                    <span style="font-weight: 700; color: var(--emerald-green); font-size: 0.78rem;">활성 관리 중</span>
                </div>
            ` : `
                <div style="display: flex; align-items: center; gap: 6px;">
                    <span class="status-led-dot" style="width: 10px; height: 10px; background: #64748b;"></span>
                    <span style="color: var(--text-muted); font-size: 0.78rem;">대기 (Standby)</span>
                </div>
            `;

            const powerBadge = isPowerOff ? `
                <span class="power-status-pill off">⚡ 전원 꺼짐</span>
            ` : `
                <span class="power-status-pill on">● 정상 통전</span>
            `;

            const powerBtn = isPowerOff ? `
                <button type="button" class="btn btn-success btn-xs" style="font-weight: 700;" onclick="App.handlePowerRestore('${SafeDOM.escape(dev.id)}')">전원 복구</button>
            ` : `
                <button type="button" class="btn btn-secondary btn-xs" style="color: #ef4444; border-color: rgba(239,68,68,0.4);" onclick="App.handlePowerSimulatePrompt('${SafeDOM.escape(dev.id)}')">전원 끄기</button>
            `;

            const actionButtons = isCur ? `
                ${powerBtn}
                <span class="badge-tag green" style="padding: 4px 8px; font-weight: 700; margin-left: 6px;">현재 활성</span>
                <button type="button" class="btn btn-secondary btn-xs" style="margin-left: 6px;" onclick="App.openEditDeviceModal('${SafeDOM.escape(dev.id)}')">수정</button>
            ` : `
                ${powerBtn}
                <button type="button" class="btn btn-primary btn-xs" style="margin-left: 6px;" onclick="App.handleSwitchDevice('${SafeDOM.escape(dev.id)}')">
                    ⚡ 전환
                </button>
                <button type="button" class="btn btn-secondary btn-xs" style="margin-left: 6px;" onclick="App.openEditDeviceModal('${SafeDOM.escape(dev.id)}')">수정</button>
                <button type="button" class="btn btn-secondary btn-xs" style="margin-left: 6px; color: var(--rose-danger);" onclick="App.handleDeleteDevice('${SafeDOM.escape(dev.id)}')">삭제</button>
            `;

            tr.innerHTML = `
                <td>${statusDot}</td>
                <td>${powerBadge}</td>
                <td>
                    <div style="font-weight: 700; color: ${isCur ? 'var(--cyan-accent)' : 'var(--text-primary)'}; font-size: 0.9rem;">
                        ${SafeDOM.escape(dev.name)}
                    </div>
                    <div style="font-size: 0.72rem; color: var(--text-muted); font-family: 'JetBrains Mono', monospace;">${SafeDOM.escape(dev.id)}</div>
                </td>
                <td style="font-family: 'JetBrains Mono', monospace; font-weight: 600; color: var(--emerald-green);">
                    ${SafeDOM.escape(dev.ipAddress)}
                </td>
                <td style="font-size: 0.8rem; color: var(--text-secondary);">
                    ${SafeDOM.escape(dev.model || 'Cisco Catalyst 2960-S')}
                </td>
                <td style="font-family: 'JetBrains Mono', monospace; font-weight: 600;">
                    ${dev.portCount || 28} Ports
                </td>
                <td style="font-size: 0.78rem; color: var(--text-muted);">
                    <div>${SafeDOM.escape(dev.location || '-')}</div>
                    <div style="font-size: 0.72rem; color: #64748b;">${SafeDOM.escape(dev.description || '')}</div>
                </td>
                <td style="font-size: 0.75rem; color: var(--text-muted); font-family: 'JetBrains Mono', monospace;">
                    ${dev.lastSynced ? SafeDOM.escape(new Date(dev.lastSynced).toLocaleString('ko-KR')) : '-'}
                </td>
                <td style="text-align: center; white-space: nowrap;">
                    ${actionButtons}
                </td>
            `;

            tbody.appendChild(tr);
        });
    },

    bindPowerEvents() {
        const btnNotif = document.getElementById('btn-header-notification');
        const notifDropdown = document.getElementById('notification-dropdown');
        if (btnNotif && notifDropdown) {
            btnNotif.addEventListener('click', (e) => {
                e.stopPropagation();
                const isShown = notifDropdown.style.display !== 'none';
                notifDropdown.style.display = isShown ? 'none' : 'block';
            });
            document.addEventListener('click', (e) => {
                if (!e.target.closest('.notification-center-wrap')) {
                    notifDropdown.style.display = 'none';
                }
            });
        }

        const btnBannerDismiss = document.getElementById('btn-power-banner-dismiss');
        if (btnBannerDismiss) {
            btnBannerDismiss.addEventListener('click', () => {
                const banner = document.getElementById('global-power-outage-banner');
                if (banner) banner.style.display = 'none';
            });
        }

        const btnBannerRestore = document.getElementById('btn-power-banner-restore');
        if (btnBannerRestore) {
            btnBannerRestore.addEventListener('click', async () => {
                const targetAlert = (this.powerAlerts && this.powerAlerts.length > 0) ? this.powerAlerts[0] : null;
                const devId = targetAlert ? targetAlert.deviceId : this.activeDeviceId;
                await this.handlePowerRestore(devId);
            });
        }

        const btnBannerView = document.getElementById('btn-power-banner-view');
        if (btnBannerView) {
            btnBannerView.addEventListener('click', () => {
                const targetAlert = (this.powerAlerts && this.powerAlerts.length > 0) ? this.powerAlerts[0] : null;
                if (targetAlert && targetAlert.reportId) {
                    this.openIncidentReportModal(targetAlert.reportId);
                } else {
                    this.switchTab('alerts');
                }
            });
        }
    },

    renderPowerAlerts(alerts = []) {
        const notifBadge = document.getElementById('header-notification-badge');
        const dropdownBadge = document.getElementById('notif-dropdown-badge');
        const dropdownList = document.getElementById('notification-dropdown-list');
        const banner = document.getElementById('global-power-outage-banner');
        const bannerTitle = document.getElementById('power-banner-title-text');
        const bannerDesc = document.getElementById('power-banner-desc-text');

        const activeCount = alerts.length;

        // 헤더 벨 배지 & 드롭다운 헤더 갱신
        if (notifBadge) {
            if (activeCount > 0) {
                notifBadge.textContent = activeCount;
                notifBadge.style.display = 'inline-block';
            } else {
                notifBadge.style.display = 'none';
            }
        }
        if (dropdownBadge) {
            dropdownBadge.textContent = `${activeCount}건`;
            dropdownBadge.className = `badge-tag ${activeCount > 0 ? 'red' : 'green'}`;
        }

        // 드롭다운 목록 렌더링
        if (dropdownList) {
            if (activeCount === 0) {
                dropdownList.innerHTML = '<div style="text-align: center; color: var(--text-muted); padding: 18px; font-size: 0.78rem;">감지된 전원 이상 또는 장애가 없습니다. (전 장비 정상 통전 중)</div>';
            } else {
                dropdownList.innerHTML = alerts.map(a => {
                    const isPoe = a.type === 'poe_power_off';
                    const iconType = isPoe ? 'amber' : 'red';
                    const iconSvg = isPoe 
                        ? `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"></path></svg>`
                        : `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>`;
                    
                    const titleText = isPoe 
                        ? `[PoE 전원차단] ${SafeDOM.escape(a.deviceName || a.deviceId)} (${SafeDOM.escape(a.portId || '')})`
                        : `[전원 꺼짐] ${SafeDOM.escape(a.deviceName || a.deviceId)} (${SafeDOM.escape(a.ipAddress || '')})`;

                    return `
                        <div class="notif-item unread-critical" onclick="App.openIncidentReportModal('${SafeDOM.escape(a.reportId)}')">
                            <div class="notif-item-icon ${iconType}">${iconSvg}</div>
                            <div class="notif-item-content">
                                <div class="notif-item-title">
                                    <span>${titleText}</span>
                                    <span class="badge-tag red" style="font-size: 0.65rem;">정전/차단</span>
                                </div>
                                <div class="notif-item-desc">${SafeDOM.escape(a.reason || '전원 공급 중단')} (보고서: ${SafeDOM.escape(a.reportId)})</div>
                                <div class="notif-item-time" style="display: flex; justify-content: space-between; align-items: center; margin-top: 6px;">
                                    <span>${SafeDOM.escape(a.timeKst || '')}</span>
                                    <div style="display: flex; gap: 4px;">
                                        <button type="button" class="btn btn-xs btn-primary" onclick="event.stopPropagation(); App.openIncidentReportModal('${SafeDOM.escape(a.reportId)}')">보고서</button>
                                        <button type="button" class="btn btn-xs btn-success" onclick="event.stopPropagation(); App.handlePowerRestore('${SafeDOM.escape(a.deviceId)}')">복구</button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    `;
                }).join('');
            }
        }

        // 상단 긴급 배너 표시 여부
        if (banner) {
            if (activeCount > 0) {
                const primary = alerts[0];
                const isPoe = primary.type === 'poe_power_off';
                if (bannerTitle) {
                    bannerTitle.textContent = isPoe
                        ? `[PoE 수전 단말 전원 차단] ${primary.deviceName || primary.deviceId} 포트 ${primary.portId || ''} 전원 소실`
                        : `[네트워크 장비 전원 꺼짐] ${primary.deviceName || primary.deviceId} (${primary.ipAddress || ''}) 정전/전원 오프 감지`;
                }
                if (bannerDesc) {
                    bannerDesc.textContent = `원인: ${primary.reason || '전원 공급 중단'} | 담당자(netadmin@company.com) 이메일 보고서 발송 완료 (보고서: ${primary.reportId})`;
                }
                banner.style.display = 'block';
            } else {
                banner.style.display = 'none';
            }
        }
    },

    renderFleetPowerMonitor() {
        const grid = document.getElementById('dashboard-fleet-power-grid');
        const overallLed = document.getElementById('fleet-power-overall-led');
        const summaryBadge = document.getElementById('fleet-power-summary-badge');
        if (!grid) return;

        const outageDevs = (this.devices || []).filter(d => d.powerStatus === 'power_off');
        const hasOutage = outageDevs.length > 0 || (this.powerAlerts && this.powerAlerts.length > 0);

        if (overallLed) {
            overallLed.className = `status-led-dot ${hasOutage ? 'red' : 'green'}`;
        }
        if (summaryBadge) {
            if (hasOutage) {
                summaryBadge.className = 'badge-tag red';
                summaryBadge.textContent = `${outageDevs.length}대 전원 꺼짐 감지됨`;
            } else {
                summaryBadge.className = 'badge-tag green';
                summaryBadge.textContent = `모든 장비 (${this.devices.length}대) 정상 통전 중`;
            }
        }

        grid.innerHTML = (this.devices || []).map(dev => {
            const isPowerOff = dev.powerStatus === 'power_off';
            const isCur = dev.id === this.activeDeviceId;
            const statusClass = isPowerOff ? 'power-outage' : 'power-normal';

            const powerPill = isPowerOff
                ? `<span class="power-status-pill off">⚡ 전원 꺼짐 (정전)</span>`
                : `<span class="power-status-pill on">● 정상 통전 중</span>`;

            const actionBtn = isPowerOff
                ? `<button type="button" class="btn btn-xs btn-success" style="font-weight: 700;" onclick="App.handlePowerRestore('${SafeDOM.escape(dev.id)}')">전원 재인가 (복구)</button>`
                : `<button type="button" class="btn btn-xs btn-secondary" style="color: #ef4444; border-color: rgba(239, 68, 68, 0.4);" onclick="App.handlePowerSimulatePrompt('${SafeDOM.escape(dev.id)}')">전원 차단 테스트</button>`;

            return `
                <div class="fleet-power-card ${statusClass}">
                    <div class="fleet-power-card-header">
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <span class="status-led-dot ${isPowerOff ? 'red' : 'green'}"></span>
                            <span class="fleet-power-hostname">${SafeDOM.escape(dev.name)}</span>
                            ${isCur ? '<span class="badge-tag cyan" style="font-size: 0.65rem;">현재 활성</span>' : ''}
                        </div>
                        ${powerPill}
                    </div>
                    <div class="fleet-power-ip">${SafeDOM.escape(dev.ipAddress)} (${dev.portCount || 28} 포트)</div>
                    <div class="fleet-power-meta">
                        <div>모델: ${SafeDOM.escape(dev.model || 'Catalyst 2960-S')}</div>
                        <div>위치: ${SafeDOM.escape(dev.location || '-')}</div>
                    </div>
                    <div class="fleet-power-actions">
                        ${actionBtn}
                        <button type="button" class="btn btn-xs btn-secondary" onclick="App.handleSwitchDevice('${SafeDOM.escape(dev.id)}')">장비 관리</button>
                    </div>
                </div>
            `;
        }).join('');
    },

    async handlePowerSimulatePrompt(deviceId) {
        const targetDev = this.devices.find(d => d.id === deviceId);
        const name = targetDev ? targetDev.name : deviceId;
        const confirmMsg = `[경고] '${name}' 장비의 전원을 차단(OFF) 상태로 전환하시겠습니까?\n\n- 즉시 '전원 꺼짐' 장애가 감지됩니다.\n- 담당자 이메일(netadmin@company.com)로 상세 원인 및 조치 보고서가 자동 발송됩니다.\n- 상단 배너 및 알림 센터에 긴급 경보가 표시됩니다.`;
        if (!confirm(confirmMsg)) return;

        const reason = prompt('전원 차단 사유를 입력하세요 (선택):', '랙 전원 분배기(PDU) 차단기 트립 / AC 주전원 소실');
        if (reason === null) return;

        await this.handlePowerSimulate(deviceId, 'switch_power_off', null, reason || '장비 전원 소실');
    },

    async handlePowerSimulate(deviceId, type = 'switch_power_off', portId = null, reason = '') {
        try {
            API.showToast('전원 이상 시뮬레이션 및 담당자 이메일 발송 중...', 'info');
            const res = await API.request('/api/switch/power/simulate', {
                method: 'POST',
                body: JSON.stringify({ deviceId, type, portId, reason })
            });

            API.showToast(res.message, 'success');
            await this.loadAllData();
            if (this.currentTab === 'devices') this.renderDevicesTab();
            if (this.currentTab === 'dashboard') this.renderDashboard();
            if (this.currentTab === 'alerts') this.renderAlertsTab();

            if (res.report && res.report.id) {
                this.openIncidentReportModal(res.report.id);
            }
        } catch (err) {
            API.showToast('전원 시뮬레이션 실패: ' + err.message, 'error');
        }
    },

    async handlePowerRestore(deviceId) {
        try {
            API.showToast('장비 전원 재인가 및 복구 보고서 발송 중...', 'info');
            const res = await API.request('/api/switch/power/restore', {
                method: 'POST',
                body: JSON.stringify({ deviceId })
            });

            API.showToast(res.message, 'success');
            await this.loadAllData();
            if (this.currentTab === 'devices') this.renderDevicesTab();
            if (this.currentTab === 'dashboard') this.renderDashboard();
            if (this.currentTab === 'alerts') this.renderAlertsTab();
        } catch (err) {
            API.showToast('전원 복구 실패: ' + err.message, 'error');
        }
    },

    openEditDeviceModal(deviceId) {
        const dev = this.devices.find(d => d.id === deviceId);
        if (!dev) return;

        document.getElementById('edit-device-id').value = dev.id;
        document.getElementById('edit-device-name').value = dev.name;
        document.getElementById('edit-device-ip').value = dev.ipAddress;
        document.getElementById('edit-device-model').value = dev.model || '';
        document.getElementById('edit-device-location').value = dev.location || '';
        document.getElementById('edit-device-desc').value = dev.description || '';

        document.getElementById('device-edit-modal').classList.add('active');
    },

    async handleUpdateDevice() {
        const deviceId = document.getElementById('edit-device-id').value;
        const name = document.getElementById('edit-device-name').value.trim();
        const ipAddress = document.getElementById('edit-device-ip').value.trim();
        const model = document.getElementById('edit-device-model').value.trim();
        const location = document.getElementById('edit-device-location').value.trim();
        const description = document.getElementById('edit-device-desc').value.trim();

        try {
            const res = await API.request(`/api/devices/${encodeURIComponent(deviceId)}`, {
                method: 'PUT',
                body: JSON.stringify({ name, ipAddress, model, location, description })
            });

            API.showToast(res.message, 'success');
            document.getElementById('device-edit-modal').classList.remove('active');

            await this.loadAllData();
            if (this.currentTab === 'devices') {
                this.renderDevicesTab();
            }
        } catch (err) {
            API.showToast('장비 정보 수정 실패: ' + err.message, 'error');
        }
    },

    async handleDeleteDevice(deviceId) {
        const dev = this.devices.find(d => d.id === deviceId);
        const name = dev ? dev.name : deviceId;

        if (!confirm(`정말로 장비 [${name}]를 목록에서 삭제하시겠습니까?`)) {
            return;
        }

        try {
            const res = await API.request(`/api/devices/${encodeURIComponent(deviceId)}`, {
                method: 'DELETE'
            });

            API.showToast(res.message, 'success');
            await this.loadAllData();
            if (this.currentTab === 'devices') {
                this.renderDevicesTab();
            }
        } catch (err) {
            API.showToast('장비 삭제 실패: ' + err.message, 'error');
        }
    }
};

window.App = App;
