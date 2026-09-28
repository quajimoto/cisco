// public/js/switchUI.js
// Cisco Catalyst 2960-S Series 단일 및 4단 스택(최대 184~208포트) 전면 패널 렌더링 모듈
// 스택 멤버별 탭 전환, 48/24포트 PoE+ RJ45 뱅크, 4포트 SFP+ 업링크 뱅크 완벽 지원

const SwitchUI = {
    selectedPortId: null,
    currentSwitchNum: 1,
    portsData: [],
    onPortSelectCallback: null,

    /**
     * 포트 데이터 정규화 (switchNum, portNum 보정)
     */
    normalizePortData(port) {
        if (!port) return null;
        const p = { ...port };
        const m = (p.name || '').match(/^(?:Gi|Te|Fa)(\d+)\/\d+\/(\d+)$/i);
        if (!p.switchNum || !p.portNum) {
            if (m) {
                p.switchNum = parseInt(m[1], 10);
                p.portNum = parseInt(m[2], 10);
            } else {
                p.switchNum = p.switchNum || 1;
                p.portNum = p.portNum || p.id || 1;
            }
        }
        p.adminState = p.adminState || (p.admin === false ? 'down' : 'up');
        p.linkState = p.linkState || p.status || 'down';
        p.status = p.status || p.linkState;
        p.admin = p.admin !== undefined ? p.admin : (p.adminState === 'up');
        p.mode = p.mode || 'access';
        p.pvid = p.pvid !== undefined ? p.pvid : 1;
        p.speed = p.speed || 'auto';
        p.duplex = p.duplex || 'auto';
        p.type = p.type || (p.speed === '10G' ? 'SFP+-10G' : 'RJ45-1G-PoE+');
        return p;
    },

    /**
     * 포트 패널 초기화 및 렌더링 (스택 스위치 탭 자동 생성)
     */
    renderFaceplate(containerId, rawPorts, onPortSelect) {
        if (!rawPorts || !Array.isArray(rawPorts)) return;

        this.portsData = rawPorts.map(p => this.normalizePortData(p));
        this.onPortSelectCallback = onPortSelect;
        const container = document.getElementById(containerId);
        if (!container) return;

        // 1. 존재하는 모든 스택 멤버 번호 추출 (예: [1, 2, 3, 4])
        const switchNumSet = new Set(this.portsData.map(p => p.switchNum || 1));
        const switchNumbers = Array.from(switchNumSet).sort((a, b) => a - b);

        // 현재 선택된 스위치가 유효하지 않으면 첫 번째 스위치 선택
        if (!switchNumbers.includes(this.currentSwitchNum)) {
            this.currentSwitchNum = switchNumbers[0] || 1;
        }

        // 2. 스택 선택기 탭바 렌더링
        this.renderStackTabs(switchNumbers);

        // 3. 섀시 상단 모델 및 상태 표시줄 업데이트
        this.updateChassisHeader(switchNumbers);

        // 4. 현재 선택된 스위치의 포트 필터링
        const currentPorts = this.portsData.filter(p => (p.switchNum || 1) === this.currentSwitchNum);

        SafeDOM.clearElement(container);

        // 48포트 모델 vs 24포트 모델 판별
        const maxPortNum = currentPorts.reduce((max, p) => Math.max(max, p.portNum || 0), 0);
        const is48PortModel = maxPortNum >= 40 || currentPorts.length >= 40;
        const rj45Count = is48PortModel ? 48 : 24;
        const rj45Columns = rj45Count / 2; // 24열(48P) 또는 12열(24P)

        // 5. RJ45 포트 뱅크 렌더링
        const rj45Bank = SafeDOM.createElement('div', {
            className: `rj45-bank ${is48PortModel ? 'bank-48p' : 'bank-24p'}`
        });

        for (let col = 0; col < rj45Columns; col++) {
            const topPortNum = col * 2 + 1;
            const bottomPortNum = col * 2 + 2;

            const topPort = currentPorts.find(p => p.portNum === topPortNum && !p.type.includes('SFP'));
            const bottomPort = currentPorts.find(p => p.portNum === bottomPortNum && !p.type.includes('SFP'));

            const colEl = SafeDOM.createElement('div', {
                className: 'port-pair-column',
                children: [
                    this.createPortSocket(topPort, false),
                    this.createPortSocket(bottomPort, false)
                ]
            });
            rj45Bank.appendChild(colEl);
        }
        container.appendChild(rj45Bank);

        // 6. SFP 구분선
        const divider = SafeDOM.createElement('div', { className: 'sfp-bank-divider' });
        container.appendChild(divider);

        // 7. SFP / SFP+ 업링크 포트 뱅크 (4개 포트: 49~52 또는 25~28)
        const sfpPorts = currentPorts
            .filter(p => p.type.includes('SFP') || p.portNum > rj45Count)
            .sort((a, b) => a.portNum - b.portNum);

        const sfpBank = SafeDOM.createElement('div', { className: 'sfp-bank' });
        const sfpColumns = Math.max(2, Math.ceil(sfpPorts.length / 2));

        for (let col = 0; col < sfpColumns; col++) {
            const topPort = sfpPorts[col * 2] || null;
            const bottomPort = sfpPorts[col * 2 + 1] || null;

            const colEl = SafeDOM.createElement('div', {
                className: 'port-pair-column',
                children: [
                    this.createPortSocket(topPort, true),
                    this.createPortSocket(bottomPort, true)
                ]
            });
            sfpBank.appendChild(colEl);
        }
        container.appendChild(sfpBank);
    },

    /**
     * 스택 스위치 유닛 탭바 렌더링
     */
    renderStackTabs(switchNumbers) {
        // 기존에 중복 생성된 바가 있다면 하나만 남기고 정리
        const allBars = document.querySelectorAll('.stack-selector-bar, #stack-selector-bar');
        if (allBars.length > 1) {
            for (let i = 1; i < allBars.length; i++) {
                allBars[i].remove();
            }
        }

        let stackBar = document.getElementById('stack-selector-bar');
        if (!stackBar) {
            const chassis = document.querySelector('.switch-rack-chassis');
            if (!chassis) return;
            stackBar = document.createElement('div');
            stackBar.id = 'stack-selector-bar';
            stackBar.className = 'stack-selector-bar';
            chassis.parentNode.insertBefore(stackBar, chassis);
        }

        // 단일 스위치인 경우 탭 숨김
        if (!switchNumbers || switchNumbers.length <= 1) {
            stackBar.style.display = 'none';
            return;
        }

        stackBar.style.display = 'flex';
        SafeDOM.clearElement(stackBar);

        const titleLabel = SafeDOM.createElement('div', {
            className: 'stack-bar-title',
            children: [
                SafeDOM.createElement('span', { className: 'stack-icon', text: '☷' }),
                SafeDOM.createElement('strong', { text: `Catalyst 2960-S Stack (${switchNumbers.length}대 구성):` })
            ]
        });
        stackBar.appendChild(titleLabel);

        const tabsWrap = SafeDOM.createElement('div', { className: 'stack-tabs-wrap' });

        switchNumbers.forEach(sNum => {
            const memberPorts = this.portsData.filter(p => (p.switchNum || 1) === sNum);
            const upCount = memberPorts.filter(p => p.linkState === 'up').length;
            const poeUsed = memberPorts.reduce((sum, p) => sum + (p.poe && p.poe.status === 'on' ? (p.poe.powerWatts || 0) : 0), 0);
            const is48P = memberPorts.length > 30;

            const isSelected = this.currentSwitchNum === sNum;
            const btn = SafeDOM.createElement('button', {
                className: `stack-tab-btn ${isSelected ? 'active' : ''}`,
                attrs: { 'data-switch-num': sNum },
                events: {
                    click: () => {
                        this.currentSwitchNum = sNum;
                        this.renderFaceplate('switch-faceplate-container', this.portsData, this.onPortSelectCallback);
                        // 포트 테이블 탭에도 동기화 이벤트 전달
                        if (window.App && typeof window.App.onStackSwitchChange === 'function') {
                            window.App.onStackSwitchChange(sNum);
                        }
                    }
                },
                children: [
                    SafeDOM.createElement('span', { className: 'stack-unit-badge', text: `#${sNum}` }),
                    SafeDOM.createElement('span', { className: 'stack-unit-name', text: `스위치 ${sNum} (${is48P ? '52P' : '28P'} PoE+)` }),
                    SafeDOM.createElement('span', {
                        className: `badge-tag ${upCount > 0 ? 'green' : 'gray'}`,
                        text: `UP ${upCount}/${memberPorts.length}`
                    }),
                    SafeDOM.createElement('span', {
                        className: 'stack-poe-stat',
                        text: `${poeUsed.toFixed(1)}W`,
                        attrs: { style: poeUsed > 0 ? 'color: var(--amber-warning);' : 'color: var(--text-muted);' }
                    })
                ]
            });
            tabsWrap.appendChild(btn);
        });

        stackBar.appendChild(tabsWrap);
    },

    /**
     * 섀시 헤더 정보 업데이트 (스택 멤버 번호 표기)
     */
    updateChassisHeader(switchNumbers) {
        const modelEl = document.querySelector('.chassis-model');
        if (modelEl) {
            const total = switchNumbers.length;
            if (total > 1) {
                modelEl.textContent = `Catalyst 2960-S Stack (Unit #${this.currentSwitchNum} of ${total})`;
            } else {
                modelEl.textContent = `WS-C2960S-48FPS-L PoE+ (Standalone)`;
            }
        }
    },

    /**
     * 개별 포트 소켓 UI 생성
     */
    createPortSocket(port, isSfp = false) {
        if (!port) {
            return SafeDOM.createElement('div', { className: 'port-socket empty' });
        }

        const isLinkUp = port.linkState === 'up';
        const isAdminDown = port.adminState === 'down';
        const isPoeActive = port.poe && port.poe.status === 'on';

        // 1. 링크 LED 색상
        let linkLedClass = 'port-led';
        if (isAdminDown) {
            linkLedClass += ' admin-disabled';
        } else if (isLinkUp) {
            if (port.speed === '10G') {
                linkLedClass += ' link-10g';
            } else if (port.speed === '1G') {
                linkLedClass += ' link-1g';
            } else {
                linkLedClass += ' link-100m';
            }
        }

        // 2. 액티비티 / PoE LED
        let actLedClass = 'port-led';
        if (isPoeActive) {
            actLedClass += ' link-poe-active'; // PoE 전력 공급 중 (Amber Glow)
        } else if (isLinkUp) {
            actLedClass += ' link-1g act-blink'; // 트래픽 깜빡임
        }

        // 3. 툴팁 상세 정보
        const clientLine = port.connectedClient 
            ? `연결 클라이언트: ${port.connectedClient.ipAddress || 'IP 미할당'} [${port.connectedClient.mac}] (${port.connectedClient.deviceName || port.connectedClient.vendor})`
            : (port.clientCount > 1 ? `연결 클라이언트: ${port.clientCount}대 감지 (트렁크/백본)` : `연결 클라이언트: (미연결)`);

        const tooltip = [
            `인터페이스: ${port.name} (${port.type || 'RJ45-1G'})`,
            `스택 유닛: 스위치 #${port.switchNum || 1}`,
            `Admin: ${(port.adminState || 'up').toUpperCase()} / Link: ${(port.linkState || 'down').toUpperCase()}`,
            `속도/듀플렉스: ${port.speed || 'auto'} / ${port.duplex || 'auto'}`,
            `VLAN: ${port.pvid || 1} (${(port.mode || 'access').toUpperCase()})`,
            `PoE+: ${isPoeActive ? `ON (${port.poe.powerWatts}W - ${port.poe.device || 'PD'})` : (port.poe ? (port.poe.mode || 'auto').toUpperCase() : 'N/A')}`,
            clientLine,
            `설명: ${port.description || '(없음)'}`
        ].join('\n');

        const socketEl = SafeDOM.createElement('div', {
            className: `port-socket ${isSfp ? 'sfp' : ''} ${isAdminDown ? 'admin-down' : ''} ${isLinkUp ? 'link-up' : ''} ${this.selectedPortId === port.id ? 'selected' : ''}`,
            attrs: {
                'data-port-id': port.id,
                'data-port-num': port.portNum,
                'data-switch-num': port.switchNum || 1,
                title: tooltip
            },
            events: {
                click: () => {
                    this.selectPort(port.id);
                    if (this.onPortSelectCallback) {
                        this.onPortSelectCallback(port);
                    }
                }
            },
            children: [
                SafeDOM.createElement('div', {
                    className: 'port-leds-row',
                    children: [
                        SafeDOM.createElement('div', { className: linkLedClass, attrs: { title: `Link: ${port.linkState}` } }),
                        SafeDOM.createElement('div', { className: actLedClass, attrs: { title: isPoeActive ? `PoE: ${port.poe.powerWatts}W` : 'Act' } })
                    ]
                }),
                SafeDOM.createElement('div', { className: 'port-graphic-hole' }),
                SafeDOM.createElement('div', {
                    className: 'port-label',
                    text: isSfp ? `S${port.portNum || port.id}` : (port.portNum || port.id)
                })
            ]
        });

        return socketEl;
    },

    /**
     * 포트 선택 하이라이트
     */
    selectPort(portId) {
        this.selectedPortId = portId;
        const allSockets = document.querySelectorAll('.port-socket');
        allSockets.forEach(s => {
            if (s.getAttribute('data-port-id') === String(portId)) {
                s.classList.add('selected');
            } else {
                s.classList.remove('selected');
            }
        });
    }
};

window.SwitchUI = SwitchUI;
