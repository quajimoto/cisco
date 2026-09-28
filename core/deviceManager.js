// core/deviceManager.js
// 다중 네트워크 장비(스위치/라우터) 관리, 장비 전환(Selector), 동적 등록 및 삭제 모듈
// 시큐어코딩 가이드 준수 (Path Traversal 방지, 입력값 검증, 원자적 저장)

const fs = require('fs');
const path = require('path');
const { isValidIPv4, isValidHostname, isSafeDescription } = require('../security/validator');

const DATA_DIR = path.join(__dirname, '..', 'data');
const DEVICES_DIR = path.join(DATA_DIR, 'devices');
const DEVICES_INDEX_FILE = path.join(DATA_DIR, 'devices.json');
const LEGACY_CONFIG_FILE = path.join(DATA_DIR, 'switch_config.json');

// 디렉토리 생성 보장
if (!fs.existsSync(DEVICES_DIR)) {
    fs.mkdirSync(DEVICES_DIR, { recursive: true });
}

/**
 * 24포트 PoE+ Cisco Catalyst 2960-S 템플릿 생성
 */
function create24PortPoeConfig(hostname = 'OFFICE_1F_SW_2', ipAddress = '10.101.241.7') {
    const ports = [];
    const macTable = [];

    // 1 ~ 24번 포트: GigabitEthernet PoE+
    for (let i = 1; i <= 24; i++) {
        const isUp = [1, 2, 5, 6, 9, 10, 14, 23, 24].includes(i);
        const isPoe = [5, 6, 9, 10].includes(i);
        const pvid = i <= 8 ? 2 : (i <= 16 ? 10 : (i >= 23 ? 1 : 20));
        const mode = (i >= 23) ? 'trunk' : 'access';

        let desc = '';
        let connectedClient = null;
        if (i === 1) desc = 'PC-1F-고객지원팀-01 (Samsung)';
        else if (i === 2) desc = 'PC-1F-고객지원팀-02 (LG)';
        else if (i === 5) desc = 'AP-1F-Lobby (Cisco Aironet PoE)';
        else if (i === 6) desc = 'AP-1F-Office (Cisco Aironet PoE)';
        else if (i === 9) desc = 'VoIP-Phone-1F-01 (Cisco 7841 PoE)';
        else if (i === 10) desc = 'VoIP-Phone-1F-02 (Cisco 7841 PoE)';
        else if (i === 14) desc = 'Printer-1F-ColorLaser (HP)';
        else if (i === 23) desc = 'Uplink-to-Core-Trunk-1';
        else if (i === 24) desc = 'Uplink-to-Core-Trunk-2';

        if (isUp && mode === 'access') {
            const macHex = (i).toString(16).padStart(2, '0');
            const mac = `00:E0:4C:1F:02:${macHex}`.toUpperCase();
            const clientIp = `10.101.${pvid}.${100 + i}`;
            connectedClient = {
                ipAddress: clientIp,
                mac,
                deviceName: desc || `Client-Gi1/0/${i}`,
                vendor: i === 5 || i === 6 || i === 9 || i === 10 ? 'Cisco Systems' : (i === 1 ? 'Samsung Electronics' : 'LG Electronics')
            };

            macTable.push({
                mac,
                ipAddress: clientIp,
                deviceName: connectedClient.deviceName,
                vendor: connectedClient.vendor,
                vlanId: pvid,
                portId: i,
                portName: `Gi1/0/${i}`,
                switchNum: 1,
                type: 'dynamic',
                interfaceType: 'access',
                age: Math.floor(Math.random() * 60) + 10
            });
        }

        ports.push({
            id: i,
            name: `Gi1/0/${i}`,
            fullName: `GigabitEthernet1/0/${i}`,
            switchNum: 1,
            portNum: i,
            type: 'RJ45-1G-PoE+',
            admin: true,
            adminState: 'up',
            status: isUp ? 'up' : 'down',
            linkState: isUp ? 'up' : 'down',
            speed: isUp ? '1G' : 'auto',
            duplex: isUp ? 'full' : 'auto',
            mtu: 1500,
            flowControl: false,
            mode,
            pvid,
            taggedVlans: mode === 'trunk' ? [1, 2, 10, 20, 241] : [],
            untaggedVlans: [pvid],
            description: desc,
            connectedClient,
            poe: {
                mode: 'auto',
                status: isPoe ? 'on' : 'off',
                powerWatts: isPoe ? (i === 5 || i === 6 ? 12.8 : 6.4) : 0,
                device: isPoe ? (i <= 6 ? 'Cisco AP' : 'Cisco IP Phone') : 'n/a',
                maxWatts: 30
            },
            stats: {
                rxPackets: isUp ? Math.floor(Math.random() * 300000) + 5000 : 0,
                txPackets: isUp ? Math.floor(Math.random() * 250000) + 4000 : 0,
                rxBytes: isUp ? Math.floor(Math.random() * 600000000) + 10000000 : 0,
                txBytes: isUp ? Math.floor(Math.random() * 500000000) + 8000000 : 0,
                rxErrors: 0,
                txErrors: 0
            },
            portSecurity: {
                enabled: i <= 4,
                maxMac: 2,
                violationAction: 'shutdown',
                sticky: true
            }
        });
    }

    // 25 ~ 28번 포트: SFP+ 10G 업링크
    for (let i = 25; i <= 28; i++) {
        const sfpIdx = i - 24;
        const isUp = (i === 25);
        ports.push({
            id: i,
            name: `Te1/0/${sfpIdx}`,
            fullName: `TenGigabitEthernet1/0/${sfpIdx}`,
            switchNum: 1,
            portNum: sfpIdx,
            type: 'SFP+-10G',
            admin: true,
            adminState: 'up',
            status: isUp ? 'up' : 'down',
            linkState: isUp ? 'up' : 'down',
            speed: isUp ? '10G' : 'auto',
            duplex: isUp ? 'full' : 'auto',
            mtu: 9216,
            flowControl: true,
            mode: 'trunk',
            pvid: 1,
            taggedVlans: [1, 2, 10, 20, 241],
            untaggedVlans: [1],
            description: i === 25 ? '10G-Fiber-Core-Backbone' : '',
            connectedClient: null,
            poe: { mode: 'never', status: 'off', powerWatts: 0, device: 'n/a', maxWatts: 0 },
            stats: {
                rxPackets: isUp ? 1520000 : 0,
                txPackets: isUp ? 1839000 : 0,
                rxBytes: isUp ? 1948201948 : 0,
                txBytes: isUp ? 2194820184 : 0,
                rxErrors: 0,
                txErrors: 0
            },
            portSecurity: { enabled: false, maxMac: 10, violationAction: 'protect', sticky: false }
        });
    }

    const vlans = [
        { id: 1, name: 'default', subnet: '10.101.1.0/24', ipAddress: '10.101.1.254', subnetMask: '255.255.255.0', usableRange: '10.101.1.1 ~ 10.101.1.253', description: '기본 시스템 VLAN' },
        { id: 2, name: 'USER_1F', subnet: '10.101.2.0/24', ipAddress: '10.101.2.254', subnetMask: '255.255.255.0', usableRange: '10.101.2.1 ~ 10.101.2.253', description: '1층 고객지원 및 업무용' },
        { id: 10, name: 'DEV_TEST', subnet: '10.101.10.0/24', ipAddress: '10.101.10.254', subnetMask: '255.255.255.0', usableRange: '10.101.10.1 ~ 10.101.10.253', description: '연구개발 테스트망' },
        { id: 20, name: 'VOIP_VOICE', subnet: '10.101.20.0/24', ipAddress: '10.101.20.254', subnetMask: '255.255.255.0', usableRange: '10.101.20.1 ~ 10.101.20.253', description: '인터넷 전화망' },
        { id: 241, name: 'MGMT', subnet: '10.101.241.0/24', ipAddress: '10.101.241.254', subnetMask: '255.255.255.0', usableRange: '10.101.241.1 ~ 10.101.241.253', description: '네트워크 관리 대역' }
    ];

    return {
        system: {
            hostname,
            model: 'Cisco Catalyst 2960-S 24-Port PoE+ (WS-C2960S-24PD-L)',
            firmwareVersion: '15.0(2)SE',
            serialNumber: `FOC2960S-${hostname.replace(/[^A-Za-z0-9]/g, '')}`,
            ipAddress,
            subnetMask: '255.255.255.0',
            defaultGateway: '10.101.241.254',
            ntpServer: '10.101.241.254',
            macAgingTime: 300,
            bootTime: new Date(Date.now() - 7 * 24 * 3600 * 1000).toISOString(),
            stackCount: 1
        },
        poeSummary: {
            availableWatts: 370.0,
            usedWatts: 38.4,
            remainingWatts: 331.6
        },
        stp: {
            mode: 'rstp',
            priority: 32768,
            helloTime: 2,
            maxAge: 20,
            forwardDelay: 15
        },
        ports,
        vlans,
        macTable,
        lagGroups: [
            { id: 1, name: 'Port-Channel1', mode: 'active', members: [23, 24], description: 'Trunk to Core L3 Switch' }
        ],
        alertSettings: {
            enabled: true,
            managerEmail: 'netadmin@company.com',
            managerName: '네트워크 운영 총괄 담당자',
            senderEmail: 'cisco-alert@switch.internal',
            senderName: `Cisco NetMonitor (${hostname})`,
            smtpHost: 'smtp.gmail.com',
            smtpPort: 587,
            smtpSecure: false,
            smtpUser: '',
            smtpPass: '',
            notifyOnLinkDown: true,
            notifyOnSecurityViolation: true,
            notifyOnPoeFault: true,
            notifyOnStackChange: true
        },
        lastSaved: new Date().toISOString()
    };
}

/**
 * 48포트 PoE+ Cisco Catalyst 2960-S 템플릿 생성
 */
function create48PortPoeConfig(hostname = 'OFFICE_3F_SW_3', ipAddress = '10.101.241.8') {
    const config = create24PortPoeConfig(hostname, ipAddress);
    config.system.model = 'Cisco Catalyst 2960-S 48-Port PoE+ (WS-C2960S-48FPD-L)';
    config.poeSummary = { availableWatts: 740.0, usedWatts: 82.5, remainingWatts: 657.5 };

    // 25 ~ 48번 RJ45 포트 추가
    const extraPorts = [];
    for (let i = 25; i <= 48; i++) {
        const isUp = [25, 26, 30, 31, 47, 48].includes(i);
        extraPorts.push({
            id: i,
            name: `Gi1/0/${i}`,
            fullName: `GigabitEthernet1/0/${i}`,
            switchNum: 1,
            portNum: i,
            type: 'RJ45-1G-PoE+',
            admin: true,
            adminState: 'up',
            status: isUp ? 'up' : 'down',
            linkState: isUp ? 'up' : 'down',
            speed: isUp ? '1G' : 'auto',
            duplex: isUp ? 'full' : 'auto',
            mtu: 1500,
            flowControl: false,
            mode: (i >= 47) ? 'trunk' : 'access',
            pvid: 2,
            taggedVlans: (i >= 47) ? [1, 2, 10, 20] : [],
            untaggedVlans: [2],
            description: isUp ? `PC-3F-User-${i}` : '',
            connectedClient: isUp ? {
                ipAddress: `10.101.2.${100 + i}`,
                mac: `00:50:56:3F:${i.toString(16).padStart(2, '0')}:A1`.toUpperCase(),
                deviceName: `PC-3F-User-${i}`,
                vendor: 'Intel Corporate'
            } : null,
            poe: { mode: 'auto', status: 'off', powerWatts: 0, device: 'n/a', maxWatts: 30 },
            stats: { rxPackets: 1000, txPackets: 900, rxBytes: 50000, txBytes: 45000, rxErrors: 0, txErrors: 0 },
            portSecurity: { enabled: false, maxMac: 1, violationAction: 'shutdown', sticky: false }
        });
    }

    // 49 ~ 52번 SFP+ 포트 추가
    for (let i = 49; i <= 52; i++) {
        const sfpIdx = i - 48;
        extraPorts.push({
            id: i,
            name: `Te1/0/${sfpIdx}`,
            fullName: `TenGigabitEthernet1/0/${sfpIdx}`,
            switchNum: 1,
            portNum: sfpIdx,
            type: 'SFP+-10G',
            admin: true,
            adminState: 'up',
            status: i === 49 ? 'up' : 'down',
            linkState: i === 49 ? 'up' : 'down',
            speed: i === 49 ? '10G' : 'auto',
            duplex: 'full',
            mtu: 9216,
            flowControl: true,
            mode: 'trunk',
            pvid: 1,
            taggedVlans: [1, 2, 10, 20, 241],
            untaggedVlans: [1],
            description: i === 49 ? '10G-Uplink-Core' : '',
            connectedClient: null,
            poe: { mode: 'never', status: 'off', powerWatts: 0, device: 'n/a', maxWatts: 0 },
            stats: { rxPackets: 0, txPackets: 0, rxBytes: 0, txBytes: 0, rxErrors: 0, txErrors: 0 },
            portSecurity: { enabled: false, maxMac: 10, violationAction: 'protect', sticky: false }
        });
    }

    // 기존 포트 중 1~24번만 남기고 25~52번 합침
    config.ports = config.ports.slice(0, 24).concat(extraPorts);
    return config;
}

/**
 * 디바이스 인덱스 및 레지스트리 초기화
 */
function ensureDevicesRegistry() {
    if (!fs.existsSync(DEVICES_INDEX_FILE)) {
        console.log('[DeviceManager] devices.json 생성 및 기존 switch_config.json 마이그레이션...');

        // 1. 기존 switch_config.json 백업/복제
        let primaryConfig = null;
        if (fs.existsSync(LEGACY_CONFIG_FILE)) {
            try {
                primaryConfig = JSON.parse(fs.readFileSync(LEGACY_CONFIG_FILE, 'utf8'));
            } catch (e) {
                console.error('legacy switch_config.json 읽기 실패:', e.message);
            }
        }

        const dev1Id = 'dev-office-2f-sw1';
        const dev1ConfigFile = `${dev1Id}.json`;
        const dev1Path = path.join(DEVICES_DIR, dev1ConfigFile);

        if (primaryConfig) {
            fs.writeFileSync(dev1Path, JSON.stringify(primaryConfig, null, 2), 'utf8');
        } else {
            primaryConfig = create24PortPoeConfig('OFFICE_2F_SW_1', '10.101.241.6');
            fs.writeFileSync(dev1Path, JSON.stringify(primaryConfig, null, 2), 'utf8');
        }

        // 2. 즉시 테스트 및 전환할 수 있는 2번째 장비(1층 스위치) 사전 등록
        const dev2Id = 'dev-office-1f-sw2';
        const dev2ConfigFile = `${dev2Id}.json`;
        const dev2Path = path.join(DEVICES_DIR, dev2ConfigFile);
        const dev2Config = create24PortPoeConfig('OFFICE_1F_SW_2', '10.101.241.7');
        fs.writeFileSync(dev2Path, JSON.stringify(dev2Config, null, 2), 'utf8');

        // 3. 3번째 코어 백본 스위치 등록
        const dev3Id = 'dev-core-l3-sw';
        const dev3ConfigFile = `${dev3Id}.json`;
        const dev3Path = path.join(DEVICES_DIR, dev3ConfigFile);
        const dev3Config = create24PortPoeConfig('MAIN_CORE_L3_SW', '10.101.241.1');
        dev3Config.system.model = 'Cisco Catalyst 3850-24XU Core L3';
        dev3Config.system.ipAddress = '10.101.241.1';
        fs.writeFileSync(dev3Path, JSON.stringify(dev3Config, null, 2), 'utf8');

        const initialRegistry = {
            activeDeviceId: dev1Id,
            devices: [
                {
                    id: dev1Id,
                    name: (primaryConfig.system && primaryConfig.system.hostname) || 'OFFICE_2F_SW_1',
                    ipAddress: (primaryConfig.system && primaryConfig.system.ipAddress) || '10.101.241.6',
                    model: (primaryConfig.system && primaryConfig.system.model) || 'Cisco Catalyst 2960-S PoE+ (Stackable)',
                    location: '본관 2층 방재통신실 랙 #2',
                    portCount: (primaryConfig.ports && primaryConfig.ports.length) || 184,
                    configFile: dev1ConfigFile,
                    status: 'connected',
                    lastSynced: new Date().toISOString(),
                    createdAt: new Date().toISOString()
                },
                {
                    id: dev2Id,
                    name: 'OFFICE_1F_SW_2',
                    ipAddress: '10.101.241.7',
                    model: 'Cisco Catalyst 2960-S 24-Port PoE+ (WS-C2960S-24PD-L)',
                    location: '본관 1층 사무실 단독 랙 #1',
                    portCount: 28,
                    configFile: dev2ConfigFile,
                    status: 'online',
                    lastSynced: new Date().toISOString(),
                    createdAt: new Date().toISOString()
                },
                {
                    id: dev3Id,
                    name: 'MAIN_CORE_L3_SW',
                    ipAddress: '10.101.241.1',
                    model: 'Cisco Catalyst 3850-24XU Core L3',
                    location: '본관 B1층 전산실 메인 백본 랙',
                    portCount: 28,
                    configFile: dev3ConfigFile,
                    status: 'online',
                    lastSynced: new Date().toISOString(),
                    createdAt: new Date().toISOString()
                }
            ]
        };

        fs.writeFileSync(DEVICES_INDEX_FILE, JSON.stringify(initialRegistry, null, 2), 'utf8');
    }
}

/**
 * 장비 목록 및 활성 장비 정보 로드
 */
function loadDevicesRegistry() {
    ensureDevicesRegistry();
    try {
        const raw = fs.readFileSync(DEVICES_INDEX_FILE, 'utf8');
        return JSON.parse(raw);
    } catch (e) {
        console.error('devices.json 로드 실패:', e.message);
        return { activeDeviceId: 'dev-office-2f-sw1', devices: [] };
    }
}

/**
 * 장비 레지스트리 저장
 */
function saveDevicesRegistry(registry) {
    const tempPath = `${DEVICES_INDEX_FILE}.tmp`;
    fs.writeFileSync(tempPath, JSON.stringify(registry, null, 2), 'utf8');
    fs.renameSync(tempPath, DEVICES_INDEX_FILE);
}

/**
 * 현재 활성화된 장비 ID 조회
 */
function getActiveDeviceId() {
    const reg = loadDevicesRegistry();
    return reg.activeDeviceId || (reg.devices[0] && reg.devices[0].id) || 'dev-office-2f-sw1';
}

/**
 * 현재 활성 장비의 설정 파일 절대경로 반환
 */
function getActiveConfigFilePath() {
    const reg = loadDevicesRegistry();
    const activeDev = reg.devices.find(d => d.id === reg.activeDeviceId) || reg.devices[0];
    if (activeDev && activeDev.configFile) {
        const p = path.join(DEVICES_DIR, activeDev.configFile);
        if (fs.existsSync(p)) return p;
    }
    return LEGACY_CONFIG_FILE;
}

/**
 * 포트 데이터 정규화 유틸리티 (adminState, linkState, switchNum, portNum 완벽 호환)
 */
function normalizeConfigPorts(config) {
    if (!config || !Array.isArray(config.ports)) return config;
    config.ports = config.ports.map((p, idx) => {
        const m = (p.name || '').match(/^(?:Gi|Te|Fa)(\d+)\/\d+\/(\d+)$/i);
        const sNum = p.switchNum || (m ? parseInt(m[1], 10) : 1);
        const pNum = p.portNum || (m ? parseInt(m[2], 10) : (p.id || idx + 1));
        
        // adminState ('up' | 'down') and admin (true | false)
        const adminState = p.adminState || (p.admin === false ? 'down' : 'up');
        const admin = p.admin !== undefined ? p.admin : (adminState === 'up');
        
        // linkState ('up' | 'down') and status ('up' | 'down')
        const linkState = p.linkState || p.status || 'down';
        const status = p.status || linkState;
        
        const isSfp = p.type && (p.type.includes('Ten') || p.type.includes('SFP'));
        const fullName = p.fullName || (isSfp ? `TenGigabitEthernet${sNum}/0/${pNum}` : `GigabitEthernet${sNum}/0/${pNum}`);

        return {
            ...p,
            id: p.id || (idx + 1),
            switchNum: sNum,
            portNum: pNum,
            adminState,
            admin,
            linkState,
            status,
            fullName
        };
    });
    return config;
}

/**
 * 특정 장비의 설정 로드
 */
function loadDeviceConfig(deviceId = null) {
    ensureDevicesRegistry();
    const targetId = deviceId || getActiveDeviceId();
    const reg = loadDevicesRegistry();
    const dev = reg.devices.find(d => d.id === targetId);

    let config = null;
    if (dev && dev.configFile) {
        const configPath = path.join(DEVICES_DIR, dev.configFile);
        if (fs.existsSync(configPath)) {
            try {
                config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
            } catch (e) {
                console.error(`장비 설정 파일(${dev.configFile}) 파싱 오류:`, e.message);
            }
        }
    }

    // 파일이 없거나 legacy 파일인 경우
    if (!config && fs.existsSync(LEGACY_CONFIG_FILE)) {
        try {
            config = JSON.parse(fs.readFileSync(LEGACY_CONFIG_FILE, 'utf8'));
        } catch (e) {}
    }

    if (!config) {
        config = create24PortPoeConfig();
    }

    return normalizeConfigPorts(config);
}

/**
 * 특정 장비의 설정 저장
 */
function saveDeviceConfig(config, deviceId = null) {
    ensureDevicesRegistry();
    const targetId = deviceId || getActiveDeviceId();
    const reg = loadDevicesRegistry();
    const dev = reg.devices.find(d => d.id === targetId);

    config.lastSaved = new Date().toISOString();

    if (dev && dev.configFile) {
        const targetPath = path.join(DEVICES_DIR, dev.configFile);
        const tempPath = `${targetPath}.tmp`;
        fs.writeFileSync(tempPath, JSON.stringify(config, null, 2), 'utf8');
        fs.renameSync(tempPath, targetPath);

        // 레지스트리 내 장비 메타데이터 동기화
        if (config.system) {
            if (config.system.hostname) dev.name = config.system.hostname;
            if (config.system.ipAddress) dev.ipAddress = config.system.ipAddress;
            if (config.system.model) dev.model = config.system.model;
        }
        if (config.ports) dev.portCount = config.ports.length;
        dev.lastSaved = config.lastSaved;
        saveDevicesRegistry(reg);
    }

    // 활성 장비인 경우 legacy switch_config.json 도 함께 동기화
    if (targetId === reg.activeDeviceId) {
        try {
            const tempLegacy = `${LEGACY_CONFIG_FILE}.tmp`;
            fs.writeFileSync(tempLegacy, JSON.stringify(config, null, 2), 'utf8');
            fs.renameSync(tempLegacy, LEGACY_CONFIG_FILE);
        } catch (e) {}
    }
}

/**
 * 활성 관리 장비 전환 (Switch Active Device)
 */
function setActiveDevice(deviceId) {
    const reg = loadDevicesRegistry();
    const dev = reg.devices.find(d => d.id === deviceId);
    if (!dev) {
        throw new Error('해당 식별자의 장비를 찾을 수 없습니다.');
    }

    reg.activeDeviceId = dev.id;
    saveDevicesRegistry(reg);

    // switch_config.json 도 활성 장비의 내용으로 즉시 동기화
    const activeConfig = loadDeviceConfig(dev.id);
    try {
        fs.writeFileSync(LEGACY_CONFIG_FILE, JSON.stringify(activeConfig, null, 2), 'utf8');
    } catch (e) {}

    return {
        success: true,
        activeDeviceId: dev.id,
        device: dev,
        config: activeConfig
    };
}

/**
 * 새로운 장비 추가 (Add New Device)
 */
function createDevice(params) {
    const reg = loadDevicesRegistry();
    const {
        name,
        ipAddress,
        model,
        location,
        description,
        templateType,
        customConfig,
        makeActive
    } = params;

    const devName = (name || '').trim();
    if (!devName) throw new Error('장비 식별명을 입력해주세요.');
    if (ipAddress && !isValidIPv4(ipAddress)) throw new Error('올바른 IPv4 주소 형식이 아닙니다.');

    // 고유 ID 생성 (알파벳, 숫자, 하이픈만 허용)
    const safeSlug = devName.toLowerCase().replace(/[^a-z0-9]/g, '-').replace(/-+/g, '-').slice(0, 20);
    const newId = `dev-${safeSlug}-${Date.now().toString(36)}`;
    const configFile = `${newId}.json`;
    const configPath = path.join(DEVICES_DIR, configFile);

    let newConfig;
    if (customConfig && typeof customConfig === 'object') {
        newConfig = JSON.parse(JSON.stringify(customConfig));
        if (!newConfig.system) newConfig.system = {};
        newConfig.system.hostname = devName;
        newConfig.system.ipAddress = ipAddress || newConfig.system.ipAddress || '10.101.241.10';
        if (model) newConfig.system.model = model;
    } else if (templateType === 'cisco-2960s-48p') {
        newConfig = create48PortPoeConfig(devName, ipAddress || '10.101.241.10');
        if (model) newConfig.system.model = model;
    } else if (templateType === 'clone-active') {
        const activeCfg = loadDeviceConfig();
        newConfig = JSON.parse(JSON.stringify(activeCfg));
        newConfig.system.hostname = devName;
        if (ipAddress) newConfig.system.ipAddress = ipAddress;
        if (model) newConfig.system.model = model;
    } else {
        // 기본 24포트 PoE+
        newConfig = create24PortPoeConfig(devName, ipAddress || '10.101.241.10');
        if (model) newConfig.system.model = model;
    }

    // 신규 설정 파일 저장
    fs.writeFileSync(configPath, JSON.stringify(newConfig, null, 2), 'utf8');

    const newDevEntry = {
        id: newId,
        name: devName,
        ipAddress: (newConfig.system && newConfig.system.ipAddress) || ipAddress || '10.101.241.10',
        model: (newConfig.system && newConfig.system.model) || model || 'Cisco Catalyst 2960-S PoE+',
        location: (location || '사내 전산실').trim(),
        description: (description || '').trim(),
        portCount: (newConfig.ports && newConfig.ports.length) || 28,
        configFile,
        status: 'online',
        lastSynced: new Date().toISOString(),
        createdAt: new Date().toISOString()
    };

    reg.devices.push(newDevEntry);

    if (makeActive !== false) {
        reg.activeDeviceId = newId;
        // switch_config.json 동기화
        try {
            fs.writeFileSync(LEGACY_CONFIG_FILE, JSON.stringify(newConfig, null, 2), 'utf8');
        } catch (e) {}
    }

    saveDevicesRegistry(reg);

    return {
        success: true,
        device: newDevEntry,
        activeDeviceId: reg.activeDeviceId,
        config: newConfig
    };
}

/**
 * 장비 메타데이터 수정
 */
function updateDevice(deviceId, params) {
    const reg = loadDevicesRegistry();
    const dev = reg.devices.find(d => d.id === deviceId);
    if (!dev) throw new Error('해당 장비를 찾을 수 없습니다.');

    const { name, ipAddress, model, location, description } = params;

    if (name && name.trim()) dev.name = name.trim();
    if (ipAddress && isValidIPv4(ipAddress)) dev.ipAddress = ipAddress.trim();
    if (model && model.trim()) dev.model = model.trim();
    if (location !== undefined) dev.location = location.trim();
    if (description !== undefined) dev.description = description.trim();

    // 설정 파일 내부의 system 필드도 동기화
    const cfg = loadDeviceConfig(deviceId);
    if (cfg && cfg.system) {
        if (dev.name) cfg.system.hostname = dev.name;
        if (dev.ipAddress) cfg.system.ipAddress = dev.ipAddress;
        if (dev.model) cfg.system.model = dev.model;
        saveDeviceConfig(cfg, deviceId);
    }

    saveDevicesRegistry(reg);
    return { success: true, device: dev };
}

/**
 * 장비 삭제
 */
function deleteDevice(deviceId) {
    const reg = loadDevicesRegistry();
    if (reg.devices.length <= 1) {
        throw new Error('최소 1개 이상의 관리 장비가 유지되어야 하므로 삭제할 수 없습니다.');
    }

    const devIndex = reg.devices.findIndex(d => d.id === deviceId);
    if (devIndex === -1) throw new Error('삭제할 장비를 찾을 수 없습니다.');

    const targetDev = reg.devices[devIndex];

    // 활성 장비가 삭제되는 경우 다른 장비로 자동 전환
    if (reg.activeDeviceId === deviceId) {
        const remaining = reg.devices.filter(d => d.id !== deviceId);
        reg.activeDeviceId = remaining[0].id;
        const newActiveConfig = loadDeviceConfig(reg.activeDeviceId);
        try {
            fs.writeFileSync(LEGACY_CONFIG_FILE, JSON.stringify(newActiveConfig, null, 2), 'utf8');
        } catch (e) {}
    }

    // 설정 파일 삭제
    if (targetDev.configFile) {
        const configPath = path.join(DEVICES_DIR, targetDev.configFile);
        if (fs.existsSync(configPath)) {
            try { fs.unlinkSync(configPath); } catch (e) {}
        }
    }

    reg.devices.splice(devIndex, 1);
    saveDevicesRegistry(reg);

    return {
        success: true,
        message: `장비 [${targetDev.name}]가 성공적으로 삭제되었습니다.`,
        activeDeviceId: reg.activeDeviceId
    };
}

module.exports = {
    loadDevicesRegistry,
    saveDevicesRegistry,
    getActiveDeviceId,
    getActiveConfigFilePath,
    loadDeviceConfig,
    saveDeviceConfig,
    setActiveDevice,
    createDevice,
    updateDevice,
    deleteDevice,
    create24PortPoeConfig,
    create48PortPoeConfig,
    normalizeConfigPorts
};
