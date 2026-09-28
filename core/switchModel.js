// core/switchModel.js
// L2 스위치 상태 관리 모델 및 비즈니스 로직

const fs = require('fs');
const path = require('path');

const CONFIG_FILE = path.join(__dirname, '..', 'data', 'switch_config.json');

/**
 * 초기 스위치 기본 설정 생성 (24x 1G RJ45 + 4x 10G SFP+)
 */
function createDefaultConfig() {
    const ports = [];
    
    // 1 ~ 24번 포트: GigabitEthernet (RJ45)
    for (let i = 1; i <= 24; i++) {
        // 일부 포트는 링크 연결 시뮬레이션을 위해 UP 상태로 설정
        const isUp = [1, 2, 3, 5, 9, 13, 23, 24].includes(i);
        ports.push({
            id: i,
            name: `Gi1/0/${i}`,
            type: 'RJ45-1G',
            adminState: 'up',
            linkState: isUp ? 'up' : 'down',
            speed: isUp ? '1G' : 'auto',
            duplex: isUp ? 'full' : 'auto',
            mtu: 1500,
            flowControl: false,
            mode: (i === 23 || i === 24) ? 'trunk' : 'access',
            pvid: (i === 5) ? 10 : (i === 9) ? 20 : (i === 13) ? 30 : 1,
            taggedVlans: (i === 23 || i === 24) ? [10, 20, 30] : [],
            untaggedVlans: (i === 23 || i === 24) ? [1] : [(i === 5) ? 10 : (i === 9) ? 20 : (i === 13) ? 30 : 1],
            description: i === 1 ? 'Uplink-Core' : i === 5 ? 'Server-Farm-01' : i === 9 ? 'VoIP-Phone-GW' : i === 23 ? 'Trunk-to-SW2' : '',
            stats: {
                rxPackets: Math.floor(Math.random() * 500000) + 10000,
                txPackets: Math.floor(Math.random() * 450000) + 9000,
                rxBytes: Math.floor(Math.random() * 800000000) + 50000000,
                txBytes: Math.floor(Math.random() * 700000000) + 40000000,
                rxErrors: 0,
                txErrors: 0
            },
            portSecurity: {
                enabled: i === 5,
                maxMac: 2,
                violationAction: 'restrict',
                sticky: true
            },
            stp: {
                edgePort: (i !== 1 && i !== 23 && i !== 24),
                bpduGuard: (i !== 1 && i !== 23 && i !== 24),
                cost: 4,
                state: isUp ? 'forwarding' : 'disabled'
            }
        });
    }

    // 25 ~ 28번 포트: TenGigabitEthernet (SFP+)
    for (let i = 25; i <= 28; i++) {
        const sfpIdx = i - 24;
        const isUp = (i === 25);
        ports.push({
            id: i,
            name: `Te1/0/${sfpIdx}`,
            type: 'SFP+-10G',
            adminState: 'up',
            linkState: isUp ? 'up' : 'down',
            speed: isUp ? '10G' : 'auto',
            duplex: isUp ? 'full' : 'auto',
            mtu: 9216,
            flowControl: true,
            mode: 'trunk',
            pvid: 1,
            taggedVlans: [10, 20, 30],
            untaggedVlans: [1],
            description: i === 25 ? '10G-Optic-Backbone' : '',
            stats: {
                rxPackets: isUp ? 15200420 : 0,
                txPackets: isUp ? 18392100 : 0,
                rxBytes: isUp ? 19482019482 : 0,
                txBytes: isUp ? 21948201842 : 0,
                rxErrors: 0,
                txErrors: 0
            },
            portSecurity: {
                enabled: false,
                maxMac: 10,
                violationAction: 'protect',
                sticky: false
            },
            stp: {
                edgePort: false,
                bpduGuard: false,
                cost: 2,
                state: isUp ? 'forwarding' : 'disabled'
            }
        });
    }

    // 기본 VLAN 목록
    const vlans = [
        { id: 1, name: 'default', description: 'Default System VLAN', isSystem: true },
        { id: 10, name: 'SERVERS', description: 'Internal Server Subnet', isSystem: false },
        { id: 20, name: 'VOIP', description: 'Voice over IP Network', isSystem: false },
        { id: 30, name: 'OFFICE', description: 'Corporate Office Workstations', isSystem: false },
        { id: 99, name: 'MANAGEMENT', description: 'Out-of-Band Management', isSystem: false }
    ];

    // 기본 MAC 주소 테이블
    const macTable = [
        { mac: '00:1A:2B:3C:4D:5E', vlanId: 1, portId: 1, type: 'dynamic', age: 42 },
        { mac: '70:85:C2:55:01:A2', vlanId: 10, portId: 5, type: 'static', age: 0 },
        { mac: '00:08:E3:44:91:BC', vlanId: 20, portId: 9, type: 'dynamic', age: 110 },
        { mac: '3C:D9:2B:10:88:FE', vlanId: 30, portId: 13, type: 'dynamic', age: 75 },
        { mac: '00:50:56:A3:89:12', vlanId: 1, portId: 23, type: 'dynamic', age: 15 },
        { mac: 'CC:D5:39:E4:00:01', vlanId: 1, portId: 25, type: 'dynamic', age: 5 }
    ];

    // 기본 LACP 그룹
    const lagGroups = [
        { id: 1, name: 'Port-Channel1', mode: 'active', members: [23, 24], description: 'Trunk to Core L3 Switch' }
    ];

    return {
        system: {
            hostname: 'Secure-L2-Switch',
            model: 'AGY-L2-28X-SECURE',
            firmwareVersion: 'v2.4.1-SecureBuild',
            serialNumber: 'AGY202609-8839210',
            ipAddress: '192.168.1.254',
            subnetMask: '255.255.255.0',
            defaultGateway: '192.168.1.1',
            ntpServer: 'time.bora.net',
            systemContact: 'admin@corp.internal',
            systemLocation: 'Server Room Rack 42-B',
            bootTime: new Date(Date.now() - 14 * 24 * 3600 * 1000).toISOString(),
            macAgingTime: 300
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
        lagGroups,
        lastSaved: new Date().toISOString()
    };
}

const {
    loadDeviceConfig,
    saveDeviceConfig
} = require('./deviceManager');

/**
 * 설정 로드 (현재 활성 장비 또는 지정된 장비)
 */
function loadConfig(deviceId = null) {
    try {
        return loadDeviceConfig(deviceId);
    } catch (err) {
        console.error('설정 로드 실패, 기본값으로 복구:', err.message);
        const fallback = createDefaultConfig();
        saveConfig(fallback);
        return fallback;
    }
}

/**
 * 원자적 설정 저장 (경쟁상태 및 쓰기 중단 방지)
 */
function saveConfig(config, deviceId = null) {
    saveDeviceConfig(config, deviceId);
}

module.exports = {
    loadConfig,
    saveConfig,
    createDefaultConfig
};
