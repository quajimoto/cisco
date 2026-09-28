// scratch/setup_four_devices.js
// 4대 장비(10.101.241.5, 10.101.241.1, 10.101.241.6, 10.101.241.7) 완벽 구성 및 분리 저장
const fs = require('fs');
const path = require('path');

const baseDir = path.join(__dirname, '..');
const dataDir = path.join(baseDir, 'data');
const devicesDir = path.join(dataDir, 'devices');

if (!fs.existsSync(devicesDir)) fs.mkdirSync(devicesDir, { recursive: true });

const {
    create24PortPoeConfig,
    create48PortPoeConfig,
    loadDevicesRegistry,
    saveDevicesRegistry
} = require('../core/deviceManager');

// 1. dev-office-3f-sw5 (10.101.241.5) - 사용자가 연동한 장비 #1
const devOffice3fPath = path.join(devicesDir, 'dev-office-3f-sw5.json');
let sw5Config;
// 기존 dev-office-2f-sw1.json에 10.101.241.5 연동 데이터가 남아있으므로 복사/사용
const currentOffice2fPath = path.join(devicesDir, 'dev-office-2f-sw1.json');
if (fs.existsSync(currentOffice2fPath)) {
    const raw = JSON.parse(fs.readFileSync(currentOffice2fPath, 'utf8'));
    if (raw.system && raw.system.ipAddress === '10.101.241.5') {
        sw5Config = raw;
    }
}
if (!sw5Config) {
    sw5Config = create24PortPoeConfig('OFFICE_3F_SW_5', '10.101.241.5');
}
sw5Config.system.hostname = 'OFFICE_3F_SW_5';
sw5Config.system.ipAddress = '10.101.241.5';
fs.writeFileSync(devOffice3fPath, JSON.stringify(sw5Config, null, 2), 'utf8');

// 2. dev-core-l3-sw (10.101.241.1) - 사용자가 연동한 장비 #2
const devCorePath = path.join(devicesDir, 'dev-core-l3-sw.json');
let coreConfig = create24PortPoeConfig('MAIN_CORE_L3_SW', '10.101.241.1');
coreConfig.system.hostname = 'MAIN_CORE_L3_SW';
coreConfig.system.model = 'Cisco Catalyst 3850-24XU Core L3';
coreConfig.system.ipAddress = '10.101.241.1';
fs.writeFileSync(devCorePath, JSON.stringify(coreConfig, null, 2), 'utf8');

// 3. dev-office-2f-sw1 (10.101.241.6) - 기존 4단 스택 스위치 (184 ports)
const devOffice2fStackPath = path.join(devicesDir, 'dev-office-2f-sw1.json');
// 4-stack 스위치 빌드
function build4StackConfig() {
    const base = create24PortPoeConfig('OFFICE_2F_SW_1', '10.101.241.6');
    base.system.hostname = 'OFFICE_2F_SW_1';
    base.system.model = 'Cisco Catalyst 2960S-48FPS-L (4-Stack)';
    base.system.ipAddress = '10.101.241.6';
    base.system.stackCount = 4;
    base.poeSummary = { availableWatts: 1480.0, usedWatts: 393.6, remainingWatts: 1086.4 };

    const ports = [];
    let pSeq = 1;
    // Stack 1~4
    for (let s = 1; s <= 4; s++) {
        // 48 RJ45 ports per switch (1..48) or switch 4 has 24 RJ45 + 4 SFP
        const portMax = (s === 4) ? 28 : 52;
        for (let p = 1; p <= portMax; p++) {
            const isSfp = (s === 4 && p > 24) || (s < 4 && p > 48);
            const isUp = (p % 3 === 1) || (s === 1 && p <= 10);
            const isPoe = !isSfp && (p % 2 === 1) && isUp;
            const pvid = (p <= 8) ? 2 : (p <= 16 ? 10 : (p <= 24 ? 20 : 1));
            const portName = isSfp ? `Te${s}/0/${p - (s === 4 ? 24 : 48)}` : `Gi${s}/0/${p}`;

            ports.push({
                id: pSeq++,
                name: portName,
                fullName: `GigabitEthernet${s}/0/${p}`,
                switchNum: s,
                portNum: p,
                type: isSfp ? 'SFP-10G' : 'RJ45-1G-PoE+',
                adminState: 'up',
                linkState: isUp ? 'up' : 'down',
                speed: isUp ? (isSfp ? '10G' : '1G') : 'auto',
                duplex: isUp ? 'full' : 'auto',
                mtu: 1500,
                flowControl: false,
                mode: isSfp ? 'trunk' : 'access',
                pvid,
                taggedVlans: isSfp ? [1, 2, 10, 20, 241] : [],
                untaggedVlans: [pvid],
                description: isUp ? `단말-스택${s}-포트${p}` : '',
                connectedClient: isUp ? {
                    ipAddress: `10.101.${pvid}.${100 + p}`,
                    mac: `00:50:56:${s.toString(16).padStart(2, '0')}:${p.toString(16).padStart(2, '0')}:E1`.toUpperCase(),
                    deviceName: `PC-스택${s}-단말-${p}`,
                    vendor: 'Intel Corporate'
                } : null,
                poe: {
                    mode: 'auto',
                    status: isPoe ? 'on' : 'off',
                    powerWatts: isPoe ? 15.4 : 0,
                    device: isPoe ? 'Cisco IP Phone / AP' : 'n/a',
                    maxWatts: 30
                },
                stats: { rxPackets: 1500, txPackets: 1200, rxBytes: 90000, txBytes: 80000, rxErrors: 0, txErrors: 0 },
                portSecurity: { enabled: false, maxMac: 1, violationAction: 'shutdown', sticky: false }
            });
        }
    }
    base.ports = ports;
    return base;
}
const stackConfig = build4StackConfig();
fs.writeFileSync(devOffice2fStackPath, JSON.stringify(stackConfig, null, 2), 'utf8');

// 4. dev-office-1f-sw2 (10.101.241.7)
const devOffice1fPath = path.join(devicesDir, 'dev-office-1f-sw2.json');
const sw2Config = create24PortPoeConfig('OFFICE_1F_SW_2', '10.101.241.7');
fs.writeFileSync(devOffice1fPath, JSON.stringify(sw2Config, null, 2), 'utf8');

// 5. devices.json 레지스트리 갱신
const devicesRegistry = {
    activeDeviceId: 'dev-office-3f-sw5', // 사용자가 가장 최근 연동한 장비를 기본 활성화
    devices: [
        {
            id: 'dev-office-3f-sw5',
            name: 'OFFICE_3F_SW_5',
            ipAddress: '10.101.241.5',
            model: 'Cisco Catalyst 2960-S PoE+ (Stackable)',
            location: '본관 3층 통신랙 #5 (실시간 연동 장비)',
            portCount: sw5Config.ports.length,
            configFile: 'dev-office-3f-sw5.json',
            status: 'online',
            lastSynced: new Date().toISOString(),
            createdAt: new Date().toISOString()
        },
        {
            id: 'dev-core-l3-sw',
            name: 'MAIN_CORE_L3_SW',
            ipAddress: '10.101.241.1',
            model: 'Cisco Catalyst 3850-24XU Core L3',
            location: '본관 B1층 전산실 메인 백본 랙 (실시간 연동 장비)',
            portCount: 28,
            configFile: 'dev-core-l3-sw.json',
            status: 'online',
            lastSynced: new Date().toISOString(),
            createdAt: new Date().toISOString()
        },
        {
            id: 'dev-office-2f-sw1',
            name: 'OFFICE_2F_SW_1',
            ipAddress: '10.101.241.6',
            model: 'Cisco Catalyst 2960S-48FPS-L (4-Stack)',
            location: '본관 2층 방재통신실 랙 #2',
            portCount: stackConfig.ports.length,
            configFile: 'dev-office-2f-sw1.json',
            status: 'online',
            lastSynced: new Date().toISOString(),
            createdAt: new Date().toISOString()
        },
        {
            id: 'dev-office-1f-sw2',
            name: 'OFFICE_1F_SW_2',
            ipAddress: '10.101.241.7',
            model: 'Cisco Catalyst 2960-S 24-Port PoE+',
            location: '본관 1층 사무실 단독 랙 #1',
            portCount: 28,
            configFile: 'dev-office-1f-sw2.json',
            status: 'online',
            lastSynced: new Date().toISOString(),
            createdAt: new Date().toISOString()
        }
    ]
};

fs.writeFileSync(path.join(dataDir, 'devices.json'), JSON.stringify(devicesRegistry, null, 2), 'utf8');
fs.writeFileSync(path.join(dataDir, 'switch_config.json'), JSON.stringify(sw5Config, null, 2), 'utf8');

console.log('✅ 4대 장비(10.101.241.5, 10.101.241.1, 10.101.241.6, 10.101.241.7) 완벽 등록 완료!');
console.log('Devices:', devicesRegistry.devices.map(d => `${d.name} (${d.ipAddress}) - ${d.portCount} ports`));
