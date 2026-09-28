// core/ciscoParser.js
// Cisco Catalyst 2960-S Series (단일 및 스택 스위치) 전체 설정 정밀 파서
// show running-config, show interfaces status, show vlan brief, show power inline, show mac address-table 지원

/**
 * IP와 서브넷 마스크를 기반으로 CIDR, 네트워크, 브로드캐스트, 가용 IP 대역, 호스트 수 계산
 */
function calculateSubnetDetails(ip, mask) {
    if (!ip || !mask) return null;
    const ipParts = ip.trim().split('.').map(Number);
    const maskParts = mask.trim().split('.').map(Number);
    if (ipParts.length !== 4 || maskParts.length !== 4) return null;
    if (ipParts.some(p => isNaN(p) || p < 0 || p > 255) || maskParts.some(p => isNaN(p) || p < 0 || p > 255)) return null;

    const ipInt = ((ipParts[0] << 24) >>> 0) + ((ipParts[1] << 16) >>> 0) + ((ipParts[2] << 8) >>> 0) + (ipParts[3] >>> 0);
    const maskInt = ((maskParts[0] << 24) >>> 0) + ((maskParts[1] << 16) >>> 0) + ((maskParts[2] << 8) >>> 0) + (maskParts[3] >>> 0);

    let cidr = 0;
    for (let i = 31; i >= 0; i--) {
        if ((maskInt & (1 << i)) !== 0) cidr++;
        else break;
    }

    const netInt = (ipInt & maskInt) >>> 0;
    const invMask = (~maskInt) >>> 0;
    const broadcastInt = (netInt | invMask) >>> 0;

    const intToIp = (n) => [
        (n >>> 24) & 255,
        (n >>> 16) & 255,
        (n >>> 8) & 255,
        n & 255
    ].join('.');

    const network = intToIp(netInt);
    const broadcast = intToIp(broadcastInt);

    let firstHost = network;
    let lastHost = broadcast;
    let totalHosts = 0;

    if (cidr <= 30) {
        firstHost = intToIp((netInt + 1) >>> 0);
        lastHost = intToIp((broadcastInt - 1) >>> 0);
        totalHosts = Math.pow(2, 32 - cidr) - 2;
    } else if (cidr === 31) {
        firstHost = network;
        lastHost = broadcast;
        totalHosts = 2;
    } else {
        firstHost = network;
        lastHost = network;
        totalHosts = 1;
    }

    return {
        cidr,
        network: `${network}/${cidr}`,
        networkIp: network,
        broadcast,
        firstHost,
        lastHost,
        ipRange: `${firstHost} ~ ${lastHost}`,
        usableRange: `${firstHost} ~ ${lastHost}`,
        totalHosts
    };
}

/**
 * Cisco 2960-S 스위치 전체 원문 출력을 파싱하여 구조화된 데이터 생성
 */
function parseCiscoConfig(rawText) {
    if (!rawText || typeof rawText !== 'string') {
        throw new Error('파싱할 설정 텍스트가 비어있습니다.');
    }

    const lines = rawText.split(/\r?\n/);
    const result = {
        system: {
            hostname: 'Switch',
            model: 'Cisco Catalyst 2960-S PoE+ (Stackable)',
            firmwareVersion: '15.0(2)SE',
            serialNumber: 'FOC2960S-STACK',
            ipAddress: '192.168.1.254',
            subnetMask: '255.255.255.0',
            defaultGateway: '192.168.1.1',
            ntpServer: '',
            macAgingTime: 300,
            bootTime: new Date(Date.now() - 30 * 24 * 3600 * 1000).toISOString(),
            stackCount: 1
        },
        poeSummary: {
            availableWatts: 370.0,
            usedWatts: 0.0,
            remainingWatts: 370.0
        },
        stp: {
            mode: 'rstp',
            priority: 32768,
            helloTime: 2,
            maxAge: 20,
            forwardDelay: 15
        },
        ports: [],
        vlans: [
            { id: 1, name: 'default', description: 'Default System VLAN', isSystem: true }
        ],
        macTable: [],
        lagGroups: [],
        lastSaved: new Date().toISOString()
    };

    let currentInterface = null;
    let currentVlan = null;
    let portSequenceId = 1;
    const stackSet = new Set();

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();

        // 1. 호스트명
        const hostMatch = line.match(/^hostname\s+(\S+)/i);
        if (hostMatch) {
            result.system.hostname = hostMatch[1];
            continue;
        }

        // 2. 디폴트 게이트웨이
        const gwMatch = line.match(/^ip\s+default-gateway\s+([0-9.]+)/i);
        if (gwMatch) {
            result.system.defaultGateway = gwMatch[1];
            continue;
        }

        // 3. NTP 서버
        const ntpMatch = line.match(/^ntp\s+server\s+(\S+)/i);
        if (ntpMatch) {
            result.system.ntpServer = ntpMatch[1];
            continue;
        }

        // 4. STP 모드 및 Priority
        const stpModeMatch = line.match(/^spanning-tree\s+mode\s+(\S+)/i);
        if (stpModeMatch) {
            result.stp.mode = stpModeMatch[1].toLowerCase() === 'rapid-pvst' ? 'rstp' : 'stp';
            continue;
        }
        const stpPrioMatch = line.match(/^spanning-tree\s+vlan\s+.*priority\s+(\d+)/i);
        if (stpPrioMatch) {
            result.stp.priority = parseInt(stpPrioMatch[1], 10);
            continue;
        }

        // 5. VLAN 정의 블록 (running-config 내)
        const vlanBlockMatch = line.match(/^vlan\s+(\d+)/i);
        if (vlanBlockMatch) {
            const vlanId = parseInt(vlanBlockMatch[1], 10);
            if (vlanId !== 1 && !result.vlans.some(v => v.id === vlanId)) {
                currentVlan = { id: vlanId, name: `VLAN${vlanId}`, description: '', isSystem: false };
                result.vlans.push(currentVlan);
            } else {
                currentVlan = result.vlans.find(v => v.id === vlanId);
            }
            continue;
        }
        if (currentVlan && line.startsWith('name ')) {
            currentVlan.name = line.substring(5).trim();
            continue;
        }
        if (line === '!' || line.startsWith('interface ')) {
            currentVlan = null;
        }

        // 6. 인터페이스 정의 블록
        // 예: interface GigabitEthernet1/0/1 ~ 52, interface GigabitEthernet2/0/1...
        const ifaceMatch = line.match(/^interface\s+(GigabitEthernet|TenGigabitEthernet|FastEthernet|Vlan)(\d+[\/\d]*)/i);
        if (ifaceMatch) {
            const typePrefix = ifaceMatch[1];
            const ifaceNum = ifaceMatch[2];
            const fullName = `${typePrefix}${ifaceNum}`;

            // SVI (VLAN 인터페이스) 처리
            if (typePrefix.toLowerCase() === 'vlan') {
                currentInterface = { isVlanInterface: true, vlanId: parseInt(ifaceNum, 10) };
                continue;
            }

            // OOB FastEthernet0 관리 포트 스킵 또는 별도 식별
            if (typePrefix.toLowerCase() === 'fastethernet' && ifaceNum === '0') {
                currentInterface = { isOob: true };
                continue;
            }

            // 스택 인터페이스 파싱: Gi<switch>/<module>/<port>
            const parts = ifaceNum.split('/');
            let switchNum = 1;
            let portNum = 1;

            if (parts.length === 3) {
                switchNum = parseInt(parts[0], 10);
                portNum = parseInt(parts[2], 10);
            } else if (parts.length === 2) {
                switchNum = parseInt(parts[0], 10);
                portNum = parseInt(parts[1], 10);
            } else {
                portNum = parseInt(ifaceNum, 10);
            }

            stackSet.add(switchNum);

            // 포트 타입 판별:
            // 48포트 모델: 1~48 RJ45 PoE+, 49~52 SFP
            // 24포트 모델: 1~24 RJ45 PoE+, 25~28 SFP
            const isTenGig = typePrefix.toLowerCase().startsWith('ten');
            let portType = 'RJ45-1G-PoE+';
            if (isTenGig) {
                portType = 'SFP+-10G';
            } else if (portNum > 48) {
                portType = 'SFP-1G';
            }

            const shortName = fullName.replace('GigabitEthernet', 'Gi').replace('TenGigabitEthernet', 'Te');

            currentInterface = {
                id: portSequenceId++,
                name: shortName,
                fullName: fullName,
                switchNum: switchNum,
                portNum: portNum,
                type: portType,
                adminState: 'up',
                linkState: 'down',
                speed: 'auto',
                duplex: 'auto',
                mtu: 1500,
                flowControl: false,
                mode: 'access',
                pvid: 1,
                taggedVlans: [],
                untaggedVlans: [1],
                description: '',
                poe: {
                    mode: 'auto',
                    status: 'off',
                    powerWatts: 0.0,
                    device: 'No PD detected',
                    maxWatts: 30.0
                },
                stats: {
                    rxPackets: Math.floor(Math.random() * 200000) + 1000,
                    txPackets: Math.floor(Math.random() * 180000) + 800,
                    rxBytes: Math.floor(Math.random() * 300000000) + 5000000,
                    txBytes: Math.floor(Math.random() * 250000000) + 4000000,
                    rxErrors: 0,
                    txErrors: 0
                },
                portSecurity: {
                    enabled: false,
                    maxMac: 1,
                    violationAction: 'shutdown',
                    sticky: false
                },
                stp: {
                    edgePort: false,
                    bpduGuard: false,
                    cost: isTenGig ? 2 : 4,
                    state: 'forwarding'
                }
            };
            result.ports.push(currentInterface);
            continue;
        }

        // VLAN 관리 IP 파싱 (SVI 및 서브넷 대역 도출)
        if (currentInterface && currentInterface.isVlanInterface) {
            const ipMatch = line.match(/^ip\s+address\s+([0-9.]+)\s+([0-9.]+)/i);
            if (ipMatch) {
                const ip = ipMatch[1];
                const mask = ipMatch[2];
                const vlanId = currentInterface.vlanId;
                const netInfo = calculateSubnetDetails(ip, mask);

                result.system.ipAddress = ip;
                result.system.subnetMask = mask;

                let vlanObj = result.vlans.find(v => v.id === vlanId);
                if (!vlanObj) {
                    vlanObj = { id: vlanId, name: `VLAN${vlanId}`, description: '', isSystem: (vlanId === 1) };
                    result.vlans.push(vlanObj);
                }
                vlanObj.ipAddress = ip;
                vlanObj.subnetMask = mask;
                vlanObj.isSvi = true;
                if (netInfo) {
                    vlanObj.cidr = netInfo.cidr;
                    vlanObj.network = netInfo.network;
                    vlanObj.broadcast = netInfo.broadcast;
                    vlanObj.ipRange = netInfo.ipRange;
                    vlanObj.totalHosts = netInfo.totalHosts;
                    vlanObj.gateway = result.system.defaultGateway || netInfo.firstHost;
                }
            }
            if (line === '!' || line.startsWith('interface ')) {
                currentInterface = null;
            }
            continue;
        }

        // OOB 관리 인터페이스
        if (currentInterface && currentInterface.isOob) {
            if (line === '!' || line.startsWith('interface ')) {
                currentInterface = null;
            }
            continue;
        }

        // 물리 인터페이스 내부 속성 파싱
        if (currentInterface && !currentInterface.isVlanInterface && !currentInterface.isOob) {
            if (line === 'shutdown') {
                currentInterface.adminState = 'down';
                currentInterface.linkState = 'down';
            } else if (line.startsWith('description ')) {
                currentInterface.description = line.substring(12).trim();
            } else if (line.startsWith('speed ')) {
                currentInterface.speed = line.substring(6).trim();
            } else if (line.startsWith('duplex ')) {
                currentInterface.duplex = line.substring(7).trim();
            } else if (line.startsWith('switchport mode ')) {
                currentInterface.mode = line.substring(16).trim().toLowerCase();
            } else if (line.startsWith('switchport access vlan ')) {
                currentInterface.pvid = parseInt(line.substring(23).trim(), 10);
                currentInterface.untaggedVlans = [currentInterface.pvid];
                // VLAN이 아직 등록되지 않았으면 자동 추가
                if (currentInterface.pvid !== 1 && !result.vlans.some(v => v.id === currentInterface.pvid)) {
                    result.vlans.push({
                        id: currentInterface.pvid,
                        name: `VLAN${currentInterface.pvid}`,
                        description: '',
                        isSystem: false
                    });
                }
            } else if (line.startsWith('switchport trunk native vlan ')) {
                currentInterface.pvid = parseInt(line.substring(29).trim(), 10);
            } else if (line.startsWith('switchport trunk allowed vlan ')) {
                const vlanTokens = line.substring(30).trim().split(',');
                const tags = [];
                vlanTokens.forEach(t => {
                    if (t.includes('-')) {
                        const [s, e] = t.split('-').map(Number);
                        for (let v = s; v <= e; v++) tags.push(v);
                    } else if (!isNaN(Number(t))) {
                        tags.push(Number(t));
                    }
                });
                currentInterface.taggedVlans = tags;
            } else if (line === 'power inline never') {
                currentInterface.poe.mode = 'never';
            } else if (line === 'power inline auto') {
                currentInterface.poe.mode = 'auto';
            } else if (line === 'switchport port-security') {
                currentInterface.portSecurity.enabled = true;
            } else if (line.startsWith('switchport port-security maximum ')) {
                currentInterface.portSecurity.maxMac = parseInt(line.substring(33).trim(), 10);
            } else if (line.startsWith('switchport port-security violation ')) {
                currentInterface.portSecurity.violationAction = line.substring(35).trim().toLowerCase();
            } else if (line === 'switchport port-security mac-address sticky') {
                currentInterface.portSecurity.sticky = true;
            } else if (line === 'spanning-tree portfast') {
                currentInterface.stp.edgePort = true;
            } else if (line === 'spanning-tree bpduguard enable') {
                currentInterface.stp.bpduGuard = true;
            }

            if (line === '!' || line.startsWith('interface ')) {
                currentInterface = null;
            }
        }

        // 7. 정적 MAC 주소
        const macMatch = line.match(/^mac\s+address-table\s+static\s+([0-9a-fA-F.:-]+)\s+vlan\s+(\d+)\s+interface\s+(\S+)/i);
        if (macMatch) {
            const rawMac = macMatch[1].replace(/[:.-]/g, '').toUpperCase().match(/.{1,2}/g).join(':');
            const vlanId = parseInt(macMatch[2], 10);
            const ifaceStr = macMatch[3].replace('GigabitEthernet', 'Gi').replace('TenGigabitEthernet', 'Te');
            const matchedPort = result.ports.find(p => p.name === ifaceStr);
            result.macTable.push({
                mac: rawMac,
                vlanId,
                portId: matchedPort ? matchedPort.id : 1,
                portName: ifaceStr,
                type: 'static',
                age: 0
            });
        }
    }

    result.system.stackCount = stackSet.size > 0 ? stackSet.size : 1;

    // 추가 명령어 결과들(show interfaces status, show vlan brief, show power inline, show mac address-table, show ip arp) 파싱
    parseInterfacesStatus(rawText, result);
    parseVlanBrief(rawText, result);
    parsePowerInline(rawText, result);
    parseMacAddressTable(rawText, result);
    parseArpTable(rawText, result);

    result.vlans.sort((a, b) => a.id - b.id);
    return result;
}

/**
 * show interfaces status 텍스트 파싱 -> 실시간 링크 상태(Up/Down), 속도, 듀플렉스, 실제 VLAN 매핑
 */
function parseInterfacesStatus(rawText, switchConfig) {
    if (!rawText || typeof rawText !== 'string') return switchConfig;

    const lines = rawText.split(/\r?\n/);
    for (const line of lines) {
        // Gi1/0/1   Name...   connected   1   a-full  a-1000 10/100/1000BaseTX
        // Gi1/0/2             notconnect  1     auto    auto 10/100/1000BaseTX
        const m = line.match(/^(Gi\d+\/\d+\/\d+|Te\d+\/\d+\/\d+|Fa\d+)\s+(.*?)\s+(connected|notconnect|disabled|err-disabled)\s+(\S+)\s+(\S+)\s+(\S+)/i);
        if (m) {
            const ifName = m[1];
            const portDesc = m[2].trim();
            const status = m[3].toLowerCase();
            const vlanCol = m[4];
            const duplexCol = m[5];
            const speedCol = m[6];

            const port = switchConfig.ports.find(p => p.name.toLowerCase() === ifName.toLowerCase());
            if (port) {
                if (status === 'connected') {
                    port.linkState = 'up';
                } else if (status === 'disabled') {
                    port.adminState = 'down';
                    port.linkState = 'down';
                } else {
                    port.linkState = 'down';
                }

                if (speedCol !== 'auto' && speedCol !== '--') {
                    port.speed = speedCol.replace('a-', '').replace('1000', '1G').replace('10000', '10G').replace('100', '100M').replace('10', '10M');
                }
                if (duplexCol !== 'auto' && duplexCol !== '--') {
                    port.duplex = duplexCol.replace('a-', '');
                }
                if (portDesc && !port.description) {
                    port.description = portDesc;
                }
                if (vlanCol.toLowerCase() === 'trunk') {
                    port.mode = 'trunk';
                } else if (!isNaN(Number(vlanCol))) {
                    port.mode = 'access';
                    port.pvid = Number(vlanCol);
                }
            }
        }
    }
    return switchConfig;
}

/**
 * show vlan brief 텍스트 파싱 -> 실제 스위치에 등록된 모든 VLAN 수집
 */
function parseVlanBrief(rawText, switchConfig) {
    if (!rawText || typeof rawText !== 'string') return switchConfig;

    const lines = rawText.split(/\r?\n/);
    let inVlanSection = false;

    for (const line of lines) {
        if (line.includes('VLAN') && line.includes('Name') && line.includes('Status')) {
            inVlanSection = true;
            continue;
        }
        if (inVlanSection && line.startsWith('----')) continue;

        if (inVlanSection) {
            // 10   MANAGEMENT                       active    Gi1/0/1...
            const vlanMatch = line.match(/^(\d+)\s+([A-Za-z0-9_\-\.\s]{1,32})\s+(active|act\/lshut|suspend)/i);
            if (vlanMatch) {
                const vlanId = parseInt(vlanMatch[1], 10);
                const vlanName = vlanMatch[2].trim();

                let existing = switchConfig.vlans.find(v => v.id === vlanId);
                if (!existing) {
                    switchConfig.vlans.push({
                        id: vlanId,
                        name: vlanName,
                        description: '',
                        isSystem: (vlanId === 1 || vlanId >= 1002)
                    });
                } else if (existing.name.startsWith('VLAN') && !vlanName.startsWith('VLAN')) {
                    existing.name = vlanName;
                }
            }
            if (line.startsWith('VLAN') && line.includes('Type')) {
                inVlanSection = false;
            }
        }
    }
    return switchConfig;
}

/**
 * show power inline 텍스트 파싱 (스택 스위치 전체 지원)
 */
function parsePowerInline(rawText, switchConfig) {
    if (!rawText || typeof rawText !== 'string') return switchConfig;

    const lines = rawText.split(/\r?\n/);
    let totalAvail = 0.0;
    let totalUsed = 0.0;
    let hasSummary = false;

    for (const line of lines) {
        // Module Available:370.0(w)  Used:125.4(w)  Remaining:244.6(w)
        const summaryMatch = line.match(/Available:\s*([\d.]+)\s*\(w\)\s+Used:\s*([\d.]+)\s*\(w\)\s+Remaining:\s*([\d.]+)\s*\(w\)/i);
        if (summaryMatch) {
            hasSummary = true;
            totalAvail += parseFloat(summaryMatch[1]);
            totalUsed += parseFloat(summaryMatch[2]);
            continue;
        }

        // Gi1/0/1   auto   on         15.4    Cisco IP Phone 7962  3     30.0
        // Gi2/0/5   auto   on         6.3     AIR-CAP2702I         4     30.0
        const portMatch = line.match(/^(Gi\d+\/\d+\/\d+|Te\d+\/\d+\/\d+)\s+(\S+)\s+(\S+)\s+([\d.]+)\s+(.*?)\s+([0-9n\/a]+)\s+([\d.]+)/i);
        if (portMatch) {
            const ifName = portMatch[1];
            const adminMode = portMatch[2].toLowerCase();
            const status = portMatch[3].toLowerCase();
            const watts = parseFloat(portMatch[4]);
            const device = portMatch[5].trim();

            const targetPort = switchConfig.ports.find(p => p.name.toLowerCase() === ifName.toLowerCase());
            if (targetPort) {
                targetPort.poe = {
                    mode: adminMode,
                    status: status,
                    powerWatts: watts,
                    device: device || (status === 'on' ? 'PoE Powered Device' : 'No PD detected'),
                    maxWatts: parseFloat(portMatch[7]) || 30.0
                };
                if (status === 'on') {
                    targetPort.linkState = 'up';
                }
            }
        }
    }

    if (hasSummary && totalAvail > 0) {
        switchConfig.poeSummary = {
            availableWatts: totalAvail,
            usedWatts: totalUsed,
            remainingWatts: Math.max(0, totalAvail - totalUsed)
        };
    } else {
        // 요약 라인이 없으면 포트별 소비 전력 합산
        let calculatedUsed = 0.0;
        switchConfig.ports.forEach(p => {
            if (p.poe && p.poe.powerWatts) calculatedUsed += p.poe.powerWatts;
        });
        const defaultBudget = (switchConfig.system.stackCount || 1) * 370.0;
        switchConfig.poeSummary = {
            availableWatts: defaultBudget,
            usedWatts: parseFloat(calculatedUsed.toFixed(1)),
            remainingWatts: parseFloat((defaultBudget - calculatedUsed).toFixed(1))
        };
    }

    return switchConfig;
}

/**
 * MAC 주소 OUI 접두사를 기반으로 장치 제조사 식별
 */
const VENDOR_OUI_MAP = {
    '00:BF:77': 'Cisco Systems',
    '00:50:56': 'VMware ESXi',
    'CC:D5:39': 'Cisco Systems',
    'B4:E9:B0': 'Cisco Systems (Local SVI)',
    '00:00:0C': 'Cisco Systems',
    '70:CA:9B': 'Samsung Electronics',
    '00:24:54': 'Samsung Electronics',
    'F8:E0:79': 'Samsung Electronics',
    '54:77:8A': 'Apple, Inc.',
    'A4:83:E7': 'Apple, Inc.',
    'BC:D0:74': 'Apple, Inc.',
    'AC:BC:32': 'Apple, Inc.',
    '0C:85:25': 'Intel Corporate',
    '00:1A:A0': 'Intel Corporate',
    'A4:4C:C8': 'Intel Corporate',
    '94:FF:06': 'LG Electronics',
    '00:1C:62': 'LG Electronics',
    '3C:D9:2B': 'HP Inc.',
    '00:1E:0B': 'HP Inc.',
    '70:85:C2': 'Dell Inc.',
    '18:66:DA': 'Dell Inc.',
    '00:1A:2B': 'Ayecom Technology',
    '00:08:E3': 'Cisco-Linksys',
    '00:11:32': 'Synology Inc.'
};

function getMacVendor(mac) {
    if (!mac) return 'Network Device';
    const prefix = mac.slice(0, 8).toUpperCase();
    return VENDOR_OUI_MAP[prefix] || 'Network Device (OUI)';
}

/**
 * show mac address-table 텍스트 파싱
 */
function parseMacAddressTable(rawText, switchConfig) {
    if (!rawText || typeof rawText !== 'string') return switchConfig;

    const lines = rawText.split(/\r?\n/);
    for (const line of lines) {
        //   1    001a.2b3c.4d5e    DYNAMIC     Gi1/0/1
        //  10    7085.c255.01a2    STATIC      Gi2/0/5
        const m = line.match(/^\s*(\d+)\s+([0-9a-fA-F.:-]+)\s+(DYNAMIC|STATIC)\s+(Gi\d+\/\d+\/\d+|Te\d+\/\d+\/\d+|Po\d+)/i);
        if (m) {
            const vlanId = parseInt(m[1], 10);
            const rawMac = m[2].replace(/[:.-]/g, '').toUpperCase().match(/.{1,2}/g).join(':');
            const type = m[3].toLowerCase();
            const portName = m[4];

            const port = switchConfig.ports.find(p => p.name.toLowerCase() === portName.toLowerCase());
            const swMatch = portName.match(/[a-zA-Z]+(\d+)\//);
            const switchNum = swMatch ? parseInt(swMatch[1], 10) : (port ? port.switchNum : 1);
            const isTrunk = (port && port.mode === 'trunk') || portName.includes('49') || portName.includes('50') || portName.includes('51') || portName.includes('52');

            const exists = switchConfig.macTable.some(entry => entry.mac === rawMac && entry.vlanId === vlanId);
            if (!exists) {
                switchConfig.macTable.push({
                    mac: rawMac,
                    ipAddress: null,
                    vlanId,
                    portId: port ? port.id : 1,
                    portName: portName,
                    switchNum: switchNum,
                    deviceName: `Client-${rawMac.slice(-5).replace(':', '')}`,
                    vendor: getMacVendor(rawMac),
                    type: type,
                    interfaceType: isTrunk ? 'trunk' : 'access',
                    age: type === 'dynamic' ? Math.floor(Math.random() * 200) + 10 : 0
                });
            }
        }
    }
    return switchConfig;
}

/**
 * show ip arp 출력 파싱 -> MAC 테이블 및 각 포트 클라이언트에 실시간 IPv4 주소 매핑
 */
function parseArpTable(rawText, switchConfig) {
    if (!rawText || typeof rawText !== 'string') return switchConfig;

    const lines = rawText.split(/\r?\n/);
    for (const line of lines) {
        // Protocol  Address          Age (min)  Hardware Addr   Type   Interface
        // Internet  10.101.241.6            -   b4e9.b0f8.a780  ARPA   Vlan241
        // Internet  10.101.2.109            4   70ca.9bc9.6d24  ARPA   Vlan2
        const m = line.match(/^Internet\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+([0-9a-fA-F.:-]+)\s+ARPA\s+(\S+)/i);
        if (m) {
            const ip = m[1];
            const rawMac = m[3].replace(/[:.-]/g, '').toUpperCase().match(/.{1,2}/g).join(':');
            const iface = m[4];

            // macTable에서 일치하는 MAC 항목 검색 및 IP 바인딩
            const entry = switchConfig.macTable.find(e => e.mac === rawMac);
            if (entry) {
                entry.ipAddress = ip;
            } else {
                const vlanMatch = iface.match(/Vlan(\d+)/i);
                const vlanId = vlanMatch ? parseInt(vlanMatch[1], 10) : 1;
                switchConfig.macTable.push({
                    mac: rawMac,
                    ipAddress: ip,
                    vlanId,
                    portId: 1,
                    portName: iface,
                    switchNum: 1,
                    deviceName: `Client-${ip.split('.').slice(-2).join('-')}`,
                    vendor: getMacVendor(rawMac),
                    type: 'dynamic',
                    interfaceType: 'access',
                    age: m[2] === '-' ? 0 : (parseInt(m[2], 10) * 60 || 30)
                });
            }
        }
    }

    // 각 포트의 primary connectedClient 정보 갱신
    if (switchConfig.ports && switchConfig.macTable) {
        switchConfig.ports.forEach(p => {
            const clients = switchConfig.macTable.filter(m => m.portId === p.id || m.portName === p.name);
            if (clients.length > 0) {
                p.connectedClient = {
                    ipAddress: clients[0].ipAddress,
                    mac: clients[0].mac,
                    deviceName: clients[0].deviceName,
                    vendor: clients[0].vendor
                };
                p.clientCount = clients.length;
            }
        });
    }

    return switchConfig;
}

/**
 * 변경 사항을 분석하여 실제 Cisco 2960-S 적용 CLI 명령어 스크립트 생성
 */
function generateCiscoDiffCommands(oldPortList, newPortList, newVlans = []) {
    const commands = ['configure terminal'];

    newPortList.forEach(np => {
        const op = (oldPortList || []).find(p => p.id === np.id || p.name === np.name);
        const ifaceCmds = [];

        if (!op) return;

        if (np.adminState !== op.adminState) {
            ifaceCmds.push(np.adminState === 'down' ? 'shutdown' : 'no shutdown');
        }

        if (np.description !== op.description) {
            ifaceCmds.push(np.description ? `description ${np.description}` : 'no description');
        }

        if (np.speed !== op.speed) {
            ifaceCmds.push(np.speed === 'auto' ? 'speed auto' : `speed ${np.speed.replace('G', '000').replace('M', '')}`);
        }
        if (np.duplex !== op.duplex) {
            ifaceCmds.push(np.duplex === 'auto' ? 'duplex auto' : `duplex ${np.duplex}`);
        }

        if (np.mode !== op.mode) {
            ifaceCmds.push(`switchport mode ${np.mode}`);
        }
        if (np.pvid !== op.pvid) {
            if (np.mode === 'access') {
                ifaceCmds.push(`switchport access vlan ${np.pvid}`);
            } else {
                ifaceCmds.push(`switchport trunk native vlan ${np.pvid}`);
            }
        }

        if (np.poe && op.poe && np.poe.mode !== op.poe.mode) {
            ifaceCmds.push(`power inline ${np.poe.mode}`);
        }

        if (np.portSecurity && op.portSecurity) {
            if (np.portSecurity.enabled !== op.portSecurity.enabled) {
                ifaceCmds.push(np.portSecurity.enabled ? 'switchport port-security' : 'no switchport port-security');
            }
            if (np.portSecurity.maxMac !== op.portSecurity.maxMac) {
                ifaceCmds.push(`switchport port-security maximum ${np.portSecurity.maxMac}`);
            }
            if (np.portSecurity.violationAction !== op.portSecurity.violationAction) {
                ifaceCmds.push(`switchport port-security violation ${np.portSecurity.violationAction}`);
            }
        }

        if (ifaceCmds.length > 0) {
            commands.push(`interface ${np.fullName || np.name}`);
            commands.push(...ifaceCmds.map(c => ` ${c}`));
            commands.push(' exit');
        }
    });

    if (newVlans && newVlans.length > 0) {
        newVlans.forEach(v => {
            if (v.id > 1) {
                commands.push(`vlan ${v.id}`);
                commands.push(` name ${v.name}`);
                commands.push(' exit');
            }
        });
    }

    commands.push('end');
    commands.push('write memory');
    return commands;
}

module.exports = {
    parseCiscoConfig,
    parseInterfacesStatus,
    parseVlanBrief,
    parsePowerInline,
    parseMacAddressTable,
    parseArpTable,
    getMacVendor,
    generateCiscoDiffCommands,
    calculateSubnetDetails
};
