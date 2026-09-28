// core/cliGenerator.js
// 시큐어코딩 가이드: OS 명령 삽입(CWE-78)을 원천 방지하기 위해 
// 실제 쉘(shell/exec)을 호출하지 않고 순수 애플리케이션 레벨에서 Cisco L2 스위치 CLI를 시뮬레이션 및 생성합니다.

/**
 * L2 스위치 설정 객체를 기반으로 Cisco 호환 Running-Config CLI 스크립트 생성
 */
function generateRunningConfig(config) {
    const lines = [];
    const dateStr = new Date().toISOString();

    lines.push(`! Current configuration generated on ${dateStr}`);
    lines.push(`! Device: ${config.system.model}`);
    lines.push(`! Software Version: ${config.system.firmwareVersion}`);
    lines.push(`!`);
    lines.push(`version 15.2`);
    lines.push(`no service pad`);
    lines.push(`service timestamps debug datetime msec`);
    lines.push(`service timestamps log datetime msec`);
    lines.push(`service password-encryption`);
    lines.push(`!`);
    lines.push(`hostname ${config.system.hostname}`);
    lines.push(`!`);
    lines.push(`spanning-tree mode ${config.stp.mode}`);
    lines.push(`spanning-tree extend system-id`);
    lines.push(`spanning-tree vlan 1-4094 priority ${config.stp.priority}`);
    lines.push(`!`);

    // VLAN 정의
    lines.push(`! --- VLAN Configuration ---`);
    for (const vlan of config.vlans) {
        lines.push(`vlan ${vlan.id}`);
        lines.push(` name ${vlan.name}`);
    }
    lines.push(`!`);

    // LACP / LAG 포트채널
    if (config.lagGroups && config.lagGroups.length > 0) {
        lines.push(`! --- Port-Channel Interfaces ---`);
        for (const lag of config.lagGroups) {
            lines.push(`interface Port-channel${lag.id}`);
            if (lag.description) lines.push(` description ${lag.description}`);
            lines.push(` switchport mode trunk`);
            lines.push(`!`);
        }
    }

    // 물리 인터페이스 설정 (1 ~ 28)
    lines.push(`! --- Physical Interfaces ---`);
    for (const port of config.ports) {
        lines.push(`interface ${port.name}`);
        if (port.description) {
            lines.push(` description ${port.description}`);
        }
        
        if (port.adminState === 'down') {
            lines.push(` shutdown`);
        } else {
            lines.push(` no shutdown`);
        }

        if (port.speed !== 'auto') {
            lines.push(` speed ${port.speed.replace('G', '000').replace('M', '')}`);
        }
        if (port.duplex !== 'auto') {
            lines.push(` duplex ${port.duplex}`);
        }
        if (port.mtu !== 1500) {
            lines.push(` mtu ${port.mtu}`);
        }

        // 스위치포트 모드
        if (port.mode === 'access') {
            lines.push(` switchport mode access`);
            lines.push(` switchport access vlan ${port.pvid}`);
        } else {
            lines.push(` switchport mode trunk`);
            lines.push(` switchport trunk native vlan ${port.pvid}`);
            if (port.taggedVlans && port.taggedVlans.length > 0) {
                lines.push(` switchport trunk allowed vlan ${port.taggedVlans.join(',')}`);
            }
        }

        // 포트 보안
        if (port.portSecurity && port.portSecurity.enabled) {
            lines.push(` switchport port-security`);
            lines.push(` switchport port-security maximum ${port.portSecurity.maxMac}`);
            lines.push(` switchport port-security violation ${port.portSecurity.violationAction}`);
            if (port.portSecurity.sticky) {
                lines.push(` switchport port-security mac-address sticky`);
            }
        }

        // STP 설정
        if (port.stp) {
            if (port.stp.edgePort) {
                lines.push(` spanning-tree portfast`);
            }
            if (port.stp.bpduGuard) {
                lines.push(` spanning-tree bpduguard enable`);
            }
        }

        // LACP 멤버 체크
        if (config.lagGroups) {
            const memberLag = config.lagGroups.find(g => g.members.includes(port.id));
            if (memberLag) {
                lines.push(` channel-group ${memberLag.id} mode ${memberLag.mode}`);
            }
        }

        lines.push(`!`);
    }

    // Static MAC 등록
    lines.push(`! --- Static MAC Address Table ---`);
    const staticMacs = config.macTable.filter(m => m.type === 'static');
    for (const sm of staticMacs) {
        const p = config.ports.find(x => x.id === sm.portId);
        const pName = p ? p.name : `Gi1/0/${sm.portId}`;
        lines.push(`mac address-table static ${sm.mac} vlan ${sm.vlanId} interface ${pName}`);
    }
    lines.push(`!`);

    // 관리 IP 및 기본 게이트웨이
    lines.push(`! --- Management Interface ---`);
    lines.push(`interface vlan 1`);
    lines.push(` ip address ${config.system.ipAddress} ${config.system.subnetMask}`);
    lines.push(` no shutdown`);
    lines.push(`!`);
    lines.push(`ip default-gateway ${config.system.defaultGateway}`);
    lines.push(`ntp server ${config.system.ntpServer}`);
    lines.push(`mac address-table aging-time ${config.system.macAgingTime}`);
    lines.push(`!`);
    lines.push(`end`);

    return lines.join('\n');
}

/**
 * 가상 콘솔 터미널 명령어 해석기 (안전한 소프트웨어 시뮬레이션)
 */
function executeVirtualCliCommand(cmdStr, config) {
    const trimmed = (cmdStr || '').trim();
    if (!trimmed) return '';

    const lower = trimmed.toLowerCase();

    // 1. Help / ?
    if (lower === '?' || lower === 'help') {
        return [
            'Secure L2 Switch CLI Virtual Console (Sandboxed Simulator)',
            'Available Commands:',
            '  show version                   - Display system hardware & firmware info',
            '  show running-config            - Display current active configuration',
            '  show vlan [brief]              - Display VLAN status and port membership',
            '  show interfaces status         - Display interface link, speed, duplex status',
            '  show mac address-table         - Display MAC address forwarding table',
            '  show spanning-tree             - Display STP / RSTP bridge and port state',
            '  show etherchannel summary      - Display LACP Port-Channel status',
            '  show port-security             - Display Port Security status',
            '  ping <ip_address>              - Send ICMP echo requests (Simulated)',
            '  write memory / copy run start  - Save running configuration to storage',
            '  clear mac address-table        - Clear dynamic MAC entries',
            '  exit / quit                    - End CLI session'
        ].join('\n');
    }

    // 2. show version
    if (lower === 'show version' || lower === 'sh ver') {
        return [
            `Secure L2 Switch Software, Version ${config.system.firmwareVersion}`,
            `Technical Support: https://antigravity.security`,
            `System Uptime: Switch running since ${new Date(config.system.bootTime).toLocaleString()}`,
            `System image file is "flash:secure-l2-sw.bin"`,
            `Model Number: ${config.system.model}`,
            `System Serial Number: ${config.system.serialNumber}`,
            `Base Ethernet MAC Address: 00:1A:2B:FF:00:01`,
            `24 Gigabit Ethernet interfaces`,
            `4 Ten Gigabit Ethernet interfaces`,
            `Configuration register is 0x2102`
        ].join('\n');
    }

    // 3. show running-config
    if (lower === 'show running-config' || lower === 'sh run') {
        return generateRunningConfig(config);
    }

    // 4. show vlan / show vlan brief
    if (lower.startsWith('show vlan') || lower.startsWith('sh vlan')) {
        const header = 'VLAN Name                             Status    Ports\n---- -------------------------------- --------- -------------------------------';
        const rows = config.vlans.map(v => {
            // 해당 VLAN에 속한 포트 목록
            const assignedPorts = config.ports
                .filter(p => p.pvid === v.id || (p.taggedVlans && p.taggedVlans.includes(v.id)))
                .map(p => p.name.replace('GigabitEthernet', 'Gi').replace('TenGigabitEthernet', 'Te'))
                .join(', ');
            
            const vlanName = v.name.padEnd(32, ' ');
            const vlanId = String(v.id).padStart(4, ' ');
            return `${vlanId} ${vlanName} active    ${assignedPorts || 'none'}`;
        });
        return `${header}\n${rows.join('\n')}`;
    }

    // 5. show interfaces status
    if (lower.startsWith('show interfaces status') || lower.startsWith('sh int status')) {
        const header = 'Port      Name               Status       Vlan       Duplex  Speed Type\n--------- ------------------ ------------ ---------- ------- ----- ------------';
        const rows = config.ports.map(p => {
            const portName = p.name.padEnd(9, ' ');
            const desc = (p.description || '').substring(0, 18).padEnd(18, ' ');
            const status = (p.linkState === 'up' ? 'connected' : 'notconnect').padEnd(12, ' ');
            const vlan = (p.mode === 'trunk' ? 'trunk' : String(p.pvid)).padEnd(10, ' ');
            const duplex = (p.linkState === 'up' ? p.duplex : 'auto').padEnd(7, ' ');
            const speed = (p.linkState === 'up' ? p.speed : 'auto').padEnd(5, ' ');
            const type = (p.type === 'RJ45-1G' ? '10/100/1000BaseTX' : '10GBase-SR');
            return `${portName} ${desc} ${status} ${vlan} ${duplex} ${speed} ${type}`;
        });
        return `${header}\n${rows.join('\n')}`;
    }

    // 6. show mac address-table
    if (lower.startsWith('show mac') || lower.startsWith('sh mac')) {
        const header = '          Mac Address Table\n-------------------------------------------\nVlan    Mac Address       Type        Ports\n----    -----------       --------    -----';
        const rows = config.macTable.map(m => {
            const p = config.ports.find(x => x.id === m.portId);
            const pName = p ? p.name : `Gi1/0/${m.portId}`;
            const vlanStr = String(m.vlanId).padStart(4, ' ');
            const macStr = m.mac.padEnd(17, ' ');
            const typeStr = m.type.toUpperCase().padEnd(11, ' ');
            return `${vlanStr}    ${macStr} ${typeStr} ${pName}`;
        });
        return `${header}\n${rows.join('\n')}\nTotal Mac Addresses for this criterion: ${config.macTable.length}`;
    }

    // 7. show spanning-tree
    if (lower.startsWith('show spanning') || lower.startsWith('sh span')) {
        return [
            `MST00 (RSTP Mode)`,
            `  Spanning tree enabled protocol ${config.stp.mode.toUpperCase()}`,
            `  Root ID    Priority    ${config.stp.priority}`,
            `             Address     00:1A:2B:FF:00:01`,
            `             This bridge is the root`,
            `             Hello Time   ${config.stp.helloTime} sec  Max Age ${config.stp.maxAge} sec  Forward Delay ${config.stp.forwardDelay} sec`,
            ``,
            `Interface        Role Sts Cost      Prio.Nbr Type`,
            `---------------- ---- --- --------- -------- --------------------------------`,
            ...config.ports.filter(p => p.linkState === 'up').map(p => {
                const name = p.name.padEnd(16, ' ');
                const sts = p.stp.state.substring(0, 3).toUpperCase().padEnd(3, ' ');
                const type = p.stp.edgePort ? 'P2p Edge' : 'P2p';
                return `${name} Desg ${sts} ${p.stp.cost}         128.${p.id}   ${type}`;
            })
        ].join('\n');
    }

    // 8. ping <ip>
    if (lower.startsWith('ping ')) {
        const target = trimmed.split(/\s+/)[1];
        return [
            `Type escape sequence to abort.`,
            `Sending 5, 100-byte ICMP Echos to ${target}, timeout is 2 seconds:`,
            `!!!!!`,
            `Success rate is 100 percent (5/5), round-trip min/avg/max = 1/2/4 ms`
        ].join('\n');
    }

    // 9. write memory / copy run start
    if (lower === 'write' || lower === 'write memory' || lower === 'wr' || lower === 'copy run start') {
        return `Building configuration...\n[OK] Configuration successfully saved to non-volatile NVRAM.`;
    }

    // 10. clear mac address-table
    if (lower.startsWith('clear mac address-table dynamic')) {
        return `Dynamic MAC address table entries flushed.`;
    }

    return `% Unrecognized command or invalid syntax: "${trimmed}". Type "?" for help.`;
}

module.exports = {
    generateRunningConfig,
    executeVirtualCliCommand
};
