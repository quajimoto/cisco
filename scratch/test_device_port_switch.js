// scratch/test_device_port_switch.js
// 4대 네트워크 장비 전환 시 포트 정보(adminState, linkState, portNum, switchNum 등) 정상 노출 검증

const http = require('http');

function req(path, method = 'GET', body = null, headers = {}) {
    return new Promise((resolve, reject) => {
        const u = new URL('http://localhost:8080' + path);
        const opt = {
            hostname: u.hostname,
            port: u.port,
            path: u.pathname + u.search,
            method: method,
            headers: {
                'Content-Type': 'application/json',
                ...headers
            }
        };
        const r = http.request(opt, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                let json = null;
                try { json = JSON.parse(data); } catch(e) {}
                resolve({ status: res.statusCode, headers: res.headers, body: json || data });
            });
        });
        r.on('error', reject);
        if (body) r.write(typeof body === 'string' ? body : JSON.stringify(body));
        r.end();
    });
}

(async () => {
    // 1. Login
    const loginRes = await req('/api/auth/login', 'POST', { username: 'admin', password: 'Admin@1234!' });
    const cookie = loginRes.headers['set-cookie'] ? loginRes.headers['set-cookie'][0].split(';')[0] : '';
    const csrfToken = loginRes.body.csrfToken;
    const authHeaders = { 'Cookie': cookie, 'x-csrf-token': csrfToken };

    console.log('[1] Login Status:', loginRes.status);

    // 2. Fetch Devices
    const devRes = await req('/api/devices', 'GET', null, authHeaders);
    console.log('[2] Total Devices Registered:', devRes.body.devices.length);

    let allPassed = true;

    for (const dev of devRes.body.devices) {
        console.log(`\n--- Testing Device Switch: ${dev.name} (${dev.id}, ${dev.ipAddress}) ---`);
        const switchRes = await req('/api/devices/active', 'POST', { deviceId: dev.id }, authHeaders);
        if (switchRes.status !== 200) {
            console.error('  FAIL: switch status is', switchRes.status);
            allPassed = false;
            continue;
        }

        const [statusRes, portsRes, vlansRes] = await Promise.all([
            req('/api/switch/status', 'GET', null, authHeaders),
            req('/api/switch/ports', 'GET', null, authHeaders),
            req('/api/switch/vlans', 'GET', null, authHeaders)
        ]);

        console.log(`  Status API: ${statusRes.status} | Active Ports: ${statusRes.body.activePorts}/${statusRes.body.totalPorts}`);
        console.log(`  Ports API: ${portsRes.status} | Total Ports Returned: ${portsRes.body.ports ? portsRes.body.ports.length : 0}`);
        console.log(`  VLANs API: ${vlansRes.status} | Total VLANs: ${vlansRes.body.vlans ? vlansRes.body.vlans.length : 0}`);

        if (!portsRes.body.ports || portsRes.body.ports.length === 0) {
            console.error(`  FAIL: No ports returned for ${dev.name}`);
            allPassed = false;
            continue;
        }

        // Validate each port
        let invalidPorts = 0;
        portsRes.body.ports.forEach((p, i) => {
            if (!p.adminState || !p.linkState || !p.switchNum || !p.portNum) {
                invalidPorts++;
                if (invalidPorts <= 3) {
                    console.error(`  Invalid Port at index ${i}:`, p);
                }
            }
        });

        if (invalidPorts > 0) {
            console.error(`  FAIL: ${invalidPorts} ports missing required fields in ${dev.name}`);
            allPassed = false;
        } else {
            console.log(`  PASS: All ${portsRes.body.ports.length} ports validated successfully (adminState, linkState, switchNum, portNum OK)!`);
        }
    }

    if (allPassed) {
        console.log('\n🎉 ALL 4 DEVICES SUCCESSFULLY SWITCHED & VERIFIED WITH 100% PORT DATA INTEGRITY!');
    } else {
        console.error('\n❌ SOME DEVICES FAILED PORT VALIDATION!');
        process.exit(1);
    }
})();
