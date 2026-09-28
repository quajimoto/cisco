// scratch/test_cisco_autoreg.js
const http = require('http');

async function testCiscoImportAutoReg() {
    console.log('=== Cisco 장비 연동 시 자동 장비 분리 등록 테스트 ===');

    // 1. 로그인
    const loginData = JSON.stringify({ username: 'admin', password: 'Admin@1234!' });
    const loginRes = await makeRequest('/api/auth/login', 'POST', loginData);
    const cookie = loginRes.headers['set-cookie'] ? loginRes.headers['set-cookie'][0].split(';')[0] : '';
    const csrfToken = JSON.parse(loginRes.body).csrfToken;

    // 2. 신규 Cisco running-config 텍스트 가져오기 (가상 IP 10.101.241.99, 호스트명 CISCO_BRANCH_SW)
    const sampleConfig = `
hostname CISCO_BRANCH_SW
interface Vlan1
 ip address 10.101.241.99 255.255.255.0
!
interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 2
!
interface GigabitEthernet1/0/2
 switchport mode access
 switchport access vlan 10
!
`;

    const importRes = await makeRequest('/api/cisco/import', 'POST', JSON.stringify({
        rawConfig: sampleConfig,
        createAsNew: true
    }), cookie, csrfToken);

    console.log('Import 결과:', JSON.parse(importRes.body));

    // 3. 등록된 장비 목록 확인
    const devicesRes = await makeRequest('/api/devices', 'GET', null, cookie);
    const devicesData = JSON.parse(devicesRes.body);
    console.log('현재 등록된 장비 수:', devicesData.devices.length);
    console.log('활성 장비 ID:', devicesData.activeDeviceId);
    const addedDev = devicesData.devices.find(d => d.ipAddress === '10.101.241.99' || d.name === 'CISCO_BRANCH_SW');
    console.log('신규 자동 추가된 장비:', addedDev ? addedDev.name : '없음');

    if (addedDev) {
        // 정리: 테스트 장비 삭제
        await makeRequest(`/api/devices/${addedDev.id}`, 'DELETE', null, cookie, csrfToken);
        console.log('테스트 장비 정리 완료!');
    }
}

function makeRequest(path, method, body, cookie = null, csrfToken = null) {
    return new Promise((resolve, reject) => {
        const headers = { 'Content-Type': 'application/json' };
        if (cookie) headers['Cookie'] = cookie;
        if (csrfToken) headers['X-CSRF-Token'] = csrfToken;

        const req = http.request({
            hostname: 'localhost',
            port: 8080,
            path,
            method,
            headers
        }, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
        });
        req.on('error', reject);
        if (body) req.write(body);
        req.end();
    });
}

testCiscoImportAutoReg();
