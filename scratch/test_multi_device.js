// scratch/test_multi_device.js
// 다중 장비 추가, 목록 조회 및 이전/다른 장비 선택 및 전환(Switch) 기능 검증

const http = require('http');

function request(options, body = null) {
    return new Promise((resolve, reject) => {
        const req = http.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                let parsed = data;
                try { parsed = JSON.parse(data); } catch(e) {}
                resolve({ statusCode: res.statusCode, headers: res.headers, body: parsed });
            });
        });
        req.on('error', reject);
        if (body) req.write(typeof body === 'string' ? body : JSON.stringify(body));
        req.end();
    });
}

async function runTest() {
    console.log('=== [1] Admin 로그인 및 인증 토큰 획득 ===');
    const loginRes = await request({
        hostname: 'localhost',
        port: 8080,
        path: '/api/auth/login',
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    }, { username: 'admin', password: 'Admin@1234!' });

    const cookieHeader = loginRes.headers['set-cookie'];
    const sessionIdCookie = (Array.isArray(cookieHeader) ? cookieHeader[0] : cookieHeader).split(';')[0];
    const csrfToken = loginRes.body.csrfToken;

    const authHeaders = {
        'Cookie': sessionIdCookie,
        'X-CSRF-Token': csrfToken,
        'Content-Type': 'application/json'
    };
    console.log('-> 로그인 성공! 세션 확보');

    console.log('\n=== [2] 등록된 전체 장비 목록 조회 (GET /api/devices) ===');
    const devListRes = await request({
        hostname: 'localhost',
        port: 8080,
        path: '/api/devices',
        method: 'GET',
        headers: authHeaders
    });
    console.log(`-> 총 ${devListRes.body.devices.length}대 장비 등록됨 (현재 활성 ID: ${devListRes.body.activeDeviceId})`);
    devListRes.body.devices.forEach((d, idx) => {
        console.log(`   ${idx + 1}. [${d.id}] ${d.name} (${d.ipAddress}) - ${d.model} [${d.portCount} 포트]`);
    });

    console.log('\n=== [3] 현재 활성 장비 상태 확인 (GET /api/switch/status) ===');
    const status1 = await request({
        hostname: 'localhost',
        port: 8080,
        path: '/api/switch/status',
        method: 'GET',
        headers: authHeaders
    });
    console.log(`-> 현재 활성 장비: [${status1.body.system.hostname}] IP: ${status1.body.system.ipAddress}, 포트수: ${status1.body.totalPorts}`);

    console.log('\n=== [4] 1층 스위치(OFFICE_1F_SW_2)로 장비 전환 (POST /api/devices/active) ===');
    const switchRes1 = await request({
        hostname: 'localhost',
        port: 8080,
        path: '/api/devices/active',
        method: 'POST',
        headers: authHeaders
    }, { deviceId: 'dev-office-1f-sw2' });
    console.log('-> 전환 결과 메시지:', switchRes1.body.message);

    const status2 = await request({
        hostname: 'localhost',
        port: 8080,
        path: '/api/switch/status',
        method: 'GET',
        headers: authHeaders
    });
    console.log(`-> 전환 후 활성 장비: [${status2.body.system.hostname}] IP: ${status2.body.system.ipAddress}, 포트수: ${status2.body.totalPorts} (24x RJ45 PoE+ + 4x SFP+)`);
    if (status2.body.system.hostname !== 'OFFICE_1F_SW_2') {
        throw new Error('장비 전환 실패! 기대값: OFFICE_1F_SW_2, 실제값: ' + status2.body.system.hostname);
    }

    console.log('\n=== [5] 새로운 3층 스위치(OFFICE_3F_SW_3) 추가 등록 (POST /api/devices) ===');
    const createRes = await request({
        hostname: 'localhost',
        port: 8080,
        path: '/api/devices',
        method: 'POST',
        headers: authHeaders
    }, {
        name: 'OFFICE_3F_SW_3',
        ipAddress: '10.101.241.8',
        model: 'Cisco Catalyst 2960-S 48-Port PoE+ (WS-C2960S-48FPD-L)',
        templateType: 'cisco-2960s-48p',
        location: '본관 3층 개발통신실 랙 #1',
        description: '3층 인공지능/클라우드 개발팀 전용',
        makeActive: true
    });
    console.log('-> 신규 장비 등록 성공:', createRes.body.message);
    const newDevId = createRes.body.device.id;
    console.log(`   생성된 ID: ${newDevId}, 포트수: ${createRes.body.device.portCount}`);

    const status3 = await request({
        hostname: 'localhost',
        port: 8080,
        path: '/api/switch/status',
        method: 'GET',
        headers: authHeaders
    });
    console.log(`-> 신규 등록 장비 활성화 확인: [${status3.body.system.hostname}] 포트수: ${status3.body.totalPorts}`);

    console.log('\n=== [6] 이전 장비(OFFICE_2F_SW_1)로 다시 전환 (POST /api/devices/active) ===');
    const switchResBack = await request({
        hostname: 'localhost',
        port: 8080,
        path: '/api/devices/active',
        method: 'POST',
        headers: authHeaders
    }, { deviceId: 'dev-office-2f-sw1' });
    console.log('-> 이전 장비 복귀 결과:', switchResBack.body.message);

    const statusBack = await request({
        hostname: 'localhost',
        port: 8080,
        path: '/api/switch/status',
        method: 'GET',
        headers: authHeaders
    });
    console.log(`-> 이전 장비 복귀 확인: [${statusBack.body.system.hostname}] 포트수: ${statusBack.body.totalPorts} (4단 스택)`);
    if (statusBack.body.system.hostname !== 'OFFICE_2F_SW_1') {
        throw new Error('이전 장비 복귀 실패!');
    }

    console.log('\n=== [7] 테스트 생성한 3층 장비 삭제 (DELETE /api/devices/:id) ===');
    const delRes = await request({
        hostname: 'localhost',
        port: 8080,
        path: `/api/devices/${newDevId}`,
        method: 'DELETE',
        headers: authHeaders
    });
    console.log('-> 삭제 결과:', delRes.body.message);

    const finalDevList = await request({
        hostname: 'localhost',
        port: 8080,
        path: '/api/devices',
        method: 'GET',
        headers: authHeaders
    });
    console.log(`-> 최종 등록 장비 수: ${finalDevList.body.devices.length}대`);

    console.log('\n🎉 [SUCCESS] 다중 장비 추가 및 이전/다른 장비 선택 및 실시간 전환 검증 완료!');
}

runTest().catch(err => {
    console.error('테스트 실패:', err);
    process.exit(1);
});
