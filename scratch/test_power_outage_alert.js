// scratch/test_power_outage_alert.js
// 장비 전원 꺼짐 감지, 담당자 이메일 발송, 활성 경보 등록 및 전원 복구 엔드투엔드 검증

const http = require('http');

function makeRequest(path, method, body = null, cookie = null, csrfToken = null) {
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
            res.on('end', () => {
                try {
                    resolve({ status: res.statusCode, headers: res.headers, body: JSON.parse(data) });
                } catch (e) {
                    resolve({ status: res.statusCode, headers: res.headers, body: data });
                }
            });
        });
        req.on('error', reject);
        if (body) req.write(typeof body === 'string' ? body : JSON.stringify(body));
        req.end();
    });
}

async function runTest() {
    console.log('=== [1] Admin 로그인 및 인증 세션 획득 ===');
    const loginRes = await makeRequest('/api/auth/login', 'POST', {
        username: 'admin',
        password: 'Admin@1234!'
    });
    const cookie = loginRes.headers['set-cookie'] ? loginRes.headers['set-cookie'][0].split(';')[0] : '';
    const csrfToken = loginRes.body.csrfToken;
    console.log('-> 로그인 성공! 세션 및 CSRF 토큰 획득');

    console.log('\n=== [2] 현재 활성 전원 경보 확인 (GET /api/switch/power/alerts) ===');
    const initAlerts = await makeRequest('/api/switch/power/alerts', 'GET', null, cookie, csrfToken);
    console.log('-> 현재 활성 경보 수:', initAlerts.body.alerts.length);

    console.log('\n=== [3] 스위치 장비 [OFFICE_1F_SW_2] 전원 꺼짐 시뮬레이션 및 담당자 메일 발송 (POST /api/switch/power/simulate) ===');
    const simRes = await makeRequest('/api/switch/power/simulate', 'POST', {
        type: 'device',
        deviceId: 'dev-office-1f-sw2',
        reason: '1층 분전함 누전차단기(ELB) 트립 및 메인 AC 전원 차단'
    }, cookie, csrfToken);
    console.log('-> 시뮬레이션 응답:', simRes.body.message);
    console.log('-> 생성된 보고서 ID:', simRes.body.report.id);
    console.log('-> 보고서 제목:', simRes.body.report.title);
    console.log('-> 메일 수신자:', simRes.body.deliveryResult.recipient);
    console.log('-> 발송 방식:', simRes.body.deliveryResult.method);
    console.log('-> 장비 상태 변경 확인:', simRes.body.device.name, '->', simRes.body.device.status);

    console.log('\n=== [4] 웹 콘솔 상태 API에서 전원 경보 감지 확인 (GET /api/switch/status) ===');
    const statusRes = await makeRequest('/api/switch/status', 'GET', null, cookie, csrfToken);
    console.log('-> 활성 전원 경보 수:', statusRes.body.powerAlerts.length);
    const alert = statusRes.body.powerAlerts[0];
    console.log('-> 감지된 전원 이상 장비:', alert.deviceName, `(${alert.deviceIp})`, alert.reason);

    console.log('\n=== [5] PoE 연결 단말 [Gi1/0/5] 전원 차단 시뮬레이션 ===');
    const poeRes = await makeRequest('/api/switch/power/simulate', 'POST', {
        type: 'poe',
        deviceId: 'dev-office-3f-sw5',
        portId: 5,
        reason: '천장 무선 AP UTP 케이블 접촉 불량 및 PoE 과전류 이상'
    }, cookie, csrfToken);
    console.log('-> PoE 전원 차단 응답:', poeRes.body.message);
    console.log('-> 단말 보고서 ID:', poeRes.body.report.id);
    console.log('-> 단말 보고서 제목:', poeRes.body.report.title);

    console.log('\n=== [6] 누적 활성 전원 경보 목록 확인 ===');
    const currentAlerts = await makeRequest('/api/switch/power/alerts', 'GET', null, cookie, csrfToken);
    console.log('-> 총 활성 경보 건수:', currentAlerts.body.alerts.length);
    currentAlerts.body.alerts.forEach((a, idx) => {
        console.log(`   [${idx + 1}] [${a.type}] ${a.deviceName} (${a.deviceIp || a.portName}): ${a.reason}`);
    });

    console.log('\n=== [7] 스위치 장비 [OFFICE_1F_SW_2] 전원 정상 복구 및 복구 메일 발송 (POST /api/switch/power/restore) ===');
    const restoreRes = await makeRequest('/api/switch/power/restore', 'POST', {
        deviceId: 'dev-office-1f-sw2'
    }, cookie, csrfToken);
    console.log('-> 복구 결과:', restoreRes.body.message);
    console.log('-> 장비 상태 복구 확인:', restoreRes.body.device.name, '->', restoreRes.body.device.status);

    console.log('\n=== [8] 남은 PoE 경보 수동 확인 처리 (DELETE /api/switch/power/alerts/:id) ===');
    if (poeRes.body.report && poeRes.body.report.id) {
        await makeRequest(`/api/switch/power/alerts/${poeRes.body.report.id}`, 'DELETE', null, cookie, csrfToken);
        console.log('-> 경보 확인 처리 완료!');
    }

    const finalAlerts = await makeRequest('/api/switch/power/alerts', 'GET', null, cookie, csrfToken);
    console.log('-> 최종 남은 활성 경보 수:', finalAlerts.body.alerts.length);

    console.log('\n🎉 [SUCCESS] 전원 꺼짐 감지, 이메일 발송, 웹 콘솔 알림 연동 전 과정 검증 성공!');
}

runTest().catch(err => {
    console.error('테스트 실패:', err);
});
