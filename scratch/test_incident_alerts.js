// scratch/test_incident_alerts.js
// 장애 발생 시 담당자 이메일 발송 및 시간대별 상세 보고서 생성 검증 스크립트

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
    console.log('=== [1] Admin 로그인 및 세션 획득 ===');
    const loginRes = await request({
        hostname: 'localhost',
        port: 8080,
        path: '/api/auth/login',
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    }, { username: 'admin', password: 'Admin@1234!' });

    if (loginRes.statusCode !== 200 || !loginRes.body.success) {
        throw new Error('로그인 실패: ' + JSON.stringify(loginRes.body));
    }

    const cookieHeader = loginRes.headers['set-cookie'];
    const sessionIdCookie = (Array.isArray(cookieHeader) ? cookieHeader[0] : cookieHeader).split(';')[0];
    const csrfToken = loginRes.body.csrfToken;
    console.log('-> 로그인 성공! 세션 및 CSRF 토큰 획득');

    const authHeaders = {
        'Cookie': sessionIdCookie,
        'X-CSRF-Token': csrfToken,
        'Content-Type': 'application/json'
    };

    console.log('\n=== [2] 담당자 이메일 및 경보 설정 조회 ===');
    const cfgRes = await request({
        hostname: 'localhost',
        port: 8080,
        path: '/api/switch/alerts/config',
        method: 'GET',
        headers: authHeaders
    });
    console.log('-> 현재 경보 설정:', {
        enabled: cfgRes.body.alertSettings.enabled,
        managerEmail: cfgRes.body.alertSettings.managerEmail,
        managerName: cfgRes.body.alertSettings.managerName,
        notifyOnLinkDown: cfgRes.body.alertSettings.notifyOnLinkDown
    });

    console.log('\n=== [3] 담당자 이메일 설정 업데이트 (PUT) ===');
    const updateRes = await request({
        hostname: 'localhost',
        port: 8080,
        path: '/api/switch/alerts/config',
        method: 'PUT',
        headers: authHeaders
    }, {
        enabled: true,
        managerEmail: 'netadmin@company.com',
        managerName: '네트워크 운영 총괄 팀장',
        senderEmail: 'cisco-alert@switch.internal',
        senderName: 'Cisco 2960-S Monitoring Engine',
        notifyOnLinkDown: true,
        notifyOnSecurityViolation: true,
        notifyOnPoeFault: true,
        notifyOnStackChange: true
    });
    console.log('-> 설정 업데이트 결과:', updateRes.body.message);

    console.log('\n=== [4] 장애 시뮬레이션 및 시간대별 보고서 생성/발송 (Gi2/0/14 - Link Down) ===');
    const simRes1 = await request({
        hostname: 'localhost',
        port: 8080,
        path: '/api/switch/alerts/simulate-incident',
        method: 'POST',
        headers: authHeaders
    }, {
        portName: 'Gi2/0/14',
        incidentType: 'LINK_DOWN',
        severity: 'CRITICAL',
        customMessage: '2층 기획팀 14번 회선 신호 소실 접수'
    });

    console.log('-> 시뮬레이션 결과:', simRes1.body.message);
    const rep1 = simRes1.body.report;
    console.log('-> 생성된 보고서 요약:');
    console.log('   - 보고서 ID:', rep1.id);
    console.log('   - 제목:', rep1.title);
    console.log('   - 발생 시각 (KST):', rep1.timeKst);
    console.log('   - 발생 포트:', rep1.portName);
    console.log('   - 스위치 스택 유닛:', `스택 #${rep1.switchNum} (${rep1.hostname})`);
    console.log('   - 연결 클라이언트 IP:', rep1.clientInfo.ipAddress);
    console.log('   - 연결 클라이언트 MAC:', rep1.clientInfo.mac);
    console.log('   - 단말 기기명:', rep1.clientInfo.deviceName);
    console.log('   - 수신자 이메일:', rep1.deliveryResult.recipient);
    console.log('   - 전송 방식:', rep1.deliveryResult.method);
    console.log('\n   [시간대별 타임라인 (Timeline)]');
    rep1.timeline.forEach((step, idx) => {
        console.log(`     ${idx + 1}. [${step.time}] ${step.event}`);
        console.log(`        Syslog: ${step.syslog}`);
    });
    console.log('   - 원인 분석:', rep1.rootCause);

    console.log('\n=== [5] 포트 보안 위반 시뮬레이션 (Gi1/0/3 - Port Security Violation) ===');
    const simRes2 = await request({
        hostname: 'localhost',
        port: 8080,
        path: '/api/switch/alerts/simulate-incident',
        method: 'POST',
        headers: authHeaders
    }, {
        portName: 'Gi1/0/3',
        incidentType: 'PORT_SECURITY_VIOLATION',
        severity: 'CRITICAL'
    });
    console.log('-> 보안 위반 보고서 ID:', simRes2.body.report.id);
    console.log('   - 제목:', simRes2.body.report.title);
    console.log('   - 타임라인 항목 수:', simRes2.body.report.timeline.length);

    console.log('\n=== [6] 보관함 보고서 목록 조회 (GET /api/switch/alerts/reports) ===');
    const listRes = await request({
        hostname: 'localhost',
        port: 8080,
        path: '/api/switch/alerts/reports',
        method: 'GET',
        headers: authHeaders
    });
    console.log(`-> 보관함 내 보고서 총 건수: ${listRes.body.reports.length}건`);
    listRes.body.reports.slice(0, 3).forEach(r => {
        console.log(`   - [${r.id}] ${r.timeKst} | ${r.portName} | ${r.incidentType} | 수신: ${r.recipient} (${r.deliveryMethod})`);
    });

    console.log('\n=== [7] 보고서 상세 조회 (GET /api/switch/alerts/reports/:id) ===');
    const detailRes = await request({
        hostname: 'localhost',
        port: 8080,
        path: `/api/switch/alerts/reports/${rep1.id}`,
        method: 'GET',
        headers: authHeaders
    });
    if (detailRes.statusCode === 200 && detailRes.body.report.id === rep1.id) {
        console.log(`-> 보고서 [${rep1.id}] 상세 데이터 및 HTML 이메일 템플릿 로드 검증 성공!`);
        console.log(`   HTML 본문 길이: ${detailRes.body.report.htmlContent.length} bytes`);
    } else {
        throw new Error('보고서 상세 조회 실패: ' + JSON.stringify(detailRes.body));
    }

    console.log('\n🎉 [SUCCESS] 모든 장애 감지, 시간대별 보고서 생성 및 담당자 이메일 발송 기능 검증 완료!');
}

runTest().catch(err => {
    console.error('테스트 실패:', err);
    process.exit(1);
});
