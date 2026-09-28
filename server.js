// server.js
// 시큐어코딩 가이드 기준 안전한 L2 스위치 웹 관리 서버
// Cisco Catalyst 2960-S Series PoE+ 실시간 연동 및 동기화 지원

const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');

const { setSecurityHeaders } = require('./security/headers');
const {
    loadUsers, saveUsers, hashPassword, verifyPassword,
    checkLockout, recordLoginFailure, recordLoginSuccess,
    createSession, validateSession, destroySession, SESSION_TIMEOUT_MS
} = require('./security/auth');
const {
    escapeHtml, isValidInteger, isValidIPv4, isValidSubnetMask,
    isValidMacAddress, normalizeMacAddress, isValidVlanId, isValidPortId,
    isValidHostname, isSafeDescription, isValidPasswordComplexity, isValidEmail,
    ALLOWED_PORT_SPEEDS, ALLOWED_PORT_DUPLEX, ALLOWED_VLAN_MODES,
    ALLOWED_VIOLATION_ACTIONS, ALLOWED_STP_MODES
} = require('./security/validator');
const { verifyCsrfToken } = require('./security/csrf');
const { logEvent, getLogs } = require('./core/auditLogger');
const { loadConfig, saveConfig } = require('./core/switchModel');
const { generateRunningConfig, executeVirtualCliCommand } = require('./core/cliGenerator');
const { parseCiscoConfig, parsePowerInline, generateCiscoDiffCommands, calculateSubnetDetails } = require('./core/ciscoParser');
const { pullLiveCiscoConfig, pushCiscoConfig } = require('./core/ciscoSSHClient');
const {
    getDefaultAlertSettings,
    generateAndDispatchIncidentReport,
    loadReportsIndex,
    REPORTS_DIR
} = require('./core/incidentReporter');
const {
    loadDevicesRegistry,
    getActiveDeviceId,
    setActiveDevice,
    createDevice,
    updateDevice,
    deleteDevice,
    saveDeviceConfig
} = require('./core/deviceManager');
const {
    getActivePowerAlerts,
    dismissPowerAlert,
    triggerDevicePowerOff,
    triggerDevicePowerOn,
    triggerPoePowerOff
} = require('./core/powerMonitor');

const PORT = process.env.PORT || 8080;
const PUBLIC_DIR = path.resolve(__dirname, 'public');

// MIME 타입 매핑 (화이트리스트)
const MIME_TYPES = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon'
};

function sendJson(res, statusCode, data) {
    res.writeHead(statusCode, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(data));
}

function sendError(res, statusCode, userMessage, internalError = null) {
    if (internalError) {
        console.error(`[INTERNAL ERROR] Status ${statusCode}:`, internalError);
    }
    sendJson(res, statusCode, {
        success: false,
        error: userMessage || '요청 처리 중 오류가 발생했습니다.'
    });
}

function parseCookies(req) {
    const list = {};
    const cookieHeader = req.headers.cookie;
    if (!cookieHeader) return list;

    cookieHeader.split(';').forEach(cookie => {
        let [name, ...rest] = cookie.split('=');
        name = name.trim();
        if (!name) return;
        const value = rest.join('=').trim();
        list[name] = decodeURIComponent(value);
    });
    return list;
}

function serveStaticFile(req, res, pathname) {
    let safePath = pathname === '/' ? '/index.html' : pathname;
    const resolvedPath = path.resolve(PUBLIC_DIR, '.' + safePath);
    if (!resolvedPath.startsWith(PUBLIC_DIR)) {
        return sendError(res, 403, '접근 권한이 없습니다.');
    }

    fs.stat(resolvedPath, (err, stats) => {
        if (err || !stats.isFile()) {
            return sendError(res, 404, '요청하신 리소스를 찾을 수 없습니다.');
        }

        const ext = path.extname(resolvedPath).toLowerCase();
        const contentType = MIME_TYPES[ext] || 'application/octet-stream';

        res.writeHead(200, { 'Content-Type': contentType });
        const stream = fs.createReadStream(resolvedPath);
        stream.on('error', streamErr => {
            sendError(res, 500, '파일을 읽는 도중 오류가 발생했습니다.', streamErr);
        });
        stream.pipe(res);
    });
}

function parseJsonBody(req) {
    return new Promise((resolve, reject) => {
        let body = '';
        let totalSize = 0;
        const MAX_BODY_SIZE = 2 * 1024 * 1024; // 2MB (큰 config 텍스트 지원)

        req.on('data', chunk => {
            totalSize += chunk.length;
            if (totalSize > MAX_BODY_SIZE) {
                reject(new Error('PAYLOAD_TOO_LARGE'));
                req.destroy();
                return;
            }
            body += chunk;
        });

        req.on('end', () => {
            if (!body) return resolve({});
            try {
                const parsed = JSON.parse(body);
                resolve(parsed);
            } catch (err) {
                reject(new Error('INVALID_JSON'));
            }
        });

        req.on('error', err => reject(err));
    });
}

const server = http.createServer(async (req, res) => {
    setSecurityHeaders(res);

    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
    const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const pathname = parsedUrl.pathname;
    const searchParams = parsedUrl.searchParams;

    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
    }

    const cookies = parseCookies(req);
    const sessionId = cookies.sessionId;
    const session = validateSession(sessionId);

    if (pathname.startsWith('/api/')) {
        try {
            // ----------------------------------------------------
            // 1. 인증 관련 API
            // ----------------------------------------------------
            if (pathname === '/api/auth/login' && req.method === 'POST') {
                const body = await parseJsonBody(req);
                const { username, password } = body;

                if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
                    return sendError(res, 400, '사용자 이름과 비밀번호를 입력해주세요.');
                }

                const lockout = checkLockout(username);
                if (lockout.locked) {
                    logEvent('AUTH', username, clientIp, `계정 잠금 상태 로그인 시도 차단 (${lockout.remainingSec}초 남음)`, 'FAILURE');
                    return sendError(res, 429, `계정이 잠금되었습니다. ${lockout.remainingSec}초 후 다시 시도해주세요.`);
                }

                const users = loadUsers();
                const user = users.find(u => u.username.toLowerCase() === username.trim().toLowerCase());

                if (!user || !verifyPassword(password, user.salt, user.hash)) {
                    const failResult = recordLoginFailure(username);
                    const failMsg = failResult.locked 
                        ? `비밀번호 5회 연속 오류로 계정이 5분간 잠금되었습니다.` 
                        : `아이디 또는 비밀번호가 올바르지 않습니다. (남은 시도 횟수: ${failResult.remaining}회)`;
                    
                    logEvent('AUTH', username, clientIp, '로그인 실패: 자격증명 불일치', 'FAILURE');
                    return sendError(res, 401, failMsg);
                }

                recordLoginSuccess(username);
                const { sessionId: newSessionId, csrfToken } = createSession(user.username, user.role);

                res.setHeader('Set-Cookie', `sessionId=${newSessionId}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_TIMEOUT_MS / 1000}`);
                
                logEvent('AUTH', user.username, clientIp, `로그인 성공 (Role: ${user.role})`, 'SUCCESS');
                return sendJson(res, 200, {
                    success: true,
                    user: { username: user.username, role: user.role },
                    csrfToken
                });
            }

            if (pathname === '/api/auth/logout' && req.method === 'POST') {
                if (sessionId) {
                    if (session) logEvent('AUTH', session.username, clientIp, '로그아웃', 'SUCCESS');
                    destroySession(sessionId);
                }
                res.setHeader('Set-Cookie', `sessionId=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`);
                return sendJson(res, 200, { success: true, message: '성공적으로 로그아웃되었습니다.' });
            }

            if (pathname === '/api/auth/me' && req.method === 'GET') {
                if (!session) {
                    return sendJson(res, 200, { authenticated: false });
                }
                return sendJson(res, 200, {
                    authenticated: true,
                    user: { username: session.username, role: session.role },
                    csrfToken: session.csrfToken
                });
            }

            // 인증 필수 체크
            if (!session) {
                return sendError(res, 401, '로그인이 필요한 서비스입니다.');
            }

            // CSRF 검증
            if (!verifyCsrfToken(req, session)) {
                logEvent('SECURITY', session.username, clientIp, `CSRF 토큰 불일치 요청 차단 (${req.method} ${pathname})`, 'FAILURE');
                return sendError(res, 403, 'CSRF 토큰이 유효하지 않거나 누락되었습니다.');
            }

            // Viewer 권한 체크
            const isWriteMethod = ['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method);
            if (isWriteMethod && session.role === 'viewer') {
                logEvent('SECURITY', session.username, clientIp, `Viewer 권한의 쓰기 시도 차단 (${req.method} ${pathname})`, 'FAILURE');
                return sendError(res, 403, '읽기 전용(Viewer) 권한으로는 설정을 변경할 수 없습니다.');
            }

            // ----------------------------------------------------
            // 2. Cisco Catalyst 2960-S Series 연동 특화 API
            // ----------------------------------------------------

            // A. 실제 Cisco 2960-S 스위치에 SSH 접속하여 현재 설정 실시간 동기화
            if (pathname === '/api/cisco/sync' && req.method === 'POST') {
                const body = await parseJsonBody(req);
                const { host, port, username, password, enableSecret } = body;

                if (!host || !isValidIPv4(host)) {
                    return sendError(res, 400, '유효한 Cisco 스위치 IPv4 주소를 입력해주세요.');
                }
                const targetPort = port ? Number(port) : 22;
                if (targetPort !== 23 && (!username || typeof username !== 'string' || !username.trim())) {
                    return sendError(res, 400, '스위치 SSH 로그인 사용자명을 입력해주세요.');
                }
                if (!password || typeof password !== 'string') {
                    return sendError(res, 400, '스위치 로그인 비밀번호를 입력해주세요.');
                }

                try {
                    // 실제 Cisco 스위치로부터 running-config 및 power inline 수집
                    const rawOutput = await pullLiveCiscoConfig({
                        host: host.trim(),
                        port: targetPort,
                        username: (username || 'admin').trim(),
                        password: password,
                        enableSecret: enableSecret || null
                    });

                    // 파싱 및 구조화
                    const parsedConfig = parseCiscoConfig(rawOutput);
                    parsePowerInline(rawOutput, parsedConfig);

                    parsedConfig.system.ipAddress = host.trim();
                    parsedConfig.ciscoConnected = {
                        host: host.trim(),
                        port: port ? Number(port) : 22,
                        syncedAt: new Date().toISOString()
                    };

                    // 다중 장비 레지스트리 연동: 동일 IP 장비 검색 또는 신규 장비 자동 등록
                    const reg = loadDevicesRegistry();
                    const targetIp = host.trim();
                    const targetDevId = body.targetDeviceId;
                    const saveMode = body.saveMode || (body.createAsNew ? 'create' : 'auto');

                    let existingDev = reg.devices.find(d => (targetDevId && d.id === targetDevId) || d.ipAddress === targetIp);
                    let finalDeviceId;
                    let isNewDevice = false;

                    if (saveMode === 'create' || (!existingDev && saveMode === 'auto')) {
                        // 신규 장비로 추가 등록하여 분리 관리
                        const autoName = parsedConfig.system.hostname || `SW_${targetIp.replace(/\./g, '_')}`;
                        const created = createDevice({
                            name: autoName,
                            ipAddress: targetIp,
                            model: parsedConfig.system.model || 'Cisco Catalyst 2960-S',
                            location: body.location || '원격 연동 장비',
                            description: `Cisco 실시간 연동 등록 (${new Date().toLocaleDateString('ko-KR')})`,
                            customConfig: parsedConfig,
                            makeActive: true
                        });
                        finalDeviceId = created.device.id;
                        isNewDevice = true;
                    } else if (existingDev) {
                        // 기존 장비의 설정 덮어쓰기 및 활성화
                        finalDeviceId = existingDev.id;
                        saveDeviceConfig(parsedConfig, finalDeviceId);
                        setActiveDevice(finalDeviceId);
                    } else {
                        // 기본 활성 장비에 저장
                        saveConfig(parsedConfig);
                        finalDeviceId = getActiveDeviceId();
                    }

                    const refreshedReg = loadDevicesRegistry();
                    logEvent('CISCO', session.username, clientIp, `Cisco 2960-S [${host}] 실시간 설정 동기화 완료 (${isNewDevice ? '신규 장비 등록' : '설정 갱신'})`, 'SUCCESS');

                    return sendJson(res, 200, {
                        success: true,
                        isNewDevice,
                        activeDeviceId: finalDeviceId,
                        devices: refreshedReg.devices,
                        message: isNewDevice
                            ? `Cisco 장비 [${parsedConfig.system.hostname || host}]가 새로운 관리 장비로 추가 등록되었습니다.`
                            : `Cisco 장비 [${parsedConfig.system.hostname || host}]의 설정이 성공적으로 갱신되었습니다.`,
                        config: parsedConfig
                    });
                } catch (sshErr) {
                    logEvent('CISCO', session.username, clientIp, `Cisco 2960-S [${host}] 동기화 실패: ${sshErr.message}`, 'FAILURE');
                    return sendError(res, 502, `Cisco 스위치 통신 실패: ${sshErr.message}`);
                }
            }

            // B. 수동 콘솔 텍스트(Running-Config & PoE) 붙여넣기 가져오기
            if (pathname === '/api/cisco/import' && req.method === 'POST') {
                const body = await parseJsonBody(req);
                const { rawConfig, rawPowerInline, targetDeviceId, createAsNew } = body;

                if (!rawConfig || typeof rawConfig !== 'string') {
                    return sendError(res, 400, '붙여넣을 Cisco Running-Config 텍스트를 입력해주세요.');
                }

                try {
                    const parsedConfig = parseCiscoConfig(rawConfig);
                    if (rawPowerInline) {
                        parsePowerInline(rawPowerInline, parsedConfig);
                    } else if (rawConfig.includes('SHOW POWER INLINE OUTPUT')) {
                        parsePowerInline(rawConfig.split('SHOW POWER INLINE OUTPUT')[1], parsedConfig);
                    }

                    const reg = loadDevicesRegistry();
                    const targetIp = (parsedConfig.system && parsedConfig.system.ipAddress) || '10.101.241.10';
                    let existingDev = reg.devices.find(d => (targetDeviceId && d.id === targetDeviceId) || (targetIp !== '10.101.241.10' && d.ipAddress === targetIp));
                    let finalDeviceId;
                    let isNewDevice = false;

                    if (createAsNew || !existingDev) {
                        const autoName = parsedConfig.system.hostname || `SW_${targetIp.replace(/\./g, '_')}`;
                        const created = createDevice({
                            name: autoName,
                            ipAddress: targetIp,
                            model: parsedConfig.system.model || 'Cisco Catalyst 2960-S',
                            location: body.location || '수동 텍스트 가져오기',
                            description: `Cisco Config 텍스트 파싱 등록 (${new Date().toLocaleDateString('ko-KR')})`,
                            customConfig: parsedConfig,
                            makeActive: true
                        });
                        finalDeviceId = created.device.id;
                        isNewDevice = true;
                    } else {
                        finalDeviceId = existingDev.id;
                        saveDeviceConfig(parsedConfig, finalDeviceId);
                        setActiveDevice(finalDeviceId);
                    }

                    const refreshedReg = loadDevicesRegistry();
                    logEvent('CISCO', session.username, clientIp, `Cisco Running-Config 텍스트 파싱 로드 (${isNewDevice ? '신규 장비 등록' : '설정 갱신'})`, 'SUCCESS');

                    return sendJson(res, 200, {
                        success: true,
                        isNewDevice,
                        activeDeviceId: finalDeviceId,
                        devices: refreshedReg.devices,
                        message: isNewDevice
                            ? `Cisco 장비 [${parsedConfig.system.hostname || '새 스위치'}]가 신규 장비로 등록되었습니다.`
                            : `Cisco Catalyst 2960-S 설정(${parsedConfig.ports.length}개 포트)이 성공적으로 반영되었습니다.`,
                        config: parsedConfig
                    });
                } catch (parseErr) {
                    return sendError(res, 400, `Cisco 설정 파싱 오류: ${parseErr.message}`);
                }
            }

            // C. 변경 사항 차분(Diff) 명령어 생성 (미리보기용)
            if (pathname === '/api/cisco/generate-diff' && req.method === 'POST') {
                const currentConfig = loadConfig();
                // 샘플 또는 원래 포트 상태와 비교
                const diffCommands = generateCiscoDiffCommands(currentConfig.ports, currentConfig.ports, currentConfig.vlans);
                return sendJson(res, 200, { success: true, commands: diffCommands });
            }

            // D. UI 수정사항을 실제 Cisco 2960-S 스위치에 반영 (Commit & write memory)
            if (pathname === '/api/cisco/commit' && req.method === 'POST') {
                const body = await parseJsonBody(req);
                const { host, port, username, password, enableSecret, commands } = body;

                if (!host || !isValidIPv4(host)) {
                    return sendError(res, 400, '유효한 Cisco 스위치 IP 주소를 입력해주세요.');
                }
                if (!Array.isArray(commands) || commands.length === 0) {
                    return sendError(res, 400, '스위치에 전송할 변경 명령어가 비어있습니다.');
                }

                try {
                    const output = await pushCiscoConfig({
                        host: host.trim(),
                        port: port ? Number(port) : 22,
                        username: username.trim(),
                        password: password,
                        enableSecret: enableSecret || null
                    }, commands);

                    logEvent('CISCO', session.username, clientIp, `Cisco 2960-S [${host}]에 ${commands.length}개 설정 명령 반영 및 NVRAM 저장 완료`, 'SUCCESS');
                    return sendJson(res, 200, {
                        success: true,
                        message: `Cisco 스위치 [${host}]에 설정이 정상 반영되었으며, write memory 저장이 완료되었습니다.`,
                        switchOutput: output
                    });
                } catch (pushErr) {
                    logEvent('CISCO', session.username, clientIp, `Cisco 2960-S [${host}] 설정 반영 실패: ${pushErr.message}`, 'FAILURE');
                    return sendError(res, 502, `스위치 설정 반영 실패: ${pushErr.message}`);
                }
            }

            // E. Cisco 2960-S PoE+ 샘플 프리셋 조회 (테스트 편의용)
            if (pathname === '/api/cisco/sample-preset' && req.method === 'GET') {
                const presetPath = path.join(__dirname, 'data', 'sample_2960s_poe.cfg');
                if (fs.existsSync(presetPath)) {
                    const text = fs.readFileSync(presetPath, 'utf8');
                    return sendJson(res, 200, { success: true, sampleConfig: text });
                }
                return sendError(res, 404, '샘플 프리셋을 찾을 수 없습니다.');
            }

            // ----------------------------------------------------
            // 2.5. 다중 네트워크 장비 관리 및 전환 API
            // ----------------------------------------------------
            if (pathname === '/api/devices' && req.method === 'GET') {
                const reg = loadDevicesRegistry();
                return sendJson(res, 200, {
                    success: true,
                    activeDeviceId: reg.activeDeviceId,
                    devices: reg.devices
                });
            }

            if (pathname === '/api/devices/active' && req.method === 'POST') {
                const body = await parseJsonBody(req);
                const { deviceId } = body;
                if (!deviceId) return sendError(res, 400, '전환할 장비 식별자를 지정해주세요.');
                try {
                    const result = setActiveDevice(deviceId);
                    logEvent('SYSTEM', session.username, clientIp, `관리 장비 전환: [${result.device.name}] (${result.device.ipAddress})`, 'SUCCESS');
                    return sendJson(res, 200, {
                        success: true,
                        message: `관리 장비가 [${result.device.name}] (${result.device.ipAddress})로 전환되었습니다.`,
                        activeDeviceId: result.activeDeviceId,
                        device: result.device
                    });
                } catch (err) {
                    return sendError(res, 404, err.message);
                }
            }

            if (pathname === '/api/devices' && req.method === 'POST') {
                const body = await parseJsonBody(req);
                try {
                    const result = createDevice(body);
                    logEvent('SYSTEM', session.username, clientIp, `신규 장비 등록: [${result.device.name}] (${result.device.ipAddress})`, 'SUCCESS');
                    return sendJson(res, 201, {
                        success: true,
                        message: `신규 장비 [${result.device.name}]가 성공적으로 등록되었습니다.`,
                        device: result.device,
                        activeDeviceId: result.activeDeviceId
                    });
                } catch (err) {
                    return sendError(res, 400, err.message);
                }
            }

            if (pathname.startsWith('/api/devices/') && req.method === 'PUT') {
                const devId = pathname.replace('/api/devices/', '').trim();
                const body = await parseJsonBody(req);
                try {
                    const result = updateDevice(devId, body);
                    logEvent('SYSTEM', session.username, clientIp, `장비 정보 수정: [${result.device.name}]`, 'SUCCESS');
                    return sendJson(res, 200, {
                        success: true,
                        message: `장비 [${result.device.name}] 정보가 수정되었습니다.`,
                        device: result.device
                    });
                } catch (err) {
                    return sendError(res, 400, err.message);
                }
            }

            if (pathname.startsWith('/api/devices/') && req.method === 'DELETE') {
                const devId = pathname.replace('/api/devices/', '').trim();
                try {
                    const result = deleteDevice(devId);
                    logEvent('SYSTEM', session.username, clientIp, `장비 삭제: ${devId}`, 'SUCCESS');
                    return sendJson(res, 200, result);
                } catch (err) {
                    return sendError(res, 400, err.message);
                }
            }

            // ----------------------------------------------------
            // 3. 기존 L2 스위치 설정 및 모니터링 API
            // ----------------------------------------------------
            if (pathname === '/api/switch/status' && req.method === 'GET') {
                const config = loadConfig();
                const reg = loadDevicesRegistry();
                const cpuSim = Math.min(95, Math.max(5, Math.floor(Math.random() * 8) + 12));
                const memSim = 42;
                const powerAlerts = getActivePowerAlerts();
                const activeDev = reg.devices.find(d => d.id === reg.activeDeviceId);

                return sendJson(res, 200, {
                    success: true,
                    activeDeviceId: reg.activeDeviceId,
                    devices: reg.devices,
                    powerAlerts,
                    currentPowerStatus: (activeDev && activeDev.powerStatus) || 'online',
                    system: config.system,
                    poeSummary: config.poeSummary || { availableWatts: 370.0, usedWatts: 98.4, remainingWatts: 271.6 },
                    cpuUsage: cpuSim,
                    memUsage: memSim,
                    totalPorts: config.ports.length,
                    activePorts: config.ports.filter(p => p.linkState === 'up' || p.status === 'up').length,
                    totalVlans: config.vlans.length,
                    totalMacs: config.macTable.length,
                    stpMode: config.stp.mode,
                    lastSaved: config.lastSaved,
                    ciscoConnected: config.ciscoConnected || null
                });
            }

            if (pathname === '/api/switch/ports' && req.method === 'GET') {
                const config = loadConfig();
                return sendJson(res, 200, { success: true, ports: config.ports });
            }

            if (pathname.startsWith('/api/switch/ports/') && req.method === 'PUT') {
                const portId = parseInt(pathname.split('/')[4], 10);
                if (!isValidPortId(portId)) {
                    return sendError(res, 400, '유효하지 않은 포트 번호입니다 (1~512).');
                }

                const body = await parseJsonBody(req);
                const config = loadConfig();
                const port = config.ports.find(p => p.id === portId);
                if (!port) {
                    return sendError(res, 404, '해당 포트를 찾을 수 없습니다.');
                }

                if (body.adminState && !['up', 'down'].includes(body.adminState)) return sendError(res, 400, 'adminState 오류');
                if (body.speed && !ALLOWED_PORT_SPEEDS.includes(body.speed)) return sendError(res, 400, 'speed 오류');
                if (body.duplex && !ALLOWED_PORT_DUPLEX.includes(body.duplex)) return sendError(res, 400, 'duplex 오류');
                if (body.mtu !== undefined && !isValidInteger(body.mtu, 64, 9216)) return sendError(res, 400, 'mtu 오류');
                if (body.mode && !ALLOWED_VLAN_MODES.includes(body.mode)) return sendError(res, 400, 'mode 오류');
                if (body.pvid !== undefined && !isValidVlanId(body.pvid)) return sendError(res, 400, 'pvid 오류');
                if (body.description !== undefined && !isSafeDescription(body.description, 64)) return sendError(res, 400, 'description 오류');
                if (body.poeMode && !['auto', 'never'].includes(body.poeMode)) return sendError(res, 400, 'poeMode는 auto 또는 never여야 합니다.');

                if (body.adminState) {
                    port.adminState = body.adminState;
                    port.linkState = body.adminState === 'down' ? 'down' : (port.linkState === 'up' ? 'up' : 'down');
                }
                if (body.speed) port.speed = body.speed;
                if (body.duplex) port.duplex = body.duplex;
                if (body.mtu) port.mtu = Number(body.mtu);
                if (body.flowControl !== undefined) port.flowControl = Boolean(body.flowControl);
                if (body.mode) port.mode = body.mode;
                if (body.pvid) {
                    port.pvid = Number(body.pvid);
                    if (port.mode === 'access') {
                        port.untaggedVlans = [port.pvid];
                        port.taggedVlans = [];
                    }
                }
                if (body.description !== undefined) port.description = body.description.trim();

                // PoE 모드 업데이트
                if (body.poeMode) {
                    port.poe = port.poe || { mode: 'auto', status: 'off', powerWatts: 0, device: 'No PD detected', maxWatts: 30.0 };
                    port.poe.mode = body.poeMode;
                    if (port.poe.mode === 'never') {
                        port.poe.status = 'off';
                        port.poe.powerWatts = 0;
                    }
                }

                saveConfig(config);
                logEvent('PORT', session.username, clientIp, `포트 ${port.name} 설정 변경 (Admin: ${port.adminState}, Mode: ${port.mode}, PoE: ${port.poe ? port.poe.mode : 'N/A'})`, 'SUCCESS');
                return sendJson(res, 200, { success: true, port });
            }

            if (pathname === '/api/switch/vlans' && req.method === 'GET') {
                const config = loadConfig();
                return sendJson(res, 200, { success: true, vlans: config.vlans });
            }

            if (pathname === '/api/switch/vlans' && req.method === 'POST') {
                const body = await parseJsonBody(req);
                const { id, name, description, ipAddress, subnetMask, gateway } = body;

                if (!isValidVlanId(id)) return sendError(res, 400, 'VLAN ID는 1 ~ 4094 범위여야 합니다.');
                if (!name || !isSafeDescription(name, 32)) return sendError(res, 400, 'VLAN 이름은 1~32자의 안전한 문자열이어야 합니다.');

                const config = loadConfig();
                const vlanIdNum = Number(id);
                if (config.vlans.some(v => v.id === vlanIdNum)) {
                    return sendError(res, 400, `이미 존재하는 VLAN ID (${vlanIdNum})입니다.`);
                }

                let netInfo = null;
                if (ipAddress && subnetMask && isValidIPv4(ipAddress) && isValidSubnetMask(subnetMask)) {
                    netInfo = calculateSubnetDetails(ipAddress, subnetMask);
                }

                const newVlan = {
                    id: vlanIdNum,
                    name: name.trim().toUpperCase(),
                    description: (description || '').trim(),
                    isSystem: false,
                    ipAddress: ipAddress ? ipAddress.trim() : '',
                    subnetMask: subnetMask ? subnetMask.trim() : '',
                    gateway: gateway && isValidIPv4(gateway) ? gateway.trim() : (netInfo ? netInfo.firstHost : ''),
                    network: netInfo ? netInfo.network : '',
                    cidr: netInfo ? netInfo.cidr : null,
                    broadcast: netInfo ? netInfo.broadcast : '',
                    ipRange: netInfo ? netInfo.ipRange : 'L2 전용 (IP 미할당)',
                    totalHosts: netInfo ? netInfo.totalHosts : 0
                };
                config.vlans.push(newVlan);
                config.vlans.sort((a, b) => a.id - b.id);

                saveConfig(config);
                logEvent('VLAN', session.username, clientIp, `새 VLAN 생성: ${newVlan.id} (${newVlan.name}, IP: ${newVlan.ipRange})`, 'SUCCESS');
                return sendJson(res, 201, { success: true, vlan: newVlan });
            }

            if (pathname.startsWith('/api/switch/vlans/') && req.method === 'PUT') {
                const vlanId = parseInt(pathname.split('/')[4], 10);
                if (!isValidVlanId(vlanId)) return sendError(res, 400, '유효하지 않은 VLAN ID입니다.');

                const body = await parseJsonBody(req);
                const config = loadConfig();
                const vlan = config.vlans.find(v => v.id === vlanId);
                if (!vlan) return sendError(res, 404, '해당 VLAN을 찾을 수 없습니다.');

                if (body.name && isSafeDescription(body.name, 32)) {
                    vlan.name = body.name.trim().toUpperCase();
                }
                if (body.description !== undefined && isSafeDescription(body.description, 64)) {
                    vlan.description = body.description.trim();
                }

                if (body.ipAddress && body.subnetMask && isValidIPv4(body.ipAddress) && isValidSubnetMask(body.subnetMask)) {
                    const netInfo = calculateSubnetDetails(body.ipAddress, body.subnetMask);
                    vlan.ipAddress = body.ipAddress.trim();
                    vlan.subnetMask = body.subnetMask.trim();
                    if (netInfo) {
                        vlan.cidr = netInfo.cidr;
                        vlan.network = netInfo.network;
                        vlan.broadcast = netInfo.broadcast;
                        vlan.ipRange = netInfo.ipRange;
                        vlan.totalHosts = netInfo.totalHosts;
                        vlan.gateway = body.gateway && isValidIPv4(body.gateway) ? body.gateway.trim() : netInfo.firstHost;
                    }
                } else if (body.ipAddress === '' || body.subnetMask === '') {
                    vlan.ipAddress = '';
                    vlan.subnetMask = '';
                    vlan.ipRange = 'L2 전용 (IP 미할당)';
                    vlan.network = '';
                    vlan.gateway = '';
                    vlan.totalHosts = 0;
                }

                if (body.gateway && isValidIPv4(body.gateway)) {
                    vlan.gateway = body.gateway.trim();
                }

                saveConfig(config);
                logEvent('VLAN', session.username, clientIp, `VLAN ${vlan.id} IP 대역/설정 변경`, 'SUCCESS');
                return sendJson(res, 200, { success: true, vlan });
            }

            if (pathname.startsWith('/api/switch/vlans/') && req.method === 'DELETE') {
                const vlanId = parseInt(pathname.split('/')[4], 10);
                if (!isValidVlanId(vlanId)) return sendError(res, 400, '유효하지 않은 VLAN ID입니다.');
                if (vlanId === 1) return sendError(res, 400, '기본 시스템 VLAN 1은 삭제할 수 없습니다.');

                const config = loadConfig();
                const vlanIndex = config.vlans.findIndex(v => v.id === vlanId);
                if (vlanIndex === -1) return sendError(res, 404, '해당 VLAN을 찾을 수 없습니다.');

                const targetVlan = config.vlans[vlanIndex];
                config.vlans.splice(vlanIndex, 1);
                config.ports.forEach(p => {
                    if (p.pvid === vlanId) p.pvid = 1;
                    p.taggedVlans = (p.taggedVlans || []).filter(v => v !== vlanId);
                });

                saveConfig(config);
                logEvent('VLAN', session.username, clientIp, `VLAN 삭제: ${targetVlan.id}`, 'SUCCESS');
                return sendJson(res, 200, { success: true, message: `VLAN ${vlanId}가 삭제되었습니다.` });
            }

            if (pathname === '/api/switch/mac-table' && req.method === 'GET') {
                const config = loadConfig();
                let table = config.macTable || [];
                const search = searchParams.get('search');
                const switchNum = searchParams.get('switch');
                const vlanId = searchParams.get('vlan');
                const ifaceType = searchParams.get('type');

                if (search) {
                    const q = search.toLowerCase();
                    table = table.filter(m => 
                        (m.mac && m.mac.toLowerCase().includes(q)) ||
                        (m.ipAddress && m.ipAddress.toLowerCase().includes(q)) ||
                        (m.portName && m.portName.toLowerCase().includes(q)) ||
                        (m.deviceName && m.deviceName.toLowerCase().includes(q)) ||
                        (m.vendor && m.vendor.toLowerCase().includes(q))
                    );
                }

                if (switchNum && switchNum !== 'all') {
                    const sNum = Number(switchNum);
                    table = table.filter(m => m.switchNum === sNum);
                }

                if (vlanId && vlanId !== 'all') {
                    const vNum = Number(vlanId);
                    table = table.filter(m => m.vlanId === vNum);
                }

                if (ifaceType && ifaceType !== 'all') {
                    if (ifaceType === 'access' || ifaceType === 'trunk') {
                        table = table.filter(m => m.interfaceType === ifaceType);
                    } else if (ifaceType === 'static' || ifaceType === 'dynamic') {
                        table = table.filter(m => m.type === ifaceType);
                    }
                }

                const allMacs = config.macTable || [];
                const totalClients = allMacs.length;
                const directClients = allMacs.filter(m => m.interfaceType === 'access').length;
                const bySwitch = {
                    1: allMacs.filter(m => m.switchNum === 1).length,
                    2: allMacs.filter(m => m.switchNum === 2).length,
                    3: allMacs.filter(m => m.switchNum === 3).length,
                    4: allMacs.filter(m => m.switchNum === 4).length
                };
                const byVlan = {};
                allMacs.forEach(m => {
                    byVlan[m.vlanId] = (byVlan[m.vlanId] || 0) + 1;
                });

                return sendJson(res, 200, {
                    success: true,
                    macTable: table,
                    summary: { totalClients, directClients, bySwitch, byVlan }
                });
            }

            if (pathname === '/api/switch/mac-table/client' && req.method === 'PUT') {
                const body = await parseJsonBody(req);
                const { mac, ipAddress, deviceName } = body;
                if (!isValidMacAddress(mac)) {
                    return sendError(res, 400, '올바른 MAC 주소를 입력해주세요.');
                }
                const normalizedMac = normalizeMacAddress(mac);
                const config = loadConfig();
                const entry = (config.macTable || []).find(m => m.mac === normalizedMac);
                if (!entry) {
                    return sendError(res, 404, '해당 MAC 주소의 클라이언트를 찾을 수 없습니다.');
                }

                if (ipAddress) entry.ipAddress = ipAddress.trim();
                if (deviceName !== undefined) entry.deviceName = isSafeDescription(deviceName, 64) ? deviceName.trim() : entry.deviceName;

                // 연결된 포트의 connectedClient 정보 동기화
                const port = (config.ports || []).find(p => p.id === entry.portId || p.name === entry.portName);
                if (port && port.connectedClient && port.connectedClient.mac === normalizedMac) {
                    port.connectedClient.ipAddress = entry.ipAddress;
                    port.connectedClient.deviceName = entry.deviceName;
                }

                saveConfig(config);
                logEvent('MAC', session.username, clientIp, `클라이언트 정보 수정 [${normalizedMac}] IP: ${entry.ipAddress}, 장치명: ${entry.deviceName}`, 'SUCCESS');
                return sendJson(res, 200, { success: true, message: '클라이언트 정보가 성공적으로 수정되었습니다.', client: entry });
            }

            if (pathname === '/api/switch/mac-table/static' && req.method === 'POST') {
                const body = await parseJsonBody(req);
                const { mac, vlanId, portId, ipAddress, deviceName } = body;
                if (!isValidMacAddress(mac) || !isValidVlanId(vlanId) || !isValidPortId(portId)) {
                    return sendError(res, 400, '올바르지 않은 정적 MAC 정보입니다.');
                }
                const normalizedMac = normalizeMacAddress(mac);
                const config = loadConfig();
                const port = config.ports.find(p => p.id === Number(portId));
                const swNum = port ? port.switchNum : 1;

                config.macTable = (config.macTable || []).filter(m => !(m.mac === normalizedMac && m.vlanId === Number(vlanId)));
                const newEntry = {
                    mac: normalizedMac,
                    ipAddress: ipAddress ? ipAddress.trim() : null,
                    deviceName: deviceName ? deviceName.trim() : `Static-Client-${normalizedMac.slice(-5).replace(':', '')}`,
                    vlanId: Number(vlanId),
                    portId: Number(portId),
                    portName: port ? port.name : `Gi${swNum}/0/1`,
                    switchNum: swNum,
                    type: 'static',
                    interfaceType: (port && port.mode === 'trunk') ? 'trunk' : 'access',
                    age: 0
                };
                config.macTable.push(newEntry);

                if (port) {
                    port.connectedClient = {
                        ipAddress: newEntry.ipAddress,
                        mac: newEntry.mac,
                        deviceName: newEntry.deviceName
                    };
                }

                saveConfig(config);
                logEvent('MAC', session.username, clientIp, `정적 MAC 등록: ${normalizedMac} (포트: ${newEntry.portName}, IP: ${newEntry.ipAddress || '-'})`, 'SUCCESS');
                return sendJson(res, 201, { success: true, message: '정적 MAC 및 IP 정보가 등록되었습니다.', client: newEntry });
            }

            if (pathname === '/api/switch/mac-table/static' && req.method === 'DELETE') {
                const body = await parseJsonBody(req);
                const { mac, vlanId } = body;
                const normalizedMac = normalizeMacAddress(mac);
                const config = loadConfig();
                config.macTable = (config.macTable || []).filter(m => !(m.mac === normalizedMac && m.vlanId === Number(vlanId) && m.type === 'static'));
                saveConfig(config);
                logEvent('MAC', session.username, clientIp, `정적 MAC 삭제: ${normalizedMac}`, 'SUCCESS');
                return sendJson(res, 200, { success: true, message: '정적 MAC 주소가 삭제되었습니다.' });
            }

            if (pathname === '/api/switch/mac-table/flush' && req.method === 'POST') {
                const config = loadConfig();
                config.macTable = (config.macTable || []).filter(m => m.type === 'static');
                saveConfig(config);
                logEvent('MAC', session.username, clientIp, '동적 MAC 주소 테이블 플러시', 'SUCCESS');
                return sendJson(res, 200, { success: true, message: '동적 MAC 주소 테이블이 비워졌습니다.' });
            }

            if (pathname.startsWith('/api/switch/port-security/') && req.method === 'PUT') {
                const portId = parseInt(pathname.split('/')[4], 10);
                const body = await parseJsonBody(req);
                const config = loadConfig();
                const port = config.ports.find(p => p.id === portId);
                if (!port) return sendError(res, 404, '포트를 찾을 수 없습니다.');

                port.portSecurity = {
                    enabled: Boolean(body.enabled),
                    maxMac: body.maxMac ? Number(body.maxMac) : 1,
                    violationAction: body.violationAction || 'shutdown',
                    sticky: Boolean(body.sticky)
                };
                saveConfig(config);
                logEvent('SECURITY', session.username, clientIp, `포트 ${port.name} 보안 설정 변경`, 'SUCCESS');
                return sendJson(res, 200, { success: true, portSecurity: port.portSecurity });
            }

            if (pathname === '/api/switch/stp' && req.method === 'GET') {
                const config = loadConfig();
                return sendJson(res, 200, { success: true, stp: config.stp });
            }

            if (pathname === '/api/switch/stp' && req.method === 'PUT') {
                const body = await parseJsonBody(req);
                const config = loadConfig();
                if (body.mode) config.stp.mode = body.mode;
                if (body.priority !== undefined) config.stp.priority = Number(body.priority);
                if (body.helloTime !== undefined) config.stp.helloTime = Number(body.helloTime);
                if (body.maxAge !== undefined) config.stp.maxAge = Number(body.maxAge);
                if (body.forwardDelay !== undefined) config.stp.forwardDelay = Number(body.forwardDelay);

                saveConfig(config);
                logEvent('STP', session.username, clientIp, `STP 설정 변경`, 'SUCCESS');
                return sendJson(res, 200, { success: true, stp: config.stp });
            }

            if (pathname === '/api/switch/lacp' && req.method === 'GET') {
                const config = loadConfig();
                return sendJson(res, 200, { success: true, lagGroups: config.lagGroups || [] });
            }

            if (pathname === '/api/switch/lacp' && req.method === 'POST') {
                const body = await parseJsonBody(req);
                const { id, mode, members, description } = body;
                const config = loadConfig();
                config.lagGroups = (config.lagGroups || []).filter(g => g.id !== Number(id));
                config.lagGroups.push({
                    id: Number(id),
                    name: `Port-Channel${id}`,
                    mode,
                    members: (members || []).map(Number),
                    description: (description || '').trim()
                });
                saveConfig(config);
                logEvent('LACP', session.username, clientIp, `LACP LAG ${id} 설정 업데이트`, 'SUCCESS');
                return sendJson(res, 200, { success: true, lagGroups: config.lagGroups });
            }

            if (pathname === '/api/switch/system' && req.method === 'PUT') {
                const body = await parseJsonBody(req);
                const config = loadConfig();
                if (body.hostname) config.system.hostname = body.hostname.trim();
                if (body.ipAddress) config.system.ipAddress = body.ipAddress.trim();
                if (body.subnetMask) config.system.subnetMask = body.subnetMask.trim();
                if (body.defaultGateway) config.system.defaultGateway = body.defaultGateway.trim();
                if (body.ntpServer) config.system.ntpServer = body.ntpServer.trim();
                if (body.macAgingTime) config.system.macAgingTime = Number(body.macAgingTime);

                saveConfig(config);
                logEvent('SYSTEM', session.username, clientIp, `시스템 설정 변경`, 'SUCCESS');
                return sendJson(res, 200, { success: true, system: config.system });
            }

            if (pathname === '/api/switch/save' && req.method === 'POST') {
                const config = loadConfig();
                saveConfig(config);
                logEvent('SYSTEM', session.username, clientIp, '스위치 Running-Config NVRAM 영구 저장 완료', 'SUCCESS');
                return sendJson(res, 200, { success: true, message: '스위치 설정이 NVRAM에 안전하게 저장되었습니다.', lastSaved: config.lastSaved });
            }

            if (pathname === '/api/switch/cli/running-config' && req.method === 'GET') {
                const config = loadConfig();
                const cliScript = generateRunningConfig(config);
                return sendJson(res, 200, { success: true, configText: cliScript });
            }

            if (pathname === '/api/switch/cli/execute' && req.method === 'POST') {
                const body = await parseJsonBody(req);
                const config = loadConfig();
                const output = executeVirtualCliCommand(body.command, config);
                logEvent('SYSTEM', session.username, clientIp, `CLI 콘솔 명령 실행: "${body.command ? body.command.substring(0, 40) : ''}"`, 'SUCCESS');
                return sendJson(res, 200, { success: true, output, prompt: `${config.system.hostname}#` });
            }

            if (pathname === '/api/audit-logs' && req.method === 'GET') {
                const logs = getLogs({
                    category: searchParams.get('category'),
                    search: searchParams.get('search')
                });
                return sendJson(res, 200, { success: true, logs });
            }

            if (pathname === '/api/auth/password' && req.method === 'POST') {
                const body = await parseJsonBody(req);
                const { currentPassword, newPassword } = body;
                if (!isValidPasswordComplexity(newPassword)) {
                    return sendError(res, 400, '새 비밀번호는 8자 이상, 대/소문자/숫자/특수문자를 포함해야 합니다.');
                }
                const users = loadUsers();
                const user = users.find(u => u.username === session.username);
                if (!user || !verifyPassword(currentPassword, user.salt, user.hash)) {
                    return sendError(res, 400, '현재 비밀번호가 일치하지 않습니다.');
                }
                const newHashed = hashPassword(newPassword);
                user.salt = newHashed.salt;
                user.hash = newHashed.hash;
                saveUsers(users);
                logEvent('AUTH', session.username, clientIp, '비밀번호 정상 변경', 'SUCCESS');
                return sendJson(res, 200, { success: true, message: '비밀번호가 변경되었습니다.' });
            }

            // ----------------------------------------------------
            // 11. 장애 경보 및 담당자 이메일 보고서 API
            // ----------------------------------------------------
            if (pathname === '/api/switch/alerts/config' && req.method === 'GET') {
                const config = loadConfig();
                return sendJson(res, 200, {
                    success: true,
                    alertSettings: config.alertSettings || getDefaultAlertSettings()
                });
            }

            if (pathname === '/api/switch/alerts/config' && req.method === 'PUT') {
                const body = await parseJsonBody(req);
                const config = loadConfig();
                const currentSettings = config.alertSettings || getDefaultAlertSettings();

                if (body.managerEmail !== undefined) {
                    if (body.managerEmail && !isValidEmail(body.managerEmail)) {
                        return sendError(res, 400, '올바른 담당자 이메일 주소 형식을 입력해주세요.');
                    }
                    currentSettings.managerEmail = body.managerEmail.trim();
                }

                if (body.managerName !== undefined) currentSettings.managerName = isSafeDescription(body.managerName, 64) ? body.managerName.trim() : currentSettings.managerName;
                if (body.senderEmail !== undefined) {
                    if (body.senderEmail && !isValidEmail(body.senderEmail)) {
                        return sendError(res, 400, '올바른 발신자 이메일 주소 형식을 입력해주세요.');
                    }
                    currentSettings.senderEmail = body.senderEmail.trim();
                }
                if (body.senderName !== undefined) currentSettings.senderName = isSafeDescription(body.senderName, 64) ? body.senderName.trim() : currentSettings.senderName;
                if (body.smtpHost !== undefined) currentSettings.smtpHost = String(body.smtpHost || '').trim();
                if (body.smtpPort !== undefined) currentSettings.smtpPort = Number(body.smtpPort) || 587;
                if (body.smtpSecure !== undefined) currentSettings.smtpSecure = Boolean(body.smtpSecure);
                if (body.smtpUser !== undefined) currentSettings.smtpUser = String(body.smtpUser || '').trim();
                if (body.smtpPass !== undefined) currentSettings.smtpPass = String(body.smtpPass || '');

                if (body.enabled !== undefined) currentSettings.enabled = Boolean(body.enabled);
                if (body.notifyOnLinkDown !== undefined) currentSettings.notifyOnLinkDown = Boolean(body.notifyOnLinkDown);
                if (body.notifyOnSecurityViolation !== undefined) currentSettings.notifyOnSecurityViolation = Boolean(body.notifyOnSecurityViolation);
                if (body.notifyOnPoeFault !== undefined) currentSettings.notifyOnPoeFault = Boolean(body.notifyOnPoeFault);
                if (body.notifyOnStackChange !== undefined) currentSettings.notifyOnStackChange = Boolean(body.notifyOnStackChange);

                config.alertSettings = currentSettings;
                saveConfig(config);
                logEvent('ALERT', session.username, clientIp, `담당자 장애 알림 이메일 설정 업데이트 (${currentSettings.managerEmail})`, 'SUCCESS');
                return sendJson(res, 200, {
                    success: true,
                    message: '담당자 이메일 및 장애 경보 설정이 안전하게 저장되었습니다.',
                    alertSettings: currentSettings
                });
            }

            if (pathname === '/api/switch/alerts/reports' && req.method === 'GET') {
                const reports = loadReportsIndex();
                return sendJson(res, 200, { success: true, reports });
            }

            if (pathname.startsWith('/api/switch/alerts/reports/') && req.method === 'GET') {
                const rawReportId = pathname.replace('/api/switch/alerts/reports/', '').trim();
                const reportId = path.basename(rawReportId);
                if (!reportId || !/^(?:INC|PWR|POE)-[0-9]{8}-[0-9A-Za-z_-]+$/.test(reportId)) {
                    return sendError(res, 400, '올바르지 않은 보고서 식별자 형식입니다.');
                }
                const reportFile = path.join(REPORTS_DIR, `${reportId}.json`);
                if (!fs.existsSync(reportFile)) {
                    return sendError(res, 404, '해당 장애 보고서를 찾을 수 없습니다.');
                }
                const reportData = JSON.parse(fs.readFileSync(reportFile, 'utf8'));
                return sendJson(res, 200, { success: true, report: reportData });
            }

            if (pathname === '/api/switch/alerts/trigger-test' && req.method === 'POST') {
                const body = await parseJsonBody(req);
                const { portName, portId, incidentType, severity, customMessage } = body;
                const config = loadConfig();

                let targetPort = null;
                if (portName) {
                    targetPort = config.ports.find(p => p.name.toLowerCase() === portName.trim().toLowerCase());
                } else if (portId) {
                    targetPort = config.ports.find(p => p.id === Number(portId));
                }
                if (!targetPort) {
                    targetPort = config.ports[0] || { id: 1, name: 'Gi1/0/1', switchNum: 1, pvid: 2 };
                }

                const report = await generateAndDispatchIncidentReport({
                    portId: targetPort.id,
                    portName: targetPort.name,
                    incidentType: incidentType || 'LINK_DOWN',
                    severity: severity || 'CRITICAL',
                    description: customMessage
                }, config, `WebAdmin (${session.username}) 수동 테스트`);

                logEvent('ALERT', session.username, clientIp, `수동 장애 보고서 발송 테스트 [${report.id}] ${targetPort.name}`, 'SUCCESS');
                return sendJson(res, 200, {
                    success: true,
                    message: `[${report.id}] 시간대별 상세 장애 보고서가 생성되어 담당자(${report.deliveryResult.recipient})에게 발송되었습니다.`,
                    report
                });
            }

            if (pathname === '/api/switch/alerts/simulate-incident' && req.method === 'POST') {
                const body = await parseJsonBody(req);
                const { portName, portId, incidentType } = body;
                const config = loadConfig();

                let targetPort = null;
                if (portName) {
                    targetPort = config.ports.find(p => p.name.toLowerCase() === portName.trim().toLowerCase());
                } else if (portId) {
                    targetPort = config.ports.find(p => p.id === Number(portId));
                }
                if (!targetPort) {
                    return sendError(res, 404, '시뮬레이션 대상 포트를 찾을 수 없습니다.');
                }

                const type = incidentType || 'LINK_DOWN';
                if (type === 'LINK_DOWN') {
                    targetPort.status = 'down';
                } else if (type === 'PORT_SECURITY_VIOLATION') {
                    targetPort.status = 'down';
                    targetPort.errDisable = true;
                    if (!targetPort.portSecurity) {
                        targetPort.portSecurity = { enabled: true, maxMac: 1, violationAction: 'shutdown', sticky: false };
                    }
                } else if (type === 'POE_FAULT') {
                    if (targetPort.poe) {
                        targetPort.poe.status = 'faulty';
                        targetPort.poe.powerWatts = 0;
                    }
                }

                saveConfig(config);

                const report = await generateAndDispatchIncidentReport({
                    portId: targetPort.id,
                    portName: targetPort.name,
                    incidentType: type,
                    severity: type === 'PORT_SECURITY_VIOLATION' ? 'CRITICAL' : 'HIGH'
                }, config, `System-Monitor Live Simulation`);

                logEvent('ALERT', session.username, clientIp, `장애 시뮬레이션 및 보고서 발송: ${targetPort.name} (${type})`, 'SUCCESS');
                return sendJson(res, 200, {
                    success: true,
                    message: `포트 ${targetPort.name}에 장애 시뮬레이션이 적용되었으며 담당자에게 보고서가 발송되었습니다.`,
                    report,
                    port: targetPort
                });
            }

            // ----------------------------------------------------
            // 12. 전원 감시 및 실시간 전원 꺼짐 경보/복구 API
            // ----------------------------------------------------
            if (pathname === '/api/switch/power/alerts' && req.method === 'GET') {
                const alerts = getActivePowerAlerts();
                return sendJson(res, 200, { success: true, alerts });
            }

            if (pathname.startsWith('/api/switch/power/alerts/') && req.method === 'DELETE') {
                const alertId = pathname.replace('/api/switch/power/alerts/', '').trim();
                const dismissed = dismissPowerAlert(alertId);
                logEvent('POWER', session.username, clientIp, `전원 경보 수동 해제: ${alertId}`, 'SUCCESS');
                return sendJson(res, 200, { success: true, message: '전원 경보가 확인 처리되었습니다.', dismissed });
            }

            if (pathname === '/api/switch/power/simulate' && req.method === 'POST') {
                const body = await parseJsonBody(req);
                const { type, deviceId, portId, reason, action } = body;
                const reg = loadDevicesRegistry();
                const targetDevId = deviceId || reg.activeDeviceId;

                if (type === 'poe') {
                    if (!portId) return sendError(res, 400, 'PoE 전원 차단 대상 포트 ID를 지정해주세요.');
                    const result = await triggerPoePowerOff(targetDevId, portId, reason || 'PoE 전원 공급 차단 테스트');
                    return sendJson(res, 200, {
                        success: true,
                        message: `포트 연결 PoE 장비 전원 꺼짐 감지 및 담당자(${result.deliveryResult.recipient}) 이메일 발송 완료!`,
                        report: result.incidentData,
                        deliveryResult: result.deliveryResult
                    });
                }

                if (action === 'on') {
                    const result = await triggerDevicePowerOn(targetDevId);
                    return sendJson(res, 200, {
                        success: true,
                        message: `장비 [${result.device.name}] 전원이 정상 인가 및 복구되었습니다. 복구 안내 메일 발송 완료!`,
                        device: result.device,
                        deliveryResult: result.deliveryResult
                    });
                }

                // 스위치 장비 전원 꺼짐 시뮬레이션
                const result = await triggerDevicePowerOff(targetDevId, reason || '스위치 AC 전원 케이블 분리 또는 정전 감지');
                return sendJson(res, 200, {
                    success: true,
                    message: `[긴급] 장비 [${result.device.name} (${result.device.ipAddress})] 전원 꺼짐 감지! 담당자(${result.deliveryResult.recipient}) 긴급 메일 발송 완료!`,
                    report: result.incidentData,
                    device: result.device,
                    deliveryResult: result.deliveryResult
                });
            }

            if (pathname === '/api/switch/power/restore' && req.method === 'POST') {
                const body = await parseJsonBody(req);
                const { deviceId } = body;
                const reg = loadDevicesRegistry();
                const targetDevId = deviceId || reg.activeDeviceId;

                const result = await triggerDevicePowerOn(targetDevId);
                return sendJson(res, 200, {
                    success: true,
                    message: `장비 [${result.device.name} (${result.device.ipAddress})] 전원이 정상 복구되었습니다.`,
                    device: result.device,
                    deliveryResult: result.deliveryResult
                });
            }

            // 사용자 관리 (Admin 전용)
            if (pathname.startsWith('/api/users')) {
                if (session.role !== 'admin') return sendError(res, 403, '관리자 권한 필요');
                if (pathname === '/api/users' && req.method === 'GET') {
                    const users = loadUsers().map(u => ({ username: u.username, role: u.role, createdAt: u.createdAt }));
                    return sendJson(res, 200, { success: true, users });
                }
            }

            return sendError(res, 404, '존재하지 않는 API 엔드포인트입니다.');

        } catch (err) {
            return sendError(res, 500, '서버 내부 에러', err);
        }
    }

    if (req.method === 'GET' || req.method === 'HEAD') {
        serveStaticFile(req, res, pathname);
        return;
    }

    sendError(res, 405, '지원하지 않는 HTTP 메서드입니다.');
});

server.listen(PORT, () => {
    console.log(`=======================================================`);
    console.log(`[SECURE L2 SWITCH WEB CONSOLE SERVER RUNNING]`);
    console.log(`- Listening on: http://localhost:${PORT}`);
    console.log(`- Cisco Catalyst 2960-S Series PoE+ 실시간 연동 지원`);
    console.log(`=======================================================`);
});
