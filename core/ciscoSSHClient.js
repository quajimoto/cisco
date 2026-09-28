// core/ciscoSSHClient.js
// Cisco Catalyst 2960-S Series PoE+ 실시간 SSH 및 Telnet 연결 클라이언트
// 프롬프트 기반 대화형 연속 명령 실행기 (Prompt-driven Interactive CLI Engine)
// Cisco IOS 특유의 keyboard-interactive 인증 및 구형 레거시 암호화 알고리즘 완벽 지원

const net = require('net');
let Client;
try {
    Client = require('ssh2').Client;
} catch (e) {
    Client = null;
}

/**
 * ANSI 이스케이프 시퀀스 제거 헬퍼
 */
function stripAnsi(str) {
    if (!str) return '';
    return str.replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '').replace(/\r/g, '');
}

/**
 * Cisco 프롬프트 완료 상태 감지
 */
function isPromptReady(cleanText, expectedHostname) {
    if (!cleanText) return false;
    const trimmed = cleanText.trim();
    if (trimmed.endsWith('#')) return true;

    const lines = trimmed.split('\n');
    const lastLine = lines[lines.length - 1].trim();

    if (expectedHostname) {
        const escapedHost = expectedHostname.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&');
        const hostRegex = new RegExp(`^${escapedHost}(?:\\([^)]*\\))?#\\s*$`);
        if (hostRegex.test(lastLine)) return true;
    }

    return /[a-zA-Z0-9_\-\.]+(?:\([^)]*\))?#\s*$/.test(lastLine);
}

/**
 * Cisco 2960-S 스위치에 SSH로 접속하여 명령어 프롬프트 기반 연속 실행
 */
function executeCiscoSshCommands(connOptions, commands = []) {
    return new Promise((resolve, reject) => {
        if (!Client) {
            return reject(new Error('ssh2 모듈이 로드되지 않았습니다.'));
        }

        const conn = new Client();
        let fullOutput = '';
        let timer = null;
        let authMethodsTried = [];

        // 60초 전체 세션 타임아웃
        timer = setTimeout(() => {
            conn.end();
            reject(new Error(`Cisco 스위치 [${connOptions.host}] SSH 응답 시간 초과 (60초 타임아웃). IP와 포트를 확인해주세요.`));
        }, 60000);

        conn.on('keyboard-interactive', (name, instructions, instructionsLang, prompts, finish) => {
            authMethodsTried.push('keyboard-interactive');
            const responses = prompts.map(p => {
                const promptText = (p.prompt || '').toLowerCase();
                if (promptText.includes('user') || promptText.includes('login') || promptText.includes('account')) {
                    return connOptions.username || '';
                }
                if (promptText.includes('pass')) {
                    return connOptions.password || '';
                }
                return connOptions.password || '';
            });
            finish(responses);
        });

        conn.on('ready', () => {
            conn.shell({ pty: { term: 'vt100', rows: 100, cols: 300 } }, (err, stream) => {
                if (err) {
                    clearTimeout(timer);
                    conn.end();
                    return reject(err);
                }

                let state = 'CONNECTED';
                let promptBuffer = '';
                let detectedHostname = '';
                let currentCmdIdx = 0;
                let cmdTimer = null;
                let isExecutingQueue = false;
                let passAttempts = 0;
                let enableAttempts = 0;

                const cmdQueue = [
                    'terminal length 0',
                    'terminal width 0',
                    ...commands,
                    'exit'
                ];

                function sendNextCommand() {
                    if (cmdTimer) {
                        clearTimeout(cmdTimer);
                        cmdTimer = null;
                    }
                    if (currentCmdIdx < cmdQueue.length) {
                        const cmd = cmdQueue[currentCmdIdx++];
                        promptBuffer = '';
                        if (stream.writable) {
                            stream.write(cmd + '\n');
                        }

                        // 타임아웃 안전 대기 (스택 show running-config 등은 최대 20초)
                        cmdTimer = setTimeout(() => {
                            sendNextCommand();
                        }, 20000);
                    } else {
                        setTimeout(() => {
                            clearTimeout(timer);
                            conn.end();
                        }, 1200);
                    }
                }

                stream.on('data', (data) => {
                    const chunk = data.toString('utf8');
                    fullOutput += chunk;
                    promptBuffer += chunk;

                    const clean = stripAnsi(promptBuffer);

                    // 페이징 처리 (--More--)
                    if (clean.includes('--More--') || clean.includes('- More -')) {
                        if (stream.writable) stream.write(' ');
                        promptBuffer = '';
                        return;
                    }

                    // 인증 거부 감지
                    if (clean.includes('% Login invalid') || clean.includes('% Bad passwords') || clean.includes('% Bad secrets') || clean.includes('% Access denied')) {
                        clearTimeout(timer);
                        if (cmdTimer) clearTimeout(cmdTimer);
                        conn.end();
                        return reject(new Error('Cisco 스위치 SSH 인증 실패: 비밀번호 또는 Enable Secret이 올바르지 않습니다.'));
                    }

                    // Enable 비밀번호 프롬프트 감지 (Password:)
                    if (clean.includes('Password:') && (state === 'ENABLE_REQUESTED' || state === 'ENABLE_SENT')) {
                        if (enableAttempts >= 1) {
                            clearTimeout(timer);
                            if (cmdTimer) clearTimeout(cmdTimer);
                            conn.end();
                            return reject(new Error('Cisco 스위치 Enable 비밀번호(Enable Secret) 인증 실패: 입력하신 Enable Secret이 일치하지 않습니다.'));
                        }
                        enableAttempts++;
                        const secret = connOptions.enableSecret || connOptions.password;
                        if (stream.writable) stream.write(secret + '\n');
                        promptBuffer = '';
                        state = 'ENABLE_SENT';
                        return;
                    }

                    // 일반 로그인 비밀번호 프롬프트
                    if (clean.includes('Password:') && state === 'CONNECTED') {
                        if (passAttempts >= 1) {
                            clearTimeout(timer);
                            if (cmdTimer) clearTimeout(cmdTimer);
                            conn.end();
                            return reject(new Error('Cisco 스위치 SSH 로그인 비밀번호가 일치하지 않습니다.'));
                        }
                        passAttempts++;
                        if (stream.writable) stream.write(connOptions.password + '\n');
                        promptBuffer = '';
                        return;
                    }

                    // 일반 사용자 모드 프롬프트 (Switch>) -> enable 명령
                    if (/[a-zA-Z0-9_\-\.]+>\s*$/.test(clean.trim()) && state !== 'ENABLE_SENT') {
                        if (stream.writable) stream.write('enable\n');
                        state = 'ENABLE_REQUESTED';
                        promptBuffer = '';
                        return;
                    }

                    // 관리자 특권 모드 프롬프트 진입 확인 (Switch#)
                    if (!isExecutingQueue) {
                        const hostMatch = clean.trim().match(/([a-zA-Z0-9_\-\.]+)#\s*$/);
                        if (hostMatch) {
                            detectedHostname = hostMatch[1];
                            isExecutingQueue = true;
                            state = 'RUNNING_COMMANDS';
                            sendNextCommand();
                            return;
                        }
                    }

                    // 명령어 큐 실행 중 프롬프트 수신 확인 -> 다음 명령 순차 전송
                    if (isExecutingQueue && isPromptReady(clean, detectedHostname)) {
                        sendNextCommand();
                    }
                });

                stream.on('close', () => {
                    clearTimeout(timer);
                    if (cmdTimer) clearTimeout(cmdTimer);
                    conn.end();
                    resolve({ success: true, output: fullOutput });
                });
            });
        });

        conn.on('error', (err) => {
            clearTimeout(timer);
            let errMsg = err.message || '';
            if (errMsg.includes('All configured authentication methods failed')) {
                errMsg = `Cisco 스위치 SSH 인증 실패: 스위치에 등록된 계정명(${connOptions.username}) 또는 비밀번호가 불일치하거나, VTY 라인에 SSH 접근 권한이 없습니다.`;
            }
            reject(new Error(`SSH 연결 오류 [${connOptions.host}]: ${errMsg}`));
        });

        try {
            conn.connect({
                host: connOptions.host,
                port: connOptions.port || 22,
                username: connOptions.username,
                password: connOptions.password,
                tryKeyboard: true,
                readyTimeout: 20000,
                keepaliveInterval: 5000,
                algorithms: {
                    kex: [
                        'diffie-hellman-group14-sha1',
                        'diffie-hellman-group-exchange-sha1',
                        'diffie-hellman-group1-sha1',
                        'diffie-hellman-group14-sha256',
                        'diffie-hellman-group-exchange-sha256',
                        'ecdh-sha2-nistp256',
                        'ecdh-sha2-nistp384'
                    ],
                    cipher: [
                        'aes128-cbc',
                        '3des-cbc',
                        'aes256-cbc',
                        'aes128-ctr',
                        'aes192-ctr',
                        'aes256-ctr'
                    ],
                    serverHostKey: [
                        'ssh-rsa',
                        'rsa-sha2-256',
                        'rsa-sha2-512',
                        'ssh-dss',
                        'ecdsa-sha2-nistp256'
                    ],
                    hmac: [
                        'hmac-sha1',
                        'hmac-sha2-256',
                        'hmac-sha2-512',
                        'hmac-md5'
                    ]
                }
            });
        } catch (connErr) {
            clearTimeout(timer);
            reject(connErr);
        }
    });
}

/**
 * Cisco 2960-S Telnet 연결 클라이언트 (프롬프트 기반 대화형 연속 실행 & RFC 854 완벽 지원)
 */
function executeCiscoTelnetCommands(connOptions, commands = []) {
    return new Promise((resolve, reject) => {
        const socket = new net.Socket();
        let fullOutput = '';
        let timer = null;
        let state = 'INIT';
        let promptBuffer = '';
        let detectedHostname = '';
        let currentCmdIdx = 0;
        let cmdTimer = null;
        let isExecutingQueue = false;
        let passAttempts = 0;
        let enableAttempts = 0;

        // 60초 전체 세션 타임아웃
        timer = setTimeout(() => {
            socket.destroy();
            reject(new Error(`Cisco 스위치 [${connOptions.host}] Telnet 응답 시간 초과 (60초 타임아웃). 호스트 IP 및 네트워크 연결을 확인해주세요.`));
        }, 60000);

        socket.connect(connOptions.port || 23, connOptions.host, () => {
            state = 'CONNECTED';
        });

        const cmdQueue = [
            'terminal length 0',
            'terminal width 0',
            ...commands,
            'exit'
        ];

        function sendNextCommand() {
            if (cmdTimer) {
                clearTimeout(cmdTimer);
                cmdTimer = null;
            }
            if (currentCmdIdx < cmdQueue.length) {
                const cmd = cmdQueue[currentCmdIdx++];
                promptBuffer = '';
                if (!socket.destroyed) {
                    socket.write(cmd + '\r\n');
                }

                // 타임아웃 안전 대기
                cmdTimer = setTimeout(() => {
                    sendNextCommand();
                }, 20000);
            } else {
                setTimeout(() => {
                    clearTimeout(timer);
                    socket.end();
                }, 1200);
            }
        }

        socket.on('data', (data) => {
            // Telnet IAC 프로토콜 바이트 협상 및 정제
            let cleanChunk = '';
            for (let i = 0; i < data.length; i++) {
                if (data[i] === 255 && i + 1 < data.length) {
                    const cmd = data[i + 1];
                    if (cmd >= 251 && cmd <= 254 && i + 2 < data.length) {
                        const opt = data[i + 2];
                        if (cmd === 253 && !socket.destroyed) socket.write(Buffer.from([255, 252, opt])); // DO -> WONT
                        if (cmd === 251 && !socket.destroyed) socket.write(Buffer.from([255, 253, opt])); // WILL -> DO
                        i += 2;
                        continue;
                    }
                    i += 1;
                    continue;
                }
                cleanChunk += String.fromCharCode(data[i]);
            }

            fullOutput += cleanChunk;
            promptBuffer += cleanChunk;

            const clean = stripAnsi(promptBuffer);

            // 페이징 처리 (--More--)
            if (clean.includes('--More--') || clean.includes('- More -')) {
                if (!socket.destroyed) socket.write(' ');
                promptBuffer = '';
                return;
            }

            // 인증 거부 감지
            if (clean.includes('% Login invalid') || clean.includes('% Bad passwords') || clean.includes('% Bad secrets') || clean.includes('% Access denied')) {
                clearTimeout(timer);
                if (cmdTimer) clearTimeout(cmdTimer);
                socket.destroy();
                return reject(new Error('Cisco 스위치 Telnet 인증 실패: 비밀번호 또는 Enable Secret이 올바르지 않습니다.'));
            }

            // Username 프롬프트 (스위치에 login local이 구성된 경우)
            if ((clean.includes('Username:') || clean.includes('login:')) && state !== 'USER_SENT') {
                socket.write((connOptions.username || 'admin') + '\r\n');
                state = 'USER_SENT';
                promptBuffer = '';
                return;
            }

            // Enable 비밀번호 프롬프트
            if (clean.includes('Password:') && (state === 'ENABLE_REQUESTED' || state === 'ENABLE_SENT')) {
                if (enableAttempts >= 1) {
                    clearTimeout(timer);
                    if (cmdTimer) clearTimeout(cmdTimer);
                    socket.destroy();
                    return reject(new Error('Cisco 스위치 Enable 비밀번호(Enable Secret) 인증 실패: 입력하신 Enable Secret이 일치하지 않습니다. 관리자 모드 암호를 입력해주세요.'));
                }
                enableAttempts++;
                const secret = connOptions.enableSecret || connOptions.password;
                socket.write(secret + '\r\n');
                state = 'ENABLE_SENT';
                promptBuffer = '';
                return;
            }

            // 일반 로그인 Password 프롬프트
            if (clean.includes('Password:')) {
                if (passAttempts >= 1) {
                    clearTimeout(timer);
                    if (cmdTimer) clearTimeout(cmdTimer);
                    socket.destroy();
                    return reject(new Error('Cisco 스위치 Telnet 비밀번호가 일치하지 않습니다. 콘솔/VTY 로그인 비밀번호를 확인해주세요.'));
                }
                passAttempts++;
                socket.write(connOptions.password + '\r\n');
                state = 'PASS_SENT';
                promptBuffer = '';
                return;
            }

            // 일반 사용자 모드 프롬프트 (Switch>)
            if (/[a-zA-Z0-9_\-\.]+>\s*$/.test(clean.trim()) && state !== 'ENABLE_SENT') {
                socket.write('enable\r\n');
                state = 'ENABLE_REQUESTED';
                promptBuffer = '';
                return;
            }

            // 관리자 모드 프롬프트 진입 확인 (Switch#)
            if (!isExecutingQueue) {
                const hostMatch = clean.trim().match(/([a-zA-Z0-9_\-\.]+)#\s*$/);
                if (hostMatch) {
                    detectedHostname = hostMatch[1];
                    isExecutingQueue = true;
                    state = 'RUNNING_COMMANDS';
                    sendNextCommand();
                    return;
                }
            }

            // 명령어 큐 실행 중 프롬프트 수신 확인 -> 다음 명령 순차 전송
            if (isExecutingQueue && isPromptReady(clean, detectedHostname)) {
                sendNextCommand();
            }
        });

        socket.on('close', () => {
            clearTimeout(timer);
            if (cmdTimer) clearTimeout(cmdTimer);
            resolve({ success: true, output: fullOutput });
        });

        socket.on('error', (err) => {
            clearTimeout(timer);
            if (cmdTimer) clearTimeout(cmdTimer);
            reject(new Error(`Telnet 연결 실패 [${connOptions.host}]: ${err.message}`));
        });
    });
}

/**
 * 포트 번호에 따라 SSH 또는 Telnet 자동 선택 실행
 */
async function executeCiscoCommands(connOptions, commands = []) {
    const port = connOptions.port ? Number(connOptions.port) : 22;
    if (port === 23) {
        return await executeCiscoTelnetCommands(connOptions, commands);
    }

    try {
        return await executeCiscoSshCommands(connOptions, commands);
    } catch (sshErr) {
        if (sshErr.message.includes('ECONNREFUSED') && port === 22) {
            console.log(`[Cisco Client] SSH 포트 22 거절됨, Telnet 23 포트로 자동 전환 시도...`);
            const telnetOptions = { ...connOptions, port: 23 };
            return await executeCiscoTelnetCommands(telnetOptions, commands);
        }
        throw sshErr;
    }
}

/**
 * Cisco 2960-S 스위치에서 Running-Config와 Power-Inline 정보를 원격 수집
 */
async function pullLiveCiscoConfig(connOptions) {
    const commands = [
        'show running-config',
        'show power inline',
        'show interfaces status',
        'show vlan brief',
        'show mac address-table',
        'show ip arp'
    ];

    const result = await executeCiscoCommands(connOptions, commands);
    return result.output;
}

/**
 * UI에서 변경된 설정을 실제 Cisco 2960-S 스위치에 반영 (Commit)
 */
async function pushCiscoConfig(connOptions, diffCommands) {
    const result = await executeCiscoCommands(connOptions, diffCommands);
    return result.output;
}

module.exports = {
    executeCiscoSshCommands,
    executeCiscoTelnetCommands,
    executeCiscoCommands,
    pullLiveCiscoConfig,
    pushCiscoConfig
};
