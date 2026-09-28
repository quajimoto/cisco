// core/auditLogger.js
// 시큐어코딩 가이드: 감사 로깅 (CWE-778 불충분한 로깅 대응)

const fs = require('fs');
const path = require('path');

const LOGS_FILE = path.join(__dirname, '..', 'data', 'audit_logs.json');
const MAX_LOG_ENTRIES = 1000; // 최대 1000개 보관

/**
 * 감사 로그 초기화 및 로드
 */
function loadLogs() {
    try {
        if (!fs.existsSync(LOGS_FILE)) {
            const dir = path.dirname(LOGS_FILE);
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir, { recursive: true });
            }
            fs.writeFileSync(LOGS_FILE, JSON.stringify([], null, 2), 'utf8');
            return [];
        }
        const content = fs.readFileSync(LOGS_FILE, 'utf8');
        return JSON.parse(content);
    } catch (err) {
        console.error('감사 로그 로드 에러:', err.message);
        return [];
    }
}

/**
 * 로그 파일 원자적 저장 (경쟁 상태 방지)
 */
function saveLogs(logs) {
    try {
        const tempFile = `${LOGS_FILE}.tmp`;
        fs.writeFileSync(tempFile, JSON.stringify(logs, null, 2), 'utf8');
        fs.renameSync(tempFile, LOGS_FILE);
    } catch (err) {
        console.error('감사 로그 저장 에러:', err.message);
    }
}

/**
 * 새로운 감사 로그 기록
 * @param {string} category AUTH, PORT, VLAN, MAC, SECURITY, STP, LACP, SYSTEM
 * @param {string} username 수행 사용자 ID
 * @param {string} ip 클라이언트 IP 주소
 * @param {string} action 수행 작업 설명
 * @param {string} status SUCCESS 또는 FAILURE
 * @param {object} details 추가 상세 정보
 */
function logEvent(category, username, ip, action, status = 'SUCCESS', details = null) {
    const logs = loadLogs();
    const newEntry = {
        id: Date.now().toString(36) + Math.random().toString(36).substring(2, 7),
        timestamp: new Date().toISOString(),
        category,
        username: username || 'anonymous',
        ip: ip || '127.0.0.1',
        action,
        status,
        details: details || {}
    };

    logs.unshift(newEntry); // 최신 로그가 맨 앞
    if (logs.length > MAX_LOG_ENTRIES) {
        logs.length = MAX_LOG_ENTRIES;
    }

    saveLogs(logs);
    return newEntry;
}

/**
 * 감사 로그 검색 및 필터링
 */
function getLogs(filter = {}) {
    let logs = loadLogs();

    if (filter.category) {
        logs = logs.filter(l => l.category === filter.category);
    }
    if (filter.username) {
        logs = logs.filter(l => l.username.toLowerCase().includes(filter.username.toLowerCase()));
    }
    if (filter.status) {
        logs = logs.filter(l => l.status === filter.status);
    }
    if (filter.search) {
        const q = filter.search.toLowerCase();
        logs = logs.filter(l => 
            l.action.toLowerCase().includes(q) || 
            l.username.toLowerCase().includes(q) ||
            l.category.toLowerCase().includes(q)
        );
    }

    const limit = parseInt(filter.limit, 10) || 100;
    return logs.slice(0, limit);
}

module.exports = {
    logEvent,
    getLogs
};
