// security/auth.js
// 시큐어코딩 가이드: 보안기능 (인증, 인가, 솔트 해시, 무차별 대입 방지, 세션 고정 방지, 세션 만료)

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const USERS_FILE = path.join(__dirname, '..', 'data', 'users.json');

// 세션 타임아웃: 15분 (밀리초)
const SESSION_TIMEOUT_MS = 15 * 60 * 1000;
// 계정 잠금 임계값: 5회 실패 시 5분 잠금
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 5 * 60 * 1000;

// 인메모리 세션 스토어
// sessionId -> { username, role, lastActivity, csrfToken }
const sessions = new Map();

// 로그인 실패 추적
// username -> { attempts: number, lockedUntil: timestamp | null }
const loginAttempts = new Map();

/**
 * 사용자 데이터 로드
 */
function loadUsers() {
    try {
        if (!fs.existsSync(USERS_FILE)) {
            initDefaultUsers();
        }
        const data = fs.readFileSync(USERS_FILE, 'utf8');
        return JSON.parse(data);
    } catch (err) {
        console.error('사용자 파일 로드 에러:', err.message);
        return [];
    }
}

/**
 * 사용자 데이터 안전한 원자적 저장
 */
function saveUsers(users) {
    const tempFile = `${USERS_FILE}.tmp`;
    fs.writeFileSync(tempFile, JSON.stringify(users, null, 2), 'utf8');
    fs.renameSync(tempFile, USERS_FILE);
}

/**
 * PBKDF2 기반 안전한 솔트 해싱
 */
function hashPassword(password, salt = null) {
    if (!salt) {
        salt = crypto.randomBytes(16).toString('hex');
    }
    const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
    return { salt, hash };
}

/**
 * 타이밍 안전한 비밀번호 검증 (Timing-attack 방어: crypto.timingSafeEqual)
 */
function verifyPassword(password, salt, storedHash) {
    const currentHash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
    const bufA = Buffer.from(currentHash, 'hex');
    const bufB = Buffer.from(storedHash, 'hex');
    if (bufA.length !== bufB.length) return false;
    return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * 기본 사용자 초기화 (Admin, Operator, Viewer)
 */
function initDefaultUsers() {
    const usersDir = path.dirname(USERS_FILE);
    if (!fs.existsSync(usersDir)) {
        fs.mkdirSync(usersDir, { recursive: true });
    }

    const adminHash = hashPassword('Admin@1234!');
    const operatorHash = hashPassword('Operator@1234!');
    const viewerHash = hashPassword('Viewer@1234!');

    const defaultUsers = [
        {
            username: 'admin',
            role: 'admin',
            salt: adminHash.salt,
            hash: adminHash.hash,
            createdAt: new Date().toISOString()
        },
        {
            username: 'operator',
            role: 'operator',
            salt: operatorHash.salt,
            hash: operatorHash.hash,
            createdAt: new Date().toISOString()
        },
        {
            username: 'viewer',
            role: 'viewer',
            salt: viewerHash.salt,
            hash: viewerHash.hash,
            createdAt: new Date().toISOString()
        }
    ];

    saveUsers(defaultUsers);
}

/**
 * 무차별 대입 방어 체크
 */
function checkLockout(username) {
    const now = Date.now();
    const track = loginAttempts.get(username);
    if (!track) return { locked: false };

    if (track.lockedUntil && track.lockedUntil > now) {
        const remainingSec = Math.ceil((track.lockedUntil - now) / 1000);
        return { locked: true, remainingSec };
    }

    if (track.lockedUntil && track.lockedUntil <= now) {
        // 잠금 시간 경과 시 리셋
        loginAttempts.delete(username);
        return { locked: false };
    }

    return { locked: false };
}

/**
 * 로그인 실패 기록
 */
function recordLoginFailure(username) {
    const now = Date.now();
    let track = loginAttempts.get(username);
    if (!track) {
        track = { attempts: 0, lockedUntil: null };
        loginAttempts.set(username, track);
    }
    track.attempts += 1;
    if (track.attempts >= MAX_LOGIN_ATTEMPTS) {
        track.lockedUntil = now + LOCKOUT_DURATION_MS;
        return { locked: true, remainingSec: Math.ceil(LOCKOUT_DURATION_MS / 1000) };
    }
    return { locked: false, attempts: track.attempts, remaining: MAX_LOGIN_ATTEMPTS - track.attempts };
}

/**
 * 로그인 성공 시 실패 기록 초기화
 */
function recordLoginSuccess(username) {
    loginAttempts.delete(username);
}

/**
 * 암호학적 난수로 세션 ID 및 CSRF 토큰 생성
 */
function generateSecureToken(bytes = 32) {
    return crypto.randomBytes(bytes).toString('hex');
}

/**
 * 세션 생성 (세션 고정 방지)
 */
function createSession(username, role) {
    const sessionId = generateSecureToken(32);
    const csrfToken = generateSecureToken(24);
    const now = Date.now();

    sessions.set(sessionId, {
        username,
        role,
        lastActivity: now,
        csrfToken
    });

    return { sessionId, csrfToken };
}

/**
 * 세션 검증 및 유효시간 갱신 (15분 타임아웃)
 */
function validateSession(sessionId) {
    if (!sessionId || !sessions.has(sessionId)) {
        return null;
    }
    const session = sessions.get(sessionId);
    const now = Date.now();

    if (now - session.lastActivity > SESSION_TIMEOUT_MS) {
        sessions.delete(sessionId);
        return null;
    }

    session.lastActivity = now;
    return session;
}

/**
 * 세션 삭제 (로그아웃)
 */
function destroySession(sessionId) {
    if (sessionId && sessions.has(sessionId)) {
        sessions.delete(sessionId);
        return true;
    }
    return false;
}

/**
 * 주기적 만료 세션 정리 (메모리 누수 방지)
 */
setInterval(() => {
    const now = Date.now();
    for (const [id, s] of sessions.entries()) {
        if (now - s.lastActivity > SESSION_TIMEOUT_MS) {
            sessions.delete(id);
        }
    }
}, 60 * 1000);

module.exports = {
    loadUsers,
    saveUsers,
    hashPassword,
    verifyPassword,
    initDefaultUsers,
    checkLockout,
    recordLoginFailure,
    recordLoginSuccess,
    createSession,
    validateSession,
    destroySession,
    SESSION_TIMEOUT_MS
};
