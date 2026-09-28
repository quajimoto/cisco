// security/csrf.js
// 시큐어코딩 가이드: 크로스사이트 요청 위조 방지 (CWE-352 CSRF)

const crypto = require('crypto');

/**
 * CSRF 토큰 검증
 * 상태 변경 요청(POST, PUT, DELETE 등)에 대해 세션의 csrfToken과 헤더의 x-csrf-token 일치 여부 확인
 */
function verifyCsrfToken(req, session) {
    // 안전한 HTTP 메서드는 검증 면제
    const safeMethods = ['GET', 'HEAD', 'OPTIONS'];
    if (safeMethods.includes(req.method)) {
        return true;
    }

    if (!session || !session.csrfToken) {
        return false;
    }

    const clientToken = req.headers['x-csrf-token'];
    if (!clientToken || typeof clientToken !== 'string') {
        return false;
    }

    const serverTokenBuf = Buffer.from(session.csrfToken, 'utf8');
    const clientTokenBuf = Buffer.from(clientToken, 'utf8');

    if (serverTokenBuf.length !== clientTokenBuf.length) {
        return false;
    }

    return crypto.timingSafeEqual(serverTokenBuf, clientTokenBuf);
}

module.exports = {
    verifyCsrfToken
};
