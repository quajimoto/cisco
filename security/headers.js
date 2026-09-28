// security/headers.js
// 시큐어코딩 가이드: 보안 헤더 설정 (XSS 방지, 클릭재킹 방지, MIME 스니핑 방지)

function setSecurityHeaders(res) {
    // 1. Content-Security-Policy (CSP)
    // 인라인 스크립트 실행 제한 및 리소스 로딩 화이트리스트 적용
    res.setHeader('Content-Security-Policy', 
        "default-src 'self'; " +
        "script-src 'self'; " +
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
        "font-src 'self' https://fonts.gstatic.com; " +
        "img-src 'self' data:; " +
        "connect-src 'self'; " +
        "frame-ancestors 'none'; " +
        "base-uri 'self'; " +
        "form-action 'self';"
    );

    // 2. X-Frame-Options (CWE-1021 클릭재킹 방지)
    res.setHeader('X-Frame-Options', 'DENY');

    // 3. X-Content-Type-Options (CWE-430 MIME 스니핑 방지)
    res.setHeader('X-Content-Type-Options', 'nosniff');

    // 4. Referrer-Policy (민감한 URL 정보 유출 방지)
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

    // 5. Permissions-Policy (불필요한 브라우저 기능 제한)
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

    // 6. 캐시 제어 (민감한 네트워크 설정 정보 캐싱 방지)
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
}

module.exports = { setSecurityHeaders };
