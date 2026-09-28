// security/validator.js
// 시큐어코딩 가이드: 입력데이터 검증 및 표현 (CWE-20, CWE-79, CWE-89 등)

/**
 * HTML 특수문자 이스케이프 (XSS 방지)
 */
function escapeHtml(str) {
    if (typeof str !== 'string') return '';
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;')
        .replace(/\//g, '&#x2F;');
}

/**
 * 정수 범위 검증
 */
function isValidInteger(val, min, max) {
    const num = Number(val);
    if (!Number.isInteger(num)) return false;
    if (min !== undefined && num < min) return false;
    if (max !== undefined && num > max) return false;
    return true;
}

/**
 * IPv4 주소 검증
 */
function isValidIPv4(ip) {
    if (typeof ip !== 'string') return false;
    const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$/;
    return ipv4Regex.test(ip.trim());
}

/**
 * 서브넷 마스크 검증
 */
function isValidSubnetMask(mask) {
    if (!isValidIPv4(mask)) return false;
    const validMasks = [
        '255.255.255.255', '255.255.255.254', '255.255.255.252', '255.255.255.248',
        '255.255.255.240', '255.255.255.224', '255.255.255.192', '255.255.255.128',
        '255.255.255.0',   '255.255.254.0',   '255.255.252.0',   '255.255.248.0',
        '255.255.240.0',   '255.255.224.0',   '255.255.192.0',   '255.255.128.0',
        '255.255.0.0',     '255.254.0.0',     '255.252.0.0',     '255.248.0.0',
        '255.240.0.0',     '255.224.0.0',     '255.192.0.0',     '255.128.0.0',
        '255.0.0.0'
    ];
    return validMasks.includes(mask.trim());
}

/**
 * MAC 주소 정규식 검증 (XX:XX:XX:XX:XX:XX 또는 XX-XX-XX-XX-XX-XX 또는 XXXX.XXXX.XXXX)
 */
function isValidMacAddress(mac) {
    if (typeof mac !== 'string') return false;
    const standardMacRegex = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;
    const ciscoMacRegex = /^[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}$/;
    return standardMacRegex.test(mac.trim()) || ciscoMacRegex.test(mac.trim());
}

/**
 * MAC 주소를 표준 형식 (XX:XX:XX:XX:XX:XX 대문자)으로 정규화
 */
function normalizeMacAddress(mac) {
    if (!isValidMacAddress(mac)) return null;
    const clean = mac.replace(/[:.-]/g, '').toUpperCase();
    return clean.match(/.{1,2}/g).join(':');
}

/**
 * VLAN ID 검증 (1 ~ 4094)
 */
function isValidVlanId(vlanId) {
    return isValidInteger(vlanId, 1, 4094);
}

/**
 * 스위치 포트 번호 검증 (1 ~ 512, 단일 및 4단 스택 스위치 지원)
 */
function isValidPortId(portId) {
    return isValidInteger(portId, 1, 512);
}

/**
 * 호스트명 검증 (RFC 1123: 영숫자, 하이픈, 1~63자)
 */
function isValidHostname(hostname) {
    if (typeof hostname !== 'string') return false;
    const trimmed = hostname.trim();
    if (trimmed.length < 1 || trimmed.length > 63) return false;
    const hostnameRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;
    return hostnameRegex.test(trimmed);
}

/**
 * 안전한 이름/설명 문자열 검증 (영문, 숫자, 한글, 하이픈, 언더스코어, 공백, 점만 허용)
 */
function isSafeDescription(desc, maxLength = 64) {
    if (typeof desc !== 'string') return false;
    const trimmed = desc.trim();
    if (trimmed.length > maxLength) return false;
    // XSS 또는 인젝션 공격 유발 특수문자(<, >, ", ', ;, &, `, \, | 등) 차단
    const safeTextRegex = /^[a-zA-Z0-9가-힣ㄱ-ㅎㅏ-ㅣ_\-\.\s]*$/;
    return safeTextRegex.test(trimmed);
}

/**
 * 패스워드 복잡도 검증
 * - 최소 8자 이상
 * - 영문 대문자, 소문자, 숫자, 특수문자 각 1개 이상 포함
 */
function isValidPasswordComplexity(password) {
    if (typeof password !== 'string') return false;
    if (password.length < 8 || password.length > 64) return false;
    const hasUpper = /[A-Z]/.test(password);
    const hasLower = /[a-z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    const hasSpecial = /[!@#$%^&*(),.?":{}|<>_\-+=~`]/.test(password);
    return hasUpper && hasLower && hasNumber && hasSpecial;
}

/**
 * 이메일 주소 형식 검증 (RFC 5322 간소화 정규식)
 */
function isValidEmail(email) {
    if (typeof email !== 'string') return false;
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return emailRegex.test(email.trim());
}

/**
 * 포트 속도 허용값 화이트리스트
 */
const ALLOWED_PORT_SPEEDS = ['auto', '10M', '100M', '1G', '10G'];
const ALLOWED_PORT_DUPLEX = ['auto', 'full', 'half'];
const ALLOWED_VLAN_MODES = ['access', 'trunk', 'hybrid'];
const ALLOWED_VIOLATION_ACTIONS = ['protect', 'restrict', 'shutdown'];
const ALLOWED_STP_MODES = ['rstp', 'stp', 'disabled'];

module.exports = {
    escapeHtml,
    isValidInteger,
    isValidIPv4,
    isValidSubnetMask,
    isValidMacAddress,
    normalizeMacAddress,
    isValidVlanId,
    isValidPortId,
    isValidHostname,
    isSafeDescription,
    isValidPasswordComplexity,
    isValidEmail,
    ALLOWED_PORT_SPEEDS,
    ALLOWED_PORT_DUPLEX,
    ALLOWED_VLAN_MODES,
    ALLOWED_VIOLATION_ACTIONS,
    ALLOWED_STP_MODES
};
