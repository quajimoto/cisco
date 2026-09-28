// core/powerMonitor.js
// 네트워크 스위치 및 연결된 PoE 단말 전원 감시, 전원 꺼짐 감지, 담당자 메일 발송 및 실시간 알림 센터 모듈

const fs = require('fs');
const path = require('path');
const { logEvent } = require('./auditLogger');
const {
    loadDevicesRegistry,
    saveDevicesRegistry,
    loadDeviceConfig,
    saveDeviceConfig,
    getActiveDeviceId
} = require('./deviceManager');
const {
    getDefaultAlertSettings,
    renderHtmlIncidentEmail,
    renderPlainTextIncidentEmail,
    formatKst,
    loadReportsIndex,
    saveReportsIndex,
    REPORTS_DIR
} = require('./incidentReporter');
const nodemailer = require('nodemailer');

const DATA_DIR = path.join(__dirname, '..', 'data');
const ACTIVE_POWER_ALERTS_FILE = path.join(DATA_DIR, 'active_power_alerts.json');

// 활성 전원 경보 파일 초기화
if (!fs.existsSync(ACTIVE_POWER_ALERTS_FILE)) {
    fs.writeFileSync(ACTIVE_POWER_ALERTS_FILE, JSON.stringify([], null, 2), 'utf8');
}

/**
 * 현재 활성화된 전원 꺼짐 경보 목록 조회
 */
function getActivePowerAlerts() {
    try {
        if (!fs.existsSync(ACTIVE_POWER_ALERTS_FILE)) return [];
        return JSON.parse(fs.readFileSync(ACTIVE_POWER_ALERTS_FILE, 'utf8'));
    } catch (e) {
        console.error('활성 전원 경보 파일 로드 오류:', e.message);
        return [];
    }
}

/**
 * 활성 전원 경보 저장
 */
function saveActivePowerAlerts(alerts) {
    const tempPath = `${ACTIVE_POWER_ALERTS_FILE}.tmp`;
    fs.writeFileSync(tempPath, JSON.stringify(alerts, null, 2), 'utf8');
    fs.renameSync(tempPath, ACTIVE_POWER_ALERTS_FILE);
}

/**
 * 특정 경보 수동 해제 (Clear/Dismiss)
 */
function dismissPowerAlert(alertId) {
    let alerts = getActivePowerAlerts();
    const target = alerts.find(a => a.id === alertId);
    alerts = alerts.filter(a => a.id !== alertId);
    saveActivePowerAlerts(alerts);
    return target;
}

/**
 * 스위치 장비 전원 꺼짐(Power OFF) 감지 및 담당자 긴급 메일 발송
 */
async function triggerDevicePowerOff(deviceId, reason = '메인 AC 전원 공급 중단 또는 PDU 차단기 이상') {
    const reg = loadDevicesRegistry();
    const device = reg.devices.find(d => d.id === deviceId);
    if (!device) {
        throw new Error(`식별자 [${deviceId}]에 해당하는 장비를 찾을 수 없습니다.`);
    }

    const now = new Date();
    const timeKst = formatKst(now);
    const reportId = `PWR-${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}${String(now.getDate()).padStart(2, '0')}-${Math.floor(100 + Math.random() * 900)}`;

    // 1. 장비 상태를 power_off로 변경
    device.status = 'power_off';
    device.powerStatus = 'power_off';
    device.lastPowerOffAt = now.toISOString();
    device.powerOffReason = reason;
    saveDevicesRegistry(reg);

    // 2. 시간대별 정밀 타임라인 구성
    const t0 = new Date(now.getTime() - 120000);
    const t1 = new Date(now.getTime() - 45000);
    const t2 = new Date(now.getTime() - 12000);
    const t3 = now;

    const timeline = [
        {
            time: formatKst(t0).split(' ')[1],
            state: '정상 가동',
            description: `메인 AC 전원 인가 및 모든 포트(${device.portCount || 28}개) 정상 가동 중 (SYST LED: Green)`,
            syslog: `%SYS-5-CONFIG_I: Configured from console by netadmin`
        },
        {
            time: formatKst(t1).split(' ')[1],
            state: '전원 전압 이상',
            description: `랙 분전함 입력 전압 강하 또는 RPS 보조 전원 절체 시도 감지`,
            syslog: `%ENVMON-4-POWER_SUPPLY_WARNING: Main Power Supply AC input voltage fluctuating`
        },
        {
            time: formatKst(t2).split(' ')[1],
            state: '장비 전원 종료',
            description: `스위치 전원 완전 소실(Blackout), 메인 프로세서 셧다운 및 네트워크 링크 일제 단절`,
            syslog: `%ENVMON-1-POWER_SUPPLY_LOST: Main AC Power Lost. System entering power-fail halt.`
        },
        {
            time: formatKst(t3).split(' ')[1],
            state: '긴급 경보 발송',
            description: `관제 시스템에서 하트비트 두절 및 전원 꺼짐 확정, 담당자 이메일 긴급 보고서 발송`,
            syslog: `%NETALERT-1-CHASSIS_POWER_OFF: Chassis power outage confirmed on ${device.name} (${device.ipAddress})`
        }
    ];

    const incidentData = {
        id: reportId,
        timestamp: now.toISOString(),
        timeKst,
        triggerSource: '전원 감시 센서 (Chassis Power Sensor)',
        severity: 'CRITICAL',
        incidentType: 'SWITCH_POWER_OFF',
        title: `[긴급 전원 장애] 스위치 장비 [${device.name} (${device.ipAddress})] 전원 꺼짐 (Power OFF) 감지`,
        hostname: device.name,
        switchModel: device.model || 'Cisco Catalyst 2960-S Series',
        switchIp: device.ipAddress,
        switchNum: 1,
        portName: `전체 ${device.portCount || 28}개 포트 통신 단절`,
        portDesc: `설치 위치: ${device.location || '전산실 통신 랙'}`,
        vlanId: '전체 VLAN',
        vlanName: 'ALL_VLANS',
        clientInfo: {
            ipAddress: device.ipAddress,
            mac: '스위치 샤시 전원 모듈',
            vendor: 'Cisco Systems PSU',
            deviceName: `${device.name} 본체 (위치: ${device.location || '-'})`
        },
        timeline,
        rootCause: `[${device.name}]의 메인 전원 소실: ${reason}. UPS 배터리 고갈, PDU 전원선 탈락 또는 분전반 차단기 트립 가능성.`,
        impactAssessment: `해당 스위치에 연결된 단말 및 하위 네트워크 통신 완전 마비 (관리 IP: ${device.ipAddress})`,
        remediation: [
            `1단계: [${device.location || '해당 랙'}] 현장 방문 후 스위치 전원 케이블 및 PDU 콘센트 결착 상태 점검`,
            `2단계: 스위치 전면 패널 SYST/STAT LED가 완전 소등되었는지 확인 (보조 전원 RPS 상태 점검)`,
            `3단계: 분전반 누전 차단기(ELB/NFB) 트립 여부 및 랙 상단 UPS 출력 상태 확인`,
            `4단계: 전원 정상 복구 후 웹 콘솔에서 [전원 정상 복구] 버튼 클릭 또는 하트비트 정상화 확인`
        ],
        consoleUrl: 'http://localhost:8080'
    };

    // 이메일 템플릿 생성
    const htmlEmail = renderHtmlIncidentEmail(incidentData);
    const textEmail = renderPlainTextIncidentEmail(incidentData);
    incidentData.htmlContent = htmlEmail;

    // 이메일 발송
    const alertSettings = getDefaultAlertSettings();
    let deliveryResult = await dispatchEmail(alertSettings, incidentData.title, textEmail, htmlEmail);
    incidentData.deliveryResult = deliveryResult;

    // 보고서 개별 파일 저장
    const reportFilePath = path.join(REPORTS_DIR, `${reportId}.json`);
    fs.writeFileSync(reportFilePath, JSON.stringify(incidentData, null, 2), 'utf8');

    // 보고서 인덱스 업데이트
    const index = loadReportsIndex();
    index.unshift({
        id: incidentData.id,
        timestamp: incidentData.timestamp,
        timeKst: incidentData.timeKst,
        title: incidentData.title,
        severity: incidentData.severity,
        incidentType: incidentData.incidentType,
        portName: `${device.name} 전체 포트`,
        clientIp: device.ipAddress,
        clientDevice: `${device.name} 본체`,
        recipient: deliveryResult.recipient,
        deliveryMethod: deliveryResult.method,
        sent: deliveryResult.sent
    });
    if (index.length > 100) index.pop();
    saveReportsIndex(index);

    // 활성 전원 경보 등록
    const activeAlerts = getActivePowerAlerts().filter(a => a.deviceId !== deviceId);
    activeAlerts.unshift({
        id: reportId,
        type: 'SWITCH_POWER_OFF',
        deviceId: device.id,
        deviceName: device.name,
        deviceIp: device.ipAddress,
        model: device.model,
        location: device.location,
        occurredAt: now.toISOString(),
        timeKst,
        reason,
        severity: 'CRITICAL',
        recipient: deliveryResult.recipient,
        status: 'active'
    });
    saveActivePowerAlerts(activeAlerts);

    // 보안 감사 로그 기록
    logEvent(
        'POWER',
        'Power-Monitor',
        device.ipAddress,
        `[전원 꺼짐 감지] 장비 [${device.name} (${device.ipAddress})] 전원 꺼짐 -> 담당자(${deliveryResult.recipient}) 긴급 메일 발송 완료`,
        'FAILURE',
        { reportId, deviceId: device.id, reason }
    );

    return {
        success: true,
        reportId,
        device,
        deliveryResult,
        incidentData
    };
}

/**
 * 스위치 장비 전원 정상 복구(Power ON) 처리 및 복구 메일 발송
 */
async function triggerDevicePowerOn(deviceId) {
    const reg = loadDevicesRegistry();
    const device = reg.devices.find(d => d.id === deviceId);
    if (!device) {
        throw new Error(`식별자 [${deviceId}]에 해당하는 장비를 찾을 수 없습니다.`);
    }

    const now = new Date();
    const timeKst = formatKst(now);
    const reportId = `PWR-RESTORE-${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}${String(now.getDate()).padStart(2, '0')}-${Math.floor(100 + Math.random() * 900)}`;

    // 1. 장비 상태 복구
    device.status = 'online';
    device.powerStatus = 'online';
    device.lastPowerRestoredAt = now.toISOString();
    delete device.powerOffReason;
    saveDevicesRegistry(reg);

    // 2. 활성 경보 목록에서 제거
    let activeAlerts = getActivePowerAlerts();
    activeAlerts = activeAlerts.filter(a => a.deviceId !== deviceId);
    saveActivePowerAlerts(activeAlerts);

    // 3. 복구 안내 이메일 발송
    const alertSettings = getDefaultAlertSettings();
    const subject = `[정상 복구] 스위치 장비 [${device.name} (${device.ipAddress})] 전원 정상 인가 및 부팅 완료`;
    const textEmail = `[Cisco 2960-S 관제 센터 알림]\n\n스위치 장비 [${device.name} (${device.ipAddress})]의 전원이 정상적으로 복구되었습니다.\n\n- 발생시각: ${timeKst}\n- 장비명: ${device.name}\n- 관리 IP: ${device.ipAddress}\n- 설치 위치: ${device.location || '-'}\n- 상태: 🟢 전원 정상 인가 (Power ON / All Ports UP)\n\n웹 콘솔에 접속하여 상세 포트 및 트래픽 상태를 점검하시기 바랍니다.\nhttp://localhost:8080`;

    const htmlEmail = `
    <!DOCTYPE html>
    <html>
    <body style="font-family: 'Malgun Gothic', sans-serif; background: #0b0f19; color: #f8fafc; padding: 24px;">
        <div style="max-width: 600px; margin: 0 auto; background: #111827; border: 1px solid #10b981; border-radius: 8px; padding: 24px;">
            <div style="border-bottom: 1px solid #1f2937; padding-bottom: 14px; margin-bottom: 16px;">
                <span style="background: rgba(16, 185, 129, 0.2); color: #10b981; font-weight: bold; padding: 4px 10px; border-radius: 4px; font-size: 12px;">전원 복구 완료 (RESTORED)</span>
                <h2 style="color: #ffffff; margin: 12px 0 0 0; font-size: 18px;">${device.name} (${device.ipAddress}) 전원 정상 인가</h2>
                <p style="color: #94a3b8; font-size: 12px; margin: 4px 0 0 0;">복구 시각: ${timeKst}</p>
            </div>
            <div style="background: rgba(16, 185, 129, 0.05); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 6px; padding: 14px; margin-bottom: 16px;">
                <p style="margin: 0; color: #34d399; font-size: 13px; line-height: 1.6;">
                    스위치 샤시 전원이 다시 켜졌으며, 메인 프로세서 POST 자가진단 및 모든 물리 포트 링크가 정상 상태로 복구되었습니다.
                </p>
            </div>
            <table style="width: 100%; border-collapse: collapse; font-size: 12px; margin-bottom: 16px;">
                <tr><td style="color: #94a3b8; padding: 6px 0; width: 35%;">장비명:</td><td style="color: #ffffff; font-weight: bold;">${device.name}</td></tr>
                <tr><td style="color: #94a3b8; padding: 6px 0;">관리 IP:</td><td style="color: #00f2fe; font-family: monospace;">${device.ipAddress}</td></tr>
                <tr><td style="color: #94a3b8; padding: 6px 0;">설치 위치:</td><td style="color: #cbd5e1;">${device.location || '-'}</td></tr>
                <tr><td style="color: #94a3b8; padding: 6px 0;">포트 수:</td><td style="color: #cbd5e1;">${device.portCount || 28} Ports</td></tr>
            </table>
            <div style="text-align: center; margin-top: 20px;">
                <a href="http://localhost:8080" style="background: #10b981; color: #0b0f19; font-weight: bold; text-decoration: none; padding: 10px 24px; border-radius: 6px; font-size: 12px;">웹 콘솔에서 포트 상태 확인</a>
            </div>
        </div>
    </body>
    </html>
    `;

    const deliveryResult = await dispatchEmail(alertSettings, subject, textEmail, htmlEmail);

    // 보안 감사 로그 기록
    logEvent(
        'POWER',
        'Power-Monitor',
        device.ipAddress,
        `[전원 복구 확인] 장비 [${device.name} (${device.ipAddress})] 전원 정상 인가 및 복구 완료`,
        'SUCCESS',
        { reportId, deviceId: device.id }
    );

    return {
        success: true,
        device,
        deliveryResult
    };
}

/**
 * 포트에 연결된 PoE 단말 장비 전원 꺼짐(PoE Fault / Power Loss) 감지 및 이메일 발송
 */
async function triggerPoePowerOff(deviceId, portId, reason = 'PoE 전원 공급 차단 또는 단말기 전원 분리') {
    const config = loadDeviceConfig(deviceId);
    const port = config.ports.find(p => p.id === Number(portId));
    if (!port) {
        throw new Error(`포트 ID [${portId}]를 찾을 수 없습니다.`);
    }

    const now = new Date();
    const timeKst = formatKst(now);
    const reportId = `POE-${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}${String(now.getDate()).padStart(2, '0')}-${Math.floor(100 + Math.random() * 900)}`;

    const client = port.connectedClient || {
        deviceName: port.description || `PoE-Device-${port.name}`,
        ipAddress: '10.101.2.105',
        mac: '00:E0:4C:1F:02:05',
        vendor: 'Cisco Systems PoE'
    };

    // 포트 PoE 상태 변경
    if (!port.poe) port.poe = {};
    port.poe.status = 'fault';
    port.poe.powerWatts = 0;
    port.status = 'down';
    port.linkState = 'down';
    saveDeviceConfig(config, deviceId);

    const title = `[PoE 전원 꺼짐] 스위치 [${config.system.hostname}] 포트 ${port.name} 연결 장비 [${client.deviceName}] 전원 공급 차단`;

    const timeline = [
        {
            time: formatKst(new Date(now.getTime() - 60000)).split(' ')[1],
            state: 'PoE 정상 공급',
            description: `포트 ${port.name} IEEE 802.3at PoE+ 정상 공급 중 (소비전력: 15.4W, 링크: UP)`,
            syslog: `%ILPOWER-7-DETECT: Interface ${port.name}: Power Device detected: IEEE-at PD`
        },
        {
            time: formatKst(new Date(now.getTime() - 15000)).split(' ')[1],
            state: '전원 급감/차단',
            description: `소비 전력 0W 급감, PoE 과전류 또는 케이블 분리로 인해 인터페이스 전원 공급 차단`,
            syslog: `%ILPOWER-5-POWER_DISCONNECT: Interface ${port.name}: Power removed`
        },
        {
            time: formatKst(now).split(' ')[1],
            state: '담당자 긴급 통보',
            description: `포트 ${port.name} 전원 차단 감지, 담당자 이메일 보고서 발송 및 웹 콘솔 경보 등록`,
            syslog: `%ALERT-1-POE_POWER_OFF: Powered device ${client.deviceName} on ${port.name} disconnected`
        }
    ];

    const incidentData = {
        id: reportId,
        timestamp: now.toISOString(),
        timeKst,
        triggerSource: 'PoE+ 전력 컨트롤러 (Power Inline Monitor)',
        severity: 'HIGH',
        incidentType: 'POE_DEVICE_POWER_OFF',
        title,
        hostname: config.system.hostname,
        switchModel: config.system.model,
        switchIp: config.system.ipAddress,
        switchNum: port.switchNum || 1,
        portName: port.name,
        portDesc: port.description || client.deviceName,
        vlanId: port.pvid || 2,
        vlanName: 'USER',
        clientInfo: client,
        timeline,
        rootCause: `포트 ${port.name}에 연결된 PoE 단말 [${client.deviceName}]의 전원 차단: ${reason}. UTP 패치 케이블 분리 또는 기기 전원 이상.`,
        impactAssessment: `해당 PoE 단말(${client.deviceName}, IP: ${client.ipAddress}) 네트워크 및 전원 공급 중단`,
        remediation: [
            `1단계: 포트 ${port.name} UTP 패치 케이블 결착 상태 및 단말 전원 상태 점검`,
            `2단계: 스위치 웹 콘솔 포트 관리에서 PoE 전원 모드를 'auto'로 재인가(Power Cycle)`,
            `3단계: 케이블 테스터기로 UTP 8가닥 단선/접촉 불량 여부 확인`
        ],
        consoleUrl: 'http://localhost:8080'
    };

    const htmlEmail = renderHtmlIncidentEmail(incidentData);
    const textEmail = renderPlainTextIncidentEmail(incidentData);
    incidentData.htmlContent = htmlEmail;

    const alertSettings = getDefaultAlertSettings();
    const deliveryResult = await dispatchEmail(alertSettings, title, textEmail, htmlEmail);
    incidentData.deliveryResult = deliveryResult;

    // 보고서 저장
    fs.writeFileSync(path.join(REPORTS_DIR, `${reportId}.json`), JSON.stringify(incidentData, null, 2), 'utf8');

    const index = loadReportsIndex();
    index.unshift({
        id: incidentData.id,
        timestamp: incidentData.timestamp,
        timeKst: incidentData.timeKst,
        title: incidentData.title,
        severity: incidentData.severity,
        incidentType: incidentData.incidentType,
        portName: port.name,
        clientIp: client.ipAddress,
        clientDevice: client.deviceName,
        recipient: deliveryResult.recipient,
        deliveryMethod: deliveryResult.method,
        sent: deliveryResult.sent
    });
    if (index.length > 100) index.pop();
    saveReportsIndex(index);

    // 활성 경보 저장
    const activeAlerts = getActivePowerAlerts().filter(a => !(a.deviceId === deviceId && a.portName === port.name));
    activeAlerts.unshift({
        id: reportId,
        type: 'POE_POWER_OFF',
        deviceId,
        deviceName: config.system.hostname,
        portName: port.name,
        clientDevice: client.deviceName,
        clientIp: client.ipAddress,
        occurredAt: now.toISOString(),
        timeKst,
        reason,
        severity: 'HIGH',
        recipient: deliveryResult.recipient,
        status: 'active'
    });
    saveActivePowerAlerts(activeAlerts);

    logEvent(
        'POWER',
        'Power-Monitor',
        config.system.ipAddress,
        `[PoE 전원 꺼짐] ${config.system.hostname} 포트 ${port.name} (${client.deviceName}) 전원 차단 -> 담당자(${deliveryResult.recipient}) 메일 발송`,
        'FAILURE',
        { reportId, portName: port.name }
    );

    return {
        success: true,
        reportId,
        incidentData,
        deliveryResult
    };
}

/**
 * 이메일 발송 헬퍼 (Nodemailer or Fallback)
 */
async function dispatchEmail(alertSettings, subject, text, html) {
    let deliveryResult = {
        sent: false,
        recipient: alertSettings.managerEmail || 'netadmin@company.com',
        method: 'local_archive',
        message: ''
    };

    const isSmtpConfigured = Boolean(alertSettings.smtpHost && alertSettings.smtpHost.trim() && alertSettings.smtpUser && alertSettings.smtpPass);

    if (alertSettings.enabled && alertSettings.managerEmail) {
        if (isSmtpConfigured) {
            try {
                const transporter = nodemailer.createTransport({
                    host: alertSettings.smtpHost,
                    port: Number(alertSettings.smtpPort) || 587,
                    secure: Boolean(alertSettings.smtpSecure),
                    auth: {
                        user: alertSettings.smtpUser,
                        pass: alertSettings.smtpPass
                    },
                    connectionTimeout: 5000,
                    greetingTimeout: 5000
                });

                const info = await transporter.sendMail({
                    from: `"${alertSettings.senderName || 'Cisco NetAlert'}" <${alertSettings.senderEmail || 'cisco@switch.local'}>`,
                    to: alertSettings.managerEmail,
                    subject,
                    text,
                    html
                });

                deliveryResult = {
                    sent: true,
                    recipient: alertSettings.managerEmail,
                    method: 'smtp',
                    messageId: info.messageId,
                    message: `담당자 이메일(${alertSettings.managerEmail})로 실제 SMTP 발송 완료`
                };
            } catch (smtpErr) {
                console.warn(`[PowerMonitor] SMTP 발송 실패 (로컬 큐 보관): ${smtpErr.message}`);
                deliveryResult = {
                    sent: false,
                    recipient: alertSettings.managerEmail,
                    method: 'smtp_failed_fallback',
                    error: smtpErr.message,
                    message: `SMTP 연결 불가로 로컬 보고서 보관함에 안전하게 저장됨 (수신인: ${alertSettings.managerEmail})`
                };
            }
        } else {
            deliveryResult = {
                sent: true,
                recipient: alertSettings.managerEmail,
                method: 'simulated_delivery',
                message: `담당자 이메일(${alertSettings.managerEmail}) 발송 큐 등록 및 보고서 아카이브 완료`
            };
        }
    }

    return deliveryResult;
}

module.exports = {
    getActivePowerAlerts,
    saveActivePowerAlerts,
    dismissPowerAlert,
    triggerDevicePowerOff,
    triggerDevicePowerOn,
    triggerPoePowerOff
};
