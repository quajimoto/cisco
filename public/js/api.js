// public/js/api.js
// 시큐어코딩 가이드: CSRF 토큰 관리, 안전한 비동기 통신 및 토스트 알림 모듈

const API = {
    csrfToken: null,
    currentUser: null,

    /**
     * CSRF 토큰 설정
     */
    setCsrfToken(token) {
        this.csrfToken = token;
    },

    /**
     * 현재 로그인 사용자 정보 설정
     */
    setUser(user) {
        this.currentUser = user;
    },

    /**
     * 안전한 API 요청 래퍼
     */
    async request(endpoint, options = {}) {
        const headers = options.headers || {};
        headers['Content-Type'] = 'application/json';

        // 상태 변경 요청에 CSRF 헤더 자동 첨부 (CWE-352)
        const method = (options.method || 'GET').toUpperCase();
        if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method) && this.csrfToken) {
            headers['X-CSRF-Token'] = this.csrfToken;
        }

        try {
            const res = await fetch(endpoint, {
                ...options,
                headers
            });

            const data = await res.json();

            if (!res.ok) {
                // 401 인증 실패 시 로그인 모달 표시 유도
                if (res.status === 401 && endpoint !== '/api/auth/login') {
                    window.dispatchEvent(new CustomEvent('auth:required'));
                }
                const errorMsg = data.error || `오류가 발생했습니다 (코드: ${res.status})`;
                throw new Error(errorMsg);
            }

            return data;
        } catch (err) {
            console.error(`API Error [${endpoint}]:`, err.message);
            throw err;
        }
    },

    /**
     * 토스트 알림 메시지 표시
     */
    showToast(message, type = 'info') {
        let container = document.getElementById('toast-container');
        if (!container) {
            container = SafeDOM.createElement('div', {
                attrs: { id: 'toast-container' },
                className: 'toast-container'
            });
            document.body.appendChild(container);
        }

        const toast = SafeDOM.createElement('div', {
            className: `toast ${type}`,
            children: [
                SafeDOM.createElement('span', { text: message })
            ]
        });

        container.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(100%)';
            toast.style.transition = 'all 0.3s ease';
            setTimeout(() => {
                if (toast.parentNode) {
                    toast.parentNode.removeChild(toast);
                }
            }, 300);
        }, 3500);
    }
};

window.API = API;
