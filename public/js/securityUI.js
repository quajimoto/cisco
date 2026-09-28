// public/js/securityUI.js
// 시큐어코딩 가이드: DOM XSS(CWE-79) 원천 방지를 위한 안전한 DOM 생성 유틸리티

const SafeDOM = {
    /**
     * 안전한 HTML 엔티티 이스케이프
     */
    escape(str) {
        if (str === null || str === undefined) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;')
            .replace(/\//g, '&#x2F;');
    },

    /**
     * innerHTML 대신 안전하게 요소 생성 및 텍스트/자식 노드 주입
     * @param {string} tag 태그명
     * @param {object} options { className, text, attrs, children, events }
     */
    createElement(tag, options = {}) {
        const el = document.createElement(tag);

        if (options.id) {
            el.id = options.id;
        }

        if (options.className) {
            el.className = options.className;
        }

        if (options.text !== undefined && options.text !== null) {
            el.textContent = String(options.text);
        }

        if (options.attrs) {
            for (const [key, val] of Object.entries(options.attrs)) {
                if (val !== undefined && val !== null) {
                    el.setAttribute(key, String(val));
                }
            }
        }

        if (options.events) {
            for (const [event, handler] of Object.entries(options.events)) {
                if (typeof handler === 'function') {
                    el.addEventListener(event, handler);
                }
            }
        }

        if (options.children && Array.isArray(options.children)) {
            for (const child of options.children) {
                if (child instanceof Node) {
                    el.appendChild(child);
                } else if (child !== null && child !== undefined) {
                    el.appendChild(document.createTextNode(String(child)));
                }
            }
        }

        return el;
    },

    /**
     * 부모 요소의 모든 자식 노드를 안전하게 비움
     */
    clearElement(el) {
        if (!el) return;
        while (el.firstChild) {
            el.removeChild(el.firstChild);
        }
    }
};

window.SafeDOM = SafeDOM;
