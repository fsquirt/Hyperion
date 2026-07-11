/**
 * 共享会话列表组件 + 工具函数
 *
 * 所有 Tracker Dashboard (process-tree / kernel-comm / dump-trigger /
 * tracker-dashboard / session-management) 共用此组件,消除 5 份重复的
 *   - loadSessions / renderSessionList / selectSession
 *   - escHtml / formatTime / formatEventTime
 *
 * 用法:
 *   var sessionList = new TrackerSessionList({
 *       containerId: 'ptSessionList',
 *       itemClass:   'pt-session-item',   // 可选,附加到每项上的页面前缀类(向后兼容旧 CSS)
 *       onSelect:    function(id) { ptLoadSnapshots(); },
 *       autoRefreshMs: 5000
 *   });
 *   sessionList.startAutoRefresh();
 *   sessionList.load();   // 手动触发首次加载
 *
 * 对外暴露:
 *   - window.TrackerUtils        工具函数(escHtml / formatTime / formatEventTime)
 *   - window.TrackerSessionList  会话列表类
 */
(function () {
    'use strict';

    // ═══════════════════════════════════════════════════════════════
    //  共享工具函数
    // ═══════════════════════════════════════════════════════════════

    function escHtml(s) {
        if (s === null || s === undefined) return '';
        return String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    function formatTime(iso) {
        if (!iso) return '-';
        try { return new Date(iso).toLocaleString('zh-CN', { hour12: false }); }
        catch (e) { return iso; }
    }

    function formatEventTime(ts) {
        if (!ts) return '';
        try {
            var d = new Date(ts);
            return d.toLocaleTimeString('zh-CN', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
                + '.' + String(d.getMilliseconds()).padStart(3, '0');
        } catch (e) { return ts; }
    }

    var TrackerUtils = { escHtml: escHtml, formatTime: formatTime, formatEventTime: formatEventTime };
    window.TrackerUtils = TrackerUtils;

    // ═══════════════════════════════════════════════════════════════
    //  共享 CSS 注入(只注入一次)
    // ═══════════════════════════════════════════════════════════════

    var cssInjected = false;
    function injectSharedCss() {
        if (cssInjected) return;
        cssInjected = true;
        var style = document.createElement('style');
        style.id = 'tracker-session-list-shared-css';
        style.textContent = [
            '.tracker-session-item {',
            '    cursor: pointer;',
            '    transition: background 0.15s;',
            '    border-left: 3px solid transparent;',
            '}',
            '.tracker-session-item:hover { background: rgba(0,0,0,0.02); }',
            '.tracker-session-item.active {',
            '    background: rgba(13,110,253,0.04);',
            '    border-left-color: #0d6efd;',
            '}',
            '.tracker-session-item .session-status {',
            '    width: 8px; height: 8px;',
            '    border-radius: 50%;',
            '    display: inline-block;',
            '    margin-right: 6px;',
            '}',
            '.tracker-session-item .session-status.active { background: #16a34a; }',
            '.tracker-session-item .session-status.finished { background: #999; }'
        ].join('\n');
        document.head.appendChild(style);
    }

    // ═══════════════════════════════════════════════════════════════
    //  TrackerSessionList 类
    // ═══════════════════════════════════════════════════════════════

    /**
     * @param {Object} opts
     *   containerId    {string}   必填,会话列表 DOM 元素 ID
     *   itemClass      {string}   可选,附加到每项上的页面前缀类(向后兼容旧 CSS)
     *   onSelect       {Function} 必填,选中会话回调 function(sessionId, session)
     *   autoRefreshMs  {number}   可选,自动刷新间隔,默认 5000
     */
    function TrackerSessionList(opts) {
        if (!opts || !opts.containerId) {
            throw new Error('TrackerSessionList: containerId 必填');
        }
        if (typeof opts.onSelect !== 'function') {
            throw new Error('TrackerSessionList: onSelect 回调必填');
        }
        this.containerId = opts.containerId;
        this.itemClass = opts.itemClass || '';
        this.onSelect = opts.onSelect;
        this.autoRefreshMs = opts.autoRefreshMs != null ? opts.autoRefreshMs : 5000;
        this.sessions = [];
        this.selectedId = null;
        this._timer = null;
        this._loading = false;
        injectSharedCss();
    }

    TrackerSessionList.prototype.load = async function () {
        if (this._loading) return;
        this._loading = true;
        try {
            var res = await fetch('/api/tracker/sessions');
            if (!res.ok) return;
            this.sessions = await res.json();
            this.render();
        } catch (e) {
            console.error('TrackerSessionList.load:', e);
        } finally {
            this._loading = false;
        }
    };

    TrackerSessionList.prototype.render = function () {
        var el = document.getElementById(this.containerId);
        if (!el) return;

        if (!this.sessions || this.sessions.length === 0) {
            el.innerHTML = '<div class="text-center text-muted py-5">'
                + '<i class="bi bi-hdd-rack display-4 d-block mb-2"></i>暂无会话'
                + '<br><small>等待 Tracker 连接...</small></div>';
            return;
        }

        var self = this;
        var cls = this.itemClass ? ('tracker-session-item ' + this.itemClass) : 'tracker-session-item';
        el.innerHTML = this.sessions.map(function (s) {
            return '<div class="list-group-item ' + cls + (s.id === self.selectedId ? ' active' : '') + '"'
                + ' data-session-id="' + escHtml(s.id) + '">'
                + '<div class="d-flex justify-content-between align-items-start">'
                + '<div>'
                + '<span class="session-status ' + escHtml(s.status) + '"></span>'
                + '<strong class="text-dark">' + escHtml(s.id) + '</strong>'
                + '<div class="text-muted small mt-1">' + escHtml(s.machineName)
                + ' · PID ' + escHtml(s.pid) + ' · ' + formatTime(s.startedAt) + '</div>'
                + '</div>'
                + '<div class="text-end">'
                + '<span class="badge ' + (s.status === 'active' ? 'badge-pass' : 'bg-secondary') + '">'
                + (s.status === 'active' ? '在线' : '已结束') + '</span>'
                + '<div class="text-muted small mt-1">' + escHtml(s.eventCount) + ' 事件</div>'
                + '</div>'
                + '</div></div>';
        }).join('');

        // 事件委托:点击任意一项
        var items = el.querySelectorAll('[data-session-id]');
        for (var i = 0; i < items.length; i++) {
            (function (item) {
                item.addEventListener('click', function () {
                    var id = item.getAttribute('data-session-id');
                    if (id) self.select(id);
                });
            })(items[i]);
        }
    };

    TrackerSessionList.prototype.select = function (id) {
        this.selectedId = id;
        this.render();
        // 找到 session 对象传给回调,便于上层填充标题/元信息
        var session = null;
        for (var i = 0; i < this.sessions.length; i++) {
            if (this.sessions[i].id === id) { session = this.sessions[i]; break; }
        }
        try { this.onSelect(id, session); }
        catch (e) { console.error('TrackerSessionList.onSelect:', e); }
    };

    TrackerSessionList.prototype.startAutoRefresh = function () {
        var self = this;
        if (this._timer) clearInterval(this._timer);
        this._timer = setInterval(function () { self.load(); }, this.autoRefreshMs);
    };

    TrackerSessionList.prototype.stopAutoRefresh = function () {
        if (this._timer) { clearInterval(this._timer); this._timer = null; }
    };

    TrackerSessionList.prototype.getSelected = function () {
        return this.selectedId;
    };

    TrackerSessionList.prototype.findById = function (id) {
        for (var i = 0; i < this.sessions.length; i++) {
            if (this.sessions[i].id === id) return this.sessions[i];
        }
        return null;
    };

    window.TrackerSessionList = TrackerSessionList;
})();
