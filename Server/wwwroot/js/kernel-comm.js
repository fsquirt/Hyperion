/**
 * 内核通信记录 Dashboard
 * 展示 kind=driver(驱动扫描) + attach(附着) + ioctl(IOCTL 拦截)
 * + IOCTL 监听开关配置
 */

var kcSessions = [];
var kcSelectedId = null;
var kcKind = '';
var kcLevel = '';
var kcSearch = '';
var kcSearchTimer = null;

var kcConfig = {
    treePollIntervalSec: 10,
    ioctlEnabled: false,
    dumpMode: 'mini',
    fileCopyEnabled: true
};

kcLoadConfig();
kcLoadSessions();
setInterval(kcLoadSessions, 5000);

// ═══════════════════════════════════════════════════════════════
//  配置(IOCTL 监听开关)
// ═══════════════════════════════════════════════════════════════

async function kcLoadConfig() {
    try {
        var res = await fetch('/api/tracker/config');
        if (!res.ok) return;
        kcConfig = await res.json();
        kcRenderConfig();
    } catch (e) { console.error('kcLoadConfig:', e); }
}

function kcRenderConfig() {
    var toggle = document.getElementById('kcIoctlToggle');
    var status = document.getElementById('kcIoctlStatus');
    if (!toggle || !status) return;
    toggle.checked = !!kcConfig.ioctlEnabled;
    if (kcConfig.ioctlEnabled) {
        status.textContent = '已开启';
        status.className = 'badge bg-success';
    } else {
        status.textContent = '已关闭';
        status.className = 'badge bg-secondary';
    }
}

async function kcSaveConfig() {
    var btn = document.getElementById('kcSaveBtn');
    var msg = document.getElementById('kcConfigMsg');
    var ioctlEnabled = document.getElementById('kcIoctlToggle').checked;

    if (btn) btn.disabled = true;
    if (msg) { msg.textContent = '保存中...'; msg.className = 'text-muted small ms-auto'; }

    try {
        // 先 GET 当前完整配置,再合并 ioctlEnabled 后 POST
        var getRes = await fetch('/api/tracker/config');
        if (!getRes.ok) {
            if (msg) { msg.textContent = '读取配置失败'; msg.className = 'text-danger small ms-auto'; }
            return;
        }
        var fresh = await getRes.json();

        var postRes = await fetch('/api/tracker/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                treePollIntervalSec: fresh.treePollIntervalSec,
                ioctlEnabled: ioctlEnabled,
                dumpMode: fresh.dumpMode,
                fileCopyEnabled: fresh.fileCopyEnabled
            })
        });

        if (!postRes.ok) {
            var err = '';
            try { err = (await postRes.json()).error || ''; } catch (_) {}
            if (msg) { msg.textContent = '保存失败' + (err ? ': ' + err : ''); msg.className = 'text-danger small ms-auto'; }
            return;
        }

        kcConfig = await postRes.json();
        kcRenderConfig();
        if (msg) { msg.textContent = '已保存'; msg.className = 'text-success small ms-auto'; }
    } catch (e) {
        if (msg) { msg.textContent = '保存失败: ' + e.message; msg.className = 'text-danger small ms-auto'; }
    } finally {
        if (btn) btn.disabled = false;
    }
}

// ═══════════════════════════════════════════════════════════════
//  会话列表
// ═══════════════════════════════════════════════════════════════

async function kcLoadSessions() {
    try {
        var res = await fetch('/api/tracker/sessions');
        if (!res.ok) return;
        kcSessions = await res.json();
        kcRenderSessionList();
    } catch (e) { console.error('kcLoadSessions:', e); }
}

function kcRenderSessionList() {
    var el = document.getElementById('kcSessionList');
    if (!el) return;
    if (kcSessions.length === 0) {
        el.innerHTML = '<div class="text-center text-muted py-5"><i class="bi bi-hdd-rack display-4 d-block mb-2"></i>暂无会话<br><small>等待 Tracker 连接...</small></div>';
        return;
    }
    el.innerHTML = kcSessions.map(function (s) {
        return '<div class="list-group-item kc-session-item ' + (s.id === kcSelectedId ? 'active' : '') + '"'
            + ' onclick="kcSelectSession(\'' + escHtml(s.id) + '\')">'
            + '<div class="d-flex justify-content-between align-items-start">'
            + '<div>'
            + '<span class="session-status ' + escHtml(s.status) + '"></span>'
            + '<strong class="text-dark">' + escHtml(s.id) + '</strong>'
            + '<div class="text-muted small mt-1">' + escHtml(s.machineName) + ' · PID ' + escHtml(s.pid) + ' · ' + formatTime(s.startedAt) + '</div>'
            + '</div>'
            + '<div class="text-end">'
            + '<span class="badge ' + (s.status === 'active' ? 'badge-pass' : 'bg-secondary') + '">' + (s.status === 'active' ? '在线' : '已结束') + '</span>'
            + '<div class="text-muted small mt-1">' + s.eventCount + ' 事件</div>'
            + '</div>'
            + '</div></div>';
    }).join('');
}

async function kcSelectSession(id) {
    kcSelectedId = id;
    kcRenderSessionList();
    var bar = document.getElementById('kcFilterBar');
    if (bar) bar.classList.remove('d-none');
    kcLoadEvents();
}

// ═══════════════════════════════════════════════════════════════
//  内核通信记录加载
//  GET /api/tracker/sessions/{id}/kernel-comms?kind=&level=&search=
//  返回数组: [{id, sessionId, timestamp, kind, level, source, title, detail}]
// ═══════════════════════════════════════════════════════════════

async function kcLoadEvents() {
    if (!kcSelectedId) return;

    var detailEl = document.getElementById('kcEventDetail');
    var titleEl = document.getElementById('kcDetailTitle');
    var metaEl = document.getElementById('kcDetailMeta');
    var countEl = document.getElementById('kcFilterCount');

    if (detailEl) detailEl.innerHTML = '<div class="text-center text-muted py-4">加载中...</div>';

    try {
        var url = '/api/tracker/sessions/' + encodeURIComponent(kcSelectedId) + '/kernel-comms';
        var params = [];
        if (kcKind) params.push('kind=' + encodeURIComponent(kcKind));
        if (kcLevel) params.push('level=' + encodeURIComponent(kcLevel));
        if (kcSearch) params.push('search=' + encodeURIComponent(kcSearch));
        if (params.length) url += '?' + params.join('&');

        var res = await fetch(url);
        if (!res.ok) {
            if (detailEl) detailEl.innerHTML = '<div class="text-center text-danger py-4">加载失败</div>';
            return;
        }
        var events = await res.json();

        if (titleEl) titleEl.innerHTML = '<i class="bi bi-hdd-network me-2"></i>' + escHtml(kcSelectedId);
        if (metaEl) metaEl.textContent = events.length + ' 条记录';

        if (countEl) {
            countEl.textContent = (kcKind || kcLevel || kcSearch)
                ? '显示 ' + events.length + ' 条'
                : '';
        }

        if (!events || events.length === 0) {
            if (detailEl) detailEl.innerHTML = '<div class="text-center text-muted py-5"><i class="bi bi-inbox display-4 d-block mb-2"></i>'
                + ((kcKind || kcLevel || kcSearch) ? '无匹配记录' : '暂无内核通信记录') + '</div>';
            return;
        }

        if (detailEl) {
            detailEl.innerHTML = events.map(function (evt, i) {
                var detailHtml = evt.detail
                    ? '<pre>' + escHtml(truncate(evt.detail, 8000)) + '</pre>'
                    : '<div class="text-muted">无详情</div>';
                return '<div class="kc-event-row" onclick="kcToggleDetail(' + i + ')">'
                    + '<div class="d-flex align-items-center gap-2">'
                    + '<span class="event-time">' + formatEventTime(evt.timestamp) + '</span>'
                    + '<span class="event-level ' + escHtml(evt.level || '') + '">' + escHtml(evt.level || '-') + '</span>'
                    + '<span class="event-type ' + escHtml(evt.kind || '') + '">' + escHtml(evt.kind || '-') + '</span>'
                    + '<span class="event-title">' + escHtml(truncate(evt.title || '', 200)) + '</span>'
                    + '<span class="event-source ms-auto">' + escHtml(evt.source || '') + '</span>'
                    + '</div></div>'
                    + '<div class="kc-detail-panel" id="kcdetail-' + i + '">' + detailHtml + '</div>';
            }).join('');
        }
    } catch (e) {
        if (detailEl) detailEl.innerHTML = '<div class="text-center text-danger py-4">加载失败: ' + escHtml(e.message) + '</div>';
    }
}

// ═══════════════════════════════════════════════════════════════
//  过滤 / 搜索
// ═══════════════════════════════════════════════════════════════

function kcSetKind(btn) {
    kcKind = btn.getAttribute('data-kind') || '';
    document.querySelectorAll('#kcKindFilter .btn').forEach(function (b) { b.classList.remove('active'); });
    btn.classList.add('active');
    kcLoadEvents();
}

function kcSetLevel(btn) {
    kcLevel = btn.getAttribute('data-level') || '';
    document.querySelectorAll('#kcLevelFilter .btn').forEach(function (b) { b.classList.remove('active'); });
    btn.classList.add('active');
    kcLoadEvents();
}

function kcOnSearch() {
    clearTimeout(kcSearchTimer);
    kcSearchTimer = setTimeout(function () {
        var el = document.getElementById('kcSearch');
        kcSearch = el ? el.value.trim() : '';
        kcLoadEvents();
    }, 300);
}

function kcClearSearch() {
    var el = document.getElementById('kcSearch');
    if (el) el.value = '';
    kcSearch = '';
    kcLoadEvents();
}

function kcToggleDetail(i) {
    var el = document.getElementById('kcdetail-' + i);
    if (el) el.classList.toggle('open');
}

// ═══════════════════════════════════════════════════════════════
//  工具
// ═══════════════════════════════════════════════════════════════

function escHtml(s) {
    if (s === null || s === undefined) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
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

function truncate(s, max) {
    if (!s) return s;
    s = String(s);
    if (s.length <= max) return s;
    return s.substring(0, max) + '\n... (截断)';
}
