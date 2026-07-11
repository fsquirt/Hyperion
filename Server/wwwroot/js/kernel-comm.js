/**
 * 内核通信记录 Dashboard
 * 展示 type=ioctl(EtwLive IOCTL 拦截) + type=comms(CommsMonitor 通信 dump)
 */

let kcSessions = [];
let kcSelectedId = null;
let kcMode = 'ioctl,comms';
let kcLevel = '';
let kcSearch = '';
let kcSearchTimer = null;

kcLoadSessions();
setInterval(kcLoadSessions, 5000);

// ═══════════════════════════════════════════════════════════════
//  会话列表
// ═══════════════════════════════════════════════════════════════

async function kcLoadSessions() {
    try {
        const res = await fetch('/api/tracker/sessions');
        if (!res.ok) return;
        kcSessions = await res.json();
        kcRenderSessionList();
    } catch (e) { console.error('kcLoadSessions:', e); }
}

function kcRenderSessionList() {
    const el = document.getElementById('kcSessionList');
    if (kcSessions.length === 0) {
        el.innerHTML = '<div class="text-center text-muted py-5"><i class="bi bi-hdd-rack display-4 d-block mb-2"></i>暂无会话<br><small>等待 Tracker 连接...</small></div>';
        return;
    }
    el.innerHTML = kcSessions.map(s => `
        <div class="list-group-item kc-session-item ${s.id === kcSelectedId ? 'active' : ''}"
             onclick="kcSelectSession('${s.id}')">
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <span class="session-status ${s.status}"></span>
                    <strong class="text-dark">${kcEsc(s.id)}</strong>
                    <div class="text-muted small mt-1">${kcEsc(s.machineName)} · PID ${s.pid} · ${kcFmtTime(s.startedAt)}</div>
                </div>
                <div class="text-end">
                    <span class="badge ${s.status === 'active' ? 'badge-pass' : 'bg-secondary'}">${s.status === 'active' ? '在线' : '已结束'}</span>
                    <div class="text-muted small mt-1">${s.eventCount} 事件</div>
                </div>
            </div>
        </div>
    `).join('');
}

async function kcSelectSession(id) {
    kcSelectedId = id;
    kcRenderSessionList();
    document.getElementById('kcFilterBar').classList.remove('d-none');
    kcLoadEvents();
}

// ═══════════════════════════════════════════════════════════════
//  事件加载
// ═══════════════════════════════════════════════════════════════

async function kcLoadEvents() {
    if (!kcSelectedId) return;

    const detailEl = document.getElementById('kcEventDetail');
    const titleEl = document.getElementById('kcDetailTitle');
    const metaEl = document.getElementById('kcDetailMeta');
    const countEl = document.getElementById('kcFilterCount');

    detailEl.innerHTML = '<div class="text-center text-muted py-4">加载中...</div>';

    try {
        var url = '/api/tracker/sessions/' + kcSelectedId;
        var params = [];
        if (kcMode) params.push('type=' + encodeURIComponent(kcMode));
        if (kcLevel) params.push('level=' + encodeURIComponent(kcLevel));
        if (kcSearch) params.push('search=' + encodeURIComponent(kcSearch));
        if (params.length) url += '?' + params.join('&');

        const res = await fetch(url);
        if (!res.ok) {
            detailEl.innerHTML = '<div class="text-center text-danger py-4">会话不存在</div>';
            return;
        }
        const data = await res.json();

        titleEl.innerHTML = '<i class="bi bi-hdd-network me-2"></i>' + kcEsc(data.id);
        metaEl.textContent = kcEsc(data.machineName) + ' · ' + (data.status === 'active' ? '在线' : '已结束') + ' · ' + data.eventCount + ' 事件 · ' + kcFmtTime(data.startedAt);

        countEl.textContent = (kcLevel || kcSearch)
            ? '显示 ' + data.events.length + ' / ' + data.eventCount + ' 条'
            : '';

        if (data.events.length === 0) {
            detailEl.innerHTML = '<div class="text-center text-muted py-5"><i class="bi bi-inbox display-4 d-block mb-2"></i>'
                + ((kcLevel || kcSearch) ? '无匹配事件' : '暂无内核通信记录') + '</div>';
            return;
        }

        detailEl.innerHTML = data.events.map(function(evt, i) {
            var detailHtml = '';
            if (evt.detail) {
                detailHtml += '<div><strong>详情:</strong><pre>' + kcEsc(evt.detail) + '</pre></div>';
            }
            if (evt.xml) {
                detailHtml += '<div class="mt-1"><strong>原始 XML:</strong><pre class="text-muted" style="max-height:200px;overflow:auto">' + kcEsc(kcTruncate(evt.xml, 2000)) + '</pre></div>';
            }
            return '<div class="kc-event-row" onclick="kcToggleDetail(' + i + ')">'
                + '<div class="d-flex align-items-center gap-2">'
                + '<span class="event-time">' + kcFmtEventTime(evt.timestamp) + '</span>'
                + '<span class="event-level ' + kcEsc(evt.level) + '">' + kcEsc(evt.level) + '</span>'
                + '<span class="event-type">' + kcEsc(evt.type || '-') + '</span>'
                + '<span class="event-title">' + kcEsc(evt.title) + '</span>'
                + '<span class="event-source ms-auto">' + kcEsc(evt.source) + '</span>'
                + '</div></div>'
                + '<div class="kc-detail-panel" id="kcdetail-' + i + '">' + detailHtml + '</div>';
        }).join('');
    } catch (e) {
        detailEl.innerHTML = '<div class="text-center text-danger py-4">加载失败: ' + e.message + '</div>';
    }
}

// ═══════════════════════════════════════════════════════════════
//  过滤
// ═══════════════════════════════════════════════════════════════

function kcSetMode(btn) {
    kcMode = btn.getAttribute('data-mode');
    document.querySelectorAll('#kcModeFilter .btn').forEach(function(b) { b.classList.remove('active'); });
    btn.classList.add('active');
    kcLoadEvents();
}

function kcSetLevel(btn) {
    kcLevel = btn.getAttribute('data-level');
    document.querySelectorAll('#kcLevelFilter .btn').forEach(function(b) { b.classList.remove('active'); });
    btn.classList.add('active');
    kcLoadEvents();
}

function kcOnSearch() {
    clearTimeout(kcSearchTimer);
    kcSearchTimer = setTimeout(function() {
        kcSearch = document.getElementById('kcSearch').value.trim();
        kcLoadEvents();
    }, 300);
}

function kcClearSearch() {
    document.getElementById('kcSearch').value = '';
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

function kcEsc(s) {
    if (!s) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function kcFmtTime(iso) {
    if (!iso) return '-';
    try { return new Date(iso).toLocaleString('zh-CN', { hour12: false }); }
    catch (e) { return iso; }
}

function kcFmtEventTime(ts) {
    if (!ts) return '';
    try {
        var d = new Date(ts);
        return d.toLocaleTimeString('zh-CN', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
            + '.' + String(d.getMilliseconds()).padStart(3, '0');
    } catch (e) { return ts; }
}

function kcTruncate(s, max) {
    if (!s || s.length <= max) return s;
    return s.substring(0, max) + '\n... (截断)';
}
