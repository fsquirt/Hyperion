/**
 * Tracker 事件追踪 Dashboard
 */

let trkSessions = [];
let trkSelectedId = null;
let trkLevel = '';
let trkSearch = '';
let trkSearchTimer = null;

loadSessions();
setInterval(loadSessions, 5000);

async function loadSessions() {
    try {
        const res = await fetch('/api/tracker/sessions');
        if (!res.ok) return;
        trkSessions = await res.json();
        renderSessionList();
        updateStats();
    } catch (e) { console.error('loadSessions:', e); }
}

function updateStats() {
    const active = trkSessions.filter(s => s.status === 'active').length;
    const finished = trkSessions.filter(s => s.status === 'finished').length;
    const total = trkSessions.reduce((sum, s) => sum + s.eventCount, 0);

    document.getElementById('activeCount').textContent = active;
    document.getElementById('finishedCount').textContent = finished;
    document.getElementById('totalEvents').textContent = total.toLocaleString();

    if (trkSessions.length > 0) {
        document.getElementById('lastActivity').textContent = formatTime(trkSessions[0].lastHeartbeat);
    } else {
        document.getElementById('lastActivity').textContent = '-';
    }
}

function renderSessionList() {
    const el = document.getElementById('sessionList');
    if (trkSessions.length === 0) {
        el.innerHTML = '<div class="text-center text-muted py-5"><i class="bi bi-hdd-rack display-4 d-block mb-2"></i>暂无会话<br><small>等待 Tracker 连接...</small></div>';
        return;
    }

    el.innerHTML = trkSessions.map(s => `
        <div class="list-group-item session-item ${s.id === trkSelectedId ? 'active' : ''}"
             onclick="selectSession('${s.id}')">
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <span class="session-status ${s.status}"></span>
                    <strong class="text-dark">${escHtml(s.id)}</strong>
                    <div class="text-muted small mt-1">${escHtml(s.machineName)} · PID ${s.pid} · ${formatTime(s.startedAt)}</div>
                </div>
                <div class="text-end">
                    <span class="badge ${s.status === 'active' ? 'badge-pass' : 'bg-secondary'}">${s.status === 'active' ? '在线' : '已结束'}</span>
                    <div class="text-muted small mt-1">${s.eventCount} 事件</div>
                </div>
            </div>
        </div>
    `).join('');
}

async function selectSession(id) {
    trkSelectedId = id;
    renderSessionList();
    document.getElementById('filterBar').classList.remove('d-none');
    loadSessionEvents();
}

async function loadSessionEvents() {
    if (!trkSelectedId) return;

    const detailEl = document.getElementById('eventDetail');
    const titleEl = document.getElementById('detailTitle');
    const metaEl = document.getElementById('detailMeta');
    const countEl = document.getElementById('filterCount');

    detailEl.innerHTML = '<div class="text-center text-muted py-4">加载中...</div>';

    try {
        var url = '/api/tracker/sessions/' + trkSelectedId;
        var params = [];
        if (trkLevel) params.push('level=' + encodeURIComponent(trkLevel));
        if (trkSearch) params.push('search=' + encodeURIComponent(trkSearch));
        if (params.length) url += '?' + params.join('&');

        const res = await fetch(url);
        if (!res.ok) {
            detailEl.innerHTML = '<div class="text-center text-danger py-4">会话不存在</div>';
            return;
        }
        const data = await res.json();

        titleEl.innerHTML = '<i class="bi bi-activity me-2"></i>' + escHtml(data.id);
        metaEl.textContent = escHtml(data.machineName) + ' · ' + (data.status === 'active' ? '在线' : '已结束') + ' · ' + data.eventCount + ' 事件 · ' + formatTime(data.startedAt);

        countEl.textContent = (trkLevel || trkSearch)
            ? '显示 ' + data.events.length + ' / ' + data.eventCount + ' 条'
            : '';

        if (data.events.length === 0) {
            detailEl.innerHTML = '<div class="text-center text-muted py-5"><i class="bi bi-inbox display-4 d-block mb-2"></i>'
                + ((trkLevel || trkSearch) ? '无匹配事件' : '暂无事件') + '</div>';
            return;
        }

        detailEl.innerHTML = data.events.map(function(evt, i) {
            var detailHtml = '';
            if (evt.detail) {
                detailHtml += '<div><strong>详情:</strong><pre>' + escHtml(evt.detail) + '</pre></div>';
            }
            if (evt.xml) {
                detailHtml += '<div class="mt-1"><strong>原始 XML:</strong><pre class="text-muted" style="max-height:200px;overflow:auto">' + escHtml(truncate(evt.xml, 2000)) + '</pre></div>';
            }
            return '<div class="event-row" onclick="toggleDetail(' + i + ')">'
                + '<div class="d-flex align-items-center gap-2">'
                + '<span class="event-time">' + formatEventTime(evt.timestamp) + '</span>'
                + '<span class="event-level ' + escHtml(evt.level) + '">' + escHtml(evt.level) + '</span>'
                + '<span class="event-title">' + escHtml(evt.title) + '</span>'
                + '<span class="event-source ms-auto">' + escHtml(evt.source) + '</span>'
                + '</div></div>'
                + '<div class="event-detail-panel" id="edetail-' + i + '">' + detailHtml + '</div>';
        }).join('');
    } catch (e) {
        detailEl.innerHTML = '<div class="text-center text-danger py-4">加载失败: ' + e.message + '</div>';
    }
}

// ── 过滤 / 搜索 ──────────────────────────────────────────────────

function setLevelFilter(btn) {
    trkLevel = btn.getAttribute('data-level');
    document.querySelectorAll('#levelFilter .btn').forEach(function(b) { b.classList.remove('active'); });
    btn.classList.add('active');
    loadSessionEvents();
}

function onSearchInput() {
    clearTimeout(trkSearchTimer);
    trkSearchTimer = setTimeout(function() {
        trkSearch = document.getElementById('eventSearch').value.trim();
        loadSessionEvents();
    }, 300);
}

function clearSearch() {
    document.getElementById('eventSearch').value = '';
    trkSearch = '';
    loadSessionEvents();
}

function toggleDetail(i) {
    var el = document.getElementById('edetail-' + i);
    if (el) el.classList.toggle('open');
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

function escHtml(s) {
    if (!s) return '';
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function truncate(s, max) {
    if (!s || s.length <= max) return s;
    return s.substring(0, max) + '\n... (截断)';
}
