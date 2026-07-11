/**
 * Tracker 事件追踪 Dashboard
 * 仅显示 winevent + etw 两种事件,走独立 events API。
 */

let trkLevel = '';
let trkSearch = '';
let trkSearchTimer = null;

// 本地别名 -> 共享工具函数 (session-list.js)
var escHtml = TrackerUtils.escHtml;
var formatTime = TrackerUtils.formatTime;
var formatEventTime = TrackerUtils.formatEventTime;

// 共享会话列表组件
var trkSessionList = new TrackerSessionList({
    containerId: 'sessionList',
    itemClass: 'session-item',
    onSelect: function (id) { selectSession(id); },
    autoRefreshMs: 5000
});

trkSessionList.load();
trkSessionList.startAutoRefresh();

// 覆盖共享组件的 load,以便同时更新顶部统计
var _trkOrigLoad = trkSessionList.load.bind(trkSessionList);
trkSessionList.load = async function () {
    await _trkOrigLoad();
    updateStats();
};

function updateStats() {
    const sessions = trkSessionList.sessions;
    const active = sessions.filter(s => s.status === 'active').length;
    const finished = sessions.filter(s => s.status === 'finished').length;
    const total = sessions.reduce((sum, s) => sum + s.eventCount, 0);

    document.getElementById('activeCount').textContent = active;
    document.getElementById('finishedCount').textContent = finished;
    document.getElementById('totalEvents').textContent = total.toLocaleString();

    if (sessions.length > 0) {
        document.getElementById('lastActivity').textContent = formatTime(sessions[0].lastHeartbeat);
    } else {
        document.getElementById('lastActivity').textContent = '-';
    }
}

/// 手动刷新(cshtml 刷新按钮 onclick 调用)
function loadSessions() { trkSessionList.load(); }

async function selectSession(id) {
    document.getElementById('filterBar').classList.remove('d-none');
    loadSessionEvents();
}

async function loadSessionEvents() {
    var trkSelectedId = trkSessionList.getSelected();
    if (!trkSelectedId) return;

    const detailEl = document.getElementById('eventDetail');
    const titleEl = document.getElementById('detailTitle');
    const metaEl = document.getElementById('detailMeta');
    const countEl = document.getElementById('filterCount');

    detailEl.innerHTML = '<div class="text-center text-muted py-4">加载中...</div>';

    try {
        var url = '/api/tracker/sessions/' + encodeURIComponent(trkSelectedId) + '/events';
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
                + '<span class="event-type ' + escHtml(evt.type) + '">' + escHtml(typeLabel(evt.type)) + '</span>'
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

// ── 辅助 (escHtml/formatTime/formatEventTime 已委托给 TrackerUtils,见文件头部别名) ──

function typeLabel(t) {
    if (t === 'winevent') return 'Windows 事件';
    if (t === 'etw') return 'ETW 事件';
    return t || '-';
}

function truncate(s, max) {
    if (!s || s.length <= max) return s;
    return s.substring(0, max) + '\n... (截断)';
}
