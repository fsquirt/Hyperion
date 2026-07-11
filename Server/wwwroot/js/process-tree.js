/**
 * 进程树快照 Dashboard
 * 展示 type=snapshot(初始全量快照) + type=tree(轮询进程树)
 */

let ptSessions = [];
let ptSelectedId = null;
let ptMode = 'snapshot,tree';
let ptLevel = '';
let ptSearch = '';
let ptSearchTimer = null;

// 初始化:加载会话列表 + 加载 Tree 频率配置
ptLoadSessions();
setInterval(ptLoadSessions, 5000);
ptLoadTreePollConfig();

// ═══════════════════════════════════════════════════════════════
//  Tree 频率配置
// ═══════════════════════════════════════════════════════════════

async function ptLoadTreePollConfig() {
    try {
        const res = await fetch('/api/tracker/config');
        if (!res.ok) return;
        const data = await res.json();
        document.getElementById('ptTreePollInput').value = data.treePollIntervalSec || 10;
        document.getElementById('ptTreePollStatus').textContent = '当前: ' + (data.treePollIntervalSec || 10) + ' 秒';
    } catch (e) { console.error('ptLoadTreePollConfig:', e); }
}

async function ptSaveTreePollConfig() {
    const val = parseInt(document.getElementById('ptTreePollInput').value, 10);
    if (!val || val < 1 || val > 3600) {
        document.getElementById('ptTreePollStatus').textContent = '请输入 1..3600 之间的整数';
        return;
    }
    try {
        const res = await fetch('/api/tracker/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ treePollIntervalSec: val })
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            document.getElementById('ptTreePollStatus').textContent = '失败: ' + (err.error || res.status);
            return;
        }
        const data = await res.json();
        document.getElementById('ptTreePollInput').value = data.treePollIntervalSec;
        document.getElementById('ptTreePollStatus').textContent = '已应用: ' + data.treePollIntervalSec + ' 秒';
    } catch (e) {
        document.getElementById('ptTreePollStatus').textContent = '失败: ' + e.message;
    }
}

// ═══════════════════════════════════════════════════════════════
//  会话列表
// ═══════════════════════════════════════════════════════════════

async function ptLoadSessions() {
    try {
        const res = await fetch('/api/tracker/sessions');
        if (!res.ok) return;
        ptSessions = await res.json();
        ptRenderSessionList();
    } catch (e) { console.error('ptLoadSessions:', e); }
}

function ptRenderSessionList() {
    const el = document.getElementById('ptSessionList');
    if (ptSessions.length === 0) {
        el.innerHTML = '<div class="text-center text-muted py-5"><i class="bi bi-hdd-rack display-4 d-block mb-2"></i>暂无会话<br><small>等待 Tracker 连接...</small></div>';
        return;
    }
    el.innerHTML = ptSessions.map(s => `
        <div class="list-group-item pt-session-item ${s.id === ptSelectedId ? 'active' : ''}"
             onclick="ptSelectSession('${s.id}')">
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <span class="session-status ${s.status}"></span>
                    <strong class="text-dark">${ptEsc(s.id)}</strong>
                    <div class="text-muted small mt-1">${ptEsc(s.machineName)} · PID ${s.pid} · ${ptFmtTime(s.startedAt)}</div>
                </div>
                <div class="text-end">
                    <span class="badge ${s.status === 'active' ? 'badge-pass' : 'bg-secondary'}">${s.status === 'active' ? '在线' : '已结束'}</span>
                    <div class="text-muted small mt-1">${s.eventCount} 事件</div>
                </div>
            </div>
        </div>
    `).join('');
}

async function ptSelectSession(id) {
    ptSelectedId = id;
    ptRenderSessionList();
    document.getElementById('ptFilterBar').classList.remove('d-none');
    ptLoadEvents();
}

// ═══════════════════════════════════════════════════════════════
//  事件加载
// ═══════════════════════════════════════════════════════════════

async function ptLoadEvents() {
    if (!ptSelectedId) return;

    const detailEl = document.getElementById('ptEventDetail');
    const titleEl = document.getElementById('ptDetailTitle');
    const metaEl = document.getElementById('ptDetailMeta');
    const countEl = document.getElementById('ptFilterCount');

    detailEl.innerHTML = '<div class="text-center text-muted py-4">加载中...</div>';

    try {
        var url = '/api/tracker/sessions/' + ptSelectedId;
        var params = [];
        // type 用服务端过滤(snapshot,tree)
        if (ptMode) params.push('type=' + encodeURIComponent(ptMode));
        if (ptLevel) params.push('level=' + encodeURIComponent(ptLevel));
        if (ptSearch) params.push('search=' + encodeURIComponent(ptSearch));
        if (params.length) url += '?' + params.join('&');

        const res = await fetch(url);
        if (!res.ok) {
            detailEl.innerHTML = '<div class="text-center text-danger py-4">会话不存在</div>';
            return;
        }
        const data = await res.json();

        titleEl.innerHTML = '<i class="bi bi-diagram-3 me-2"></i>' + ptEsc(data.id);
        metaEl.textContent = ptEsc(data.machineName) + ' · ' + (data.status === 'active' ? '在线' : '已结束') + ' · ' + data.eventCount + ' 事件 · ' + ptFmtTime(data.startedAt);

        countEl.textContent = (ptLevel || ptSearch)
            ? '显示 ' + data.events.length + ' / ' + data.eventCount + ' 条'
            : '';

        if (data.events.length === 0) {
            detailEl.innerHTML = '<div class="text-center text-muted py-5"><i class="bi bi-inbox display-4 d-block mb-2"></i>'
                + ((ptLevel || ptSearch) ? '无匹配事件' : '暂无进程快照/树数据') + '</div>';
            return;
        }

        detailEl.innerHTML = data.events.map(function(evt, i) {
            var detailHtml = '';
            if (evt.detail) {
                detailHtml += '<div><strong>进程详情:</strong><pre>' + ptEsc(evt.detail) + '</pre></div>';
            }
            if (evt.xml) {
                detailHtml += '<div class="mt-1"><strong>原始 XML:</strong><pre class="text-muted" style="max-height:200px;overflow:auto">' + ptEsc(ptTruncate(evt.xml, 2000)) + '</pre></div>';
            }
            return '<div class="pt-event-row" onclick="ptToggleDetail(' + i + ')">'
                + '<div class="d-flex align-items-center gap-2">'
                + '<span class="event-time">' + ptFmtEventTime(evt.timestamp) + '</span>'
                + '<span class="event-level ' + ptEsc(evt.level) + '">' + ptEsc(evt.level) + '</span>'
                + '<span class="event-type">' + ptEsc(evt.type || '-') + '</span>'
                + '<span class="event-title">' + ptEsc(evt.title) + '</span>'
                + '<span class="event-source ms-auto">' + ptEsc(evt.source) + '</span>'
                + '</div></div>'
                + '<div class="pt-detail-panel" id="ptdetail-' + i + '">' + detailHtml + '</div>';
        }).join('');
    } catch (e) {
        detailEl.innerHTML = '<div class="text-center text-danger py-4">加载失败: ' + e.message + '</div>';
    }
}

// ═══════════════════════════════════════════════════════════════
//  过滤
// ═══════════════════════════════════════════════════════════════

function ptSetMode(btn) {
    ptMode = btn.getAttribute('data-mode');
    document.querySelectorAll('#ptModeFilter .btn').forEach(function(b) { b.classList.remove('active'); });
    btn.classList.add('active');
    ptLoadEvents();
}

function ptSetLevel(btn) {
    ptLevel = btn.getAttribute('data-level');
    document.querySelectorAll('#ptLevelFilter .btn').forEach(function(b) { b.classList.remove('active'); });
    btn.classList.add('active');
    ptLoadEvents();
}

function ptOnSearch() {
    clearTimeout(ptSearchTimer);
    ptSearchTimer = setTimeout(function() {
        ptSearch = document.getElementById('ptSearch').value.trim();
        ptLoadEvents();
    }, 300);
}

function ptClearSearch() {
    document.getElementById('ptSearch').value = '';
    ptSearch = '';
    ptLoadEvents();
}

function ptToggleDetail(i) {
    var el = document.getElementById('ptdetail-' + i);
    if (el) el.classList.toggle('open');
}

// ═══════════════════════════════════════════════════════════════
//  工具
// ═══════════════════════════════════════════════════════════════

function ptEsc(s) {
    if (!s) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function ptFmtTime(iso) {
    if (!iso) return '-';
    try { return new Date(iso).toLocaleString('zh-CN', { hour12: false }); }
    catch (e) { return iso; }
}

function ptFmtEventTime(ts) {
    if (!ts) return '';
    try {
        var d = new Date(ts);
        return d.toLocaleTimeString('zh-CN', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
            + '.' + String(d.getMilliseconds()).padStart(3, '0');
    } catch (e) { return ts; }
}

function ptTruncate(s, max) {
    if (!s || s.length <= max) return s;
    return s.substring(0, max) + '\n... (截断)';
}
