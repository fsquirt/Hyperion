/**
 * Dump 内容触发 Dashboard
 * 展示 type=comms(CommsMonitor 命中注入特征后的通信 dump 记录)
 * 重点高亮 dump 文件路径
 */

let dtSessions = [];
let dtSelectedId = null;
let dtLevel = '';
let dtSearch = '';
let dtSearchTimer = null;

dtLoadSessions();
setInterval(dtLoadSessions, 5000);

// ═══════════════════════════════════════════════════════════════
//  会话列表
// ═══════════════════════════════════════════════════════════════

async function dtLoadSessions() {
    try {
        const res = await fetch('/api/tracker/sessions');
        if (!res.ok) return;
        dtSessions = await res.json();
        dtRenderSessionList();
    } catch (e) { console.error('dtLoadSessions:', e); }
}

function dtRenderSessionList() {
    const el = document.getElementById('dtSessionList');
    if (dtSessions.length === 0) {
        el.innerHTML = '<div class="text-center text-muted py-5"><i class="bi bi-hdd-rack display-4 d-block mb-2"></i>暂无会话<br><small>等待 Tracker 连接...</small></div>';
        return;
    }
    el.innerHTML = dtSessions.map(s => `
        <div class="list-group-item dt-session-item ${s.id === dtSelectedId ? 'active' : ''}"
             onclick="dtSelectSession('${s.id}')">
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <span class="session-status ${s.status}"></span>
                    <strong class="text-dark">${dtEsc(s.id)}</strong>
                    <div class="text-muted small mt-1">${dtEsc(s.machineName)} · PID ${s.pid} · ${dtFmtTime(s.startedAt)}</div>
                </div>
                <div class="text-end">
                    <span class="badge ${s.status === 'active' ? 'badge-pass' : 'bg-secondary'}">${s.status === 'active' ? '在线' : '已结束'}</span>
                    <div class="text-muted small mt-1">${s.eventCount} 事件</div>
                </div>
            </div>
        </div>
    `).join('');
}

async function dtSelectSession(id) {
    dtSelectedId = id;
    dtRenderSessionList();
    document.getElementById('dtFilterBar').classList.remove('d-none');
    dtLoadEvents();
}

// ═══════════════════════════════════════════════════════════════
//  事件加载(type 固定 comms)
// ═══════════════════════════════════════════════════════════════

async function dtLoadEvents() {
    if (!dtSelectedId) return;

    const detailEl = document.getElementById('dtEventDetail');
    const titleEl = document.getElementById('dtDetailTitle');
    const metaEl = document.getElementById('dtDetailMeta');
    const countEl = document.getElementById('dtFilterCount');

    detailEl.innerHTML = '<div class="text-center text-muted py-4">加载中...</div>';

    try {
        var url = '/api/tracker/sessions/' + dtSelectedId + '?type=comms';
        var params = [];
        if (dtLevel) params.push('level=' + encodeURIComponent(dtLevel));
        if (dtSearch) params.push('search=' + encodeURIComponent(dtSearch));
        if (params.length) url += '&' + params.join('&');

        const res = await fetch(url);
        if (!res.ok) {
            detailEl.innerHTML = '<div class="text-center text-danger py-4">会话不存在</div>';
            return;
        }
        const data = await res.json();

        titleEl.innerHTML = '<i class="bi bi-bug me-2"></i>' + dtEsc(data.id);
        metaEl.textContent = dtEsc(data.machineName) + ' · ' + (data.status === 'active' ? '在线' : '已结束') + ' · ' + data.eventCount + ' 事件 · ' + dtFmtTime(data.startedAt);

        countEl.textContent = (dtLevel || dtSearch)
            ? '显示 ' + data.events.length + ' / ' + data.eventCount + ' 条'
            : '';

        if (data.events.length === 0) {
            detailEl.innerHTML = '<div class="text-center text-muted py-5"><i class="bi bi-inbox display-4 d-block mb-2"></i>'
                + ((dtLevel || dtSearch) ? '无匹配记录' : '暂无 dump 记录') + '</div>';
            return;
        }

        detailEl.innerHTML = data.events.map(function(evt, i) {
            // 提取 detail 中的 dump 文件路径单独高亮
            var dumpPaths = dtExtractDumpPaths(evt.detail || '');

            var detailHtml = '';
            if (dumpPaths.length > 0) {
                detailHtml += '<div><strong>Dump 文件路径:</strong>';
                dumpPaths.forEach(function(p) {
                    detailHtml += '<div class="dt-dump-path"><i class="bi bi-file-earmark-binary me-1"></i>' + dtEsc(p) + '</div>';
                });
                detailHtml += '</div>';
            }
            if (evt.detail) {
                detailHtml += '<div class="mt-2"><strong>完整详情:</strong><pre>' + dtEsc(evt.detail) + '</pre></div>';
            }
            if (evt.xml) {
                detailHtml += '<div class="mt-1"><strong>原始 XML:</strong><pre class="text-muted" style="max-height:200px;overflow:auto">' + dtEsc(dtTruncate(evt.xml, 2000)) + '</pre></div>';
            }

            var dumpBadge = dumpPaths.length > 0
                ? '<span class="badge bg-danger ms-1">' + dumpPaths.length + ' dump</span>'
                : '';

            return '<div class="dt-event-row" onclick="dtToggleDetail(' + i + ')">'
                + '<div class="d-flex align-items-center gap-2">'
                + '<span class="event-time">' + dtFmtEventTime(evt.timestamp) + '</span>'
                + '<span class="event-level ' + dtEsc(evt.level) + '">' + dtEsc(evt.level) + '</span>'
                + '<span class="event-type">' + dtEsc(evt.type || '-') + '</span>'
                + '<span class="event-title">' + dtEsc(evt.title) + dumpBadge + '</span>'
                + '<span class="event-source ms-auto">' + dtEsc(evt.source) + '</span>'
                + '</div></div>'
                + '<div class="dt-detail-panel" id="dtdetail-' + i + '">' + detailHtml + '</div>';
        }).join('');
    } catch (e) {
        detailEl.innerHTML = '<div class="text-center text-danger py-4">加载失败: ' + e.message + '</div>';
    }
}

/// 从 detail 文本中提取 dump 文件路径(匹配 dumpfile/filecopy 路径)
function dtExtractDumpPaths(detail) {
    var paths = [];
    // 匹配常见的路径模式(绝对路径)
    var re = /[A-Za-z]:\\[^\s:]+?\.(dmp|dump|bin|raw)/gi;
    var m;
    while ((m = re.exec(detail)) !== null) {
        paths.push(m[0]);
    }
    // 匹配 DumpFile: / FileCopy: / Dump file: 等标签后的路径
    var re2 = /(?:DumpFile|FileCopy|Dump\s*file|File\s*copy)\s*[:：]\s*([^\r\n]+)/gi;
    while ((m = re2.exec(detail)) !== null) {
        var p = m[1].trim();
        if (p && paths.indexOf(p) === -1) paths.push(p);
    }
    return paths;
}

// ═══════════════════════════════════════════════════════════════
//  过滤
// ═══════════════════════════════════════════════════════════════

function dtSetLevel(btn) {
    dtLevel = btn.getAttribute('data-level');
    document.querySelectorAll('#dtLevelFilter .btn').forEach(function(b) { b.classList.remove('active'); });
    btn.classList.add('active');
    dtLoadEvents();
}

function dtOnSearch() {
    clearTimeout(dtSearchTimer);
    dtSearchTimer = setTimeout(function() {
        dtSearch = document.getElementById('dtSearch').value.trim();
        dtLoadEvents();
    }, 300);
}

function dtClearSearch() {
    document.getElementById('dtSearch').value = '';
    dtSearch = '';
    dtLoadEvents();
}

function dtToggleDetail(i) {
    var el = document.getElementById('dtdetail-' + i);
    if (el) el.classList.toggle('open');
}

// ═══════════════════════════════════════════════════════════════
//  工具
// ═══════════════════════════════════════════════════════════════

function dtEsc(s) {
    if (!s) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function dtFmtTime(iso) {
    if (!iso) return '-';
    try { return new Date(iso).toLocaleString('zh-CN', { hour12: false }); }
    catch (e) { return iso; }
}

function dtFmtEventTime(ts) {
    if (!ts) return '';
    try {
        var d = new Date(ts);
        return d.toLocaleTimeString('zh-CN', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
            + '.' + String(d.getMilliseconds()).padStart(3, '0');
    } catch (e) { return ts; }
}

function dtTruncate(s, max) {
    if (!s || s.length <= max) return s;
    return s.substring(0, max) + '\n... (截断)';
}
