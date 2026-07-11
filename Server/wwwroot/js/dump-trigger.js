/**
 * Dump 触发 Dashboard
 * 顶部:全局配置(dump 模式 + 磁盘文件拷贝开关)
 * 左侧:会话列表;右侧:dump 触发记录(含 dump 文件路径高亮)
 *
 * API:
 *   GET  /api/tracker/sessions                 会话列表
 *   GET  /api/tracker/sessions/{id}/dumps       dump 记录(?level=&search=)
 *   GET  /api/tracker/config                    读取配置
 *   POST /api/tracker/config                    保存配置
 */

var dtSessions = [];
var dtSelectedId = null;
var dtLevel = '';
var dtSearch = '';
var dtSearchTimer = null;

dtLoadConfig();
dtLoadSessions();
setInterval(dtLoadSessions, 5000);

// ═══════════════════════════════════════════════════════════════
//  全局配置
// ═══════════════════════════════════════════════════════════════

async function dtLoadConfig() {
    try {
        var res = await fetch('/api/tracker/config');
        if (!res.ok) return;
        var cfg = await res.json();
        dtApplyConfig(cfg);
    } catch (e) { console.error('dtLoadConfig:', e); }
}

function dtApplyConfig(cfg) {
    var mode = (cfg && cfg.dumpMode) || 'mini';
    document.querySelectorAll('input[name="dtDumpMode"]').forEach(function (r) {
        r.checked = (r.value === mode);
    });
    document.getElementById('dtFileCopy').checked = (cfg && cfg.fileCopyEnabled !== false);
}

async function dtSaveConfig() {
    // 先 GET 当前配置,合并 dumpMode + fileCopyEnabled 后 POST
    var cfg;
    try {
        var getRes = await fetch('/api/tracker/config');
        if (!getRes.ok) {
            dtShowConfigMsg('danger', '读取当前配置失败');
            return;
        }
        cfg = await getRes.json();
    } catch (e) {
        dtShowConfigMsg('danger', '读取当前配置失败: ' + e.message);
        return;
    }

    var checked = document.querySelector('input[name="dtDumpMode"]:checked');
    cfg.dumpMode = checked ? checked.value : 'mini';
    cfg.fileCopyEnabled = document.getElementById('dtFileCopy').checked;

    try {
        var postRes = await fetch('/api/tracker/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(cfg)
        });
        if (!postRes.ok) {
            var err = await postRes.json().catch(function () { return {}; });
            dtShowConfigMsg('danger', '保存失败: ' + (err.error || postRes.status));
            return;
        }
        var result = await postRes.json();
        dtApplyConfig(result);
        dtShowConfigMsg('success', '配置已保存');
    } catch (e) {
        dtShowConfigMsg('danger', '保存失败: ' + e.message);
    }
}

function dtShowConfigMsg(type, text) {
    var el = document.getElementById('dtConfigMsg');
    var icon = type === 'success' ? 'bi-check-circle' : 'bi-exclamation-triangle';
    el.innerHTML = '<div class="alert alert-' + type + ' py-1 px-2 mb-0 small">'
        + '<i class="bi ' + icon + ' me-1"></i>' + dtEsc(text) + '</div>';
    if (type === 'success') {
        setTimeout(function () {
            if (el.innerHTML.indexOf('check-circle') >= 0) el.innerHTML = '';
        }, 3000);
    }
}

// ═══════════════════════════════════════════════════════════════
//  会话列表
// ═══════════════════════════════════════════════════════════════

async function dtLoadSessions() {
    try {
        var res = await fetch('/api/tracker/sessions');
        if (!res.ok) return;
        dtSessions = await res.json();
        dtRenderSessionList();
    } catch (e) { console.error('dtLoadSessions:', e); }
}

function dtRenderSessionList() {
    var el = document.getElementById('dtSessionList');
    if (!dtSessions || dtSessions.length === 0) {
        el.innerHTML = '<div class="text-center text-muted py-5">'
            + '<i class="bi bi-hdd-rack display-4 d-block mb-2"></i>暂无会话'
            + '<br><small>等待 Tracker 连接...</small></div>';
        return;
    }
    el.innerHTML = dtSessions.map(function (s) {
        return '<div class="list-group-item dt-session-item ' + (s.id === dtSelectedId ? 'active' : '') + '"'
            + ' onclick="dtSelectSession(\'' + dtEsc(s.id) + '\')">'
            + '<div class="d-flex justify-content-between align-items-start">'
            + '<div>'
            + '<span class="session-status ' + dtEsc(s.status) + '"></span>'
            + '<strong class="text-dark">' + dtEsc(s.id) + '</strong>'
            + '<div class="text-muted small mt-1">' + dtEsc(s.machineName) + ' · PID ' + dtEsc(s.pid) + ' · ' + dtFmtTime(s.startedAt) + '</div>'
            + '</div>'
            + '<div class="text-end">'
            + '<span class="badge ' + (s.status === 'active' ? 'badge-pass' : 'bg-secondary') + '">'
            + (s.status === 'active' ? '在线' : '已结束') + '</span>'
            + '<div class="text-muted small mt-1">' + dtEsc(s.eventCount) + ' 事件</div>'
            + '</div>'
            + '</div></div>';
    }).join('');
}

async function dtSelectSession(id) {
    dtSelectedId = id;
    dtRenderSessionList();
    document.getElementById('dtFilterBar').classList.remove('d-none');
    await dtLoadDumps();
}

// ═══════════════════════════════════════════════════════════════
//  Dump 记录加载
// ═══════════════════════════════════════════════════════════════

async function dtLoadDumps() {
    if (!dtSelectedId) return;

    var detailEl = document.getElementById('dtEventDetail');
    var titleEl = document.getElementById('dtDetailTitle');
    var metaEl = document.getElementById('dtDetailMeta');
    var countEl = document.getElementById('dtFilterCount');

    detailEl.innerHTML = '<div class="text-center text-muted py-4">加载中...</div>';

    var url = '/api/tracker/sessions/' + encodeURIComponent(dtSelectedId) + '/dumps';
    var params = [];
    if (dtLevel) params.push('level=' + encodeURIComponent(dtLevel));
    if (dtSearch) params.push('search=' + encodeURIComponent(dtSearch));
    if (params.length) url += '?' + params.join('&');

    try {
        var res = await fetch(url);
        if (res.status === 404) {
            titleEl.innerHTML = '<i class="bi bi-bug me-2"></i>Dump 触发记录';
            metaEl.textContent = '';
            countEl.textContent = '';
            detailEl.innerHTML = '<div class="text-center text-danger py-4">会话不存在</div>';
            return;
        }
        if (!res.ok) {
            detailEl.innerHTML = '<div class="text-center text-danger py-4">加载失败 (HTTP ' + res.status + ')</div>';
            return;
        }
        var data = await res.json();

        // 从会话列表中取会话信息填充头部
        var session = null;
        for (var i = 0; i < dtSessions.length; i++) {
            if (dtSessions[i].id === dtSelectedId) { session = dtSessions[i]; break; }
        }
        if (session) {
            titleEl.innerHTML = '<i class="bi bi-bug me-2"></i>' + dtEsc(session.id);
            metaEl.textContent = dtEsc(session.machineName)
                + ' · ' + (session.status === 'active' ? '在线' : '已结束')
                + ' · ' + data.length + ' dumps · ' + dtFmtTime(session.startedAt);
        } else {
            titleEl.innerHTML = '<i class="bi bi-bug me-2"></i>' + dtEsc(dtSelectedId);
            metaEl.textContent = data.length + ' dumps';
        }

        if (dtLevel || dtSearch) {
            countEl.textContent = '显示 ' + data.length + ' 条';
        } else {
            countEl.textContent = data.length > 0 ? '共 ' + data.length + ' 条' : '';
        }

        if (!data || data.length === 0) {
            detailEl.innerHTML = '<div class="text-center text-muted py-5">'
                + '<i class="bi bi-inbox display-4 d-block mb-2"></i>'
                + ((dtLevel || dtSearch) ? '无匹配记录' : '暂无 dump 记录') + '</div>';
            return;
        }

        detailEl.innerHTML = data.map(function (evt, i) {
            return dtRenderRow(evt, i);
        }).join('');
    } catch (e) {
        detailEl.innerHTML = '<div class="text-center text-danger py-4">加载失败: ' + dtEsc(e.message) + '</div>';
    }
}

function dtRenderRow(evt, i) {
    var files = dtParseDumpFiles(evt.dumpFilesJson);

    var detailHtml = '';
    if (files.length > 0) {
        detailHtml += '<div><strong>Dump 文件路径:</strong>';
        files.forEach(function (f) { detailHtml += dtRenderDumpFile(f); });
        detailHtml += '</div>';
    }
    if (evt.detail) {
        detailHtml += '<div class="mt-2"><strong>详情:</strong><pre>' + dtEsc(evt.detail) + '</pre></div>';
    }
    if (!detailHtml) {
        detailHtml = '<div class="text-muted small">无详细信息</div>';
    }

    var dumpBadge = files.length > 0
        ? '<span class="badge bg-danger ms-1">' + files.length + ' dumps</span>'
        : '';

    return '<div class="dt-event-row" onclick="dtToggleDetail(' + i + ')">'
        + '<div class="d-flex align-items-center gap-2">'
        + '<span class="event-time">' + dtFmtEventTime(evt.timestamp) + '</span>'
        + '<span class="event-level ' + dtEsc(evt.level || 'INFO') + '">' + dtEsc(evt.level || 'INFO') + '</span>'
        + '<span class="event-title">' + dtEsc(evt.title || '(无标题)') + dumpBadge + '</span>'
        + '</div></div>'
        + '<div class="dt-detail-panel" id="dtdetail-' + i + '">' + detailHtml + '</div>';
}

function dtRenderDumpFile(f) {
    var kind = f.kind || 'dump';
    var icon = kind === 'filecopy'
        ? '<i class="bi bi-files me-1"></i>'
        : '<i class="bi bi-file-earmark-binary me-1"></i>';
    var kindLabel = kind === 'filecopy' ? 'filecopy' : 'dump';

    return '<div class="dt-dump-path">'
        + icon
        + '<span class="dump-path-text">' + dtEsc(f.path || '') + '</span>'
        + '<span class="badge dump-kind-' + dtEsc(kind) + '">' + dtEsc(kindLabel) + '</span>'
        + '<span class="text-muted small">PID: ' + dtEsc(f.pid != null ? f.pid : '-') + '</span>'
        + '<span class="text-muted small">Hit: ' + dtEsc(f.hitCount != null ? f.hitCount : '-') + '</span>'
        + '</div>';
}

/// dumpFilesJson 是字符串,解析为 [{path, kind, pid, hitCount, abnormal}]
function dtParseDumpFiles(json) {
    if (!json) return [];
    if (Array.isArray(json)) return json;
    try {
        var arr = JSON.parse(json);
        return Array.isArray(arr) ? arr : [];
    } catch (e) { return []; }
}

// ═══════════════════════════════════════════════════════════════
//  过滤 / 展开
// ═══════════════════════════════════════════════════════════════

function dtSetLevel(btn) {
    dtLevel = btn.getAttribute('data-level') || '';
    document.querySelectorAll('#dtLevelFilter .btn').forEach(function (b) { b.classList.remove('active'); });
    btn.classList.add('active');
    dtLoadDumps();
}

function dtOnSearch() {
    clearTimeout(dtSearchTimer);
    dtSearchTimer = setTimeout(function () {
        dtSearch = document.getElementById('dtSearch').value.trim();
        dtLoadDumps();
    }, 300);
}

function dtClearSearch() {
    document.getElementById('dtSearch').value = '';
    dtSearch = '';
    dtLoadDumps();
}

function dtToggleDetail(i) {
    var el = document.getElementById('dtdetail-' + i);
    if (el) el.classList.toggle('open');
}

// ═══════════════════════════════════════════════════════════════
//  工具
// ═══════════════════════════════════════════════════════════════

function dtEsc(s) {
    if (s === null || s === undefined) return '';
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
