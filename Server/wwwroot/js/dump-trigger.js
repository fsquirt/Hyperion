/**
 * Dump 触发 Dashboard — 三段式: 汇总卡片 + 路径表格 + 驱动 Dump 元数据
 *
 * 布局:
 *   - 顶部: 全局配置 (dump 模式 + 磁盘文件拷贝开关)
 *   - 左侧: 会话列表
 *   - 右侧:
 *     1) 7 汇总卡片 (从最新一条 dump 记录取值, 含驱动 dump 数)
 *     2) dump 记录时间线 (每条展开后显示)
 *        a) 路径表格 (10 维度: path/tag/pid/abnormal/note/hitCount/dumped/dumpFile/fileCopied/fileCopyName)
 *        b) 驱动 dump 元数据表格 (9 维度: status/attachId/driverObjectAddr/imageBase/imageSize/bytesDumped/fullPath/baseName/dumpFile)
 *        c) 路径目录区块 (jsonLogPath/dumpFileDir/fileCopyDir)
 *
 * API:
 *   GET  /api/tracker/sessions                 会话列表
 *   GET  /api/tracker/sessions/{id}/dumps       dump 记录 (?level=&search=&minDriverDumpCount=)
 *   GET  /api/tracker/config                    读取配置
 *   POST /api/tracker/config                    保存配置
 */

var dtLevel = '';
var dtSearch = '';
var dtSearchTimer = null;

// 本地别名 -> 共享工具函数 (session-list.js)
var dtEsc = TrackerUtils.escHtml;
var dtFmtTime = TrackerUtils.formatTime;
var dtFmtEventTime = TrackerUtils.formatEventTime;

// 共享会话列表组件
var dtSessionList = new TrackerSessionList({
    containerId: 'dtSessionList',
    itemClass: 'dt-session-item',
    onSelect: function (id) { dtSelectSession(id); },
    autoRefreshMs: 5000
});

dtLoadConfig();
dtSessionList.load();
dtSessionList.startAutoRefresh();

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
//  会话列表 (委托给共享组件 dtSessionList)
// ═══════════════════════════════════════════════════════════════

function dtLoadSessions() { dtSessionList.load(); }

async function dtSelectSession(id) {
    document.getElementById('dtFilterBar').classList.remove('d-none');
    await dtLoadDumps();
}

// ═══════════════════════════════════════════════════════════════
//  Dump 记录加载
// ═══════════════════════════════════════════════════════════════

async function dtLoadDumps() {
    var dtSelectedId = dtSessionList.getSelected();
    if (!dtSelectedId) return;

    var detailEl = document.getElementById('dtEventDetail');
    var titleEl = document.getElementById('dtDetailTitle');
    var metaEl = document.getElementById('dtDetailMeta');
    var countEl = document.getElementById('dtFilterCount');
    var summaryEl = document.getElementById('dtSummaryCards');

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
            summaryEl.classList.add('d-none');
            detailEl.innerHTML = '<div class="text-center text-danger py-4">会话不存在</div>';
            return;
        }
        if (!res.ok) {
            detailEl.innerHTML = '<div class="text-center text-danger py-4">加载失败 (HTTP ' + res.status + ')</div>';
            return;
        }
        var data = await res.json();

        var session = dtSessionList.findById(dtSelectedId);
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

        // 渲染汇总卡片 (7 卡片, 从最新一条记录取值)
        dtRenderSummaryCards(data);

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

// ═══════════════════════════════════════════════════════════════
//  汇总卡片 (7 卡片, 从最新一条 dump 记录取值)
// ═══════════════════════════════════════════════════════════════

function dtRenderSummaryCards(data) {
    var summaryEl = document.getElementById('dtSummaryCards');
    if (!data || data.length === 0) {
        summaryEl.classList.add('d-none');
        return;
    }
    summaryEl.classList.remove('d-none');

    // data[0] 是最新一条 (服务端按 timestamp 倒序)
    var latest = data[0];
    document.getElementById('dtStatIoctls').textContent = latest.totalIoctls != null ? latest.totalIoctls : '-';
    document.getElementById('dtStatEvents').textContent = latest.totalEvents != null ? latest.totalEvents : '-';
    document.getElementById('dtStatPaths').textContent = latest.pathCount != null ? latest.pathCount : '-';
    document.getElementById('dtStatAbnormal').textContent = latest.abnormalCount != null ? latest.abnormalCount : '-';
    document.getElementById('dtStatDumped').textContent = latest.dumpedCount != null ? latest.dumpedCount : '-';
    document.getElementById('dtStatCopied').textContent = latest.copiedCount != null ? latest.copiedCount : '-';
    document.getElementById('dtStatDriverDumps').textContent = latest.driverDumpCount != null ? latest.driverDumpCount : '-';
}

// ═══════════════════════════════════════════════════════════════
//  Dump 记录行渲染 (标题行 + 展开后三段式: 路径表 + 驱动 dump + 路径目录)
// ═══════════════════════════════════════════════════════════════

function dtRenderRow(evt, i) {
    var paths = dtParseDumpFiles(evt.dumpFilesJson);
    var driverDumps = dtParseDriverDumps(evt.driverDumpsJson);

    // 异常路径分组 (Category C: abnormal grouping)
    var abnormalPaths = paths.filter(function (p) { return p.abnormal; });
    var normalPaths = paths.filter(function (p) { return !p.abnormal; });

    // 标题行徽章
    var badges = '';
    if (paths.length > 0) {
        badges += '<span class="badge bg-secondary ms-1">' + paths.length + ' 路径</span>';
    }
    if (abnormalPaths.length > 0) {
        badges += '<span class="badge bg-danger ms-1">' + abnormalPaths.length + ' 异常</span>';
    }
    if (driverDumps.length > 0) {
        badges += '<span class="badge bg-purple ms-1">' + driverDumps.length + ' 驱动 Dump</span>';
    }

    // 展开后: 三段式
    var detailHtml = '';

    // 段 1: 路径表格 (异常路径置顶, 然后正常路径)
    if (paths.length > 0) {
        detailHtml += '<div class="detail-section">';
        detailHtml += '<div class="detail-section-title">路径表格 (' + paths.length + ' 条';
        if (abnormalPaths.length > 0) {
            detailHtml += ', ' + abnormalPaths.length + ' 异常';
        }
        detailHtml += ')</div>';
        detailHtml += '<table class="dt-path-table">';
        detailHtml += '<thead><tr>'
            + '<th>路径</th><th>Tag</th><th>PID</th><th>Hits</th>'
            + '<th>异常</th><th>备注</th>'
            + '<th>Dump</th><th>文件拷贝</th>'
            + '</tr></thead><tbody>';
        // 异常路径优先显示
        abnormalPaths.forEach(function (p) { detailHtml += dtRenderPathRow(p); });
        normalPaths.forEach(function (p) { detailHtml += dtRenderPathRow(p); });
        detailHtml += '</tbody></table>';
        detailHtml += '</div>';
    } else {
        detailHtml += '<div class="detail-section"><div class="text-muted small">无路径数据</div></div>';
    }

    // 段 2: 驱动 dump 元数据表格 (Category D: 之前 C++ 只写磁盘)
    if (driverDumps.length > 0) {
        detailHtml += '<div class="detail-section">';
        detailHtml += '<div class="detail-section-title">驱动 Dump 元数据 (' + driverDumps.length + ' 条)</div>';
        detailHtml += '<table class="dt-driver-dump-table">';
        detailHtml += '<thead><tr>'
            + '<th>Status</th><th>AttachId</th><th>DriverObject</th><th>ImageBase</th><th>ImageSize</th>'
            + '<th>BytesDumped</th><th>FullPath</th><th>BaseName</th><th>DumpFile</th>'
            + '</tr></thead><tbody>';
        driverDumps.forEach(function (d) {
            detailHtml += dtRenderDriverDumpRow(d);
        });
        detailHtml += '</tbody></table>';
        detailHtml += '</div>';
    }

    // 段 3: 路径目录区块 (Category D: jsonLogPath/dumpFileDir/fileCopyDir)
    var hasDir = evt.jsonLogPath || evt.dumpFileDir || evt.fileCopyDir;
    if (hasDir) {
        detailHtml += '<div class="detail-section">';
        detailHtml += '<div class="detail-section-title">输出目录</div>';
        detailHtml += '<div class="dt-dir-section"><div class="dt-dir-kv">';
        detailHtml += dtRenderDirKv('JSON 日志', evt.jsonLogPath);
        detailHtml += dtRenderDirKv('Dump 目录', evt.dumpFileDir);
        detailHtml += dtRenderDirKv('文件拷贝目录', evt.fileCopyDir);
        detailHtml += '</div></div>';
        detailHtml += '</div>';
    }

    return '<div class="dt-event-row" onclick="dtToggleDetail(' + i + ')">'
        + '<div class="d-flex align-items-center gap-2">'
        + '<span class="event-time">' + dtFmtEventTime(evt.timestamp) + '</span>'
        + '<span class="event-level ' + dtEsc(evt.level || 'INFO') + '">' + dtEsc(evt.level || 'INFO') + '</span>'
        + '<span class="event-title">' + dtEsc(evt.title || '(无标题)') + badges + '</span>'
        + '</div></div>'
        + '<div class="dt-detail-panel" id="dtdetail-' + i + '">' + detailHtml + '</div>';
}

/// 渲染路径表格行 (完整结构化: path/tag/pid/abnormal/note/hitCount/dumped/dumpFile/fileCopied/fileCopyName)
function dtRenderPathRow(p) {
    var abnormalClass = p.abnormal ? ' dt-abnormal' : '';
    var abnormalHtml = p.abnormal
        ? '<span class="abnormal-yes">是</span>'
        : '<span class="abnormal-no">否</span>';

    var tagHtml = p.tag ? '<span class="tag-badge">' + dtEsc(p.tag) + '</span>' : '<span class="abnormal-no">-</span>';
    var noteHtml = p.note ? '<span class="note-text">' + dtEsc(p.note) + '</span>' : '<span class="abnormal-no">-</span>';

    var dumpHtml;
    if (p.dumped) {
        dumpHtml = '<span class="dump-yes"><i class="bi bi-check-lg"></i></span>';
        if (p.dumpFile) {
            dumpHtml += '<span class="file-path-small">' + dtEsc(p.dumpFile) + '</span>';
        }
    } else {
        dumpHtml = '<span class="dump-no"><i class="bi bi-dash"></i></span>';
    }

    var copyHtml;
    if (p.fileCopied) {
        copyHtml = '<span class="dump-yes"><i class="bi bi-check-lg"></i></span>';
        if (p.fileCopyName) {
            copyHtml += '<span class="file-path-small">' + dtEsc(p.fileCopyName) + '</span>';
        }
    } else {
        copyHtml = '<span class="dump-no"><i class="bi bi-dash"></i></span>';
    }

    return '<tr class="' + abnormalClass + '">'
        + '<td class="mono">' + dtEsc(p.path || '(空)') + '</td>'
        + '<td>' + tagHtml + '</td>'
        + '<td>' + dtEsc(p.pid != null ? p.pid : '-') + '</td>'
        + '<td>' + dtEsc(p.hitCount != null ? p.hitCount : '-') + '</td>'
        + '<td>' + abnormalHtml + '</td>'
        + '<td>' + noteHtml + '</td>'
        + '<td>' + dumpHtml + '</td>'
        + '<td>' + copyHtml + '</td>'
        + '</tr>';
}

/// 渲染驱动 dump 元数据行 (Category D: 9 维度)
function dtRenderDriverDumpRow(d) {
    var statusHtml = d.status === 0
        ? '<span class="status-ok">0 (OK)</span>'
        : '<span class="status-err">' + dtEsc(d.status != null ? d.status : '-') + '</span>';
    return '<tr>'
        + '<td>' + statusHtml + '</td>'
        + '<td>' + dtEsc(d.attachId != null ? d.attachId : '-') + '</td>'
        + '<td class="mono">0x' + (d.driverObjectAddr != null ? d.driverObjectAddr.toString(16).toUpperCase() : '-') + '</td>'
        + '<td class="mono">0x' + (d.imageBase != null ? d.imageBase.toString(16).toUpperCase().padStart(8, '0') : '-') + '</td>'
        + '<td>' + (d.imageSize != null ? dtFmtBytes(d.imageSize) : '-') + '</td>'
        + '<td>' + (d.bytesDumped != null ? dtFmtBytes(d.bytesDumped) : '-') + '</td>'
        + '<td class="mono">' + dtEsc(d.fullPath || '-') + '</td>'
        + '<td>' + dtEsc(d.baseName || '-') + '</td>'
        + '<td class="mono">' + dtEsc(d.dumpFile || '-') + '</td>'
        + '</tr>';
}

/// 渲染路径目录键值对
function dtRenderDirKv(label, val) {
    if (val) {
        return '<span class="key">' + dtEsc(label) + '</span><span class="val">' + dtEsc(val) + '</span>';
    }
    return '<span class="key">' + dtEsc(label) + '</span><span class="val empty">-</span>';
}

/// 解析 dumpFilesJson 为路径数组
function dtParseDumpFiles(json) {
    if (!json) return [];
    if (Array.isArray(json)) return json;
    try {
        var arr = JSON.parse(json);
        return Array.isArray(arr) ? arr : [];
    } catch (e) { return []; }
}

/// 解析 driverDumpsJson 为驱动 dump 元数据数组 (Category D)
function dtParseDriverDumps(json) {
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

// 字节格式化 (KB/MB/GB)
function dtFmtBytes(n) {
    if (n == null) return '-';
    var bytes = Number(n);
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    if (bytes < 1024 * 1024 * 1024) return (bytes / 1024 / 1024).toFixed(2) + ' MB';
    return (bytes / 1024 / 1024 / 1024).toFixed(2) + ' GB';
}
