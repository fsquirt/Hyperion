/**
 * 内核通信 Dashboard — 因果链管道图 + 阶段卡片
 *
 * 布局:
 *   - 左栏: 会话列表
 *   - 右栏:
 *     1) 顶部: 因果链管道图 (7 阶段水平流程图)
 *        driver → iat → device → attach → object → comms → ioctl
 *     2) 下方: 选中阶段的卡片列表 (每条记录是一个卡片, 不是表格行)
 *
 * 核心区别 (vs 事件追踪 UI):
 *   1. 顶部是因果链管道图, 不是 Tab 导航
 *   2. 阶段之间有箭头连接, 体现因果关系
 *   3. 每条记录是卡片, 不是表格行
 *   4. attach 卡片有追溯链接 → 可以查看该 attach 产生的 comms 事件
 *
 * kind 取值: driver | iat | device | attach | attach-summary | object-scan | handle-scan | comms-event | ioctl
 */

var kcAllRecords = [];         // 全部 kernel-comms 记录
var kcCurrentStage = 'driver'; // 当前查看的因果链阶段
var kcFilterTimer = null;

var kcConfig = {
    treePollIntervalSec: 10,
    ioctlEnabled: false,
    dumpMode: 'mini',
    fileCopyEnabled: true
};

// 因果链阶段定义 (顺序 = 因果链顺序)
var kcStages = [
    { key: 'driver',  name: '驱动扫描',   icon: 'bi-hdd-network',   kinds: ['driver'] },
    { key: 'iat',     name: 'IAT 分析',   icon: 'bi-exclamation-triangle', kinds: ['iat'] },
    { key: 'device',  name: '设备枚举',   icon: 'bi-plugin',       kinds: ['device'] },
    { key: 'attach',  name: '附着',       icon: 'bi-link-45deg',   kinds: ['attach', 'attach-summary'] },
    { key: 'object',  name: '对象/句柄',  icon: 'bi-diagram-3',    kinds: ['object-scan', 'handle-scan'] },
    { key: 'comms',   name: '通信事件',   icon: 'bi-broadcast',    kinds: ['comms-event'] },
    { key: 'ioctl',   name: 'IOCTL拦截',  icon: 'bi-shield-exclamation', kinds: ['ioctl'] },
];

// 本地别名 -> 共享工具函数
var escHtml = TrackerUtils.escHtml;
var formatTime = TrackerUtils.formatTime;
var formatEventTime = TrackerUtils.formatEventTime;

// 共享会话列表组件
var kcSessionList = new TrackerSessionList({
    containerId: 'kcSessionList',
    itemClass: 'kc-session-item',
    onSelect: function (id) { kcSelectSession(id); },
    autoRefreshMs: 5000
});

kcLoadConfig();
kcSessionList.load();
kcSessionList.startAutoRefresh();

// ═══════════════════════════════════════════════════════════════
//  配置
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
    var ioctlEnabled = document.getElementById('kcIoctlToggle').checked;
    try {
        var getRes = await fetch('/api/tracker/config');
        if (!getRes.ok) return;
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
        if (!postRes.ok) return;
        kcConfig = await postRes.json();
        kcRenderConfig();
    } catch (e) { console.error('kcSaveConfig:', e); }
}

// ═══════════════════════════════════════════════════════════════
//  会话列表
// ═══════════════════════════════════════════════════════════════

function kcLoadSessions() { kcSessionList.load(); }

async function kcSelectSession(id) {
    document.getElementById('kcPipelineWrap').classList.remove('d-none');
    document.getElementById('kcFilterBar').classList.remove('d-none');
    await kcLoadEvents();
}

// ═══════════════════════════════════════════════════════════════
//  加载全部 kernel-comms 记录
// ═══════════════════════════════════════════════════════════════

async function kcLoadEvents() {
    var kcSelectedId = kcSessionList.getSelected();
    if (!kcSelectedId) return;

    var detailEl = document.getElementById('kcEventDetail');
    if (detailEl) detailEl.innerHTML = '<div class="kc-empty">加载中...</div>';

    try {
        var url = '/api/tracker/sessions/' + encodeURIComponent(kcSelectedId) + '/kernel-comms';
        var res = await fetch(url);
        if (!res.ok) {
            if (detailEl) detailEl.innerHTML = '<div class="kc-empty">加载失败</div>';
            return;
        }
        kcAllRecords = await res.json() || [];

        // 更新标题
        var titleEl = document.getElementById('kcDetailTitle');
        var metaEl = document.getElementById('kcDetailMeta');
        var session = kcSessionList.findById(kcSelectedId);
        if (titleEl) titleEl.innerHTML = '<i class="bi bi-diagram-2 me-2"></i>' + escHtml(kcSelectedId);
        if (metaEl) metaEl.textContent = kcAllRecords.length + ' 条记录';

        // 渲染管道图
        kcRenderPipeline();

        // 渲染当前阶段卡片
        kcRenderCards();
    } catch (e) {
        if (detailEl) detailEl.innerHTML = '<div class="kc-empty">加载失败: ' + escHtml(e.message) + '</div>';
    }
}

// ═══════════════════════════════════════════════════════════════
//  因果链管道图 — 7 阶段水平流程图
// ═══════════════════════════════════════════════════════════════

function kcRenderPipeline() {
    var pipelineEl = document.getElementById('kcPipeline');
    if (!pipelineEl) return;

    // 计算每个阶段的记录数
    var counts = {};
    kcStages.forEach(function (stage) {
        counts[stage.key] = kcAllRecords.filter(function (r) {
            return stage.kinds.indexOf(r.kind) >= 0;
        }).length;
    });

    var html = '';
    for (var i = 0; i < kcStages.length; i++) {
        var stage = kcStages[i];
        var count = counts[stage.key];
        var isActive = kcCurrentStage === stage.key;
        var isEmpty = count === 0;

        var cls = 'kc-stage';
        if (isActive) cls += ' active';
        if (isEmpty) cls += ' empty';

        // 子标题: 阶段的补充信息
        var sub = kcGetStageSub(stage.key, count);

        html += '<div class="' + cls + '" data-stage="' + stage.key + '" onclick="kcSetStage(\'' + stage.key + '\')">'
            + '<div class="kc-stage-icon"><i class="bi ' + stage.icon + '"></i></div>'
            + '<div class="kc-stage-name">' + escHtml(stage.name) + '</div>'
            + '<div class="kc-stage-count">' + count + '</div>'
            + (sub ? '<div class="kc-stage-sub">' + sub + '</div>' : '')
            + '</div>';

        // 阶段之间有箭头 (最后一个阶段没有)
        if (i < kcStages.length - 1) {
            var arrowActive = count > 0;
            html += '<div class="kc-arrow' + (arrowActive ? ' active' : '') + '"><i class="bi bi-arrow-right"></i></div>';
        }
    }
    pipelineEl.innerHTML = html;
}

function kcGetStageSub(key, count) {
    if (count === 0) return '';
    if (key === 'driver') {
        var thirdParty = kcAllRecords.filter(function (r) { return r.kind === 'driver' && r.driverClass === 2; }).length;
        return thirdParty > 0 ? thirdParty + ' 个三方驱动' : '';
    }
    if (key === 'iat') {
        var totalDanger = kcAllRecords.filter(function (r) { return r.kind === 'iat'; })
            .reduce(function (sum, r) { return sum + (r.dangerousApiCount || 0); }, 0);
        return totalDanger > 0 ? totalDanger + ' 个危险API' : '';
    }
    if (key === 'attach') {
        var attached = kcAllRecords.filter(function (r) { return r.kind === 'attach'; }).length;
        return attached > 0 ? attached + ' 个设备已附着' : '';
    }
    if (key === 'object') {
        var handleScans = kcAllRecords.filter(function (r) { return r.kind === 'handle-scan'; }).length;
        var objScans = kcAllRecords.filter(function (r) { return r.kind === 'object-scan'; }).length;
        return (objScans > 0 ? objScans + ' 对象' : '') + (handleScans > 0 ? (objScans > 0 ? ' · ' : '') + handleScans + ' 句柄' : '');
    }
    if (key === 'comms') {
        var distinctPids = new Set();
        kcAllRecords.filter(function (r) { return r.kind === 'comms-event'; })
            .forEach(function (r) { if (r.requestorPid != null) distinctPids.add(r.requestorPid); });
        return distinctPids.size > 0 ? distinctPids.size + ' 个进程' : '';
    }
    return '';
}

// ═══════════════════════════════════════════════════════════════
//  阶段切换
// ═══════════════════════════════════════════════════════════════

function kcSetStage(stage) {
    kcCurrentStage = stage;
    // 更新管道图高亮
    document.querySelectorAll('#kcPipeline .kc-stage').forEach(function (el) {
        el.classList.toggle('active', el.getAttribute('data-stage') === stage);
    });
    // 更新阶段标签
    var stageLabel = document.getElementById('kcStageLabel');
    if (stageLabel) {
        var stageInfo = kcStages.find(function (s) { return s.key === stage; });
        stageLabel.textContent = stageInfo ? stageInfo.name : stage;
    }
    // 切换过滤组
    document.querySelectorAll('.kc-filter-group').forEach(function (g) {
        g.classList.toggle('d-none', g.getAttribute('data-stage') !== stage);
    });
    kcRenderCards();
}

// ═══════════════════════════════════════════════════════════════
//  筛选
// ═══════════════════════════════════════════════════════════════

function kcOnFilter() {
    clearTimeout(kcFilterTimer);
    kcFilterTimer = setTimeout(kcRenderCards, 200);
}

function kcGetFilteredRecords() {
    var stage = kcCurrentStage;
    var stageInfo = kcStages.find(function (s) { return s.key === stage; });
    if (!stageInfo) return [];

    var records = kcAllRecords.filter(function (r) {
        return stageInfo.kinds.indexOf(r.kind) >= 0;
    });

    // 按阶段应用特定筛选
    if (stage === 'driver') {
        var classFilter = document.getElementById('kcDriverClassFilter').value;
        var vendorSearch = (document.getElementById('kcVendorSearch').value || '').toLowerCase();
        var fileSearch = (document.getElementById('kcDriverFileSearch').value || '').toLowerCase();
        if (classFilter !== '') {
            var cls = parseInt(classFilter, 10);
            records = records.filter(function (r) { return r.driverClass === cls; });
        }
        if (vendorSearch) {
            records = records.filter(function (r) { return (r.vendorName || '').toLowerCase().indexOf(vendorSearch) >= 0; });
        }
        if (fileSearch) {
            records = records.filter(function (r) { return (r.driverFileName || '').toLowerCase().indexOf(fileSearch) >= 0; });
        }
    } else if (stage === 'iat') {
        var iatSearch = (document.getElementById('kcIatDriverSearch').value || '').toLowerCase();
        if (iatSearch) {
            records = records.filter(function (r) { return (r.driverFileName || '').toLowerCase().indexOf(iatSearch) >= 0; });
        }
    } else if (stage === 'device') {
        var devSearch = (document.getElementById('kcDeviceNameSearch').value || '').toLowerCase();
        if (devSearch) {
            records = records.filter(function (r) {
                return (r.deviceName || '').toLowerCase().indexOf(devSearch) >= 0 ||
                       (r.driverFileName || '').toLowerCase().indexOf(devSearch) >= 0;
            });
        }
    } else if (stage === 'attach') {
        var attachIdSearch = (document.getElementById('kcAttachIdSearch').value || '').toLowerCase();
        var attachDevSearch = (document.getElementById('kcAttachDeviceSearch').value || '').toLowerCase();
        if (attachIdSearch) {
            records = records.filter(function (r) { return String(r.attachId || '').indexOf(attachIdSearch) >= 0; });
        }
        if (attachDevSearch) {
            records = records.filter(function (r) { return (r.deviceName || '').toLowerCase().indexOf(attachDevSearch) >= 0; });
        }
    } else if (stage === 'object') {
        var typeSearch = (document.getElementById('kcTypeNameSearch').value || '').toLowerCase();
        var highRiskOnly = document.getElementById('kcHighRiskOnly').checked;
        if (typeSearch) {
            records = records.filter(function (r) {
                var data = kcParseDataJson(r.dataJson);
                if (!data) return false;
                var list = data.entries || data.handles || [];
                return list.some(function (e) { return (e.typeName || '').toLowerCase().indexOf(typeSearch) >= 0; });
            });
        }
        if (highRiskOnly) {
            records = records.filter(function (r) {
                if (r.kind !== 'handle-scan') return false;
                var data = kcParseDataJson(r.dataJson);
                return data && data.highRiskCount > 0;
            });
        }
    } else if (stage === 'comms') {
        var codeSearch = (document.getElementById('kcCommsCodeSearch').value || '').toLowerCase();
        var pidSearch = (document.getElementById('kcCommsPidSearch').value || '').toLowerCase();
        var commsAttachSearch = (document.getElementById('kcCommsAttachSearch').value || '').toLowerCase();
        if (codeSearch) {
            records = records.filter(function (r) {
                var hex = r.ioControlCode != null ? '0x' + r.ioControlCode.toString(16).toUpperCase() : '';
                return hex.toLowerCase().indexOf(codeSearch) >= 0 || String(r.ioControlCode || '').indexOf(codeSearch) >= 0;
            });
        }
        if (pidSearch) {
            records = records.filter(function (r) { return String(r.requestorPid || '').indexOf(pidSearch) >= 0; });
        }
        if (commsAttachSearch) {
            records = records.filter(function (r) { return String(r.attachId || '').indexOf(commsAttachSearch) >= 0; });
        }
    } else if (stage === 'ioctl') {
        var ioctlCode = (document.getElementById('kcIoctlCodeSearch').value || '').toLowerCase();
        var ioctlPid = (document.getElementById('kcRequestorPidSearch').value || '').toLowerCase();
        if (ioctlCode) {
            records = records.filter(function (r) {
                var hex = r.ioControlCode != null ? '0x' + r.ioControlCode.toString(16).toUpperCase() : '';
                return hex.toLowerCase().indexOf(ioctlCode) >= 0 || String(r.ioControlCode || '').indexOf(ioctlCode) >= 0;
            });
        }
        if (ioctlPid) {
            records = records.filter(function (r) { return String(r.requestorPid || '').indexOf(ioctlPid) >= 0; });
        }
    }

    return records;
}

// ═══════════════════════════════════════════════════════════════
//  渲染卡片列表 (每条记录是一个卡片)
// ═══════════════════════════════════════════════════════════════

function kcRenderCards() {
    var detailEl = document.getElementById('kcEventDetail');
    var countEl = document.getElementById('kcFilterCount');
    if (!detailEl) return;

    var records = kcGetFilteredRecords();

    // 计算总数
    var stageInfo = kcStages.find(function (s) { return s.key === kcCurrentStage; });
    var total = stageInfo ? kcAllRecords.filter(function (r) { return stageInfo.kinds.indexOf(r.kind) >= 0; }).length : 0;
    if (countEl) {
        countEl.textContent = (records.length < total) ? ('显示 ' + records.length + ' / ' + total + ' 条') : '';
    }

    if (records.length === 0) {
        var stageName = stageInfo ? stageInfo.name : kcCurrentStage;
        detailEl.innerHTML = '<div class="kc-empty"><i class="bi bi-inbox display-4 d-block mb-2"></i>暂无' + escHtml(stageName) + '记录</div>';
        return;
    }

    var html = '<div class="kc-card-list">';
    records.forEach(function (r, i) {
        html += kcRenderCard(r, i);
    });
    html += '</div>';
    detailEl.innerHTML = html;
}

function kcRenderCard(r, i) {
    var kind = r.kind;
    var header = kcRenderCardHeader(r, i);
    var body = kcRenderCardBody(r, i);
    return '<div class="kc-card" id="kccard-' + i + '">'
        + header
        + '<div class="kc-card-body">' + body + '</div>'
        + '</div>';
}

function kcRenderCardHeader(r, i) {
    var kind = r.kind;
    var level = r.level || 'INFO';
    var time = formatEventTime(r.timestamp);
    var title = r.title || '(无标题)';

    // kind badge
    var kindBadge = '<span class="kc-card-badge ' + escHtml(kind) + '">' + escHtml(kind) + '</span>';
    // level badge
    var levelBadge = '<span class="kc-card-badge level-' + escHtml(level) + '">' + escHtml(level) + '</span>';

    // 阶段特定的 chips
    var chips = '';
    if (kind === 'driver') {
        chips += kcChip('info', kcGetClassName(r.driverClass));
        if (r.vendorName) chips += kcChip('', escHtml(r.vendorName));
        if (r.imageBase != null) chips += kcChip('mono', '0x' + r.imageBase.toString(16).toUpperCase());
    } else if (kind === 'iat') {
        chips += kcChip('danger', (r.dangerousApiCount || 0) + ' 危险API');
    } else if (kind === 'device') {
        var data = kcParseDataJson(r.dataJson);
        if (data && data.devices) chips += kcChip('info', data.devices.length + ' 设备');
    } else if (kind === 'attach') {
        if (r.attachId != null) chips += kcChip('mono', 'AttachId=' + r.attachId);
        if (r.deviceName) chips += kcChip('', escHtml(r.deviceName));
    } else if (kind === 'attach-summary') {
        var adata = kcParseDataJson(r.dataJson);
        if (adata && adata.count != null) chips += kcChip('info', adata.count + ' 附着');
    } else if (kind === 'object-scan') {
        var odata = kcParseDataJson(r.dataJson);
        if (odata && odata.totalCount != null) chips += kcChip('info', odata.totalCount + ' 对象');
    } else if (kind === 'handle-scan') {
        var hdata = kcParseDataJson(r.dataJson);
        if (hdata) {
            if (hdata.totalCount != null) chips += kcChip('info', hdata.totalCount + ' 句柄');
            if (hdata.highRiskCount > 0) chips += kcChip('danger', hdata.highRiskCount + ' 高危');
        }
    } else if (kind === 'comms-event') {
        if (r.ioControlCode != null) chips += kcChip('mono', '0x' + r.ioControlCode.toString(16).toUpperCase().padStart(8, '0'));
        if (r.requestorPid != null) chips += kcChip('', 'PID=' + r.requestorPid);
        if (r.attachId != null) chips += kcChip('mono', 'AttachId=' + r.attachId);
    } else if (kind === 'ioctl') {
        if (r.ioControlCode != null) chips += kcChip('mono', '0x' + r.ioControlCode.toString(16).toUpperCase().padStart(8, '0'));
        if (r.requestorPid != null) chips += kcChip('', 'PID=' + r.requestorPid);
    }

    return '<div class="kc-card-header" onclick="kcToggleCard(' + i + ')">'
        + '<span class="kc-card-time">' + escHtml(time) + '</span>'
        + kindBadge + levelBadge
        + '<span class="kc-card-title">' + escHtml(title) + '</span>'
        + '<span class="kc-card-meta">' + chips + '</span>'
        + '</div>';
}

function kcChip(cls, val) {
    if (val == null || val === '') return '';
    return '<span class="kc-card-chip ' + cls + '">' + val + '</span>';
}

function kcToggleCard(i) {
    var card = document.getElementById('kccard-' + i);
    if (card) card.classList.toggle('expanded');
}

// ═══════════════════════════════════════════════════════════════
//  卡片详情体 (按 kind 分发)
// ═══════════════════════════════════════════════════════════════

function kcRenderCardBody(r, i) {
    var kind = r.kind;
    if (kind === 'driver') return kcRenderDriverBody(r, i);
    if (kind === 'iat') return kcRenderIatBody(r, i);
    if (kind === 'device') return kcRenderDeviceBody(r, i);
    if (kind === 'attach') return kcRenderAttachBody(r, i);
    if (kind === 'attach-summary') return kcRenderAttachSummaryBody(r, i);
    if (kind === 'object-scan') return kcRenderObjectScanBody(r, i);
    if (kind === 'handle-scan') return kcRenderHandleScanBody(r, i);
    if (kind === 'comms-event') return kcRenderCommsBody(r, i);
    if (kind === 'ioctl') return kcRenderIoctlBody(r, i);
    return '<pre>' + escHtml(r.dataJson || '无详情') + '</pre>';
}

// ── 驱动扫描 ──────────────────────────────────────────────────

function kcRenderDriverBody(r, i) {
    var data = kcParseDataJson(r.dataJson);
    if (!data) return kcRawJson(r.dataJson);

    var html = '<div class="kc-detail-section"><div class="kc-detail-section-title">驱动基本信息</div>';
    html += '<div class="kc-detail-kv">';
    html += kcKv('文件名', data.fileName, true);
    html += kcKv('文件路径', data.filePath, true);
    html += kcKv('驱动对象名', data.driverObjectName, true);
    html += kcKv('分类', data.klassName || kcGetClassName(data.klass));
    html += kcKv('厂商', data.vendorName);
    html += kcKv('错误原因', data.errorReason);
    html += kcKv('映像基址', data.imageBase != null ? '0x' + data.imageBase.toString(16).toUpperCase().padStart(8, '0') : null, true);
    html += kcKv('映像大小', data.imageSize != null ? kcFmtBytes(data.imageSize) : null);
    html += kcKv('加载顺序', data.loadOrderIndex);
    html += kcKv('Catalog签名', kcYesNo(data.hasCatalog));
    html += kcKv('内嵌签名', kcYesNo(data.hasEmbedded));
    html += '</div></div>';

    if (data.signers && data.signers.length > 0) {
        html += '<div class="kc-detail-section"><div class="kc-detail-section-title">签名者 (' + data.signers.length + ')</div>';
        html += '<table class="kc-detail-sub-table"><thead><tr><th>Subject</th><th>Issuer</th><th>MS</th><th>WHQL</th><th>Vendor</th></tr></thead><tbody>';
        data.signers.forEach(function (s) {
            html += '<tr>'
                + '<td>' + escHtml(s.subject || '-') + '</td>'
                + '<td>' + escHtml(s.issuer || '-') + '</td>'
                + '<td>' + kcYesNo(s.isMicrosoft) + '</td>'
                + '<td>' + kcYesNo(s.isWhql) + '</td>'
                + '<td>' + kcYesNo(s.isVendor) + '</td>'
                + '</tr>';
        });
        html += '</tbody></table></div>';
    }
    return html;
}

// ── IAT 分析 ──────────────────────────────────────────────────

function kcRenderIatBody(r, i) {
    var data = kcParseDataJson(r.dataJson);
    if (!data) return kcRawJson(r.dataJson);

    var html = '<div class="kc-detail-section"><div class="kc-detail-section-title">IAT 扫描概要</div>';
    html += '<div class="kc-detail-kv">';
    html += kcKv('文件路径', data.filePath, true);
    html += kcKv('DLL 数', data.dllCount);
    html += kcKv('API 总数', data.totalApiCount);
    html += kcKv('危险 API 数', data.dangerousApiCount, false, true);
    html += '</div></div>';

    if (data.entries && data.entries.length > 0) {
        data.entries.forEach(function (e) {
            html += '<div class="kc-detail-section"><div class="kc-detail-section-title">' + escHtml(e.dllName || '?') + ' (' + e.apiCount + ' APIs)</div>';
            html += '<table class="kc-detail-sub-table"><thead><tr><th>API 名称</th><th>危险</th></tr></thead><tbody>';
            if (e.apis) {
                e.apis.forEach(function (a) {
                    html += '<tr' + (a.isDangerous ? ' class="danger-row"' : '') + '>'
                        + '<td class="mono">' + escHtml(a.name || '?') + '</td>'
                        + '<td>' + (a.isDangerous ? '<span class="danger">是</span>' : '否') + '</td>'
                        + '</tr>';
                });
            }
            html += '</tbody></table></div>';
        });
    }
    return html;
}

// ── 设备枚举 ──────────────────────────────────────────────────

function kcRenderDeviceBody(r, i) {
    var data = kcParseDataJson(r.dataJson);
    if (!data) return kcRawJson(r.dataJson);

    var html = '<div class="kc-detail-section"><div class="kc-detail-section-title">驱动 ' + escHtml(data.driverFileName || '-') + ' 的设备列表</div>';
    if (data.devices && data.devices.length > 0) {
        html += '<table class="kc-detail-sub-table"><thead><tr>'
            + '<th>设备名</th><th>DeviceObject</th><th>DeviceType</th><th>Characteristics</th><th>Flags</th><th>AttachedCount</th><th>StackSize</th>'
            + '</tr></thead><tbody>';
        data.devices.forEach(function (d) {
            html += '<tr>'
                + '<td class="mono">' + escHtml(d.deviceName || '-') + '</td>'
                + '<td class="mono">0x' + (d.deviceObject != null ? d.deviceObject.toString(16).toUpperCase() : '-') + '</td>'
                + '<td class="mono">0x' + (d.deviceType != null ? d.deviceType.toString(16).toUpperCase() : '-') + '</td>'
                + '<td class="mono">0x' + (d.characteristics != null ? d.characteristics.toString(16).toUpperCase() : '-') + '</td>'
                + '<td class="mono">0x' + (d.flags != null ? d.flags.toString(16).toUpperCase() : '-') + '</td>'
                + '<td>' + escHtml(d.attachedCount != null ? d.attachedCount : '-') + '</td>'
                + '<td>' + escHtml(d.stackSize != null ? d.stackSize : '-') + '</td>'
                + '</tr>';
        });
        html += '</tbody></table>';
    }
    html += '</div>';
    return html;
}

// ── 附着 (单设备) ─────────────────────────────────────────────

function kcRenderAttachBody(r, i) {
    var data = kcParseDataJson(r.dataJson);
    if (!data) return kcRawJson(r.dataJson);

    var html = '<div class="kc-detail-section"><div class="kc-detail-section-title">附着结果</div>';
    html += '<div class="kc-detail-kv">';
    html += kcKv('驱动文件', data.driverFileName);
    html += kcKv('设备名', data.deviceName, true);
    html += kcKv('状态', data.status);
    html += kcKv('AttachId', data.attachId);
    html += kcKv('FilterDevice', data.filterDeviceAddr != null ? '0x' + data.filterDeviceAddr.toString(16).toUpperCase() : null, true);
    html += kcKv('LowerDevice', data.lowerDeviceAddr != null ? '0x' + data.lowerDeviceAddr.toString(16).toUpperCase() : null, true);
    html += kcKv('NewStackSize', data.newStackSize);
    html += kcKv('TargetStackSize', data.targetStackSize);
    html += '</div></div>';

    // 追溯链接: 查看该 AttachId 产生的 comms 事件
    if (data.attachId != null) {
        var commsCount = kcAllRecords.filter(function (r2) {
            return r2.kind === 'comms-event' && r2.attachId === data.attachId;
        }).length;
        if (commsCount > 0) {
            html += '<div class="kc-trace-panel">'
                + '<div class="kc-trace-panel-title"><i class="bi bi-broadcast me-1"></i>因果追溯: AttachId=' + data.attachId + ' 产生了 ' + commsCount + ' 个通信事件</div>'
                + '<span class="kc-trace-link" onclick="kcTraceComms(' + data.attachId + ')">'
                + '<i class="bi bi-arrow-right-circle"></i> 查看通信事件'
                + '</span>'
                + '</div>';
        }
    }
    return html;
}

// ── 附着列表汇总 ──────────────────────────────────────────────

function kcRenderAttachSummaryBody(r, i) {
    var data = kcParseDataJson(r.dataJson);
    if (!data) return kcRawJson(r.dataJson);

    var html = '<div class="kc-detail-section"><div class="kc-detail-section-title">附着列表 (' + (data.count || 0) + ')</div>';
    if (data.attachments && data.attachments.length > 0) {
        html += '<table class="kc-detail-sub-table"><thead><tr>'
            + '<th>FilterDevice</th><th>LowerDevice</th><th>TargetPath</th><th>AttachId</th><th>StackSize</th><th>通信事件</th>'
            + '</tr></thead><tbody>';
        data.attachments.forEach(function (a) {
            var commsCount = kcAllRecords.filter(function (r2) {
                return r2.kind === 'comms-event' && r2.attachId === a.attachId;
            }).length;
            html += '<tr>'
                + '<td class="mono">0x' + (a.filterDeviceAddr != null ? a.filterDeviceAddr.toString(16).toUpperCase() : '-') + '</td>'
                + '<td class="mono">0x' + (a.lowerDeviceAddr != null ? a.lowerDeviceAddr.toString(16).toUpperCase() : '-') + '</td>'
                + '<td class="mono">' + escHtml(a.targetPath || '-') + '</td>'
                + '<td>' + escHtml(a.attachId != null ? a.attachId : '-') + '</td>'
                + '<td>' + escHtml(a.stackSize != null ? a.stackSize : '-') + '</td>'
                + '<td>' + (commsCount > 0
                    ? '<span class="kc-trace-link" onclick="kcTraceComms(' + a.attachId + ')"><i class="bi bi-arrow-right-circle"></i> ' + commsCount + ' 事件</span>'
                    : '<span class="text-muted">-</span>') + '</td>'
                + '</tr>';
        });
        html += '</tbody></table>';
    }
    html += '</div>';
    return html;
}

// ── 对象命名空间扫描 ──────────────────────────────────────────

function kcRenderObjectScanBody(r, i) {
    var data = kcParseDataJson(r.dataJson);
    if (!data) return kcRawJson(r.dataJson);

    var html = '<div class="kc-detail-section"><div class="kc-detail-section-title">对象命名空间扫描概要</div>';
    html += '<div class="kc-detail-kv">';
    html += kcKv('扫描目录', data.directories ? data.directories.join(', ') : null, true);
    html += kcKv('总数', data.totalCount);
    html += kcKv('类型数', data.byType ? data.byType.length : 0);
    html += '</div></div>';

    if (data.byType && data.byType.length > 0) {
        html += '<div class="kc-detail-section"><div class="kc-detail-section-title">按类型聚合</div>';
        html += '<table class="kc-detail-sub-table"><thead><tr><th>TypeName</th><th>数量</th></tr></thead><tbody>';
        data.byType.forEach(function (t) {
            html += '<tr><td class="mono">' + escHtml(t.typeName || '?') + '</td><td>' + t.count + '</td></tr>';
        });
        html += '</tbody></table></div>';
    }

    if (data.entries && data.entries.length > 0) {
        html += '<div class="kc-detail-section"><div class="kc-detail-section-title">对象列表 (' + data.entries.length + ')</div>';
        html += '<table class="kc-detail-sub-table"><thead><tr><th>Name</th><th>TypeName</th><th>LinkTarget</th></tr></thead><tbody>';
        data.entries.forEach(function (e) {
            html += '<tr>'
                + '<td class="mono">' + escHtml(e.name || '-') + '</td>'
                + '<td>' + escHtml(e.typeName || '-') + '</td>'
                + '<td class="mono">' + escHtml(e.linkTarget || '-') + '</td>'
                + '</tr>';
        });
        html += '</tbody></table></div>';
    }
    return html;
}

// ── 句柄扫描 ──────────────────────────────────────────────────

function kcRenderHandleScanBody(r, i) {
    var data = kcParseDataJson(r.dataJson);
    if (!data) return kcRawJson(r.dataJson);

    var html = '<div class="kc-detail-section"><div class="kc-detail-section-title">句柄扫描概要</div>';
    html += '<div class="kc-detail-kv">';
    html += kcKv('目标 PID', data.targetPid);
    html += kcKv('进程名', data.processName);
    html += kcKv('句柄总数', data.totalCount);
    html += kcKv('高危数', data.highRiskCount, false, data.highRiskCount > 0);
    html += '</div></div>';

    if (data.byType && data.byType.length > 0) {
        html += '<div class="kc-detail-section"><div class="kc-detail-section-title">按类型聚合</div>';
        html += '<table class="kc-detail-sub-table"><thead><tr><th>TypeName</th><th>数量</th><th>高危</th></tr></thead><tbody>';
        data.byType.forEach(function (t) {
            html += '<tr>'
                + '<td class="mono">' + escHtml(t.typeName || '?') + '</td>'
                + '<td>' + t.count + '</td>'
                + '<td>' + (t.highRisk > 0 ? '<span class="danger">' + t.highRisk + '</span>' : '0') + '</td>'
                + '</tr>';
        });
        html += '</tbody></table></div>';
    }

    if (data.handles && data.handles.length > 0) {
        html += '<div class="kc-detail-section"><div class="kc-detail-section-title">句柄列表 (' + data.handles.length + ')</div>';
        html += '<table class="kc-detail-sub-table"><thead><tr>'
            + '<th>OwnerPid</th><th>OwnerName</th><th>HandleValue</th><th>GrantedAccess</th><th>AccessStr</th><th>TargetPid</th><th>TypeName</th><th>高危</th>'
            + '</tr></thead><tbody>';
        data.handles.forEach(function (h) {
            var hr = h.highRisk != null && h.highRisk !== 0;
            html += '<tr' + (hr ? ' class="danger-row"' : '') + '>'
                + '<td>' + escHtml(h.ownerPid != null ? h.ownerPid : '-') + '</td>'
                + '<td>' + escHtml(h.ownerName || '-') + '</td>'
                + '<td class="mono">0x' + (h.handleValue != null ? h.handleValue.toString(16).toUpperCase() : '-') + '</td>'
                + '<td class="mono">0x' + (h.grantedAccess != null ? h.grantedAccess.toString(16).toUpperCase() : '-') + '</td>'
                + '<td class="mono">' + escHtml(h.accessStr || '-') + '</td>'
                + '<td>' + escHtml(h.targetPid != null ? h.targetPid : '-') + '</td>'
                + '<td>' + escHtml(h.typeName || '-') + '</td>'
                + '<td>' + (hr ? '<span class="danger">是</span>' : '否') + '</td>'
                + '</tr>';
        });
        html += '</tbody></table></div>';
    }
    return html;
}

// ── 通信事件 ──────────────────────────────────────────────────

function kcRenderCommsBody(r, i) {
    var data = kcParseDataJson(r.dataJson);
    if (!data) return kcRawJson(r.dataJson);

    var html = '<div class="kc-detail-section"><div class="kc-detail-section-title">通信事件详情</div>';
    html += '<div class="kc-detail-kv">';
    html += kcKv('时间戳', data.timestamp, true);
    html += kcKv('IoControlCode', data.ioControlCode != null ? '0x' + data.ioControlCode.toString(16).toUpperCase().padStart(8, '0') : null, true);
    html += kcKv('MajorFunction', data.majorFunction != null ? '0x' + data.majorFunction.toString(16).toUpperCase() : null, true);
    html += kcKv('Method', data.method);
    html += kcKv('RequestorPid', data.requestorPid);
    html += kcKv('AttachId', data.attachId);
    html += kcKv('ProcessExe', data.processExe, true);
    html += kcKv('PayloadSize', data.payloadSize != null ? data.payloadSize + ' 字节' : null);
    html += '</div></div>';

    // 追溯: 查看该 AttachId 的附着信息
    if (data.attachId != null) {
        var attachRec = kcAllRecords.find(function (r2) {
            return r2.kind === 'attach' && r2.attachId === data.attachId;
        });
        if (attachRec) {
            var aData = kcParseDataJson(attachRec.dataJson);
            html += '<div class="kc-trace-panel">'
                + '<div class="kc-trace-panel-title"><i class="bi bi-link-45deg me-1"></i>因果追溯: AttachId=' + data.attachId + ' 的附着来源</div>'
                + '<div class="kc-detail-kv">'
                + kcKv('驱动文件', aData ? aData.driverFileName : null)
                + kcKv('设备名', aData ? aData.deviceName : null, true)
                + kcKv('FilterDevice', aData && aData.filterDeviceAddr != null ? '0x' + aData.filterDeviceAddr.toString(16).toUpperCase() : null, true)
                + '</div></div>';
        }
    }

    if (data.payloadHex) {
        html += '<div class="kc-detail-section"><div class="kc-detail-section-title">Payload (Hex)</div>';
        html += '<div class="kc-payload-hex">' + escHtml(data.payloadHex) + '</div>';
        html += '</div>';
    }

    if (data.stackModules && data.stackModules.length > 0) {
        html += '<div class="kc-detail-section"><div class="kc-detail-section-title">调用栈模块 (' + data.stackModules.length + ')</div>';
        html += '<table class="kc-detail-sub-table"><thead><tr><th>#</th><th>路径</th><th>基址</th><th>大小</th></tr></thead><tbody>';
        data.stackModules.forEach(function (m, idx) {
            html += '<tr>'
                + '<td>' + idx + '</td>'
                + '<td class="mono">' + escHtml(m.path || '-') + '</td>'
                + '<td class="mono">0x' + (m.baseAddr != null ? m.baseAddr.toString(16).toUpperCase() : '-') + '</td>'
                + '<td>' + (m.size != null ? kcFmtBytes(m.size) : '-') + '</td>'
                + '</tr>';
        });
        html += '</tbody></table></div>';
    }
    return html;
}

// ── IOCTL 拦截 ────────────────────────────────────────────────

function kcRenderIoctlBody(r, i) {
    var data = kcParseDataJson(r.dataJson);
    if (!data) return kcRawJson(r.dataJson);

    var html = '<div class="kc-detail-section"><div class="kc-detail-section-title">IOCTL 拦截详情</div>';
    html += '<div class="kc-detail-kv">';
    html += kcKv('IoControlCode', data.ioControlCode != null ? '0x' + data.ioControlCode.toString(16).toUpperCase().padStart(8, '0') : null, true);
    html += kcKv('InputBufferLength', data.inputBufferLength);
    html += kcKv('CaptureSize', data.captureSize);
    html += kcKv('RequestorPid', data.requestorPid);
    html += kcKv('TargetDevice', data.targetDeviceAddr != null ? '0x' + data.targetDeviceAddr.toString(16).toUpperCase() : null, true);
    html += kcKv('FilterDevice', data.filterDeviceAddr != null ? '0x' + data.filterDeviceAddr.toString(16).toUpperCase() : null, true);
    html += kcKv('AttachId', data.attachId);
    html += kcKv('MajorFunction', data.majorFunction != null ? '0x' + data.majorFunction.toString(16).toUpperCase() : null, true);
    html += kcKv('Method', data.method);
    html += '</div></div>';

    if (data.stackFrames && data.stackFrames.length > 0) {
        html += '<div class="kc-detail-section"><div class="kc-detail-section-title">调用栈 (' + data.stackFrames.length + ' 帧)</div>';
        html += '<table class="kc-detail-sub-table"><thead><tr><th>#</th><th>地址</th></tr></thead><tbody>';
        data.stackFrames.forEach(function (addr, idx) {
            html += '<tr><td>' + idx + '</td><td class="mono">0x' + (addr != null ? addr.toString(16).toUpperCase() : '-') + '</td></tr>';
        });
        html += '</tbody></table></div>';
    }
    return html;
}

// ═══════════════════════════════════════════════════════════════
//  attach → comms 追溯
//  点击 attach 卡片上的追溯链接, 切换到 comms 阶段并过滤该 AttachId
// ═══════════════════════════════════════════════════════════════

function kcTraceComms(attachId) {
    // 切换到 comms 阶段
    kcCurrentStage = 'comms';
    // 更新管道图高亮
    document.querySelectorAll('#kcPipeline .kc-stage').forEach(function (el) {
        el.classList.toggle('active', el.getAttribute('data-stage') === 'comms');
    });
    // 更新阶段标签
    var stageLabel = document.getElementById('kcStageLabel');
    if (stageLabel) stageLabel.textContent = '通信事件';
    // 切换过滤组
    document.querySelectorAll('.kc-filter-group').forEach(function (g) {
        g.classList.toggle('d-none', g.getAttribute('data-stage') !== 'comms');
    });
    // 设置 AttachId 过滤
    var searchEl = document.getElementById('kcCommsAttachSearch');
    if (searchEl) searchEl.value = String(attachId);
    kcRenderCards();
}

// ═══════════════════════════════════════════════════════════════
//  工具
// ═══════════════════════════════════════════════════════════════

function kcParseDataJson(json) {
    if (!json) return null;
    try { return JSON.parse(json); } catch (e) { return null; }
}

function kcGetClassName(klass) {
    return { 0: 'INBOX', 1: 'MICROSOFT', 2: 'THIRD_PARTY_WHQL', 3: 'UNTRUSTED' }[klass] || (klass != null ? 'UNKNOWN(' + klass + ')' : '-');
}

function kcYesNo(val) {
    if (val === 1 || val === true) return '是';
    if (val === 0 || val === false) return '否';
    return '-';
}

function kcKv(key, val, mono, danger) {
    if (val == null || val === '') val = '-';
    var cls = 'val';
    if (mono) cls += ' mono';
    if (danger) cls += ' danger';
    return '<div class="key">' + escHtml(key) + '</div><div class="' + cls.trim() + '">' + (mono ? val : escHtml(String(val))) + '</div>';
}

function kcRawJson(json) {
    return '<pre style="font-size:0.72rem;white-space:pre-wrap;word-break:break-all;">' + escHtml(json || '无详情') + '</pre>';
}

function kcFmtBytes(n) {
    if (n == null) return '-';
    var bytes = Number(n);
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    if (bytes < 1073741824) return (bytes / 1048576).toFixed(2) + ' MB';
    return (bytes / 1073741824).toFixed(2) + ' GB';
}
