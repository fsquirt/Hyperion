/**
 * 内核通信记录 Dashboard — 7 Tab 因果链视图
 *
 * 因果链顺序 (从上游到下游):
 *   1. driver   — 驱动扫描 (扫描已加载驱动 + 签名分类 + 映像信息)
 *   2. iat      — IAT 分析 (THIRD_PARTY 驱动的危险 API)
 *   3. device   — 设备枚举 (驱动暴露的设备对象)
 *   4. attach   — 附着 (单设备附着结果 + 附着列表汇总)
 *   5. object   — 对象/句柄 (NT 目录对象扫描 + 句柄扫描)
 *   6. comms    — 通信事件 (被附着设备的 per-event IOCTL 通信)
 *   7. ioctl    — IOCTL 拦截 (抓包式 IOCTL 监听)
 *
 * 数据加载策略: 一次加载全部 kind, 前端按 Tab 分组显示
 * kind 取值: driver | iat | device | attach | attach-summary | object-scan | handle-scan | comms-event | ioctl
 */

var kcAllRecords = [];         // 全部 kernel-comms 记录
var kcCurrentTab = 'driver';   // 当前 Tab
var kcFilterTimer = null;

var kcConfig = {
    treePollIntervalSec: 10,
    ioctlEnabled: false,
    dumpMode: 'mini',
    fileCopyEnabled: true
};

// 本地别名 -> 共享工具函数 (session-list.js)
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
//  配置 (IOCTL 监听开关)
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
//  会话列表 (委托给共享组件 kcSessionList)
// ═══════════════════════════════════════════════════════════════

function kcLoadSessions() { kcSessionList.load(); }

async function kcSelectSession(id) {
    document.getElementById('kcTabBar').classList.remove('d-none');
    document.getElementById('kcFilterBar').classList.remove('d-none');
    await kcLoadEvents();
}

// ═══════════════════════════════════════════════════════════════
//  加载全部 kernel-comms 记录
//  GET /api/tracker/sessions/{id}/kernel-comms (不加 kind, 一次加载全部)
// ═══════════════════════════════════════════════════════════════

async function kcLoadEvents() {
    var kcSelectedId = kcSessionList.getSelected();
    if (!kcSelectedId) return;

    var detailEl = document.getElementById('kcEventDetail');
    if (detailEl) detailEl.innerHTML = '<div class="text-center text-muted py-4">加载中...</div>';

    try {
        var url = '/api/tracker/sessions/' + encodeURIComponent(kcSelectedId) + '/kernel-comms';
        var res = await fetch(url);
        if (!res.ok) {
            if (detailEl) detailEl.innerHTML = '<div class="text-center text-danger py-4">加载失败</div>';
            return;
        }
        kcAllRecords = await res.json() || [];

        // 按 Tab 分组计数 (7 个 Tab, 对应因果链 7 段)
        var counts = { driver: 0, iat: 0, device: 0, attach: 0, object: 0, comms: 0, ioctl: 0 };
        kcAllRecords.forEach(function (r) {
            var k = r.kind;
            if (k === 'driver') counts.driver++;
            else if (k === 'iat') counts.iat++;
            else if (k === 'device') counts.device++;
            else if (k === 'attach' || k === 'attach-summary') counts.attach++;
            else if (k === 'object-scan' || k === 'handle-scan') counts.object++;
            else if (k === 'comms-event') counts.comms++;
            else if (k === 'ioctl') counts.ioctl++;
        });
        document.getElementById('kcCountDriver').textContent = counts.driver;
        document.getElementById('kcCountIat').textContent = counts.iat;
        document.getElementById('kcCountDevice').textContent = counts.device;
        document.getElementById('kcCountAttach').textContent = counts.attach;
        document.getElementById('kcCountObject').textContent = counts.object;
        document.getElementById('kcCountComms').textContent = counts.comms;
        document.getElementById('kcCountIoctl').textContent = counts.ioctl;

        var titleEl = document.getElementById('kcDetailTitle');
        var metaEl = document.getElementById('kcDetailMeta');
        if (titleEl) titleEl.innerHTML = '<i class="bi bi-hdd-network me-2"></i>' + escHtml(kcSelectedId);
        if (metaEl) metaEl.textContent = kcAllRecords.length + ' 条记录';

        kcRenderTable();
    } catch (e) {
        if (detailEl) detailEl.innerHTML = '<div class="text-center text-danger py-4">加载失败: ' + escHtml(e.message) + '</div>';
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tab 切换
// ═══════════════════════════════════════════════════════════════

function kcSetTab(tab) {
    kcCurrentTab = tab;
    document.querySelectorAll('#kcTabNav .nav-link').forEach(function (a) {
        a.classList.toggle('active', a.getAttribute('data-tab') === tab);
    });
    document.querySelectorAll('.kc-filter-group').forEach(function (g) {
        g.classList.toggle('d-none', g.getAttribute('data-tab') !== tab);
    });
    kcRenderTable();
}

// ═══════════════════════════════════════════════════════════════
//  筛选 + 渲染
// ═══════════════════════════════════════════════════════════════

function kcOnFilterChange() {
    clearTimeout(kcFilterTimer);
    kcFilterTimer = setTimeout(kcRenderTable, 200);
}

// 按 Tab 选取记录并应用筛选
function kcGetFilteredRecords() {
    var tab = kcCurrentTab;
    var records;

    if (tab === 'driver') {
        records = kcAllRecords.filter(function (r) { return r.kind === 'driver'; });
    } else if (tab === 'iat') {
        records = kcAllRecords.filter(function (r) { return r.kind === 'iat'; });
    } else if (tab === 'device') {
        records = kcAllRecords.filter(function (r) { return r.kind === 'device'; });
    } else if (tab === 'attach') {
        records = kcAllRecords.filter(function (r) { return r.kind === 'attach' || r.kind === 'attach-summary'; });
    } else if (tab === 'object') {
        records = kcAllRecords.filter(function (r) { return r.kind === 'object-scan' || r.kind === 'handle-scan'; });
    } else if (tab === 'comms') {
        records = kcAllRecords.filter(function (r) { return r.kind === 'comms-event'; });
    } else if (tab === 'ioctl') {
        records = kcAllRecords.filter(function (r) { return r.kind === 'ioctl'; });
    } else {
        records = [];
    }

    // 按 Tab 应用特定筛选
    if (tab === 'driver') {
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
    } else if (tab === 'iat') {
        var iatSearch = (document.getElementById('kcIatDriverSearch').value || '').toLowerCase();
        if (iatSearch) {
            records = records.filter(function (r) { return (r.driverFileName || '').toLowerCase().indexOf(iatSearch) >= 0; });
        }
    } else if (tab === 'device') {
        var devSearch = (document.getElementById('kcDeviceNameSearch').value || '').toLowerCase();
        if (devSearch) {
            records = records.filter(function (r) {
                return (r.deviceName || '').toLowerCase().indexOf(devSearch) >= 0 ||
                       (r.driverFileName || '').toLowerCase().indexOf(devSearch) >= 0;
            });
        }
    } else if (tab === 'attach') {
        var attachIdSearch = (document.getElementById('kcAttachIdSearch').value || '').toLowerCase();
        var attachDevSearch = (document.getElementById('kcAttachDeviceSearch').value || '').toLowerCase();
        if (attachIdSearch) {
            records = records.filter(function (r) { return String(r.attachId || '').indexOf(attachIdSearch) >= 0; });
        }
        if (attachDevSearch) {
            records = records.filter(function (r) {
                return (r.deviceName || '').toLowerCase().indexOf(attachDevSearch) >= 0;
            });
        }
    } else if (tab === 'object') {
        var typeSearch = (document.getElementById('kcTypeNameSearch').value || '').toLowerCase();
        var highRiskOnly = document.getElementById('kcHighRiskOnly').checked;
        if (typeSearch) {
            // 在 DataJson.entries/handles 里按 typeName 搜索
            records = records.filter(function (r) {
                var data = kcParseDataJson(r.dataJson);
                if (!data) return false;
                var list = data.entries || data.handles || [];
                return list.some(function (e) { return (e.typeName || '').toLowerCase().indexOf(typeSearch) >= 0; });
            });
        }
        if (highRiskOnly) {
            // 只保留有 highRiskCount>0 的 handle-scan 记录
            records = records.filter(function (r) {
                if (r.kind !== 'handle-scan') return false;
                var data = kcParseDataJson(r.dataJson);
                return data && data.highRiskCount > 0;
            });
        }
    } else if (tab === 'comms') {
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
    } else if (tab === 'ioctl') {
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

function kcRenderTable() {
    var detailEl = document.getElementById('kcEventDetail');
    var countEl = document.getElementById('kcFilterCount');
    if (!detailEl) return;

    var records = kcGetFilteredRecords();

    if (countEl) {
        var totalForTab = kcGetTabTotal(kcCurrentTab);
        countEl.textContent = records.length < totalForTab ? '显示 ' + records.length + ' / ' + totalForTab + ' 条' : '';
    }

    if (records.length === 0) {
        detailEl.innerHTML = '<div class="text-center text-muted py-5"><i class="bi bi-inbox display-4 d-block mb-2"></i>暂无' + kcGetTabName(kcCurrentTab) + '记录</div>';
        return;
    }

    if (kcCurrentTab === 'driver') {
        detailEl.innerHTML = kcRenderDriverTable(records);
    } else if (kcCurrentTab === 'iat') {
        detailEl.innerHTML = kcRenderIatTable(records);
    } else if (kcCurrentTab === 'device') {
        detailEl.innerHTML = kcRenderDeviceTable(records);
    } else if (kcCurrentTab === 'attach') {
        detailEl.innerHTML = kcRenderAttachTable(records);
    } else if (kcCurrentTab === 'object') {
        detailEl.innerHTML = kcRenderObjectTable(records);
    } else if (kcCurrentTab === 'comms') {
        detailEl.innerHTML = kcRenderCommsTable(records);
    } else if (kcCurrentTab === 'ioctl') {
        detailEl.innerHTML = kcRenderIoctlTable(records);
    }
}

function kcGetTabTotal(tab) {
    if (tab === 'attach') {
        return kcAllRecords.filter(function (r) { return r.kind === 'attach' || r.kind === 'attach-summary'; }).length;
    }
    if (tab === 'object') {
        return kcAllRecords.filter(function (r) { return r.kind === 'object-scan' || r.kind === 'handle-scan'; }).length;
    }
    return kcAllRecords.filter(function (r) { return r.kind === tab; }).length;
}

function kcGetTabName(tab) {
    return {
        driver: '驱动扫描',
        iat: 'IAT',
        device: '设备枚举',
        attach: '附着',
        object: '对象/句柄',
        comms: '通信事件',
        ioctl: 'IOCTL拦截'
    }[tab] || '';
}

// ═══════════════════════════════════════════════════════════════
//  Tab 1: 驱动扫描表格
//  含 Category A 维度: ImageBase / ImageSize / LoadOrderIndex
// ═══════════════════════════════════════════════════════════════

function kcRenderDriverTable(records) {
    var html = '<table class="kc-table"><thead><tr>'
        + '<th>时间</th><th>文件名</th><th>分类</th><th>厂商</th><th>映像基址</th><th>映像大小</th><th>加载顺序</th><th>签名</th><th>级别</th>'
        + '</tr></thead><tbody>';
    records.forEach(function (r, i) {
        var className = kcGetClassName(r.driverClass);
        var imgBase = r.imageBase != null ? '0x' + r.imageBase.toString(16).toUpperCase().padStart(8, '0') : '-';
        var imgSize = r.imageSize != null ? kcFmtBytes(r.imageSize) : '-';
        var loadOrder = r.loadOrderIndex != null ? r.loadOrderIndex : '-';
        var sig = kcYesNo(r.hasCatalog) + '/' + kcYesNo(r.hasEmbedded);
        html += '<tr onclick="kcToggleDetail(' + i + ')">'
            + '<td class="mono">' + formatEventTime(r.timestamp) + '</td>'
            + '<td>' + escHtml(r.driverFileName || '-') + '</td>'
            + '<td><span class="kc-badge driver-class-' + (r.driverClass != null ? r.driverClass : '-') + '">' + escHtml(className) + '</span></td>'
            + '<td>' + escHtml(r.vendorName || '-') + '</td>'
            + '<td class="mono">' + imgBase + '</td>'
            + '<td>' + imgSize + '</td>'
            + '<td>' + loadOrder + '</td>'
            + '<td class="text-center">' + sig + '</td>'
            + '<td><span class="kc-badge level-' + escHtml(r.level || 'INFO') + '">' + escHtml(r.level || 'INFO') + '</span></td>'
            + '</tr>';
        html += '<tr><td colspan="9" style="padding:0;">'
            + '<div class="kc-detail-panel" id="kcdetail-' + i + '">' + kcRenderDriverDetail(r) + '</div>'
            + '</td></tr>';
    });
    html += '</tbody></table>';
    return html;
}

function kcRenderDriverDetail(r) {
    var data = kcParseDataJson(r.dataJson);
    if (!data) return '<pre>' + escHtml(r.dataJson || '无详情') + '</pre>';

    var html = '<div class="detail-section"><div class="detail-section-title">驱动基本信息</div>';
    html += '<div class="detail-kv">';
    html += '<span class="key">文件名</span><span class="val">' + escHtml(data.fileName || '-') + '</span>';
    html += '<span class="key">文件路径</span><span class="val mono">' + escHtml(data.filePath || '-') + '</span>';
    html += '<span class="key">驱动对象名</span><span class="val mono">' + escHtml(data.driverObjectName || '-') + '</span>';
    html += '<span class="key">分类</span><span class="val">' + escHtml(data.klassName || kcGetClassName(data.klass)) + '</span>';
    html += '<span class="key">厂商</span><span class="val">' + escHtml(data.vendorName || '-') + '</span>';
    html += '<span class="key">错误原因</span><span class="val">' + escHtml(data.errorReason || '-') + '</span>';
    // Category A: 映像信息 (之前 FFI 丢失)
    html += '<span class="key">映像基址</span><span class="val mono">0x' + (data.imageBase != null ? data.imageBase.toString(16).toUpperCase().padStart(8, '0') : '-') + '</span>';
    html += '<span class="key">映像大小</span><span class="val">' + (data.imageSize != null ? kcFmtBytes(data.imageSize) : '-') + '</span>';
    html += '<span class="key">加载顺序索引</span><span class="val">' + escHtml(data.loadOrderIndex != null ? data.loadOrderIndex : '-') + '</span>';
    html += '</div></div>';

    if (data.signers && data.signers.length > 0) {
        html += '<div class="detail-section"><div class="detail-section-title">签名者 (' + data.signers.length + ')</div>';
        html += '<table class="detail-sub-table"><thead><tr><th>Subject</th><th>Issuer</th><th>MS</th><th>WHQL</th><th>Vendor</th></tr></thead><tbody>';
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

// ═══════════════════════════════════════════════════════════════
//  Tab 2: IAT 危险函数表格
// ═══════════════════════════════════════════════════════════════

function kcRenderIatTable(records) {
    var html = '<table class="kc-table"><thead><tr>'
        + '<th>时间</th><th>驱动文件</th><th>危险 API 数</th><th>总 API 数</th><th>DLL 数</th>'
        + '</tr></thead><tbody>';
    records.forEach(function (r, i) {
        var data = kcParseDataJson(r.dataJson);
        var totalApi = data ? data.totalApiCount : '-';
        var dllCount = data ? data.dllCount : '-';
        html += '<tr onclick="kcToggleDetail(' + i + ')">'
            + '<td class="mono">' + formatEventTime(r.timestamp) + '</td>'
            + '<td>' + escHtml(r.driverFileName || '-') + '</td>'
            + '<td><span class="kc-badge danger-count">' + (r.dangerousApiCount || 0) + ' 个</span></td>'
            + '<td>' + escHtml(totalApi) + '</td>'
            + '<td>' + escHtml(dllCount) + '</td>'
            + '</tr>';
        html += '<tr><td colspan="5" style="padding:0;">'
            + '<div class="kc-detail-panel" id="kcdetail-' + i + '">' + kcRenderIatDetail(r) + '</div>'
            + '</td></tr>';
    });
    html += '</tbody></table>';
    return html;
}

function kcRenderIatDetail(r) {
    var data = kcParseDataJson(r.dataJson);
    if (!data) return '<pre>' + escHtml(r.dataJson || '无详情') + '</pre>';

    var html = '<div class="detail-section"><div class="detail-section-title">IAT 扫描概要</div>';
    html += '<div class="detail-kv">';
    html += '<span class="key">文件路径</span><span class="val mono">' + escHtml(data.filePath || '-') + '</span>';
    html += '<span class="key">DLL 数</span><span class="val">' + escHtml(data.dllCount || 0) + '</span>';
    html += '<span class="key">API 总数</span><span class="val">' + escHtml(data.totalApiCount || 0) + '</span>';
    html += '<span class="key">危险 API 数</span><span class="val" style="color:#dc2626;font-weight:600;">' + escHtml(data.dangerousApiCount || 0) + '</span>';
    html += '</div></div>';

    if (data.entries && data.entries.length > 0) {
        data.entries.forEach(function (e) {
            html += '<div class="detail-section"><div class="detail-section-title">' + escHtml(e.dllName || '?') + ' (' + e.apiCount + ' APIs)</div>';
            html += '<table class="detail-sub-table"><thead><tr><th>API 名称</th><th>危险</th></tr></thead><tbody>';
            if (e.apis) {
                e.apis.forEach(function (a) {
                    html += '<tr>'
                        + '<td class="mono">' + escHtml(a.name || '?') + '</td>'
                        + '<td>' + (a.isDangerous ? '<span class="danger">是</span>' : '<span class="kc-no">否</span>') + '</td>'
                        + '</tr>';
                });
            }
            html += '</tbody></table></div>';
        });
    }
    return html;
}

// ═══════════════════════════════════════════════════════════════
//  Tab 3: 设备枚举表格 (只 kind=device)
// ═══════════════════════════════════════════════════════════════

function kcRenderDeviceTable(records) {
    var html = '<table class="kc-table"><thead><tr>'
        + '<th>时间</th><th>驱动文件</th><th>设备数</th>'
        + '</tr></thead><tbody>';
    records.forEach(function (r, i) {
        var data = kcParseDataJson(r.dataJson);
        var devCount = (data && data.devices) ? data.devices.length : '-';
        html += '<tr onclick="kcToggleDetail(' + i + ')">'
            + '<td class="mono">' + formatEventTime(r.timestamp) + '</td>'
            + '<td>' + escHtml(r.driverFileName || (data && data.driverFileName) || '-') + '</td>'
            + '<td>' + devCount + '</td>'
            + '</tr>';
        html += '<tr><td colspan="3" style="padding:0;">'
            + '<div class="kc-detail-panel" id="kcdetail-' + i + '">' + kcRenderDeviceDetail(r) + '</div>'
            + '</td></tr>';
    });
    html += '</tbody></table>';
    return html;
}

function kcRenderDeviceDetail(r) {
    var data = kcParseDataJson(r.dataJson);
    if (!data) return '<pre>' + escHtml(r.dataJson || '无详情') + '</pre>';

    var html = '<div class="detail-section"><div class="detail-section-title">驱动 ' + escHtml(data.driverFileName || '-') + ' 的设备列表</div>';
    if (data.devices && data.devices.length > 0) {
        // Category C: 之前 UI 丢弃的设备维度 (Characteristics/Flags/DeviceType/AttachedCount/StackSize)
        html += '<table class="detail-sub-table"><thead><tr>'
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

// ═══════════════════════════════════════════════════════════════
//  Tab 4: 附着表格 (kind=attach + kind=attach-summary)
//  - kind=attach: 单设备附着结果
//  - kind=attach-summary: 附着列表汇总 (Category B 之前从不上报)
// ═══════════════════════════════════════════════════════════════

function kcRenderAttachTable(records) {
    var html = '<table class="kc-table"><thead><tr>'
        + '<th>时间</th><th>类型</th><th>设备名/路径</th><th>AttachId</th><th>FilterDevice</th><th>LowerDevice</th><th>StackSize</th>'
        + '</tr></thead><tbody>';
    records.forEach(function (r, i) {
        var isSummary = r.kind === 'attach-summary';
        var data = kcParseDataJson(r.dataJson);
        if (isSummary) {
            // 汇总行: 显示 count + 第一个 attachment 概要
            var count = data ? data.count : '-';
            html += '<tr onclick="kcToggleDetail(' + i + ')">'
                + '<td class="mono">' + formatEventTime(r.timestamp) + '</td>'
                + '<td><span class="kc-badge kind-attach-summary">汇总</span></td>'
                + '<td colspan="2">共 ' + count + ' 个附着</td>'
                + '<td colspan="3" class="text-muted small">展开查看完整附着列表</td>'
                + '</tr>';
        } else {
            var devName = r.deviceName || (data && data.deviceName) || '-';
            var stackSize = data ? (data.newStackSize != null ? data.newStackSize : '-') : '-';
            html += '<tr onclick="kcToggleDetail(' + i + ')">'
                + '<td class="mono">' + formatEventTime(r.timestamp) + '</td>'
                + '<td><span class="kc-badge kind-attach">附着</span></td>'
                + '<td class="mono">' + escHtml(devName) + '</td>'
                + '<td>' + (r.attachId != null ? escHtml(r.attachId) : '-') + '</td>'
                + '<td class="mono">' + (r.filterDeviceAddr != null ? '0x' + r.filterDeviceAddr.toString(16).toUpperCase() : '-') + '</td>'
                + '<td class="mono">' + (data && data.lowerDeviceAddr != null ? '0x' + data.lowerDeviceAddr.toString(16).toUpperCase() : '-') + '</td>'
                + '<td>' + stackSize + '</td>'
                + '</tr>';
        }
        html += '<tr><td colspan="7" style="padding:0;">'
            + '<div class="kc-detail-panel" id="kcdetail-' + i + '">' + kcRenderAttachDetail(r) + '</div>'
            + '</td></tr>';
    });
    html += '</tbody></table>';
    return html;
}

function kcRenderAttachDetail(r) {
    var data = kcParseDataJson(r.dataJson);
    if (!data) return '<pre>' + escHtml(r.dataJson || '无详情') + '</pre>';

    if (r.kind === 'attach-summary') {
        // 附着列表汇总详情: 显示完整 attachments[]
        var html = '<div class="detail-section"><div class="detail-section-title">附着列表 (' + (data.count || 0) + ')</div>';
        if (data.attachments && data.attachments.length > 0) {
            html += '<table class="detail-sub-table"><thead><tr>'
                + '<th>FilterDevice</th><th>LowerDevice</th><th>TargetPath</th><th>AttachId</th><th>StackSize</th>'
                + '</tr></thead><tbody>';
            data.attachments.forEach(function (a) {
                html += '<tr>'
                    + '<td class="mono">0x' + (a.filterDeviceAddr != null ? a.filterDeviceAddr.toString(16).toUpperCase() : '-') + '</td>'
                    + '<td class="mono">0x' + (a.lowerDeviceAddr != null ? a.lowerDeviceAddr.toString(16).toUpperCase() : '-') + '</td>'
                    + '<td class="mono">' + escHtml(a.targetPath || '-') + '</td>'
                    + '<td>' + escHtml(a.attachId != null ? a.attachId : '-') + '</td>'
                    + '<td>' + escHtml(a.stackSize != null ? a.stackSize : '-') + '</td>'
                    + '</tr>';
            });
            html += '</tbody></table>';
        }
        html += '</div>';
        return html;
    }

    // 单设备附着详情
    var html2 = '<div class="detail-section"><div class="detail-section-title">附着结果</div>';
    html2 += '<div class="detail-kv">';
    html2 += '<span class="key">驱动文件</span><span class="val">' + escHtml(data.driverFileName || '-') + '</span>';
    html2 += '<span class="key">设备名</span><span class="val mono">' + escHtml(data.deviceName || '-') + '</span>';
    html2 += '<span class="key">状态</span><span class="val">' + escHtml(data.status != null ? data.status : '-') + '</span>';
    html2 += '<span class="key">AttachId</span><span class="val">' + escHtml(data.attachId != null ? data.attachId : '-') + '</span>';
    html2 += '<span class="key">FilterDevice</span><span class="val mono">0x' + (data.filterDeviceAddr != null ? data.filterDeviceAddr.toString(16).toUpperCase() : '-') + '</span>';
    html2 += '<span class="key">LowerDevice</span><span class="val mono">0x' + (data.lowerDeviceAddr != null ? data.lowerDeviceAddr.toString(16).toUpperCase() : '-') + '</span>';
    html2 += '<span class="key">NewStackSize</span><span class="val">' + escHtml(data.newStackSize != null ? data.newStackSize : '-') + '</span>';
    html2 += '<span class="key">TargetStackSize</span><span class="val">' + escHtml(data.targetStackSize != null ? data.targetStackSize : '-') + '</span>';
    html2 += '</div></div>';
    return html2;
}

// ═══════════════════════════════════════════════════════════════
//  Tab 5: 对象/句柄表格 (kind=object-scan + kind=handle-scan)
//  - object-scan: NT 目录对象扫描 (Category B 之前 UserService 从不调用)
//  - handle-scan: 句柄扫描 (Category B 之前 UserService 从不调用)
// ═══════════════════════════════════════════════════════════════

function kcRenderObjectTable(records) {
    var html = '<table class="kc-table"><thead><tr>'
        + '<th>时间</th><th>类型</th><th>标题</th><th>总数</th><th>高危数</th><th>类型数</th>'
        + '</tr></thead><tbody>';
    records.forEach(function (r, i) {
        var data = kcParseDataJson(r.dataJson);
        var isHandle = r.kind === 'handle-scan';
        var total = data ? (data.totalCount || 0) : '-';
        var highRisk = isHandle && data ? (data.highRiskCount || 0) : '-';
        var typeCount = data && data.byType ? data.byType.length : '-';
        var badge = isHandle
            ? '<span class="kc-badge kind-handle-scan">句柄</span>'
            : '<span class="kc-badge kind-object-scan">对象</span>';
        var highRiskCell = isHandle
            ? (highRisk > 0 ? '<span class="kc-badge danger-count">' + highRisk + '</span>' : '0')
            : '-';
        html += '<tr onclick="kcToggleDetail(' + i + ')">'
            + '<td class="mono">' + formatEventTime(r.timestamp) + '</td>'
            + '<td>' + badge + '</td>'
            + '<td>' + escHtml(r.title || (data && data.title) || '-') + '</td>'
            + '<td>' + total + '</td>'
            + '<td>' + highRiskCell + '</td>'
            + '<td>' + typeCount + '</td>'
            + '</tr>';
        html += '<tr><td colspan="6" style="padding:0;">'
            + '<div class="kc-detail-panel" id="kcdetail-' + i + '">' + kcRenderObjectDetail(r) + '</div>'
            + '</td></tr>';
    });
    html += '</tbody></table>';
    return html;
}

function kcRenderObjectDetail(r) {
    var data = kcParseDataJson(r.dataJson);
    if (!data) return '<pre>' + escHtml(r.dataJson || '无详情') + '</pre>';

    if (r.kind === 'handle-scan') {
        return kcRenderHandleScanDetail(data);
    }
    return kcRenderObjectScanDetail(data);
}

function kcRenderObjectScanDetail(data) {
    var html = '<div class="detail-section"><div class="detail-section-title">对象命名空间扫描概要</div>';
    html += '<div class="detail-kv">';
    html += '<span class="key">扫描目录</span><span class="val mono">' + (data.directories ? escHtml(data.directories.join(', ')) : '-') + '</span>';
    html += '<span class="key">总数</span><span class="val">' + escHtml(data.totalCount || 0) + '</span>';
    html += '<span class="key">类型数</span><span class="val">' + (data.byType ? data.byType.length : 0) + '</span>';
    html += '</div></div>';

    if (data.byType && data.byType.length > 0) {
        html += '<div class="detail-section"><div class="detail-section-title">按类型聚合</div>';
        html += '<table class="detail-sub-table"><thead><tr><th>TypeName</th><th>数量</th></tr></thead><tbody>';
        data.byType.forEach(function (t) {
            html += '<tr><td class="mono">' + escHtml(t.typeName || '?') + '</td><td>' + t.count + '</td></tr>';
        });
        html += '</tbody></table></div>';
    }

    if (data.entries && data.entries.length > 0) {
        html += '<div class="detail-section"><div class="detail-section-title">对象列表 (' + data.entries.length + ')</div>';
        html += '<table class="detail-sub-table"><thead><tr><th>Name</th><th>TypeName</th><th>LinkTarget</th></tr></thead><tbody>';
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

function kcRenderHandleScanDetail(data) {
    var html = '<div class="detail-section"><div class="detail-section-title">句柄扫描概要</div>';
    html += '<div class="detail-kv">';
    html += '<span class="key">目标 PID</span><span class="val">' + escHtml(data.targetPid != null ? data.targetPid : '-') + '</span>';
    html += '<span class="key">进程名</span><span class="val">' + escHtml(data.processName || '-') + '</span>';
    html += '<span class="key">句柄总数</span><span class="val">' + escHtml(data.totalCount || 0) + '</span>';
    html += '<span class="key">高危数</span><span class="val" style="color:#dc2626;font-weight:600;">' + escHtml(data.highRiskCount || 0) + '</span>';
    html += '</div></div>';

    if (data.byType && data.byType.length > 0) {
        html += '<div class="detail-section"><div class="detail-section-title">按类型聚合</div>';
        html += '<table class="detail-sub-table"><thead><tr><th>TypeName</th><th>数量</th><th>高危</th></tr></thead><tbody>';
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
        html += '<div class="detail-section"><div class="detail-section-title">句柄列表 (' + data.handles.length + ')</div>';
        // Category C: 之前 UI 丢弃的全维度 (GrantedAccess/AccessStr/TargetPid/TypeName/HighRisk)
        html += '<table class="detail-sub-table"><thead><tr>'
            + '<th>OwnerPid</th><th>OwnerName</th><th>HandleValue</th><th>GrantedAccess</th><th>AccessStr</th><th>TargetPid</th><th>TypeName</th><th>高危</th>'
            + '</tr></thead><tbody>';
        data.handles.forEach(function (h) {
            var hr = h.highRisk != null && h.highRisk !== 0;
            html += '<tr' + (hr ? ' style="background:rgba(220,38,38,0.05);"' : '') + '>'
                + '<td>' + escHtml(h.ownerPid != null ? h.ownerPid : '-') + '</td>'
                + '<td>' + escHtml(h.ownerName || '-') + '</td>'
                + '<td class="mono">0x' + (h.handleValue != null ? h.handleValue.toString(16).toUpperCase() : '-') + '</td>'
                + '<td class="mono">0x' + (h.grantedAccess != null ? h.grantedAccess.toString(16).toUpperCase() : '-') + '</td>'
                + '<td class="mono">' + escHtml(h.accessStr || '-') + '</td>'
                + '<td>' + escHtml(h.targetPid != null ? h.targetPid : '-') + '</td>'
                + '<td>' + escHtml(h.typeName || '-') + '</td>'
                + '<td>' + (hr ? '<span class="danger">是</span>' : '<span class="kc-no">否</span>') + '</td>'
                + '</tr>';
        });
        html += '</tbody></table></div>';
    }
    return html;
}

// ═══════════════════════════════════════════════════════════════
//  Tab 6: 通信事件表格 (kind=comms-event, per-event 实时投递)
//  含全维度: ioControlCode/majorFunction/method/requestorPid/attachId/processExe/stackModules[]/payloadHex
// ═══════════════════════════════════════════════════════════════

function kcRenderCommsTable(records) {
    var html = '<table class="kc-table"><thead><tr>'
        + '<th>时间</th><th>PID</th><th>进程</th><th>IoControlCode</th><th>Major</th><th>Method</th><th>AttachId</th><th>Payload</th><th>栈模块</th>'
        + '</tr></thead><tbody>';
    records.forEach(function (r, i) {
        var data = kcParseDataJson(r.dataJson);
        var processExe = (data && data.processExe) || '-';
        var stackCount = (data && data.stackModules) ? data.stackModules.length : (r.stackModuleCount || 0);
        var payloadSize = (data && data.payloadSize != null) ? data.payloadSize : (r.payloadSize || 0);
        html += '<tr onclick="kcToggleDetail(' + i + ')">'
            + '<td class="mono">' + formatEventTime(r.timestamp) + '</td>'
            + '<td>' + (r.requestorPid != null ? escHtml(r.requestorPid) : '-') + '</td>'
            + '<td>' + escHtml(processExe) + '</td>'
            + '<td class="mono">0x' + (r.ioControlCode != null ? r.ioControlCode.toString(16).toUpperCase().padStart(8, '0') : '-') + '</td>'
            + '<td class="mono">0x' + (r.majorFunction != null ? r.majorFunction.toString(16).toUpperCase() : '-') + '</td>'
            + '<td>' + (r.method != null ? escHtml(r.method) : '-') + '</td>'
            + '<td>' + (r.attachId != null ? escHtml(r.attachId) : '-') + '</td>'
            + '<td class="mono">' + payloadSize + ' 字节</td>'
            + '<td>' + stackCount + '</td>'
            + '</tr>';
        html += '<tr><td colspan="9" style="padding:0;">'
            + '<div class="kc-detail-panel" id="kcdetail-' + i + '">' + kcRenderCommsDetail(r) + '</div>'
            + '</td></tr>';
    });
    html += '</tbody></table>';
    return html;
}

function kcRenderCommsDetail(r) {
    var data = kcParseDataJson(r.dataJson);
    if (!data) return '<pre>' + escHtml(r.dataJson || '无详情') + '</pre>';

    var html = '<div class="detail-section"><div class="detail-section-title">通信事件详情</div>';
    html += '<div class="detail-kv">';
    html += '<span class="key">时间戳</span><span class="val mono">' + escHtml(data.timestamp != null ? data.timestamp : '-') + '</span>';
    html += '<span class="key">IoControlCode</span><span class="val mono">0x' + (data.ioControlCode != null ? data.ioControlCode.toString(16).toUpperCase().padStart(8, '0') : '-') + '</span>';
    html += '<span class="key">MajorFunction</span><span class="val mono">0x' + (data.majorFunction != null ? data.majorFunction.toString(16).toUpperCase() : '-') + '</span>';
    html += '<span class="key">Method</span><span class="val">' + escHtml(data.method != null ? data.method : '-') + '</span>';
    html += '<span class="key">RequestorPid</span><span class="val">' + escHtml(data.requestorPid != null ? data.requestorPid : '-') + '</span>';
    html += '<span class="key">AttachId</span><span class="val">' + escHtml(data.attachId != null ? data.attachId : '-') + '</span>';
    html += '<span class="key">ProcessExe</span><span class="val mono">' + escHtml(data.processExe || '-') + '</span>';
    html += '<span class="key">PayloadSize</span><span class="val">' + escHtml(data.payloadSize != null ? data.payloadSize : '-') + ' 字节</span>';
    html += '</div></div>';

    // Payload hex
    if (data.payloadHex) {
        html += '<div class="detail-section"><div class="detail-section-title">Payload (Hex)</div>';
        html += '<pre style="background:#1a1a1a;color:#0f0;padding:0.5rem;font-size:0.75rem;word-break:break-all;">' + escHtml(data.payloadHex) + '</pre>';
        html += '</div>';
    }

    // Stack modules
    if (data.stackModules && data.stackModules.length > 0) {
        html += '<div class="detail-section"><div class="detail-section-title">调用栈模块 (' + data.stackModules.length + ')</div>';
        html += '<table class="detail-sub-table"><thead><tr><th>#</th><th>路径</th><th>基址</th><th>大小</th></tr></thead><tbody>';
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

// ═══════════════════════════════════════════════════════════════
//  Tab 7: IOCTL 拦截表格 (抓包式)
// ═══════════════════════════════════════════════════════════════

function kcRenderIoctlTable(records) {
    var html = '<table class="kc-table"><thead><tr>'
        + '<th>时间</th><th>IoControlCode</th><th>RequestorPid</th><th>AttachId</th><th>MajorFunction</th><th>级别</th>'
        + '</tr></thead><tbody>';
    records.forEach(function (r, i) {
        html += '<tr onclick="kcToggleDetail(' + i + ')">'
            + '<td class="mono">' + formatEventTime(r.timestamp) + '</td>'
            + '<td class="mono">0x' + (r.ioControlCode != null ? r.ioControlCode.toString(16).toUpperCase().padStart(8, '0') : '-') + '</td>'
            + '<td>' + escHtml(r.requestorPid != null ? r.requestorPid : '-') + '</td>'
            + '<td>' + escHtml(r.attachId != null ? r.attachId : '-') + '</td>'
            + '<td class="mono">0x' + (r.majorFunction != null ? r.majorFunction.toString(16).toUpperCase() : '-') + '</td>'
            + '<td><span class="kc-badge level-' + escHtml(r.level || 'HIGH') + '">' + escHtml(r.level || 'HIGH') + '</span></td>'
            + '</tr>';
        html += '<tr><td colspan="6" style="padding:0;">'
            + '<div class="kc-detail-panel" id="kcdetail-' + i + '">' + kcRenderIoctlDetail(r) + '</div>'
            + '</td></tr>';
    });
    html += '</tbody></table>';
    return html;
}

function kcRenderIoctlDetail(r) {
    var data = kcParseDataJson(r.dataJson);
    if (!data) return '<pre>' + escHtml(r.dataJson || '无详情') + '</pre>';

    var html = '<div class="detail-section"><div class="detail-section-title">IOCTL 拦截详情</div>';
    html += '<div class="detail-kv">';
    html += '<span class="key">IoControlCode</span><span class="val mono">0x' + (data.ioControlCode != null ? data.ioControlCode.toString(16).toUpperCase().padStart(8, '0') : '-') + '</span>';
    html += '<span class="key">InputBufferLength</span><span class="val">' + escHtml(data.inputBufferLength != null ? data.inputBufferLength : '-') + '</span>';
    html += '<span class="key">CaptureSize</span><span class="val">' + escHtml(data.captureSize != null ? data.captureSize : '-') + '</span>';
    html += '<span class="key">RequestorPid</span><span class="val">' + escHtml(data.requestorPid != null ? data.requestorPid : '-') + '</span>';
    html += '<span class="key">TargetDevice</span><span class="val mono">0x' + (data.targetDeviceAddr != null ? data.targetDeviceAddr.toString(16).toUpperCase() : '-') + '</span>';
    html += '<span class="key">FilterDevice</span><span class="val mono">0x' + (data.filterDeviceAddr != null ? data.filterDeviceAddr.toString(16).toUpperCase() : '-') + '</span>';
    html += '<span class="key">AttachId</span><span class="val">' + escHtml(data.attachId != null ? data.attachId : '-') + '</span>';
    html += '<span class="key">MajorFunction</span><span class="val mono">0x' + (data.majorFunction != null ? data.majorFunction.toString(16).toUpperCase() : '-') + '</span>';
    html += '<span class="key">Method</span><span class="val">' + escHtml(data.method != null ? data.method : '-') + '</span>';
    html += '</div></div>';

    if (data.stackFrames && data.stackFrames.length > 0) {
        html += '<div class="detail-section"><div class="detail-section-title">调用栈 (' + data.stackFrames.length + ' 帧)</div>';
        html += '<table class="detail-sub-table"><thead><tr><th>#</th><th>地址</th></tr></thead><tbody>';
        data.stackFrames.forEach(function (addr, idx) {
            html += '<tr><td>' + idx + '</td><td class="mono">0x' + (addr != null ? addr.toString(16).toUpperCase() : '-') + '</td></tr>';
        });
        html += '</tbody></table></div>';
    }
    return html;
}

// ═══════════════════════════════════════════════════════════════
//  工具
// ═══════════════════════════════════════════════════════════════

function kcToggleDetail(i) {
    var el = document.getElementById('kcdetail-' + i);
    if (el) el.classList.toggle('open');
}

function kcParseDataJson(json) {
    if (!json) return null;
    try { return JSON.parse(json); } catch (e) { return null; }
}

function kcGetClassName(klass) {
    return { 0: 'INBOX', 1: 'MICROSOFT', 2: 'THIRD_PARTY_WHQL', 3: 'UNTRUSTED' }[klass] || (klass != null ? 'UNKNOWN(' + klass + ')' : '-');
}

function kcYesNo(val) {
    if (val === 1 || val === true) return '<span class="kc-yes"><i class="bi bi-check-lg"></i></span>';
    if (val === 0 || val === false) return '<span class="kc-no"><i class="bi bi-dash"></i></span>';
    return '<span class="kc-no">-</span>';
}

// 字节格式化 (KB/MB/GB)
function kcFmtBytes(n) {
    if (n == null) return '-';
    var bytes = Number(n);
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    if (bytes < 1024 * 1024 * 1024) return (bytes / 1024 / 1024).toFixed(2) + ' MB';
    return (bytes / 1024 / 1024 / 1024).toFixed(2) + ' GB';
}
