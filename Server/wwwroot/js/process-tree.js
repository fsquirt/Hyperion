/**
 * 进程树快照 Dashboard
 * 展示 security(初始全量安全快照) + tree(后续轮询进程树)
 * - 左侧:会话列表(5s 自动刷新)
 * - 右侧顶部:快照列表(时间 / 类型徽章 / 进程数 / diff 计数)
 * - 右侧下方:按 PPID 构建树形层级,与上一次快照 diff 高亮
 *   - 新增进程:绿色背景
 *   - 消失进程:红色删除线
 */

var ptSnapshots = [];            // 按时间倒序(newest first)
var ptSelectedSnapshotId = null;
var ptKind = '';                 // '' | 'security' | 'tree'
var ptSearch = '';
var ptSearchTimer = null;
var ptProcCache = {};            // snapshotId -> 解析后的进程数组
var ptCurrentModalProc = null;   // 当前 Modal 显示的进程对象 (供 Tab 切换复用)

// 本地别名 -> 共享工具函数 (session-list.js)
var ptEsc = TrackerUtils.escHtml;
var ptFmtTime = TrackerUtils.formatTime;
var ptFmtEventTime = TrackerUtils.formatEventTime;

// 共享会话列表组件
var ptSessionList = new TrackerSessionList({
    containerId: 'ptSessionList',
    itemClass: 'pt-session-item',
    onSelect: function (id) { ptSelectSession(id); },
    autoRefreshMs: 5000
});

// 初始化:加载会话列表 + 加载 Tree 频率配置
ptSessionList.load();
ptSessionList.startAutoRefresh();
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
            const err = await res.json().catch(function() { return {}; });
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
//  会话列表 (委托给共享组件 ptSessionList)
// ═══════════════════════════════════════════════════════════════

/// 手动刷新(cshtml 刷新按钮 onclick 调用)
function ptLoadSessions() { ptSessionList.load(); }

async function ptSelectSession(id) {
    ptSelectedSnapshotId = null;
    ptProcCache = {};
    document.getElementById('ptFilterBar').classList.remove('d-none');
    await ptLoadSnapshots();
}

// ═══════════════════════════════════════════════════════════════
//  快照列表
// ═══════════════════════════════════════════════════════════════

async function ptLoadSnapshots() {
    var ptSelectedId = ptSessionList.getSelected();
    if (!ptSelectedId) return;

    var url = '/api/tracker/sessions/' + encodeURIComponent(ptSelectedId) + '/snapshots';
    if (ptKind) url += '?kind=' + encodeURIComponent(ptKind);

    var listEl = document.getElementById('ptSnapshotList');
    var wrapEl = document.getElementById('ptSnapshotListWrap');
    wrapEl.style.display = 'block';
    listEl.innerHTML = '<div class="text-center text-muted py-3">加载中...</div>';

    try {
        const res = await fetch(url);
        if (!res.ok) {
            listEl.innerHTML = '<div class="text-center text-danger py-3">加载失败</div>';
            return;
        }
        var data = await res.json();
        // 服务端已按 timestamp 倒序,这里再保险排序一次
        data.sort(function(a, b) {
            return String(b.timestamp).localeCompare(String(a.timestamp));
        });
        ptSnapshots = data;

        // 更新标题/元信息
        var sess = ptSessionList.findById(ptSelectedId);
        var meta = document.getElementById('ptDetailMeta');
        if (sess) {
            meta.textContent = ptEsc(sess.machineName) + ' · ' + (sess.status === 'active' ? '在线' : '已结束') + ' · ' + ptSnapshots.length + ' 快照';
        }
        document.getElementById('ptDetailTitle').innerHTML = '<i class="bi bi-diagram-3 me-2"></i>' + ptEsc(ptSelectedId);

        if (ptSnapshots.length === 0) {
            listEl.innerHTML = '<div class="text-center text-muted py-3"><i class="bi bi-inbox d-block mb-1"></i>暂无快照</div>';
            ptSelectedSnapshotId = null;
            ptRenderTreeEmpty('该会话暂无进程树快照');
            return;
        }

        // 保持选择(若仍存在),否则选第一条(最新)
        var stillExists = ptSnapshots.some(function(s) { return s.id === ptSelectedSnapshotId; });
        if (!stillExists) ptSelectedSnapshotId = ptSnapshots[0].id;

        ptRenderSnapshotList();
        ptRenderTree();
    } catch (e) {
        listEl.innerHTML = '<div class="text-center text-danger py-3">加载失败: ' + ptEsc(e.message) + '</div>';
    }
}

function ptRenderSnapshotList() {
    var el = document.getElementById('ptSnapshotList');
    el.innerHTML = ptSnapshots.map(function(snap, i) {
        var diff = ptSnapshotDiff(i);
        var diffHtml = '';
        if (diff) {
            diffHtml = '<span class="snap-diff">'
                + (diff.added > 0 ? '<span class="added">+' + diff.added + '</span> ' : '')
                + (diff.removed > 0 ? '<span class="removed">-' + diff.removed + '</span>' : '')
                + '</span>';
        }
        return '<div class="pt-snapshot-list-item ' + (snap.id === ptSelectedSnapshotId ? 'active' : '') + '"'
            + ' onclick="ptSelectSnapshot(\'' + ptEsc(snap.id) + '\')">'
            + '<span class="snap-time">' + ptFmtEventTime(snap.timestamp) + '</span>'
            + '<span class="snap-kind ' + ptEsc(snap.kind) + '">' + ptEsc(snap.kind) + '</span>'
            + '<span class="snap-count">' + snap.processCount + ' 进程</span>'
            + diffHtml
            + '</div>';
    }).join('');
}

/// 计算第 i 条快照相对于"上一条(时间上更早)"的 diff 计数。
/// ptSnapshots 按时间倒序,所以"上一条"= index+1。
function ptSnapshotDiff(i) {
    if (i + 1 >= ptSnapshots.length) return null; // 最旧一条,无前序
    var cur = ptParseProcesses(ptSnapshots[i]);
    var prev = ptParseProcesses(ptSnapshots[i + 1]);
    var curPids = ptPidSet(cur);
    var prevPids = ptPidSet(prev);
    var added = 0, removed = 0;
    curPids.forEach(function(p) { if (!prevPids.has(p)) added++; });
    prevPids.forEach(function(p) { if (!curPids.has(p)) removed++; });
    return { added: added, removed: removed };
}

// ═══════════════════════════════════════════════════════════════
//  快照选择 + 进程树渲染
// ═══════════════════════════════════════════════════════════════

function ptSelectSnapshot(id) {
    ptSelectedSnapshotId = id;
    ptRenderSnapshotList();
    ptRenderTree();
}

function ptRenderTreeEmpty(msg) {
    var detailEl = document.getElementById('ptEventDetail');
    detailEl.innerHTML = '<div class="text-center text-muted py-5"><i class="bi bi-cursor display-4 d-block mb-3"></i>' + ptEsc(msg) + '</div>';
    document.getElementById('ptFilterCount').textContent = '';
}

function ptRenderTree() {
    var detailEl = document.getElementById('ptEventDetail');
    var countEl = document.getElementById('ptFilterCount');

    var idx = ptSnapshots.findIndex(function(s) { return s.id === ptSelectedSnapshotId; });
    if (idx < 0) {
        ptRenderSummaryCards(null);
        ptRenderTreeEmpty('选择上方快照查看进程树');
        return;
    }

    var snap = ptSnapshots[idx];
    ptRenderSummaryCards(snap);
    var curProcs = ptParseProcesses(snap);
    // 上一条(时间更早)= index+1
    var prevProcs = (idx + 1 < ptSnapshots.length) ? ptParseProcesses(ptSnapshots[idx + 1]) : null;

    var curPids = ptPidSet(curProcs);
    var prevPids = prevProcs ? ptPidSet(prevProcs) : null;

    var addedSet = prevPids ? new Set() : null;       // 当前有,上次没有
    var removedSet = prevPids ? new Set() : null;      // 上次有,当前没有
    if (prevPids) {
        curPids.forEach(function(p) { if (!prevPids.has(p)) addedSet.add(p); });
        prevPids.forEach(function(p) { if (!curPids.has(p)) removedSet.add(p); });
    }

    // 合并:当前进程(normal/new) + 消失进程(removed)
    var merged = [];
    curProcs.forEach(function(p) {
        var st = (addedSet && addedSet.has(p.pid)) ? 'new' : 'normal';
        merged.push({ proc: p, status: st });
    });
    if (removedSet) {
        // 消失的进程来自上一条快照
        prevProcs.forEach(function(p) {
            if (removedSet.has(p.pid)) merged.push({ proc: p, status: 'removed' });
        });
    }

    // 搜索过滤(保留匹配节点 + 祖先链)
    var q = ptSearch.toLowerCase();
    var filtered = merged;
    if (q) {
        var allMap = {};
        merged.forEach(function(n) { allMap[n.proc.pid] = n; });
        var keep = new Set();
        merged.forEach(function(n) {
            if (ptMatchProc(n.proc, q)) {
                // 向上收集祖先链
                var cur = n.proc.pid;
                var guard = 0;
                while (cur != null && allMap[cur] && !keep.has(cur) && guard++ < 10000) {
                    keep.add(cur);
                    cur = allMap[cur].proc.ppid || null;
                }
            }
        });
        filtered = merged.filter(function(n) { return keep.has(n.proc.pid); });
    }

    // 构建 pid -> node 映射
    var nodeMap = {};
    filtered.forEach(function(n) {
        nodeMap[n.proc.pid] = { proc: n.proc, status: n.status, children: [] };
    });
    // 挂载 children,确定 roots
    var roots = [];
    filtered.forEach(function(n) {
        var node = nodeMap[n.proc.pid];
        var ppid = n.proc.ppid;
        if (ppid && ppid !== n.proc.pid && nodeMap[ppid]) {
            nodeMap[ppid].children.push(node);
        } else {
            roots.push(node);
        }
    });
    // 排序:PID 升序,便于定位
    var pidCmp = function(a, b) { return (a.proc.pid || 0) - (b.proc.pid || 0); };
    roots.sort(pidCmp);
    Object.keys(nodeMap).forEach(function(k) { nodeMap[k].children.sort(pidCmp); });

    // 渲染
    var html = '';
    html += '<div class="pt-tree-legend">'
        + '<span><i class="bi bi-diagram-3 me-1"></i>进程树</span>'
        + '<span><span class="dot normal"></span>普通</span>'
        + (prevPids ? '<span><span class="dot new"></span>新增</span><span><span class="dot removed"></span>消失</span>' : '<span class="text-muted">基线快照(无 diff)</span>')
        + '<span class="ms-auto text-muted">' + ptEsc(snap.kind) + ' · ' + ptFmtTime(snap.timestamp) + '</span>'
        + '</div>';
    html += '<div class="p-2"><ul class="pt-tree">';
    var visited = {};
    function renderNode(node) {
        if (visited[node.proc.pid]) return '';
        visited[node.proc.pid] = true;
        var p = node.proc;
        // 内联维度: 线程数 / 句柄数 / 工作集 / 私有内存 / Session / BasePriority / CreateTime
        var meta = (p.threads != null ? '<span class="nmeta">' + p.threads + ' 线程</span>' : '');
        var hdls = (p.handles != null ? '<span class="nmeta"><i class="bi bi-key"></i> ' + p.handles + '</span>' : '');
        var ws = (p.workingSet != null && p.workingSet !== 0 ? '<span class="nmeta">' + ptFmtBytes(p.workingSet) + '</span>' : '');
        var pp = (p.privatePages != null && p.privatePages !== 0 ? '<span class="nmeta">' + ptFmtBytes(p.privatePages) + '</span>' : '');
        var sess = (p.session != null ? '<span class="nsession">Session ' + ptEsc(p.session) + '</span>' : '');
        var prio = (p.basePriority != null ? '<span class="nmeta">P' + ptEsc(p.basePriority) + '</span>' : '');
        var ct = (p.createTime ? '<span class="nmeta"><i class="bi bi-clock"></i> ' + ptFmtTime(p.createTime) + '</span>' : '');
        var cls = node.status === 'new' ? ' new' : (node.status === 'removed' ? ' removed' : '');
        var clickAttr = ' onclick="ptShowProcDetail(' + p.pid + ')" style="cursor:pointer"';
        var hint = '<span class="click-hint"><i class="bi bi-zoom-in"></i> 详情</span>';
        var html = '<li class="pt-tree-node"><div class="pt-tree-node-content' + cls + '"' + clickAttr + '>'
            + '<span class="npid">PID ' + ptEsc(p.pid) + '</span>'
            + '<span class="nname">' + ptEsc(p.name || '(unknown)') + '</span>'
            + meta + hdls + ws + pp + sess + prio + ct + hint
            + '</div>';
        if (node.children.length > 0) {
            html += '<ul>';
            node.children.forEach(function(c) { html += renderNode(c); });
            html += '</ul>';
        }
        html += '</li>';
        return html;
    }
    roots.forEach(function(r) { html += renderNode(r); });
    html += '</ul></div>';

    detailEl.innerHTML = html;

    var shown = filtered.length;
    var total = merged.length;
    countEl.textContent = q ? ('显示 ' + shown + ' / ' + total + ' 进程') : (total + ' 进程');
}

// ═══════════════════════════════════════════════════════════════
//  过滤 / 搜索
// ═══════════════════════════════════════════════════════════════

function ptSetKind(btn) {
    ptKind = btn.getAttribute('data-kind');
    document.querySelectorAll('#ptKindFilter .btn').forEach(function(b) { b.classList.remove('active'); });
    btn.classList.add('active');
    ptProcCache = {};
    ptLoadSnapshots();
}

function ptOnSearch() {
    clearTimeout(ptSearchTimer);
    ptSearchTimer = setTimeout(function() {
        ptSearch = document.getElementById('ptSearch').value.trim();
        ptRenderTree();
    }, 200);
}

function ptClearSearch() {
    document.getElementById('ptSearch').value = '';
    ptSearch = '';
    ptRenderTree();
}

// ═══════════════════════════════════════════════════════════════
//  工具 (escHtml/formatTime/formatEventTime 已委托给 TrackerUtils,见文件头部别名)
// ═══════════════════════════════════════════════════════════════

function ptTruncate(s, max) {
    if (!s || s.length <= max) return s;
    return s.substring(0, max) + '\n... (截断)';
}

/// 解析快照 processesJson,带缓存。
function ptParseProcesses(snap) {
    if (!snap) return [];
    if (ptProcCache[snap.id]) return ptProcCache[snap.id];
    var arr = [];
    try {
        arr = JSON.parse(snap.processesJson || '[]') || [];
        // 归一化数值字段(便于集合对比/排序/格式化)
        for (var i = 0; i < arr.length; i++) {
            var p = arr[i] || {};
            if (p.pid != null) p.pid = Number(p.pid);
            if (p.ppid != null) p.ppid = Number(p.ppid);
            if (p.threads != null) p.threads = Number(p.threads);
            if (p.session != null) p.session = Number(p.session);
            if (p.handles != null) p.handles = Number(p.handles);
            if (p.workingSet != null) p.workingSet = Number(p.workingSet);
            if (p.privatePages != null) p.privatePages = Number(p.privatePages);
            if (p.basePriority != null) p.basePriority = Number(p.basePriority);
        }
    } catch (e) {
        arr = [];
    }
    ptProcCache[snap.id] = arr;
    return arr;
}

function ptPidSet(procs) {
    var s = new Set();
    for (var i = 0; i < procs.length; i++) {
        if (procs[i] && procs[i].pid != null) s.add(procs[i].pid);
    }
    return s;
}

function ptMatchProc(proc, q) {
    if (!q) return true;
    var name = String(proc.name || '').toLowerCase();
    var pid = String(proc.pid || '');
    var handles = String(proc.handles || '');
    var session = String(proc.session || '');
    return name.indexOf(q) >= 0 || pid.indexOf(q) >= 0
        || handles.indexOf(q) >= 0 || session.indexOf(q) >= 0;
}

// ═══════════════════════════════════════════════════════════════
//  辅助: 地址/字节格式化
// ═══════════════════════════════════════════════════════════════

function ptFmtAddr(n) {
    if (n == null || n === 0) return '0x0';
    return '0x' + Number(n).toString(16).toUpperCase();
}

function ptFmtBytes(n) {
    if (n == null) return '-';
    var b = Number(n);
    if (b < 1024) return b + ' B';
    if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
    if (b < 1073741824) return (b / 1048576).toFixed(2) + ' MB';
    return (b / 1073741824).toFixed(2) + ' GB';
}

/// 判断进程对象是否来自 security 快照(含安全详情字段)
function ptIsSecurityProc(p) {
    return !!(p && Array.isArray(p.threadInfos));
}

// ═══════════════════════════════════════════════════════════════
//  汇总卡片
// ═══════════════════════════════════════════════════════════════

function ptRenderSummaryCards(snap) {
    var box = document.getElementById('ptSummaryCards');
    if (!snap) {
        if (box) box.classList.add('d-none');
        return;
    }
    box.classList.remove('d-none');
    // 第一行: 安全维度
    document.getElementById('ptStatPpl').textContent = snap.pplBrokenCount || 0;
    document.getElementById('ptStatMem').textContent = snap.suspiciousMemCount || 0;
    document.getElementById('ptStatHandle').textContent = snap.highRiskHandleCount || 0;
    document.getElementById('ptStatProc').textContent = snap.processCount || 0;

    // 第二行: Tree 汇总统计 (Category C)
    document.getElementById('ptStatTotalThreads').textContent = snap.totalThreads != null ? snap.totalThreads : '-';
    document.getElementById('ptStatMaxThreads').textContent = snap.maxThreadsInSingleProc != null ? snap.maxThreadsInSingleProc : '-';
    document.getElementById('ptStatTopPid').textContent = snap.topPidByThreads != null ? snap.topPidByThreads : '-';
    document.getElementById('ptStatTotalWS').textContent = snap.totalWorkingSet != null ? ptFmtBytes(snap.totalWorkingSet) : '-';
    document.getElementById('ptStatTotalPP').textContent = snap.totalPrivatePages != null ? ptFmtBytes(snap.totalPrivatePages) : '-';
    document.getElementById('ptStatTotalHandles').textContent = snap.totalHandles != null ? snap.totalHandles : '-';
}

// ═══════════════════════════════════════════════════════════════
//  进程详情 Modal
// ═══════════════════════════════════════════════════════════════

function ptShowProcDetail(pid) {
    var idx = ptSnapshots.findIndex(function(s) { return s.id === ptSelectedSnapshotId; });
    if (idx < 0) return;

    var snap = ptSnapshots[idx];
    var procs = ptParseProcesses(snap);
    var p = procs.filter(function(x) { return x.pid === pid; })[0];

    // removed 节点: 当前快照找不到时, 从上一条快照查找
    if (!p && idx + 1 < ptSnapshots.length) {
        var prevProcs = ptParseProcesses(ptSnapshots[idx + 1]);
        p = prevProcs.filter(function(x) { return x.pid === pid; })[0];
    }
    if (!p) return;

    document.getElementById('ptModalTitle').textContent =
        '进程详情 · ' + (p.name || '(unknown)') + ' · PID ' + pid;

    ptCurrentModalProc = p;
    ptSetModalTab('basic');

    bootstrap.Modal.getOrCreateInstance(document.getElementById('ptProcDetailModal')).show();
}

function ptSetModalTab(tab) {
    document.querySelectorAll('#ptModalTabNav .nav-link').forEach(function(a) {
        a.classList.toggle('active', a.getAttribute('data-mtab') === tab);
    });
    var p = ptCurrentModalProc;
    var html = '';
    if (tab === 'basic')         html = ptRenderModalBasic(p);
    else if (tab === 'threads')  html = ptRenderModalThreads(p);
    else if (tab === 'modules')  html = ptRenderModalModules(p);
    else if (tab === 'memory')   html = ptRenderModalMemory(p);
    else if (tab === 'handles')  html = ptRenderModalHandles(p);
    document.getElementById('ptModalTabContent').innerHTML = html;
}

// ── 基本信息 Tab ───────────────────────────────────────────────

function ptRenderModalBasic(p) {
    if (!p) return '<div class="pt-modal-empty">无数据</div>';
    var isSec = ptIsSecurityProc(p);
    var rows = '';
    rows += ptKvRow('PID', ptEsc(p.pid), true);
    rows += ptKvRow('PPID', ptEsc(p.ppid), true);
    rows += ptKvRow('进程名', ptEsc(p.name || '-'));
    rows += ptKvRow('线程数', ptEsc(p.threads != null ? p.threads : '-'));
    rows += ptKvRow('Session', ptEsc(p.session != null ? p.session : '-'), true);
    rows += ptKvRow('句柄数', ptEsc(p.handles != null ? p.handles : '-'));
    rows += ptKvRow('BasePriority', ptEsc(p.basePriority != null ? p.basePriority : '-'));
    rows += ptKvRow('WorkingSet', ptFmtBytes(p.workingSet), true);
    rows += ptKvRow('PrivatePages', ptFmtBytes(p.privatePages), true);
    rows += ptKvRow('CreateTime', ptEsc(p.createTime != null ? p.createTime : '-'), true);

    if (isSec) {
        rows += ptKvRow('ImagePath', ptEsc(p.image || '-'));
        rows += ptKvRow('CommandLine', ptEsc(p.cmd || '-'));
        rows += ptKvRow('Protection', ptEsc(p.protection || '-'));
        rows += ptKvRow('PPL Broken', ptEsc(p.pplBroken ? '是' : '否'), true);
    }

    var html = '<div class="pt-modal-kv">' + rows + '</div>';

    // 特权区 (仅 security 快照)
    if (isSec) {
        html += ptRenderPrivSection(p.enabledPrivs, p.disabledPrivs);
    }

    // tree 快照提示
    if (!isSec) {
        html += '<div class="pt-modal-empty mt-3"><i class="bi bi-info-circle me-1"></i>'
              + '该快照为 tree 模式, 仅含 Brief 字段。'
              + '查看 ImagePath/CommandLine/Protection/特权等安全详情请切换 security 快照。'
              + '</div>';
    }

    return html;
}

function ptKvRow(key, val, mono) {
    var cls = mono ? ' val mono' : ' val';
    return '<div class="key">' + ptEsc(key) + '</div><div class="' + cls.trim() + '">' + val + '</div>';
}

function ptRenderPrivSection(enabled, disabled) {
    var html = '<div class="pt-priv-section">'
        + '<div class="priv-title">特权 (Token Privileges)</div>';

    if (enabled && enabled.length > 0) {
        html += '<div class="mb-1"><span class="text-muted small">已启用 (' + enabled.length + '):</span> ';
        for (var i = 0; i < enabled.length; i++) {
            html += '<span class="priv-badge priv-enabled">' + ptEsc(enabled[i]) + '</span>';
        }
        html += '</div>';
    }

    if (disabled && disabled.length > 0) {
        html += '<div class="mb-1"><span class="text-muted small">已禁用 (' + disabled.length + '):</span> ';
        for (var j = 0; j < disabled.length; j++) {
            html += '<span class="priv-badge priv-disabled">' + ptEsc(disabled[j]) + '</span>';
        }
        html += '</div>';
    }

    if ((!enabled || enabled.length === 0) && (!disabled || disabled.length === 0)) {
        html += '<div class="text-muted small">无特权信息</div>';
    }

    html += '</div>';
    return html;
}

// ── 线程 Tab ───────────────────────────────────────────────────

function ptRenderModalThreads(p) {
    if (!p) return '<div class="pt-modal-empty">无数据</div>';

    // security 快照: threadInfos[] (含 Win32StartAddress)
    if (ptIsSecurityProc(p)) {
        var tis = p.threadInfos || [];
        if (tis.length === 0) return '<div class="pt-modal-empty">无线程信息</div>';

        var rows = '';
        for (var i = 0; i < tis.length; i++) {
            var t = tis[i];
            var mismatch = (t.win32StartAddress != null && t.win32StartAddress !== 0
                && t.startAddress != null
                && Number(t.win32StartAddress) !== Number(t.startAddress));
            var cls = mismatch ? ' pt-win32-mismatch' : '';
            var flag = mismatch ? '<span class="mismatch-flag">不匹配</span>' : '';
            rows += '<tr class="' + cls.trim() + '">'
                + '<td class="mono">' + ptEsc(t.tid) + '</td>'
                + '<td class="mono">' + ptFmtAddr(t.startAddress) + '</td>'
                + '<td class="mono">' + ptFmtAddr(t.win32StartAddress) + flag + '</td>'
                + '<td>' + ptEsc(t.suspendCount != null ? t.suspendCount : '-') + '</td>'
                + '<td>' + ptEsc(t.startModule || '-') + '</td>'
                + '<td>' + (t.isSuspended ? '是' : '否') + '</td>'
                + '</tr>';
        }

        return '<div class="mb-2"><span class="badge bg-danger">安全维度: Win32StartAddress ≠ StartAddress = 手动映射 shellcode</span></div>'
            + '<table class="pt-modal-tab-table"><thead><tr>'
            + '<th>TID</th><th>StartAddress</th><th>Win32StartAddress</th>'
            + '<th>SuspendCount</th><th>StartModule</th><th>Suspended</th>'
            + '</tr></thead><tbody>' + rows + '</tbody></table>';
    }

    // tree 快照: threadList[] (仅 tid/startAddress)
    var tl = p.threadList || [];
    if (tl.length === 0) return '<div class="pt-modal-empty">无线程信息</div>';

    var trows = '';
    for (var k = 0; k < tl.length; k++) {
        var th = tl[k];
        trows += '<tr>'
            + '<td class="mono">' + ptEsc(th.tid) + '</td>'
            + '<td class="mono">' + ptFmtAddr(th.startAddress) + '</td>'
            + '</tr>';
    }

    return '<div class="alert alert-info py-1 small"><i class="bi bi-info-circle me-1"></i>'
        + 'tree 模式仅含 TID/StartAddress。查看 Win32StartAddress(检测 manual-map shellcode) 请切换 security 快照。'
        + '</div>'
        + '<table class="pt-modal-tab-table"><thead><tr>'
        + '<th>TID</th><th>StartAddress</th>'
        + '</tr></thead><tbody>' + trows + '</tbody></table>';
}

// ── 模块 Tab ───────────────────────────────────────────────────

function ptRenderModalModules(p) {
    if (!p) return '<div class="pt-modal-empty">无数据</div>';
    if (!ptIsSecurityProc(p)) {
        return '<div class="pt-modal-empty"><i class="bi bi-info-circle me-1"></i>'
            + '该快照为 tree 模式, 无模块详情数据。请查看 security 快照。'
            + '</div>';
    }

    var mods = p.modules || [];
    if (mods.length === 0) return '<div class="pt-modal-empty">无模块信息</div>';

    var rows = '';
    for (var i = 0; i < mods.length; i++) {
        var m = mods[i];
        rows += '<tr>'
            + '<td class="mono">' + ptFmtAddr(m.baseAddr) + '</td>'
            + '<td class="mono">' + ptFmtBytes(m.size) + '</td>'
            + '<td>' + ptEsc(m.name || '-') + '</td>'
            + '<td>' + ptEsc(m.path || '-') + '</td>'
            + '</tr>';
    }

    return '<table class="pt-modal-tab-table"><thead><tr>'
        + '<th>Base</th><th>Size</th><th>Name</th><th>Path</th>'
        + '</tr></thead><tbody>' + rows + '</tbody></table>';
}

// ── 内存区域 Tab ───────────────────────────────────────────────

function ptRenderModalMemory(p) {
    if (!p) return '<div class="pt-modal-empty">无数据</div>';
    if (!ptIsSecurityProc(p)) {
        return '<div class="pt-modal-empty"><i class="bi bi-info-circle me-1"></i>'
            + '该快照为 tree 模式, 无内存区域数据。请查看 security 快照。'
            + '</div>';
    }

    var regs = p.memRegions || [];
    if (regs.length === 0) return '<div class="pt-modal-empty">无可疑内存区域</div>';

    var rows = '';
    for (var i = 0; i < regs.length; i++) {
        var r = regs[i];
        var suspicious = r.reason && String(r.reason).length > 0;
        var cls = suspicious ? ' pt-mem-suspicious' : '';
        var reasonBadge = suspicious
            ? '<span class="reason-badge">' + ptEsc(r.reason) + '</span>'
            : '-';
        rows += '<tr class="' + cls.trim() + '">'
            + '<td class="mono">' + ptFmtAddr(r.baseAddr) + '</td>'
            + '<td class="mono">' + ptFmtBytes(r.size) + '</td>'
            + '<td>' + ptEsc(r.protectStr || '-') + '</td>'
            + '<td>' + ptEsc(r.typeStr || '-') + '</td>'
            + '<td>' + reasonBadge + '</td>'
            + '</tr>';
    }

    return '<div class="mb-2"><span class="badge bg-danger">安全维度: Reason 非空 = RWX/RX-unbacked 可疑内存</span></div>'
        + '<table class="pt-modal-tab-table"><thead><tr>'
        + '<th>Base</th><th>Size</th><th>Protect</th><th>Type</th><th>Reason</th>'
        + '</tr></thead><tbody>' + rows + '</tbody></table>';
}

// ── 句柄 Tab ───────────────────────────────────────────────────

function ptRenderModalHandles(p) {
    if (!p) return '<div class="pt-modal-empty">无数据</div>';
    if (!ptIsSecurityProc(p)) {
        return '<div class="pt-modal-empty"><i class="bi bi-info-circle me-1"></i>'
            + '该快照为 tree 模式, 无句柄详情数据。请查看 security 快照。'
            + '</div>';
    }

    var hdls = p.extHandles || [];
    if (hdls.length === 0) return '<div class="pt-modal-empty">无句柄信息</div>';

    var rows = '';
    for (var i = 0; i < hdls.length; i++) {
        var h = hdls[i];
        var highRisk = h.highRisk && h.highRisk !== 0;
        var cls = highRisk ? ' pt-handle-highrisk' : '';
        var riskBadge = highRisk ? '<span class="highrisk-badge">高危</span>' : '-';
        rows += '<tr class="' + cls.trim() + '">'
            + '<td class="mono">' + ptEsc(h.ownerPid != null ? h.ownerPid : '-') + '</td>'
            + '<td>' + ptEsc(h.ownerName || '-') + '</td>'
            + '<td class="mono">' + ptFmtAddr(h.handleValue) + '</td>'
            + '<td>' + ptEsc(h.grantedAccess != null ? '0x' + Number(h.grantedAccess).toString(16).toUpperCase() : '-') + '</td>'
            + '<td>' + ptEsc(h.accessStr || '-') + '</td>'
            + '<td class="mono">' + ptEsc(h.targetPid != null ? h.targetPid : '-') + '</td>'
            + '<td>' + ptEsc(h.typeName || '-') + '</td>'
            + '<td>' + riskBadge + '</td>'
            + '</tr>';
    }

    return '<div class="mb-2"><span class="badge bg-danger">安全维度: HighRisk = 跨进程高危句柄</span></div>'
        + '<table class="pt-modal-tab-table"><thead><tr>'
        + '<th>OwnerPID</th><th>OwnerName</th><th>Handle</th>'
        + '<th>GrantedAccess</th><th>AccessStr</th><th>TargetPID</th>'
        + '<th>Type</th><th>HighRisk</th>'
        + '</tr></thead><tbody>' + rows + '</tbody></table>';
}
