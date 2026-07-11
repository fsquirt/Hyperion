/**
 * 进程树快照 Dashboard
 * 展示 security(初始全量安全快照) + tree(后续轮询进程树)
 * - 左侧:会话列表(5s 自动刷新)
 * - 右侧顶部:快照列表(时间 / 类型徽章 / 进程数 / diff 计数)
 * - 右侧下方:按 PPID 构建树形层级,与上一次快照 diff 高亮
 *   - 新增进程:绿色背景
 *   - 消失进程:红色删除线
 */

var ptSessions = [];
var ptSelectedId = null;
var ptSnapshots = [];            // 按时间倒序(newest first)
var ptSelectedSnapshotId = null;
var ptKind = '';                 // '' | 'security' | 'tree'
var ptSearch = '';
var ptSearchTimer = null;
var ptProcCache = {};            // snapshotId -> 解析后的进程数组

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
    el.innerHTML = ptSessions.map(function(s) {
        return '<div class="list-group-item pt-session-item ' + (s.id === ptSelectedId ? 'active' : '') + '"'
            + ' onclick="ptSelectSession(\'' + ptEsc(s.id) + '\')">'
            + '<div class="d-flex justify-content-between align-items-start">'
            + '<div>'
            + '<span class="session-status ' + ptEsc(s.status) + '"></span>'
            + '<strong class="text-dark">' + ptEsc(s.id) + '</strong>'
            + '<div class="text-muted small mt-1">' + ptEsc(s.machineName) + ' · PID ' + s.pid + ' · ' + ptFmtTime(s.startedAt) + '</div>'
            + '</div>'
            + '<div class="text-end">'
            + '<span class="badge ' + (s.status === 'active' ? 'badge-pass' : 'bg-secondary') + '">' + (s.status === 'active' ? '在线' : '已结束') + '</span>'
            + '<div class="text-muted small mt-1">' + s.eventCount + ' 事件</div>'
            + '</div>'
            + '</div></div>';
    }).join('');
}

async function ptSelectSession(id) {
    ptSelectedId = id;
    ptSelectedSnapshotId = null;
    ptProcCache = {};
    ptRenderSessionList();
    document.getElementById('ptFilterBar').classList.remove('d-none');
    await ptLoadSnapshots();
}

// ═══════════════════════════════════════════════════════════════
//  快照列表
// ═══════════════════════════════════════════════════════════════

async function ptLoadSnapshots() {
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
        var sess = ptSessions.filter(function(s) { return s.id === ptSelectedId; })[0];
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
        ptRenderTreeEmpty('选择上方快照查看进程树');
        return;
    }

    var snap = ptSnapshots[idx];
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
        var meta = (p.threads != null ? '<span class="nmeta">' + p.threads + ' 线程</span>' : '');
        var sess = (p.session != null ? '<span class="nsession">Session ' + ptEsc(p.session) + '</span>' : '');
        var cls = node.status === 'new' ? ' new' : (node.status === 'removed' ? ' removed' : '');
        var html = '<li class="pt-tree-node"><div class="pt-tree-node-content' + cls + '">'
            + '<span class="npid">PID ' + ptEsc(p.pid) + '</span>'
            + '<span class="nname">' + ptEsc(p.name || '(unknown)') + '</span>'
            + meta + sess
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
//  工具
// ═══════════════════════════════════════════════════════════════

function ptEsc(s) {
    if (s == null) return '';
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

/// 解析快照 processesJson,带缓存。
function ptParseProcesses(snap) {
    if (!snap) return [];
    if (ptProcCache[snap.id]) return ptProcCache[snap.id];
    var arr = [];
    try {
        arr = JSON.parse(snap.processesJson || '[]') || [];
        // 归一化 pid/ppid 为数字(便于集合对比与排序)
        for (var i = 0; i < arr.length; i++) {
            var p = arr[i] || {};
            if (p.pid != null) p.pid = Number(p.pid);
            if (p.ppid != null) p.ppid = Number(p.ppid);
            if (p.threads != null) p.threads = Number(p.threads);
            if (p.session != null) p.session = Number(p.session);
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
    return name.indexOf(q) >= 0 || pid.indexOf(q) >= 0;
}
