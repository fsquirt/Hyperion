/**
 * 进程树快照 Dashboard — 文本树 (仿 SuperUserService tree 命令)
 *
 * 骨架 (vs 事件追踪 UI 的根本区别):
 *   1. 主视图是 ASCII 文本树 (├── └── 缩进), 不是列表/图形
 *   2. 快照选择用 sparkline 趋势曲线, 不是滑块/列表
 *   3. 节点详情用雷达图 (五轴同图), 不是 tab 串行切换
 *   4. 全维度平铺显示 (PID/线程/句柄/WS/私有页/优先级), 不靠编码切换
 *   5. 异常清单在底部聚焦, 不是全量列表
 *   6. diff 用行级着色 + 标签 (新增/消失/变化), 不是图形拓扑
 *
 * 交互:
 *   - 点击行: 选中 + 右侧雷达图
 *   - 点击 sparkline 上的点: 切换快照
 *   - 点击异常清单 chip: 滚动到对应行并高亮
 */

// ═══════════════════════════════════════════════════════════════
//  状态
// ═══════════════════════════════════════════════════════════════

var ptSnapshots = [];               // 按时间倒序 (newest first)
var ptSelectedSnapshotId = null;
var ptKind = '';                    // '' | 'security' | 'tree'
var ptSearch = '';
var ptSearchTimer = null;
var ptProcCache = {};               // snapshotId -> 解析后的进程数组
var ptSelectedNodePid = null;       // 当前选中的节点 PID
var ptMaxDims = {};                 // 当前快照各维度最大值 (用于雷达图归一化)

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

// 初始化
ptSessionList.load();
ptSessionList.startAutoRefresh();

// ═══════════════════════════════════════════════════════════════
//  会话列表 (委托给共享组件)
// ═══════════════════════════════════════════════════════════════

function ptLoadSessions() { ptSessionList.load(); }

async function ptSelectSession(id) {
    ptSelectedSnapshotId = null;
    ptProcCache = {};
    ptSelectedNodePid = null;
    ptClearRadar();
    document.getElementById('ptSparklineWrap').classList.remove('d-none');
    await ptLoadSnapshots();
}

// ═══════════════════════════════════════════════════════════════
//  快照加载
// ═══════════════════════════════════════════════════════════════

async function ptLoadSnapshots() {
    var ptSelectedId = ptSessionList.getSelected();
    if (!ptSelectedId) return;

    var url = '/api/tracker/sessions/' + encodeURIComponent(ptSelectedId) + '/snapshots';
    if (ptKind) url += '?kind=' + encodeURIComponent(ptKind);

    try {
        var res = await fetch(url);
        if (!res.ok) {
            ptRenderGraphEmpty('加载失败');
            return;
        }
        var data = await res.json();
        data.sort(function (a, b) {
            return String(b.timestamp).localeCompare(String(a.timestamp));
        });
        ptSnapshots = data;

        var sess = ptSessionList.findById(ptSelectedId);
        var metaEl = document.getElementById('ptDetailTitle');
        if (sess) {
            metaEl.innerHTML = '<i class="bi bi-diagram-3 me-1"></i>' + ptEsc(ptSelectedId)
                + ' <span class="text-muted fw-normal">' + ptEsc(sess.machineName) + ' · '
                + (sess.status === 'active' ? '在线' : '已结束') + ' · ' + ptSnapshots.length + ' 快照</span>';
        }

        if (ptSnapshots.length === 0) {
            ptRenderGraphEmpty('该会话暂无进程树快照');
            document.getElementById('ptSparklineWrap').classList.add('d-none');
            return;
        }

        // 保持选择, 否则选第一条 (最新)
        var stillExists = ptSnapshots.some(function (s) { return s.id === ptSelectedSnapshotId; });
        if (!stillExists) ptSelectedSnapshotId = ptSnapshots[0].id;

        ptRenderSparklines();
        ptRenderGraph();
    } catch (e) {
        ptRenderGraphEmpty('加载失败: ' + e.message);
    }
}

// ═══════════════════════════════════════════════════════════════
//  Sparkline 快照选择器 (3 条趋势曲线, 点击曲线上的点切快照)
// ═══════════════════════════════════════════════════════════════

function ptRenderSparklines() {
    if (ptSnapshots.length === 0) return;

    // 时间正序 (oldest first) 用于 sparkline
    var chrono = ptSnapshots.slice().reverse();

    ptDrawSparkline('ptSparkThreads',
        chrono.map(function (s) { return s.totalThreads || 0; }),
        chrono,
        function (v) { return String(v); });
    ptDrawSparkline('ptSparkMem',
        chrono.map(function (s) { return s.totalWorkingSet || 0; }),
        chrono,
        function (v) { return ptFmtBytes(v); });
    ptDrawSparkline('ptSparkHandles',
        chrono.map(function (s) { return s.totalHandles || 0; }),
        chrono,
        function (v) { return String(v); });
}

function ptDrawSparkline(svgId, values, chrono, fmtLabel) {
    var svgEl = document.getElementById(svgId);
    if (!svgEl) return;
    var svg = d3.select('#' + svgId);
    svg.selectAll('*').remove();

    var w = svgEl.clientWidth || 250;
    var h = 48;
    svg.attr('viewBox', '0 0 ' + w + ' ' + h);

    var max = Math.max.apply(null, values.concat([1]));
    var min = Math.min.apply(null, values.concat([0]));
    var range = max - min || 1;
    var pad = 6;
    var n = values.length;

    var xScale = function (i) { return pad + (n <= 1 ? 0 : (i / (n - 1)) * (w - 2 * pad)); };
    var yScale = function (v) { return h - pad - ((v - min) / range) * (h - 2 * pad); };

    // Area path
    var areaPath = 'M ' + xScale(0) + ' ' + (h - pad);
    for (var i = 0; i < n; i++) {
        areaPath += ' L ' + xScale(i) + ' ' + yScale(values[i]);
    }
    areaPath += ' L ' + xScale(n - 1) + ' ' + (h - pad) + ' Z';
    svg.append('path').attr('d', areaPath).attr('class', 'spark-area');

    // Line path
    var linePath = '';
    for (var j = 0; j < n; j++) {
        linePath += (j === 0 ? 'M ' : 'L ') + xScale(j) + ' ' + yScale(values[j]) + ' ';
    }
    svg.append('path').attr('d', linePath).attr('class', 'spark-line');

    // 当前选中快照的索引
    var selectedIdx = -1;
    for (var k = 0; k < chrono.length; k++) {
        if (chrono[k].id === ptSelectedSnapshotId) { selectedIdx = k; break; }
    }

    // 点击区域 + 圆点
    var stepW = n > 0 ? w / n : w;
    for (var m = 0; m < n; m++) {
        var snap = chrono[m];
        var isSelected = m === selectedIdx;

        // 点击区域 (不可见矩形)
        svg.append('rect')
            .attr('class', 'spark-click-target')
            .attr('x', xScale(m) - stepW / 2)
            .attr('y', 0)
            .attr('width', stepW)
            .attr('height', h)
            .on('click', function () { ptSelectSnapshot(snap.id); });

        // 圆点
        svg.append('circle')
            .attr('class', 'spark-dot' + (isSelected ? ' selected' : ''))
            .attr('cx', xScale(m))
            .attr('cy', yScale(values[m]))
            .attr('r', isSelected ? 4 : 2);

        // 选中竖线
        if (isSelected) {
            svg.append('line')
                .attr('class', 'spark-vline')
                .attr('x1', xScale(m)).attr('y1', 2)
                .attr('x2', xScale(m)).attr('y2', h - 2);
        }
    }
}

function ptTimelinePrev() {
    var idx = ptSnapshots.findIndex(function (s) { return s.id === ptSelectedSnapshotId; });
    if (idx < 0) return;
    // 时间倒序, 上一个 = idx+1 (更早)
    if (idx + 1 < ptSnapshots.length) {
        ptSelectSnapshot(ptSnapshots[idx + 1].id);
    }
}

function ptTimelineNext() {
    var idx = ptSnapshots.findIndex(function (s) { return s.id === ptSelectedSnapshotId; });
    if (idx < 0) return;
    // 时间倒序, 下一个 = idx-1 (更新)
    if (idx - 1 >= 0) {
        ptSelectSnapshot(ptSnapshots[idx - 1].id);
    }
}

// ═══════════════════════════════════════════════════════════════
//  快照选择
// ═══════════════════════════════════════════════════════════════

function ptSelectSnapshot(id) {
    ptSelectedSnapshotId = id;
    ptSelectedNodePid = null;
    ptClearRadar();
    ptRenderSparklines();
    ptRenderGraph();
}

function ptRenderGraphEmpty(msg) {
    var emptyEl = document.getElementById('ptGraphEmpty');
    if (emptyEl) {
        emptyEl.classList.remove('d-none');
        emptyEl.innerHTML = '<i class="bi bi-diagram-3 display-4 d-block mb-3"></i>' + ptEsc(msg);
    }
    var treeEl = document.getElementById('ptTreeText');
    if (treeEl) treeEl.innerHTML = '';
    ptRenderAnomalyList([]);
    var diffEl = document.getElementById('ptDiffSummary');
    if (diffEl) diffEl.classList.add('d-none');
    var infoEl = document.getElementById('ptSnapshotInfo');
    if (infoEl) infoEl.textContent = '';
    var summaryEl = document.getElementById('ptTreeSummary');
    if (summaryEl) summaryEl.textContent = '';
}

// ═══════════════════════════════════════════════════════════════
//  文本树渲染 (仿 SuperUserService tree 命令)
// ═══════════════════════════════════════════════════════════════

function ptRenderGraph() {
    var emptyEl = document.getElementById('ptGraphEmpty');
    var treeEl = document.getElementById('ptTreeText');
    var idx = ptSnapshots.findIndex(function (s) { return s.id === ptSelectedSnapshotId; });

    if (idx < 0) {
        if (emptyEl) emptyEl.classList.remove('d-none');
        if (treeEl) treeEl.innerHTML = '';
        ptRenderAnomalyList([]);
        return;
    }

    var snap = ptSnapshots[idx];
    if (emptyEl) emptyEl.classList.add('d-none');

    var curProcs = ptParseProcesses(snap);
    var prevProcs = (idx + 1 < ptSnapshots.length) ? ptParseProcesses(ptSnapshots[idx + 1]) : null;
    var diffMap = ptComputeDiff(curProcs, prevProcs);

    // 搜索过滤 (保留匹配节点 + 祖先链)
    var q = ptSearch.toLowerCase();
    var filtered = curProcs;
    if (q) {
        var allMap = {};
        curProcs.forEach(function (p) { allMap[p.pid] = p; });
        var keep = new Set();
        curProcs.forEach(function (p) {
            if (ptMatchProc(p, q)) {
                var cur = p.pid;
                var guard = 0;
                while (cur != null && allMap[cur] && !keep.has(cur) && guard++ < 10000) {
                    keep.add(cur);
                    cur = allMap[cur].ppid || null;
                }
            }
        });
        filtered = curProcs.filter(function (p) { return keep.has(p.pid); });
    }

    // 构建 nodes
    var nodes = filtered.map(function (p) {
        var d = diffMap[p.pid] || { status: 'normal', changes: [] };
        return {
            id: p.pid,
            proc: p,
            diffStatus: d.status,
            changes: d.changes || []
        };
    });

    // 添加消失节点 (ghost, 从上一条快照)
    if (prevProcs) {
        var curPidSet = ptPidSet(curProcs);
        prevProcs.forEach(function (p) {
            if (!curPidSet.has(p.pid) && (!q || ptMatchProc(p, q))) {
                nodes.push({ id: p.pid, proc: p, diffStatus: 'removed', changes: [] });
            }
        });
    }

    // 各维度最大值 (雷达图归一化用)
    ptMaxDims = {
        threads: Math.max.apply(null, nodes.map(function (n) { return n.proc.threads || 0; }).concat([1])),
        workingSet: Math.max.apply(null, nodes.map(function (n) { return n.proc.workingSet || 0; }).concat([1])),
        handles: Math.max.apply(null, nodes.map(function (n) { return n.proc.handles || 0; }).concat([1])),
        privatePages: Math.max.apply(null, nodes.map(function (n) { return n.proc.privatePages || 0; }).concat([1]))
    };

    // 构建 parent -> children map
    var nodeMap = {};
    nodes.forEach(function (n) { nodeMap[n.id] = n; });
    var childrenMap = {};
    var roots = [];
    nodes.forEach(function (n) {
        var ppid = n.proc.ppid;
        if (ppid != null && ppid !== 0 && ppid !== n.proc.pid && nodeMap[ppid]) {
            if (!childrenMap[ppid]) childrenMap[ppid] = [];
            childrenMap[ppid].push(n);
        } else {
            roots.push(n);
        }
    });
    // PID 排序 (与 SuperUserService 一致)
    roots.sort(function (a, b) { return Number(a.id) - Number(b.id); });
    Object.keys(childrenMap).forEach(function (k) {
        childrenMap[k].sort(function (a, b) { return Number(a.id) - Number(b.id); });
    });

    // 递归渲染
    var html = '';
    for (var i = 0; i < roots.length; i++) {
        var isLast = (i + 1 === roots.length);
        html += ptRenderTreeNode(roots[i], '', isLast, true, childrenMap);
        if (i + 1 < roots.length) html += '\n';
    }

    treeEl.innerHTML = html;

    // 行点击事件
    treeEl.querySelectorAll('.pt-tree-row').forEach(function (row) {
        row.addEventListener('click', function (e) {
            e.stopPropagation();
            var pid = Number(row.getAttribute('data-pid'));
            ptOnRowClick(pid);
        });
    });

    // diff 摘要
    var addedCount = nodes.filter(function (n) { return n.diffStatus === 'new'; }).length;
    var removedCount = nodes.filter(function (n) { return n.diffStatus === 'removed'; }).length;
    var changedCount = nodes.filter(function (n) { return n.diffStatus === 'changed'; }).length;
    var diffEl = document.getElementById('ptDiffSummary');
    if (diffEl) {
        if (addedCount > 0 || removedCount > 0 || changedCount > 0) {
            var parts = [];
            if (addedCount > 0) parts.push('+' + addedCount);
            if (removedCount > 0) parts.push('-' + removedCount);
            if (changedCount > 0) parts.push('\u0394' + changedCount);
            diffEl.textContent = parts.join(' ');
            diffEl.classList.remove('d-none');
        } else {
            diffEl.classList.add('d-none');
        }
    }

    // 快照信息
    var infoEl = document.getElementById('ptSnapshotInfo');
    if (infoEl) {
        var kindLabel = { 'security': '初始全量', 'tree': '轮询(已弃用)', 'tree-triggered': '事件触发' }[snap.kind] || snap.kind;
        infoEl.textContent = ptFmtEventTime(snap.timestamp) + ' \u00b7 ' + kindLabel + ' \u00b7 ' + nodes.length + ' \u8fdb\u7a0b';
    }

    // 顶部摘要 (仿 SuperUserService)
    var totalThreads = nodes.reduce(function (s, n) { return s + (n.proc.threads || 0); }, 0);
    var totalWs = nodes.reduce(function (s, n) { return s + (n.proc.workingSet || 0); }, 0);
    var summaryEl = document.getElementById('ptTreeSummary');
    if (summaryEl) {
        summaryEl.textContent = nodes.length + ' \u8fdb\u7a0b \u00b7 ' + totalThreads + ' \u7ebf\u7a0b \u00b7 WS ' + ptFmtBytes(totalWs);
    }

    // 异常清单
    ptRenderAnomalyList(nodes);

    // 恢复选中节点
    if (ptSelectedNodePid != null) {
        var prevSelected = nodes.find(function (n) { return n.id === ptSelectedNodePid; });
        if (prevSelected) {
            ptRenderRadar(prevSelected.proc);
            ptHighlightRow(ptSelectedNodePid);
        } else {
            ptSelectedNodePid = null;
        }
    }
}

/// 递归渲染一个树节点 (返回 HTML 字符串)
function ptRenderTreeNode(node, indent, isLast, isRoot, childrenMap) {
    var p = node.proc;
    var branch = isRoot ? '' : (isLast ? '\u2514\u2500\u2500 ' : '\u251c\u2500\u2500 ');
    var diffCls = node.diffStatus !== 'normal' ? ' diff-' + node.diffStatus : '';
    var selectedCls = (p.pid === ptSelectedNodePid) ? ' selected' : '';

    // 安全标志 (行内缩写)
    var flags = '';
    if (p.pplBroken) flags += '<span class="pt-tree-flag ppl">[PPL]</span>';
    if (ptHasSuspiciousMem(p)) flags += '<span class="pt-tree-flag mem">[MEM]</span>';
    if (ptHasHighRiskHandle(p)) flags += '<span class="pt-tree-flag handle">[HDL]</span>';
    if (p.untrusted) flags += '<span class="pt-tree-flag untrusted">[UNS]</span>';

    // diff 标签
    var diffTag = '';
    if (node.diffStatus === 'new') diffTag = '<span class="pt-tree-diff-tag new">NEW</span>';
    else if (node.diffStatus === 'removed') diffTag = '<span class="pt-tree-diff-tag removed">DEL</span>';
    else if (node.diffStatus === 'changed') diffTag = '<span class="pt-tree-diff-tag changed">CHG</span>';

    // 维度信息 (全平铺, 仿 SuperUserService)
    var name = ptTrunc(p.name || '(unknown)', 30);
    var ws = p.workingSet != null ? ptFmtBytes(p.workingSet) : '-';
    var priv = p.privatePages != null ? ptFmtBytes(p.privatePages) : '-';
    var meta = '[PPID=' + (p.ppid != null ? p.ppid : '-')
        + ', \u7ebf\u7a0b=' + (p.threads != null ? p.threads : '-')
        + ', \u53e5\u67c4=' + (p.handles != null ? p.handles : '-')
        + ', WS=' + ws
        + ', \u79c1\u6709=' + priv
        + ', \u4f18\u5148=' + (p.basePriority != null ? p.basePriority : '-')
        + ']';

    var html = '<span class="pt-tree-row' + diffCls + selectedCls + '" data-pid="' + p.pid + '">'
        + '<span class="pt-tree-branch">' + ptEsc(indent + branch) + '</span>'
        + '<span class="pt-tree-pid">' + ptEsc(p.pid) + '</span>'
        + ' <span class="pt-tree-name">' + ptEsc(name) + '</span>'
        + flags
        + diffTag
        + ' <span class="pt-tree-meta">' + ptEsc(meta) + '</span>'
        + '</span>\n';

    var kids = childrenMap[node.id];
    if (kids && kids.length > 0) {
        var childIndent = isRoot ? '' : indent + (isLast ? '    ' : '\u2502   ');
        for (var i = 0; i < kids.length; i++) {
            var last = (i + 1 === kids.length);
            html += ptRenderTreeNode(kids[i], childIndent, last, false, childrenMap);
        }
    }
    return html;
}

function ptTrunc(s, max) {
    if (!s) return s;
    return s.length <= max ? s : s.substring(0, max - 1) + '\u2026';
}

// ═══════════════════════════════════════════════════════════════
//  行交互
// ═══════════════════════════════════════════════════════════════

function ptOnRowClick(pid) {
    ptSelectedNodePid = pid;
    ptHighlightRow(pid);

    // 找到对应 proc 渲染雷达
    var idx = ptSnapshots.findIndex(function (s) { return s.id === ptSelectedSnapshotId; });
    if (idx < 0) return;
    var snap = ptSnapshots[idx];
    var procs = ptParseProcesses(snap);
    var proc = procs.find(function (p) { return p.pid === pid; });
    if (proc) ptRenderRadar(proc);

    document.querySelectorAll('.pt-anomaly-chip').forEach(function (c) {
        c.classList.toggle('focused', Number(c.getAttribute('data-pid')) === pid);
    });
}

function ptHighlightRow(pid) {
    document.querySelectorAll('.pt-tree-row').forEach(function (r) {
        r.classList.toggle('selected', Number(r.getAttribute('data-pid')) === pid);
    });
}

function ptClearNodeSelection() {
    ptSelectedNodePid = null;
    document.querySelectorAll('.pt-tree-row').forEach(function (r) {
        r.classList.remove('selected');
    });
    ptClearRadar();
    document.querySelectorAll('.pt-anomaly-chip').forEach(function (c) {
        c.classList.remove('focused');
    });
}

/// 从异常清单点击 -> 滚动到对应行并高亮
function ptFocusNode(pid) {
    ptSelectedNodePid = pid;
    ptHighlightRow(pid);

    var row = document.querySelector('.pt-tree-row[data-pid="' + pid + '"]');
    if (row) {
        row.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }

    var idx = ptSnapshots.findIndex(function (s) { return s.id === ptSelectedSnapshotId; });
    if (idx < 0) return;
    var snap = ptSnapshots[idx];
    var procs = ptParseProcesses(snap);
    var proc = procs.find(function (p) { return p.pid === pid; });
    if (proc) ptRenderRadar(proc);

    document.querySelectorAll('.pt-anomaly-chip').forEach(function (c) {
        c.classList.toggle('focused', Number(c.getAttribute('data-pid')) === pid);
    });
}

// ═══════════════════════════════════════════════════════════════
//  雷达图 (五轴同图, 不是 tab)
// ═══════════════════════════════════════════════════════════════

function ptRenderRadar(proc) {
    var emptyEl = document.getElementById('ptRadarEmpty');
    var contentEl = document.getElementById('ptRadarContent');
    if (!emptyEl || !contentEl) return;

    emptyEl.classList.add('d-none');
    contentEl.classList.remove('d-none');

    var titleEl = document.getElementById('ptRadarTitle');
    titleEl.innerHTML = '<i class="bi bi-activity me-1"></i>' + ptEsc(proc.name || '(unknown)') + ' \u00b7 PID ' + proc.pid;

    // 计算归一化值 (相对当前快照最大值)
    var idx = ptSnapshots.findIndex(function (s) { return s.id === ptSelectedSnapshotId; });
    if (idx < 0) return;
    var snap = ptSnapshots[idx];
    var allProcs = ptParseProcesses(snap);

    var maxThreads = Math.max.apply(null, allProcs.map(function (p) { return p.threads || 0; }).concat([1]));
    var maxWS = Math.max.apply(null, allProcs.map(function (p) { return p.workingSet || 0; }).concat([1]));
    var maxPP = Math.max.apply(null, allProcs.map(function (p) { return p.privatePages || 0; }).concat([1]));
    var maxHandles = Math.max.apply(null, allProcs.map(function (p) { return p.handles || 0; }).concat([1]));

    var secScore = ptSecurityScore(proc);

    var axes = [
        { label: '\u7ebf\u7a0b', value: (proc.threads || 0) / maxThreads, raw: proc.threads || 0, fmt: String },
        { label: '\u5de5\u4f5c\u96c6', value: (proc.workingSet || 0) / maxWS, raw: proc.workingSet || 0, fmt: ptFmtBytes },
        { label: '\u79c1\u6709\u9875', value: (proc.privatePages || 0) / maxPP, raw: proc.privatePages || 0, fmt: ptFmtBytes },
        { label: '\u53e5\u67c4', value: (proc.handles || 0) / maxHandles, raw: proc.handles || 0, fmt: String },
        { label: '\u5b89\u5168\u98ce\u9669', value: secScore / 4, raw: secScore + '/4', fmt: String }
    ];

    var svg = d3.select('#ptRadarSvg');
    svg.selectAll('*').remove();

    var cx = 110, cy = 105, r = 68;
    var n = axes.length;

    // 网格 (同心多边形)
    [0.25, 0.5, 0.75, 1.0].forEach(function (scale) {
        var points = axes.map(function (a, i) {
            var angle = (i / n) * 2 * Math.PI - Math.PI / 2;
            return [cx + Math.cos(angle) * r * scale, cy + Math.sin(angle) * r * scale];
        });
        svg.append('polygon')
            .attr('points', points.map(function (p) { return p.join(','); }).join(' '))
            .attr('class', 'radar-grid');
    });

    // 轴线 + 标签
    axes.forEach(function (a, i) {
        var angle = (i / n) * 2 * Math.PI - Math.PI / 2;
        var ex = cx + Math.cos(angle) * r;
        var ey = cy + Math.sin(angle) * r;
        svg.append('line')
            .attr('x1', cx).attr('y1', cy)
            .attr('x2', ex).attr('y2', ey)
            .attr('class', 'radar-axis');

        var lx = cx + Math.cos(angle) * (r + 16);
        var ly = cy + Math.sin(angle) * (r + 16);
        svg.append('text')
            .attr('x', lx).attr('y', ly)
            .attr('class', 'radar-axis-label')
            .text(a.label);

        // 值
        svg.append('text')
            .attr('x', lx).attr('y', ly + 10)
            .attr('class', 'radar-axis-value')
            .text(a.fmt(a.raw));
    });

    // 数据多边形
    var dataPoints = axes.map(function (a, i) {
        var angle = (i / n) * 2 * Math.PI - Math.PI / 2;
        return [cx + Math.cos(angle) * r * a.value, cy + Math.sin(angle) * r * a.value];
    });
    svg.append('polygon')
        .attr('points', dataPoints.map(function (p) { return p.join(','); }).join(' '))
        .attr('class', 'radar-polygon');

    // 数据点
    dataPoints.forEach(function (p, i) {
        var isCritical = axes[i].label === '\u5b89\u5168\u98ce\u9669' && axes[i].value > 0;
        svg.append('circle')
            .attr('cx', p[0]).attr('cy', p[1])
            .attr('r', 2.5)
            .attr('class', 'radar-point' + (isCritical ? ' critical' : ''));
    });

    // 节点详细信息
    ptRenderNodeInfo(proc);
}

function ptRenderNodeInfo(proc) {
    var html = '<div class="pt-node-info"><div class="kv">';
    html += '<div class="k">PID</div><div class="v mono">' + ptEsc(proc.pid) + '</div>';
    html += '<div class="k">PPID</div><div class="v mono">' + ptEsc(proc.ppid != null ? proc.ppid : '-') + '</div>';
    html += '<div class="k">\u8fdb\u7a0b\u540d</div><div class="v">' + ptEsc(proc.name || '-') + '</div>';
    html += '<div class="k">\u7ebf\u7a0b\u6570</div><div class="v mono">' + ptEsc(proc.threads != null ? proc.threads : '-') + '</div>';
    html += '<div class="k">\u53e5\u67c4\u6570</div><div class="v mono">' + ptEsc(proc.handles != null ? proc.handles : '-') + '</div>';
    html += '<div class="k">\u5de5\u4f5c\u96c6</div><div class="v mono">' + ptFmtBytes(proc.workingSet) + '</div>';
    html += '<div class="k">\u79c1\u6709\u9875</div><div class="v mono">' + ptFmtBytes(proc.privatePages) + '</div>';
    html += '<div class="k">Session</div><div class="v mono">' + ptEsc(proc.session != null ? proc.session : '-') + '</div>';
    if (proc.createTime) {
        html += '<div class="k">\u521b\u5efa\u65f6\u95f4</div><div class="v mono" style="font-size:0.7rem">' + ptEsc(proc.createTime) + '</div>';
    }
    html += '</div>';

    // 安全标志
    var flags = '';
    if (proc.pplBroken) flags += '<span class="flag-badge ppl">PPL\u7834</span>';
    if (ptHasSuspiciousMem(proc)) flags += '<span class="flag-badge mem">\u53ef\u7591\u5185\u5b58</span>';
    if (ptHasHighRiskHandle(proc)) flags += '<span class="flag-badge handle">\u9ad8\u5371\u53e5\u67c4</span>';
    if (proc.untrusted) flags += '<span class="flag-badge untrusted">\u4e0d\u53d7\u4fe1</span>';
    if (flags) {
        html += '<div class="flag-badges">' + flags + '</div>';
    }

    // 安全进程额外信息
    if (ptIsSecurityProc(proc)) {
        html += '<div class="kv mt-2">';
        if (proc.image) {
            html += '<div class="k">ImagePath</div><div class="v mono" style="font-size:0.7rem">' + ptEsc(proc.image) + '</div>';
        }
        if (proc.cmd) {
            html += '<div class="k">CmdLine</div><div class="v mono" style="font-size:0.7rem">' + ptEsc(proc.cmd) + '</div>';
        }
        if (proc.protection) {
            html += '<div class="k">Protection</div><div class="v mono">' + ptEsc(proc.protection) + '</div>';
        }
        // 线程/模块/内存/句柄 数量统计
        var threadCount = Array.isArray(proc.threadInfos) ? proc.threadInfos.length : 0;
        var modCount = Array.isArray(proc.modules) ? proc.modules.length : 0;
        var memCount = Array.isArray(proc.memRegions) ? proc.memRegions.length : 0;
        var hdlCount = Array.isArray(proc.extHandles) ? proc.extHandles.length : 0;
        html += '<div class="k">\u8be6\u7ec6\u7edf\u8ba1</div><div class="v mono" style="font-size:0.7rem">';
        html += '\u7ebf\u7a0b' + threadCount + ' / \u6a21\u5757' + modCount + ' / \u5185\u5b58\u533a' + memCount + ' / \u53e5\u67c4' + hdlCount;
        html += '</div>';
        html += '</div>';
    } else {
        html += '<div class="text-muted mt-2" style="font-size:0.7rem"><i class="bi bi-info-circle me-1"></i>'
            + 'tree \u6a21\u5f0f\u4ec5\u542b Brief \u5b57\u6bb5\u3002\u67e5\u770b\u6a21\u5757/\u5185\u5b58/\u53e5\u67c4\u8be6\u60c5\u8bf7\u5207\u6362 security \u5feb\u7167\u3002'
            + '</div>';
    }

    html += '</div>';
    document.getElementById('ptNodeInfo').innerHTML = html;
}

function ptClearRadar() {
    var emptyEl = document.getElementById('ptRadarEmpty');
    var contentEl = document.getElementById('ptRadarContent');
    if (emptyEl) emptyEl.classList.remove('d-none');
    if (contentEl) contentEl.classList.add('d-none');
    var titleEl = document.getElementById('ptRadarTitle');
    if (titleEl) titleEl.innerHTML = '<i class="bi bi-activity me-1"></i>\u591a\u7ef4\u96f7\u8fbe';
}

// ═══════════════════════════════════════════════════════════════
//  异常进程清单 (底部, 只列安全问题进程)
// ═══════════════════════════════════════════════════════════════

function ptRenderAnomalyList(nodes) {
    var anomalies = nodes.filter(function (n) { return ptIsAnomaly(n.proc); });
    var container = document.getElementById('ptAnomalyList');
    var countEl = document.getElementById('ptAnomalyCount');
    if (!container) return;

    if (anomalies.length === 0) {
        container.innerHTML = '<div class="text-center text-muted py-2 w-100 small">\u5f53\u524d\u5feb\u7167\u65e0\u5f02\u5e38\u8fdb\u7a0b</div>';
        if (countEl) countEl.textContent = '';
        return;
    }

    if (countEl) countEl.textContent = anomalies.length + ' \u4e2a\u5f02\u5e38\u8fdb\u7a0b';
    container.innerHTML = anomalies.map(function (n) {
        var p = n.proc;
        var badges = '';
        if (p.pplBroken) badges += '<span class="badge bg-danger">PPL\u7834</span>';
        if (ptHasSuspiciousMem(p)) badges += '<span class="badge bg-warning text-dark">\u53ef\u7591\u5185\u5b58</span>';
        if (ptHasHighRiskHandle(p)) badges += '<span class="badge bg-danger">\u9ad8\u5371\u53e5\u67c4</span>';
        if (p.untrusted) badges += '<span class="badge bg-secondary">\u4e0d\u53d7\u4fe1</span>';
        return '<div class="pt-anomaly-chip" data-pid="' + p.pid + '" onclick="ptFocusNode(' + p.pid + ')">'
            + '<span class="pid">' + p.pid + '</span>'
            + '<span class="name">' + ptEsc(p.name || '-') + '</span>'
            + badges
            + '</div>';
    }).join('');
}

// ═══════════════════════════════════════════════════════════════
//  过滤 / 搜索
// ═══════════════════════════════════════════════════════════════

function ptSetKind(btn) {
    ptKind = btn.getAttribute('data-kind');
    document.querySelectorAll('#ptKindFilter .btn').forEach(function (b) { b.classList.remove('active'); });
    btn.classList.add('active');
    ptProcCache = {};
    ptLoadSnapshots();
}

function ptOnSearch() {
    clearTimeout(ptSearchTimer);
    ptSearchTimer = setTimeout(function () {
        ptSearch = document.getElementById('ptSearch').value.trim();
        ptRenderGraph();
    }, 200);
}

function ptClearSearch() {
    document.getElementById('ptSearch').value = '';
    ptSearch = '';
    ptRenderGraph();
}

// ═══════════════════════════════════════════════════════════════
//  diff 计算
// ═══════════════════════════════════════════════════════════════

function ptComputeDiff(curProcs, prevProcs) {
    var diffMap = {};
    if (!prevProcs) return diffMap;

    var prevMap = {};
    prevProcs.forEach(function (p) { prevMap[p.pid] = p; });

    var curPidSet = ptPidSet(curProcs);
    var prevPidSet = ptPidSet(prevProcs);

    curProcs.forEach(function (p) {
        if (!prevPidSet.has(p.pid)) {
            diffMap[p.pid] = { status: 'new', changes: [] };
        } else {
            var prev = prevMap[p.pid];
            var changes = [];
            if (prev) {
                if (ptNumDiff(p.threads, prev.threads)) changes.push('threads');
                if (ptNumDiff(p.handles, prev.handles)) changes.push('handles');
                if (ptNumDiff(p.workingSet, prev.workingSet)) changes.push('workingSet');
                if (ptNumDiff(p.privatePages, prev.privatePages)) changes.push('privatePages');
                if (ptNumDiff(p.session, prev.session)) changes.push('session');
                if (ptNumDiff(p.basePriority, prev.basePriority)) changes.push('basePriority');
            }
            diffMap[p.pid] = { status: changes.length > 0 ? 'changed' : 'normal', changes: changes };
        }
    });

    prevProcs.forEach(function (p) {
        if (!curPidSet.has(p.pid)) {
            diffMap[p.pid] = { status: 'removed', changes: [] };
        }
    });

    return diffMap;
}

function ptNumDiff(a, b) {
    if (a == null && b == null) return false;
    if (a == null || b == null) return true;
    return Number(a) !== Number(b);
}

// ═══════════════════════════════════════════════════════════════
//  工具函数
// ═══════════════════════════════════════════════════════════════

function ptParseProcesses(snap) {
    if (!snap) return [];
    if (ptProcCache[snap.id]) return ptProcCache[snap.id];
    var arr = [];
    try {
        arr = JSON.parse(snap.processesJson || '[]') || [];
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
    } catch (e) { arr = []; }
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

function ptFmtBytes(n) {
    if (n == null) return '-';
    var b = Number(n);
    if (b < 1024) return b + ' B';
    if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
    if (b < 1073741824) return (b / 1048576).toFixed(2) + ' MB';
    return (b / 1073741824).toFixed(2) + ' GB';
}

function ptIsSecurityProc(p) {
    return !!(p && Array.isArray(p.threadInfos));
}

function ptSecurityScore(p) {
    var score = 0;
    if (p.pplBroken) score++;
    if (ptHasSuspiciousMem(p)) score++;
    if (ptHasHighRiskHandle(p)) score++;
    if (p.untrusted) score++;
    return score;
}

function ptHasSuspiciousMem(p) {
    if (p.suspiciousMem) return true;
    if (Array.isArray(p.memRegions) && p.memRegions.some(function (r) {
        return r.reason && String(r.reason).length > 0;
    })) return true;
    return false;
}

function ptHasHighRiskHandle(p) {
    if (p.highRiskHandle) return true;
    if (Array.isArray(p.extHandles) && p.extHandles.some(function (h) {
        return h.highRisk;
    })) return true;
    return false;
}

function ptIsAnomaly(p) {
    return !!(p.pplBroken || ptHasSuspiciousMem(p) || ptHasHighRiskHandle(p) || p.untrusted);
}

// ═══════════════════════════════════════════════════════════════
//  窗口 resize
// ═══════════════════════════════════════════════════════════════

window.addEventListener('resize', function () {
    if (ptSnapshots.length > 0) {
        ptRenderSparklines();
    }
});
