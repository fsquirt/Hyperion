/**
 * 进程树快照 Dashboard — 力导向节点-连线图
 *
 * 骨架 (vs 事件追踪 UI 的根本区别):
 *   1. 主视图是 D3 力导向图 (2D 空间), 不是列表 (1D 滚动)
 *   2. 快照选择用 sparkline 趋势曲线, 不是滑块/列表
 *   3. 节点详情用雷达图 (五轴同图), 不是 tab 串行切换
 *   4. 多维同时编码 (大小=资源, 颜色=安全), 不靠记忆拼维度
 *   5. 异常清单在底部聚焦, 不是全量列表
 *   6. diff 用拓扑着色 (新增/消失/变化), 不是行级 +/-
 *
 * 交互:
 *   - 拖拽节点: 固定位置 (双击释放)
 *   - 滚轮: 缩放画布
 *   - 拖拽背景: 平移画布
 *   - 点击节点: 选中 + 右侧雷达图
 *   - 点击 sparkline 上的点: 切换快照
 *   - 点击异常清单 chip: 聚焦图中对应节点
 *   - 维度下拉: 切换节点大小/颜色编码
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
var ptSizeEnc = 'threads';          // 节点大小编码维度
var ptColorEnc = 'security';        // 节点颜色编码维度

// D3 力导向图状态
var ptSimulation = null;
var ptZoomBehavior = null;
var ptGraphSvg = null;
var ptGraphG = null;
var ptMaxDims = {};                 // 当前快照各维度最大值 (用于归一化)

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
ptLoadTreePollConfig();

// ═══════════════════════════════════════════════════════════════
//  Tree 频率配置
// ═══════════════════════════════════════════════════════════════

async function ptLoadTreePollConfig() {
    try {
        var res = await fetch('/api/tracker/config');
        if (!res.ok) return;
        var data = await res.json();
        var input = document.getElementById('ptTreePollInput');
        var status = document.getElementById('ptTreePollStatus');
        if (input) input.value = data.treePollIntervalSec || 10;
        if (status) status.textContent = '当前: ' + (data.treePollIntervalSec || 10) + ' 秒';
    } catch (e) { console.error('ptLoadTreePollConfig:', e); }
}

async function ptSaveTreePollConfig() {
    var val = parseInt(document.getElementById('ptTreePollInput').value, 10);
    if (!val || val < 1 || val > 3600) {
        document.getElementById('ptTreePollStatus').textContent = '请输入 1..3600 之间的整数';
        return;
    }
    try {
        var getRes = await fetch('/api/tracker/config');
        if (!getRes.ok) { document.getElementById('ptTreePollStatus').textContent = '读取配置失败'; return; }
        var fresh = await getRes.json();
        var postRes = await fetch('/api/tracker/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                treePollIntervalSec: val,
                ioctlEnabled: fresh.ioctlEnabled,
                dumpMode: fresh.dumpMode,
                fileCopyEnabled: fresh.fileCopyEnabled
            })
        });
        if (!postRes.ok) {
            var err = await postRes.json().catch(function () { return {}; });
            document.getElementById('ptTreePollStatus').textContent = '失败: ' + (err.error || postRes.status);
            return;
        }
        var data = await postRes.json();
        document.getElementById('ptTreePollInput').value = data.treePollIntervalSec;
        document.getElementById('ptTreePollStatus').textContent = '已应用: ' + data.treePollIntervalSec + ' 秒';
    } catch (e) {
        document.getElementById('ptTreePollStatus').textContent = '失败: ' + e.message;
    }
}

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
            metaEl.innerHTML = '<i class="bi bi-share-fill me-1"></i>' + ptEsc(ptSelectedId)
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
        emptyEl.innerHTML = '<i class="bi bi-share display-4 d-block mb-3"></i>' + ptEsc(msg);
    }
    var svg = d3.select('#ptGraph');
    if (svg) svg.selectAll('*').remove();
    if (ptSimulation) { ptSimulation.stop(); ptSimulation = null; }
    ptRenderAnomalyList([]);
    var diffEl = document.getElementById('ptDiffSummary');
    if (diffEl) diffEl.classList.add('d-none');
    var infoEl = document.getElementById('ptSnapshotInfo');
    if (infoEl) infoEl.textContent = '';
}

// ═══════════════════════════════════════════════════════════════
//  D3 力导向图核心
// ═══════════════════════════════════════════════════════════════

function ptRenderGraph() {
    var emptyEl = document.getElementById('ptGraphEmpty');
    var idx = ptSnapshots.findIndex(function (s) { return s.id === ptSelectedSnapshotId; });

    if (idx < 0) {
        if (emptyEl) emptyEl.classList.remove('d-none');
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

    // 构建 links (parent -> child)
    var nodeIds = new Set(nodes.map(function (n) { return n.id; }));
    var links = [];
    nodes.forEach(function (n) {
        var ppid = n.proc.ppid;
        if (ppid != null && ppid !== n.proc.pid && nodeIds.has(ppid)) {
            links.push({ source: ppid, target: n.proc.pid, removed: n.diffStatus === 'removed' });
        }
    });

    // 计算各维度最大值 (用于节点大小归一化)
    ptMaxDims = {
        threads: Math.max.apply(null, nodes.map(function (n) { return n.proc.threads || 0; }).concat([1])),
        workingSet: Math.max.apply(null, nodes.map(function (n) { return n.proc.workingSet || 0; }).concat([1])),
        handles: Math.max.apply(null, nodes.map(function (n) { return n.proc.handles || 0; }).concat([1])),
        privatePages: Math.max.apply(null, nodes.map(function (n) { return n.proc.privatePages || 0; }).concat([1]))
    };

    // 停止旧仿真
    if (ptSimulation) { ptSimulation.stop(); }

    // SVG 设置
    var svgEl = document.getElementById('ptGraph');
    var svg = d3.select('#ptGraph');
    svg.selectAll('*').remove();

    var width = svgEl.clientWidth || 600;
    var height = 680;

    // Zoom 行为
    ptZoomBehavior = d3.zoom()
        .scaleExtent([0.1, 5])
        .on('zoom', function (e) { g.attr('transform', e.transform); });
    svg.call(ptZoomBehavior);

    var g = svg.append('g');
    ptGraphSvg = svg;
    ptGraphG = g;

    // 连线
    var link = g.append('g')
        .attr('class', 'pt-links')
        .selectAll('line')
        .data(links)
        .join('line')
        .attr('class', function (d) { return 'pt-link' + (d.removed ? ' diff-removed' : ''); });

    // 节点
    var node = g.append('g')
        .attr('class', 'pt-nodes')
        .selectAll('circle')
        .data(nodes)
        .join('circle')
        .attr('class', function (d) {
            var cls = 'pt-node';
            if (d.diffStatus !== 'normal') cls += ' diff-' + d.diffStatus;
            if (d.proc.pid === ptSelectedNodePid) cls += ' selected';
            return cls;
        })
        .attr('r', function (d) { return ptNodeRadius(d); })
        .attr('fill', function (d) { return ptNodeColor(d); })
        .attr('stroke', function (d) { return ptNodeStroke(d); })
        .on('click', function (e, d) { e.stopPropagation(); ptOnNodeClick(d); })
        .on('mouseenter', function (e, d) { ptOnNodeHover(e, d); })
        .on('mouseleave', function () { ptOnNodeLeave(); })
        .call(d3.drag()
            .on('start', function (e, d) {
                if (!e.active) ptSimulation.alphaTarget(0.3).restart();
                d.fx = d.x; d.fy = d.y;
            })
            .on('drag', function (e, d) { d.fx = e.x; d.fy = e.y; })
            .on('end', function (e, d) {
                if (!e.active) ptSimulation.alphaTarget(0);
                d.fx = null; d.fy = null;
            })
        );

    // 双击释放固定位置
    node.on('dblclick', function (e, d) {
        e.stopPropagation();
        d.fx = null; d.fy = null;
        ptSimulation.alphaTarget(0.3).restart();
        setTimeout(function () { ptSimulation.alphaTarget(0); }, 500);
    });

    // 标签 (只给异常节点 + 大节点 + 选中节点)
    var label = g.append('g')
        .attr('class', 'pt-labels')
        .selectAll('text')
        .data(nodes)
        .join('text')
        .attr('class', function (d) {
            return 'pt-node-label' + (d.proc.pid === ptSelectedNodePid ? ' selected' : '');
        })
        .attr('dy', function (d) { return ptNodeRadius(d) + 8; })
        .text(function (d) {
            if (d.proc.pid === ptSelectedNodePid) return d.proc.name || '';
            if (ptIsAnomaly(d.proc)) return d.proc.name || '';
            if (ptNodeRadius(d) > 14) return (d.proc.name || '').substring(0, 12);
            return '';
        });

    // 背景点击 = 取消选择
    svg.on('click', function () { ptClearNodeSelection(); });

    // 力导向仿真
    ptSimulation = d3.forceSimulation(nodes)
        .force('link', d3.forceLink(links).id(function (d) { return d.id; }).distance(45).strength(0.3))
        .force('charge', d3.forceManyBody().strength(-70))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collide', d3.forceCollide().radius(function (d) { return ptNodeRadius(d) + 5; }).strength(0.8))
        .force('x', d3.forceX(width / 2).strength(0.04))
        .force('y', d3.forceY(height / 2).strength(0.04));

    ptSimulation.on('tick', function () {
        link.attr('x1', function (d) { return d.source.x; })
            .attr('y1', function (d) { return d.source.y; })
            .attr('x2', function (d) { return d.target.x; })
            .attr('y2', function (d) { return d.target.y; });
        node.attr('cx', function (d) { return d.x; })
            .attr('cy', function (d) { return d.y; });
        label.attr('x', function (d) { return d.x; })
            .attr('y', function (d) { return d.y; });
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
        infoEl.textContent = ptFmtEventTime(snap.timestamp) + ' \u00b7 ' + snap.kind + ' \u00b7 ' + nodes.length + ' 进程';
    }

    // 异常清单
    ptRenderAnomalyList(nodes);

    // 恢复选中节点
    if (ptSelectedNodePid != null) {
        var prevSelected = nodes.find(function (n) { return n.id === ptSelectedNodePid; });
        if (prevSelected) {
            ptRenderRadar(prevSelected.proc);
        } else {
            ptSelectedNodePid = null;
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  节点视觉编码
// ═══════════════════════════════════════════════════════════════

function ptNodeRadius(d) {
    if (d.diffStatus === 'removed') return 5;
    var val = d.proc[ptSizeEnc];
    if (val == null || val <= 0) return 4;
    var max = ptMaxDims[ptSizeEnc] || 1;
    if (max <= 0) return 4;
    var norm = Math.sqrt(val / max);  // sqrt 让面积 (而非半径) 正比于数值
    return 4 + norm * 16;             // 4~20px
}

function ptNodeColor(d) {
    if (d.diffStatus === 'removed') return 'rgba(220,38,38,0.25)';
    if (ptColorEnc === 'security') {
        var p = d.proc;
        if (p.pplBroken) return '#dc2626';       // 红
        if (ptHasSuspiciousMem(p)) return '#f59e0b';  // 橙
        if (ptHasHighRiskHandle(p)) return '#d97706'; // 深橙
        if (p.untrusted) return '#7c3aed';       // 紫
        return '#6b7280';                        // 灰 (正常)
    }
    if (ptColorEnc === 'kind') {
        return ptIsSecurityProc(d.proc) ? '#3b82f6' : '#16a34a';
    }
    return '#6b7280';
}

function ptNodeStroke(d) {
    if (d.diffStatus === 'new') return '#16a34a';
    if (d.diffStatus === 'removed') return '#dc2626';
    if (d.diffStatus === 'changed') return '#f59e0b';
    return '#fff';
}

// ═══════════════════════════════════════════════════════════════
//  节点交互
// ═══════════════════════════════════════════════════════════════

function ptOnNodeClick(d) {
    ptSelectedNodePid = d.proc.pid;

    d3.selectAll('.pt-node').classed('selected', false);
    d3.selectAll('.pt-node').filter(function (x) { return x.id === d.id; }).classed('selected', true);

    d3.selectAll('.pt-node-label').classed('selected', false);
    d3.selectAll('.pt-node-label').filter(function (x) { return x.id === d.id; })
        .classed('selected', true)
        .text(d.proc.name || '');

    ptRenderRadar(d.proc);

    // 高亮异常清单对应项
    document.querySelectorAll('.pt-anomaly-chip').forEach(function (c) {
        c.classList.toggle('focused', c.getAttribute('data-pid') == d.proc.pid);
    });
}

function ptOnNodeHover(e, d) {
    var tooltip = document.getElementById('ptGraphTooltip');
    if (!tooltip) return;
    var p = d.proc;
    var html = '<div class="tt-title">' + ptEsc(p.name || '(unknown)')
        + ' <span style="color:#aaa">PID ' + p.pid + '</span></div>';
    html += '<div class="tt-row">PPID: ' + (p.ppid != null ? p.ppid : '-') + '</div>';
    html += '<div class="tt-row">\u7ebf\u7a0b: ' + (p.threads != null ? p.threads : '-') + '</div>';
    html += '<div class="tt-row">\u5de5\u4f5c\u96c6: ' + ptFmtBytes(p.workingSet) + '</div>';
    html += '<div class="tt-row">\u53e5\u67c4: ' + (p.handles != null ? p.handles : '-') + '</div>';
    if (d.diffStatus !== 'normal') {
        html += '<div class="tt-row" style="color:#f59e0b">diff: ' + d.diffStatus + '</div>';
    }
    tooltip.innerHTML = html;
    tooltip.classList.remove('d-none');

    // 定位 (相对于 SVG 父容器)
    var container = e.target.ownerSVGElement.parentElement;
    var rect = container.getBoundingClientRect();
    var tx = e.clientX - rect.left + 12;
    var ty = e.clientY - rect.top + 12;
    // 边界检查
    if (tx + 200 > rect.width) tx = e.clientX - rect.left - 200;
    if (ty + 100 > rect.height) ty = e.clientY - rect.top - 100;
    tooltip.style.left = tx + 'px';
    tooltip.style.top = ty + 'px';
}

function ptOnNodeLeave() {
    var tooltip = document.getElementById('ptGraphTooltip');
    if (tooltip) tooltip.classList.add('d-none');
}

function ptClearNodeSelection() {
    ptSelectedNodePid = null;
    d3.selectAll('.pt-node').classed('selected', false);
    d3.selectAll('.pt-node-label').classed('selected', false).text(function (d) {
        if (ptIsAnomaly(d.proc)) return d.proc.name || '';
        if (ptNodeRadius(d) > 14) return (d.proc.name || '').substring(0, 12);
        return '';
    });
    ptClearRadar();
    document.querySelectorAll('.pt-anomaly-chip').forEach(function (c) {
        c.classList.remove('focused');
    });
}

/// 从异常清单点击 -> 聚焦图中节点
function ptFocusNode(pid) {
    if (!ptSimulation) return;
    var node = ptSimulation.nodes().find(function (n) { return n.id === pid; });
    if (!node) return;

    ptSelectedNodePid = pid;
    d3.selectAll('.pt-node').classed('selected', false);
    d3.selectAll('.pt-node').filter(function (d) { return d.id === pid; }).classed('selected', true);
    d3.selectAll('.pt-node-label').classed('selected', false);
    d3.selectAll('.pt-node-label').filter(function (d) { return d.id === pid; })
        .classed('selected', true)
        .text(node.proc.name || '');

    ptRenderRadar(node.proc);

    // 缩放到节点位置
    var svgEl = document.getElementById('ptGraph');
    var w = svgEl.clientWidth || 600;
    var transform = d3.zoomIdentity
        .translate(w / 2 - node.x * 2, 340 - node.y * 2)
        .scale(2);
    ptGraphSvg.transition().duration(500).call(ptZoomBehavior.transform, transform);

    // 高亮异常清单项
    document.querySelectorAll('.pt-anomaly-chip').forEach(function (c) {
        c.classList.toggle('focused', c.getAttribute('data-pid') == pid);
    });
}

// ═══════════════════════════════════════════════════════════════
//  Zoom 控制
// ═══════════════════════════════════════════════════════════════

function ptZoomIn() {
    if (ptGraphSvg && ptZoomBehavior) {
        ptGraphSvg.transition().duration(200).call(ptZoomBehavior.scaleBy, 1.3);
    }
}

function ptZoomOut() {
    if (ptGraphSvg && ptZoomBehavior) {
        ptGraphSvg.transition().duration(200).call(ptZoomBehavior.scaleBy, 1 / 1.3);
    }
}

function ptResetZoom() {
    if (ptGraphSvg && ptZoomBehavior) {
        ptGraphSvg.transition().duration(200).call(ptZoomBehavior.transform, d3.zoomIdentity);
    }
}

// ═══════════════════════════════════════════════════════════════
//  维度编码切换
// ═══════════════════════════════════════════════════════════════

function ptSetSizeEncoding(val) {
    ptSizeEnc = val;
    if (!ptSimulation) return;
    d3.selectAll('.pt-node').attr('r', function (d) { return ptNodeRadius(d); });
    d3.selectAll('.pt-node-label').attr('dy', function (d) { return ptNodeRadius(d) + 8; });
    ptSimulation.force('collide', d3.forceCollide().radius(function (d) { return ptNodeRadius(d) + 5; }).strength(0.8));
    ptSimulation.alpha(0.3).restart();
}

function ptSetColorEncoding(val) {
    ptColorEnc = val;
    d3.selectAll('.pt-node').attr('fill', function (d) { return ptNodeColor(d); });
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
