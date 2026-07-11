/**
 * 会话管理页面
 * 列表 + 详情 + 结束(活跃会话) + 删除
 */

// 本地别名 -> 共享工具函数 (session-list.js)
var smEsc = TrackerUtils.escHtml;
var smFmtTime = TrackerUtils.formatTime;

// 共享会话列表组件
var smSessionList = new TrackerSessionList({
    containerId: 'smSessionList',
    itemClass: 'sm-session-item',
    onSelect: function (id) { smSelectSession(id); },
    autoRefreshMs: 5000
});

smSessionList.load();
smSessionList.startAutoRefresh();

// ═══════════════════════════════════════════════════════════════
//  会话列表 (委托给共享组件 smSessionList)
// ═══════════════════════════════════════════════════════════════

/// 手动刷新(cshtml 刷新按钮 onclick 调用)
function smLoadSessions() { smSessionList.load(); }

async function smSelectSession(id) {
    await smLoadDetail();
}

// ═══════════════════════════════════════════════════════════════
//  会话详情
// ═══════════════════════════════════════════════════════════════

async function smLoadDetail() {
    var smSelectedId = smSessionList.getSelected();
    if (!smSelectedId) return;

    const detailEl = document.getElementById('smDetail');
    const titleEl = document.getElementById('smDetailTitle');
    const actionsEl = document.getElementById('smActions');
    const endBtn = document.getElementById('smEndBtn');

    detailEl.innerHTML = '<div class="text-center text-muted py-4">加载中...</div>';

    try {
        const res = await fetch('/api/tracker/sessions/' + encodeURIComponent(smSelectedId));
        if (!res.ok) {
            detailEl.innerHTML = '<div class="text-center text-danger py-4">会话不存在</div>';
            return;
        }
        const data = await res.json();

        titleEl.innerHTML = '<i class="bi bi-info-circle me-1"></i>' + smEsc(data.id);
        actionsEl.classList.remove('d-none');

        // 活跃会话才显示结束按钮
        endBtn.style.display = data.status === 'active' ? '' : 'none';

        // 统计数据
        const events = data.events || [];
        const wineventCount = events.filter(e => e.type === 'winevent').length;
        const etwCount = events.filter(e => e.type === 'etw').length;

        detailEl.innerHTML = `
            <div class="sm-detail-row"><div class="sm-detail-label">会话 ID</div><div class="sm-detail-value"><code>${smEsc(data.id)}</code></div></div>
            <div class="sm-detail-row"><div class="sm-detail-label">机器名</div><div class="sm-detail-value">${smEsc(data.machineName)}</div></div>
            <div class="sm-detail-row"><div class="sm-detail-label">游戏 PID</div><div class="sm-detail-value">${data.pid}</div></div>
            <div class="sm-detail-row"><div class="sm-detail-label">状态</div><div class="sm-detail-value">
                <span class="badge ${data.status === 'active' ? 'badge-pass' : 'bg-secondary'}">${data.status === 'active' ? '在线' : '已结束'}</span>
            </div></div>
            <div class="sm-detail-row"><div class="sm-detail-label">启动时间</div><div class="sm-detail-value">${smFmtTime(data.startedAt)}</div></div>
            <div class="sm-detail-row"><div class="sm-detail-label">结束时间</div><div class="sm-detail-value">${data.endedAt ? smFmtTime(data.endedAt) : '-'}</div></div>
            <div class="sm-detail-row"><div class="sm-detail-label">事件总数</div><div class="sm-detail-value">${data.eventCount}</div></div>
            <div class="sm-detail-row"><div class="sm-detail-label">Windows 事件</div><div class="sm-detail-value">${wineventCount}</div></div>
            <div class="sm-detail-row"><div class="sm-detail-label">ETW 事件</div><div class="sm-detail-value">${etwCount}</div></div>
            <div class="mt-3">
                <a href="/dashboard?page=TrackerDashboard" class="btn btn-outline-primary btn-sm">
                    <i class="bi bi-activity me-1"></i>查看事件追踪
                </a>
                <a href="/dashboard?page=ProcessTree" class="btn btn-outline-success btn-sm ms-1">
                    <i class="bi bi-diagram-3 me-1"></i>查看进程树
                </a>
                <a href="/dashboard?page=KernelComm" class="btn btn-outline-warning btn-sm ms-1">
                    <i class="bi bi-hdd-network me-1"></i>查看内核通信
                </a>
                <a href="/dashboard?page=DumpTrigger" class="btn btn-outline-danger btn-sm ms-1">
                    <i class="bi bi-bug me-1"></i>查看 Dump
                </a>
            </div>
        `;
    } catch (e) {
        detailEl.innerHTML = '<div class="text-center text-danger py-4">加载失败: ' + e.message + '</div>';
    }
}

// ═══════════════════════════════════════════════════════════════
//  结束会话
// ═══════════════════════════════════════════════════════════════

async function smEndSession() {
    var smSelectedId = smSessionList.getSelected();
    if (!smSelectedId) return;
    if (!confirm('确定要结束会话 ' + smSelectedId + ' 吗?客户端将收到结束通知。')) return;

    try {
        const res = await fetch('/api/tracker/end', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ sessionId: smSelectedId })
        });
        if (res.ok) {
            alert('会话已结束');
            await smLoadSessions();
            await smLoadDetail();
        } else {
            alert('结束失败: ' + res.status);
        }
    } catch (e) {
        alert('结束失败: ' + e.message);
    }
}

// ═══════════════════════════════════════════════════════════════
//  删除会话(连同关联数据)
// ═══════════════════════════════════════════════════════════════

async function smDeleteSession() {
    var smSelectedId = smSessionList.getSelected();
    if (!smSelectedId) return;
    if (!confirm('确定要删除会话 ' + smSelectedId + ' 吗?\n所有关联的快照、内核通信、dump 记录都会被删除!')) return;

    try {
        const res = await fetch('/api/tracker/sessions/' + encodeURIComponent(smSelectedId), {
            method: 'DELETE'
        });
        if (res.ok) {
            alert('会话已删除');
            smSessionList.selectedId = null;
            await smLoadSessions();
            document.getElementById('smDetail').innerHTML = '<div class="text-center text-muted py-5"><i class="bi bi-cursor display-4 d-block mb-3"></i>选择左侧会话查看详情</div>';
            document.getElementById('smDetailTitle').innerHTML = '<span class="small text-muted">选择会话查看详情</span>';
            document.getElementById('smActions').classList.add('d-none');
        } else {
            alert('删除失败: ' + res.status);
        }
    } catch (e) {
        alert('删除失败: ' + e.message);
    }
}

// ═══════════════════════════════════════════════════════════════
//  工具 (escHtml/formatTime 已委托给 TrackerUtils,见文件头部别名)
// ═══════════════════════════════════════════════════════════════
