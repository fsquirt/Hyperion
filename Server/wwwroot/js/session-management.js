/**
 * 会话管理页面
 * 列表 + 详情 + 结束(活跃会话) + 删除
 */

let smSessions = [];
let smSelectedId = null;

smLoadSessions();
setInterval(smLoadSessions, 5000);

// ═══════════════════════════════════════════════════════════════
//  会话列表
// ═══════════════════════════════════════════════════════════════

async function smLoadSessions() {
    try {
        const res = await fetch('/api/tracker/sessions');
        if (!res.ok) return;
        smSessions = await res.json();
        smRenderSessionList();
    } catch (e) { console.error('smLoadSessions:', e); }
}

function smRenderSessionList() {
    const el = document.getElementById('smSessionList');
    if (smSessions.length === 0) {
        el.innerHTML = '<div class="text-center text-muted py-5"><i class="bi bi-hdd-rack display-4 d-block mb-2"></i>暂无会话<br><small>等待 Tracker 连接...</small></div>';
        return;
    }
    el.innerHTML = smSessions.map(s => `
        <div class="list-group-item sm-session-item ${s.id === smSelectedId ? 'active' : ''}"
             onclick="smSelectSession('${s.id}')">
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <span class="session-status ${s.status}"></span>
                    <strong class="text-dark">${smEsc(s.id)}</strong>
                    <div class="text-muted small mt-1">${smEsc(s.machineName)} · PID ${s.pid} · ${smFmtTime(s.startedAt)}</div>
                </div>
                <div class="text-end">
                    <span class="badge ${s.status === 'active' ? 'badge-pass' : 'bg-secondary'}">${s.status === 'active' ? '在线' : '已结束'}</span>
                    <div class="text-muted small mt-1">${s.eventCount} 事件</div>
                </div>
            </div>
        </div>
    `).join('');
}

async function smSelectSession(id) {
    smSelectedId = id;
    smRenderSessionList();
    await smLoadDetail();
}

// ═══════════════════════════════════════════════════════════════
//  会话详情
// ═══════════════════════════════════════════════════════════════

async function smLoadDetail() {
    if (!smSelectedId) return;

    const detailEl = document.getElementById('smDetail');
    const titleEl = document.getElementById('smDetailTitle');
    const actionsEl = document.getElementById('smActions');
    const endBtn = document.getElementById('smEndBtn');

    detailEl.innerHTML = '<div class="text-center text-muted py-4">加载中...</div>';

    try {
        const res = await fetch('/api/tracker/sessions/' + smSelectedId);
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
    if (!smSelectedId) return;
    if (!confirm('确定要删除会话 ' + smSelectedId + ' 吗?\n所有关联的快照、内核通信、dump 记录都会被删除!')) return;

    try {
        const res = await fetch('/api/tracker/sessions/' + smSelectedId, {
            method: 'DELETE'
        });
        if (res.ok) {
            alert('会话已删除');
            smSelectedId = null;
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
//  工具
// ═══════════════════════════════════════════════════════════════

function smEsc(s) {
    if (!s) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function smFmtTime(iso) {
    if (!iso) return '-';
    try { return new Date(iso).toLocaleString('zh-CN', { hour12: false }); }
    catch (e) { return iso; }
}
