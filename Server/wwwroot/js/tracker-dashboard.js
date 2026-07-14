/**
 * Tracker 会话列表 Dashboard（点击会话开新 tab 显示全部详情）
 */

let trkSessions = [];
let trkActiveTab = null;
const trkTabs = new Map();   // id -> { title, data, level, search }

loadSessions();
setInterval(loadSessions, 5000);

async function loadSessions() {
    try {
        const res = await fetch('/api/tracker/sessions');
        if (!res.ok) return;
        trkSessions = await res.json();
        renderSessionList();
        updateStats();
        // 若当前激活 tab 仍在线，静默刷新其详情（避免错过新产物）
        if (trkActiveTab && trkTabs.has(trkActiveTab)) {
            refreshTab(trkActiveTab, false);
        }
    } catch (e) { console.error('loadSessions:', e); }
}

function updateStats() {
    const active = trkSessions.filter(s => s.status === 'active').length;
    const finished = trkSessions.filter(s => s.status === 'finished').length;
    const total = trkSessions.reduce((sum, s) => sum + (s.eventCount || 0), 0);
    document.getElementById('activeCount').textContent = active;
    document.getElementById('finishedCount').textContent = finished;
    document.getElementById('totalEvents').textContent = total.toLocaleString();
    document.getElementById('lastActivity').textContent =
        trkSessions.length > 0 ? formatTime(trkSessions[0].lastHeartbeat) : '-';
}

function renderSessionList() {
    const el = document.getElementById('sessionList');
    if (trkSessions.length === 0) {
        el.innerHTML = '<div class="text-center text-muted py-5"><i class="bi bi-hdd-rack display-4 d-block mb-2"></i>暂无会话<br><small>等待 UserService 连接...</small></div>';
        return;
    }
    el.innerHTML = trkSessions.map(s => `
        <div class="list-group-item session-item ${s.id === trkActiveTab ? 'active' : ''}"
             onclick="openSession('${s.id}')">
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <span class="session-status ${s.status}"></span>
                    <strong class="text-dark">${escHtml(s.id)}</strong>
                    <div class="text-muted small mt-1">${escHtml(s.machineName)} · PID ${s.pid}</div>
                    <div class="text-muted small">${formatTime(s.startedAt)}</div>
                </div>
                <div class="text-end">
                    <span class="badge ${s.status === 'active' ? 'badge-pass' : 'bg-secondary'}">${s.status === 'active' ? '在线' : '已结束'}</span>
                    <div class="text-muted small mt-1">${s.eventCount} 事件</div>
                    <div class="text-muted small">${ioctlDevFileSnap(s)}</div>
                </div>
            </div>
        </div>
    `).join('');
}

function ioctlDevFileSnap(s) {
    const parts = [];
    if (s.hasIoctlStats) parts.push('IOCTL统计');
    if (s.deviceCount) parts.push(s.deviceCount + ' 设备');
    if (s.fileCount) parts.push(s.fileCount + ' 文件');
    if (s.snapshotCount) parts.push(s.snapshotCount + ' 快照');
    return parts.join(' · ') || '—';
}

// ── tab 管理 ────────────────────────────────────────────────

function openSession(id) {
    if (trkTabs.has(id)) { setActiveTab(id); return; }
    trkActiveTab = id;
    renderTabs();
    refreshTab(id, true);
}

function setActiveTab(id) {
    trkActiveTab = id;
    renderSessionList();
    renderTabs();
    const t = trkTabs.get(id);
    if (t) document.getElementById('tabContent').innerHTML = t.html || '<div class="text-center text-muted py-5">加载中...</div>';
}

function closeTab(id) {
    trkTabs.delete(id);
    if (trkActiveTab === id) {
        trkActiveTab = trkTabs.size ? [...trkTabs.keys()][trkTabs.size - 1] : null;
    }
    renderTabs();
    if (trkActiveTab && trkTabs.has(trkActiveTab)) {
        const t = trkTabs.get(trkActiveTab);
        document.getElementById('tabContent').innerHTML = t.html || '';
    } else {
        document.getElementById('tabContent').innerHTML = '<div class="text-center text-muted py-5">尚未打开任何会话</div>';
    }
    renderSessionList();
}

function renderTabs() {
    const ul = document.getElementById('sessionTabs');
    if (trkTabs.size === 0) {
        ul.innerHTML = '<li class="nav-item"><span class="nav-link disabled text-muted" id="noTabHint"><i class="bi bi-cursor me-1"></i>点击左侧会话打开详情</span></li>';
        return;
    }
    let html = '';
    for (const [id, t] of trkTabs) {
        const active = id === trkActiveTab ? 'active' : '';
        html += `<li class="nav-item">
            <span class="nav-link ${active} d-inline-flex align-items-center" style="cursor:pointer" onclick="setActiveTab('${id}')">
                <i class="bi bi-hdd-rack me-1"></i>${escHtml(t.title)}
                <i class="bi bi-x-lg ms-2 text-muted" onclick="event.stopPropagation();closeTab('${id}')"></i>
            </span></li>`;
    }
    ul.innerHTML = html;
}

async function refreshTab(id, showLoading) {
    const content = document.getElementById('tabContent');
    if (showLoading) content.innerHTML = '<div class="text-center text-muted py-5"><div class="spinner-border"></div><div class="mt-2">加载会话详情...</div></div>';
    try {
        const res = await fetch('/api/tracker/sessions/' + id);
        if (!res.ok) { content.innerHTML = '<div class="text-center text-danger py-4">会话不存在</div>'; return; }
        const data = await res.json();
        const tab = trkTabs.get(id) || { title: data.id, level: '', search: '' };
        tab.title = data.id;
        tab.data = data;
        tab.html = renderDetail(data, tab.level, tab.search);
        trkTabs.set(id, tab);
        if (trkActiveTab === id) content.innerHTML = tab.html;
    } catch (e) {
        if (trkActiveTab === id) content.innerHTML = '<div class="text-center text-danger py-4">加载失败: ' + e.message + '</div>';
    }
}

// ── 详情渲染 ────────────────────────────────────────────────

function renderDetail(d, level, search) {
    const sess = section('会话建立事件', `
        <div class="kv"><span class="k">会话 ID</span><span class="v">${escHtml(d.id)}</span></div>
        <div class="kv"><span class="k">机器名</span><span class="v">${escHtml(d.machineName)}</span></div>
        <div class="kv"><span class="k">PID</span><span class="v">${d.pid}</span></div>
        <div class="kv"><span class="k">状态</span><span class="v">${d.status === 'active' ? '在线' : '已结束'}</span></div>
        <div class="kv"><span class="k">建立时间</span><span class="v">${formatTime(d.startedAt)}</span></div>
        ${d.endedAt ? `<div class="kv"><span class="k">结束时间</span><span class="v">${formatTime(d.endedAt)}</span></div>` : ''}
        <div class="kv"><span class="k">是否采纳策略</span><span class="v">${d.policy ? '是' : '否'}</span></div>
    `);

    const policy = d.policy ? section('会话使用策略', `
        <div class="kv"><span class="k">危险内核函数</span><span class="v">${(d.policy.kernelFuncs || []).length} 个</span></div>
        <div class="kv"><span class="k">白名单证书</span><span class="v">${(d.policy.whitelistCertSubjects || []).length} 条</span></div>
        <div class="kv"><span class="k">白名单哈希</span><span class="v">${(d.policy.whitelistHashes || []).length} 条</span></div>
        ${renderPolicyCollapse(d.policy)}
    `) : section('会话使用策略', '<div class="text-muted">（未上报策略）</div>');

    const events = section('Tracker 事件', renderEventsBlock(d, level, search), true);
    const ioctl = section('IOCTL 通信记录', renderIoctlStats(d.ioctlStats));
    const devs = section('附着设备列表', renderDevices(d.attachedDevices || []));
    const files = section('FileCopy / DebugDump 文件', renderFiles(d.fileEntries || []));
    const snaps = section('进程树快照', renderSnapshots(d.snapshots || []));

    return sess + policy + events + ioctl + devs + files + snaps;
}

function renderPolicyCollapse(p) {
    const kf = (p.kernelFuncs || []);
    const certs = (p.whitelistCertSubjects || []);
    const hashes = (p.whitelistHashes || []);
    if (kf.length === 0 && certs.length === 0 && hashes.length === 0) return '';
    let html = '<div class="mt-2"><button class="btn btn-sm btn-outline-secondary" onclick="this.nextElementSibling.classList.toggle(\'d-none\')"><i class="bi bi-chevron-down me-1"></i>展开策略明细</button><div class="d-none mt-2">';
    if (kf.length) html += '<div class="mb-1"><strong>危险内核函数:</strong><br>' + kf.map(x => escHtml(x)).join('<br>') + '</div>';
    if (certs.length) html += '<div class="mb-1"><strong>白名单证书:</strong><br>' + certs.map(x => escHtml(x)).join('<br>') + '</div>';
    if (hashes.length) html += '<div><strong>白名单哈希:</strong><br>' + hashes.map(x => escHtml(x)).join('<br>') + '</div>';
    html += '</div></div>';
    return html;
}

function renderEventsBlock(d, level, search) {
    let events = d.events || [];
    if (level) events = events.filter(e => (e.level || '').toUpperCase() === level.toUpperCase());
    if (search) {
        const kw = search.toLowerCase();
        events = events.filter(e =>
            (e.title || '').toLowerCase().includes(kw) ||
            (e.detail || '').toLowerCase().includes(kw) ||
            (e.source || '').toLowerCase().includes(kw) ||
            (e.type || '').toLowerCase().includes(kw));
    }
    let html = `
        <div class="d-flex align-items-center gap-2 flex-wrap mb-2">
            <div class="btn-group btn-group-sm" id="lvlFilter">
                <button class="btn btn-outline-secondary ${!level ? 'active' : ''}" onclick="setTabLevel('')">全部</button>
                <button class="btn btn-outline-danger ${level === 'HIGH' ? 'active' : ''}" onclick="setTabLevel('HIGH')">HIGH</button>
                <button class="btn btn-outline-warning ${level === 'WARN' ? 'active' : ''}" onclick="setTabLevel('WARN')">WARN</button>
                <button class="btn btn-outline-primary ${level === 'INFO' ? 'active' : ''}" onclick="setTabLevel('INFO')">INFO</button>
            </div>
            <div class="input-group input-group-sm" style="max-width:260px;">
                <span class="input-group-text"><i class="bi bi-search"></i></span>
                <input type="text" id="tabSearch" class="form-control" placeholder="搜索事件..." value="${escHtml(search || '')}" oninput="onTabSearchInput()">
            </div>
            <span class="text-muted small">${events.length} / ${d.eventCount} 条</span>
        </div>`;

    if (events.length === 0) {
        html += '<div class="text-center text-muted py-4"><i class="bi bi-inbox display-4 d-block mb-2"></i>暂无事件</div>';
        return html;
    }
    html += events.map((e, i) => {
        let detailHtml = '';
        if (e.detail) detailHtml += '<div><strong>详情:</strong><pre>' + escHtml(e.detail) + '</pre></div>';
        if (e.xml) detailHtml += '<div class="mt-1"><strong>原始 XML:</strong><pre class="text-muted" style="max-height:200px;overflow:auto">' + escHtml(truncate(e.xml, 2000)) + '</pre></div>';
        return `<div class="event-row" onclick="toggleDetail('evt-${i}')">
            <div class="d-flex align-items-center gap-2">
                <span class="event-time">${formatEventTime(e.timestamp)}</span>
                <span class="event-level ${escHtml(e.level)}">${escHtml(e.level)}</span>
                <span class="event-title">${escHtml(e.title)}</span>
                <span class="event-source ms-auto">${escHtml(e.source)}</span>
            </div></div>
            <div class="event-detail-panel" id="evt-${i}">${detailHtml}</div>`;
    }).join('');
    return html;
}

function renderIoctlStats(stats) {
    if (!stats) return '<div class="text-muted">（暂无 IOCTL 通信统计）</div>';
    const counts = stats.IoctlCounts || {};
    const modules = stats.Modules || [];
    const keys = Object.keys(counts);
    let html = `<div class="text-muted small mb-2">每 30 秒上报最新值 · 当前 ${keys.length} 种 IOCTL 码 · ${modules.length} 个交互模块</div>`;

    html += '<div class="row g-3"><div class="col-md-5"><strong>IOCTL 码 → 次数</strong>';
    if (keys.length === 0) html += '<div class="text-muted small mt-1">（无）</div>';
    else {
        html += '<table class="table table-sm table-hover ioctl-table mt-1"><thead><tr><th>IOCTL 码</th><th class="text-end">次数</th></tr></thead><tbody>';
        keys.sort().forEach(k => { html += `<tr><td><code>${escHtml(k)}</code></td><td class="text-end">${counts[k].toLocaleString()}</td></tr>`; });
        html += '</tbody></table>';
    }
    html += '</div><div class="col-md-7"><strong>交互模块</strong>';
    if (modules.length === 0) html += '<div class="text-muted small mt-1">（无）</div>';
    else html += '<ul class="small mt-1 mb-0">' + modules.map(m => `<li><code>${escHtml(m)}</code></li>`).join('') + '</ul>';
    html += '</div></div>';
    return html;
}

function renderDevices(devices) {
    if (!devices.length) return '<div class="text-muted">（暂无附着设备）</div>';
    return devices.map(d => `<div class="dev-row">
        <i class="bi bi-hdd-network me-1"></i><code>${escHtml(d.deviceName)}</code>
        <span class="text-muted">AttachId=${d.attachId}</span><br>
        <span class="text-muted small">对端: ${escHtml(d.targetPath)}</span>
    </div>`).join('');
}

function renderFiles(files) {
    if (!files.length) return '<div class="text-muted">（暂无 FileCopy / DebugDump 文件）</div>';
    return files.map(f => `<div class="file-row">
        <span class="badge ${f.kind === 'DebugDump' ? 'bg-warning text-dark' : 'bg-info text-dark'}">${escHtml(f.kind)}</span>
        <code>${escHtml(f.name)}</code>
        <span class="text-muted small">(${formatSize(f.size)} · ${formatTime(f.time)})</span>
        ${f.downloadUrl ? `<a class="btn btn-sm btn-outline-primary ms-2" href="${escHtml(f.downloadUrl)}" target="_blank" download><i class="bi bi-download me-1"></i>下载</a>` : ''}
        <br>
        <span class="text-muted small">${escHtml(f.path)}</span>
    </div>`).join('');
}

function renderSnapshots(snaps) {
    if (!snaps.length) return '<div class="text-muted">（暂无进程树快照）</div>';
    return snaps.map((s, i) => {
        let pretty = s;
        try { pretty = JSON.stringify(JSON.parse(s), null, 2); } catch (_) {}
        let meta = '';
        try { const o = JSON.parse(s); meta = `触发=${escHtml(o.trigger || '-')} · 进程数=${(o.processes || []).length} · 连接数=${(o.connections || []).length} · ${formatTime(o.captureTime)}`; } catch (_) {}
        return `<div class="file-row">
            <div class="d-flex justify-content-between align-items-center" style="cursor:pointer" onclick="toggleDetail('snap-${i}')">
                <span><i class="bi bi-diagram-3 me-1"></i>快照 #${i + 1} <span class="text-muted small">${meta}</span></span>
                <i class="bi bi-chevron-down"></i>
            </div>
            <div class="event-detail-panel open" id="snap-${i}"><pre class="snap-json">${escHtml(pretty)}</pre></div>
        </div>`;
    }).join('');
}

function section(title, bodyHtml, noPad) {
    return `<div class="detail-section">
        <div class="section-head"><i class="bi bi-chevron-right me-1"></i>${title}</div>
        <div class="section-body" style="${noPad ? 'padding:0' : ''}">${bodyHtml}</div>
    </div>`;
}

// ── tab 内事件过滤 ──────────────────────────────────────────

function setTabLevel(lv) {
    if (!trkActiveTab) return;
    const t = trkTabs.get(trkActiveTab); if (!t) return;
    t.level = lv; t.search = t.search || '';
    t.html = renderDetail(t.data, lv, t.search);
    document.getElementById('tabContent').innerHTML = t.html;
}
function onTabSearchInput() {
    if (!trkActiveTab) return;
    const t = trkTabs.get(trkActiveTab); if (!t) return;
    const v = document.getElementById('tabSearch').value.trim();
    t.search = v;
    t.html = renderDetail(t.data, t.level || '', v);
    document.getElementById('tabContent').innerHTML = t.html;
}

function toggleDetail(id) {
    const el = document.getElementById(id);
    if (el) el.classList.toggle('open');
}

function formatSize(b) {
    if (!b && b !== 0) return '-';
    if (b < 1024) return b + ' B';
    if (b < 1024 * 1024) return (b / 1024).toFixed(1) + ' KB';
    return (b / 1024 / 1024).toFixed(1) + ' MB';
}

function formatTime(iso) {
    if (!iso) return '-';
    try { return new Date(iso).toLocaleString('zh-CN', { hour12: false }); }
    catch (e) { return iso; }
}
function formatEventTime(ts) {
    if (!ts) return '';
    try {
        const d = new Date(ts);
        return d.toLocaleTimeString('zh-CN', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
            + '.' + String(d.getMilliseconds()).padStart(3, '0');
    } catch (e) { return ts; }
}
function escHtml(s) {
    if (!s) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
function truncate(s, max) {
    if (!s || s.length <= max) return s;
    return s.substring(0, max) + '\n... (截断)';
}
