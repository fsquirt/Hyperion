/**
 * 研判队列 — 待研判会话列表
 */

let queueRefreshTimer = null;

// 初始加载
loadQueue();
// 10 秒自动刷新
queueRefreshTimer = setInterval(loadQueue, 10000);

// 分析状态映射
const queueStatusMap = {
    'pending':   '<span class="badge bg-secondary">尚未分析</span>',
    'analyzing': '<span class="badge bg-primary">正在分析</span>',
    'done':      '<span class="badge bg-success">已分析</span>',
    'no_files':  '<span class="badge bg-secondary">无文件无需分析</span>'
};

// 研判结果映射
const queueResultMap = {
    'normal':     '<span class="badge bg-success">正常</span>',
    'cheat':      '<span class="badge bg-danger">作弊</span>',
    'suspicious': '<span class="badge bg-warning text-dark">可疑</span>'
};

async function loadQueue() {
    const tbody = document.getElementById('queueTableBody');
    if (!tbody) {
        // 容器已卸载,停止自动刷新
        if (queueRefreshTimer) { clearInterval(queueRefreshTimer); queueRefreshTimer = null; }
        return;
    }
    tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted py-4">加载中...</td></tr>';

    try {
        const res = await fetch('/api/admin/analysis-queue');
        if (!res.ok) {
            tbody.innerHTML = `<tr><td colspan="7" class="text-center text-danger py-4">加载失败 (HTTP ${res.status})</td></tr>`;
            return;
        }
        const data = await res.json();

        if (!Array.isArray(data) || data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted py-4">暂无数据</td></tr>';
            return;
        }

        tbody.innerHTML = data.map(q => {
            const statusBadge = queueStatusMap[q.analysis_status]
                || `<span class="badge bg-secondary">${escapeHtml(q.analysis_status ?? '-')}</span>`;
            const resultBadge = (q.analysis_result == null)
                ? '<span class="text-muted">—</span>'
                : (queueResultMap[q.analysis_result]
                    || `<span class="badge bg-secondary">${escapeHtml(q.analysis_result)}</span>`);

            // 操作按钮：分析中禁用删除；重置任意状态可用。服务端执行强制重置，兜底 Agent 断联卡死的会话
            const isAnalyzing = q.analysis_status === 'analyzing';
            const sid = encodeURIComponent(q.session_id);
            const deleteBtn = isAnalyzing
                ? '<button class="btn btn-outline-secondary btn-sm" disabled title="分析中无法删除"><i class="bi bi-trash"></i></button>'
                : `<button class="btn btn-outline-danger btn-sm" onclick="deleteSession('${sid}')" title="删除会话"><i class="bi bi-trash"></i></button>`;
            const resetTitle = isAnalyzing
                ? '强制重置：Agent 可能仍在分析，谨慎操作'
                : '重置为尚未分析';
            const resetBtn = `<button class="btn btn-outline-warning btn-sm ms-1" onclick="resetSession('${sid}', ${isAnalyzing})" title="${resetTitle}"><i class="bi bi-arrow-counterclockwise"></i></button>`;
            const terminalBtn = `<button class="btn btn-outline-secondary btn-sm me-1" onclick="openTerminal('${q.session_id}')" title="查看研判终端输出"><i class="bi bi-terminal"></i></button>`;

            return `
            <tr>
                <td><code class="small">${escapeHtml(q.session_id)}</code></td>
                <td><small>${escapeHtml(q.machine_name ?? '-')}</small></td>
                <td><small class="text-muted">${formatQueueTime(q.started_at)}</small></td>
                <td><small>${q.file_count ?? 0}</small></td>
                <td>${statusBadge}</td>
                <td>${resultBadge}</td>
                <td class="text-nowrap">${terminalBtn}${deleteBtn}${resetBtn}</td>
            </tr>`;
        }).join('');
    } catch (e) {
        console.error('loadQueue:', e);
        tbody.innerHTML = `<tr><td colspan="7" class="text-center text-danger py-4">加载异常: ${escapeHtml(e.message)}</td></tr>`;
    }
}

// ═══════════════════════════════════════════════════════════════
//  会话操作：删除 / 重置
// ═══════════════════════════════════════════════════════════════

async function deleteSession(sessionId) {
    if (!confirm(`确认删除会话 ${sessionId}？\n将一并删除其分析状态、报告和上传文件，且不可恢复。`))
        return;
    try {
        const res = await fetch(`/api/admin/sessions/${sessionId}/delete`, { method: 'POST' });
        if (res.ok) {
            await loadQueue();
        } else {
            const err = await res.json().catch(() => ({}));
            alert(`删除失败: ${err.error ?? res.status}`);
        }
    } catch (e) {
        alert(`删除异常: ${e.message}`);
    }
}

async function resetSession(sessionId, force = false) {
    const msg = force
        ? `强制重置会话 ${sessionId} 的分析状态？\n该会话正在分析中：若 Agent 仍在线，其后续提交的报告将被拒绝。\n将清空研判结果和报告，会话重新排队等待分析。`
        : `确认重置会话 ${sessionId} 的分析状态？\n将清空研判结果和报告，会话重新排队等待分析。`;
    if (!confirm(msg)) return;
    try {
        const res = await fetch(`/api/admin/sessions/${sessionId}/reset`, { method: 'POST' });
        if (res.ok) {
            await loadQueue();
        } else {
            const err = await res.json().catch(() => ({}));
            alert(`重置失败: ${err.error ?? res.status}`);
        }
    } catch (e) {
        alert(`重置异常: ${e.message}`);
    }
}

// ═══════════════════════════════════════════════════════════════
//  研判终端输出弹窗
// ═══════════════════════════════════════════════════════════════

let termCurrentSession = null;
let termAutoTimer = null;

async function openTerminal(sessionId) {
    termCurrentSession = sessionId;
    const sessEl = document.getElementById('term-session');
    if (sessEl) sessEl.textContent = sessionId;
    const modalEl = document.getElementById('terminalModal');
    const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
    modalEl.addEventListener('hidden.bs.modal', stopTerminalAuto, { once: true });
    modal.show();
    await refreshTerminal();
}

async function refreshTerminal() {
    if (!termCurrentSession) return;
    const $log = document.getElementById('term-log');
    if (!$log) return;
    const atBottom = $log.scrollHeight - $log.scrollTop - $log.clientHeight < 40;
    const prev = $log.scrollTop;
    $log.textContent = '加载中...';
    try {
        const r = await fetch('/api/admin/analysis-logs/' + encodeURIComponent(termCurrentSession));
        if (!r.ok) throw new Error('加载失败 (HTTP ' + r.status + ')');
        const logs = await r.json();
        if (!Array.isArray(logs) || logs.length === 0) {
            $log.innerHTML = '<span class="text-secondary">暂无终端输出。Agent 正在分析该会话,或尚未上报任何日志。</span>';
            return;
        }
        const colorMap = {
            info: 'text-light',
            llm: 'text-info',
            tool_call: 'text-warning',
            tool_result: 'text-success'
        };
        const tagMap = { info: 'INFO', llm: 'LLM', tool_call: 'TOOL', tool_result: 'OUT' };
        let html = '';
        for (const l of logs) {
            const cls = colorMap[l.level] || 'text-light';
            const tag = tagMap[l.level] || 'INFO';
            const ts = (l.ts || '').replace('T', ' ').replace('Z', '').slice(0, 19);
            const fileTag = l.file ? ' <span class="text-secondary">[' + escapeHtml(l.file) + ']</span>' : '';
            html += '<div class="' + cls + '"><span class="text-secondary">[' + ts + '][' + tag + ']</span>' + fileTag + ' ' + escapeHtml(l.text) + '</div>';
        }
        $log.innerHTML = html;
        $log.scrollTop = atBottom ? $log.scrollHeight : prev;
    } catch (e) {
        $log.textContent = e.message;
    }
}

function startTerminalAuto() {
    if (termAutoTimer) return;
    const badge = document.getElementById('term-auto');
    if (badge) {
        badge.textContent = '自动刷新:开';
        badge.classList.remove('bg-secondary');
        badge.classList.add('bg-success');
    }
    termAutoTimer = setInterval(refreshTerminal, 3000);
}

function stopTerminalAuto() {
    if (termAutoTimer) { clearInterval(termAutoTimer); termAutoTimer = null; }
    const badge = document.getElementById('term-auto');
    if (badge) {
        badge.textContent = '自动刷新:关';
        badge.classList.add('bg-secondary');
        badge.classList.remove('bg-success');
    }
}

function toggleTerminalAuto() {
    if (termAutoTimer) stopTerminalAuto(); else startTerminalAuto();
}

// ═══════════════════════════════════════════════════════════════
//  辅助
// ═══════════════════════════════════════════════════════════════

function formatQueueTime(s) {
    if (!s) return '-';
    try {
        const d = new Date(s);
        return d.toLocaleString('zh-CN', { hour12: false });
    } catch { return s; }
}

function escapeHtml(s) {
    if (s == null) return '';
    return String(s).replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    })[c]);
}
