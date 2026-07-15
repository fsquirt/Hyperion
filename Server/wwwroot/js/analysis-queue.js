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
    tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-4">加载中...</td></tr>';

    try {
        const res = await fetch('/api/admin/analysis-queue');
        if (!res.ok) {
            tbody.innerHTML = `<tr><td colspan="6" class="text-center text-danger py-4">加载失败 (HTTP ${res.status})</td></tr>`;
            return;
        }
        const data = await res.json();

        if (!Array.isArray(data) || data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-4">暂无数据</td></tr>';
            return;
        }

        tbody.innerHTML = data.map(q => {
            const statusBadge = queueStatusMap[q.analysis_status]
                || `<span class="badge bg-secondary">${escapeHtml(q.analysis_status ?? '-')}</span>`;
            const resultBadge = (q.analysis_result == null)
                ? '<span class="text-muted">—</span>'
                : (queueResultMap[q.analysis_result]
                    || `<span class="badge bg-secondary">${escapeHtml(q.analysis_result)}</span>`);
            return `
            <tr>
                <td><code class="small">${escapeHtml(q.session_id)}</code></td>
                <td><small>${escapeHtml(q.machine_name ?? '-')}</small></td>
                <td><small class="text-muted">${formatQueueTime(q.started_at)}</small></td>
                <td><small>${q.file_count ?? 0}</small></td>
                <td>${statusBadge}</td>
                <td>${resultBadge}</td>
            </tr>`;
        }).join('');
    } catch (e) {
        console.error('loadQueue:', e);
        tbody.innerHTML = `<tr><td colspan="6" class="text-center text-danger py-4">加载异常: ${escapeHtml(e.message)}</td></tr>`;
    }
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
