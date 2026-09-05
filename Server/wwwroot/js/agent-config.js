/**
 * Agent 配置 — 活跃逆向 Agent 列表
 */

let agentRefreshTimer = null;

// 初始加载
loadAgents();
// 10 秒自动刷新
agentRefreshTimer = setInterval(loadAgents, 10000);

async function loadAgents() {
    const tbody = document.getElementById('agentTableBody');
    if (!tbody) {
        // 容器已卸载,停止自动刷新
        if (agentRefreshTimer) { clearInterval(agentRefreshTimer); agentRefreshTimer = null; }
        return;
    }
    tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-4">加载中...</td></tr>';

    try {
        const res = await fetch('/api/admin/reverse-agents');
        if (!res.ok) {
            tbody.innerHTML = `<tr><td colspan="6" class="text-center text-danger py-4">加载失败 (HTTP ${res.status})</td></tr>`;
            return;
        }
        const data = await res.json();

        if (!Array.isArray(data) || data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-4">暂无数据</td></tr>';
            return;
        }

        tbody.innerHTML = data.map(a => {
            const onlineBadge = a.is_online
                ? '<span class="badge bg-success">在线</span>'
                : '<span class="badge bg-danger">离线</span>';
            return `
            <tr>
                <td><code class="small">${escapeHtml(a.agent_id)}</code></td>
                <td><small>${escapeHtml(a.llm_api_name ?? '-')}</small></td>
                <td><small class="text-muted">${formatAgentTime(a.connected_at)}</small></td>
                <td><small>${a.completed_tasks ?? 0}</small></td>
                <td><small>${escapeHtml(a.current_status ?? '-')}</small></td>
                <td>${onlineBadge}</td>
            </tr>`;
        }).join('');
    } catch (e) {
        console.error('loadAgents:', e);
        tbody.innerHTML = `<tr><td colspan="6" class="text-center text-danger py-4">加载异常: ${escapeHtml(e.message)}</td></tr>`;
    }
}


//  辅助
function formatAgentTime(s) {
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
