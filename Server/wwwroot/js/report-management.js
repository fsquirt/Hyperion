/**
 * 报告管理 — 报告列表与详情查看
 */

// 报告结果映射
const reportResultMap = {
    'normal':     '<span class="badge bg-success">正常</span>',
    'cheat':      '<span class="badge bg-danger">作弊</span>',
    'suspicious': '<span class="badge bg-warning text-dark">可疑</span>'
};

// 初始加载
loadReports();

async function loadReports() {
    const tbody = document.getElementById('reportTableBody');
    if (!tbody) return;
    tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-4">加载中...</td></tr>';

    try {
        const res = await fetch('/api/admin/reports');
        if (!res.ok) {
            tbody.innerHTML = `<tr><td colspan="6" class="text-center text-danger py-4">加载失败 (HTTP ${res.status})</td></tr>`;
            return;
        }
        const data = await res.json();

        if (!Array.isArray(data) || data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-4">暂无数据</td></tr>';
            return;
        }

        tbody.innerHTML = data.map(r => {
            const resultBadge = reportResultMap[r.result]
                || `<span class="badge bg-secondary">${escapeHtml(r.result ?? '-')}</span>`;
            return `
            <tr>
                <td><code class="small">${escapeHtml(r.id)}</code></td>
                <td><code class="small">${escapeHtml(r.session_id)}</code></td>
                <td><small>${escapeHtml(r.file_name ?? '-')}</small></td>
                <td>${resultBadge}</td>
                <td><small class="text-muted">${formatReportTime(r.generated_at)}</small></td>
                <td>
                    <button class="btn btn-outline-dark btn-sm" onclick="viewReport('${escapeHtml(r.id)}')">
                        <i class="bi bi-eye me-1"></i>查看
                    </button>
                </td>
            </tr>`;
        }).join('');
    } catch (e) {
        console.error('loadReports:', e);
        tbody.innerHTML = `<tr><td colspan="6" class="text-center text-danger py-4">加载异常: ${escapeHtml(e.message)}</td></tr>`;
    }
}

async function viewReport(id) {
    const body = document.getElementById('reportModalBody');
    if (!body) return;
    body.innerHTML = '<div class="text-center text-muted py-4">加载中...</div>';

    // 显示 Modal
    const modalEl = document.getElementById('reportModal');
    let modal = bootstrap.Modal.getInstance(modalEl);
    if (!modal) modal = new bootstrap.Modal(modalEl);
    modal.show();

    try {
        const res = await fetch(`/api/admin/reports/${encodeURIComponent(id)}`);
        if (!res.ok) {
            body.innerHTML = `<div class="alert alert-danger">加载失败 (HTTP ${res.status})</div>`;
            return;
        }
        const data = await res.json();

        // 头部元信息
        const resultBadge = reportResultMap[data.result]
            || `<span class="badge bg-secondary">${escapeHtml(data.result ?? '-')}</span>`;
        const metaHtml = `
            <div class="mb-3">
                <table class="table table-sm table-borderless mb-0">
                    <tbody>
                        <tr><th style="width:120px">报告 ID</th><td><code>${escapeHtml(data.id)}</code></td></tr>
                        <tr><th>会话 ID</th><td><code>${escapeHtml(data.session_id ?? '-')}</code></td></tr>
                        <tr><th>文件名</th><td>${escapeHtml(data.file_name ?? '-')}</td></tr>
                        <tr><th>结果</th><td>${resultBadge}</td></tr>
                        <tr><th>生成时间</th><td>${formatReportTime(data.generated_at)}</td></tr>
                        ${data.agent_id ? `<tr><th>Agent ID</th><td><code>${escapeHtml(data.agent_id)}</code></td></tr>` : ''}
                    </tbody>
                </table>
            </div>
            <hr>
            <h6 class="mb-2"><i class="bi bi-file-earmark-text me-1"></i>报告内容</h6>`;

        // 渲染 Markdown 内容: marked 默认放行内联 HTML, 必须过 DOMPurify 消毒。
        // Agent 上报内容里可能夹带 img 标签的 onerror 之类内联脚本, 直接渲染会形成存储型 XSS, 横向打管理员会话
        let contentHtml;
        try {
            const raw = data.content ?? '';
            const rendered = window.marked ? marked.parse(raw) : null;
            contentHtml = rendered != null && window.DOMPurify
                ? DOMPurify.sanitize(rendered)
                : `<pre>${escapeHtml(raw)}</pre>`;
        } catch (e2) {
            contentHtml = `<pre>${escapeHtml(data.content ?? '')}</pre>`;
        }

        body.innerHTML = metaHtml + `<div class="markdown-body">${contentHtml}</div>`;
    } catch (e) {
        console.error('viewReport:', e);
        body.innerHTML = `<div class="alert alert-danger">加载异常: ${escapeHtml(e.message)}</div>`;
    }
}


//  辅助
function formatReportTime(s) {
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
