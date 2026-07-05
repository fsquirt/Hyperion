/**
 * 危险内核函数列表 Dashboard
 */

// 状态变量(必须在任何调用前声明,避免 TDZ)
let kfPage = 1;
const kfPageSize = 100;

loadKfStats();
loadKfList();

// ═══════════════════════════════════════════════════════════════
//  统计
// ═══════════════════════════════════════════════════════════════

async function loadKfStats() {
    try {
        const res = await fetch('/api/admin/kernel-funcs/stats');
        if (!res.ok) return;
        const s = await res.json();
        document.getElementById('kfStatTotal').textContent = s.total;
        document.getElementById('kfStatEnabled').textContent = s.enabled_count;
        document.getElementById('kfStatDisabled').textContent = s.disabled_count;
        document.getElementById('kfStatHigh').textContent = s.high_count;
    } catch (e) { console.error('loadKfStats:', e); }
}

// ═══════════════════════════════════════════════════════════════
//  列表
// ═══════════════════════════════════════════════════════════════

async function loadKfList() {
    const search = document.getElementById('kfSearch').value.trim();
    const severity = document.getElementById('kfSeverityFilter').value;
    const enabledStr = document.getElementById('kfEnabledFilter').value;
    const enabled = enabledStr === '' ? null : (enabledStr === 'true');
    const tbody = document.getElementById('kfTableBody');
    tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted py-4">加载中...</td></tr>';

    try {
        const params = new URLSearchParams();
        if (search) params.set('search', search);
        if (severity) params.set('severity', severity);
        if (enabled !== null) params.set('enabled', enabled);
        params.set('page', kfPage);
        params.set('pageSize', kfPageSize);

        const res = await fetch('/api/admin/kernel-funcs/?' + params.toString());
        if (!res.ok) {
            tbody.innerHTML = `<tr><td colspan="8" class="text-center text-danger py-4">加载失败 (HTTP ${res.status})</td></tr>`;
            return;
        }
        const data = await res.json();

        if (!data.rows || data.rows.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted py-4">暂无函数记录</td></tr>';
        } else {
            tbody.innerHTML = data.rows.map(r => {
                const sev = String(r.severity || '').toLowerCase();
                const sevBadge = sev === 'high'   ? '<span class="badge bg-danger">高危</span>' :
                                 sev === 'medium' ? '<span class="badge bg-warning text-dark">中危</span>' :
                                 sev === 'low'    ? '<span class="badge bg-secondary">低危</span>' :
                                                    `<span class="badge bg-secondary">${escapeHtml(r.severity)}</span>`;
                const statusBadge = r.enabled
                    ? '<span class="badge bg-success">启用</span>'
                    : '<span class="badge bg-secondary">禁用</span>';
                return `
                <tr>
                    <td><code class="font-monospace">${escapeHtml(r.func_name)}</code></td>
                    <td><small>${escapeHtml(r.display_name || '-')}</small></td>
                    <td><small class="text-muted">${escapeHtml(r.category || '-')}</small></td>
                    <td>${sevBadge}</td>
                    <td>${statusBadge}</td>
                    <td><small class="text-muted">${formatKfTime(r.added_at)}</small></td>
                    <td><small class="text-muted">${escapeHtml(r.notes || '')}</small></td>
                    <td class="text-nowrap">
                        <button class="btn btn-outline-${r.enabled ? 'secondary' : 'success'} btn-sm py-0 px-1"
                                onclick="toggleKf('${r.id}', ${!r.enabled})"
                                title="${r.enabled ? '禁用' : '启用'}">
                            <i class="bi bi-${r.enabled ? 'pause' : 'play'}"></i>
                        </button>
                        <button class="btn btn-outline-danger btn-sm py-0 px-1" onclick="deleteKf('${r.id}')" title="删除">
                            <i class="bi bi-trash"></i>
                        </button>
                    </td>
                </tr>
                `;
            }).join('');
        }

        document.getElementById('kfPageInfo').textContent = `第 ${data.page} / ${Math.max(1, Math.ceil(data.total / kfPageSize))} 页,共 ${data.total} 条`;
        document.getElementById('kfPrev').disabled = data.page <= 1;
        document.getElementById('kfNext').disabled = data.page * kfPageSize >= data.total;
    } catch (e) {
        console.error('loadKfList:', e);
        tbody.innerHTML = `<tr><td colspan="8" class="text-center text-danger py-4">加载异常: ${escapeHtml(e.message)}</td></tr>`;
    }
}

function kfChangePage(delta) {
    kfPage = Math.max(1, kfPage + delta);
    loadKfList();
}

// ═══════════════════════════════════════════════════════════════
//  启用 / 禁用
// ═══════════════════════════════════════════════════════════════

async function toggleKf(id, enabled) {
    try {
        const res = await fetch(`/api/admin/kernel-funcs/${id}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: enabled })
        });
        const data = await res.json();
        if (data.success) {
            loadKfStats();
            loadKfList();
        } else {
            alert('操作失败: ' + (data.error || '未知错误'));
        }
    } catch (e) {
        alert('操作异常: ' + e.message);
    }
}

// ═══════════════════════════════════════════════════════════════
//  删除
// ═══════════════════════════════════════════════════════════════

async function deleteKf(id) {
    if (!confirm('确认删除该函数记录?')) return;
    try {
        const res = await fetch(`/api/admin/kernel-funcs/${id}`, { method: 'DELETE' });
        if (res.ok) {
            loadKfStats();
            loadKfList();
        } else {
            alert('删除失败: HTTP ' + res.status);
        }
    } catch (e) {
        alert('删除异常: ' + e.message);
    }
}

// ═══════════════════════════════════════════════════════════════
//  恢复默认
// ═══════════════════════════════════════════════════════════════

async function resetKfDefaults() {
    if (!confirm('确认清空所有函数记录,恢复为默认 4 个?\n\n默认:\n  MmCopyMemory\n  MmMapIoSpace\n  ZwMapViewOfSection\n  MmCopyVirtualMemory')) return;
    try {
        const res = await fetch('/api/admin/kernel-funcs/reset-defaults', { method: 'POST' });
        const data = await res.json();
        if (data.success) {
            alert('已恢复默认');
            loadKfStats();
            loadKfList();
        } else {
            alert('恢复失败: ' + (data.error || '未知错误'));
        }
    } catch (e) {
        alert('恢复异常: ' + e.message);
    }
}

// ═══════════════════════════════════════════════════════════════
//  添加
// ═══════════════════════════════════════════════════════════════

async function addKf() {
    const req = {
        func_name: document.getElementById('kfAddName').value.trim(),
        display_name: document.getElementById('kfAddDisplay').value.trim(),
        category: document.getElementById('kfAddCategory').value.trim(),
        severity: document.getElementById('kfAddSeverity').value,
        enabled: document.getElementById('kfAddEnabled').checked,
        notes: document.getElementById('kfAddNotes').value.trim()
    };
    const resultEl = document.getElementById('kfAddResult');
    resultEl.innerHTML = '<div class="text-muted small">添加中...</div>';

    try {
        const res = await fetch('/api/admin/kernel-funcs', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(req)
        });
        const data = await res.json();
        if (data.success) {
            resultEl.innerHTML = '<div class="alert alert-success">已添加 <i class="bi bi-check-circle"></i></div>';
            document.getElementById('kfAddName').value = '';
            document.getElementById('kfAddDisplay').value = '';
            document.getElementById('kfAddNotes').value = '';
            loadKfStats();
            loadKfList();
        } else {
            resultEl.innerHTML = `<div class="alert alert-danger">${escapeHtml(data.error || '添加失败')}</div>`;
        }
    } catch (e) {
        resultEl.innerHTML = `<div class="alert alert-danger">异常: ${escapeHtml(e.message)}</div>`;
    }
}

// ═══════════════════════════════════════════════════════════════
//  辅助
// ═══════════════════════════════════════════════════════════════

function formatKfTime(s) {
    if (!s) return '-';
    try {
        const d = new Date(s);
        return d.toLocaleString('zh-CN', { hour12: false });
    } catch { return s; }
}

function escapeHtml(s) {
    if (s == null) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
