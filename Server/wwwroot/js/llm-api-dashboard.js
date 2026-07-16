/**
 * 大模型 API 配置 + 访问凭据 Dashboard
 */

// ───────────────────────────────────────────────────────────────
//  状态变量(必须在任何调用前声明,避免 TDZ)
// ───────────────────────────────────────────────────────────────
let llmPage = 1;
const llmPageSize = 50;
let credPage = 1;
const credPageSize = 50;

// 初始加载
loadLlmStats();
loadLlmList();
loadCredStats();
loadCredList();

// ═══════════════════════════════════════════════════════════════
//  LLM API 列表
// ═══════════════════════════════════════════════════════════════

async function loadLlmStats() {
    try {
        const res = await fetch('/api/admin/llm-apis/stats');
        if (!res.ok) return;
        const s = await res.json();
        document.getElementById('llmStatTotal').textContent = s.total;
        document.getElementById('llmStatEnabled').textContent = s.enabled_count;
        document.getElementById('llmStatDisabled').textContent = s.disabled_count;
    } catch (e) { console.error('loadLlmStats:', e); }
}

async function loadLlmList() {
    const provider = document.getElementById('llmProviderFilter').value;
    const enabled = document.getElementById('llmEnabledFilter').value;
    const search = document.getElementById('llmSearch').value.trim();
    const tbody = document.getElementById('llmTableBody');
    tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted py-4">加载中...</td></tr>';

    try {
        const params = new URLSearchParams();
        if (provider) params.set('provider', provider);
        if (enabled) params.set('enabled', enabled);
        if (search) params.set('search', search);
        params.set('page', llmPage);
        params.set('pageSize', llmPageSize);

        const res = await fetch('/api/admin/llm-apis/?' + params.toString());
        if (!res.ok) {
            tbody.innerHTML = `<tr><td colspan="8" class="text-center text-danger py-4">加载失败 (HTTP ${res.status})</td></tr>`;
            return;
        }
        const data = await res.json();

        if (!data.rows || data.rows.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted py-4">暂无 API 配置,请到"添加 API"页签添加</td></tr>';
        } else {
            tbody.innerHTML = data.rows.map(r => {
                const providerBadge = {
                    'openai': '<span class="badge bg-success">OpenAI</span>',
                    'anthropic': '<span class="badge bg-warning text-dark">Anthropic</span>',
                    'deepseek': '<span class="badge bg-info">DeepSeek</span>',
                    'qwen': '<span class="badge bg-primary">通义千问</span>',
                    'custom': '<span class="badge bg-secondary">自定义</span>'
                }[r.provider] || `<span class="badge bg-secondary">${escapeHtml(r.provider)}</span>`;

                const statusBadge = r.enabled
                    ? '<span class="badge bg-success">启用</span>'
                    : '<span class="badge bg-secondary">禁用</span>';

                return `
                <tr>
                    <td><small>${escapeHtml(r.name)}</small></td>
                    <td>${providerBadge}</td>
                    <td><code class="small">${escapeHtml(r.model_name)}</code></td>
                    <td><small class="text-muted text-break" style="word-break:break-all;max-width:200px;display:inline-block">${escapeHtml(r.base_url)}</small></td>
                    <td><code class="small font-monospace">${escapeHtml(r.api_key_masked)}</code></td>
                    <td><small>${r.priority}</small></td>
                    <td>${statusBadge}</td>
                    <td class="text-nowrap">
                        <button class="btn btn-outline-primary btn-sm py-0 px-1" onclick="testLlmApi('${r.id}')" title="测试 API">
                            <i class="bi bi-lightning"></i>
                        </button>
                        <button class="btn btn-outline-${r.enabled ? 'warning' : 'success'} btn-sm py-0 px-1" onclick="toggleLlmApi('${r.id}', ${!r.enabled})" title="${r.enabled ? '禁用' : '启用'}">
                            <i class="bi bi-${r.enabled ? 'pause' : 'play'}"></i>
                        </button>
                        <button class="btn btn-outline-danger btn-sm py-0 px-1" onclick="deleteLlmApi('${r.id}')"><i class="bi bi-trash"></i></button>
                    </td>
                </tr>`;
            }).join('');
        }

        document.getElementById('llmPageInfo').textContent = `第 ${data.page} / ${Math.max(1, Math.ceil(data.total / llmPageSize))} 页,共 ${data.total} 条`;
        document.getElementById('llmPrev').disabled = data.page <= 1;
        document.getElementById('llmNext').disabled = data.page * llmPageSize >= data.total;
    } catch (e) {
        console.error('loadLlmList:', e);
        tbody.innerHTML = `<tr><td colspan="8" class="text-center text-danger py-4">加载异常: ${escapeHtml(e.message)}</td></tr>`;
    }
}

function llmChangePage(delta) {
    llmPage = Math.max(1, llmPage + delta);
    loadLlmList();
}

async function toggleLlmApi(id, enable) {
    try {
        const res = await fetch(`/api/admin/llm-apis/${id}?enabled=${enable}`, { method: 'PUT' });
        const data = await res.json();
        if (data.success) {
            loadLlmStats();
            loadLlmList();
        } else {
            alert('操作失败: ' + (data.error || '未知错误'));
        }
    } catch (e) {
        alert('操作异常: ' + e.message);
    }
}

async function deleteLlmApi(id) {
    if (!confirm('确认删除该 API 配置?')) return;
    try {
        const res = await fetch(`/api/admin/llm-apis/${id}`, { method: 'DELETE' });
        if (res.ok) {
            loadLlmStats();
            loadLlmList();
        } else {
            alert('删除失败: HTTP ' + res.status);
        }
    } catch (e) {
        alert('删除异常: ' + e.message);
    }
}

async function testLlmApi(id) {
    const resultEl = document.getElementById('testApiResult');
    resultEl.innerHTML = '<div class="text-muted"><span class="spinner-border spinner-border-sm me-1"></span>正在发送测试请求...</div>';
    const modal = new bootstrap.Modal(document.getElementById('testApiModal'));
    modal.show();

    try {
        const res = await fetch(`/api/admin/llm-apis/${id}/test`, { method: 'POST' });
        const data = await res.json();
        if (data.success) {
            resultEl.innerHTML =
                '<div class="alert alert-success"><i class="bi bi-check-circle me-1"></i>测试成功,大模型回复:</div>' +
                '<pre class="bg-dark text-light p-3 rounded small mt-2" style="white-space:pre-wrap;word-break:break-word"><code>' + escapeHtml(data.response) + '</code></pre>';
        } else {
            resultEl.innerHTML =
                '<div class="alert alert-danger"><i class="bi bi-x-circle me-1"></i>测试失败: ' + escapeHtml(data.error || '未知错误') + '</div>' +
                (data.response ? '<pre class="bg-dark text-light p-3 rounded small mt-2" style="white-space:pre-wrap;word-break:break-word"><code>' + escapeHtml(data.response) + '</code></pre>' : '');
        }
    } catch (e) {
        resultEl.innerHTML = '<div class="alert alert-danger">异常: ' + escapeHtml(e.message) + '</div>';
    }
}

// ═══════════════════════════════════════════════════════════════
//  添加 LLM API
// ═══════════════════════════════════════════════════════════════

async function addLlmApi() {
    const req = {
        name: document.getElementById('llmAddName').value.trim(),
        provider: document.getElementById('llmAddProvider').value,
        base_url: document.getElementById('llmAddUrl').value.trim(),
        api_key: document.getElementById('llmAddKey').value.trim(),
        model_name: document.getElementById('llmAddModel').value.trim(),
        enabled: document.getElementById('llmAddEnabled').checked,
        priority: parseInt(document.getElementById('llmAddPriority').value) || 100,
        max_tokens: parseInt(document.getElementById('llmAddMaxTokens').value) || 4096,
        temperature: parseFloat(document.getElementById('llmAddTemp').value) || 0.7,
        notes: document.getElementById('llmAddNotes').value.trim()
    };
    const resultEl = document.getElementById('llmAddResult');
    resultEl.innerHTML = '<div class="text-muted small">添加中...</div>';

    try {
        const res = await fetch('/api/admin/llm-apis/', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(req)
        });
        const data = await res.json();
        if (data.success) {
            resultEl.innerHTML = '<div class="alert alert-success">已添加 <i class="bi bi-check-circle"></i></div>';
            // 清空表单
            document.getElementById('llmAddName').value = '';
            document.getElementById('llmAddUrl').value = '';
            document.getElementById('llmAddKey').value = '';
            document.getElementById('llmAddModel').value = '';
            document.getElementById('llmAddNotes').value = '';
            loadLlmStats();
            loadLlmList();
        } else {
            resultEl.innerHTML = `<div class="alert alert-danger">${escapeHtml(data.error || '添加失败')}</div>`;
        }
    } catch (e) {
        resultEl.innerHTML = `<div class="alert alert-danger">异常: ${escapeHtml(e.message)}</div>`;
    }
}

// ═══════════════════════════════════════════════════════════════
//  访问凭据
// ═══════════════════════════════════════════════════════════════

async function loadCredStats() {
    try {
        const res = await fetch('/api/admin/llm-apis/credentials/stats');
        if (!res.ok) return;
        const s = await res.json();
        document.getElementById('credStatTotal').textContent = s.total;
        document.getElementById('credStatEnabled').textContent = s.enabled_count;
        document.getElementById('credStatDisabled').textContent = s.disabled_count;
    } catch (e) { console.error('loadCredStats:', e); }
}

async function loadCredList() {
    const enabled = document.getElementById('credEnabledFilter').value;
    const search = document.getElementById('credSearch').value.trim();
    const tbody = document.getElementById('credTableBody');
    tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted py-4">加载中...</td></tr>';

    try {
        const params = new URLSearchParams();
        if (enabled) params.set('enabled', enabled);
        if (search) params.set('search', search);
        params.set('page', credPage);
        params.set('pageSize', credPageSize);

        const res = await fetch('/api/admin/llm-apis/credentials?' + params.toString());
        if (!res.ok) {
            tbody.innerHTML = `<tr><td colspan="7" class="text-center text-danger py-4">加载失败 (HTTP ${res.status})</td></tr>`;
            return;
        }
        const data = await res.json();

        if (!data.rows || data.rows.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted py-4">暂无凭据,点"创建凭据"按钮生成</td></tr>';
        } else {
            tbody.innerHTML = data.rows.map(r => {
                const statusBadge = r.enabled
                    ? '<span class="badge bg-success">启用</span>'
                    : '<span class="badge bg-secondary">禁用</span>';
                return `
                <tr>
                    <td><small>${escapeHtml(r.name)}</small></td>
                    <td><code class="small font-monospace">${escapeHtml(r.token_masked)}</code></td>
                    <td>${statusBadge}</td>
                    <td><small class="text-muted">${formatCredTime(r.created_at)}</small></td>
                    <td><small class="text-muted">${r.last_used_at ? formatCredTime(r.last_used_at) : '从未使用'}</small></td>
                    <td><small class="text-muted">${escapeHtml(r.notes || '')}</small></td>
                    <td class="text-nowrap">
                        <button class="btn btn-outline-${r.enabled ? 'warning' : 'success'} btn-sm py-0 px-1" onclick="toggleCred('${r.id}', ${!r.enabled})" title="${r.enabled ? '禁用' : '启用'}">
                            <i class="bi bi-${r.enabled ? 'pause' : 'play'}"></i>
                        </button>
                        <button class="btn btn-outline-danger btn-sm py-0 px-1" onclick="deleteCred('${r.id}')"><i class="bi bi-trash"></i></button>
                    </td>
                </tr>`;
            }).join('');
        }

        document.getElementById('credPageInfo').textContent = `第 ${data.page} / ${Math.max(1, Math.ceil(data.total / credPageSize))} 页,共 ${data.total} 条`;
        document.getElementById('credPrev').disabled = data.page <= 1;
        document.getElementById('credNext').disabled = data.page * credPageSize >= data.total;
    } catch (e) {
        console.error('loadCredList:', e);
        tbody.innerHTML = `<tr><td colspan="7" class="text-center text-danger py-4">加载异常: ${escapeHtml(e.message)}</td></tr>`;
    }
}

function credChangePage(delta) {
    credPage = Math.max(1, credPage + delta);
    loadCredList();
}

async function toggleCred(id, enable) {
    try {
        const res = await fetch(`/api/admin/llm-apis/credentials/${id}?enabled=${enable}`, { method: 'PUT' });
        const data = await res.json();
        if (data.success) {
            loadCredStats();
            loadCredList();
        } else {
            alert('操作失败: ' + (data.error || '未知错误'));
        }
    } catch (e) {
        alert('操作异常: ' + e.message);
    }
}

async function deleteCred(id) {
    if (!confirm('确认删除该凭据?删除后使用此 token 的集群机器将无法获取 API 配置。')) return;
    try {
        const res = await fetch(`/api/admin/llm-apis/credentials/${id}`, { method: 'DELETE' });
        if (res.ok) {
            loadCredStats();
            loadCredList();
        } else {
            alert('删除失败: HTTP ' + res.status);
        }
    } catch (e) {
        alert('删除异常: ' + e.message);
    }
}

// ═══════════════════════════════════════════════════════════════
//  创建凭据 Modal
// ═══════════════════════════════════════════════════════════════

function showCreateCredModal() {
    document.getElementById('credAddName').value = '';
    document.getElementById('credAddEnabled').checked = true;
    document.getElementById('credAddNotes').value = '';
    document.getElementById('credAddResult').innerHTML = '';
    const modal = new bootstrap.Modal(document.getElementById('createCredModal'));
    modal.show();
}

async function createCred() {
    const req = {
        name: document.getElementById('credAddName').value.trim(),
        enabled: document.getElementById('credAddEnabled').checked,
        notes: document.getElementById('credAddNotes').value.trim()
    };
    const resultEl = document.getElementById('credAddResult');

    if (!req.name) {
        resultEl.innerHTML = '<div class="alert alert-warning">凭据名不能为空</div>';
        return;
    }

    resultEl.innerHTML = '<div class="text-muted small">创建中...</div>';

    try {
        const res = await fetch('/api/admin/llm-apis/credentials', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(req)
        });
        const data = await res.json();
        if (data.success) {
            // 显示完整 token(仅此一次)
            resultEl.innerHTML = `
                <div class="alert alert-success">
                    <i class="bi bi-check-circle me-1"></i>凭据已创建<br>
                    <label class="form-label small mt-2">完整 Token(仅显示一次,请立即保存):</label>
                    <div class="input-group">
                        <input type="text" class="form-control font-monospace small" id="newTokenField" value="${escapeHtml(data.token)}" readonly>
                        <button class="btn btn-outline-secondary btn-sm" onclick="copyNewToken()"><i class="bi bi-clipboard"></i>复制</button>
                    </div>
                </div>`;
            loadCredStats();
            loadCredList();
        } else {
            resultEl.innerHTML = `<div class="alert alert-danger">${escapeHtml(data.error || '创建失败')}</div>`;
        }
    } catch (e) {
        resultEl.innerHTML = `<div class="alert alert-danger">异常: ${escapeHtml(e.message)}</div>`;
    }
}

function copyNewToken() {
    const field = document.getElementById('newTokenField');
    field.select();
    navigator.clipboard.writeText(field.value).then(() => {
        alert('Token 已复制到剪贴板');
    }).catch(() => {
        document.execCommand('copy');
        alert('Token 已复制');
    });
}

// ═══════════════════════════════════════════════════════════════
//  辅助
// ═══════════════════════════════════════════════════════════════

function formatCredTime(s) {
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
