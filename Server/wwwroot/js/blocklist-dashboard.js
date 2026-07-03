/**
 * 驱动阻止列表 Dashboard
 */

// 状态变量(必须在任何调用前声明,避免 TDZ)
let blPage = 1;
const blPageSize = 50;
let blStats = null;
let blRowsCache = [];      // 当前页行数据缓存,供编辑查找
let blEditingId = null;    // 当前编辑中的记录 ID
let blHistoryData = [];    // 验证历史数据缓存

loadBlStats();
loadBlList();
loadBlSourceInfo();
loadBlHistory();

// ═══════════════════════════════════════════════════════════════
//  统计
// ═══════════════════════════════════════════════════════════════

async function loadBlStats() {
    try {
        const res = await fetch('/api/admin/blocklist/stats');
        if (!res.ok) return;
        blStats = await res.json();
        document.getElementById('blStatTotal').textContent = blStats.total;
    } catch (e) { console.error('loadBlStats:', e); }
}

async function loadBlSourceInfo() {
    try {
        const res = await fetch('/api/admin/blocklist/stats');
        if (!res.ok) return;
        const s = await res.json();

        const lolEl = document.getElementById('blLolInfo');
        if (lolEl) {
            lolEl.innerHTML = `当前: <strong>${s.loldriver}</strong> 条` +
                (s.loldriver_updated_at ? ` | 更新: ${formatBlTime(s.loldriver_updated_at)}` : ' | 未导入');
        }
        const msftEl = document.getElementById('blMsftInfo');
        if (msftEl) {
            msftEl.innerHTML = `当前: <strong>${s.msft}</strong> 条` +
                (s.msft_updated_at ? ` | 更新: ${formatBlTime(s.msft_updated_at)}` : ' | 未导入');
        }
    } catch (e) { console.error('loadBlSourceInfo:', e); }
}

// ═══════════════════════════════════════════════════════════════
//  列表
// ═══════════════════════════════════════════════════════════════

async function loadBlList() {
    const source = document.getElementById('blSourceFilter').value;
    const search = document.getElementById('blSearch').value.trim();
    const tbody = document.getElementById('blTableBody');
    tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted py-4">加载中...</td></tr>';

    try {
        const params = new URLSearchParams({ page: blPage, pageSize: blPageSize });
        if (source) params.set('source', source);
        if (search) params.set('search', search);

        const res = await fetch('/api/admin/blocklist?' + params);
        if (!res.ok) { tbody.innerHTML = '<tr><td colspan="7" class="text-danger py-4">加载失败</td></tr>'; return; }
        const data = await res.json();

        blRowsCache = data.rows || [];
        renderBlTable(data.rows);
        document.getElementById('blPageInfo').textContent =
            `共 ${data.total} 条，第 ${data.page}/${Math.max(1, Math.ceil(data.total / blPageSize))} 页`;
        document.getElementById('blPrev').disabled = blPage <= 1;
        document.getElementById('blNext').disabled = blPage * blPageSize >= data.total;
    } catch (e) {
        console.error('loadBlList:', e);
        tbody.innerHTML = `<tr><td colspan="7" class="text-danger py-4">${e.message}</td></tr>`;
    }
}

function renderBlTable(rows) {
    const tbody = document.getElementById('blTableBody');
    if (!rows || rows.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted py-4">无数据</td></tr>';
        return;
    }
    tbody.innerHTML = rows.map(r => `
        <tr>
            <td>${blSourceBadge(r.source)}</td>
            <td><small>${escHtml(r.driver_name)}</small></td>
            <td><code class="text-muted" style="font-size:0.72rem;word-break:break-all">${r.md5 || '-'}</code></td>
            <td><code class="text-muted" style="font-size:0.72rem;word-break:break-all">${r.sha1 || '-'}</code></td>
            <td><code class="text-muted" style="font-size:0.72rem;word-break:break-all">${r.sha256 || '-'}</code></td>
            <td><small class="text-muted">${formatBlTime(r.added_at)}</small></td>
            <td class="text-nowrap">
                <button class="btn btn-outline-secondary btn-sm py-0 px-1" title="编辑"
                        onclick="editBl('${r.id}')"><i class="bi bi-pencil"></i></button>
                <button class="btn btn-outline-danger btn-sm py-0 px-1" title="删除"
                        onclick="deleteBl('${r.id}')"><i class="bi bi-trash"></i></button>
            </td>
        </tr>
    `).join('');
}

function blSourceBadge(src) {
    if (src === 'loldriver') return '<span class="badge" style="background:rgba(168,85,247,0.15);color:#a855f7">LOLDrivers</span>';
    if (src === 'msft') return '<span class="badge" style="background:rgba(59,130,246,0.15);color:#3b82f6">MSFT</span>';
    if (src === 'manual') return '<span class="badge badge-fail">手动</span>';
    return `<span class="badge bg-secondary">${escHtml(src)}</span>`;
}

// ═══════════════════════════════════════════════════════════════
//  验证历史
// ═══════════════════════════════════════════════════════════════

async function loadBlHistory() {
    const tbody = document.getElementById('blHistoryTable');
    if (!tbody) return;
    try {
        const res = await fetch('/api/admin/driver-history');
        if (!res.ok) { tbody.innerHTML = '<tr><td colspan="5" class="text-danger py-4">加载失败</td></tr>'; return; }
        blHistoryData = await res.json();
        renderBlHistoryTable(blHistoryData);
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="5" class="text-danger py-4">异常: ${e.message}</td></tr>`;
    }
}

function renderBlHistoryTable(data) {
    const tbody = document.getElementById('blHistoryTable');
    if (!data || data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-4">暂无校验记录</td></tr>';
        return;
    }
    tbody.innerHTML = data.map((h, i) => `
        <tr style="cursor:pointer" onclick="showBlHistoryDetail(${i})">
            <td><small>${formatBlTime(h.timestamp)}</small></td>
            <td><code>${escHtml(h.id || '-')}</code></td>
            <td>${h.client_driver_count}</td>
            <td>${h.blocked_count > 0
                ? '<span class="badge badge-fail">' + h.blocked_count + '</span>'
                : '<span class="badge badge-pass">0</span>'}</td>
            <td>${h.result === 'pass'
                ? '<span class="badge badge-pass">通过</span>'
                : '<span class="badge badge-fail">命中</span>'}</td>
        </tr>
    `).join('');
}

async function filterBlHistory() {
    const q = document.getElementById('blHistorySearch').value.trim();
    const url = q ? `/api/admin/driver-history?q=${encodeURIComponent(q)}` : '/api/admin/driver-history';
    try {
        const res = await fetch(url);
        if (!res.ok) return;
        blHistoryData = await res.json();
        renderBlHistoryTable(blHistoryData);
    } catch (e) { console.error('filterBlHistory:', e); }
}

function showBlHistoryDetail(index) {
    const h = blHistoryData[index];
    if (!h) return;

    // 优先使用 all_drivers（新数据），回退到 suspicious_drivers（旧数据兼容）
    const allDrivers = (h.all_drivers && h.all_drivers.length > 0) ? h.all_drivers : (h.suspicious_drivers || []);
    const blockedSet = new Set((h.suspicious_drivers || []).map(d => d.file_name + '|' + d.file_path));

    const driversHtml = `<div class="table-responsive" style="max-height:50vh;overflow:auto">
        <table class="table table-sm table-hover mb-0">
            <thead class="sticky-top bg-white"><tr>
                <th>驱动名</th>
                <th>文件路径</th>
                <th>SHA-256</th>
                <th>MD5</th>
                <th>证书名称</th>
                <th>证书签发机构</th>
            </tr></thead>
            <tbody>${allDrivers.map(d => {
                const key = d.file_name + '|' + d.file_path;
                const blocked = blockedSet.has(key);
                return `<tr class="${blocked ? 'table-danger' : ''}">
                    <td><small>${escHtml(d.file_name || '-')}</small>${blocked ? ' <span class="badge badge-fail" style="font-size:0.6rem">拉黑</span>' : ''}</td>
                    <td><code style="font-size:0.75rem;word-break:break-all">${escHtml(d.file_path || '-')}</code></td>
                    <td><code class="text-muted" style="font-size:0.72rem;word-break:break-all">${d.sha256 || '-'}</code></td>
                    <td><code class="text-muted" style="font-size:0.72rem;word-break:break-all">${d.md5 || '-'}</code></td>
                    <td><small>${escHtml(d.signer || '-')}</small></td>
                    <td><small>${escHtml(d.issuer || '-')}</small></td>
                </tr>`;
            }).join('')}</tbody>
        </table></div>`;

    document.getElementById('blHistoryDetailBody').innerHTML = `
        <div class="row mb-3">
            <div class="col-4"><strong>校验 ID:</strong> <code>${escHtml(h.id || '-')}</code></div>
            <div class="col-4"><strong>校验时间:</strong> ${formatBlTime(h.timestamp)}</div>
            <div class="col-4"><strong>结果:</strong> ${h.result === 'pass'
                ? '<span class="badge badge-pass">通过</span>'
                : '<span class="badge badge-fail">命中</span>'}</div>
        </div>
        <div class="row mb-3">
            <div class="col-6"><strong>客户端已加载驱动:</strong> ${h.client_driver_count} 个</div>
            <div class="col-6"><strong>命中拉黑列表:</strong> ${h.blocked_count} 个</div>
        </div>
        <h6 class="mt-4 mb-3">已加载驱动列表 <span class="text-muted small">（命中拉黑的驱动以<span class="text-danger">红色</span>标出）</span></h6>
        ${driversHtml}
    `;
    new bootstrap.Modal(document.getElementById('blHistoryDetailModal')).show();
}

function blChangePage(delta) {
    blPage = Math.max(1, blPage + delta);
    loadBlList();
}

async function deleteBl(id) {
    if (!confirm('确认删除此拉黑记录？')) return;
    try {
        const res = await fetch('/api/admin/blocklist/' + id, { method: 'DELETE' });
        if (res.ok) {
            loadBlList();
            loadBlStats();
        } else {
            alert('删除失败');
        }
    } catch (e) { alert('异常: ' + e.message); }
}

// ═══════════════════════════════════════════════════════════════
//  编辑
// ═══════════════════════════════════════════════════════════════

function editBl(id) {
    const r = blRowsCache.find(x => x.id === id);
    if (!r) { alert('记录数据未找到,请刷新列表'); return; }

    blEditingId = id;
    document.getElementById('blEditId').value = r.id;
    document.getElementById('blEditSource').textContent = blSourceBadge(r.source);
    document.getElementById('blEditDriverName').value = r.driver_name || '';
    document.getElementById('blEditMd5').value = r.md5 || '';
    document.getElementById('blEditSha1').value = r.sha1 || '';
    document.getElementById('blEditSha256').value = r.sha256 || '';
    document.getElementById('blEditNotes').value = r.notes || '';
    document.getElementById('blEditResult').innerHTML = '';

    new bootstrap.Modal(document.getElementById('blEditModal')).show();
}

async function submitEditBl() {
    if (!blEditingId) return;
    const btn = document.getElementById('blEditSubmit');
    const result = document.getElementById('blEditResult');

    const body = {
        driver_name: document.getElementById('blEditDriverName').value,
        md5: document.getElementById('blEditMd5').value,
        sha1: document.getElementById('blEditSha1').value,
        sha256: document.getElementById('blEditSha256').value,
        notes: document.getElementById('blEditNotes').value,
    };

    btn.disabled = true;
    btn.textContent = '保存中...';
    result.innerHTML = '';

    try {
        const res = await fetch('/api/admin/blocklist/' + encodeURIComponent(blEditingId), {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        const data = await res.json();

        if (data.success) {
            bootstrap.Modal.getInstance(document.getElementById('blEditModal')).hide();
            loadBlList();
            loadBlStats();
        } else {
            result.innerHTML = `<div class="alert alert-danger py-2 mb-0">${data.error || '保存失败'}</div>`;
        }
    } catch (e) {
        result.innerHTML = `<div class="alert alert-danger py-2 mb-0">异常: ${e.message}</div>`;
    } finally {
        btn.disabled = false;
        btn.textContent = '保存';
    }
}

// ═══════════════════════════════════════════════════════════════
//  手动按哈希添加
// ═══════════════════════════════════════════════════════════════

async function addByHash() {
    const name = document.getElementById('blHashName').value.trim();
    const md5 = document.getElementById('blHashMd5').value.trim();
    const sha1 = document.getElementById('blHashSha1').value.trim();
    const sha256 = document.getElementById('blHashSha256').value.trim();
    const notes = document.getElementById('blHashNotes').value.trim();
    const btn = document.getElementById('blHashBtn');
    const result = document.getElementById('blHashResult');

    if (!md5 && !sha1 && !sha256) {
        result.innerHTML = '<div class="alert alert-warning py-2">至少填写一个哈希</div>';
        return;
    }

    btn.disabled = true;
    btn.textContent = '提交中...';
    result.innerHTML = '';

    try {
        const res = await fetch('/api/admin/blocklist/add-hash', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                driver_name: name,
                md5: md5 || null,
                sha1: sha1 || null,
                sha256: sha256 || null,
                notes: notes || null,
            }),
        });
        const data = await res.json();

        if (data.success) {
            result.innerHTML = `<div class="alert alert-success py-2 mb-0">
                <i class="bi bi-check-circle me-1"></i>已拉黑 <strong>${escHtml(data.driver_name)}</strong>
                <table class="table table-sm table-borderless mt-2 mb-0">
                    <tr><td style="width:60px">MD5</td><td><code style="font-size:0.72rem">${data.md5 || '-'}</code></td></tr>
                    <tr><td>SHA1</td><td><code style="font-size:0.72rem">${data.sha1 || '-'}</code></td></tr>
                    <tr><td>SHA256</td><td><code style="font-size:0.72rem">${data.sha256 || '-'}</code></td></tr>
                </table>
            </div>`;
            document.getElementById('blHashName').value = '';
            document.getElementById('blHashMd5').value = '';
            document.getElementById('blHashSha1').value = '';
            document.getElementById('blHashSha256').value = '';
            document.getElementById('blHashNotes').value = '';
            loadBlList();
            loadBlStats();
        } else {
            result.innerHTML = `<div class="alert alert-danger py-2 mb-0">${data.error || '添加失败'}</div>`;
        }
    } catch (e) {
        result.innerHTML = `<div class="alert alert-danger py-2 mb-0">异常: ${e.message}</div>`;
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="bi bi-plus-circle me-1"></i>添加拉黑';
    }
}

// ═══════════════════════════════════════════════════════════════
//  更新源
// ═══════════════════════════════════════════════════════════════

async function updateLoldrivers(local) {
    const btn = document.getElementById('blLolBtn');
    const result = document.getElementById('blLolResult');
    btn.disabled = true;
    btn.textContent = '处理中...';
    result.innerHTML = '<div class="text-muted small"><span class="spinner-border spinner-border-sm me-1"></span>正在' + (local ? '解析本地' : '下载') + '...</div>';

    try {
        const url = '/api/admin/blocklist/update-loldrivers' + (local ? '?local=true' : '');
        const res = await fetch(url, { method: 'POST' });
        const data = await res.json();

        if (data.success) {
            result.innerHTML = `<div class="alert alert-success py-2 mb-0">
                <i class="bi bi-check-circle me-1"></i>更新成功:新增 <strong>${data.added}</strong> 条,移除旧 <strong>${data.removed}</strong> 条,总计 <strong>${data.total}</strong> 条
            </div>`;
            loadBlStats();
            loadBlSourceInfo();
            loadBlList();
        } else {
            result.innerHTML = `<div class="alert alert-danger py-2 mb-0">${data.error || '更新失败'}</div>`;
        }
    } catch (e) {
        result.innerHTML = `<div class="alert alert-danger py-2 mb-0">异常: ${e.message}</div>`;
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="bi bi-cloud-download me-1"></i>联网更新';
    }
}

async function updateMsft(local) {
    const btn = document.getElementById('blMsftBtn');
    const result = document.getElementById('blMsftResult');
    btn.disabled = true;
    btn.textContent = '处理中...';
    result.innerHTML = '<div class="text-muted small"><span class="spinner-border spinner-border-sm me-1"></span>正在' + (local ? '解析本地' : '下载解压') + '...</div>';

    try {
        const url = '/api/admin/blocklist/update-msft' + (local ? '?local=true' : '');
        const res = await fetch(url, { method: 'POST' });
        const data = await res.json();

        if (data.success) {
            result.innerHTML = `<div class="alert alert-success py-2 mb-0">
                <i class="bi bi-check-circle me-1"></i>更新成功:新增 <strong>${data.added}</strong> 条,移除旧 <strong>${data.removed}</strong> 条,总计 <strong>${data.total}</strong> 条
            </div>`;
            loadBlStats();
            loadBlSourceInfo();
            loadBlList();
        } else {
            result.innerHTML = `<div class="alert alert-danger py-2 mb-0">${data.error || '更新失败'}</div>`;
        }
    } catch (e) {
        result.innerHTML = `<div class="alert alert-danger py-2 mb-0">异常: ${e.message}</div>`;
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="bi bi-cloud-download me-1"></i>联网更新';
    }
}

// ═══════════════════════════════════════════════════════════════
//  手动上传
// ═══════════════════════════════════════════════════════════════

async function uploadSys() {
    const fileInput = document.getElementById('blUploadFile');
    const notesInput = document.getElementById('blUploadNotes');
    const btn = document.getElementById('blUploadBtn');
    const result = document.getElementById('blUploadResult');

    if (!fileInput.files || !fileInput.files[0]) {
        result.innerHTML = '<div class="alert alert-warning py-2">请选择文件</div>';
        return;
    }

    btn.disabled = true;
    btn.textContent = '计算中...';
    result.innerHTML = '<div class="text-muted small"><span class="spinner-border spinner-border-sm me-1"></span>正在计算哈希...</div>';

    try {
        const fd = new FormData();
        fd.append('file', fileInput.files[0]);
        if (notesInput.value.trim()) fd.append('notes', notesInput.value.trim());

        const res = await fetch('/api/admin/blocklist/upload-sys', { method: 'POST', body: fd });
        const data = await res.json();

        if (data.success) {
            result.innerHTML = `<div class="alert alert-success py-2 mb-0">
                <i class="bi bi-check-circle me-1"></i>已拉黑 <strong>${escHtml(data.driver_name)}</strong>
                <table class="table table-sm table-borderless mt-2 mb-0">
                    <tr><td style="width:60px">MD5</td><td><code style="font-size:0.72rem">${data.md5}</code></td></tr>
                    <tr><td>SHA1</td><td><code style="font-size:0.72rem">${data.sha1}</code></td></tr>
                    <tr><td>SHA256</td><td><code style="font-size:0.72rem">${data.sha256}</code></td></tr>
                </table>
            </div>`;
            fileInput.value = '';
            notesInput.value = '';
            loadBlStats();
            loadBlList();
        } else {
            result.innerHTML = `<div class="alert alert-danger py-2">${data.error || '拉黑失败'}</div>`;
        }
    } catch (e) {
        result.innerHTML = `<div class="alert alert-danger py-2">异常: ${e.message}</div>`;
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="bi bi-shield-x me-1"></i>计算哈希并拉黑';
    }
}

// ═══════════════════════════════════════════════════════════════
//  工具
// ═══════════════════════════════════════════════════════════════

function formatBlTime(iso) {
    if (!iso) return '-';
    try { return new Date(iso).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' }); }
    catch { return iso; }
}

function escHtml(s) {
    if (!s) return '';
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
