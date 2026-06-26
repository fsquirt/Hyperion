/**
 * 驱动阻止列表 Dashboard
 */

// 状态变量(必须在任何调用前声明,避免 TDZ)
let blPage = 1;
const blPageSize = 50;
let blStats = null;

loadBlStats();
loadBlList();
loadBlSourceInfo();

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
            <td><code class="text-muted" style="font-size:0.72rem">${r.md5 ? r.md5.substring(0, 16) + '...' : '-'}</code></td>
            <td><code class="text-muted" style="font-size:0.72rem">${r.sha1 ? r.sha1.substring(0, 16) + '...' : '-'}</code></td>
            <td><code class="text-muted" style="font-size:0.72rem">${r.sha256 ? r.sha256.substring(0, 16) + '...' : '-'}</code></td>
            <td><small class="text-muted">${formatBlTime(r.added_at)}</small></td>
            <td>${r.source === 'manual'
                ? `<button class="btn btn-outline-danger btn-sm py-0 px-1" onclick="deleteBl('${r.id}')"><i class="bi bi-trash"></i></button>`
                : '-'}</td>
        </tr>
    `).join('');
}

function blSourceBadge(src) {
    if (src === 'loldriver') return '<span class="badge" style="background:rgba(168,85,247,0.15);color:#a855f7">LOLDrivers</span>';
    if (src === 'msft') return '<span class="badge" style="background:rgba(59,130,246,0.15);color:#3b82f6">MSFT</span>';
    if (src === 'manual') return '<span class="badge badge-fail">手动</span>';
    return `<span class="badge bg-secondary">${escHtml(src)}</span>`;
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
