/**
 * 附着白名单 Dashboard
 */

// 状态变量，必须在任何调用前声明，避免 TDZ
let wlPage = 1;
const wlPageSize = 50;
let wlRowsCache = [];

loadWlStats();
loadWlList();


//  统计
async function loadWlStats() {
    try {
        const res = await fetch('/api/admin/whitelist/stats');
        if (!res.ok) return;
        const s = await res.json();
        document.getElementById('wlStatTotal').textContent = s.total;
        document.getElementById('wlStatHash').textContent = s.hash_count;
        document.getElementById('wlStatCert').textContent = s.cert_count;
    } catch (e) { console.error('loadWlStats:', e); }
}


//  列表
async function loadWlList() {
    const type = document.getElementById('wlTypeFilter').value;
    const search = document.getElementById('wlSearch').value.trim();
    const tbody = document.getElementById('wlTableBody');
    tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted py-4">加载中...</td></tr>';

    try {
        const params = new URLSearchParams();
        if (type) params.set('type', type);
        if (search) params.set('search', search);
        params.set('page', wlPage);
        params.set('pageSize', wlPageSize);

        const res = await fetch('/api/admin/whitelist/?' + params.toString());
        if (!res.ok) {
            tbody.innerHTML = `<tr><td colspan="7" class="text-center text-danger py-4">加载失败 (HTTP ${res.status})</td></tr>`;
            return;
        }
        const data = await res.json();
        wlRowsCache = data.rows;

        if (!data.rows || data.rows.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted py-4">暂无白名单条目</td></tr>';
        } else {
            tbody.innerHTML = data.rows.map(r => {
                const isCert = String(r.type).toLowerCase() === 'cert';
                const typeBadge = isCert
                    ? '<span class="badge bg-info">证书</span>'
                    : '<span class="badge bg-secondary">哈希</span>';
                // SHA256 列:哈希条目显示文件 SHA256;证书条目显示证书指纹
                const shaCell = r.sha256
                    ? `<code class="font-monospace small text-break" style="word-break:break-all">${escapeHtml(r.sha256)}</code>`
                    : '-';
                // 证书 Subject 列:哈希条目无,显示 -
                const subjCell = r.cert_subject
                    ? `<small class="d-block text-break" style="word-break:break-all">${escapeHtml(r.cert_subject)}</small>`
                    : '-';
                return `
                <tr>
                    <td>${typeBadge}</td>
                    <td><small>${escapeHtml(r.display_name)}</small></td>
                    <td>${shaCell}</td>
                    <td>${subjCell}</td>
                    <td><small class="text-muted">${formatWlTime(r.added_at)}</small></td>
                    <td><small class="text-muted">${escapeHtml(r.notes || '')}</small></td>
                    <td class="text-nowrap">
                        <button class="btn btn-outline-danger btn-sm py-0 px-1" onclick="deleteWl('${r.id}')"><i class="bi bi-trash"></i></button>
                    </td>
                </tr>
                `;
            }).join('');
        }

        document.getElementById('wlPageInfo').textContent = `第 ${data.page} / ${Math.max(1, Math.ceil(data.total / wlPageSize))} 页,共 ${data.total} 条`;
        document.getElementById('wlPrev').disabled = data.page <= 1;
        document.getElementById('wlNext').disabled = data.page * wlPageSize >= data.total;
    } catch (e) {
        console.error('loadWlList:', e);
        tbody.innerHTML = `<tr><td colspan="7" class="text-center text-danger py-4">加载异常: ${escapeHtml(e.message)}</td></tr>`;
    }
}

function wlChangePage(delta) {
    wlPage = Math.max(1, wlPage + delta);
    loadWlList();
}


//  删除
async function deleteWl(id) {
    if (!confirm('确认删除该白名单条目?')) return;
    try {
        const res = await fetch(`/api/admin/whitelist/${id}`, { method: 'DELETE' });
        if (res.ok) {
            loadWlStats();
            loadWlList();
        } else {
            alert('删除失败: HTTP ' + res.status);
        }
    } catch (e) {
        alert('删除异常: ' + e.message);
    }
}


//  上传 sys 解析，核心是返回多签名让管理员选
async function uploadSysForParse() {
    const fileInput = document.getElementById('wlUploadFile');
    const file = fileInput.files[0];
    const resultEl = document.getElementById('wlUploadResult');
    const btn = document.getElementById('wlUploadBtn');

    if (!file) {
        resultEl.innerHTML = '<div class="alert alert-warning">请选择文件</div>';
        return;
    }

    btn.disabled = true;
    btn.innerHTML = '<i class="bi bi-hourglass-split me-1"></i>解析中...';
    resultEl.innerHTML = '<div class="text-muted small">正在上传并解析签名...</div>';

    try {
        const fd = new FormData();
        fd.append('file', file);

        const res = await fetch('/api/admin/whitelist/upload-sys', {
            method: 'POST',
            body: fd
        });
        const data = await res.json();

        if (!data.success) {
            resultEl.innerHTML = `<div class="alert alert-danger">解析失败: ${escapeHtml(data.error || '未知错误')}</div>`;
            return;
        }

        renderSysParseResult(data, resultEl);
    } catch (e) {
        resultEl.innerHTML = `<div class="alert alert-danger">异常: ${escapeHtml(e.message)}</div>`;
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="bi bi-search me-1"></i>解析文件';
    }
}

function renderSysParseResult(data, el) {
    let html = `
        <div class="card border-info">
            <div class="card-header bg-info text-white">
                <i class="bi bi-file-earmark-binary me-2"></i>${escapeHtml(data.file_name)}
                <span class="ms-2 small">${(data.file_size / 1024).toFixed(1)} KB</span>
            </div>
            <div class="card-body">
                <div class="mb-3">
                    <h6>文件哈希</h6>
                    <table class="table table-sm table-borderless mb-0">
                        <tr><td class="text-muted" style="width:80px">MD5</td><td class="font-monospace small">${data.md5 || '-'}</td></tr>
                        <tr><td class="text-muted">SHA1</td><td class="font-monospace small">${data.sha1 || '-'}</td></tr>
                        <tr><td class="text-muted">SHA256</td><td class="font-monospace small">${data.sha256 || '-'}</td></tr>
                    </table>
                </div>
                <div class="mb-2">
                    <h6>选择添加方式</h6>
                    <div class="d-flex flex-wrap gap-2 mb-3">
                        <button class="btn btn-success btn-sm" onclick='addHashFromUpload(${JSON.stringify(data).replace(/'/g, "&#39;")})'>
                            <i class="bi bi-hash me-1"></i>添加哈希到白名单
                        </button>
                    </div>
                    <div class="text-muted small mb-2">或者从下面的签名者证书中选择一个添加:</div>
    `;

    if (!data.signers || data.signers.length === 0) {
        html += '<div class="text-muted">无签名者证书</div>';
    } else {
        // 按类型分组展示,时间戳过滤掉
        const signers = data.signers.filter(s => s.tag !== 'Timestamp');
        if (signers.length === 0) {
            html += '<div class="text-muted">无有效签名者证书，只有时间戳签名</div>';
        } else {
            html += '<div class="list-group">';
            signers.forEach((s, i) => {
                const tagColor = s.tag === 'WHQL' ? 'primary' :
                                 s.tag === 'Microsoft' ? 'success' :
                                 s.tag === 'Vendor' ? 'warning' : 'secondary';
                html += `
                    <div class="list-group-item list-group-item-action d-flex justify-content-between align-items-start">
                        <div class="ms-2 me-auto">
                            <div class="fw-bold">
                                <span class="badge bg-${tagColor} me-2">${escapeHtml(s.tag)}</span>
                                ${escapeHtml(s.subject)}
                            </div>
                            <div class="text-muted small mt-1">Issuer: ${escapeHtml(s.issuer)}</div>
                            <div class="text-muted small">SHA256 指纹: <span class="font-monospace">${escapeHtml(s.thumbprint_sha256)}</span></div>
                        </div>
                        <button class="btn btn-outline-success btn-sm" onclick='addCertFromUpload(${JSON.stringify(s).replace(/'/g, "&#39;")})'>
                            <i class="bi bi-plus-circle me-1"></i>添加此证书
                        </button>
                    </div>
                `;
            });
            html += '</div>';
        }
    }

    html += `
            </div>
        </div>
    </div>
</div>
    `;
    el.innerHTML = html;
}

async function addHashFromUpload(parseData) {
    const req = {
        driver_name: parseData.file_name,
        md5: parseData.md5,
        sha1: parseData.sha1,
        sha256: parseData.sha256,
        notes: '上传 sys 添加'
    };
    const res = await fetch('/api/admin/whitelist/add-hash', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(req)
    });
    const data = await res.json();
    if (data.success) {
        alert('已添加哈希白名单');
        loadWlStats();
        loadWlList();
    } else {
        alert('添加失败: ' + (data.error || '未知错误'));
    }
}

async function addCertFromUpload(signer) {
    const req = {
        cert_subject: signer.subject,
        cert_thumbprint_sha256: signer.thumbprint_sha256,
        cert_issuer: signer.issuer,
        display_name: signer.tag === 'Vendor' ? signer.subject.split(',')[0].replace(/CN=/i, '').replace(/"/g, '').trim() : signer.tag,
        notes: '上传 sys 选择签名添加'
    };
    const res = await fetch('/api/admin/whitelist/add-cert', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(req)
    });
    const data = await res.json();
    if (data.success) {
        alert('已添加证书白名单');
        loadWlStats();
        loadWlList();
    } else {
        alert('添加失败: ' + (data.error || '未知错误'));
    }
}


//  按哈希添加
async function addByHash() {
    const req = {
        driver_name: document.getElementById('wlHashName').value.trim(),
        md5: document.getElementById('wlHashMd5').value.trim(),
        sha1: document.getElementById('wlHashSha1').value.trim(),
        sha256: document.getElementById('wlHashSha256').value.trim(),
        notes: document.getElementById('wlHashNotes').value.trim()
    };
    const resultEl = document.getElementById('wlHashResult');
    resultEl.innerHTML = '<div class="text-muted small">添加中...</div>';

    try {
        const res = await fetch('/api/admin/whitelist/add-hash', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(req)
        });
        const data = await res.json();
        if (data.success) {
            resultEl.innerHTML = '<div class="alert alert-success">已添加 <i class="bi bi-check-circle"></i></div>';
            document.getElementById('wlHashName').value = '';
            document.getElementById('wlHashMd5').value = '';
            document.getElementById('wlHashSha1').value = '';
            document.getElementById('wlHashSha256').value = '';
            document.getElementById('wlHashNotes').value = '';
            loadWlStats();
            loadWlList();
        } else {
            resultEl.innerHTML = `<div class="alert alert-danger">${escapeHtml(data.error || '添加失败')}</div>`;
        }
    } catch (e) {
        resultEl.innerHTML = `<div class="alert alert-danger">异常: ${escapeHtml(e.message)}</div>`;
    }
}


//  按证书添加
async function addByCert() {
    const req = {
        cert_subject: document.getElementById('wlCertSubject').value.trim(),
        cert_thumbprint_sha256: document.getElementById('wlCertThumbprint').value.trim(),
        cert_issuer: document.getElementById('wlCertIssuer').value.trim(),
        display_name: document.getElementById('wlCertDisplay').value.trim(),
        notes: document.getElementById('wlCertNotes').value.trim()
    };
    const resultEl = document.getElementById('wlCertResult');
    resultEl.innerHTML = '<div class="text-muted small">添加中...</div>';

    try {
        const res = await fetch('/api/admin/whitelist/add-cert', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(req)
        });
        const data = await res.json();
        if (data.success) {
            resultEl.innerHTML = '<div class="alert alert-success">已添加 <i class="bi bi-check-circle"></i></div>';
            document.getElementById('wlCertSubject').value = '';
            document.getElementById('wlCertThumbprint').value = '';
            document.getElementById('wlCertIssuer').value = '';
            document.getElementById('wlCertDisplay').value = '';
            document.getElementById('wlCertNotes').value = '';
            loadWlStats();
            loadWlList();
        } else {
            resultEl.innerHTML = `<div class="alert alert-danger">${escapeHtml(data.error || '添加失败')}</div>`;
        }
    } catch (e) {
        resultEl.innerHTML = `<div class="alert alert-danger">异常: ${escapeHtml(e.message)}</div>`;
    }
}


//  辅助
function formatWlTime(s) {
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
