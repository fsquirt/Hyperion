/**
 * 根证书验证 Dashboard
 */

// 动态加载时 DOMContentLoaded 已触发，直接执行
loadCertHistory();
loadCertCsv();
loadCertManageInfo();

// ═══════════════════════════════════════════════════════════════
//  校验历史
// ═══════════════════════════════════════════════════════════════

let certHistoryData = [];

async function loadCertHistory() {
    try {
        const res = await fetch('/api/admin/cert-history');
        if (!res.ok) { console.error('cert-history:', res.status); return; }
        certHistoryData = await res.json();

        const tbody = document.getElementById('certHistoryTable');
        if (certHistoryData.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-4">暂无校验记录</td></tr>';
            return;
        }
        tbody.innerHTML = certHistoryData.map((h, i) => `
            <tr style="cursor:pointer" onclick="showCertDetail(${i})">
                <td>${formatTime(h.timestamp)}</td>
                <td>${h.client_cert_count}</td>
                <td>${h.trusted_count}</td>
                <td>${h.suspicious_count > 0
                    ? '<span class="badge badge-fail">' + h.suspicious_count + '</span>'
                    : '<span class="badge badge-pass">0</span>'}</td>
                <td>${h.result === 'pass'
                    ? '<span class="badge badge-pass">通过</span>'
                    : '<span class="badge badge-fail">可疑</span>'}</td>
            </tr>
        `).join('');
    } catch (e) { console.error('loadCertHistory:', e); }
}

function showCertDetail(index) {
    const h = certHistoryData[index];
    if (!h) return;

    const certs = h.suspicious_certs || [];
    const certsHtml = certs.length > 0
        ? `<table class="table table-sm">
            <thead><tr><th>Subject</th><th>签发者</th><th>存储位置</th><th>SHA-256</th><th>有效期</th></tr></thead>
            <tbody>${certs.map(c => `
                <tr>
                    <td><small>${c.subject || '-'}</small></td>
                    <td><small>${c.issuer || '-'}</small></td>
                    <td><code>${c.store || '-'}</code></td>
                    <td><code class="text-muted">${(c.sha256 || '').substring(0, 24)}...</code></td>
                    <td><small>${formatTime(c.not_before)} ~ ${formatTime(c.not_after)}</small></td>
                </tr>
            `).join('')}</tbody>
           </table>`
        : '<p class="text-muted">无可疑证书</p>';

    document.getElementById('certDetailBody').innerHTML = `
        <div class="row mb-3">
            <div class="col-6"><strong>校验时间:</strong> ${formatTime(h.timestamp)}</div>
            <div class="col-6"><strong>结果:</strong> ${h.result === 'pass'
                ? '<span class="badge badge-pass">通过</span>'
                : '<span class="badge badge-fail">可疑</span>'}</div>
        </div>
        <div class="row mb-3">
            <div class="col-4"><strong>客户端证书:</strong> ${h.client_cert_count} 个</div>
            <div class="col-4"><strong>信任列表:</strong> ${h.trusted_count} 个</div>
            <div class="col-4"><strong>可疑证书:</strong> ${h.suspicious_count} 个</div>
        </div>
        <h6 class="mt-4 mb-3">不受信任的证书详情</h6>
        ${certsHtml}
    `;

    new bootstrap.Modal(document.getElementById('certDetailModal')).show();
}

// ═══════════════════════════════════════════════════════════════
//  证书浏览
// ═══════════════════════════════════════════════════════════════

let certCsvData = null;

async function loadCertCsv() {
    try {
        const res = await fetch('/api/admin/cert-csv');
        if (!res.ok) { console.error('cert-csv:', res.status); return; }
        certCsvData = await res.json();

        if (certCsvData.error) {
            document.getElementById('certCsvMeta').textContent = '错误: ' + certCsvData.error;
            return;
        }

        document.getElementById('certCsvMeta').textContent =
            `文件: ${certCsvData.path} | 更新时间: ${formatTime(certCsvData.last_modified)} | 共 ${certCsvData.total} 条`;

        renderCertTable(certCsvData.rows);
    } catch (e) { console.error('loadCertCsv:', e); }
}

function renderCertTable(rows) {
    const tbody = document.getElementById('certCsvBody');
    if (!rows || rows.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-4">无数据</td></tr>';
        return;
    }
    const display = rows.slice(0, 500);
    tbody.innerHTML = display.map(r => `
        <tr>
            <td><small>${r[0] || '-'}</small></td>
            <td><small>${r[1] || '-'}</small></td>
            <td><small>${r[2] || '-'}</small></td>
            <td><small class="text-muted">${truncate(r[3] || '-', 60)}</small></td>
            <td><code class="text-muted" style="font-size:0.75rem">${r[4] || '-'}</code></td>
            <td><code class="text-muted" style="font-size:0.75rem">${(r[5] || '-').substring(0, 24)}...</code></td>
        </tr>
    `).join('');
    if (rows.length > 500) {
        tbody.innerHTML += `<tr><td colspan="6" class="text-center text-muted py-2">显示前 500 条，共 ${rows.length} 条</td></tr>`;
    }
}

function filterCertTable() {
    if (!certCsvData) return;
    const q = document.getElementById('certSearch').value.toLowerCase();
    if (!q) { renderCertTable(certCsvData.rows); return; }
    const filtered = certCsvData.rows.filter(r => r.some(cell => (cell || '').toLowerCase().includes(q)));
    renderCertTable(filtered);
}

// ═══════════════════════════════════════════════════════════════
//  证书管理
// ═══════════════════════════════════════════════════════════════

async function loadCertManageInfo() {
    try {
        const res = await fetch('/api/admin/cert-csv');
        if (!res.ok) return;
        const data = await res.json();

        const info = document.getElementById('certManageInfo');
        if (data.error) { info.innerHTML = `<div class="text-danger">${data.error}</div>`; return; }
        info.innerHTML = `
            <table class="table table-borderless mb-0">
                <tr><td class="text-muted" style="width:120px">文件路径</td><td><code>${data.path}</code></td></tr>
                <tr><td class="text-muted">更新日期</td><td>${formatTime(data.last_modified)}</td></tr>
                <tr><td class="text-muted">证书条目</td><td>${data.total} 个</td></tr>
            </table>
        `;
    } catch (e) { console.error('loadCertManageInfo:', e); }
}

let pendingCsvContent = null;

async function syncCertCsv() {
    const btn = document.getElementById('syncBtn');
    const result = document.getElementById('syncResult');
    btn.disabled = true;
    btn.textContent = '同步中...';
    result.innerHTML = '';

    try {
        const res = await fetch('/api/admin/cert-csv-sync', { method: 'POST' });
        const data = await res.json();

        if (!data.success) {
            result.innerHTML = `<div class="alert alert-danger">同步失败: ${data.error}</div>`;
            return;
        }

        pendingCsvContent = data.content;

        document.getElementById('syncConfirmBody').innerHTML = `
            <div class="mb-3">
                <p><strong>旧列表:</strong> ${data.old_count} 个证书</p>
                <p><strong>新列表:</strong> ${data.new_count} 个证书</p>
            </div>
            <div class="alert ${data.added > 0 || data.removed > 0 ? 'alert-warning' : 'alert-success'}">
                <i class="bi bi-plus-circle me-1"></i>新增 <strong>${data.added}</strong> 个证书<br>
                <i class="bi bi-dash-circle me-1"></i>删除 <strong>${data.removed}</strong> 个证书
            </div>
            <p>是否需要替换当前 CSV 文件？</p>
        `;

        document.getElementById('syncConfirmBtn').onclick = applyCsv;
        new bootstrap.Modal(document.getElementById('syncConfirmModal')).show();
    } catch (e) {
        result.innerHTML = `<div class="alert alert-danger">异常: ${e.message}</div>`;
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="bi bi-cloud-download me-1"></i>一键同步';
    }
}

async function applyCsv() {
    bootstrap.Modal.getInstance(document.getElementById('syncConfirmModal')).hide();
    const result = document.getElementById('syncResult');

    try {
        const res = await fetch('/api/admin/cert-csv-apply', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content: pendingCsvContent })
        });
        const data = await res.json();

        if (data.success) {
            result.innerHTML = '<div class="alert alert-success"><i class="bi bi-check-circle me-1"></i>CSV 已更新，重启服务端后生效。</div>';
            pendingCsvContent = null;
            loadCertManageInfo();
        } else {
            result.innerHTML = `<div class="alert alert-danger">写入失败: ${data.error}</div>`;
        }
    } catch (e) {
        result.innerHTML = `<div class="alert alert-danger">异常: ${e.message}</div>`;
    }
}

// ═══════════════════════════════════════════════════════════════
//  工具
// ═══════════════════════════════════════════════════════════════

function formatTime(iso) {
    if (!iso) return '-';
    try { return new Date(iso).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' }); }
    catch { return iso; }
}

function truncate(str, len) {
    return str.length > len ? str.substring(0, len) + '...' : str;
}
