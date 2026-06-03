/**
 * Dashboard 数据加载和展示
 */

// ═══════════════════════════════════════════════════════════════
//  初始化
// ═══════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
    loadAll();
    // 每 30 秒自动刷新
    setInterval(loadAll, 30000);
});

async function loadAll() {
    await Promise.all([
        loadEkList(),
        loadAkList(),
        loadHistory(),
        loadConfig()
    ]);
}

// ═══════════════════════════════════════════════════════════════
//  EK 列表
// ═══════════════════════════════════════════════════════════════

async function loadEkList() {
    try {
        const res = await fetch('/api/admin/ek-list');
        if (!res.ok) return;
        const data = await res.json();
        document.getElementById('ekCount').textContent = data.length;

        const tbody = document.getElementById('ekTable');
        if (data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="3" class="text-center text-muted py-3">暂无记录</td></tr>';
            return;
        }
        tbody.innerHTML = data.map(ek => `
            <tr>
                <td><code class="text-dark">${ek.fingerprint?.substring(0, 16)}...</code></td>
                <td>${ek.subject || '-'}</td>
                <td>${formatTime(ek.ts)}</td>
            </tr>
        `).join('');
    } catch (e) { console.error('loadEkList:', e); }
}

// ═══════════════════════════════════════════════════════════════
//  AK 列表
// ═══════════════════════════════════════════════════════════════

async function loadAkList() {
    try {
        const res = await fetch('/api/admin/ak-list');
        if (!res.ok) return;
        const data = await res.json();
        document.getElementById('akCount').textContent = data.length;

        const tbody = document.getElementById('akTable');
        if (data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="3" class="text-center text-muted py-3">暂无记录</td></tr>';
            return;
        }
        tbody.innerHTML = data.map(ak => `
            <tr>
                <td><code class="text-dark">${ak.ak_name?.substring(0, 16)}...</code></td>
                <td><code class="text-dark">${ak.ek_fingerprint?.substring(0, 16)}...</code></td>
                <td>${formatTime(ak.ts)}</td>
            </tr>
        `).join('');
    } catch (e) { console.error('loadAkList:', e); }
}

// ═══════════════════════════════════════════════════════════════
//  验证历史
// ═══════════════════════════════════════════════════════════════

let historyData = [];

async function loadHistory() {
    try {
        const res = await fetch('/api/admin/history');
        if (!res.ok) return;
        historyData = await res.json();
        document.getElementById('historyCount').textContent = historyData.length;

        // 更新"上次验证"
        if (historyData.length > 0) {
            const last = historyData[0];
            const el = document.getElementById('lastResult');
            el.innerHTML = last.result === 'success'
                ? '<span>✓ 成功</span>'
                : '<span>✗ 失败</span>';
        }

        const tbody = document.getElementById('historyTable');
        if (historyData.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted py-4">暂无验证记录</td></tr>';
            return;
        }
        tbody.innerHTML = historyData.map((h, i) => `
            <tr style="cursor:pointer" onclick="showDetail(${i})">
                <td>${formatTime(h.timestamp)}</td>
                <td><code>${h.id}</code></td>
                <td><code class="text-dark">${h.ek_fingerprint || '-'}</code></td>
                <td>${badge(h.sig_valid)}</td>
                <td>${badge(h.magic_ok)}</td>
                <td>${badge(h.nonce_ok)}</td>
                <td>${badge(h.pcr_match)}</td>
                <td>${h.result === 'success'
                    ? '<span class="badge badge-pass">通过</span>'
                    : '<span class="badge badge-fail">失败</span>'}</td>
            </tr>
        `).join('');

        // 更新安全特性面板
        if (historyData.length > 0) {
            renderFeatures(historyData[0].security_features || []);
        }
    } catch (e) { console.error('loadHistory:', e); }
}

// ═══════════════════════════════════════════════════════════════
//  安全特性
// ═══════════════════════════════════════════════════════════════

function renderFeatures(features) {
    const grid = document.getElementById('featuresGrid');
    if (!features || features.length === 0) {
        grid.innerHTML = '<div class="col-12 text-center text-muted py-4">暂无数据</div>';
        return;
    }

    const iconMap = {
        'Secure Boot': 'bi-shield-lock',
        'CPU Virtualization': 'bi-cpu',
        'IOMMU': 'bi-hdd-network',
        'HVCI': 'bi-layers',
        'Driver Signature': 'bi-file-earmark-check',
        'Vulnerable Driver': 'bi-ban',
        'Boot Log': 'bi-journal-check',
        'ELAM': 'bi-shield-exclamation',
        'DRTM': 'bi-arrow-repeat'
    };

    grid.innerHTML = features.map(f => {
        const statusClass = f.status.toLowerCase().replace(' ', '');
        const icon = Object.entries(iconMap).find(([k]) => f.name.includes(k))?.[1] || 'bi-question-circle';
        return `
        <div class="col-md-4 col-sm-6">
            <div class="feature-card">
                <div class="d-flex justify-content-between align-items-start">
                    <i class="bi ${icon} fs-4 text-muted"></i>
                    <span class="feature-status status-${statusClass}">${statusText(f.status)}</span>
                </div>
                <div class="feature-name">${f.name}</div>
                <div class="feature-evidence">${f.evidence || '无证据'}</div>
                ${f.detail ? `<div class="feature-evidence mt-1"><small>${f.detail}</small></div>` : ''}
            </div>
        </div>`;
    }).join('');
}

function statusText(status) {
    const map = { 'Enabled': '已启用', 'Disabled': '已禁用', 'Unknown': '未知', 'NotMeasured': '未测量' };
    return map[status] || status;
}

// ═══════════════════════════════════════════════════════════════
//  系统配置
// ═══════════════════════════════════════════════════════════════

async function loadConfig() {
    try {
        const res = await fetch('/api/admin/config');
        if (!res.ok) return;
        const cfg = await res.json();
        document.getElementById('configInfo').innerHTML = `
            <div class="col-md-6">
                <table class="table table-borderless">
                    <tr><td class="text-muted" style="width:180px">可信根证书目录</td><td><code>${cfg.trustedRootDir || '-'}</code></td></tr>
                    <tr><td class="text-muted">服务器域名</td><td>${cfg.serverDomain || '-'}</td></tr>
                    <tr><td class="text-muted">API 监听地址</td><td><code>${cfg.apiUrl || '-'}</code></td></tr>
                </table>
            </div>
        `;
    } catch (e) { console.error('loadConfig:', e); }
}

// ═══════════════════════════════════════════════════════════════
//  详情模态框
// ═══════════════════════════════════════════════════════════════

function showDetail(index) {
    const h = historyData[index];
    if (!h) return;

    const featuresHtml = (h.security_features || []).map(f => `
        <tr>
            <td>${f.name}</td>
            <td class="status-${f.status.toLowerCase().replace(' ', '')}">${statusText(f.status)}</td>
            <td><small>${f.evidence || '-'}</small></td>
        </tr>
    `).join('');

    document.getElementById('detailBody').innerHTML = `
        <div class="row mb-3">
            <div class="col-6"><strong>ID:</strong> ${h.id}</div>
            <div class="col-6"><strong>时间:</strong> ${formatTime(h.timestamp)}</div>
        </div>
        <div class="row mb-3">
            <div class="col-6"><strong>EK 指纹:</strong> <code>${h.ek_fingerprint}</code></div>
            <div class="col-6"><strong>AK Name:</strong> <code>${h.ak_name}</code></div>
        </div>
        <div class="row mb-3">
            <div class="col-3">${badge(h.sig_valid)} 签名</div>
            <div class="col-3">${badge(h.magic_ok)} Magic</div>
            <div class="col-3">${badge(h.nonce_ok)} Nonce</div>
            <div class="col-3">${badge(h.pcr_match)} PCR</div>
        </div>
        <h6 class="mt-4 mb-3">安全特性分析</h6>
        <table class="table table-sm">
            <thead><tr><th>特性</th><th>状态</th><th>证据</th></tr></thead>
            <tbody>${featuresHtml || '<tr><td colspan="3" class="text-muted">无</td></tr>'}</tbody>
        </table>
    `;

    new bootstrap.Modal(document.getElementById('detailModal')).show();
}

// ═══════════════════════════════════════════════════════════════
//  工具函数
// ═══════════════════════════════════════════════════════════════

function badge(val) {
    return val
        ? '<span class="badge badge-pass"><i class="bi bi-check-lg"></i></span>'
        : '<span class="badge badge-fail"><i class="bi bi-x-lg"></i></span>';
}

function formatTime(iso) {
    if (!iso) return '-';
    try {
        const d = new Date(iso);
        return d.toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
    } catch { return iso; }
}
