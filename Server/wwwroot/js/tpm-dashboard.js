/**
 * TPM 远程验证 Dashboard
 */

// 动态加载时 DOMContentLoaded 已触发，直接执行
loadAll();
setInterval(loadAll, 30000);

async function loadAll() {
    await Promise.all([loadEkList(), loadAkList(), loadHistory(), loadConfig()]);
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
                <td><code class="text-dark" style="word-break:break-all">${ek.fingerprint || '-'}</code></td>
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
                <td><code class="text-dark" style="word-break:break-all">${ak.ak_name || '-'}</code></td>
                <td><code class="text-dark" style="word-break:break-all">${ak.ek_fingerprint || '-'}</code></td>
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

        if (historyData.length > 0) {
            const el = document.getElementById('lastResult');
            el.innerHTML = historyData[0].result === 'success'
                ? '<span>✓ 成功</span>'
                : '<span>✗ 失败</span>';
        }

        renderTpmHistoryTable(historyData);

        loadVbsHistory();
    } catch (e) { console.error('loadHistory:', e); }
}

function renderTpmHistoryTable(data) {
    const tbody = document.getElementById('historyTable');
    if (data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted py-4">暂无验证记录</td></tr>';
        return;
    }
    tbody.innerHTML = data.map((h, i) => `
        <tr style="cursor:pointer" onclick="showDetail(${historyData.indexOf(h)})">
            <td>${formatTime(h.timestamp)}</td>
            <td><code>${h.id}</code></td>
            <td><code class="text-dark" style="word-break:break-all">${h.ek_fingerprint || '-'}</code></td>
            <td>${badge(h.sig_valid)}</td>
            <td>${badge(h.magic_ok)}</td>
            <td>${badge(h.nonce_ok)}</td>
            <td>${badge(h.pcr_match)}</td>
            <td>${h.result === 'success'
                ? '<span class="badge badge-pass">通过</span>'
                : '<span class="badge badge-fail">失败</span>'}</td>
        </tr>
    `).join('');
}

async function filterTpmHistory() {
    const q = document.getElementById('tpmHistorySearch').value.trim();
    const url = q ? `/api/admin/history?q=${encodeURIComponent(q)}` : '/api/admin/history';
    try {
        const res = await fetch(url);
        if (!res.ok) return;
        const data = await res.json();
        renderTpmHistoryTable(data);
    } catch (e) { console.error('filterTpmHistory:', e); }
}

// ═══════════════════════════════════════════════════════════════
//  安全特性
// ═══════════════════════════════════════════════════════════════

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
            <td class="status-${f.status.toLowerCase().replace(' ', '')}" style="white-space:nowrap">${statusText(f.status)}</td>
            <td>
                <small>${f.evidence || '-'}</small>
                ${f.detail ? `<div class="text-muted" style="white-space:pre-wrap;font-size:.8em;margin-top:2px">${f.detail}</div>` : ''}
            </td>
        </tr>
    `).join('');

    document.getElementById('detailBody').innerHTML = `
        <div class="row mb-3">
            <div class="col-6"><strong>ID:</strong> ${h.id}</div>
            <div class="col-6"><strong>时间:</strong> ${formatTime(h.timestamp)}</div>
        </div>
        <div class="row mb-3">
            <div class="col-6"><strong>EK 指纹:</strong> <code style="word-break:break-all">${h.ek_fingerprint}</code></div>
            <div class="col-6"><strong>AK Name:</strong> <code style="word-break:break-all">${h.ak_name}</code></div>
        </div>
        <div class="row mb-3">
            <div class="col-3">${badge(h.sig_valid)} 签名</div>
            <div class="col-3">${badge(h.magic_ok)} Magic</div>
            <div class="col-3">${badge(h.nonce_ok)} Nonce</div>
            <div class="col-3">${badge(h.pcr_match)} PCR</div>
        </div>
        <h6 class="mt-4 mb-3">安全特性分析</h6>
        <table class="table table-sm">
            <colgroup><col style="width:30%"><col style="width:15%"><col></colgroup>
            <thead><tr><th>特性</th><th>状态</th><th>证据</th></tr></thead>
            <tbody>${featuresHtml || '<tr><td colspan="3" class="text-muted">无</td></tr>'}</tbody>
        </table>
    `;
    new bootstrap.Modal(document.getElementById('detailModal')).show();
}

// ═══════════════════════════════════════════════════════════════
//  工具
// ═══════════════════════════════════════════════════════════════

function badge(val) {
    return val
        ? '<span class="badge badge-pass"><i class="bi bi-check-lg"></i></span>'
        : '<span class="badge badge-fail"><i class="bi bi-x-lg"></i></span>';
}

function formatTime(iso) {
    if (!iso) return '-';
    try { return new Date(iso).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' }); }
    catch { return iso; }
}

// ═══════════════════════════════════════════════════════════════
//  VBS / HVCI 运行态检测，数据由 VBSRemoteDetect 客户端提交
// ═══════════════════════════════════════════════════════════════

// HTML 转义 — 提交材料中的驱动名/OEM/判定文案等来自客户端, 渲染前必须转义
// 目的在于防存储型 XSS: 即使验证 FAIL 的提交也会入库展示
function escHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

async function loadVbsHistory() {
    const tbody = document.getElementById('vbsHistoryTable');
    if (!tbody) return;
    try {
        const res = await fetch('/api/vbs/history');
        const items = await res.json();
        if (!items.length) {
            tbody.innerHTML = '<tr><td colspan="10" class="text-center text-muted py-4">暂无数据 — 等待 VBSRemoteDetect 客户端提交</td></tr>';
            return;
        }
        tbody.innerHTML = items.map(v => {
            const verdictLower = (v.verdict || '').toUpperCase();
            const cls = verdictLower.startsWith('PASS') ? 'status-Enabled'
                      : verdictLower.startsWith('FAIL') ? 'status-Disabled' : 'status-Unknown';
            const mark = ok => ok ? '<span class="badge bg-success">✔</span>' : '<span class="badge bg-danger">✘</span>';
            const cBadge = !v.report_present ? '<span class="badge bg-secondary">—未提交</span>'
                         : v.report_valid ? '<span class="badge bg-success">✔</span>'
                         : '<span class="badge bg-danger">✘</span>';
            const safeId = escHtml(v.id);
            return `<tr style="cursor:pointer" onclick="toggleVbsDetail('${safeId}', this)">
                <td>${escHtml(v.timestamp)}</td>
                <td><code>${safeId}</code></td>
                <td><code>${escHtml(v.client_ip || '-')}</code></td>
                <td title="方案A: NCryptVerifyClaim 远程验证 VBS Root Claim">${mark(v.claim_verified)}</td>
                <td title="方案D: PoP 签名，公钥取自 claim Attributes">${mark(v.pop_valid)}</td>
                <td title="方案C: GetRuntimeAttestationReport 运行时报告，可选">${cBadge}</td>
                <td>${v.nonce_match ? '<span class="badge bg-success">✓</span>' : '<span class="badge bg-danger">✗</span>'}</td>
                <td>${escHtml(v.driver_count)}</td>
                <td><span class="feature-status ${cls}">${escHtml(v.verdict)}</span></td>
                <td><i class="bi bi-chevron-down"></i></td>
            </tr><tr class="vbs-detail-row" data-id="${safeId}" style="display:none"><td colspan="10" class="bg-light"><div class="p-2"><span class="text-muted">加载中...</span></div></td></tr>`;
        }).join('');
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="10" class="text-danger py-3">加载失败: ${escHtml(e.message)}</td></tr>`;
    }
}

// 展开/收起单条详情，展开后展示全量驱动明细
async function toggleVbsDetail(id, tr) {
    const detailRow = tr.nextElementSibling;
    const box = detailRow.querySelector('div');
    if (detailRow.style.display !== 'none') { detailRow.style.display = 'none'; return; }
    detailRow.style.display = '';
    box.innerHTML = '<span class="text-muted">加载中...</span>';
    try {
        const res = await fetch(`/api/vbs/history/${encodeURIComponent(id)}`);
        const d = await res.json();
        if (d.error) { box.innerHTML = `<span class="text-danger">${escHtml(d.error)}</span>`; return; }

        const sc = d.schemes || {};
        // ASP.NET 序列化可能为 camelCase (a_claim_chain) 或原样 (A_claim_chain) — 双向兼容
        const scA = sc.A_claim_chain || sc.a_claim_chain || {};
        const scD = sc.D_pop_signature || sc.d_pop_signature || {};
        const scC = sc.C_runtime_report || sc.c_runtime_report || {};
        const scBadge = (ok, label) => ok === true ? `<span class="badge bg-success">方案${label} ✔</span>`
                        : `<span class="badge bg-danger">方案${label} ✘</span>`;
        const cInfo = scC;
        const cBadge = !cInfo.present ? '<span class="badge bg-secondary">方案C — 未提交</span>'
                     : cInfo.valid ? '<span class="badge bg-success">方案C ✔</span>'
                     : '<span class="badge bg-danger">方案C ✘</span>';

        const dr = d.driver_report || {};
        const drivers = dr.drivers || [];
        // result_json 可能是新数据的 camelCase 或旧库行的 PascalCase — 大小写兼容取值
        const gv = (o, ...keys) => { for (const k of keys) if (o && o[k] !== undefined && o[k] !== null) return o[k]; return ''; };
        const driverRows = drivers.map(dv => {
            const name = gv(dv, 'name', 'Name');
            const boot = gv(dv, 'boot', 'Boot');
            const unloaded = gv(dv, 'unloaded', 'Unloaded');
            const loadTimes = gv(dv, 'load_times', 'loadTimes', 'LoadTimes');
            const oem = gv(dv, 'oem', 'Oem');
            const imgHash = gv(dv, 'image_hash', 'imageHash', 'ImageHash');
            const pubHash = gv(dv, 'publisher_thumbprint', 'publisherThumbprint', 'PublisherThumbprint');
            return `<tr>
            <td><code>${escHtml(name)}</code></td>
            <td>${boot ? '<span class="badge bg-warning text-dark">Boot</span>' : '<span class="badge bg-light text-dark">Runtime</span>'}</td>
            <td>${unloaded ? '<span class="badge bg-info text-dark">Unloaded</span>' : ''}</td>
            <td>${escHtml(loadTimes)}</td>
            <td>${escHtml(oem)}</td>
            <td><small class="font-monospace text-muted">${escHtml(imgHash)}</small></td>
            <td><small class="font-monospace text-muted">${escHtml(pubHash)}</small></td>
        </tr>`;
        }).join('');

        box.innerHTML = `
            <div class="mb-2">
                ${scBadge(scA.verified, 'A')}
                ${scBadge(scD.valid, 'D')}
                ${cBadge}
                ${d.idks_fingerprint ? `<span class="badge bg-dark ms-2" title="IDKS 公钥指纹，取 SHA-256 前 16 字节，提取自 PCR12 VSMIDKSInfo 事件，即报告签名者">IDKS ${escHtml(d.idks_fingerprint)}</span>` : '<span class="badge bg-secondary ms-2">IDKS 未提交</span>'}
                ${d.tpm_history_id ? `<span class="badge bg-primary" title="已锚定 TPM 证明链 (EK→AK→AIK Quote)">TPM ${escHtml(d.tpm_history_id)}</span>` : ''}
                ${d.ak_name ? `<span class="badge bg-secondary">AK ${escHtml(d.ak_name)}</span>` : ''}
                <span class="badge bg-dark">Nonce ${d.hvci_runtime_report && d.hvci_runtime_report.nonceMatch ? '✓绑定' : '✗'}</span>
                <span class="badge bg-dark">Digest ${escHtml(dr.digest_verification || '-')}</span>
                <span class="badge bg-dark">${escHtml(dr.signature_scheme || '')}</span>
                <span class="badge bg-primary">驱动 ${escHtml(dr.count ?? 0)}，其中 Boot ${escHtml(dr.boot ?? 0)}，Unloaded ${escHtml(dr.unloaded ?? 0)}</span>
            </div>
            <div style="max-height:420px;overflow:auto">
                <table class="table table-sm table-striped table-hover mb-0" style="font-size:.85em">
                    <thead><tr><th>驱动名</th><th>类型</th><th>卸载</th><th>加载次数</th><th>OEM</th><th>镜像哈希</th><th>发布者指纹</th></tr></thead>
                    <tbody>${driverRows || '<tr><td colspan="7" class="text-muted">无驱动明细</td></tr>'}</tbody>
                </table>
            </div>`;
    } catch (e) {
        box.innerHTML = `<span class="text-danger">详情加载失败: ${escHtml(e.message)}</span>`;
    }
}
