/**
 * SiPolicy.p7b 策略 Dashboard
 */

loadSiPolicyInfo();

async function loadSiPolicyInfo() {
    try {
        const res = await fetch('/api/admin/sipolicy/');
        if (!res.ok) { showSpMsg('加载失败 (HTTP ' + res.status + ')', 'danger'); return; }
        const data = await res.json();

        document.getElementById('spEnabledSwitch').checked = !!data.enabled;

        const f = data.file || {};
        const exists = !!f.exists;
        document.getElementById('spFileExists').innerHTML = exists
            ? '<span class="badge bg-success">存在</span>'
            : '<span class="badge bg-danger">不存在</span>';
        document.getElementById('spFileSize').textContent = exists ? formatSpSize(f.size) : '-';
        document.getElementById('spFileModified').textContent = exists ? (f.last_modified || '-') : '-';
        document.getElementById('spFileMissing').classList.toggle('d-none', exists);
    } catch (e) {
        console.error('loadSiPolicyInfo:', e);
        showSpMsg('加载异常: ' + e.message, 'danger');
    }
}

async function setSiPolicyEnabled(enabled) {
    try {
        const res = await fetch('/api/admin/sipolicy/', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: enabled })
        });
        if (!res.ok) {
            showSpMsg('保存失败 (HTTP ' + res.status + ')', 'danger');
            document.getElementById('spEnabledSwitch').checked = !enabled;
            return;
        }
        showSpMsg(enabled ? '已开启:客户端将在游戏启动前更新 SiPolicy.p7b' : '已关闭', 'success');
    } catch (e) {
        console.error('setSiPolicyEnabled:', e);
        showSpMsg('保存异常: ' + e.message, 'danger');
        document.getElementById('spEnabledSwitch').checked = !enabled;
    }
}

function showSpMsg(text, type) {
    const el = document.getElementById('spMsg');
    el.className = 'alert alert-' + type;
    el.textContent = text;
    el.classList.remove('d-none');
    clearTimeout(el._spTimer);
    el._spTimer = setTimeout(() => el.classList.add('d-none'), 4000);
}

function formatSpSize(bytes) {
    if (bytes == null) return '-';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1024 / 1024).toFixed(2) + ' MB';
}
