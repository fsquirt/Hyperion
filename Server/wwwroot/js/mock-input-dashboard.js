/**
 * 模拟键鼠策略 Dashboard
 */

loadMockInputInfo();

async function loadMockInputInfo() {
    try {
        const res = await fetch('/api/admin/mockinput/');
        if (!res.ok) { showMiMsg('加载失败 (HTTP ' + res.status + ')', 'danger'); return; }
        const data = await res.json();
        document.getElementById('miReportSwitch').checked = !!data.report;
        document.getElementById('miBlockSwitch').checked = !!data.block;
    } catch (e) {
        console.error('loadMockInputInfo:', e);
        showMiMsg('加载异常: ' + e.message, 'danger');
    }
}

async function setMockInput() {
    const report = document.getElementById('miReportSwitch').checked;
    const block = document.getElementById('miBlockSwitch').checked;
    try {
        const res = await fetch('/api/admin/mockinput/', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ report: report, block: block })
        });
        if (!res.ok) {
            showMiMsg('保存失败 (HTTP ' + res.status + ')', 'danger');
            loadMockInputInfo();
            return;
        }
        showMiMsg(report || block ? '已保存:客户端将安装全局钩子' : '已保存:客户端不安装全局钩子', 'success');
    } catch (e) {
        console.error('setMockInput:', e);
        showMiMsg('保存异常: ' + e.message, 'danger');
        loadMockInputInfo();
    }
}

function showMiMsg(text, type) {
    const el = document.getElementById('miMsg');
    el.className = 'alert alert-' + type;
    el.textContent = text;
    el.classList.remove('d-none');
    clearTimeout(el._miTimer);
    el._miTimer = setTimeout(() => el.classList.add('d-none'), 4000);
}
