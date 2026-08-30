/**
 * 启动权限策略 Dashboard
 */

loadLaunchInfo();

async function loadLaunchInfo() {
    try {
        const res = await fetch('/api/admin/launch/');
        if (!res.ok) { showLmMsg('加载失败 (HTTP ' + res.status + ')', 'danger'); return; }
        const data = await res.json();
        // 未知值/缺省一律按 explorer 显示(与服务端默认一致)
        const mode = data.mode === 'inherit' ? 'inherit' : 'explorer';
        document.getElementById('lmInherit').checked = (mode === 'inherit');
        document.getElementById('lmExplorer').checked = (mode === 'explorer');
    } catch (e) {
        console.error('loadLaunchInfo:', e);
        showLmMsg('加载异常: ' + e.message, 'danger');
    }
}

async function setLaunchMode(mode) {
    try {
        const res = await fetch('/api/admin/launch/', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ mode: mode })
        });
        if (!res.ok) {
            showLmMsg('保存失败 (HTTP ' + res.status + ')', 'danger');
            loadLaunchInfo();
            return;
        }
        showLmMsg(mode === 'explorer'
            ? '已保存:游戏将以 explorer 权限(标准用户令牌)启动'
            : '已保存:游戏将继承管理员权限启动', 'success');
    } catch (e) {
        console.error('setLaunchMode:', e);
        showLmMsg('保存异常: ' + e.message, 'danger');
        loadLaunchInfo();
    }
}

function showLmMsg(text, type) {
    const el = document.getElementById('lmMsg');
    el.className = 'alert alert-' + type;
    el.textContent = text;
    el.classList.remove('d-none');
    clearTimeout(el._lmTimer);
    el._lmTimer = setTimeout(() => el.classList.add('d-none'), 4000);
}
