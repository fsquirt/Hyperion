/**
 * 保护能力策略 Dashboard
 */

loadProtectInfo();

async function loadProtectInfo() {
    try {
        const res = await fetch('/api/admin/protect/');
        if (!res.ok) { showPtMsg('加载失败 (HTTP ' + res.status + ')', 'danger'); return; }
        const d = await res.json();
        document.getElementById('ptHandleDowngrade').checked = !!d.handle_downgrade;
        document.getElementById('ptImageLoad').checked = !!d.image_load_monitor;
        document.getElementById('ptThreadAntiDebug').checked = !!d.thread_anti_debug;
        document.getElementById('ptHideExisting').checked = !!d.hide_existing_threads;
        document.getElementById('ptDropHandles').checked = !!d.drop_handles;
    } catch (e) {
        console.error('loadProtectInfo:', e);
        showPtMsg('加载异常: ' + e.message, 'danger');
    }
}

async function setProtect() {
    const body = {
        handle_downgrade: document.getElementById('ptHandleDowngrade').checked,
        image_load_monitor: document.getElementById('ptImageLoad').checked,
        thread_anti_debug: document.getElementById('ptThreadAntiDebug').checked,
        hide_existing_threads: document.getElementById('ptHideExisting').checked,
        drop_handles: document.getElementById('ptDropHandles').checked
    };
    try {
        const res = await fetch('/api/admin/protect/', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        if (!res.ok) {
            showPtMsg('保存失败 (HTTP ' + res.status + ')', 'danger');
            loadProtectInfo();
            return;
        }
        const on = ['handle_downgrade', 'image_load_monitor', 'thread_anti_debug', 'hide_existing_threads', 'drop_handles']
            .filter(k => body[k]).length;
        showPtMsg(on === 0 ? '已保存:不施加任何进程保护' : '已保存:启用 ' + on + ' 项保护', 'success');
    } catch (e) {
        console.error('setProtect:', e);
        showPtMsg('保存异常: ' + e.message, 'danger');
        loadProtectInfo();
    }
}

function showPtMsg(text, type) {
    const el = document.getElementById('ptMsg');
    el.className = 'alert alert-' + type;
    el.textContent = text;
    el.classList.remove('d-none');
    clearTimeout(el._ptTimer);
    el._ptTimer = setTimeout(() => el.classList.add('d-none'), 4000);
}
