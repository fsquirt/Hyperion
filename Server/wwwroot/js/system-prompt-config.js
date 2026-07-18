/**
 * 大模型系统提示词配置
 */
(function () {
    const $exe = document.getElementById('sp-exe');
    const $sys = document.getElementById('sp-sys');
    const $updated = document.getElementById('sp-updated');
    const $status = document.getElementById('sp-status');
    const $save = document.getElementById('sp-save');

    function setStatus(msg, ok) {
        if (!msg) { $status.innerHTML = ''; return; }
        const cls = ok ? 'text-success' : 'text-danger';
        const icon = ok ? 'check-circle' : 'exclamation-triangle';
        $status.innerHTML = '<span class="' + cls + '"><i class="bi bi-' + icon + ' me-1"></i>' + msg + '</span>';
    }

    async function load() {
        try {
            const r = await fetch('/api/admin/settings');
            if (!r.ok) throw new Error('加载失败 (HTTP ' + r.status + ')');
            const d = await r.json();
            $exe.value = d.system_prompt_exe || '';
            $sys.value = d.system_prompt_sys || '';
            $updated.textContent = d.updated_at ? ('更新于 ' + d.updated_at) : '';
            setStatus('', true);
        } catch (e) {
            setStatus(e.message, false);
        }
    }

    $save.addEventListener('click', async () => {
        $save.disabled = true;
        try {
            const r = await fetch('/api/admin/settings', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    system_prompt_exe: $exe.value,
                    system_prompt_sys: $sys.value
                })
            });
            if (!r.ok) throw new Error('保存失败 (HTTP ' + r.status + ')');
            $updated.textContent = '更新于 ' + new Date().toISOString();
            setStatus('已保存,Agent 下一次分析将使用新提示词', true);
        } catch (e) {
            setStatus(e.message, false);
        } finally {
            $save.disabled = false;
        }
    });

    load();
})();
