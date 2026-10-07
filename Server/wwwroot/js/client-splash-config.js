(function () {
    let currentConfig = { mode: 'specified', selectedImageId: null, images: [] };

    const galleryEl = document.getElementById('splash-gallery');
    const badgeEl = document.getElementById('splash-status-badge');
    const countTextEl = document.getElementById('image-count-text');
    const btnSaveMode = document.getElementById('btn-save-mode');
    const btnRefresh = document.getElementById('btn-refresh-splash');
    const formUpload = document.getElementById('form-upload-splash');
    const fileInput = document.getElementById('splashFileInput');
    const radioSpecified = document.getElementById('mode-specified');
    const radioRandom = document.getElementById('mode-random');

    async function loadConfig() {
        try {
            badgeEl.className = 'badge bg-secondary';
            badgeEl.textContent = '加载中...';
            const res = await fetch('/api/splash/config');
            if (!res.ok) throw new Error('HTTP ' + res.status);
            currentConfig = await res.json();
            render();
        } catch (err) {
            badgeEl.className = 'badge bg-danger';
            badgeEl.textContent = '加载失败: ' + err.message;
            galleryEl.innerHTML = `<div class="col-12 text-center text-danger py-4">加载配置失败: ${err.message}</div>`;
        }
    }

    function render() {
        if (currentConfig.mode === 'random') {
            radioRandom.checked = true;
            badgeEl.className = 'badge bg-warning text-dark';
            badgeEl.textContent = '当前模式: 随机返回';
        } else {
            radioSpecified.checked = true;
            badgeEl.className = 'badge bg-primary';
            badgeEl.textContent = '当前模式: 指定图片';
        }

        const images = currentConfig.images || [];
        countTextEl.textContent = `共 ${images.length} 张图片`;

        if (images.length === 0) {
            galleryEl.innerHTML = `
                <div class="col-12 text-center text-muted py-5">
                    <i class="bi bi-image" style="font-size: 3rem; opacity: 0.35;"></i>
                    <p class="mt-2 mb-0">暂无上传的背景图，请通过上方卡片上传</p>
                </div>`;
            return;
        }

        let html = '';
        images.forEach(img => {
            const isSelected = currentConfig.mode === 'specified' && currentConfig.selectedImageId === img.id;
            const sizeKb = (img.fileSizeBytes / 1024).toFixed(1);
            const uploadDate = new Date(img.uploadedAt).toLocaleString('zh-CN');

            html += `
                <div class="col-md-4 col-sm-6">
                    <div class="card h-100 position-relative ${isSelected ? 'border-primary shadow-sm' : ''}">
                        ${isSelected ? '<span class="badge bg-primary position-absolute top-0 end-0 m-2"><i class="bi bi-check-circle-fill me-1"></i>当前指定</span>' : ''}
                        <div style="height: 180px; overflow: hidden; background: #f8f9fa; display: flex; align-items: center; justify-content: center; border-bottom: 1px solid #dee2e6;">
                            <img src="/api/splash/image/${img.id}" alt="${img.originalFileName}" style="width: 100%; height: 100%; object-fit: cover;">
                        </div>
                        <div class="card-body p-3 d-flex flex-column justify-content-between">
                            <div>
                                <div class="fw-bold text-truncate mb-1" title="${img.originalFileName}">
                                    ${img.originalFileName}
                                </div>
                                <div class="text-muted small mb-2">
                                    <span>${sizeKb} KB</span> &bull; <span>${uploadDate}</span>
                                </div>
                            </div>
                            <div class="d-flex gap-2 mt-2">
                                ${!isSelected ? `
                                <button class="btn btn-outline-primary btn-sm flex-grow-1 btn-select" data-id="${img.id}">
                                    <i class="bi bi-pin-angle me-1"></i>设为指定
                                </button>` : `
                                <button class="btn btn-primary btn-sm flex-grow-1" disabled>
                                    <i class="bi bi-check2 me-1"></i>已指定
                                </button>`}
                                <button class="btn btn-outline-danger btn-sm btn-delete" data-id="${img.id}" title="删除">
                                    <i class="bi bi-trash"></i>
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        });

        galleryEl.innerHTML = html;

        // 绑定单项设置与删除事件
        document.querySelectorAll('.btn-select').forEach(btn => {
            btn.addEventListener('click', () => setSelectedImage(btn.getAttribute('data-id')));
        });

        document.querySelectorAll('.btn-delete').forEach(btn => {
            btn.addEventListener('click', () => deleteImage(btn.getAttribute('data-id')));
        });
    }

    async function saveMode() {
        const mode = radioRandom.checked ? 'random' : 'specified';
        try {
            btnSaveMode.disabled = true;
            btnSaveMode.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>保存中...';

            const res = await fetch('/api/splash/config', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ mode: mode, selectedImageId: currentConfig.selectedImageId })
            });

            if (!res.ok) throw new Error('HTTP ' + res.status);
            const data = await res.json();
            currentConfig = data.config;
            render();
            alert('模式配置已成功保存');
        } catch (err) {
            alert('保存失败: ' + err.message);
        } finally {
            btnSaveMode.disabled = false;
            btnSaveMode.innerHTML = '<i class="bi bi-check2-circle me-1"></i>保存模式配置';
        }
    }

    async function setSelectedImage(id) {
        try {
            const res = await fetch('/api/splash/config', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ mode: 'specified', selectedImageId: id })
            });
            if (!res.ok) throw new Error('HTTP ' + res.status);
            const data = await res.json();
            currentConfig = data.config;
            render();
        } catch (err) {
            alert('设置失败: ' + err.message);
        }
    }

    async function deleteImage(id) {
        if (!confirm('确定要删除此背景图吗？')) return;
        try {
            const res = await fetch(`/api/splash/${id}`, { method: 'DELETE' });
            if (!res.ok) throw new Error('HTTP ' + res.status);
            const data = await res.json();
            currentConfig = data.config;
            render();
        } catch (err) {
            alert('删除失败: ' + err.message);
        }
    }

    async function handleUpload(e) {
        e.preventDefault();
        const file = fileInput.files[0];
        if (!file) return;

        const formData = new FormData();
        formData.append('file', file);

        const btnUpload = document.getElementById('btn-upload');
        try {
            btnUpload.disabled = true;
            btnUpload.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>上传中...';

            const res = await fetch('/api/splash/upload', {
                method: 'POST',
                body: formData
            });

            const data = await res.json();
            if (!res.ok || !data.success) {
                throw new Error(data.error || 'HTTP ' + res.status);
            }

            fileInput.value = '';
            currentConfig = data.config;
            render();
            alert('背景图上传成功');
        } catch (err) {
            alert('上传失败: ' + err.message);
        } finally {
            btnUpload.disabled = false;
            btnUpload.innerHTML = '<i class="bi bi-upload me-1"></i>上传背景图';
        }
    }

    btnSaveMode.addEventListener('click', saveMode);
    btnRefresh.addEventListener('click', loadConfig);
    formUpload.addEventListener('submit', handleUpload);

    loadConfig();
})();
