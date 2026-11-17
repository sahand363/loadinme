// LoadInMe web UI: file list (Explorer style), clips, drag & drop,
// per-file upload progress, Ctrl+V to clip, settings modal.
(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const fileList = $('fileList'), clipList = $('clipList'), progressArea = $('progressArea');

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, (c) =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }
  function fmtSize(n) {
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    if (n < 1024 * 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + ' MB';
    return (n / 1024 / 1024 / 1024).toFixed(2) + ' GB';
  }
  function fmtTime(t) { return new Date(t).toLocaleString(); }
  function expiryBadge(it) {
    if (it.keepForever || !it.expiresAt) return '<span class="badge forever">Forever</span>';
    const ms = new Date(it.expiresAt) - Date.now();
    if (ms <= 0) return '<span class="badge soon">Expired</span>';
    const h = Math.floor(ms / 3600000), m = Math.floor((ms % 3600000) / 60000);
    const cls = ms < 3600000 ? ' soon' : '';
    const txt = h >= 1 ? h + 'h ' + m + 'm left' : m + 'm left';
    return '<span class="badge' + cls + '">' + txt + '</span>';
  }
  function fileIcon(name) {
    const ext = (name.split('.').pop() || '').toLowerCase();
    if (['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'bmp'].includes(ext)) return '🖼️';
    if (['mp4', 'mov', 'mkv', 'webm', 'avi'].includes(ext)) return '🎬';
    if (['mp3', 'wav', 'flac', 'ogg'].includes(ext)) return '🎵';
    if (['zip', 'rar', '7z', 'tar', 'gz'].includes(ext)) return '🗜️';
    if (['pdf'].includes(ext)) return '📕';
    if (['doc', 'docx', 'txt', 'md'].includes(ext)) return '📄';
    if (['xls', 'xlsx', 'csv'].includes(ext)) return '📊';
    if (['ppt', 'pptx'].includes(ext)) return '📽️';
    if (['exe', 'msi', 'dmg'].includes(ext)) return '⚙️';
    return '📄';
  }

  async function api(path, opts) {
    const res = await fetch(path, opts);
    if (res.status === 401) { location.href = '/login'; throw new Error('logged out'); }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || ('HTTP ' + res.status));
    return data;
  }

  let items = [];
  async function refresh() {
    try {
      const data = await api('/api/items');
      items = data.items || [];
      render();
    } catch (e) { /* logged out or offline — leave the list as-is */ }
  }

  function render() {
    const files = items.filter((i) => i.kind === 'file');
    const clips = items.filter((i) => i.kind === 'clip');
    fileList.innerHTML = files.length ? files.map((it) => `
      <li class="file-row">
        <span class="file-icon">${fileIcon(it.name)}</span>
        <div class="file-meta">
          <div class="file-name">${esc(it.name)}</div>
          <div class="file-sub">${fmtSize(it.size)} · ${fmtTime(it.createdAt)}
            ${it.relPath ? `<span class="rel">· ${esc(it.relPath)}</span>` : ''} ${expiryBadge(it)}</div>
        </div>
        <a class="btn small secondary" href="/f/${esc(it.id)}">Download</a>
        <button class="btn small danger" data-del="${esc(it.id)}">Delete</button>
      </li>`).join('') : '<li class="empty">No files yet — drag some in or click Upload files.</li>';
    clipList.innerHTML = clips.length ? clips.map((it) => `
      <div class="clip">
        <div class="clip-text">${esc(it.text)}</div>
        <div class="clip-meta">
          <span>${fmtTime(it.createdAt)}</span> ${expiryBadge(it)}
          <button class="btn small secondary" data-copy="${esc(it.id)}">Copy</button>
          <button class="btn small danger" data-del="${esc(it.id)}">Delete</button>
        </div>
      </div>`).join('') : '<p class="empty">No clips yet — press Ctrl+V anywhere to save one.</p>';
  }

  document.addEventListener('click', async (e) => {
    const del = e.target.closest('[data-del]');
    if (del) {
      if (!confirm('Delete this item?')) return;
      try { await api('/api/items/' + del.dataset.del, { method: 'DELETE' }); refresh(); }
      catch (err) { alert(err.message); }
      return;
    }
    const cp = e.target.closest('[data-copy]');
    if (cp) {
      const it = items.find((i) => i.id === cp.dataset.copy);
      if (it) { await navigator.clipboard.writeText(it.text); cp.textContent = 'Copied!'; setTimeout(() => cp.textContent = 'Copy', 1200); }
    }
  });

  // --- clips ---
  async function addClip(text, keepForever) {
    text = (text || '').trim();
    if (!text) return;
    try {
      await api('/api/clips', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text, keepForever: !!keepForever }) });
      $('clipText').value = '';
      refresh();
    } catch (err) { alert(err.message); }
  }
  $('addClipBtn').addEventListener('click', () => addClip($('clipText').value, $('clipKeepForever').checked));

  // Ctrl+V anywhere on the page saves a clip (unless typing in a field,
  // where the normal paste still works — we only grab it if the target
  // is not the clip box itself).
  document.addEventListener('paste', (e) => {
    const text = (e.clipboardData || window.clipboardData).getData('text');
    if (!text) return;
    if (e.target === $('clipText')) return; // let the user paste into the box
    e.preventDefault();
    addClip(text, $('clipKeepForever').checked);
  });

  // --- uploads with per-file progress ---
  function uploadFile(file, relPath) {
    return new Promise((resolve, reject) => {
      const row = document.createElement('div');
      row.className = 'progress-wrap';
      row.innerHTML = `<div>${esc(file.name)} — <span class="pct">0%</span></div><div class="bar"><i></i></div>`;
      progressArea.appendChild(row);
      const pct = row.querySelector('.pct'), bar = row.querySelector('.bar i');
      const fd = new FormData();
      fd.append('file', file);
      if (relPath) fd.append('relPath', relPath);
      if ($('clipKeepForever').checked) fd.append('keepForever', 'true');
      const xhr = new XMLHttpRequest();
      xhr.open('POST', '/api/upload');
      xhr.upload.onprogress = (e) => {
        if (e.lengthComputable) {
          const p = Math.round((e.loaded / e.total) * 100);
          pct.textContent = p + '%';
          bar.style.width = p + '%';
        }
      };
      xhr.onload = () => {
        if (xhr.status === 201) { row.remove(); refresh(); resolve(); }
        else {
          let msg = 'Upload failed';
          try { msg = JSON.parse(xhr.responseText).error || msg; } catch (_) {}
          pct.textContent = 'failed: ' + msg;
          bar.style.background = '#b3261e';
          reject(new Error(msg));
        }
      };
      xhr.onerror = () => { pct.textContent = 'failed: network error'; reject(new Error('network error')); };
      xhr.send(fd);
    });
  }

  async function uploadFiles(fileListLike) {
    const files = Array.from(fileListLike || []);
    for (const f of files) {
      const rel = (f && f.relPath) || f.webkitRelativePath || '';
      const file = (f && f.file) || f;
      try { await uploadFile(file, rel); } catch (_) { /* keep going with the rest */ }
    }
    refresh();
  }

  // Dragged folders: browsers only expose top-level files via
  // dataTransfer.files, so traverse entries (webkitGetAsEntry) to
  // collect every file inside a dropped folder, with its path.
  async function filesFromDrop(dt) {
    const items = dt && dt.items ? Array.from(dt.items) : [];
    const entries = [];
    for (const it of items) {
      const en = (it.getAsEntry && it.getAsEntry()) || (it.webkitGetAsEntry && it.webkitGetAsEntry());
      if (en) entries.push(en);
    }
    if (!entries.length) return dt && dt.files ? Array.from(dt.files) : [];
    const out = [];
    async function walk(entry, prefix) {
      if (entry.isFile) {
        const file = await new Promise((res, rej) => entry.file(res, rej));
        out.push({ file, relPath: (prefix ? prefix + '/' : '') + file.name });
      } else if (entry.isDirectory) {
        const reader = entry.createReader();
        let batch;
        do {
          batch = await new Promise((res, rej) => reader.readEntries(res, rej));
          for (const child of batch) await walk(child, (prefix ? prefix + '/' : '') + entry.name);
        } while (batch.length);
      }
    }
    for (const en of entries) await walk(en, '');
    return out;
  }

  $('uploadFilesBtn').addEventListener('click', () => $('fileInput').click());
  $('uploadFolderBtn').addEventListener('click', () => $('folderInput').click());
  $('fileInput').addEventListener('change', (e) => { uploadFiles(e.target.files); e.target.value = ''; });
  $('folderInput').addEventListener('change', (e) => { uploadFiles(e.target.files); e.target.value = ''; });

  const dz = $('dropzone'), panel = $('filesPanel');
  ['dragenter', 'dragover'].forEach((ev) => panel.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add('over'); }));
  ['dragleave', 'drop'].forEach((ev) => panel.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove('over'); }));
  panel.addEventListener('drop', async (e) => {
    const dt = e.dataTransfer;
    if (!dt) return;
    try { await uploadFiles(await filesFromDrop(dt)); }
    catch (_) { if (dt.files && dt.files.length) uploadFiles(dt.files); }
  });
  // Keep the browser from navigating away when a file is dropped outside the panel.
  document.addEventListener('dragover', (e) => e.preventDefault());
  document.addEventListener('drop', (e) => e.preventDefault());

  // --- settings modal ---
  const modal = $('settingsModal');
  $('settingsBtn').addEventListener('click', async () => {
    modal.classList.add('open');
    try {
      const data = await api('/api/settings');
      const s = data.settings;
      $('setMaxItems').value = s.maxItems;
      $('setMaxFileMB').value = s.maxFileMB;
      $('setExpiry').value = s.defaultExpiryHours;
      $('userLabel').textContent = data.username ? '👤 ' + data.username : '';
    } catch (err) { $('settingsMsg').textContent = err.message; $('settingsMsg').classList.add('err'); }
  });
  $('settingsClose').addEventListener('click', () => modal.classList.remove('open'));
  modal.addEventListener('click', (e) => { if (e.target === modal) modal.classList.remove('open'); });
  $('settingsSave').addEventListener('click', async () => {
    const msg = $('settingsMsg');
    try {
      await api('/api/settings', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          maxItems: parseInt($('setMaxItems').value, 10),
          maxFileMB: parseInt($('setMaxFileMB').value, 10),
          defaultExpiryHours: parseInt($('setExpiry').value, 10),
        }) });
      msg.textContent = 'Saved.'; msg.classList.remove('err');
    } catch (err) { msg.textContent = err.message; msg.classList.add('err'); }
  });
  $('pwSave').addEventListener('click', async () => {
    const msg = $('pwMsg');
    try {
      await api('/api/change-password', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ currentPassword: $('pwCurrent').value, newPassword: $('pwNew').value }) });
      msg.textContent = 'Password changed.'; msg.classList.remove('err');
      $('pwCurrent').value = ''; $('pwNew').value = '';
    } catch (err) { msg.textContent = err.message; msg.classList.add('err'); }
  });

  $('logoutBtn').addEventListener('click', () => { location.href = '/logout'; });

  refresh();
  setInterval(refresh, 30000); // keep expiry badges fresh
})();
