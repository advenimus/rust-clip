// Tauri v2 frontend shim. Uses the global injected by `withGlobalTauri`.

(function () {
  const bootError = document.getElementById('boot-error');

  function showBootError(msg) {
    if (!bootError) return;
    bootError.textContent = msg;
    bootError.classList.remove('hidden');
  }

  function waitForTauri(maxMs = 2000) {
    return new Promise((resolve, reject) => {
      const started = Date.now();
      (function poll() {
        if (window.__TAURI__ && window.__TAURI__.core && window.__TAURI__.event) {
          resolve(window.__TAURI__);
          return;
        }
        if (Date.now() - started > maxMs) {
          reject(new Error('window.__TAURI__ never appeared — withGlobalTauri may be off'));
          return;
        }
        setTimeout(poll, 25);
      })();
    });
  }

  async function boot() {
    let tauri;
    try {
      tauri = await waitForTauri();
    } catch (e) {
      showBootError('Frontend could not reach Tauri runtime: ' + e.message);
      return;
    }
    const { invoke } = tauri.core;
    const { listen } = tauri.event;

    window.addEventListener('error', (ev) => {
      showBootError('Script error: ' + (ev.error?.stack || ev.message || ev.type));
    });
    window.addEventListener('unhandledrejection', (ev) => {
      showBootError('Unhandled rejection: ' + (ev.reason?.stack || ev.reason));
    });

    const panelAccount = document.getElementById('panel-account');
    const panelHistory = document.getElementById('panel-history');
    const panelAbout = document.getElementById('panel-about');
    const tabs = document.querySelectorAll('.tabs a');

    function showPanel(name) {
      panelAccount.classList.toggle('hidden', name !== 'account');
      panelHistory.classList.toggle('hidden', name !== 'history');
      panelAbout.classList.toggle('hidden', name !== 'about');
      tabs.forEach((a) => a.classList.toggle('active', a.dataset.tab === name));
      if (name === 'account') refreshAccount();
      if (name === 'history') refreshHistory();
      if (name === 'about') refreshAbout();
    }

    tabs.forEach((a) => {
      a.addEventListener('click', (e) => {
        e.preventDefault();
        const name = a.dataset.tab;
        window.location.hash = name;
        showPanel(name);
      });
    });

    function pickPanelFromHash() {
      const h = window.location.hash.replace('#', '') || 'account';
      showPanel(h);
    }

    // ---- Account panel ----
    const modeEnroll = document.getElementById('mode-enroll');
    const modeLogin = document.getElementById('mode-login');
    const formEnroll = document.getElementById('form-enroll');
    const formLogin = document.getElementById('form-login');
    const accountStatus = document.getElementById('account-status');
    const accountMsg = document.getElementById('account-msg');
    const authForms = document.getElementById('auth-forms');
    const autostartToggle = document.getElementById('autostart-toggle');

    modeEnroll.addEventListener('click', () => {
      formEnroll.classList.remove('hidden');
      formLogin.classList.add('hidden');
    });
    modeLogin.addEventListener('click', () => {
      formLogin.classList.remove('hidden');
      formEnroll.classList.add('hidden');
    });

    formEnroll.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(formEnroll);
      if (fd.get('password') !== fd.get('confirm_password')) {
        setMsg('Passwords do not match.', 'err');
        return;
      }
      setMsg('Enrolling…');
      try {
        await invoke('cmd_enroll', {
          input: {
            server_url: fd.get('server_url'),
            enrollment_token: fd.get('enrollment_token'),
            password: fd.get('password'),
            device_name: fd.get('device_name') || null,
          },
        });
        setMsg('Enrolled successfully.', 'ok');
        formEnroll.reset();
        refreshAccount();
      } catch (err) {
        setMsg(String(err), 'err');
      }
    });

    formLogin.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(formLogin);
      setMsg('Logging in…');
      try {
        await invoke('cmd_login', {
          input: {
            server_url: fd.get('server_url'),
            username: fd.get('username'),
            password: fd.get('password'),
            device_name: fd.get('device_name') || null,
          },
        });
        setMsg('Logged in.', 'ok');
        formLogin.reset();
        refreshAccount();
      } catch (err) {
        setMsg(String(err), 'err');
      }
    });

    autostartToggle.addEventListener('change', async () => {
      try {
        await invoke('cmd_set_autostart', { enable: autostartToggle.checked });
      } catch (err) {
        setMsg(String(err), 'err');
      }
    });

    async function refreshAccount() {
      try {
        const acc = await invoke('cmd_status');
        if (acc) {
          authForms.classList.add('hidden');
          accountStatus.innerHTML = `
            <div class="account-card">
              <h3>Signed in as ${escapeHtml(acc.username)}</h3>
              <dl>
                <dt>Server</dt><dd>${escapeHtml(acc.server_url)}</dd>
                <dt>User ID</dt><dd>${escapeHtml(acc.user_id)}</dd>
                <dt>Device ID</dt><dd>${escapeHtml(acc.device_id)}</dd>
              </dl>
              <div class="account-actions">
                <button class="btn btn-ghost" id="start-sync-btn">Start sync</button>
                <button class="btn btn-ghost" id="stop-sync-btn">Stop sync</button>
                <button class="btn btn-danger" id="logout-btn">Log out</button>
              </div>
            </div>`;
          document.getElementById('logout-btn').addEventListener('click', async () => {
            if (!confirm('Log out of this device? This will sign out and clear local keys.')) return;
            try { await invoke('cmd_logout'); setMsg('Logged out.', 'ok'); refreshAccount(); }
            catch (err) { setMsg(String(err), 'err'); }
          });
          document.getElementById('start-sync-btn').addEventListener('click', async () => {
            try { await invoke('cmd_start_sync'); setMsg('Sync started.', 'ok'); }
            catch (err) { setMsg(String(err), 'err'); }
          });
          document.getElementById('stop-sync-btn').addEventListener('click', async () => {
            try { await invoke('cmd_stop_sync'); setMsg('Sync stopped.', 'ok'); }
            catch (err) { setMsg(String(err), 'err'); }
          });
        } else {
          authForms.classList.remove('hidden');
          accountStatus.innerHTML = '';
        }
        try { autostartToggle.checked = await invoke('cmd_get_autostart'); } catch {}
      } catch (err) {
        setMsg(String(err), 'err');
      }
    }

    function setMsg(text, cls = '') {
      accountMsg.textContent = text;
      accountMsg.className = 'status ' + cls;
    }

    // ---- History panel ----
    const historyList = document.getElementById('history-list');
    document.getElementById('refresh-history').addEventListener('click', refreshHistory);
    document.getElementById('clear-history').addEventListener('click', async () => {
      if (!confirm('Clear all local history? This cannot be undone.')) return;
      try { await invoke('cmd_clear_history'); refreshHistory(); }
      catch (err) { alert(String(err)); }
    });

    async function refreshHistory() {
      try {
        const items = await invoke('cmd_list_history', { limit: 100 });
        if (items.length === 0) {
          historyList.innerHTML = '<div class="history-empty">No history yet. Copy something on any enrolled device.</div>';
          return;
        }
        historyList.innerHTML = items
          .map((it) => {
            const when = new Date(it.created_at).toLocaleString();
            return `
              <div class="history-row">
                <span class="dir">${escapeHtml(it.direction)}</span>
                <span class="kind">${escapeHtml(it.kind)}</span>
                <span class="preview" title="${escapeHtml(it.preview)}">${escapeHtml(it.preview)}</span>
                <span class="size">${formatBytes(it.size_bytes)}</span>
                <span class="when">${escapeHtml(when)}</span>
                <button class="btn btn-ghost row-copy" data-id="${it.id}" ${it.kind === 'text' ? '' : 'disabled'}>Copy</button>
              </div>`;
          })
          .join('');
        historyList.querySelectorAll('.row-copy').forEach((btn) => {
          btn.addEventListener('click', async () => {
            try {
              await invoke('cmd_copy_history_text', { entryId: btn.dataset.id });
            } catch (err) {
              alert(String(err));
            }
          });
        });
      } catch (err) {
        historyList.innerHTML = `<div class="history-empty">${escapeHtml(String(err))}</div>`;
      }
    }

    function formatBytes(n) {
      if (n < 1024) return n + ' B';
      if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
      return (n / (1024 * 1024)).toFixed(1) + ' MB';
    }

    function escapeHtml(s) {
      return String(s).replace(/[&<>"']/g, (c) => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
      })[c]);
    }

    // ---- About panel ----
    let aboutCache = null;

    async function refreshAbout() {
      if (!aboutCache) {
        try {
          aboutCache = await invoke('cmd_about');
        } catch (err) {
          panelAbout.innerHTML = `<div class="history-empty">${escapeHtml(String(err))}</div>`;
          return;
        }
      }
      document.getElementById('about-version').textContent = 'v' + aboutCache.version;
      const repoEl = document.getElementById('about-repo');
      repoEl.textContent = aboutCache.repo_url;
      repoEl.href = aboutCache.repo_url;
      document.getElementById('about-license').textContent = aboutCache.license;
      document.getElementById('about-author').textContent = aboutCache.author_name;
      const handleEl = document.getElementById('about-author-handle');
      handleEl.textContent = '@' + aboutCache.author_handle;
      handleEl.href = aboutCache.author_url;
    }

    // Any element with a data-ext attribute opens an external URL via the
    // opener plugin (Tauri's webview won't navigate to remote origins).
    panelAbout.addEventListener('click', async (e) => {
      const trigger = e.target.closest('[data-ext]');
      if (!trigger) return;
      e.preventDefault();
      if (!aboutCache) {
        try { aboutCache = await invoke('cmd_about'); } catch { return; }
      }
      const url = ({
        repo: aboutCache.repo_url,
        releases: aboutCache.repo_url + '/releases/latest',
        author: aboutCache.author_url,
      })[trigger.dataset.ext];
      if (!url) return;
      try { await invoke('cmd_open_external', { url }); }
      catch (err) { alert(String(err)); }
    });

    // ---- Backend events ----
    listen('sync-status', (evt) => {
      console.log('sync-status', evt.payload);
    });
    listen('history-updated', () => {
      if (!panelHistory.classList.contains('hidden')) refreshHistory();
    });

    // ---- Update banner ----
    const updateBanner = document.getElementById('update-banner');
    const updateVersions = document.getElementById('update-banner-versions');
    const updateActions = document.getElementById('update-banner-actions');
    const updateMsg = document.getElementById('update-banner-msg');
    const updateInstallBtn = document.getElementById('update-install-btn');
    const updateLaterBtn = document.getElementById('update-later-btn');
    let currentUpdate = null;

    function showUpdateBanner(info) {
      currentUpdate = info;
      updateVersions.textContent = `v${info.current_version} → ${info.latest_version}`;
      updateMsg.textContent = '';
      updateMsg.className = 'status';
      // Rebuild the action row based on install kind.
      updateActions.innerHTML = '';
      const selfUpdatable = ['dmg', 'msi', 'nsis', 'app_image'].includes(info.install_kind);
      if (selfUpdatable) {
        const btn = document.createElement('button');
        btn.className = 'btn btn-primary';
        btn.textContent = 'Install update';
        btn.addEventListener('click', installUpdateHandler);
        updateActions.appendChild(btn);
      } else {
        const link = document.createElement('button');
        link.className = 'btn btn-primary';
        const tip = info.install_kind === 'deb'
          ? 'Update via your package manager (apt/dpkg) — installer replaces system-managed files.'
          : info.install_kind === 'rpm'
            ? 'Update via your package manager (dnf/rpm) — installer replaces system-managed files.'
            : 'Open the release page to download the latest installer.';
        link.textContent = 'Open release page ↗';
        link.title = tip;
        link.addEventListener('click', async () => {
          try { await invoke('cmd_open_external', { url: info.release_url }); }
          catch (err) { alert(String(err)); }
        });
        updateActions.appendChild(link);
        const note = document.createElement('span');
        note.className = 'muted-note';
        note.textContent = tip;
        updateActions.appendChild(note);
      }
      const later = document.createElement('button');
      later.className = 'btn btn-ghost';
      later.textContent = 'Later';
      later.addEventListener('click', () => updateBanner.classList.add('hidden'));
      updateActions.appendChild(later);

      updateBanner.classList.remove('hidden');
    }

    async function installUpdateHandler() {
      updateMsg.textContent = 'Downloading update…';
      updateMsg.className = 'status';
      try {
        await invoke('cmd_install_update');
        // Backend restarts the process on success; if we're still here the
        // user likely cancelled the system prompt.
      } catch (err) {
        updateMsg.textContent = String(err);
        updateMsg.className = 'status err';
      }
    }

    updateInstallBtn && updateInstallBtn.addEventListener('click', installUpdateHandler);
    updateLaterBtn && updateLaterBtn.addEventListener('click', () => {
      updateBanner.classList.add('hidden');
    });

    listen('update-available', (evt) => {
      if (evt.payload) showUpdateBanner(evt.payload);
    });

    // Manual "Check for updates" button on the About panel.
    const aboutCheckBtn = document.getElementById('about-check-update');
    const aboutUpdateMsg = document.getElementById('about-update-msg');
    aboutCheckBtn && aboutCheckBtn.addEventListener('click', async () => {
      aboutUpdateMsg.textContent = 'Checking…';
      try {
        const info = await invoke('cmd_check_update');
        if (info) {
          aboutUpdateMsg.textContent = `Update available: ${info.latest_version}`;
          showUpdateBanner(info);
        } else {
          aboutUpdateMsg.textContent = "You're on the latest version.";
        }
      } catch (err) {
        aboutUpdateMsg.textContent = 'Check failed: ' + String(err);
      }
    });

    pickPanelFromHash();
    window.addEventListener('hashchange', pickPanelFromHash);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
