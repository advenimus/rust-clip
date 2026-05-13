// Tauri v2 frontend. Single-window UI with three tabs (History,
// Settings, About). Account lives as the first section in Settings.

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
    const dialog = tauri.dialog ?? (window.__TAURI__ && window.__TAURI__.dialog);

    async function confirmDialog(message, title = 'RustClip') {
      if (dialog && typeof dialog.confirm === 'function') {
        return dialog.confirm(message, { title, kind: 'warning' });
      }
      return window.confirm(message);
    }
    async function alertDialog(message, title = 'RustClip') {
      if (dialog && typeof dialog.message === 'function') {
        return dialog.message(message, { title, kind: 'error' });
      }
      window.alert(message);
    }

    window.addEventListener('error', (ev) => {
      showBootError('Script error: ' + (ev.error?.stack || ev.message || ev.type));
    });
    window.addEventListener('unhandledrejection', (ev) => {
      showBootError('Unhandled rejection: ' + (ev.reason?.stack || ev.reason));
    });

    // ───────── Tab navigation ─────────
    const panels = {
      history: document.getElementById('panel-history'),
      settings: document.getElementById('panel-settings'),
      about: document.getElementById('panel-about'),
    };
    const tabs = Array.from(document.querySelectorAll('.tab'));
    let currentAccount = null; // cached from cmd_status

    function defaultTab() {
      // Settings is the first-run target so the user can enroll; once
      // enrolled, History is more useful.
      return currentAccount ? 'history' : 'settings';
    }
    function resolveTab(name) {
      if (name && panels[name]) return name;
      return defaultTab();
    }
    function showPanel(name) {
      const target = resolveTab(name);
      for (const [k, el] of Object.entries(panels)) {
        if (!el) continue;
        if (k === target) el.removeAttribute('hidden');
        else el.setAttribute('hidden', '');
      }
      tabs.forEach((t) => t.classList.toggle('is-active', t.dataset.tab === target));
      if (target === 'history') refreshHistory();
      if (target === 'settings') { refreshSettings(); refreshLogDir(); }
      if (target === 'about') refreshAbout();
    }

    tabs.forEach((t) => {
      t.addEventListener('click', () => {
        const name = t.dataset.tab;
        window.location.hash = name;
        showPanel(name);
      });
    });
    function panelFromHash() {
      showPanel(window.location.hash.replace('#', ''));
    }

    // ───────── Account section ─────────
    const accountCard = document.getElementById('account-card');
    const accountSignedIn = document.getElementById('account-signed-in');
    const accountSignedOut = document.getElementById('account-signed-out');
    const accountSub = document.getElementById('account-sub');
    const accountMsg = document.getElementById('account-msg');
    const syncPill = document.getElementById('sync-pill');
    const brandStatus = document.getElementById('brand-status');
    const accUser = document.getElementById('acc-user');
    const accServer = document.getElementById('acc-server');
    const accDevice = document.getElementById('acc-device');
    const btnStartSync = document.getElementById('btn-start-sync');
    const btnStopSync = document.getElementById('btn-stop-sync');
    const btnLogout = document.getElementById('btn-logout');
    const modeEnroll = document.getElementById('mode-enroll');
    const modeLogin = document.getElementById('mode-login');
    const formEnroll = document.getElementById('form-enroll');
    const formLogin = document.getElementById('form-login');

    modeEnroll.addEventListener('click', () => {
      modeEnroll.classList.add('is-active');
      modeLogin.classList.remove('is-active');
      formEnroll.classList.remove('hidden');
      formLogin.classList.add('hidden');
    });
    modeLogin.addEventListener('click', () => {
      modeLogin.classList.add('is-active');
      modeEnroll.classList.remove('is-active');
      formLogin.classList.remove('hidden');
      formEnroll.classList.add('hidden');
    });

    function setAccountMsg(text, cls = '') {
      if (!text) { accountMsg.setAttribute('hidden', ''); accountMsg.textContent = ''; return; }
      accountMsg.removeAttribute('hidden');
      accountMsg.textContent = text;
      accountMsg.className = 'card-msg ' + cls;
    }

    formEnroll.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(formEnroll);
      if (fd.get('password') !== fd.get('confirm_password')) {
        setAccountMsg('Passwords do not match.', 'err');
        return;
      }
      setAccountMsg('Enrolling…');
      try {
        await invoke('cmd_enroll', {
          input: {
            server_url: fd.get('server_url'),
            enrollment_token: fd.get('enrollment_token'),
            password: fd.get('password'),
            device_name: fd.get('device_name') || null,
          },
        });
        setAccountMsg('Enrolled successfully.', 'ok');
        formEnroll.reset();
        await refreshAccount();
      } catch (err) {
        setAccountMsg(String(err), 'err');
      }
    });

    formLogin.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(formLogin);
      setAccountMsg('Logging in…');
      try {
        await invoke('cmd_login', {
          input: {
            server_url: fd.get('server_url'),
            username: fd.get('username'),
            password: fd.get('password'),
            device_name: fd.get('device_name') || null,
          },
        });
        setAccountMsg('Logged in.', 'ok');
        formLogin.reset();
        await refreshAccount();
      } catch (err) {
        setAccountMsg(String(err), 'err');
      }
    });

    btnLogout.addEventListener('click', async () => {
      if (!(await confirmDialog('Log out of this device? This will sign out and clear local keys.'))) return;
      try {
        await invoke('cmd_logout');
        setAccountMsg('Logged out.', 'ok');
        await refreshAccount();
      } catch (err) {
        setAccountMsg(String(err), 'err');
      }
    });
    btnStartSync.addEventListener('click', async () => {
      try { await invoke('cmd_start_sync'); setAccountMsg('Sync started.', 'ok'); await refreshSyncState(); }
      catch (err) { setAccountMsg(String(err), 'err'); }
    });
    btnStopSync.addEventListener('click', async () => {
      try { await invoke('cmd_stop_sync'); setAccountMsg('Sync stopped.', 'ok'); await refreshSyncState(); }
      catch (err) { setAccountMsg(String(err), 'err'); }
    });

    function renderAccountCard(acc) {
      if (acc) {
        accountSignedIn.removeAttribute('hidden');
        accountSignedOut.setAttribute('hidden', '');
        accountSub.textContent = `Signed in as ${acc.username}.`;
        accUser.textContent = acc.username;
        accServer.textContent = acc.server_url;
        accDevice.textContent = acc.device_id;
      } else {
        accountSignedIn.setAttribute('hidden', '');
        accountSignedOut.removeAttribute('hidden');
        accountSub.textContent = 'Sign in or enroll a new device to start syncing.';
      }
    }

    function setSyncBadge(state) {
      // state: 'connected' | 'offline' | 'error' | 'none'
      const map = {
        connected: { text: 'Connected', cls: 'pill pill-ok',   brand: 'connected', brandText: 'Connected' },
        offline:   { text: 'Offline',   cls: 'pill pill-warn', brand: 'offline',   brandText: 'Offline' },
        error:     { text: 'Error',     cls: 'pill pill-err',  brand: 'error',     brandText: 'Error' },
        none:      { text: 'Not connected', cls: 'pill pill-muted', brand: 'idle', brandText: 'Not enrolled' },
      };
      const m = map[state] || map.none;
      syncPill.textContent = m.text;
      syncPill.className = m.cls;
      brandStatus.dataset.state = m.brand;
      brandStatus.textContent = m.brandText;
    }

    async function refreshSyncState() {
      try {
        if (!currentAccount) { setSyncBadge('none'); return; }
        const running = await invoke('cmd_sync_running');
        setSyncBadge(running ? 'connected' : 'offline');
      } catch {
        setSyncBadge('error');
      }
    }

    async function refreshAccount() {
      try {
        const acc = await invoke('cmd_status');
        currentAccount = acc || null;
        renderAccountCard(currentAccount);
        await refreshSyncState();
      } catch (err) {
        setAccountMsg(String(err), 'err');
      }
    }

    // ───────── Settings panel ─────────
    const autostartToggle = document.getElementById('autostart-toggle');
    const autoSyncFilesToggle = document.getElementById('auto-sync-files-toggle');
    const autoSyncMaxMb = document.getElementById('auto-sync-max-mb');
    const autoSyncMaxSave = document.getElementById('auto-sync-max-save');
    const notificationsToggle = document.getElementById('notifications-toggle');
    const clipboardGuardMode = document.getElementById('clipboard-guard-mode');
    const clipboardGuardSeconds = document.getElementById('clipboard-guard-seconds');
    const clipboardGuardSave = document.getElementById('clipboard-guard-save');
    const recopyHotkeyToggle = document.getElementById('recopy-hotkey-toggle');
    const recopyHotkey = document.getElementById('recopy-hotkey');
    const recopyHotkeySave = document.getElementById('recopy-hotkey-save');
    const settingsMsg = document.getElementById('settings-msg');

    function setSettingsMsg(text, cls = '') {
      if (!text) { settingsMsg.setAttribute('hidden', ''); settingsMsg.textContent = ''; return; }
      settingsMsg.removeAttribute('hidden');
      settingsMsg.textContent = text;
      settingsMsg.className = 'page-msg ' + cls;
    }

    function bindSubRow(toggleEl) {
      const row = document.querySelector(`.sub-row[data-bound-to="${toggleEl.id}"]`);
      if (!row) return;
      const apply = () => row.classList.toggle('is-disabled', !toggleEl.checked);
      apply();
      toggleEl.addEventListener('change', apply);
    }

    // Wire boolean dependent rows once.
    [autoSyncFilesToggle, recopyHotkeyToggle].forEach(bindSubRow);

    // The clipboard guard sub-row depends on the select, not a checkbox.
    const guardSubRow = document.querySelector('.sub-row[data-guard-mode-sub]');
    function applyGuardSub() {
      if (!guardSubRow) return;
      guardSubRow.classList.toggle('is-disabled', clipboardGuardMode.value === 'off');
    }
    applyGuardSub();
    clipboardGuardMode.addEventListener('change', applyGuardSub);

    async function refreshSettings() {
      try { autostartToggle.checked = await invoke('cmd_get_autostart'); } catch {}
      try {
        const cfg = await invoke('cmd_get_client_config');
        autoSyncFilesToggle.checked = !!cfg.auto_sync_files;
        autoSyncMaxMb.value = Math.max(1, Math.round(cfg.auto_sync_max_bytes / (1024 * 1024)));
        notificationsToggle.checked = !!cfg.notifications_enabled;
        clipboardGuardMode.value = normalizeGuardMode(cfg.clipboard_guard_mode);
        clipboardGuardSeconds.value = clampGuardSeconds(cfg.clipboard_guard_seconds);
        recopyHotkeyToggle.checked = !!cfg.recopy_hotkey_enabled;
        recopyHotkey.value = cfg.recopy_hotkey || '';
        // Re-evaluate dependent rows after values are loaded.
        [autoSyncFilesToggle, recopyHotkeyToggle].forEach((t) =>
          document.querySelector(`.sub-row[data-bound-to="${t.id}"]`)
            ?.classList.toggle('is-disabled', !t.checked));
        applyGuardSub();
      } catch (err) {
        setSettingsMsg(String(err), 'err');
      }
    }

    function clampGuardSeconds(v) {
      const n = parseInt(v, 10);
      if (!Number.isFinite(n) || n < 1) return 5;
      if (n > 30) return 30;
      return n;
    }

    function normalizeGuardMode(v) {
      if (v === 'aggressive' || v === 'empty_only') return v;
      return 'off';
    }

    async function saveClientConfig(okMessage) {
      const mb = Math.max(1, parseInt(autoSyncMaxMb.value, 10) || 500);
      const guardSeconds = clampGuardSeconds(clipboardGuardSeconds.value);
      const guardMode = normalizeGuardMode(clipboardGuardMode.value);
      try {
        const updated = await invoke('cmd_set_client_config', {
          config: {
            auto_sync_files: autoSyncFilesToggle.checked,
            auto_sync_max_bytes: mb * 1024 * 1024,
            notifications_enabled: notificationsToggle.checked,
            clipboard_guard_mode: guardMode,
            // Legacy bool kept in sync server-side; sent here so older
            // client logic doesn't drift if it ever reads it directly.
            clipboard_guard_enabled: guardMode !== 'off',
            clipboard_guard_seconds: guardSeconds,
            recopy_hotkey_enabled: recopyHotkeyToggle.checked,
            recopy_hotkey: recopyHotkey.value.trim(),
          },
        });
        autoSyncMaxMb.value = Math.max(1, Math.round(updated.auto_sync_max_bytes / (1024 * 1024)));
        clipboardGuardMode.value = normalizeGuardMode(updated.clipboard_guard_mode);
        clipboardGuardSeconds.value = clampGuardSeconds(updated.clipboard_guard_seconds);
        recopyHotkey.value = updated.recopy_hotkey || '';
        recopyHotkeyToggle.checked = !!updated.recopy_hotkey_enabled;
        setSettingsMsg(okMessage || 'Saved.', 'ok');
      } catch (err) {
        setSettingsMsg(String(err), 'err');
      }
    }

    autostartToggle.addEventListener('change', async () => {
      try {
        await invoke('cmd_set_autostart', { enable: autostartToggle.checked });
        setSettingsMsg('Saved.', 'ok');
      } catch (err) {
        setSettingsMsg(String(err), 'err');
      }
    });
    autoSyncFilesToggle.addEventListener('change', () =>
      saveClientConfig('Saved. Restart sync to apply the auto-sync toggle.'));
    autoSyncMaxSave.addEventListener('click', () => saveClientConfig());
    autoSyncMaxMb.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') { e.preventDefault(); saveClientConfig(); }
    });
    notificationsToggle.addEventListener('change', () => saveClientConfig());
    clipboardGuardMode.addEventListener('change', () => saveClientConfig());
    clipboardGuardSave.addEventListener('click', () => saveClientConfig());
    clipboardGuardSeconds.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') { e.preventDefault(); saveClientConfig(); }
    });
    recopyHotkeyToggle.addEventListener('change', () => saveClientConfig());
    recopyHotkeySave.addEventListener('click', () => saveClientConfig());
    recopyHotkey.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') { e.preventDefault(); saveClientConfig(); }
    });

    listen('recopy-hotkey-error', (evt) => {
      const detail = evt && evt.payload ? String(evt.payload) : 'unknown error';
      setSettingsMsg('Could not register shortcut: ' + detail, 'err');
    });

    // ───────── Diagnostics ─────────
    const openLogsBtn = document.getElementById('open-logs-btn');
    const exportLogsBtn = document.getElementById('export-logs-btn');
    const logDirPath = document.getElementById('log-dir-path');
    const diagnosticsMsg = document.getElementById('diagnostics-msg');

    function setDiagnosticsMsg(text, cls = '') {
      if (!text) { diagnosticsMsg.setAttribute('hidden', ''); diagnosticsMsg.textContent = ''; return; }
      diagnosticsMsg.removeAttribute('hidden');
      diagnosticsMsg.textContent = text;
      diagnosticsMsg.className = 'status ' + cls;
    }
    async function refreshLogDir() {
      try { logDirPath.textContent = await invoke('cmd_log_dir'); }
      catch (err) { logDirPath.textContent = '(unable to resolve: ' + String(err) + ')'; }
    }
    openLogsBtn.addEventListener('click', async () => {
      try { await invoke('cmd_open_log_dir'); setDiagnosticsMsg('Opened logs folder.', 'ok'); }
      catch (err) { setDiagnosticsMsg(String(err), 'err'); }
    });
    exportLogsBtn.addEventListener('click', async () => {
      setDiagnosticsMsg('Preparing zip…');
      try {
        const path = await invoke('cmd_export_logs_zip');
        setDiagnosticsMsg(path ? 'Saved to ' + path : 'Export cancelled.', path ? 'ok' : '');
      } catch (err) {
        setDiagnosticsMsg(String(err), 'err');
      }
    });

    // ───────── History panel ─────────
    const historyList = document.getElementById('history-list');
    document.getElementById('refresh-history').addEventListener('click', refreshHistory);
    document.getElementById('clear-history').addEventListener('click', async () => {
      if (!(await confirmDialog('Clear all local history? This cannot be undone.'))) return;
      try { await invoke('cmd_clear_history'); refreshHistory(); }
      catch (err) { await alertDialog(String(err)); }
    });

    async function refreshHistory() {
      try {
        const items = await invoke('cmd_list_history', { limit: 100 });
        if (items.length === 0) {
          historyList.innerHTML = `
            <div class="history-empty">
              <div class="empty-title">No clips yet</div>
              <div class="empty-sub">Copy something on any enrolled device and it will show up here. Items are stored locally only and encrypted at rest.</div>
            </div>`;
          return;
        }
        historyList.innerHTML = items.map((it) => {
          const dt = new Date(it.created_at);
          const fullWhen = dt.toLocaleString();
          const shortWhen = formatShortWhen(dt);
          const dirCls = it.direction === 'incoming' ? 'tag-row incoming' : 'tag-row';
          const tagText = `${it.direction} ${it.kind}`;
          return `
            <div class="history-row" data-id="${escapeHtml(it.id)}" data-kind="${escapeHtml(it.kind)}">
              <span class="${dirCls}">${escapeHtml(tagText)}</span>
              <span class="preview" title="${escapeHtml(it.preview)}">${escapeHtml(it.preview)}</span>
              <span class="size">${formatBytes(it.size_bytes)}</span>
              <span class="when" title="${escapeHtml(fullWhen)}">${escapeHtml(shortWhen)}</span>
              <button class="btn btn-ghost row-copy">Copy</button>
            </div>`;
        }).join('');
        historyList.querySelectorAll('.row-copy').forEach((btn) => {
          btn.addEventListener('click', async (e) => {
            e.stopPropagation();
            const row = btn.closest('.history-row');
            try {
              await invoke('cmd_copy_history_item', { entryId: row.dataset.id });
            } catch (err) {
              await alertDialog(String(err));
            }
          });
        });
        // Whole-row click as a shortcut for Copy.
        historyList.querySelectorAll('.history-row').forEach((row) => {
          row.addEventListener('click', async () => {
            try {
              await invoke('cmd_copy_history_item', { entryId: row.dataset.id });
            } catch (err) {
              await alertDialog(String(err));
            }
          });
        });
      } catch (err) {
        historyList.innerHTML = `<div class="history-empty"><div class="empty-sub">${escapeHtml(String(err))}</div></div>`;
      }
    }

    function formatBytes(n) {
      if (n < 1024) return n + ' B';
      if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
      return (n / (1024 * 1024)).toFixed(1) + ' MB';
    }
    // Compact "when" — time only for today, "MMM D, h:mma" for older,
    // year suffix when it differs from now. Full timestamp lives in the
    // tooltip.
    function formatShortWhen(d) {
      const now = new Date();
      const sameDay =
        d.getFullYear() === now.getFullYear() &&
        d.getMonth() === now.getMonth() &&
        d.getDate() === now.getDate();
      const time = d.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
      if (sameDay) return time;
      const opts = d.getFullYear() === now.getFullYear()
        ? { month: 'short', day: 'numeric' }
        : { month: 'short', day: 'numeric', year: '2-digit' };
      const datePart = d.toLocaleDateString(undefined, opts);
      return `${datePart}, ${time}`;
    }
    function escapeHtml(s) {
      return String(s).replace(/[&<>"']/g, (c) => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
      })[c]);
    }

    // ───────── About panel ─────────
    let aboutCache = null;
    async function refreshAbout() {
      if (!aboutCache) {
        try { aboutCache = await invoke('cmd_about'); }
        catch (err) {
          panels.about.innerHTML = `<div class="history-empty"><div class="empty-sub">${escapeHtml(String(err))}</div></div>`;
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
    panels.about.addEventListener('click', async (e) => {
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
      catch (err) { await alertDialog(String(err)); }
    });

    // ───────── Backend events ─────────
    listen('sync-status', () => { refreshSyncState(); });
    listen('history-updated', () => {
      if (!panels.history.hasAttribute('hidden')) refreshHistory();
    });

    // ───────── Update banner ─────────
    const updateBanner = document.getElementById('update-banner');
    const updateVersions = document.getElementById('update-banner-versions');
    const updateActions = document.getElementById('update-banner-actions');
    const updateMsg = document.getElementById('update-banner-msg');
    const updateInstallBtn = document.getElementById('update-install-btn');
    const updateLaterBtn = document.getElementById('update-later-btn');

    function showUpdateBanner(info) {
      updateVersions.textContent = `v${info.current_version} → ${info.latest_version}`;
      updateMsg.textContent = '';
      updateMsg.className = 'status';
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
          catch (err) { await alertDialog(String(err)); }
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

    // Expose to the Rust side so the tray can bring the window to the
    // right tab even when the hash already matches (which wouldn't fire
    // hashchange on its own).
    window.__rcShow = (name) => {
      const target = resolveTab(name);
      if (window.location.hash !== '#' + target) {
        window.location.hash = target;
      } else {
        showPanel(target);
      }
    };

    // ───────── Boot ─────────
    setSyncBadge('none');
    await refreshAccount();
    panelFromHash();
    window.addEventListener('hashchange', panelFromHash);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
