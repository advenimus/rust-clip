// Tauri v2 frontend shim.
const invoke = window.__TAURI__.core.invoke;
const listen = window.__TAURI__.event.listen;

const panelAccount = document.getElementById('panel-account');
const panelHistory = document.getElementById('panel-history');
const tabs = document.querySelectorAll('.tabs a');

function showPanel(name) {
  panelAccount.classList.toggle('hidden', name !== 'account');
  panelHistory.classList.toggle('hidden', name !== 'history');
  tabs.forEach((a) => a.classList.toggle('active', a.dataset.tab === name));
  if (name === 'account') refreshAccount();
  if (name === 'history') refreshHistory();
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

// ----- Account panel -----
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
    try {
      autostartToggle.checked = await invoke('cmd_get_autostart');
    } catch {}
  } catch (err) {
    setMsg(String(err), 'err');
  }
}

function setMsg(text, cls = '') {
  accountMsg.textContent = text;
  accountMsg.className = 'status ' + cls;
}

// ----- History panel -----
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

// ----- Events from backend -----
listen('sync-status', (evt) => {
  // Future: show a connected/offline dot in the titlebar.
  console.log('sync-status', evt.payload);
});
listen('history-updated', () => {
  if (!panelHistory.classList.contains('hidden')) refreshHistory();
});

// Boot
pickPanelFromHash();
window.addEventListener('hashchange', pickPanelFromHash);
