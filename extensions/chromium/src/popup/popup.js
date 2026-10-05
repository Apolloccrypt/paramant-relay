import { getHistory } from '../shared/settings.js';

// ── i18n ────────────────────────────────────────────────────────────────────────
function applyI18n() {
  for (const node of document.querySelectorAll('[data-i18n]')) {
    const msg = chrome.i18n.getMessage(node.dataset.i18n);
    if (msg) node.textContent = msg;
  }
}

// ── DOM ──────────────────────────────────────────────────────────────────────────
const elLoading  = document.getElementById('state-loading');
const elLogin    = document.getElementById('state-login');
const elLoggedIn = document.getElementById('state-logged-in');

const bannerRollingOut = document.getElementById('banner-rolling-out');
const formApikey       = document.getElementById('form-apikey');
const formTotp         = document.getElementById('form-totp');
const showTotpLink     = document.getElementById('show-totp');
const showApikeyLink   = document.getElementById('show-apikey');

const planBadge    = document.getElementById('plan-badge');
const sessionTimer = document.getElementById('session-timer');
const historyList  = document.getElementById('history-list');
const historyEmpty = document.getElementById('history-empty');
const logoutBtn    = document.getElementById('logout-btn');
const settingsBtn  = document.getElementById('settings-btn');

// ── Init ───────────────────────────────────────────────────────────────────────
async function init() {
  applyI18n();
  showState('loading');

  const auth = await chrome.runtime.sendMessage({ type: 'CHECK_SESSION' });
  if (auth?.authenticated) return showLoggedIn(auth);

  const caps = await chrome.runtime.sendMessage({ type: 'GET_CAPABILITIES' });
  const totpOn = !!caps?.user_totp;
  showTotpLink.classList.toggle('hidden', !totpOn);
  bannerRollingOut.classList.toggle('hidden', totpOn);
  showState('login');
}

function showState(name) {
  elLoading.classList.toggle('hidden', name !== 'loading');
  elLogin.classList.toggle('hidden', name !== 'login');
  elLoggedIn.classList.toggle('hidden', name !== 'logged-in');
}

async function showLoggedIn(auth) {
  if (auth.plan) {
    planBadge.textContent = auth.plan;
    planBadge.classList.remove('hidden');
  } else {
    planBadge.classList.add('hidden');
  }
  sessionTimer.textContent = formatTimeRemaining(auth.expires_at);
  await renderHistory();
  showState('logged-in');
}

async function renderHistory() {
  const items = await getHistory();
  historyList.textContent = '';
  historyEmpty.classList.toggle('hidden', items.length > 0);

  for (const it of items.slice(0, 8)) {
    const li = document.createElement('li');
    li.className = 'history-item';
    const name = document.createElement('span');
    name.className = 'history-name';
    name.textContent = it.name;
    name.title = it.name;
    const meta = document.createElement('span');
    meta.className = 'history-meta';
    meta.textContent = `${formatSize(it.size)} · ${relativeTime(it.at)}`;
    li.append(name, meta);
    historyList.appendChild(li);
  }
}

// ── Mode switch ──────────────────────────────────────────────────────────────────
showTotpLink.addEventListener('click', e => { e.preventDefault(); formApikey.classList.add('hidden'); formTotp.classList.remove('hidden'); });
showApikeyLink.addEventListener('click', e => { e.preventDefault(); formTotp.classList.add('hidden'); formApikey.classList.remove('hidden'); });

// ── API key form ─────────────────────────────────────────────────────────────────
formApikey.addEventListener('submit', async e => {
  e.preventDefault();
  const apikey   = document.getElementById('apikey').value.trim();
  const errorDiv = document.getElementById('error-apikey');
  const btn      = formApikey.querySelector('button[type="submit"]');
  errorDiv.classList.remove('visible');
  btn.disabled = true;

  const result = await chrome.runtime.sendMessage({ type: 'LOGIN_APIKEY', apikey });
  if (result?.success) {
    showLoggedIn(result);
  } else {
    errorDiv.textContent = result?.message || 'Invalid API key.';
    errorDiv.classList.add('visible');
    btn.disabled = false;
  }
});

// ── TOTP form ────────────────────────────────────────────────────────────────────
formTotp.addEventListener('submit', async e => {
  e.preventDefault();
  const email    = document.getElementById('email').value.trim();
  const totp     = document.getElementById('totp').value.trim();
  const errorDiv = document.getElementById('error-totp');
  const btn      = formTotp.querySelector('button[type="submit"]');
  errorDiv.classList.remove('visible');
  btn.disabled = true;

  const result = await chrome.runtime.sendMessage({ type: 'LOGIN_TOTP', email, totp });
  if (result?.success) {
    showLoggedIn(result);
  } else {
    errorDiv.textContent = result?.message || 'Invalid email or code.';
    errorDiv.classList.add('visible');
    document.getElementById('totp').value = '';
    btn.disabled = false;
  }
});

document.getElementById('totp').addEventListener('input', e => {
  if (e.target.value.replace(/\D/g, '').length === 6) formTotp.requestSubmit?.();
});

// ── Actions ──────────────────────────────────────────────────────────────────────
logoutBtn.addEventListener('click', async () => {
  await chrome.runtime.sendMessage({ type: 'LOGOUT' });
  await init();
});

settingsBtn.addEventListener('click', () => chrome.runtime.openOptionsPage());

// ── Helpers ──────────────────────────────────────────────────────────────────────
function formatTimeRemaining(expiresAt) {
  const ms = new Date(expiresAt) - Date.now();
  if (ms <= 0) return 'expired';
  const mins = Math.ceil(ms / 60_000);
  return mins > 60 ? `${Math.round(mins / 60)}h` : `${mins}m`;
}

function relativeTime(at) {
  const s = Math.max(0, Math.round((Date.now() - at) / 1000));
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function formatSize(bytes) {
  if (bytes == null) return '';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

init();
