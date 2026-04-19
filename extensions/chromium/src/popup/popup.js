// DOM — states
const elLoading  = document.getElementById('state-loading');
const elLogin    = document.getElementById('state-login');
const elLoggedIn = document.getElementById('state-logged-in');

// DOM — login UI
const bannerRollingOut = document.getElementById('banner-rolling-out');
const formApikey       = document.getElementById('form-apikey');
const formTotp         = document.getElementById('form-totp');
const showTotpLink     = document.getElementById('show-totp');
const showApikeyLink   = document.getElementById('show-apikey');

// DOM — logged-in UI
const statusEmail  = document.getElementById('status-email');
const sessionTimer = document.getElementById('session-timer');
const logoutBtn    = document.getElementById('logout-btn');

// ── Init ──────────────────────────────────────────────────────────────────────

async function init() {
  showState('loading');

  const auth = await chrome.runtime.sendMessage({ type: 'CHECK_SESSION' });
  if (auth.authenticated) {
    showLoggedIn(auth);
    return;
  }

  const caps = await chrome.runtime.sendMessage({ type: 'GET_CAPABILITIES' });

  if (caps.user_totp) {
    showTotpLink.classList.remove('hidden');
    bannerRollingOut.classList.add('hidden');
  } else {
    showTotpLink.classList.add('hidden');
    bannerRollingOut.classList.remove('hidden');
  }

  showState('login');
}

// ── State management ──────────────────────────────────────────────────────────

function showState(name) {
  elLoading.classList.toggle('hidden', name !== 'loading');
  elLogin.classList.toggle('hidden', name !== 'login');
  elLoggedIn.classList.toggle('hidden', name !== 'logged-in');
}

function showLoggedIn(auth) {
  statusEmail.textContent = auth.email || '—';
  sessionTimer.textContent = formatTimeRemaining(auth.expires_at);
  showState('logged-in');
}

function switchToApikey() {
  formApikey.classList.remove('hidden');
  formTotp.classList.add('hidden');
}

function switchToTotp() {
  formApikey.classList.add('hidden');
  formTotp.classList.remove('hidden');
}

// ── Mode switch ───────────────────────────────────────────────────────────────

showTotpLink.addEventListener('click', e => { e.preventDefault(); switchToTotp(); });
showApikeyLink.addEventListener('click', e => { e.preventDefault(); switchToApikey(); });

// ── API key form ──────────────────────────────────────────────────────────────

formApikey.addEventListener('submit', async e => {
  e.preventDefault();
  const apikey   = document.getElementById('apikey').value.trim();
  const errorDiv = document.getElementById('error-apikey');
  const btn      = formApikey.querySelector('button[type="submit"]');

  errorDiv.classList.remove('visible');
  btn.disabled = true;

  const result = await chrome.runtime.sendMessage({ type: 'LOGIN_APIKEY', apikey });

  if (result.success) {
    showLoggedIn(result);
  } else {
    errorDiv.textContent = result.message || 'Invalid API key.';
    errorDiv.classList.add('visible');
    btn.disabled = false;
  }
});

// ── TOTP form ─────────────────────────────────────────────────────────────────

formTotp.addEventListener('submit', async e => {
  e.preventDefault();
  const email    = document.getElementById('email').value.trim();
  const totp     = document.getElementById('totp').value.trim();
  const errorDiv = document.getElementById('error-totp');
  const btn      = formTotp.querySelector('button[type="submit"]');

  errorDiv.classList.remove('visible');
  btn.disabled = true;

  const result = await chrome.runtime.sendMessage({ type: 'LOGIN_TOTP', email, totp });

  if (result.success) {
    showLoggedIn(result);
  } else {
    errorDiv.textContent = result.message || 'Invalid email or code.';
    errorDiv.classList.add('visible');
    document.getElementById('totp').value = '';
    btn.disabled = false;
  }
});

// Auto-advance when 6 digits entered
document.getElementById('totp').addEventListener('input', e => {
  if (e.target.value.replace(/\D/g, '').length === 6) {
    formTotp.requestSubmit?.() ?? formTotp.dispatchEvent(new Event('submit'));
  }
});

// ── Logout ────────────────────────────────────────────────────────────────────

logoutBtn.addEventListener('click', async () => {
  await chrome.runtime.sendMessage({ type: 'LOGOUT' });
  await init();
});

// ── Helpers ───────────────────────────────────────────────────────────────────

function formatTimeRemaining(expiresAt) {
  const ms = new Date(expiresAt) - Date.now();
  if (ms <= 0) return 'expired';
  const mins = Math.ceil(ms / 60_000);
  return mins > 60 ? `${Math.round(mins / 60)}h` : `${mins}m`;
}

init();
