const elLoading   = document.getElementById('state-loading');
const elLogin     = document.getElementById('state-login');
const elLoggedIn  = document.getElementById('state-logged-in');
const form        = document.getElementById('login-form');
const errorDiv    = document.getElementById('error');
const submitBtn   = document.getElementById('submit-btn');
const statusEmail = document.getElementById('status-email');
const sessionTimer = document.getElementById('session-timer');
const logoutBtn   = document.getElementById('logout-btn');

// ── Session check ─────────────────────────────────────────────────────────────

async function checkSession() {
  showState('loading');
  const result = await chrome.runtime.sendMessage({ type: 'CHECK_SESSION' });

  if (result.authenticated) {
    statusEmail.textContent = result.email;
    sessionTimer.textContent = formatTimeRemaining(result.expires_at);
    showState('logged-in');
  } else {
    showState('login');
  }
}

function showState(name) {
  elLoading.classList.toggle('hidden', name !== 'loading');
  elLogin.classList.toggle('hidden', name !== 'login');
  elLoggedIn.classList.toggle('hidden', name !== 'logged-in');
}

// ── Login form ────────────────────────────────────────────────────────────────

form.addEventListener('submit', async e => {
  e.preventDefault();
  clearError();
  setSubmitting(true);

  const email = document.getElementById('email').value.trim();
  const totp  = document.getElementById('totp').value.trim();

  const result = await chrome.runtime.sendMessage({ type: 'LOGIN', email, totp });

  if (result.success) {
    await checkSession();
  } else {
    showError(result.message ?? 'Invalid email or code.');
    document.getElementById('totp').value = '';
    document.getElementById('totp').focus();
  }

  setSubmitting(false);
});

// Auto-advance when 6 digits entered
document.getElementById('totp').addEventListener('input', e => {
  if (e.target.value.replace(/\D/g, '').length === 6) {
    form.requestSubmit?.() ?? form.dispatchEvent(new Event('submit'));
  }
});

// ── Logout ────────────────────────────────────────────────────────────────────

logoutBtn.addEventListener('click', async () => {
  await chrome.runtime.sendMessage({ type: 'LOGOUT' });
  await checkSession();
});

// ── Helpers ───────────────────────────────────────────────────────────────────

function showError(msg) {
  errorDiv.textContent = msg;
  errorDiv.classList.add('visible');
}

function clearError() {
  errorDiv.textContent = '';
  errorDiv.classList.remove('visible');
}

function setSubmitting(busy) {
  submitBtn.disabled = busy;
  submitBtn.textContent = busy ? 'Signing in…' : 'Sign in';
}

function formatTimeRemaining(expiresAt) {
  const ms = new Date(expiresAt) - Date.now();
  if (ms <= 0) return 'expired';
  const mins = Math.ceil(ms / 60_000);
  return mins > 60 ? `${Math.round(mins / 60)}h` : `${mins}m`;
}

// ── Init ──────────────────────────────────────────────────────────────────────

checkSession();
