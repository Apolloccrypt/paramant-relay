import {
  getCapabilities, loginWithApiKey, loginWithTotp, verifySession, logout, uploadAttachment,
} from '../shared/paramant-api.js';
import { getAttachments, removeAttachments, insertIntoBody } from '../shared/office-helpers.js';
import { buildLinkHtml } from '../../../shared/link-block.js';

Office.onReady(async (info) => {
  if (info.host !== Office.HostType.Outlook) return;

  const session = await verifySession();
  if (session.authenticated) {
    showStatus(session);
    await refreshAttachments();
    return;
  }

  const caps = await getCapabilities();
  const totpOn = !!caps.user_totp;
  document.getElementById('show-totp').classList.toggle('hidden', !totpOn);
  document.getElementById('banner-rolling-out').classList.toggle('hidden', totpOn);
  showLogin();
});

// ── Login state ───────────────────────────────────────────────────────────────────
function showLogin() {
  switchState('state-login');
  wireLoginForms();
}

let formsWired = false;
function wireLoginForms() {
  if (formsWired) return;
  formsWired = true;

  document.getElementById('show-totp').addEventListener('click', e => {
    e.preventDefault();
    document.getElementById('form-apikey').classList.add('hidden');
    document.getElementById('form-totp').classList.remove('hidden');
  });
  document.getElementById('show-apikey').addEventListener('click', e => {
    e.preventDefault();
    document.getElementById('form-totp').classList.add('hidden');
    document.getElementById('form-apikey').classList.remove('hidden');
  });

  document.getElementById('form-apikey').addEventListener('submit', async e => {
    e.preventDefault();
    const apikey   = document.getElementById('apikey').value.trim();
    const errorDiv = document.getElementById('error-apikey');
    const btn      = e.target.querySelector('button[type="submit"]');
    errorDiv.classList.remove('visible'); errorDiv.textContent = '';
    btn.disabled = true;

    const result = await loginWithApiKey(apikey);
    if (result.success) { showStatus(result); await refreshAttachments(); }
    else { showFormError(errorDiv, result.message || 'Invalid API key.'); btn.disabled = false; }
  });

  document.getElementById('form-totp').addEventListener('submit', async e => {
    e.preventDefault();
    const email    = document.getElementById('email').value.trim();
    const totp     = document.getElementById('totp').value.trim();
    const errorDiv = document.getElementById('error-totp');
    const btn      = e.target.querySelector('button[type="submit"]');
    errorDiv.classList.remove('visible'); errorDiv.textContent = '';
    btn.disabled = true;

    const result = await loginWithTotp(email, totp);
    if (result.success) { showStatus(result); await refreshAttachments(); }
    else { showFormError(errorDiv, result.message || 'Invalid email or code.'); document.getElementById('totp').value = ''; btn.disabled = false; }
  });
}

function showFormError(el, msg) { el.textContent = msg; el.classList.add('visible'); }

// ── Session status ──────────────────────────────────────────────────────────────────
function showStatus(session) {
  const label = session.email || (session.plan ? `Signed in · ${session.plan}` : 'Signed in');
  for (const id of ['status-email', 'status-email-2']) {
    const el = document.getElementById(id);
    if (el) el.textContent = label;
  }
}

// ── Attachments ───────────────────────────────────────────────────────────────────
async function refreshAttachments() {
  const attachments = (await getAttachments()).filter(a => a.attachmentType === 'file' || a.attachmentType === undefined);

  if (attachments.length === 0) {
    switchState('state-no-attachments');
    document.getElementById('refresh-btn').onclick = refreshAttachments;
  } else {
    switchState('state-has-attachments');
    const list = document.getElementById('attachment-list');
    list.textContent = '';
    for (const att of attachments) {
      const li = document.createElement('li');
      const name = document.createElement('span'); name.className = 'attach-name'; name.textContent = att.name;
      const size = document.createElement('span'); size.className = 'attach-size'; size.textContent = formatSize(att.size);
      li.append(name, size);
      list.appendChild(li);
    }
    document.getElementById('encrypt-btn').onclick = () => encryptAll(attachments);
  }

  for (const id of ['logout-btn', 'logout-btn-2']) {
    const btn = document.getElementById(id);
    if (btn) btn.onclick = doLogout;
  }
}

async function encryptAll(attachments) {
  const btn      = document.getElementById('encrypt-btn');
  const progress = document.getElementById('encrypt-progress');
  const bar      = document.getElementById('progress-bar');
  const text     = document.getElementById('progress-text');
  const ttlMs    = parseInt(document.getElementById('expiry').value, 10) * 1000;

  btn.disabled = true;
  progress.classList.remove('hidden');

  const n = attachments.length;
  const results = [];

  for (let i = 0; i < n; i++) {
    const att = attachments[i];
    text.textContent = `Encrypting ${i + 1}/${n}: ${att.name}`;
    const setOverall = frac => { bar.style.width = `${Math.round(((i + frac) / n) * 100)}%`; };
    setOverall(0);

    const result = await uploadAttachment(att, { ttlMs, onProgress: p => setOverall(p.fraction || 0) });
    if (!result.success) {
      text.textContent = friendly(result.message, att.name);
      text.classList.add('failed');
      btn.disabled = false;
      return;
    }
    results.push({ ...result, name: att.name });
    setOverall(1);
  }

  text.textContent = 'Updating email…';
  await insertParamantBlock(results);
  await removeAttachments(attachments.map(a => a.id));
  switchState('state-success');
}

async function insertParamantBlock(uploads) {
  const items = uploads.map(u =>
    buildLinkHtml({ url: u.shareUrl, filename: u.name, expiresAt: u.expiresAt, format: 'block' })
  ).join('');
  await insertIntoBody(`${items}<p></p>`);
}

async function doLogout() {
  await logout();
  formsWired = false;
  showLogin();
}

// ── Util ──────────────────────────────────────────────────────────────────────────
function switchState(stateId) {
  document.querySelectorAll('.state').forEach(el => el.classList.add('hidden'));
  document.getElementById(stateId).classList.remove('hidden');
}

function friendly(message, name) {
  const m = String(message || '');
  if (m === 'not_authenticated') return 'Session expired. Sign in again.';
  if (!m) return `Failed to encrypt ${name}`;
  return m; // relay messages are already human ("Max 5MB on trial", etc.)
}

function formatSize(bytes) {
  if (bytes == null) return '';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}
