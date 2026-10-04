import {
  loginWithApiKey, verifySession, logout, uploadAttachment,
} from '../shared/paramant-api.js';
import { getAttachments, removeAttachments, insertIntoBody } from '../shared/office-helpers.js';
import { buildLinkHtml } from '../../../shared/link-block.js';

// Guard against a second copy of this script on the page. Until 1.0.2 the
// template carried its own <script type=module> next to the one webpack
// injects, so every handler ran twice (fase 1, EXT-19-A).
if (window.__paramantTaskpane) throw new Error('taskpane.js loaded twice');
window.__paramantTaskpane = true;

Office.onReady(async (info) => {
  if (info.host !== Office.HostType.Outlook) return;

  const session = await verifySession();
  if (session.authenticated) {
    showStatus(session);
    await refreshAttachments();
    return;
  }
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
}

function showFormError(el, msg) { el.textContent = msg; el.classList.add('visible'); }

// Reveal the 402 upgrade notice with the plan/limit from the relay body. Text is
// set via textContent and the link target is a fixed paramant.app URL, so no inline
// script is introduced (the taskpane runs under the add-in host CSP).
function showQuotaNotice(info) {
  const box  = document.getElementById('quota-notice');
  const body = document.getElementById('quota-notice-text');
  const link = document.getElementById('quota-notice-link');
  const text = document.getElementById('progress-text');
  if (text) { text.textContent = ''; text.classList.remove('failed'); }
  if (!box || !body || !link) return;
  const planPart = info.plan ? ` on the ${info.plan} plan` : '';
  body.textContent = (info.limit || info.limit === 0)
    ? `You have used all ${info.limit} monthly transfer${info.limit === 1 ? '' : 's'}${planPart}. Upgrade to send more.`
    : `You have used this month's transfer allowance${planPart}. Upgrade to send more.`;
  link.href = info.upgradeUrl || 'https://paramant.app/pricing';
  box.classList.remove('hidden');
}

// ── Session status ──────────────────────────────────────────────────────────────────
function showStatus(session) {
  const label = session.email || (session.plan ? `Signed in · ${session.plan}` : 'Signed in');
  for (const id of ['status-email', 'status-email-2']) {
    const el = document.getElementById(id);
    if (el) el.textContent = label;
  }
}

// ── Attachments ───────────────────────────────────────────────────────────────────
async function fileAttachments() {
  return (await getAttachments()).filter(a => a.attachmentType === 'file' || a.attachmentType === undefined);
}

function sameList(a, b) {
  return a.length === b.length && a.every((x, i) => x.id === b[i].id);
}

let shown = [];
async function refreshAttachments() {
  const attachments = await fileAttachments();
  shown = attachments;
  const note = document.getElementById('progress-text');
  if (note) { note.textContent = ''; note.classList.remove('failed'); }
  document.getElementById('encrypt-progress')?.classList.add('hidden');
  document.getElementById('encrypt-btn').disabled = false;

  if (attachments.length === 0) {
    switchState('state-no-attachments');
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
  }
  // onclick, not addEventListener: refreshAttachments runs again on every
  // refresh, and an assignment replaces the handler instead of stacking one.
  document.getElementById('encrypt-btn').onclick = encryptCurrent;
  for (const id of ['refresh-btn', 'refresh-btn-2', 'back-btn']) {
    const btn = document.getElementById(id);
    if (btn) btn.onclick = refreshAttachments;
  }
  for (const id of ['logout-btn', 'logout-btn-2']) {
    const btn = document.getElementById(id);
    if (btn) btn.onclick = doLogout;
  }
}

// The list is read again at the click. An attachment added while the pane was
// open used to be skipped and sent unencrypted, under a success screen that
// said every original was removed (fase 1, EXT-21-A).
async function encryptCurrent() {
  const now = await fileAttachments();
  if (!sameList(now, shown)) {
    await refreshAttachments();
    const text = document.getElementById('progress-text');
    document.getElementById('encrypt-progress').classList.remove('hidden');
    text.textContent = 'The attachments changed. Check the list and click Encrypt again.';
    return;
  }
  await encryptAll(now);
}

async function encryptAll(attachments) {
  const btn      = document.getElementById('encrypt-btn');
  const progress = document.getElementById('encrypt-progress');
  const bar      = document.getElementById('progress-bar');
  const text     = document.getElementById('progress-text');
  const ttlMs    = parseInt(document.getElementById('expiry').value, 10) * 1000;

  btn.disabled = true;
  progress.classList.remove('hidden');
  text.classList.remove('failed');

  const n = attachments.length;
  const results = [];

  for (let i = 0; i < n; i++) {
    const att = attachments[i];
    text.textContent = `Encrypting ${i + 1}/${n}: ${att.name}`;
    const setOverall = frac => { bar.style.width = `${Math.round(((i + frac) / n) * 100)}%`; };
    setOverall(0);

    const result = await uploadAttachment(att, { ttlMs, onProgress: p => setOverall(p.fraction || 0) });
    if (!result.success) {
      if (result.code === 'quota_reached') {
        showQuotaNotice(result);
      } else {
        text.textContent = friendly(result.message, att.name);
        text.classList.add('failed');
      }
      btn.disabled = false;
      return;
    }
    results.push({ ...result, name: att.name });
    setOverall(1);
  }

  text.textContent = 'Updating email…';
  await insertParamantBlock(results);
  await removeAttachments(attachments.map(a => a.id));

  // Whatever is still attached now (added during the upload) goes out as a
  // plain attachment. Say so instead of claiming everything was removed.
  const left = await fileAttachments();
  const successText = document.getElementById('success-text');
  if (successText) {
    successText.textContent = left.length
      ? `Paramant links have been added to your email body. ${left.length} attachment${left.length === 1 ? ' was' : 's were'} added during encryption and ${left.length === 1 ? 'is' : 'are'} still a normal, unencrypted attachment: ${left.map(a => a.name).join(', ')}. Click "Back to attachments" to encrypt ${left.length === 1 ? 'it' : 'them'} too.`
      : 'Paramant links have been added to your email body. The original attachments have been removed.';
  }
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
  if (m === 'not_authenticated') return 'Your sign-in has expired. Sign in again.';
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
