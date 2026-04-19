import { login, verifySession, logout, uploadAttachment } from '../shared/paramant-api.js';
import { getAttachments, removeAttachments, insertIntoBody } from '../shared/office-helpers.js';

Office.onReady(async (info) => {
  if (info.host !== Office.HostType.Outlook) return;

  const session = await verifySession();
  if (session.authenticated) {
    showEmail(session.email);
    await refreshAttachments();
  } else {
    showLogin();
  }
});

function showLogin() {
  switchState('state-login');
  document.getElementById('login-form').addEventListener('submit', onLoginSubmit);
}

async function onLoginSubmit(e) {
  e.preventDefault();
  const email = document.getElementById('email').value.trim();
  const totp = document.getElementById('totp').value.trim();
  const errorDiv = document.getElementById('login-error');

  errorDiv.classList.remove('visible');

  const result = await login(email, totp);
  if (result.success) {
    showEmail(email);
    await refreshAttachments();
  } else {
    errorDiv.textContent = result.message || 'Invalid email or code';
    errorDiv.classList.add('visible');
    document.getElementById('totp').value = '';
  }
}

function showEmail(email) {
  for (const id of ['status-email', 'status-email-2']) {
    const el = document.getElementById(id);
    if (el) el.textContent = email;
  }
}

async function refreshAttachments() {
  const attachments = await getAttachments();

  if (attachments.length === 0) {
    switchState('state-no-attachments');
    document.getElementById('refresh-btn').addEventListener('click', refreshAttachments);
  } else {
    switchState('state-has-attachments');

    const list = document.getElementById('attachment-list');
    list.innerHTML = '';
    for (const att of attachments) {
      const li = document.createElement('li');
      li.innerHTML = `
        <span class="attach-name">${escapeHtml(att.name)}</span>
        <span class="attach-size">${formatSize(att.size)}</span>
      `;
      list.appendChild(li);
    }

    document.getElementById('encrypt-btn').addEventListener('click', () => encryptAll(attachments));
  }

  for (const id of ['logout-btn', 'logout-btn-2']) {
    const btn = document.getElementById(id);
    if (btn) btn.addEventListener('click', doLogout);
  }
}

async function encryptAll(attachments) {
  const btn = document.getElementById('encrypt-btn');
  const progress = document.getElementById('encrypt-progress');
  const bar = document.getElementById('progress-bar');
  const text = document.getElementById('progress-text');
  const expiry = parseInt(document.getElementById('expiry').value);

  btn.disabled = true;
  progress.classList.remove('hidden');

  const results = [];

  for (let i = 0; i < attachments.length; i++) {
    const att = attachments[i];
    text.textContent = `Encrypting ${i + 1}/${attachments.length}: ${att.name}`;
    bar.style.width = `${(i / attachments.length) * 100}%`;

    const result = await uploadAttachment(att, { ttl_seconds: expiry });
    if (result.success) {
      results.push({ ...result, name: att.name });
    } else {
      text.textContent = `Failed to encrypt ${att.name}`;
      btn.disabled = false;
      return;
    }
  }

  bar.style.width = '100%';
  text.textContent = 'Updating email...';

  await insertParamantBlock(results);
  await removeAttachments(attachments.map(a => a.id));

  switchState('state-success');
}

async function insertParamantBlock(uploads) {
  const html = `
    <div style="border: 1px solid #0B3A6A; padding: 16px; margin: 16px 0; font-family: Arial, sans-serif;">
      <div style="font-family: 'Courier New', monospace; font-size: 11px; color: #0B3A6A; text-transform: uppercase; letter-spacing: 0.1em; font-weight: 700; margin-bottom: 12px;">
        🔒 Encrypted attachments via Paramant
      </div>
      ${uploads.map(u => `
        <div style="margin: 8px 0;">
          <a href="${u.share_url}" style="color: #1D4ED8; font-weight: 600; text-decoration: none;">
            ${escapeHtml(u.name)}
          </a>
          <div style="font-size: 11px; color: #6B7280;">
            Expires ${new Date(u.expires_at).toLocaleString()}
          </div>
        </div>
      `).join('')}
      <div style="font-size: 10px; color: #9CA3AF; margin-top: 12px; border-top: 1px solid #E2E8F0; padding-top: 8px;">
        End-to-end encrypted. Burn-on-read. Sent via
        <a href="https://paramant.app" style="color: #9CA3AF;">paramant.app</a>
      </div>
    </div>
    <p></p>
  `;

  await insertIntoBody(html);
}

async function doLogout() {
  await logout();
  showLogin();
}

function switchState(stateId) {
  document.querySelectorAll('.state').forEach(el => el.classList.add('hidden'));
  document.getElementById(stateId).classList.remove('hidden');
}

function escapeHtml(s) {
  return s.replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}
