
import { vaultAvailable, vaultList } from '/vendor/vault.js?v=5';

const escHtml = s => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#x27;');

function fmtTs(iso) {
  if (!iso) return '-';
  try { return new Date(iso).toLocaleString(); } catch { return iso; }
}

async function loadEnrolledKeys() {
  const listEl = document.getElementById('signing-list');
  const emptyEl = document.getElementById('signing-empty');
  try {
    const res = await fetch('/api/user/account/signing-key', { credentials: 'include' });
    if (!res.ok) {
      emptyEl.textContent = 'Could not load enrolled keys (HTTP ' + res.status + ').';
      return;
    }
    const data = await res.json();
    const keys = (data.keys || []);
    if (!keys.length) {
      emptyEl.textContent = 'No signing keys enrolled yet. Use "Set up your signing key" below to create one.';
      listEl.innerHTML = '';
      return;
    }
    emptyEl.hidden = true;
    listEl.innerHTML = keys.map(k => {
      const fp = escHtml((k.pk_hash_sha3 || '').slice(0, 16));
      const lbl = k.label ? escHtml(k.label) : '<em>no label</em>';
      const enrolled = escHtml(fmtTs(k.enrolled_at));
      const revoked = k.revoked_at ? ' &middot; revoked ' + escHtml(fmtTs(k.revoked_at)) : '';
      const alg = escHtml(k.alg || '?');
      const btn = k.revoked_at
        ? ''
        : '<button type="button" class="btn btn-secondary btn-small" data-revoke="' + escHtml(k.pk_hash_sha3) + '">Revoke</button>';
      return '<li style="padding:12px 0;border-bottom:1px solid var(--border-soft, #e5e7eb)">' +
        '<div style="font-weight:600">' + lbl + '</div>' +
        '<div class="mono small" style="margin:4px 0">' + fp + '...</div>' +
        '<div class="small" style="color:var(--muted, #6b7280)">' + alg + ' &middot; enrolled ' + enrolled + revoked + '</div>' +
        (btn ? '<div style="margin-top:8px">' + btn + '</div>' : '') +
        '</li>';
    }).join('');
    listEl.querySelectorAll('button[data-revoke]').forEach(b => {
      b.addEventListener('click', () => revokeKey(b.getAttribute('data-revoke')));
    });
  } catch (e) {
    emptyEl.textContent = 'Could not load enrolled keys: ' + e.message;
  }
}

function askRevokeTotp() {
  return new Promise((resolve) => {
    const wrap = document.getElementById('revoke-totp-wrap');
    const input = document.getElementById('revoke-totp');
    const ok = document.getElementById('revoke-totp-confirm');
    const cancel = document.getElementById('revoke-totp-cancel');
    if (!wrap || !input || !ok || !cancel) { resolve((window.prompt('Enter your 6-digit authenticator code to revoke this signing key.') || '').trim()); return; }
    input.value = ''; wrap.hidden = false; input.focus();
    const done = (v) => { ok.removeEventListener('click', onOk); cancel.removeEventListener('click', onCancel); input.removeEventListener('keydown', onKey); wrap.hidden = true; resolve(v); };
    const onOk = () => { const t = (input.value || '').trim(); if (!/^\d{6}$/.test(t)) { input.focus(); return; } done(t); };
    const onCancel = () => done('');
    const onKey = (e) => { if (e.key === 'Enter') { e.preventDefault(); onOk(); } if (e.key === 'Escape') onCancel(); };
    ok.addEventListener('click', onOk); cancel.addEventListener('click', onCancel); input.addEventListener('keydown', onKey);
  });
}
async function revokeKey(pkHash) {
  const totp = await askRevokeTotp();
  if (!totp) return;
  try {
    const res = await fetch('/api/user/account/signing-key', {
      method: 'DELETE',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pk_hash_sha3: pkHash, totp }),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) { alert('Revoke failed: ' + (body.error || ('HTTP ' + res.status))); return; }
    await loadEnrolledKeys();
  } catch (e) { alert('Revoke failed: ' + e.message); }
}

async function loadVaultStatus() {
  const el = document.getElementById('vault-status');
  if (!(await vaultAvailable())) {
    el.textContent = 'IndexedDB or WebCrypto is unavailable in this browser (private/incognito mode can cause this), so a signing key cannot be stored here.';
    return;
  }
  try {
    const list = await vaultList();
    if (!list.length) {
      el.textContent = 'No signing key in this browser yet. Use "Set up your signing key" below.';
      return;
    }
    const fmt = e => (e.label ? e.label : '(no label)') + ' [' + (e.pk_hash || '').slice(0, 12) + '...]';
    const last = list.reduce((acc, e) => (e.last_used_at && (!acc || e.last_used_at > acc) ? e.last_used_at : acc), null);
    el.textContent = list.length + ' key' + (list.length === 1 ? '' : 's') + ' saved in this browser'
      + (last ? '. Last used ' + fmtTs(last) : '. Never unlocked yet')
      + '. Keys: ' + list.map(fmt).join(', ');
  } catch (e) {
    el.textContent = 'Could not read browser vault: ' + e.message;
  }
}

loadEnrolledKeys();
loadVaultStatus();
document.addEventListener('signing-key-enrolled', () => { loadEnrolledKeys(); loadVaultStatus(); });
