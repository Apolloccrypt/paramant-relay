// compose-inject.js — host-agnostic compose integration shared by gmail.js and outlook.js.
//
// Flow: watch for compose windows → inject a "Paramant" button next to the native attach
// button → on click, read the chosen file(s) in plaintext chunks and stream them to the
// service worker (which encrypts + uploads each chunk) → insert the resulting burn-on-read
// link into the compose body. The page never sees the API key, and the whole file is never
// held in memory at once (chunks are sliced lazily from disk).

import { CHUNK_PLAIN } from '../../../shared/paramant-core.js';
import { startUpload, showError } from './shared/banner.js';
import { buildLinkHtml } from './shared/link-replace.js';
import { getSettings } from '../shared/settings.js';

// ── i18n ─────────────────────────────────────────────────────────────────────────
const FALLBACK = {
  btn_label:    'Paramant',
  btn_aria:     'Send encrypted attachment via Paramant',
  msg_signin:   'Sign in to Paramant: click the Paramant icon in your browser toolbar.',
  err_network:  'Network error. Check your connection and try again.',
  err_upload:   'Upload failed. Please try again.',
  err_incomplete: 'Upload did not finish. Please try again.',
  success_inserted: 'Encrypted link inserted',
  link_title:   'Encrypted attachment via Paramant',
  link_meta:    'End-to-end encrypted. Single download. Expires {expiry}.',
  link_sentvia: 'Sent via paramant.app',
};
function t(key) {
  try { return chrome.i18n.getMessage(key) || FALLBACK[key] || key; }
  catch { return FALLBACK[key] || key; }
}

const send = msg => chrome.runtime.sendMessage(msg);

// ── Public entry ───────────────────────────────────────────────────────────────────

export function initCompose(config) {
  const injected = new WeakSet();

  const scan = () => {
    document.querySelectorAll(config.composeSelector).forEach(win => {
      if (injected.has(win)) return;
      injected.add(win);
      waitForAttachButton(win, config);
    });
  };

  new MutationObserver(scan).observe(document.body, { childList: true, subtree: true });
  scan(); // catch compose windows already open
}

function waitForAttachButton(composeWin, config, attempts = 0) {
  const btn = composeWin.querySelector(config.attachSelector);
  if (btn) return injectButton(composeWin, btn, config);
  if (attempts < (config.attachAttempts ?? 25)) {
    setTimeout(() => waitForAttachButton(composeWin, config, attempts + 1), config.attachDelay ?? 180);
  }
}

function injectButton(composeWin, attachBtn, config) {
  if (composeWin.querySelector('.paramant-attach-btn')) return;

  const btn = document.createElement('div');
  btn.className = 'paramant-attach-btn';
  btn.setAttribute('role', 'button');
  btn.setAttribute('tabindex', '0');
  btn.setAttribute('aria-label', t('btn_aria'));
  btn.title = t('btn_aria');

  const svg = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <rect x="5" y="11" width="14" height="10" stroke="currentColor" stroke-width="1.5" fill="none"/>
    <path d="M8 11V7a4 4 0 0 1 8 0v4" stroke="currentColor" stroke-width="1.5" fill="none"/>
    <circle cx="12" cy="16" r="1.5" fill="currentColor"/></svg>`;
  btn.insertAdjacentHTML('beforeend', svg);
  btn.appendChild(Object.assign(document.createElement('span'), { textContent: t('btn_label') }));

  const activate = () => openPickerAndSend(composeWin, config);
  btn.addEventListener('click', activate);
  btn.addEventListener('keydown', e => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); activate(); }
  });

  attachBtn.parentElement.insertBefore(btn, attachBtn.nextSibling);
}

// ── Click → pick → upload → insert ──────────────────────────────────────────────────

async function openPickerAndSend(composeWin, config) {
  const auth = await send({ type: 'CHECK_SESSION' });
  if (!auth?.authenticated) {
    send({ type: 'OPEN_POPUP' }).catch(() => {});
    showError(t('msg_signin'));
    return;
  }

  const input = document.createElement('input');
  input.type = 'file';
  input.multiple = true;
  input.style.display = 'none';
  document.body.appendChild(input);

  input.onchange = async () => {
    const files = Array.from(input.files || []);
    input.remove();
    for (const file of files) {
      await uploadOne(composeWin, file, config);
    }
  };
  input.click();
}

async function uploadOne(composeWin, file, config) {
  let cancelled = false;
  const ui = startUpload(file.name, { onCancel: () => { cancelled = true; } });

  let transferId;
  try {
    const begin = await send({ type: 'TRANSFER_BEGIN', file: { name: file.name, size: file.size } });
    if (!begin?.ok) throw new TransferError(begin?.error);
    transferId = begin.transferId;
    const total = begin.totalChunks;

    for (let i = 0; i < total; i++) {
      if (cancelled) { await send({ type: 'TRANSFER_ABORT', transferId }).catch(() => {}); ui.remove(); return; }
      const slice = file.slice(i * CHUNK_PLAIN, Math.min((i + 1) * CHUNK_PLAIN, file.size));
      const bytes = await slice.arrayBuffer();
      const res = await send({ type: 'TRANSFER_CHUNK', transferId, index: i, bytes });
      if (!res?.ok) throw new TransferError(res?.error);
      ui.setProgress((i + 1) / total);
    }

    const fin = await send({ type: 'TRANSFER_FINISH', transferId });
    if (!fin?.ok) throw new TransferError(fin?.error || 'incomplete');

    const { link_format } = await getSettings();
    const html = buildLinkHtml({ url: fin.shareUrl, filename: file.name, expiresAt: fin.expiresAt, format: link_format, t });
    insertHtml(config.findEditor(composeWin), html);
    ui.succeed(t('success_inserted'));
  } catch (err) {
    if (transferId) send({ type: 'TRANSFER_ABORT', transferId }).catch(() => {});
    ui.fail(friendlyError(err));
  }
}

class TransferError extends Error {}

function friendlyError(err) {
  const m = String(err?.message || err || '');
  if (m === 'not_authenticated') return t('msg_signin');
  if (m === 'incomplete_transfer' || m === 'incomplete' || m === 'unknown_transfer') return t('err_incomplete');
  if (/network/i.test(m)) return t('err_network');
  if (!m || m === 'undefined') return t('err_upload');
  return m; // relay messages ("Max 5MB on trial", "Daily upload limit reached") are already human
}

// ── Robust insertion into a contenteditable compose body ────────────────────────────

function insertHtml(editor, html) {
  if (!editor) { showError(t('err_upload')); return; }
  const doc = editor.ownerDocument;
  editor.focus();

  const sel = doc.getSelection ? doc.getSelection() : null;
  let range;
  if (sel && sel.rangeCount && editor.contains(sel.anchorNode)) {
    range = sel.getRangeAt(0);
  } else {
    range = doc.createRange();
    range.selectNodeContents(editor);
    range.collapse(false); // caret at end
    sel?.removeAllRanges();
    sel?.addRange(range);
  }

  let ok = false;
  try { ok = doc.execCommand('insertHTML', false, html); } catch { ok = false; }
  if (ok) return;

  // Fallback when execCommand is unavailable: parse to nodes and splice in.
  const tpl = doc.createElement('template');
  tpl.innerHTML = html;
  range.deleteContents();
  range.insertNode(tpl.content);
}
