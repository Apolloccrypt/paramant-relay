// link-block.js — builds the attachment link inserted into a compose body.
// Framework-agnostic (no chrome/Office APIs): shared by the Chromium content scripts and
// the Outlook add-in. Two formats: 'block' = a formatted card, 'plain' = a single line.
//
// Security: the filename comes from the user's disk and the URL carries a key fragment, so
// both are untrusted. Everything interpolated into HTML is escaped, and the href is
// restricted to the https paramant.app origins we mint. A crafted filename must never
// become live markup in the sender's mailbox.

const ALLOWED_URL = /^https:\/\/(paramant\.app|[a-z0-9-]+\.paramant\.app)\//i;

export function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

function safeUrl(url) {
  return ALLOWED_URL.test(url) ? url : '#';
}

const DEFAULT_STRINGS = {
  link_title:   'Encrypted attachment via Paramant',
  link_meta:    'End-to-end encrypted. Single download. Expires {expiry}.',
  link_sentvia: 'Sent via paramant.app',
};

// Interpolate {vars} into an already-translated template, escaping the literal segments and
// each value independently so neither can inject markup.
function fillEscaped(template, vars) {
  return template.replace(/\{(\w+)\}|([^{]+)/g, (m, key, lit) =>
    lit !== undefined ? escapeHtml(lit) : escapeHtml(String(vars[key] ?? ''))
  );
}

export function buildLinkHtml({ url, filename, expiresAt, format = 'block', t }) {
  const tr = key => (t && t(key)) || DEFAULT_STRINGS[key];
  const name = escapeHtml(filename);
  const href = escapeHtml(safeUrl(url));
  const meta = fillEscaped(tr('link_meta'), { expiry: formatExpiry(expiresAt) });

  if (format === 'plain') {
    return (
      `<div style="font-family:Arial,sans-serif;font-size:13px;margin:8px 0">` +
        `🔒 <a href="${href}" style="color:#1D4ED8;font-weight:600;text-decoration:none">${name}</a> ` +
        `<span style="color:#6B7280;font-size:11px">(${meta})</span>` +
      `</div>`
    );
  }

  return (
    `<div style="border:1px solid #0B3A6A;padding:12px;margin:12px 0;font-family:Arial,sans-serif;max-width:480px">` +
      `<div style="font-size:11px;color:#0B3A6A;text-transform:uppercase;letter-spacing:0.1em;font-weight:700;margin-bottom:8px">` +
        `🔒 ${escapeHtml(tr('link_title'))}` +
      `</div>` +
      `<a href="${href}" style="color:#1D4ED8;text-decoration:none;font-weight:600">${name}</a>` +
      `<div style="font-size:11px;color:#6B7280;margin-top:6px">${meta}</div>` +
      `<div style="font-size:10px;color:#9CA3AF;margin-top:8px">` +
        `<a href="https://paramant.app" style="color:#9CA3AF">${escapeHtml(tr('link_sentvia'))}</a>` +
      `</div>` +
    `</div>`
  );
}

export function formatExpiry(expiresAt) {
  const d = new Date(expiresAt);
  if (isNaN(d.getTime())) return '';
  try { return d.toLocaleString(); } catch { return d.toISOString(); }
}
