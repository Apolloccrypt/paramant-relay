// link-replace.js — stub for Week 3+
// Will handle removing an existing attachment node from Gmail/Outlook DOM
// and replacing it with the Paramant link block.
// Kept separate to isolate the host-specific DOM surgery.

export function buildLinkBlock(url, filename, expiresAt) {
  const expiry = new Date(expiresAt).toLocaleString();
  return `
    <div style="border:1px solid #0B3A6A;padding:12px;margin:12px 0;font-family:sans-serif;max-width:480px">
      <div style="font-size:11px;color:#0B3A6A;text-transform:uppercase;letter-spacing:0.1em;font-weight:700;margin-bottom:8px">
        🔒 Encrypted attachment via Paramant
      </div>
      <a href="${url}" style="color:#1D4ED8;text-decoration:none;font-weight:600">${filename}</a>
      <div style="font-size:11px;color:#6B7280;margin-top:6px">
        End-to-end encrypted · single-read · expires ${expiry}
      </div>
      <div style="font-size:10px;color:#9CA3AF;margin-top:8px">
        Sent via <a href="https://paramant.app" style="color:#9CA3AF">paramant.app</a>
      </div>
    </div>
  `.trim();
}
