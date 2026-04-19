// banner.js — injected before gmail.js / outlook.js
// Runs as a plain content script (no ES module imports).
// Attaches helpers to window.ParamantBanner so gmail.js / outlook.js can use them.

(function () {
  'use strict';

  // ── Banner UI ───────────────────────────────────────────────────────────────

  function showBanner({ message, actions, anchor }) {
    return new Promise(resolve => {
      const existing = document.getElementById('paramant-banner');
      if (existing) existing.remove();

      const banner = document.createElement('div');
      banner.id = 'paramant-banner';
      banner.className = 'paramant-banner';
      banner.setAttribute('role', 'alertdialog');
      banner.setAttribute('aria-label', 'Paramant attachment prompt');

      const icon = `<svg class="paramant-banner-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <rect x="5" y="11" width="14" height="10" rx="0" stroke="#0B3A6A" stroke-width="1.5" fill="none"/>
        <path d="M8 11V7a4 4 0 0 1 8 0v4" stroke="#0B3A6A" stroke-width="1.5" fill="none"/>
        <circle cx="12" cy="16" r="1.5" fill="#1D4ED8"/>
      </svg>`;

      banner.innerHTML = `
        <div class="paramant-banner-body">
          ${icon}
          <span class="paramant-banner-msg">${message}</span>
        </div>
        <div class="paramant-banner-actions">
          ${actions.map((a, i) =>
            `<button class="paramant-btn ${a.primary ? 'paramant-btn-primary' : 'paramant-btn-secondary'}"
                     data-value="${i}">${a.label}</button>`
          ).join('')}
        </div>
      `;

      banner.querySelectorAll('.paramant-btn').forEach(btn => {
        btn.addEventListener('click', () => {
          const idx = parseInt(btn.dataset.value, 10);
          banner.remove();
          resolve(actions[idx].value);
        });
      });

      // Dismiss on Escape
      const onKey = e => {
        if (e.key === 'Escape') {
          banner.remove();
          document.removeEventListener('keydown', onKey);
          resolve(false);
        }
      };
      document.addEventListener('keydown', onKey);

      // Anchor inside compose window, or fallback to top of body
      const container = anchor ?? document.body;
      container.insertBefore(banner, container.firstChild);
    });
  }

  // ── Upload progress UI ──────────────────────────────────────────────────────

  function showUploadUI(filename) {
    const existing = document.getElementById('paramant-upload-ui');
    if (existing) existing.remove();

    const el = document.createElement('div');
    el.id = 'paramant-upload-ui';
    el.className = 'paramant-upload-ui';
    el.innerHTML = `
      <span class="paramant-upload-spinner" aria-hidden="true"></span>
      <span>Encrypting and uploading <strong>${filename}</strong>…</span>
    `;
    document.body.appendChild(el);
  }

  function hideUploadUI() {
    document.getElementById('paramant-upload-ui')?.remove();
  }

  function showError(message) {
    hideUploadUI();
    const el = document.createElement('div');
    el.className = 'paramant-upload-ui paramant-upload-error';
    el.textContent = message;
    document.body.appendChild(el);
    setTimeout(() => el.remove(), 4000);
  }

  // ── Exports via global namespace ────────────────────────────────────────────

  window.ParamantBanner = { showBanner, showUploadUI, hideUploadUI, showError };
})();
