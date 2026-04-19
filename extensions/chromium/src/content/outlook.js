// outlook.js — injects Paramant button into Outlook web compose windows
// Runs as a plain content script after banner.js.
// Covers outlook.live.com, outlook.office.com, outlook.office365.com.

(function () {
  'use strict';

  const { showUploadUI, hideUploadUI, showError } = window.ParamantBanner;

  // Outlook selectors — heuristic, detected at runtime per host.
  // The new Outlook (2024+) uses OWA-style markup on all three hosts.
  const SELECTORS = {
    compose_window: '[role="dialog"][aria-label], div[class*="compose"], div[class*="Compose"]',
    attach_button:  '[aria-label*="Attach"], [aria-label*="attach"], [data-icon-name="Attach"]',
    body_editor:    '[contenteditable="true"][role="textbox"]',
  };

  const injectedWindows = new WeakSet();

  // ── Observe compose windows ─────────────────────────────────────────────────

  function observeComposeWindows() {
    const observer = new MutationObserver(() => {
      document.querySelectorAll(SELECTORS.compose_window).forEach(win => {
        if (!injectedWindows.has(win)) {
          injectedWindows.add(win);
          waitForAttachButton(win);
        }
      });
    });

    observer.observe(document.body, { childList: true, subtree: true });
  }

  function waitForAttachButton(composeWin, attempts = 0) {
    const btn = composeWin.querySelector(SELECTORS.attach_button);
    if (btn) {
      injectParamantButton(composeWin, btn);
      return;
    }
    if (attempts < 25) {
      setTimeout(() => waitForAttachButton(composeWin, attempts + 1), 200);
    }
  }

  // ── Button injection ────────────────────────────────────────────────────────

  function injectParamantButton(composeWin, attachBtn) {
    if (composeWin.querySelector('.paramant-attach-btn')) return;

    const btn = document.createElement('div');
    btn.className = 'paramant-attach-btn';
    btn.setAttribute('role', 'button');
    btn.setAttribute('tabindex', '0');
    btn.setAttribute('aria-label', 'Send encrypted attachment via Paramant');
    btn.innerHTML = `
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <rect x="5" y="11" width="14" height="10" stroke="currentColor" stroke-width="1.5" fill="none"/>
        <path d="M8 11V7a4 4 0 0 1 8 0v4" stroke="currentColor" stroke-width="1.5" fill="none"/>
        <circle cx="12" cy="16" r="1.5" fill="currentColor"/>
      </svg>
      <span>Paramant</span>
    `;

    btn.addEventListener('click', () => openFilePickerAndSend(composeWin));
    btn.addEventListener('keydown', e => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        openFilePickerAndSend(composeWin);
      }
    });

    attachBtn.parentElement.insertBefore(btn, attachBtn.nextSibling);
  }

  // ── File picker + upload ────────────────────────────────────────────────────

  async function openFilePickerAndSend(composeWin) {
    const auth = await chrome.runtime.sendMessage({ type: 'CHECK_SESSION' });
    if (!auth.authenticated) {
      chrome.runtime.sendMessage({ type: 'OPEN_POPUP' });
      return;
    }

    const input = document.createElement('input');
    input.type = 'file';
    input.style.display = 'none';
    document.body.appendChild(input);

    input.onchange = async () => {
      const file = input.files[0];
      document.body.removeChild(input);
      if (!file) return;

      showUploadUI(file.name);

      const buffer = await file.arrayBuffer();
      const result = await chrome.runtime.sendMessage({
        type: 'UPLOAD_FILE',
        fileData: buffer,
        metadata: { filename: file.name, size: file.size, type: file.type },
      });

      hideUploadUI();

      if (result.success) {
        insertLinkIntoOutlook(composeWin, result.share_url, file.name, result.expires_at);
      } else {
        showError('Upload failed. Please try again.');
      }
    };

    input.click();
  }

  // ── Link insertion ──────────────────────────────────────────────────────────

  function insertLinkIntoOutlook(composeWin, url, filename, expiresAt) {
    const editor = composeWin.querySelector(SELECTORS.body_editor);
    if (!editor) {
      console.warn('[Paramant] Could not find Outlook compose editor');
      return;
    }

    editor.focus();
    const expiry = new Date(expiresAt).toLocaleString();

    const html = `
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
      <p></p>
    `;

    document.execCommand('insertHTML', false, html);
  }

  // ── Init ────────────────────────────────────────────────────────────────────

  observeComposeWindows();
})();
