// gmail.js — injects Paramant button into Gmail compose windows
// Runs as a plain content script after banner.js.
// Approach 2 from spec: dedicated "Paramant" button, no post-hoc interception.

(function () {
  'use strict';

  const { showUploadUI, hideUploadUI, showError } = window.ParamantBanner;

  // Gmail selectors — verified against Gmail as of early 2026.
  // These are heuristic and may need updates if Gmail ships a redesign.
  const COMPOSE_SELECTOR    = '.nH.Hd[role="dialog"], .dw.dw-sk-bUdYId'; // full compose + inline reply
  const ATTACH_BTN_SELECTOR = '[data-tooltip="Attach files"], [aria-label="Attach files"]';

  const injectedWindows = new WeakSet();

  // ── Observe compose window creation ────────────────────────────────────────

  function observeComposeWindows() {
    const bodyObserver = new MutationObserver(() => {
      document.querySelectorAll(COMPOSE_SELECTOR).forEach(win => {
        if (!injectedWindows.has(win)) {
          injectedWindows.add(win);
          waitForAttachButton(win);
        }
      });
    });

    bodyObserver.observe(document.body, { childList: true, subtree: true });

    // Also handle any already-open compose windows
    document.querySelectorAll(COMPOSE_SELECTOR).forEach(win => {
      if (!injectedWindows.has(win)) {
        injectedWindows.add(win);
        waitForAttachButton(win);
      }
    });
  }

  // Gmail renders the toolbar lazily; poll briefly before giving up.
  function waitForAttachButton(composeWin, attempts = 0) {
    const btn = composeWin.querySelector(ATTACH_BTN_SELECTOR);
    if (btn) {
      injectParamantButton(composeWin, btn);
      return;
    }
    if (attempts < 20) {
      setTimeout(() => waitForAttachButton(composeWin, attempts + 1), 150);
    }
  }

  // ── Button injection ────────────────────────────────────────────────────────

  function injectParamantButton(composeWin, attachBtn) {
    if (composeWin.querySelector('.paramant-attach-btn')) return;

    const btn = createParamantButton();
    btn.addEventListener('click', () => openFilePickerAndSend(composeWin));
    btn.addEventListener('keydown', e => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        openFilePickerAndSend(composeWin);
      }
    });

    attachBtn.parentElement.insertBefore(btn, attachBtn.nextSibling);
  }

  function createParamantButton() {
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
    return btn;
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
        insertLinkIntoGmail(composeWin, result.share_url, file.name, result.expires_at);
      } else {
        showError('Upload failed. Please try again.');
      }
    };

    input.click();
  }

  // ── Link insertion ──────────────────────────────────────────────────────────

  function insertLinkIntoGmail(composeWin, url, filename, expiresAt) {
    // Gmail compose body is inside an iframe in classic mode, or a contenteditable in new mode.
    const iframe = composeWin.querySelector('iframe');
    const editor = iframe
      ? iframe.contentDocument?.querySelector('[contenteditable="true"]')
      : composeWin.querySelector('[contenteditable="true"][role="textbox"]');

    if (!editor) {
      console.warn('[Paramant] Could not find Gmail compose editor');
      return;
    }

    editor.focus();
    document.execCommand('insertHTML', false, buildLinkHtml(url, filename, expiresAt));
  }

  function buildLinkHtml(url, filename, expiresAt) {
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
    `;
  }

  // ── Init ────────────────────────────────────────────────────────────────────

  observeComposeWindows();
})();
