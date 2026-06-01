// gmail.js — Gmail host adapter. Selectors verified against Gmail as of early 2026; they
// are heuristic and may need updates after a Gmail redesign. All behaviour lives in the
// shared compose-inject module.

import { initCompose } from './compose-inject.js';

initCompose({
  // Full compose dialog + inline reply.
  composeSelector: '.nH.Hd[role="dialog"], .dw.dw-sk-bUdYId',
  attachSelector:  '[data-tooltip="Attach files"], [aria-label="Attach files"]',
  attachAttempts: 20,
  attachDelay: 150,
  findEditor(composeWin) {
    // Classic compose uses an iframe; modern compose a contenteditable div.
    const iframe = composeWin.querySelector('iframe');
    return iframe
      ? iframe.contentDocument?.querySelector('[contenteditable="true"]')
      : composeWin.querySelector('[contenteditable="true"][role="textbox"]');
  },
});
