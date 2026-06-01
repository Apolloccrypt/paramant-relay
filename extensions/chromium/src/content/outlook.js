// outlook.js — Outlook on the web adapter (outlook.live.com / office.com / office365.com).
// Native desktop Outlook is served by the separate Office.js add-in; this content script
// covers the browser webmail. All behaviour lives in the shared compose-inject module.

import { initCompose } from './compose-inject.js';

initCompose({
  composeSelector: '[role="dialog"][aria-label], div[class*="compose"], div[class*="Compose"]',
  attachSelector:  '[aria-label*="Attach"], [aria-label*="attach"], [data-icon-name="Attach"]',
  attachAttempts: 25,
  attachDelay: 200,
  findEditor(composeWin) {
    return composeWin.querySelector('[contenteditable="true"][role="textbox"]');
  },
});
