// outlook.js — Outlook on the web adapter (outlook.live.com / office.com / office365.com).
// Native desktop Outlook is served by the separate Office.js add-in; this content script
// covers the browser webmail. All behaviour lives in the shared compose-inject module.

import { initCompose } from './compose-inject.js';

initCompose({
  composeSelector: '[role="dialog"][aria-label], div[class*="compose"], div[class*="Compose"]',
  attachSelector:  '[aria-label*="Attach"], [aria-label*="attach"], [data-icon-name="Attach"]',
  // The selector above only knows the English word. Outlook in Dutch labels the
  // button "Bijvoegen", and there the Paramant button never appeared (fase 1,
  // EXT-12-A). Same locale-independent fallback gmail.js has: match the attach
  // verb in the major UI languages, never the "insert"/"invoegen" controls.
  attachMatch: (label) =>
    /attach|bijvoeg|anfüg|anhäng|joindre|adjunt|allega|anexa|bifoga|vedlegg|liitä|csatol|załącz|přilož|вложи|添付|附加/i.test(label) &&
    !/invoeg|insert|insér|einfüg|onedrive/i.test(label),
  attachAttempts: 25,
  attachDelay: 200,
  findEditor(composeWin) {
    return composeWin.querySelector('[contenteditable="true"][role="textbox"]');
  },
});
