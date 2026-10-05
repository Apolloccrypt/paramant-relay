// gmail.js — Gmail host adapter. Selectors verified against Gmail as of early 2026; they
// are heuristic and may need updates after a Gmail redesign. All behaviour lives in the
// shared compose-inject module.

import { initCompose } from './compose-inject.js';

initCompose({
  // Full compose dialog + inline reply.
  composeSelector: '.nH.Hd[role="dialog"], .dw.dw-sk-bUdYId',
  // Fast path: the English exact label. Fallback below handles every other UI language.
  attachSelector:  '[data-tooltip="Attach files"], [aria-label="Attach files"]',
  // Locale-independent match on the attach button's tooltip/aria-label. We match the "file"
  // noun in the major Gmail UI languages and exclude the Drive "insert files" button (whose
  // verb is insert/invoegen/einfügen/insérer/insertar) so we never grab the wrong control.
  // This is what makes the button appear in e.g. Dutch ("Bestanden bijvoegen") Gmail.
  attachMatch: (label) =>
    /bestand|file|datei|fichier|archivo|allegat|arquivo|ficheiro|vedlegg|bilaga|liite|melléklet|załącz|příloh|вложение|附件|添付/i.test(label) &&
    !/invoeg|insert|insér|inser|einfüg|drive/i.test(label),
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
