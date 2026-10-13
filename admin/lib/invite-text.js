'use strict';
// Sender-written text that goes into a mail from hello@paramant.app to
// somebody who is not our customer: the ParaSign invitation's subject and
// message. Same rule as relay.js veiligeBestandsnaam for ParaSend: printable
// text only, no link and no address.
//
// WHY. Subject and message were free text, only trimmed and cut (sweep-acct
// finding 6): "Paramant support: confirm your account at evil-example.com"
// went out from our own domain, with our DKIM, and a CR/LF in the subject went
// to the mail provider as-is.
const LINK = /\b(?:https?:\/\/|www\.)\S*/gi;
const ADDR = /\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/gi;
const BARE = /\b(?:[a-z0-9-]+\.)+(?:com|net|org|nl|be|de|eu|io|app|info|biz|co|uk|ru|xyz|top|site|online|link|click|live|shop)\b(?:\/\S*)?/gi;

function scrub(s) {
  return s
    .replace(/[\uD800-\uDFFF]/gu, '')
    .replace(LINK, '[link]')
    .replace(ADDR, '[adres]')
    .replace(BARE, '[link]');
}

// One line: CR, LF, tabs and every control character become a space.
function safeSubject(raw, max = 140) {
  return scrub(String(raw == null ? '' : raw).replace(/[\u0000-\u001f\u007f\u2028\u2029]+/g, ' '))
    .replace(/\s+/g, ' ').trim().slice(0, max);
}

// Lines are allowed (a message has paragraphs), other control characters not.
function safeMessage(raw, max = 1000) {
  return scrub(String(raw == null ? '' : raw)
    .replace(/\r\n?/g, '\n')
    .replace(/[\u0000-\u0009\u000b-\u001f\u007f\u2028\u2029]/g, ' '))
    .replace(/[ \t]+/g, ' ').replace(/\n{3,}/g, '\n\n').trim().slice(0, max);
}

module.exports = { safeSubject, safeMessage };
