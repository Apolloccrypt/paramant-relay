/* The receiving end of a send to named recipients.
 *
 * Two calls, and nothing else:
 *   GET  /v2/pickup/:token          mails a code to the address the invitation
 *                                   went to, and answers with that address
 *                                   masked. Does not claim the link.
 *   POST /v2/pickup/:token {code}   returns the bytes, once.
 *
 * No account, no session, no cookie. Whoever holds the link and can read that
 * mailbox is the person this file is for, and proving both is the whole check.
 *
 * ASCII-only, no dependencies, same as the rest of the frontend.
 */
(function () {
  'use strict';

  // The token is the last path segment: /ontvang/<token>.
  var TOKEN = (function () {
    var parts = location.pathname.split('/').filter(Boolean);
    return parts.length ? decodeURIComponent(parts[parts.length - 1]) : '';
  })();

  var el = function (id) { return document.getElementById(id); };
  var show = function (id) { var n = el(id); if (n) n.hidden = false; };
  var hide = function (id) { var n = el(id); if (n) n.hidden = true; };

  function say(id, text, tone) {
    var n = el(id);
    if (!n) return;
    n.textContent = text || '';
    n.className = 'say' + (tone ? ' ' + tone : '');
  }

  // One sentence per reason, written for the person holding the link rather
  // than for a log. "Gone" and "already used" are different facts and a reader
  // needs to know which one applies to them.
  var WORDS = {
    unknown_token: ['This link cannot be used',
      'The link is not one we recognise. It may have been copied incompletely from the email.'],
    already_collected: ['You already collected this file',
      'This link works once, and it has been used. If you need the file again, ask the sender for a new link.'],
    revoked: ['The sender withdrew this link',
      'Whoever sent the file took this link back. The file itself is untouched; ask them for a new one.'],
    expired: ['This file is no longer available',
      'The window the sender set has closed and the file has been deleted. Ask them to send it again.'],
    pickup_failed: ['Something went wrong on our side',
      'That is not your doing. Try again in a minute.'],
  };

  function stop(reason) {
    var w = WORDS[reason] || WORDS.pickup_failed;
    var t = el('stop-title'), l = el('stop-line');
    if (t) t.textContent = w[0];
    if (l) l.textContent = w[1];
    hide('step-start'); hide('step-code'); hide('step-done');
    show('step-stop');
  }

  function vraagCode(knop, zegId) {
    if (knop) knop.disabled = true;
    say(zegId, 'Sending the code...');
    fetch('/v2/pickup/' + encodeURIComponent(TOKEN), {
      headers: { 'Accept': 'application/json' }, cache: 'no-store'
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (b) {
        return { status: r.status, body: b };
      });
    }).then(function (res) {
      if (knop) knop.disabled = false;
      if (res.status !== 200) return stop(res.body.error || 'pickup_failed');
      var naar = el('sent-to');
      if (naar) naar.textContent = res.body.sent_to || 'your mailbox';
      var geldig = el('valid-for');
      if (geldig && res.body.expires_in_s) {
        geldig.textContent = String(Math.round(res.body.expires_in_s / 60));
      }
      hide('step-start');
      show('step-code');
      say('code-say', '');
      var invoer = el('code');
      if (invoer) { invoer.value = ''; invoer.focus(); }
    }).catch(function () {
      if (knop) knop.disabled = false;
      say(zegId, 'Could not reach Paramant. Check your connection and try again.', 'fail');
    });
  }

  // The bytes come back as a blob, so the browser saves a real file with the
  // name the sender gave it rather than a string of characters in a tab.
  function haalOp() {
    var knop = el('open');
    var invoer = el('code');
    var code = invoer ? invoer.value.replace(/\D+/g, '') : '';
    if (code.length !== 6) {
      say('code-say', 'The code is six digits.', 'fail');
      if (invoer) invoer.focus();
      return;
    }
    if (knop) knop.disabled = true;
    say('code-say', 'Checking...');

    fetch('/v2/pickup/' + encodeURIComponent(TOKEN), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ code: code }),
      cache: 'no-store'
    }).then(function (r) {
      if (r.status === 200) {
        var naam = r.headers.get('X-Paramant-Filename') || 'file';
        return r.blob().then(function (b) { return { ok: true, blob: b, naam: naam }; });
      }
      return r.json().catch(function () { return {}; })
        .then(function (b) { return { ok: false, status: r.status, body: b }; });
    }).then(function (res) {
      if (knop) knop.disabled = false;
      if (res.ok) return bewaar(res.blob, res.naam);

      var reden = res.body.error;
      if (reden === 'wrong_code') {
        var over = res.body.tries_left;
        say('code-say', over === 0
          ? 'That code is wrong, and that was the last try.'
          : 'That code is wrong. ' + over + (over === 1 ? ' try left.' : ' tries left.'), 'fail');
        if (invoer) { invoer.value = ''; invoer.focus(); }
        return;
      }
      if (reden === 'code_expired') {
        say('code-say', 'That code has expired. Ask for a new one.', 'fail');
        return;
      }
      if (reden === 'too_many_tries') {
        say('code-say', 'Too many wrong codes. Ask the sender for a new link.', 'fail');
        if (knop) knop.disabled = true;
        return;
      }
      if (reden === 'no_code_requested') {
        hide('step-code'); show('step-start');
        say('start-say', 'Ask for a code first.', 'fail');
        return;
      }
      stop(reden || 'pickup_failed');
    }).catch(function () {
      if (knop) knop.disabled = false;
      say('code-say', 'Could not reach Paramant. Try again.', 'fail');
    });
  }

  var laatste = null;
  function bewaar(blob, naam) {
    laatste = { blob: blob, naam: naam };
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = naam;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    // Revoke late: some browsers start the save after the click returns.
    setTimeout(function () { URL.revokeObjectURL(url); }, 60000);

    hide('step-code');
    show('step-done');
    var lijn = el('done-line');
    if (lijn) lijn.textContent = 'Saved as ' + naam + '. If nothing happened, '
      + 'your browser may have blocked it.';
    var opnieuw = el('again-download');
    if (opnieuw) opnieuw.hidden = false;
  }

  function start() {
    if (!TOKEN || TOKEN.length < 16) return stop('unknown_token');

    var ask = el('ask');
    if (ask) ask.addEventListener('click', function () { vraagCode(ask, 'start-say'); });

    var open = el('open');
    if (open) open.addEventListener('click', haalOp);

    var invoer = el('code');
    if (invoer) {
      // Enter is what a person presses after typing six digits.
      invoer.addEventListener('keydown', function (ev) {
        if (ev.key === 'Enter') { ev.preventDefault(); haalOp(); }
      });
      // Digits only, and never silently truncated further than the field says.
      invoer.addEventListener('input', function () {
        var schoon = invoer.value.replace(/\D+/g, '').slice(0, 6);
        if (schoon !== invoer.value) invoer.value = schoon;
      });
    }

    var again = el('again');
    if (again) again.addEventListener('click', function (ev) {
      ev.preventDefault();
      vraagCode(null, 'code-say');
    });

    // The file is already in memory here, so a second save costs nothing and
    // does not touch the link, which has been used up.
    var nog = el('again-download');
    if (nog) nog.addEventListener('click', function () {
      if (laatste) bewaar(laatste.blob, laatste.naam);
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }
})();
