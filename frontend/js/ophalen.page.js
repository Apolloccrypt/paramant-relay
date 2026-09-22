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

  // WHICH RELAY HOLDS THIS FILE. An account lives on exactly one sector, and
  // /ontvang/ is served by the apex, whose /v2/ goes to health. Asking health
  // for a token that sits on legal gets "this link cannot be used", which is
  // the most alarming thing we could tell somebody about a confidential file
  // that is in fact perfectly fine. So the invitation carries `?r=`, exactly
  // as the one-link flow already does.
  var SECTOREN = {
    health:  'https://health.paramant.app',
    legal:   'https://legal.paramant.app',
    finance: 'https://finance.paramant.app',
    iot:     'https://iot.paramant.app',
  };
  var RELAY = (function () {
    var r = '';
    try { r = new URLSearchParams(location.search).get('r') || ''; } catch (e) { r = ''; }
    // Same origin when it is one of ours already, so a self-hosted install and
    // a local test do not get sent to paramant.app.
    if (/(^|\.)paramant\.app$/.test(location.hostname) === false) return '';
    return Object.prototype.hasOwnProperty.call(SECTOREN, r) ? SECTOREN[r] : '';
  })();
  function pickupUrl() { return RELAY + '/v2/pickup/' + encodeURIComponent(TOKEN); }

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
      'This link works once, and it has been used. If you still need the file, ask the sender to send it again.'],
    revoked: ['The sender withdrew this link',
      'Whoever sent the file took this link back. Ask them if you should have had it.'],
    expired: ['This file is no longer available',
      'The window the sender set has closed and the file has been deleted. Ask them to send it again.'],
    too_many_codes: ['Too many codes were requested for this link',
      'For your own protection this link is now closed. Ask the sender to send the file again.'],
    too_many_tries: ['Too many wrong codes',
      'For your own protection this link is now closed. Ask the sender to send the file again.'],
    code_not_sent: ['We could not send the code',
      'The code did not leave our side, so there is nothing in your mailbox to look for. '
      + 'Try again in a minute.'],
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
    // POST, not GET. Asking for a code sends a mail, and every Safe Links or
    // antivirus scanner that opens the invitation would fire a GET: the
    // recipient got a code before touching anything.
    fetch(pickupUrl(), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ action: 'code' }),
      cache: 'no-store'
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
      // A fresh code means fresh tries, so the button comes back. Leaving it
      // grey was a dead end on a phone: the numeric keypad has no Enter.
      var open = el('open');
      if (open) open.disabled = false;
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

    fetch(pickupUrl(), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ code: code }),
      cache: 'no-store'
    }).then(function (r) {
      if (r.status === 200) {
        // The file key comes back wrapped under this link's own token. The
        // relay could not open it and neither could the mail provider, which
        // only ever saw the token and never this wrapping.
        var wrapped = r.headers.get('X-Paramant-Key') || '';
        return r.arrayBuffer().then(function (buf) {
          return openMetToken(new Uint8Array(buf), wrapped);
        }).then(function (uit) {
          return { ok: true, blob: uit.blob, naam: uit.naam };
        });
      }
      return r.json().catch(function () { return {}; })
        .then(function (b) { return { ok: false, status: r.status, body: b }; });
    }).then(function (res) {
      if (knop) knop.disabled = false;
      if (res.ok) {
        // Bevestigen dat het bestand ECHT openging. Tot dat bericht staat de
        // ophaling op "bezig" en krijgt de ontvanger zijn kans terug als er
        // onderweg iets misgaat. Best effort: lukt de bevestiging niet, dan
        // vervalt de claim vanzelf en kan hij het opnieuw proberen.
        fetch(pickupUrl(), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ action: 'confirm' }),
          cache: 'no-store'
        }).catch(function () { /* de claim vervalt vanzelf */ });
        return bewaar(res.blob, res.naam);
      }

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
        return stop('too_many_tries');
      }
      if (reden === 'too_many_codes') {
        return stop('too_many_codes');
      }
      if (reden === 'no_code_requested') {
        hide('step-code'); show('step-start');
        say('start-say', 'Ask for a code first.', 'fail');
        return;
      }
      stop(reden || 'pickup_failed');
    }).catch(function (err) {
      if (knop) knop.disabled = false;
      // ELKE fout uit het uitpakken telt, niet drie met naam.
      //
      // send-wrap.js gooit ook 'wrapped key too short' en 'unexpected key
      // material', en die stonden er niet bij. De ontvanger las dan "Could not
      // reach Paramant. Try again" terwijl zijn eenmalige link net was
      // verbrand: een zin die hem terugstuurt naar een deur die al dicht is.
      var naam = (err && err.message) || '';
      var uitpakfout = naam === 'no_key' || naam === 'bad_payload'
        || /wrapped key|key material|base64|atob/i.test(naam)
        || (err && (err.name === 'OperationError' || err.name === 'InvalidCharacterError'));
      if (uitpakfout) {
        // The code was right and the bytes arrived, but this link cannot open
        // them. Telling somebody to try again would send them round forever.
        say('code-say', 'The file came through but this link cannot open it. '
          + 'Ask the sender for a new link.', 'fail');
        return;
      }
      say('code-say', 'Could not reach Paramant. Try again.', 'fail');
    });
  }


  // Unwrap the file key with the token from this page's own URL, then open the
  // bytes. The sealed block is the same shape the one-link flow uses: a 32-byte
  // key and a 12-byte IV together, and inside, the file name in front of the
  // file itself.
  //
  // Everything here happens in this browser. The relay handed over a locked box
  // and never had the key to it.
  async function openMetToken(sealed, wrapped) {
    if (!wrapped) throw new Error('no_key');
    var sleutel = await paramantSendWrap.unwrap(TOKEN, wrapped);
    var key = await crypto.subtle.importKey('raw', sleutel.rawKey,
                                            { name: 'AES-GCM' }, false, ['decrypt']);
    var plain = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: sleutel.iv }, key, sealed));
    // u32 little-endian name length, the name, then the file.
    var dv = new DataView(plain.buffer, plain.byteOffset, 4);
    var naamLen = dv.getUint32(0, true);
    if (naamLen > plain.length - 4) throw new Error('bad_payload');
    var naam = new TextDecoder().decode(plain.subarray(4, 4 + naamLen)) || 'file';
    var body = plain.subarray(4 + naamLen);
    return { naam: naam, blob: new Blob([body], { type: 'application/octet-stream' }) };
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
