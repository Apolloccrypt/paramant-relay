// One file, two languages: the Dutch page and its English copy under /en/ load
// this same script, and <html lang> says which of the two strings to show.
function nlEn(nl, en) { return /^en\b/i.test(document.documentElement.lang || '') ? en : nl; }
// The ParaSign API keys block on /account.
//
// /pricing sells Firm with "a developer API with its own documentation and
// webhooks", and the only place a key could be minted was the operator
// dashboard behind an email allowlist, which answers 404 to everybody else. So
// a paying customer could read the documentation and never obtain a key. This
// is the customer's own door to the same relay route.
//
// The entitlement decision is NOT made here. The relay answers 403
// parasign_not_entitled for an account with no paid ParaSign tier, and the
// block simply stays hidden; nothing in this file may decide who is entitled,
// because a client-side plan check is a plan check an attacker edits.
(function () {
  'use strict';
  var block = document.getElementById('parasign-api-block');
  if (!block) return;
  var list = document.getElementById('parasign-api-list');
  var btn = document.getElementById('parasign-api-new');
  var fresh = document.getElementById('parasign-api-fresh');
  var msg = document.getElementById('parasign-api-msg');

  function say(text) {
    if (!msg) return;
    msg.textContent = text || '';
    msg.hidden = !text;
  }

  function render(keys) {
    if (!list) return;
    list.textContent = '';
    if (!keys || !keys.length) {
      list.textContent = nlEn('Nog geen API-sleutels.', 'No API keys yet.');
      return;
    }
    var ul = document.createElement('ul');
    ul.style.listStyle = 'none';
    ul.style.padding = '0';
    ul.style.margin = '0 0 12px';
    keys.forEach(function (k) {
      var li = document.createElement('li');
      li.style.display = 'flex';
      li.style.gap = '12px';
      li.style.alignItems = 'center';
      li.style.padding = '6px 0';
      var code = document.createElement('code');
      code.textContent = k.key_masked || k.masked || k.kid || '';
      var mode = document.createElement('span');
      mode.textContent = (k.mode === 'test' ? 'test' : 'live');
      var revoke = document.createElement('button');
      revoke.type = 'button';
      revoke.className = 'btn btn-secondary btn-small';
      revoke.textContent = nlEn('Intrekken', 'Revoke');
      revoke.addEventListener('click', function () {
        if (!window.confirm(nlEn('Deze sleutel intrekken? Alles wat hem gebruikt, stopt direct.', 'Revoke this key? Anything using it stops working immediately.'))) return;
        say(nlEn('Intrekken…', 'Revoking…'));
        fetch('/api/user/parasign-keys', {
          method: 'DELETE', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ kid: k.kid }),
        }).then(function () { say(nlEn('Sleutel ingetrokken.', 'Key revoked.')); load(); })
          .catch(function () { say(nlEn('Die sleutel kon niet worden ingetrokken.', 'Could not revoke that key.')); });
      });
      li.appendChild(code); li.appendChild(mode); li.appendChild(revoke);
      ul.appendChild(li);
    });
    list.appendChild(ul);
  }

  function load() {
    fetch('/api/user/parasign-keys').then(function (r) {
      // 403 is the honest answer for an account without the entitlement, and
      // 404 for a relay that does not have the route. Either way: no block.
      if (r.status === 403 || r.status === 404) { block.hidden = true; return null; }
      if (!r.ok) throw new Error('http_' + r.status);
      return r.json();
    }).then(function (body) {
      if (!body) return;
      block.hidden = false;
      render(body.keys || []);
    }).catch(function () {
      // A relay that cannot answer must not make the block claim anything.
      block.hidden = true;
    });
  }

  if (btn) {
    btn.addEventListener('click', function () {
      say(nlEn('Maken…', 'Creating…'));
      fetch('/api/user/parasign-keys', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ label: 'account' }),
      }).then(function (r) { return r.json().then(function (b) { return { status: r.status, body: b }; }); })
        .then(function (out) {
          if (out.status !== 201 && out.status !== 200) {
            say((out.body && out.body.message) || nlEn('De sleutel kon niet worden gemaakt.', 'Could not create a key.'));
            return;
          }
          say('');
          if (fresh) {
            fresh.textContent = out.body.key + nlEn('  ·  kopieer hem nu. U ziet hem één keer en daarna niet meer.', '  ·  copy it now; it is shown once and cannot be read again.');
            fresh.hidden = false;
          }
          load();
        })
        .catch(function () { say(nlEn('De sleutel kon niet worden gemaakt.', 'Could not create a key.')); });
    });
  }

  load();
})();
