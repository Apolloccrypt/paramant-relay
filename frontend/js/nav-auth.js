(function() {
  // What a signed-in customer leaves in THIS browser, and when it goes
  // (security review r2 (a)): the /sign draft (IndexedDB paramant-sign-draft,
  // sealed with an account key the page only holds in memory) and the whole
  // document key K a sender keeps per envelope (localStorage
  // paramant.cosign.key.v1:<id>, with an expiry). Both are wiped on sign-out
  // and when another account signs in here; expired ones on any page.
  var COSIGN_KEY = 'paramant.cosign.key.v1:';
  var OWNER = 'paramant.local.owner';
  function wipeDraft() {
    try { indexedDB.deleteDatabase('paramant-sign-draft'); } catch (e) { /* no IndexedDB */ }
  }
  function cosignKeys() {
    var out = [];
    try { for (var i = 0; i < localStorage.length; i++) { var k = localStorage.key(i); if (k && k.indexOf(COSIGN_KEY) === 0) out.push(k); } } catch (e) { /* storage off */ }
    return out;
  }
  var COSIGN_LINKS = 'paramant.cosign.links.v1:';
  function cosignLinks() {
    var out = [];
    try { for (var i = 0; i < localStorage.length; i++) { var k = localStorage.key(i); if (k && k.indexOf(COSIGN_LINKS) === 0) out.push(k); } } catch (e) { /* storage off */ }
    return out;
  }
  function wipeLocal() {
    wipeDraft();
    cosignKeys().forEach(function(k) { try { localStorage.removeItem(k); } catch (e) {} });
    cosignLinks().forEach(function(k) { try { localStorage.removeItem(k); } catch (e) {} });
    try { localStorage.removeItem(OWNER); } catch (e) {}
  }
  window.paramantWipeLocal = wipeLocal;
  // A session that simply ran out takes K with it too, not only an explicit
  // sign-out (review #555, M4): the key of every open envelope must not sit in
  // a browser nobody is signed in to.
  function wipeCosignKeys() {
    cosignKeys().forEach(function(k) { try { localStorage.removeItem(k); } catch (e) {} });
  }
  // K lives at most 24 hours (review #555, M4). Expired entries go; an entry
  // with a later expiry (the 31 days of before) is brought back to 24 hours
  // from now; an old bare value (no expiry yet) gets 24 hours.
  var COSIGN_KEY_MAX_MS = 864e5;
  (function sweep() {
    var now = Date.now();
    // The signer links (sign-flow.js rememberSignerLinks) go when they expire.
    cosignLinks().forEach(function(k) {
      try { var r = JSON.parse(localStorage.getItem(k) || 'null'); if (!r || !(now < Number(r.exp))) localStorage.removeItem(k); } catch (e) { try { localStorage.removeItem(k); } catch (e2) {} }
    });
    cosignKeys().forEach(function(k) {
      try {
        var raw = localStorage.getItem(k) || '';
        var rec = null;
        try { rec = JSON.parse(raw); } catch (e) { rec = null; }
        if (!rec || typeof rec !== 'object') { localStorage.setItem(k, JSON.stringify({ f: raw, exp: now + COSIGN_KEY_MAX_MS })); return; }
        if (!(now < Number(rec.exp))) { localStorage.removeItem(k); return; }
        if (Number(rec.exp) > now + COSIGN_KEY_MAX_MS) localStorage.setItem(k, JSON.stringify({ f: rec.f, exp: now + COSIGN_KEY_MAX_MS }));
      } catch (e) { /* storage off */ }
    });
    try {
      if (!indexedDB.databases) return;
      indexedDB.databases().then(function(list) {
        if (!list.some(function(d) { return d.name === 'paramant-sign-draft'; })) return;
        var r = indexedDB.open('paramant-sign-draft');
        r.onsuccess = function() {
          var db = r.result;
          try {
            var g = db.transaction('kv').objectStore('kv').get('current');
            g.onsuccess = function() {
              var v = g.result;
              db.close();
              if (v && (v.v !== 2 || !(now < v.expiresAt))) wipeDraft();
            };
            g.onerror = function() { db.close(); };
          } catch (e) { db.close(); }
        };
      }).catch(function() {});
    } catch (e) { /* no IndexedDB */ }
  })();
  // Another account signs in here: whatever the previous one left goes.
  window.paramantNoteAccount = function(email) {
    try {
      if (!email || !crypto.subtle) return;
      crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(email).trim().toLowerCase())).then(function(buf) {
        var h = Array.from(new Uint8Array(buf)).map(function(b) { return b.toString(16).padStart(2, '0'); }).join('');
        var prev = null;
        try { prev = localStorage.getItem(OWNER); } catch (e) {}
        if (prev && prev !== h) wipeLocal();
        try { localStorage.setItem(OWNER, h); } catch (e) {}
      }).catch(function() {});
    } catch (e) { /* nothing to compare */ }
  };

  var container = document.getElementById('nav-auth');
  if (!container) return;

  // Keep this list identical to the <ul class="nav-links"> that
  // frontend/apply-nav.py stamps into every page. The generator is the source
  // of truth; this array only re-renders the same links after the session
  // check, so a visitor never sees the navigation move under them.
  // Every page carries the Dutch bar that apply-nav.py stamps as NEW_NAV_NL,
  // with the two outward product names, except a page that declares
  // <html lang="en">. The rule is the page's own lang, as it is in the
  // generator, so a page is never re-rendered in the other language than the
  // one it was stamped with.
  var DUTCH = !/^en\b/i.test(document.documentElement.lang || '');
  var PUBLIC_NAV = DUTCH ? [
    ['Versturen', '/parasend'],
    ['Ondertekenen', '/parasign'],
    ['Gereedschap', '/gereedschap'],
    ['Beveiliging', '/security'],
    ['Prijzen', '/pricing']
  ] : [
    // The English bar points at the English pages (apply-nav.py
    // to_english_links), /en/gereedschap included since fase 2 SITE-03-A.
    ['Product', '/en#products'],
    ['Tools', '/en/gereedschap'],
    ['Security', '/en/security'],
    ['Pricing', '/en/pricing'],
    ['Docs', '/en/docs']
  ];
  // The workspace bar is verbs: what you came here to do, in the order you do
  // it. Send and Sign were the two; locking a file with a passphrase is the
  // third, so it sits beside them under the same kind of name. /vault is the
  // route, "Lock a file" is what it does; the page keeps no product name of its
  // own because there is not one to give it yet.
  var APP_NAV = DUTCH ? [
    ['Documenten', '/dashboard'],
    ['Versturen', '/parashare'],
    ['Ondertekenen', '/sign'],
    ['Bestand vergrendelen', '/vault'],
    ['Controleren', '/verify'],
    ['Instellingen', '/account']
  ] : [
    // The English pages exist for each of these (frontend/en/), so an English
    // reader stays English (fase 1 SITE-06).
    ['Documents', '/en/dashboard'],
    ['Send', '/en/parashare'],
    ['Sign', '/en/sign'],
    ['Lock a file', '/en/vault'],
    ['Verify', '/en/verify'],
    ['Settings', '/en/account']
  ];
  // Where Help, Sign in and Create account lead, per language.
  var R = DUTCH
    ? { help: '/help', login: '/auth/login', signup: '/signup', dashboard: '/dashboard', account: '/account', pricing: '/pricing' }
    : { help: '/en/help', login: '/en/auth/login', signup: '/en/signup', dashboard: '/en/dashboard', account: '/en/account', pricing: '/en/pricing' };

  function setNavigation(items, label) {
    var lists = document.querySelectorAll('nav.nav .nav-links');
    if (lists.length) {
      var primary = lists[0];
      primary.className = 'nav-links';
      primary.setAttribute('aria-label', label);
      primary.innerHTML = items.map(function(item) {
        var active = location.pathname === item[1] || (item[1] === '/#products' && location.pathname === '/') || (item[1] === '/en#products' && location.pathname === '/en');
        return '<li><a href="' + item[1] + '" class="nav-link' + (active ? ' active' : '') + '">' + item[0] + '</a></li>';
      }).join('');
      for (var i = 1; i < lists.length; i++) lists[i].remove();
    }

    var mobile = document.getElementById('nav-mobile');
    if (mobile) {
      mobile.innerHTML = items.map(function(item) {
        var current = location.pathname === item[1] || (item[1] === '/#products' && location.pathname === '/') || (item[1] === '/en#products' && location.pathname === '/en');
        return '<a href="' + item[1] + '" class="nav-mobile-standalone"' + (current ? ' aria-current="page"' : '') + '>' + item[0] + '</a>';
      }).join('');
    }
    var obsolete = document.getElementById('nav-mobile-marketing');
    if (obsolete) obsolete.remove();
  }

  function renderLoggedOut() {
    setNavigation(PUBLIC_NAV, DUTCH ? 'Hoofdmenu' : 'Primary');
    container.innerHTML = DUTCH
      ? '<a href="/help" class="nav-help">Hulp</a>' +
        '<a href="/auth/login" class="nav-signin">Inloggen</a>' +
        '<a href="/signup" class="nav-cta">Account maken</a>'
      : '<a href="' + R.help + '" class="nav-help">Help</a>' +
        '<a href="' + R.login + '" class="nav-signin">Sign in</a>' +
        '<a href="' + R.signup + '" class="nav-cta">Create account</a>';
  }

  // The session check itself failed (429, 5xx, no network): we do not know
  // whether this visitor is signed in. Telling a signed-in customer "Create
  // account" was wrong (fase 1 SITE-02-K), so offer the one link that is right
  // either way: the account page, which sends a stranger to the login.
  function renderUnknown() {
    setNavigation(PUBLIC_NAV, DUTCH ? 'Hoofdmenu' : 'Primary');
    container.innerHTML =
      '<a href="' + R.help + '" class="nav-help">' + (DUTCH ? 'Hulp' : 'Help') + '</a>' +
      '<a href="' + R.account + '" class="nav-signin">' + (DUTCH ? 'Mijn account' : 'My account') + '</a>';
  }

  function renderLoggedIn(email) {
    setNavigation(APP_NAV, DUTCH ? 'Werkruimte' : 'Workspace');
    // Support survives signing in. The tail used to be REMOVED here, on the
    // reasoning that the user menu carries Help from then on. On a phone that
    // left no Help at all: the bar sheds .nav-help below 700px, the drawer is
    // pinned to the workspace links, and the menu behind the email
    // address is not where anyone looks for support. A signed-in customer with
    // a stuck signature had to type the url.
    //
    // So the strip stays and carries the one route the bar handed over. Sign in
    // does go: it is not an action you still need. Help lands in the same place
    // as it does signed out, one tap under the drawer, 48px tall.
    var tail = document.getElementById('nav-mobile-tail');
    // The language and theme switches apply-nav.py stamps into the strip stay
    // with it (one .nav-prefs row; a page stamped before it has .nav-lang).
    if (tail) {
      var langSwitch = tail.querySelector('.nav-prefs') || tail.querySelector('.nav-lang');
      tail.innerHTML = '<a href="' + R.help + '" class="nav-tail-link">' + (DUTCH ? 'Hulp' : 'Help') + '</a>';
      if (langSwitch) tail.appendChild(langSwitch);
    }
    var shortEmail = email.length > 24 ? email.slice(0, 18) + '...' : email;
    // Help sits where it sits signed out: a text link left of the account
    // control. nav.css hides it below 700px, where the drawer tail above takes
    // over, and gives it a 44px target from 1279px down.
    //
    // Never interpolate the email into innerHTML (stored/self DOM XSS): the
    // signup regex permits HTML metacharacters. Build static markup, then set
    // the email via textContent (mirrors home-auth.js / dashboard.js).
    var T = DUTCH ? {
      help: 'Hulp', docs: 'Documenten', account: 'Account', dev: 'Ontwikkelaarsinstellingen',
      plan: 'Abonnement en betaling', out: 'Uitloggen'
    } : {
      help: 'Help', docs: 'Documents', account: 'Account', dev: 'Developer settings',
      plan: 'Plan &amp; billing', out: 'Sign out'
    };
    container.innerHTML =
      '<a href="' + R.help + '" class="nav-help">' + T.help + '</a>' +
      '<div class="nav-user">' +
        '<button type="button" class="nav-user-trigger" aria-expanded="false">' +
          '<span class="nav-user-email"></span>' +
          '<span class="nav-user-chevron">\u25be</span>' +
        '</button>' +
        '<div class="nav-user-menu" hidden>' +
          '<a href="' + R.dashboard + '" class="nav-menu-item">' + T.docs + '</a>' +
          '<a href="' + R.account + '" class="nav-menu-item">' + T.account + '</a>' +
          '<a href="/developer" class="nav-menu-item">' + T.dev + '</a>' +
          '<a href="' + R.pricing + '" class="nav-menu-item">' + T.plan + '</a>' +
          '<a href="' + R.help + '" class="nav-menu-item">' + T.help + '</a>' +
          '<div class="nav-menu-divider"></div>' +
          '<button type="button" class="nav-menu-item nav-menu-signout" id="nav-signout">' + T.out + '</button>' +
        '</div>' +
      '</div>';

    var trigger = container.querySelector('.nav-user-trigger');
    var menu    = container.querySelector('.nav-user-menu');
    var signout = container.querySelector('#nav-signout');
    var emailEl = container.querySelector('.nav-user-email');
    if (emailEl) emailEl.textContent = shortEmail;

    trigger.addEventListener('click', function(e) {
      e.stopPropagation();
      var open = !menu.hidden;
      menu.hidden = open;
      trigger.setAttribute('aria-expanded', String(!open));
    });

    document.addEventListener('click', function(e) {
      if (!container.contains(e.target)) {
        menu.hidden = true;
        trigger.setAttribute('aria-expanded', 'false');
      }
    });

    signout.addEventListener('click', async function() {
      try {
        await fetch('/api/user/logout', { method: 'POST', credentials: 'include' });
      } catch (err) {}
      wipeLocal();
      try { localStorage.removeItem('paramant_api_key'); } catch (err) {} // legacy: /parashare no longer writes it, clear an old one
      if (location.pathname === '/account' || location.pathname.startsWith('/auth/')) {
        location.href = '/';
      } else {
        location.reload();
      }
    });
  }

  setNavigation(PUBLIC_NAV, DUTCH ? 'Hoofdmenu' : 'Primary');
  container.innerHTML = '<span class="nav-signin" aria-hidden="true">' + (DUTCH ? 'Even kijken' : 'Checking session') + '</span>';

  // A page that signs the visitor in without a reload (the login tip, the end
  // of the account setup) says so, and the bar follows: it showed "Account
  // maken" to somebody who was already signed in (hertest r2 K4).
  window.addEventListener('paramant:session-changed', function() { check(); });
  check();
  async function check() {
    try {
      var res = null;
      // A busy relay (429) or a hiccup (5xx) is not "signed out": ask again a
      // couple of times, honouring a short Retry-After, before giving up.
      for (var attempt = 0; attempt < 3; attempt++) {
        res = await fetch('/api/user/session/verify', {
          credentials: 'include',
          cache: 'no-store',
        });
        if (res.status !== 429 && res.status < 500) break;
        if (attempt === 2) break;
        var wait = Math.min(5, Number(res.headers.get('Retry-After')) || (attempt + 1));
        await new Promise(function(r) { setTimeout(r, wait * 1000); });
      }
      if (res.status === 429 || res.status >= 500) { renderUnknown(); return; }
      if (!res.ok) { wipeCosignKeys(); renderLoggedOut(); return; }
      var data = await res.json();
      if (data.authenticated && data.email) {
        window.paramantNoteAccount(data.email);
        renderLoggedIn(data.email);
      } else {
        wipeCosignKeys();
        renderLoggedOut();
      }
    } catch (err) {
      renderUnknown();
    }
  }
})();
