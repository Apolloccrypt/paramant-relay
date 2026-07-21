(function() {
  var container = document.getElementById('nav-auth');
  if (!container) return;

  var PUBLIC_NAV = [
    ['Product', '/#products'],
    ['Security', '/security'],
    ['Pricing', '/pricing'],
    ['Docs', '/docs']
  ];
  var APP_NAV = [
    ['Documents', '/dashboard'],
    ['Send', '/parashare'],
    ['Sign', '/sign'],
    ['Verify', '/verify'],
    ['Settings', '/account']
  ];

  function setNavigation(items, label) {
    var lists = document.querySelectorAll('nav.nav .nav-links');
    if (lists.length) {
      var primary = lists[0];
      primary.className = 'nav-links';
      primary.setAttribute('aria-label', label);
      primary.innerHTML = items.map(function(item) {
        var active = location.pathname === item[1] || (item[1] === '/#products' && location.pathname === '/');
        return '<li><a href="' + item[1] + '" class="nav-link' + (active ? ' active' : '') + '">' + item[0] + '</a></li>';
      }).join('');
      for (var i = 1; i < lists.length; i++) lists[i].remove();
    }

    var mobile = document.getElementById('nav-mobile');
    if (mobile) {
      mobile.innerHTML = items.map(function(item) {
        var current = location.pathname === item[1] || (item[1] === '/#products' && location.pathname === '/');
        return '<a href="' + item[1] + '" class="nav-mobile-standalone"' + (current ? ' aria-current="page"' : '') + '>' + item[0] + '</a>';
      }).join('');
    }
    var obsolete = document.getElementById('nav-mobile-marketing');
    if (obsolete) obsolete.remove();
  }

  function renderLoggedOut() {
    setNavigation(PUBLIC_NAV, 'Primary');
    container.innerHTML = '<a href="/help" class="nav-help">HELP</a>' +
      '<a href="/auth/login" class="nav-signin">Sign in</a>' +
      '<a href="/signup" class="nav-cta">Create account</a>';
  }

  function renderLoggedIn(email) {
    setNavigation(APP_NAV, 'Workspace');
    var shortEmail = email.length > 24 ? email.slice(0, 18) + '...' : email;
    // Never interpolate the email into innerHTML (stored/self DOM XSS): the
    // signup regex permits HTML metacharacters. Build static markup, then set
    // the email via textContent (mirrors home-auth.js / dashboard.js).
    container.innerHTML =
      '<div class="nav-user">' +
        '<button type="button" class="nav-user-trigger" aria-expanded="false">' +
          '<span class="nav-user-email"></span>' +
          '<span class="nav-user-chevron">\u25be</span>' +
        '</button>' +
        '<div class="nav-user-menu" hidden>' +
          '<a href="/dashboard" class="nav-menu-item">Documents</a>' +
          '<a href="/account" class="nav-menu-item">Account</a>' +
          '<a href="/developer" class="nav-menu-item">Developer settings</a>' +
          '<a href="/pricing" class="nav-menu-item">Plan &amp; billing</a>' +
          '<a href="/help" class="nav-menu-item">Help</a>' +
          '<div class="nav-menu-divider"></div>' +
          '<button type="button" class="nav-menu-item nav-menu-signout" id="nav-signout">Sign out</button>' +
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
      if (location.pathname === '/account' || location.pathname.startsWith('/auth/')) {
        location.href = '/';
      } else {
        location.reload();
      }
    });
  }

  setNavigation(PUBLIC_NAV, 'Primary');
  container.innerHTML = '<span class="nav-signin" aria-hidden="true">Checking session</span>';

  (async function check() {
    try {
      var res = await fetch('/api/user/session/verify', {
        credentials: 'include',
        cache: 'no-store',
      });
      if (!res.ok) { renderLoggedOut(); return; }
      var data = await res.json();
      if (data.authenticated && data.email) {
        renderLoggedIn(data.email);
      } else {
        renderLoggedOut();
      }
    } catch (err) {
      renderLoggedOut();
    }
  })();
})();
