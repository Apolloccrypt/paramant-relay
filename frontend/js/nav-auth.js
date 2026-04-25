(function() {
  var desktop = document.getElementById('nav-auth');
  var mobile  = document.getElementById('nav-auth-mobile');
  if (!desktop && !mobile) return;

  function loggedOutHTML(includeHelp) {
    return (includeHelp ? '<a href="/help" class="nav-help">HELP</a>' : '') +
      '<a href="/auth/login" class="nav-signin">Sign in</a>' +
      '<a href="/signup" class="nav-cta">Create account</a>';
  }

  function loggedInHTML(email) {
    var shortEmail = email.length > 24 ? email.slice(0, 18) + '...' : email;
    return '<div class="nav-user">' +
        '<button type="button" class="nav-user-trigger" aria-expanded="false">' +
          '<span class="nav-user-email">' + shortEmail + '</span>' +
          '<span class="nav-user-chevron">▾</span>' +
        '</button>' +
        '<div class="nav-user-menu" hidden>' +
          '<a href="/account" class="nav-menu-item">Account</a>' +
          '<a href="/pricing" class="nav-menu-item">Plan &amp; billing</a>' +
          '<a href="/help" class="nav-menu-item">Help</a>' +
          '<div class="nav-menu-divider"></div>' +
          '<button type="button" class="nav-menu-item nav-menu-signout">Sign out</button>' +
        '</div>' +
      '</div>';
  }

  function attachLoggedInHandlers(container) {
    var trigger = container.querySelector('.nav-user-trigger');
    var menu    = container.querySelector('.nav-user-menu');
    var signout = container.querySelector('.nav-menu-signout');

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

  function renderLoggedOut() {
    if (desktop) desktop.innerHTML = loggedOutHTML(true);
    if (mobile)  mobile.innerHTML  = loggedOutHTML(false);
  }

  function renderLoggedIn(email) {
    var html = loggedInHTML(email);
    if (desktop) {
      desktop.innerHTML = html;
      attachLoggedInHandlers(desktop);
    }
    if (mobile) {
      mobile.innerHTML = html;
      attachLoggedInHandlers(mobile);
    }
  }

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
