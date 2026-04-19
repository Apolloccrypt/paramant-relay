(function() {
  var container = document.getElementById('nav-auth');
  if (!container) return;

  function renderLoggedOut() {
    container.innerHTML = '<a href="/auth/login" class="nav-signin">Sign in</a>' +
      '<a href="/signup" class="nav-cta">Create account</a>';
  }

  function renderLoggedIn(email) {
    var shortEmail = email.length > 24 ? email.slice(0, 18) + '...' : email;
    container.innerHTML =
      '<div class="nav-user">' +
        '<button type="button" class="nav-user-trigger" aria-expanded="false">' +
          '<span class="nav-user-email">' + shortEmail + '</span>' +
          '<span class="nav-user-chevron">\u25be</span>' +
        '</button>' +
        '<div class="nav-user-menu" hidden>' +
          '<a href="/account" class="nav-menu-item">Account</a>' +
          '<a href="/pricing" class="nav-menu-item">Plan &amp; billing</a>' +
          '<a href="/help" class="nav-menu-item">Help</a>' +
          '<div class="nav-menu-divider"></div>' +
          '<button type="button" class="nav-menu-item nav-menu-signout" id="nav-signout">Sign out</button>' +
        '</div>' +
      '</div>';

    var trigger = container.querySelector('.nav-user-trigger');
    var menu    = container.querySelector('.nav-user-menu');
    var signout = container.querySelector('#nav-signout');

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
