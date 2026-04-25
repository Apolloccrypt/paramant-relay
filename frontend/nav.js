// PARAMANT nav v3 — desktop dropdowns + mobile accordion + lime accents
(function () {
  'use strict';

  var hamburger = document.getElementById('nav-hamburger');
  var mobile    = document.getElementById('nav-mobile');
  var closeBtn  = document.querySelector('.nav-mobile-close');

  // ── Helpers ───────────────────────────────────────────
  function lockScroll()   { document.body.classList.add('nav-locked'); }
  function unlockScroll() { document.body.classList.remove('nav-locked'); }

  // ── Desktop dropdowns ─────────────────────────────────
  var dropdowns = Array.from(document.querySelectorAll('nav.nav .nav-dropdown'));
  var hoverLeaveTimers = new WeakMap();

  function openDropdown(dd) {
    dropdowns.forEach(function (d) {
      if (d !== dd) closeDropdown(d);
    });
    dd.classList.add('open');
    var trig = dd.querySelector('.nav-dropdown-trigger');
    if (trig) trig.setAttribute('aria-expanded', 'true');
  }

  function closeDropdown(dd) {
    dd.classList.remove('open');
    var trig = dd.querySelector('.nav-dropdown-trigger');
    if (trig) trig.setAttribute('aria-expanded', 'false');
  }

  function closeAllDropdowns() {
    dropdowns.forEach(closeDropdown);
  }

  dropdowns.forEach(function (dd) {
    var trig = dd.querySelector('.nav-dropdown-trigger');
    var menu = dd.querySelector('.nav-dropdown-menu');
    if (!trig || !menu) return;

    trig.addEventListener('click', function (e) {
      e.stopPropagation();
      dd.classList.contains('open') ? closeDropdown(dd) : openDropdown(dd);
    });

    dd.addEventListener('mouseenter', function () {
      clearTimeout(hoverLeaveTimers.get(dd));
      openDropdown(dd);
    });

    dd.addEventListener('mouseleave', function () {
      var t = setTimeout(function () { closeDropdown(dd); }, 150);
      hoverLeaveTimers.set(dd, t);
    });

    trig.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') {
        closeDropdown(dd);
        trig.focus();
        return;
      }
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        dd.classList.contains('open') ? closeDropdown(dd) : openDropdown(dd);
        if (dd.classList.contains('open')) {
          var first = menu.querySelector('a');
          if (first) first.focus();
        }
        return;
      }
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        openDropdown(dd);
        var first = menu.querySelector('a');
        if (first) first.focus();
      }
    });

    menu.addEventListener('keydown', function (e) {
      var items = Array.from(menu.querySelectorAll('a'));
      var idx   = items.indexOf(document.activeElement);
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        if (items[idx + 1]) items[idx + 1].focus();
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        if (idx > 0) items[idx - 1].focus();
        else { closeDropdown(dd); trig.focus(); }
      } else if (e.key === 'Escape') {
        e.preventDefault();
        closeDropdown(dd);
        trig.focus();
      } else if (e.key === 'Tab') {
        closeDropdown(dd);
      }
    });
  });

  document.addEventListener('click', function () { closeAllDropdowns(); });

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') {
      closeAllDropdowns();
      if (mobile && mobile.classList.contains('open')) closeMobileMenu();
    }
  });

  // ── Active page indicator — desktop ───────────────────
  var path = window.location.pathname;

  document.querySelectorAll('nav.nav .nav-link').forEach(function (link) {
    if (link.getAttribute('href') === path) link.classList.add('active');
  });

  document.querySelectorAll('nav.nav .nav-dropdown-menu a').forEach(function (link) {
    var href = link.getAttribute('href') || '';
    if (href && href !== '/' && path.startsWith(href)) {
      var trig = link.closest('.nav-dropdown');
      if (trig) {
        var t = trig.querySelector('.nav-dropdown-trigger');
        if (t) t.classList.add('active');
      }
    }
  });

  // ── Mobile menu ───────────────────────────────────────
  if (!hamburger || !mobile) return;

  function openMobileMenu() {
    mobile.classList.add('open');
    hamburger.setAttribute('aria-expanded', 'true');
    hamburger.setAttribute('aria-label', 'Close menu');
    lockScroll();
    if (closeBtn) closeBtn.focus();
  }

  function closeMobileMenu() {
    mobile.classList.remove('open');
    hamburger.setAttribute('aria-expanded', 'false');
    hamburger.setAttribute('aria-label', 'Open menu');
    unlockScroll();
    hamburger.focus();
  }

  hamburger.addEventListener('click', function (e) {
    e.stopPropagation();
    mobile.classList.contains('open') ? closeMobileMenu() : openMobileMenu();
  });

  if (closeBtn) closeBtn.addEventListener('click', closeMobileMenu);

  mobile.querySelectorAll('a').forEach(function (a) {
    a.addEventListener('click', closeMobileMenu);
  });

  document.addEventListener('click', function (e) {
    if (
      mobile.classList.contains('open') &&
      !hamburger.contains(e.target) &&
      !mobile.contains(e.target)
    ) {
      closeMobileMenu();
    }
  });

  // ── Reset mobile state when viewport crosses into desktop ─
  // Without this, opening the drawer on mobile then rotating / resizing
  // to desktop leaves the drawer visible with no way to close it
  // (hamburger is display:none at >1023px) and body stuck scroll-locked.
  var desktopQuery = window.matchMedia('(min-width: 1024px)');
  function onDesktopChange(e) {
    if (e.matches && mobile.classList.contains('open')) closeMobileMenu();
  }
  if (desktopQuery.addEventListener) desktopQuery.addEventListener('change', onDesktopChange);
  else if (desktopQuery.addListener) desktopQuery.addListener(onDesktopChange);

  // ── Mobile accordions ─────────────────────────────────
  mobile.querySelectorAll('.nav-mobile-group-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var group  = btn.closest('.nav-mobile-group');
      var isOpen = group.classList.contains('open');

      mobile.querySelectorAll('.nav-mobile-group').forEach(function (g) {
        g.classList.remove('open');
        var b = g.querySelector('.nav-mobile-group-btn');
        if (b) b.setAttribute('aria-expanded', 'false');
      });

      if (!isOpen) {
        group.classList.add('open');
        btn.setAttribute('aria-expanded', 'true');
      }
    });
  });

  // ── Active page indicator — mobile ────────────────────
  mobile.querySelectorAll('a').forEach(function (a) {
    if (a.getAttribute('href') === path) {
      a.setAttribute('aria-current', 'page');
      var parentGroup = a.closest('.nav-mobile-group');
      if (parentGroup) {
        parentGroup.classList.add('open');
        var btn = parentGroup.querySelector('.nav-mobile-group-btn');
        if (btn) btn.setAttribute('aria-expanded', 'true');
      }
    }
  });
  mobile.querySelectorAll('.nav-mobile-standalone').forEach(function (a) {
    if (a.getAttribute('href') === path) a.setAttribute('aria-current', 'page');
  });
})();
