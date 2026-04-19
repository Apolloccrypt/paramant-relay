// PARAMANT nav v2 — desktop dropdowns + mobile accordion
(function () {
  'use strict';

  var hamburger = document.getElementById('nav-hamburger');
  var mobile    = document.getElementById('nav-mobile');
  var closeBtn  = document.getElementById('nav-mobile-close');

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

    // Click trigger: toggle
    trig.addEventListener('click', function (e) {
      e.stopPropagation();
      dd.classList.contains('open') ? closeDropdown(dd) : openDropdown(dd);
    });

    // Hover open
    dd.addEventListener('mouseenter', function () {
      clearTimeout(hoverLeaveTimers.get(dd));
      openDropdown(dd);
    });

    // Hover close with short delay so moving into menu doesn't flicker
    dd.addEventListener('mouseleave', function () {
      var t = setTimeout(function () { closeDropdown(dd); }, 150);
      hoverLeaveTimers.set(dd, t);
    });

    // Keyboard: trigger
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

    // Keyboard: within menu items
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

  // Click outside closes all dropdowns
  document.addEventListener('click', function () { closeAllDropdowns(); });

  // Global Escape
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') {
      closeAllDropdowns();
      if (mobile && mobile.classList.contains('open')) closeMobileMenu();
    }
  });

  // ── Active page indicator ─────────────────────────────
  var path = window.location.pathname;

  // Standalone links (e.g. Pricing)
  document.querySelectorAll('nav.nav .nav-link').forEach(function (link) {
    if (link.getAttribute('href') === path) link.classList.add('active');
  });

  // Dropdown items — mark parent trigger
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
    var spans = hamburger.querySelectorAll('span');
    if (spans[0]) spans[0].style.transform = 'translateY(7px) rotate(45deg)';
    if (spans[1]) spans[1].style.opacity   = '0';
    if (spans[2]) spans[2].style.transform = 'translateY(-7px) rotate(-45deg)';
  }

  function closeMobileMenu() {
    mobile.classList.remove('open');
    hamburger.setAttribute('aria-expanded', 'false');
    hamburger.setAttribute('aria-label', 'Open menu');
    unlockScroll();
    var spans = hamburger.querySelectorAll('span');
    spans.forEach(function (s) { s.removeAttribute('style'); });
  }

  hamburger.addEventListener('click', function (e) {
    e.stopPropagation();
    mobile.classList.contains('open') ? closeMobileMenu() : openMobileMenu();
  });

  if (closeBtn) closeBtn.addEventListener('click', closeMobileMenu);

  // Close on link tap
  mobile.querySelectorAll('a').forEach(function (a) {
    a.addEventListener('click', closeMobileMenu);
  });

  // Close on outside click
  document.addEventListener('click', function (e) {
    if (
      mobile.classList.contains('open') &&
      !hamburger.contains(e.target) &&
      !mobile.contains(e.target)
    ) {
      closeMobileMenu();
    }
  });

  // ── Mobile accordions ─────────────────────────────────
  mobile.querySelectorAll('.nav-mobile-group-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var group  = btn.closest('.nav-mobile-group');
      var isOpen = group.classList.contains('open');

      // Collapse all groups
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
})();
