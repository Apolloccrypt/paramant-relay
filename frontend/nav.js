// PARAMANT shared navbar — hamburger + dropdown behavior
(function() {
  var hamburger = document.getElementById('nav-hamburger');
  var mobileMenu = document.getElementById('nav-mobile');
  if (!hamburger || !mobileMenu) return;

  hamburger.addEventListener('click', function() {
    var open = mobileMenu.classList.toggle('open');
    var spans = hamburger.querySelectorAll('span');
    if (open) {
      spans[0].style.transform = 'translateY(7px) rotate(45deg)';
      spans[1].style.opacity = '0';
      spans[2].style.transform = 'translateY(-7px) rotate(-45deg)';
    } else {
      spans[0].style.transform = '';
      spans[1].style.opacity = '';
      spans[2].style.transform = '';
    }
  });

  // Close mobile menu when a link is clicked
  mobileMenu.querySelectorAll('a').forEach(function(a) {
    a.addEventListener('click', function() {
      mobileMenu.classList.remove('open');
      hamburger.querySelectorAll('span').forEach(function(s) {
        s.removeAttribute('style');
      });
    });
  });

  // Close mobile menu on outside click
  document.addEventListener('click', function(e) {
    if (!hamburger.contains(e.target) && !mobileMenu.contains(e.target)) {
      if (mobileMenu.classList.contains('open')) {
        mobileMenu.classList.remove('open');
        hamburger.querySelectorAll('span').forEach(function(s) {
          s.removeAttribute('style');
        });
      }
    }
  });
})();
