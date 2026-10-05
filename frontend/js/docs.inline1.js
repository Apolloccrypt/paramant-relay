
// Sidebar highlight for /docs and /en/docs (P10 API-01-A).
//
// It used to read h.offsetTop of the .content h2 headings only. offsetTop is
// relative to the offset parent, not the page, and the sidebar also links to
// h3 headings and span anchors, so 17 of the 37 links never lit up, and the
// last sections, which cannot scroll to the top of the window, never did either.
//
// Now: every sidebar link with a #target takes part; the position is read with
// getBoundingClientRect (relative to the window, whatever the layout); and a
// click lights its own link at once and keeps it lit until the reader scrolls
// by hand, so a short section at the end of the page still shows where you are.
const links = Array.prototype.slice.call(document.querySelectorAll('.sidebar a[href^="#"]'));
const targets = [];
links.forEach(function (a) {
  const t = document.getElementById(a.getAttribute('href').slice(1));
  if (t && targets.indexOf(t) === -1) targets.push(t);
});
targets.sort(function (a, b) {
  return a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING ? -1 : 1;
});
let pinned = null;
function setActive(id) {
  links.forEach(function (a) { a.classList.toggle('active', a.getAttribute('href') === '#' + id); });
}
function fromScroll() {
  if (pinned) { setActive(pinned); return; }
  let cur = targets.length ? targets[0].id : '';
  for (let i = 0; i < targets.length; i++) {
    if (targets[i].getBoundingClientRect().top <= 100) cur = targets[i].id; else break;
  }
  setActive(cur);
}
links.forEach(function (a) {
  a.addEventListener('click', function () {
    pinned = a.getAttribute('href').slice(1);
    setActive(pinned);
  });
});
['wheel', 'touchstart', 'keydown'].forEach(function (ev) {
  window.addEventListener(ev, function () { pinned = null; }, { passive: true });
});
window.addEventListener('scroll', fromScroll, { passive: true });
if (location.hash && document.getElementById(location.hash.slice(1))) {
  pinned = location.hash.slice(1);
}
fromScroll();
