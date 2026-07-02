
const headings = document.querySelectorAll('.content h2[id]');
const links = document.querySelectorAll('.sidebar a');
window.addEventListener('scroll', () => {
  let cur = '';
  headings.forEach(h => { if (window.scrollY >= h.offsetTop - 80) cur = h.id; });
  links.forEach(a => a.classList.toggle('active', a.getAttribute('href') === '#' + cur));
}, { passive: true });
