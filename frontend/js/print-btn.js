// Print-knop zonder inline handler: de CSP (script-src 'self') weigert onclick="".
document.addEventListener('DOMContentLoaded', function () {
  document.querySelectorAll('.print-btn').forEach(function (b) {
    b.addEventListener('click', function () { window.print(); });
  });
});
