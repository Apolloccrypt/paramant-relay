// The appearance switch on /account: three radios, one localStorage key, no
// save button. Picking an option is the change, and the page it is on repaints
// under the answer, so the choice is its own preview.
//
// Deferred on purpose: the DOM is parsed by the time this runs, and the theme
// itself was already applied by /js/theme.js during head parsing. This file
// only wires the control; it is never what decides how the page looks.
(function () {
  var api = window.paramantTheme;
  var group = document.getElementById('theme-choice');
  if (!api || !group) return;

  var current = api.read() || 'light';
  var inputs = group.querySelectorAll('input[name="appearance"]');

  for (var i = 0; i < inputs.length; i++) {
    inputs[i].checked = inputs[i].value === current;
    inputs[i].addEventListener('change', function (event) {
      if (event.target.checked) api.save(event.target.value);
    });
  }
}());
