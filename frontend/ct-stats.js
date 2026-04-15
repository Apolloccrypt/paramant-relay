// CT log widget — fetches live data from public relay endpoints
(function() {
  var RELAY = 'https://health.paramant.app';

  function set(id, val) {
    var el = document.getElementById(id);
    if (el) el.textContent = val;
  }

  function setDot(ok) {
    var dot = document.getElementById('ct-dot');
    if (dot) dot.style.background = ok ? '#00cc33' : '#c84040';
  }

  // Primary: /v2/ct/log — size, root, last 3 entries
  fetch(RELAY + '/v2/ct/log?limit=3', {signal: AbortSignal.timeout(6000)})
    .then(function(r) { return r.json(); })
    .then(function(d) {
      if (!d.ok) return;
      setDot(true);

      if (d.size != null) set('ct-transfers', d.size.toLocaleString());

      var root = d.root;
      if (root && root !== '0'.repeat(64)) {
        set('ct-root', root.slice(0, 16) + '...' + root.slice(-8));
      }

      var feedEl = document.getElementById('ct-feed');
      if (feedEl && d.entries && d.entries.length) {
        var rows = d.entries.slice().reverse().map(function(e) {
          var ts = new Date(e.ts);
          var time = ts.toISOString().slice(11, 19);
          var hash = e.leaf_hash ? e.leaf_hash.slice(0, 12) + '...' : '—';
          return '<div><span style="color:var(--quiet)">#' + e.index + '</span>'
            + ' &nbsp;·&nbsp; ' + hash
            + ' &nbsp;·&nbsp; <span style="color:var(--quiet)">' + time + ' UTC</span></div>';
        });
        feedEl.innerHTML = rows.join('');
      }
    })
    .catch(function() { setDot(false); });

  // Relay self-registrations
  fetch(RELAY + '/v2/relays', {signal: AbortSignal.timeout(5000)})
    .then(function(r) { return r.json(); })
    .then(function(d) {
      if (d.total != null) set('ct-relays', d.total.toLocaleString());
    })
    .catch(function() {});

  // STH status — ghost_pipe mode returns error, show RAM-only
  fetch(RELAY + '/v2/sth', {signal: AbortSignal.timeout(5000)})
    .then(function(r) { return r.json(); })
    .then(function(d) {
      var el = document.getElementById('ct-sth-status');
      if (!el) return;
      if (d.tree_size != null) {
        el.textContent = '✓ signed';
        el.style.color = '#00cc33';
      } else {
        el.textContent = 'RAM-only';
        el.style.color = '#555';
      }
    })
    .catch(function() { set('ct-sth-status', 'RAM-only'); });
})();

// Pricing tab toggle
window.showTab = function(tab) {
  var opPane  = document.getElementById('pane-op');
  var userPane = document.getElementById('pane-user');
  var opBtn   = document.getElementById('tab-op');
  var userBtn = document.getElementById('tab-user');
  if (!opPane || !userPane) return;
  if (tab === 'op') {
    opPane.style.display   = '';
    userPane.style.display = 'none';
    opBtn.style.background   = '#ededed';
    opBtn.style.color        = '#111';
    userBtn.style.background = 'transparent';
    userBtn.style.color      = '#888';
  } else {
    opPane.style.display   = 'none';
    userPane.style.display = '';
    userBtn.style.background = '#ededed';
    userBtn.style.color      = '#111';
    opBtn.style.background   = 'transparent';
    opBtn.style.color        = '#888';
  }
};
