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

  // /ct/feed — tree_size, root, last 50 entries with types
  fetch(RELAY + '/ct/feed', {signal: AbortSignal.timeout(6000)})
    .then(function(r) { return r.json(); })
    .then(function(d) {
      setDot(true);

      if (d.tree_size != null) set('ct-transfers', d.tree_size.toLocaleString());

      var root = d.root;
      if (root && root !== '0'.repeat(64)) {
        set('ct-root', root.slice(0, 16) + '...' + root.slice(-8));
      }

      if (d.entries) {
        // Registered relays = device key registrations (no type or type='key_reg')
        var keyRegCount = d.entries.filter(function(e) {
          return !e.type || e.type === 'key_reg';
        }).length;
        set('ct-relays', keyRegCount.toLocaleString());

        var feedEl = document.getElementById('ct-feed');
        if (feedEl && d.entries.length) {
          var last3 = d.entries.slice(-3).reverse();
          var rows = last3.map(function(e) {
            var ts = new Date(e.t);
            var time = ts.toISOString().slice(11, 19);
            var hash = e.h ? e.h.slice(0, 12) + '...' : '—';
            return '<div><span style="color:var(--quiet)">#' + e.i + '</span>'
              + ' &nbsp;·&nbsp; ' + hash
              + ' &nbsp;·&nbsp; <span style="color:var(--quiet)">' + time + ' UTC</span></div>';
          });
          feedEl.innerHTML = rows.join('');
        }
      }
    })
    .catch(function() { setDot(false); });

  // STH status — disk-backed, signed with ML-DSA-65
  fetch(RELAY + '/v2/sth', {signal: AbortSignal.timeout(5000)})
    .then(function(r) { return r.json(); })
    .then(function(d) {
      var el = document.getElementById('ct-sth-status');
      if (!el) return;
      if (d.ok && d.sth) {
        el.textContent = 'ML-DSA-65';
        el.style.color = '#00cc33';
      } else {
        el.textContent = 'signed';
        el.style.color = '#555';
      }
    })
    .catch(function() { set('ct-sth-status', 'offline'); });
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
