// CT log widget — fetches live data from public relay endpoints
(function() {
  var RELAY = 'https://health.paramant.app';

  // Full HTML-entity encoder (escapes & < > " ') so esc() is safe in both text
  // and attribute contexts. The /ct/feed JSON is relay-controlled, not strictly
  // trusted, so anything interpolated into innerHTML below is run through this.
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c];
    });
  }

  function set(id, val) {
    var el = document.getElementById(id);
    if (el) el.textContent = val;
  }

  function setDot(ok) {
    var dot = document.getElementById('ct-dot');
    if (dot) dot.style.background = ok ? '#B2FF3F' : '#FCA5A5';
  }

  // /ct/feed -- tree_size, root, last 50 entries with types
  fetch(RELAY + '/ct/feed', {signal: AbortSignal.timeout(6000)})
    .then(function(r) { return r.json(); })
    .then(function(d) {
      setDot(true);

      if (d.tree_size != null) set('ct-transfers', d.tree_size.toLocaleString());

      var root = d.root;
      if (root && root !== '0'.repeat(64)) {
        set('ct-root', root.slice(0, 16) + ' ... ' + root.slice(-16));
      }

      if (d.entries) {
        var sectors = {};
        d.entries.forEach(function(e) {
          if (e && (e.type === 'relay_reg' || e.type === 'key_reg' || !e.type) && e.s) {
            sectors[e.s] = true;
          }
        });
        var n = Object.keys(sectors).length;
        if (n > 0) set('ct-relays', n.toLocaleString());

        var feedEl = document.getElementById('ct-feed');
        if (feedEl && d.entries.length) {
          var last3 = d.entries.slice(-3).reverse();
          var rows = last3.map(function(e) {
            var ts = new Date(e.t);
            var time = ts.toISOString().slice(11, 19);
            // index is an integer log position; coerce and drop anything else.
            var idx = Number(e.i);
            var idxStr = Number.isFinite(idx) ? String(Math.trunc(idx)) : '?';
            // hash is a hex digest; keep only the hex prefix, else show nothing.
            var hex = /^[0-9a-fA-F]+$/.test(e.h) ? e.h.slice(0, 12) : '';
            var hash = hex ? hex + '...' : '--';
            return '<div><span style="color:var(--quiet)">#' + esc(idxStr) + '</span>'
              + ' &nbsp;&middot;&nbsp; ' + esc(hash)
              + ' &nbsp;&middot;&nbsp; <span style="color:var(--quiet)">' + esc(time) + ' UTC</span></div>';
          });
          feedEl.innerHTML = rows.join('');
        }
      }
    })
    .catch(function() { setDot(false); });

  // STH status -- disk-backed, signed with ML-DSA-65
  fetch(RELAY + '/v2/sth', {signal: AbortSignal.timeout(5000)})
    .then(function(r) { return r.json(); })
    .then(function(d) {
      var el = document.getElementById('ct-sth-status');
      if (!el) return;
      if (d.ok && d.sth) {
        el.textContent = 'ML-DSA-65';
      } else {
        el.textContent = 'signed';
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
