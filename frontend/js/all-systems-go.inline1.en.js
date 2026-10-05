
  'use strict';
  function esc(s){ return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;'); }
  function cap(s){ return s ? s.charAt(0).toUpperCase()+s.slice(1) : s; }

  function render(data){
    var overall = (data && data.overall) || 'red';
    var dot = document.getElementById('overall-dot');
    var title = document.getElementById('overall-title');
    var sub = document.getElementById('overall-sub');
    dot.className = 'asg-dot-lg asg-overall-' + overall;
    if (overall === 'green') {
      dot.innerHTML = '&#10003;'; title.textContent = 'All systems go';
      sub.textContent = 'Your relay ' + esc(data.version||'') + ' is healthy and ready.';
    } else if (overall === 'yellow') {
      dot.innerHTML = '!'; title.textContent = 'Up, with warnings';
      sub.textContent = 'The relay is running; some checks need attention below.';
    } else {
      dot.innerHTML = '&times;'; title.textContent = 'Attention needed';
      sub.textContent = 'One or more checks failed. See details below.';
    }
    var box = document.getElementById('checks');
    var checks = (data && data.checks) || [];
    box.innerHTML = checks.map(function(c){
      return '<div class="asg-row">' +
        '<span class="asg-dot asg-' + esc(c.status) + '"></span>' +
        '<span class="asg-name">' + esc(cap(c.name)) + '</span>' +
        '<span class="asg-detail">' + esc(c.detail) + '</span>' +
        '</div>';
    }).join('');
    document.getElementById('asg-meta').textContent =
      'Relay ' + esc(data.version||'?') + ' / sector ' + esc(data.sector||'?') + ' - updated ' + new Date().toLocaleTimeString();
  }

  function poll(){
    fetch('/v2/health/deep', { cache: 'no-store' })
      .then(function(r){ return r.json(); })
      .then(render)
      .catch(function(){
        document.getElementById('overall-title').textContent = 'Cannot reach the relay';
        document.getElementById('overall-sub').textContent = 'The /v2/health/deep endpoint did not respond.';
        document.getElementById('overall-dot').className = 'asg-dot-lg asg-overall-red';
        document.getElementById('overall-dot').innerHTML = '&times;';
      });
  }
  poll();
  setInterval(poll, 5000);
  