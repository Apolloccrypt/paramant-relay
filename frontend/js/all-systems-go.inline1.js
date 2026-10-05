
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
      dot.innerHTML = '&#10003;'; title.textContent = 'Alles werkt';
      sub.textContent = 'Uw relay ' + esc(data.version||'') + ' is gezond en klaar voor gebruik.';
    } else if (overall === 'yellow') {
      dot.innerHTML = '!'; title.textContent = 'Actief, met waarschuwingen';
      sub.textContent = 'De relay draait. Een paar controles hieronder vragen aandacht.';
    } else {
      dot.innerHTML = '&times;'; title.textContent = 'Aandacht nodig';
      sub.textContent = 'Een of meer controles zijn mislukt. Zie de details hieronder.';
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
      'Relay ' + esc(data.version||'?') + ' / sector ' + esc(data.sector||'?') + ' · bijgewerkt ' + new Date().toLocaleTimeString('nl-NL');
  }

  function poll(){
    fetch('/v2/health/deep', { cache: 'no-store' })
      .then(function(r){ return r.json(); })
      .then(render)
      .catch(function(){
        document.getElementById('overall-title').textContent = 'De relay is niet bereikbaar';
        document.getElementById('overall-sub').textContent = 'Het endpoint /v2/health/deep gaf geen antwoord.';
        document.getElementById('overall-dot').className = 'asg-dot-lg asg-overall-red';
        document.getElementById('overall-dot').innerHTML = '&times;';
      });
  }
  poll();
  setInterval(poll, 5000);
  