
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

  var T_UP = 'De relay antwoordt';
  var T_DOWN = 'De relay antwoordt niet op /health';
  var T_SUB = 'De uitgebreide controle (opslag, sleutels, TLS) is alleen zichtbaar voor de beheerder van deze relay. Openbaar te zien is alleen of de relay antwoordt.';
  var T_AT = ' · bijgewerkt ';
  var T_LOC = 'nl-NL';

  // What anyone can measure without operator access: does /health answer.
  // Neutral, never green: the deep checks were not run.
  function publicOnly(){
    return fetch('/health', { cache: 'no-store' })
      .then(function(r){ return r.ok ? r.json() : null; })
      .catch(function(){ return null; })
      .then(function(h){
        var dot = document.getElementById('overall-dot');
        dot.className = 'asg-dot-lg asg-overall-loading';
        dot.innerHTML = 'i';
        document.getElementById('overall-title').textContent = h && h.ok ? T_UP : T_DOWN;
        document.getElementById('overall-sub').textContent = T_SUB;
        document.getElementById('checks').innerHTML = '';
        document.getElementById('asg-meta').textContent = h && h.ok
          ? 'Relay ' + esc(h.version||'?') + ' / sector ' + esc(h.sector||'?') + T_AT + new Date().toLocaleTimeString(T_LOC)
          : '';
      });
  }

  function poll(){
    fetch('/v2/health/deep', { cache: 'no-store' })
      .then(function(r){
        // 401/403: the deep check is for the operator of this relay only (on
        // our own relays it sits behind internal auth). That is not a failed
        // check, so it must not read as one: show what is public instead.
        if (r.status === 401 || r.status === 403) return publicOnly();
        return r.json().then(render);
      })
      .catch(function(){
        document.getElementById('overall-title').textContent = 'De relay is niet bereikbaar';
        document.getElementById('overall-sub').textContent = 'Het endpoint /v2/health/deep gaf geen antwoord.';
        document.getElementById('overall-dot').className = 'asg-dot-lg asg-overall-red';
        document.getElementById('overall-dot').innerHTML = '&times;';
      });
  }
  poll();
  setInterval(poll, 5000);
  