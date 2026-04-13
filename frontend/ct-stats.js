fetch('https://health.paramant.app/v2/ct/log?limit=1000',{signal:AbortSignal.timeout(5000)})
  .then(function(r){return r.json()})
  .then(function(d){
    var ce=document.getElementById('ct-count');
    var re=document.getElementById('ct-root');
    var entries=d.entries||[];
    var relayCount=entries.filter(function(e){return e.type==='relay_reg';}).length;
    if(ce) ce.textContent=relayCount.toLocaleString();
    if(re && d.root && d.root!=='0'.repeat(64)) re.textContent=d.root.slice(0,16)+'...'+d.root.slice(-8);
  }).catch(function(){});

fetch('https://health.paramant.app/health',{signal:AbortSignal.timeout(5000)}).then(function(r){return r.json()}).then(function(d){
  if(d.ok){
    document.getElementById('sdot').style.background='#2d6a4f';
    document.getElementById('stxt').textContent='All relays operational \u00b7 v'+d.version;
  }else{
    document.getElementById('stxt').textContent='Relay degraded';
  }
}).catch(function(){
  document.getElementById('sdot').style.background='#555';
  document.getElementById('stxt').textContent='Relay status unknown';
});

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
