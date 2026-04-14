// Relay count from registry
fetch('https://health.paramant.app/v2/relays',{signal:AbortSignal.timeout(5000)})
  .then(function(r){return r.json()})
  .then(function(d){
    var ce=document.getElementById('ct-count');
    if(ce && d.total!=null) ce.textContent=d.total.toLocaleString();
  }).catch(function(){});

// Merkle root from CT log
fetch('https://health.paramant.app/v2/ct/log?limit=1',{signal:AbortSignal.timeout(5000)})
  .then(function(r){return r.json()})
  .then(function(d){
    var re=document.getElementById('ct-root');
    if(re && d.root && d.root!=='0'.repeat(64)) re.textContent=d.root.slice(0,16)+'...'+d.root.slice(-8);
  }).catch(function(){});

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
