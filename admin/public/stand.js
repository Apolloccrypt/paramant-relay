'use strict';

// De standpagina. Hergebruikt de adminsessie uit de SPA (sessionStorage
// 'adm_session') en stuurt bij afwezigheid of afwijzing terug naar de inlog op
// /admin/. Zelfde patroon als settings.js, met opzet: er hoort geen tweede
// manier te bestaan om hier binnen te komen.

var SESSION = sessionStorage.getItem('adm_session') || '';
if (!SESSION) location.href = '/admin/';

// De vier standen zoals lib/stand.js ze noemt, elk met een eigen klasse. Ze
// staan hier bij elkaar zodat "niet gemeten" nooit per ongeluk als "goed" kan
// worden getekend: dat is precies de fout die deze pagina moet uitsluiten.
var KLASSE = {
  'goed': 's-goed',
  'let op': 's-letop',
  'niet gemeten': 's-onbekend',
  'kapot': 's-kapot',
};
var KOPWOORD = {
  'goed': 'het gaat goed',
  'let op': 'let op',
  'niet gemeten': 'onbekend',
  'kapot': 'er is iets kapot',
};

function klasse(stand) { return KLASSE[stand] || 's-onbekend'; }

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function api(pad, opts) {
  opts = opts || {};
  return fetch('/admin/api' + pad, {
    method: opts.method || 'GET',
    headers: { 'X-Session': SESSION, 'Content-Type': 'application/json' },
  }).then(function (r) {
    if (r.status === 401) { sessionStorage.removeItem('adm_session'); location.href = '/admin/'; throw new Error('unauthorized'); }
    return r.json().catch(function () { return null; }).then(function (data) {
      return { ok: r.ok, status: r.status, data: data };
    });
  });
}

function melden(tekst, stand) {
  var el = document.getElementById('melding');
  el.textContent = tekst;
  el.style.display = tekst ? 'block' : 'none';
  el.style.borderLeftColor = stand === 'kapot' ? 'var(--kapot)' : (stand === 'goed' ? 'var(--goed)' : 'var(--onbekend)');
}

function tekenPunt(p) {
  var h = '<div class="punt">';
  h += '<div class="punt-kop">';
  h += '<span class="punt-naam">' + esc(p.naam) + '</span>';
  h += '<span class="punt-stand ' + klasse(p.stand) + '">' + esc(p.stand) + '</span>';
  h += '</div>';
  h += '<div class="punt-zin">' + esc(p.zin) + '</div>';
  h += '<div class="punt-bron">gemeten met: ' + esc(p.bron) + '</div>';
  if (p.hoe && p.hoe.length) {
    h += '<div class="hoe"><div class="hoe-lbl">dit kun alleen jij doen</div>';
    for (var i = 0; i < p.hoe.length; i++) h += '<code>' + esc(p.hoe[i]) + '</code>';
    h += '</div>';
  }
  h += '</div>';
  return h;
}

function tekenBlok(b) {
  // Gaat een blok goed, dan staat het dicht. Is er iets aan de hand, dan staat
  // het open: dan hoort het gelezen te worden zonder eerst te tikken.
  var open = b.stand !== 'goed' ? ' open' : '';
  var mis = b.punten.filter(function (p) { return p.stand !== 'goed'; }).length;
  var tel = mis ? mis + ' van ' + b.punten.length : b.punten.length + ' in orde';

  var h = '<details class="blok"' + open + '><summary>';
  h += '<span class="stip ' + klasse(b.stand) + '"></span>';
  h += '<span class="blok-titel">' + esc(b.titel) + '</span>';
  h += '<span class="blok-tel">' + esc(tel) + '</span>';
  h += '<span class="pijl">&#9656;</span>';
  h += '</summary>';
  for (var i = 0; i < b.punten.length; i++) h += tekenPunt(b.punten[i]);
  h += '</details>';
  return h;
}

function tekenen(stand) {
  var kop = document.getElementById('kop');
  kop.className = 'kop ' + klasse(stand.kop.stand);
  document.getElementById('kop-woord').textContent = KOPWOORD[stand.kop.stand] || stand.kop.stand;
  document.getElementById('kop-zin').textContent = stand.kop.zin;

  var d = new Date(stand.gemeten_op);
  document.getElementById('gemeten').textContent =
    'gemeten op ' + d.toLocaleString('nl-NL', { dateStyle: 'short', timeStyle: 'short' });

  var uit = '';
  for (var i = 0; i < stand.blokken.length; i++) uit += tekenBlok(stand.blokken[i]);
  document.getElementById('blokken').innerHTML = uit;
}

function meten() {
  var knop = document.getElementById('ververs');
  knop.disabled = true;
  knop.textContent = 'Meten...';
  return api('/admin/stand').then(function (r) {
    if (!r.ok || !r.data || !r.data.blokken) {
      // Ook hier geen groen bij gebrek aan uitslag: de kop zegt dan dat het
      // meten zelf niet lukte.
      document.getElementById('kop').className = 'kop s-onbekend';
      document.getElementById('kop-woord').textContent = 'onbekend';
      document.getElementById('kop-zin').textContent =
        'Ik kon de stand niet meten' + (r.data && r.data.message ? ' (' + r.data.message + ')' : '') + '.';
      document.getElementById('blokken').innerHTML = '';
      return;
    }
    tekenen(r.data);
  }).catch(function (e) {
    if (e.message !== 'unauthorized') melden('Het meten liep vast: ' + e.message, 'kapot');
  }).then(function () {
    knop.disabled = false;
    knop.textContent = 'Opnieuw meten';
  });
}

document.getElementById('ververs').addEventListener('click', function () { melden(''); meten(); });

document.getElementById('proef').addEventListener('click', function () {
  var knop = document.getElementById('proef');
  knop.disabled = true;
  knop.textContent = 'Bezig...';
  melden('Er gaat nu een bestand door de relay heen.');
  api('/admin/stand/proef', { method: 'POST' }).then(function (r) {
    if (r.status === 429) {
      melden(r.data && r.data.message ? r.data.message : 'Er is net een proef gedaan.');
    } else if (r.data && r.data.ok) {
      melden('Gelukt. Het bestand ging erin, kwam byte voor byte hetzelfde terug en was daarna vernietigd. Dat duurde ' + r.data.ms + ' ms.', 'goed');
    } else {
      melden('Mislukt: ' + ((r.data && r.data.reden) || 'onbekende reden') + '.', 'kapot');
    }
    return meten();
  }).catch(function (e) {
    if (e.message !== 'unauthorized') melden('De proef liep vast: ' + e.message, 'kapot');
  }).then(function () {
    knop.disabled = false;
    knop.textContent = 'Doe de echte proef';
  });
});

meten();
