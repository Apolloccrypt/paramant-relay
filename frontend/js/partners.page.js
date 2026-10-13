// /partners en /en/partners: elke externe partij, live uit /partners.json.
//
// /partners.json is een kopie van deploy/partners.json, het bestand waar de
// site, de code en de productiesleutels tegen getoetst worden
// (tests/partners.test.mjs houdt de twee byte voor byte gelijk). Deze pagina
// schrijft zelf geen enkele partij: staat er iets niet in het bestand, dan
// staat het hier ook niet. Alles gaat via textContent, niets via innerHTML.
(function () {
  'use strict';
  var root = document.getElementById('partners-lijst');
  if (!root) return;
  var en = (document.documentElement.lang || '').slice(0, 2) === 'en';
  var taal = en ? 'en' : 'nl';

  var T = en ? {
    rol: 'Role', land: 'Country', moeder: 'Parent company', onbekend: 'unknown',
    krijgt: 'Receives', nooit: 'Never receives', sub: 'Sub-processor (GDPR)',
    ja: 'Yes', nee: 'No', dpa: 'Data processing agreement', geenDpa: 'No public link',
    sinds: 'since', tot: 'since', datumOnbekend: 'date unknown', juridisch: 'Legal name unknown',
    fout: 'The list could not be loaded. The file itself is at ',
    groepen: { 'actief': 'Active', 'in-code-niet-actief': 'In preparation', 'uitgefaseerd': 'Phased out' },
    uitleg: {
      'actief': 'Production uses these today.',
      'in-code-niet-actief': 'The code knows these, but production holds no keys for them. They receive nothing.',
      'uitgefaseerd': 'No longer in use. Where a leftover key still sits on the server, it is listed with a clean-up date in the file.'
    },
    maanden: ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December']
  } : {
    rol: 'Rol', land: 'Land', moeder: 'Moederbedrijf', onbekend: 'onbekend',
    krijgt: 'Krijgt', nooit: 'Krijgt nooit', sub: 'Subverwerker (AVG)',
    ja: 'Ja', nee: 'Nee', dpa: 'Verwerkersovereenkomst', geenDpa: 'Geen openbare link',
    sinds: 'sinds', tot: 'sinds', datumOnbekend: 'datum onbekend', juridisch: 'Juridische naam onbekend',
    fout: 'De lijst kon niet geladen worden. Het bestand zelf staat op ',
    groepen: { 'actief': 'Actief', 'in-code-niet-actief': 'In voorbereiding', 'uitgefaseerd': 'Uitgefaseerd' },
    uitleg: {
      'actief': 'Productie gebruikt deze partijen vandaag.',
      'in-code-niet-actief': 'De code kent ze, maar productie heeft er geen sleutels voor. Ze krijgen niets.',
      'uitgefaseerd': 'Niet meer in gebruik. Staat er nog een oude sleutel op de server, dan staat die met een opruimdatum in het bestand.'
    },
    maanden: ['januari', 'februari', 'maart', 'april', 'mei', 'juni', 'juli', 'augustus', 'september', 'oktober', 'november', 'december']
  };

  function datum(iso) {
    var m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(iso || ''));
    if (!m) return '';
    return Number(m[3]) + ' ' + T.maanden[Number(m[2]) - 1] + ' ' + m[1];
  }

  function el(tag, cls, tekst) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (tekst != null) e.textContent = tekst;
    return e;
  }

  function rij(dl, label, waarde) {
    dl.appendChild(el('dt', null, label));
    var dd = el('dd');
    if (waarde && waarde.nodeType) dd.appendChild(waarde);
    else dd.textContent = waarde;
    dl.appendChild(dd);
  }

  function kaart(p, data) {
    var art = el('article', 'partner');
    art.id = 'partij-' + p.id;
    art.setAttribute('data-status', p.status);
    var kop = el('div', 'partner-kop');
    kop.appendChild(el('h3', null, p.handelsnaam));
    var label = T.groepen[p.status] || p.status;
    var wanneer = p.status === 'uitgefaseerd' ? p.tot : p.sinds;
    var badge = el('span', 'partner-status status-' + p.status,
      label + (p.status === 'in-code-niet-actief' ? '' : ' · ' + (wanneer ? T.sinds + ' ' + datum(wanneer) : T.datumOnbekend)));
    kop.appendChild(badge);
    art.appendChild(kop);
    art.appendChild(el('p', 'partner-naam', p.naam || T.juridisch));

    var dl = el('dl', 'partner-feiten');
    var rol = (data.rollen && data.rollen[p.rol]) ? data.rollen[p.rol][taal] : p.rol;
    rij(dl, T.rol, rol);
    rij(dl, T.land, (p.land && p.land[taal]) || T.onbekend);
    var moeder = p.moederbedrijf
      ? p.moederbedrijf + (p.moederbedrijf_land ? ' (' + p.moederbedrijf_land[taal] + ')' : '')
      : T.onbekend;
    rij(dl, T.moeder, moeder);
    rij(dl, T.krijgt, (p.gegevens && p.gegevens[taal]) || '');
    rij(dl, T.nooit, (p.nooit && p.nooit[taal]) || '');
    rij(dl, T.sub, p.subverwerker ? T.ja : T.nee);
    if (p.dpa_url) {
      var a = el('a', null, p.dpa_url.replace(/^https:\/\//, ''));
      a.href = p.dpa_url;
      a.rel = 'noopener';
      rij(dl, T.dpa, a);
    } else {
      rij(dl, T.dpa, T.geenDpa);
    }
    art.appendChild(dl);
    return art;
  }

  function toon(data) {
    var g = document.getElementById('partners-gewijzigd');
    if (g) g.textContent = datum(data.gewijzigd) || data.gewijzigd || '';
    root.textContent = '';
    ['actief', 'in-code-niet-actief', 'uitgefaseerd'].forEach(function (status) {
      var lijst = (data.partijen || []).filter(function (p) { return p.status === status; });
      if (!lijst.length) return;
      var sec = el('section', 'partner-groep');
      sec.setAttribute('aria-labelledby', 'groep-' + status);
      var h = el('h2', null, T.groepen[status] + ' (' + lijst.length + ')');
      h.id = 'groep-' + status;
      sec.appendChild(h);
      sec.appendChild(el('p', 'partner-uitleg', T.uitleg[status]));
      var grid = el('div', 'partner-grid');
      lijst.forEach(function (p) { grid.appendChild(kaart(p, data)); });
      sec.appendChild(grid);
      root.appendChild(sec);
    });
    root.setAttribute('aria-busy', 'false');
  }

  function fout() {
    root.textContent = '';
    var p = el('p', 'partner-fout', T.fout);
    var a = el('a', null, '/partners.json');
    a.href = '/partners.json';
    p.appendChild(a);
    p.appendChild(document.createTextNode('.'));
    root.appendChild(p);
    root.setAttribute('aria-busy', 'false');
  }

  fetch('/partners.json', { credentials: 'omit', cache: 'no-cache' })
    .then(function (r) { if (!r.ok) throw new Error('http ' + r.status); return r.json(); })
    .then(toon)
    .catch(fout);
})();
