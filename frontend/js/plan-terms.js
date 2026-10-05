/* One line per product about the terms that are paid for: what runs now, until
 * when, and what takes over after it.
 *
 * Why. After a Firm customer bought a month of Business, /account said "Ends
 * on 5 November" and directly under it "Access until 6 December": two true
 * dates with nothing to say which product they belonged to (betaaltest
 * 05-10, row 8). The relay serves every running term per product
 * (terms_parasign / terms_parasend, highest tier first, relay.js
 * _runningTermsView), and this turns them into
 *   "Ondertekenen: Business tot 5 november 2026, daarna Firm tot 5 december 2026."
 *   "Versturen: Firm tot 5 december 2026."
 * Used by /account and /dashboard, Dutch and English, so the two pages can not
 * word the same terms in two ways. Plain browser script, CSP-safe; needs
 * /js/format-date.js (paramantDate) for the one date notation of the site.
 */
(function () {
  'use strict';

  function en() { return /^en\b/i.test(document.documentElement.lang || ''); }
  function t(nl, eng) { return en() ? eng : nl; }

  var PRODUCT = {
    parasign: function () { return t('Ondertekenen', 'ParaSign'); },
    parasend: function () { return t('Versturen', 'ParaSend'); }
  };
  // The names /pricing sells. Pro is Firm on both products: Firm is the only
  // thing on sale that grants it. ParaSend Pro bought as part of Business is
  // named after Business, because that is what the customer paid for.
  function tierName(product, term) {
    if (product === 'parasend' && term.tier === 'pro' && term.bundle === 'business') {
      return t('inbegrepen bij Business', 'included with Business');
    }
    return { pro: 'Firm', business: 'Business', enterprise: 'Enterprise' }[term.tier] || term.tier;
  }

  function day(iso) {
    return (window.paramantDate && window.paramantDate.day) ? window.paramantDate.day(iso) : String(iso).slice(0, 10);
  }

  function part(product, term) {
    var name = tierName(product, term);
    return term.until
      ? name + t(' tot ', ' until ') + day(term.until)
      : name + t(', zonder einddatum', ', no end date');
  }

  // The running paid terms of one product, from the served list, or from the
  // single tier and date an older admin plane sends.
  function termsOf(data, product) {
    var list = data && data['terms_' + product];
    var now = Date.now();
    if (Array.isArray(list) && list.length) {
      return list.filter(function (x) { return x && x.tier && (!x.until || Date.parse(x.until) > now); });
    }
    var tier = String((data && data['plan_' + product]) || '').toLowerCase();
    if (!tier || tier === 'free' || tier === 'community' || tier === 'standard') return [];
    var until = data['paid_until_' + product] || null;
    if (until && Date.parse(until) <= now) return [];
    return [{ tier: tier, until: until, bundle: null }];
  }

  function lines(data) {
    var out = [];
    ['parasign', 'parasend'].forEach(function (product) {
      var terms = termsOf(data, product);
      if (!terms.length) return;
      var text = PRODUCT[product]() + ': ' + part(product, terms[0]);
      for (var i = 1; i < terms.length; i++) text += t(', daarna ', ', then ') + part(product, terms[i]);
      out.push(text + '.');
    });
    return out;
  }

  // Fill a list element with one <li> per product, and hide it when there is
  // nothing paid to say. textContent only: the tier names come from the server.
  function render(el, data) {
    if (!el) return;
    while (el.firstChild) el.removeChild(el.firstChild);
    var ls = lines(data);
    ls.forEach(function (text) {
      var li = document.createElement('li');
      li.textContent = text;
      el.appendChild(li);
    });
    el.hidden = ls.length === 0;
  }

  window.paPlanTerms = { lines: lines, render: render };
})();
