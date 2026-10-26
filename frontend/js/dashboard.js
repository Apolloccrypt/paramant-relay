// One file, two languages: the Dutch page and its English copy under /en/ load
// this same script, and <html lang> says which of the two strings to show.
function nlEn(nl, en) { return /^en\b/i.test(document.documentElement.lang || '') ? en : nl; }
/* "Je documenten": the one signed-in screen (/dashboard, /en/dashboard).
 *
 * WHAT IT REPLACES. Until 25 October 2026 a signed-in customer had two
 * overviews: the homepage drew a workbench (a big figure, the inbox, the
 * month) and /dashboard drew the same documents again in four sections. They
 * counted the same request differently more than once. Now the homepage sends
 * a signed-in visitor here (js/home-auth.js) and this screen is the overview:
 * two tabs, Open and Klaar, and in them one card per piece of work, whatever
 * kind it is. The look is the one of Stukken opvragen (app-ui.css).
 *
 * WHAT IT READS, all with the session cookie, never with a key:
 *   GET /api/user/me                   who, which plan, until when
 *   GET /api/user/documents            the signing requests this account sent
 *   GET /api/user/parasign/inbox       what waits for YOUR signature
 *   GET /api/user/sends                the files this account sent by name
 *   GET /api/user/sends/:id            who collected one of them (open ones)
 *   GET /api/user/opvragen             the requests for documents
 *   GET /api/user/dashboard/overview   the month's use, for the one plan line
 * Every list is counted once, by js/document-state.js tally(), so the number
 * on the tab is the number of cards under it.
 *
 * Auth-gate is hard: 401/403 on /api/user/me goes to the sign-in page before
 * anything of the account is shown (#dh-root starts hidden).
 *
 * TOLERANT. A list that does not load says so in one calm line with a way to
 * try again, and is never shown as empty: "nothing here" on a failed fetch is
 * the one lie this screen could tell, and the reader would stop looking.
 *
 * Names and file names are chosen by other people, so everything they touch
 * goes through esc() or textContent.
 */
(function () {
  'use strict';

  var KEYSETUP_KEY = 'paramant.keysetup.dismissed.v1';
  // Every page this script links to has an English copy under /en/, and the
  // English dashboard used to send its reader to the Dutch ones (acceptatie
  // 3.1.1, betalen punt 5). LP is the prefix of the page's own language.
  var LP = nlEn('', '/en');
  var LOGIN_URL = LP + '/auth/login?next=' + encodeURIComponent(LP + '/dashboard');

  var loading = document.getElementById('dh-loading');
  var root    = document.getElementById('dh-root');
  var errBox  = document.getElementById('dh-error');
  var errMsg  = document.getElementById('dh-error-detail');
  if (!root || !loading) return;

  var docState = window.paramantDocState;

  function show(el)   { if (el) el.hidden = false; }
  function hide(el)   { if (el) el.hidden = true; }
  function txt(sel, value) {
    var nodes = root.querySelectorAll('[data-dh="' + sel + '"]');
    for (var i = 0; i < nodes.length; i++) nodes[i].textContent = value;
  }
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c];
    });
  }
  // CSS.escape is not everywhere yet and the ids are relay-generated, so keep
  // the selector safe by hand.
  function cssEscape(value) {
    return String(value == null ? '' : value).replace(/["\\]/g, '\\$&');
  }
  function ico(name, size) {
    return '<svg width="' + size + '" height="' + size + '" aria-hidden="true"><use href="#i-' + name + '"/></svg>';
  }
  // One notation for every date (js/format-date.js): day, month, year. A
  // sending also gets its time, because two sends of one day to the same
  // number of people are otherwise one line twice (fase 1, SENDNAME-18-A).
  function fmtDate(iso) { return paramantDate.day(iso); }

  // What went wrong, in words, and the way back that fits. A 429 or a 5xx says
  // nothing about the session, so it gets "try again" and not "sign in again"
  // (fase 1, DASH-01-K and DASH-21-A: both showed "Opnieuw inloggen HTTP 500").
  function showError(kind) {
    hide(loading);
    hide(root);
    show(errBox);
    var text = document.getElementById('dh-error-text');
    var login = document.getElementById('dh-error-login');
    var retry = document.getElementById('dh-error-retry');
    var says = kind === 'busy'
      ? nlEn('Even te veel verzoeken tegelijk. Probeer het over een minuut opnieuw. Je bent nog ingelogd.', 'Too many requests at once. Try again in a minute. You are still signed in.')
      : kind === 'server'
        ? nlEn('Je overzicht laadt niet door een storing bij ons. Er is niets veranderd. Probeer het zo opnieuw.', 'Your overview did not load because of a fault on our side. Nothing changed. Try again shortly.')
        : nlEn('We konden je overzicht niet laden. Controleer je verbinding en probeer het opnieuw.', 'We could not load your overview. Check your connection and try again.');
    if (text) text.textContent = says;
    if (errMsg) errMsg.textContent = '';
    if (login) login.hidden = true;
    if (retry && !retry._wired) {
      retry._wired = 1;
      retry.addEventListener('click', function () {
        retry.disabled = true;
        hide(errBox);
        show(loading);
        start();
        setTimeout(function () { retry.disabled = false; }, 1500);
      });
    }
  }

  // Plan names, mirroring relay/lib/tiers.js, which is the declared single
  // source of truth. TIER_LIMITS has exactly four rows and normalisePlan folds
  // every other ID onto one of them: 'free' and 'dev' become community,
  // 'licensed' becomes enterprise, anything unknown becomes community. So the
  // badge has four names to say and never a raw machine string, which is what
  // it printed for 'licensed' before. tests/ui-truthfulness.test.mjs reads the
  // rows and the aliases OUT of tiers.js and fails if this drifts from it.
  var PLAN_ALIASES = { free: 'community', dev: 'community', licensed: 'enterprise' };
  var PLAN_NAMES = {
    community: 'Community',
    pro:       'Firm',
    business:  'Business',
    enterprise:'Enterprise',
  };

  function normalisePlan(plan) {
    var id = String(plan == null ? '' : plan).toLowerCase();
    if (PLAN_ALIASES[id]) return PLAN_ALIASES[id];
    return PLAN_NAMES[id] ? id : 'community';
  }

  // Per-product ladders, lowest first, so the badge can show the highest tier a
  // customer actually pays for. Mirrors PARASEND_TIERS / PARASIGN_TIERS in
  // relay/lib/entitlements.js. The two products do NOT share a floor there:
  // PARASEND_TIERS starts at 'community' and PARASIGN_TIERS at 'free', so both
  // words have to count as unpaid.
  // Only the rungs you can pay for. The two products do NOT share a floor in
  // relay/lib/entitlements.js: PARASEND_TIERS starts at 'community' and
  // PARASIGN_TIERS at 'free'. Rather than list both floor words and hope the
  // list stays complete, this reads the other way round and fails closed: a
  // tier counts as paid only when it is one of these three. A floor word, a
  // renamed tier or a typo all come out unpaid, which is the safe direction.
  var PRODUCT_LADDER = ['pro', 'business', 'enterprise'];
  var PRODUCT_NAMES = { pro: 'Firm', business: 'Business', enterprise: 'Enterprise' };

  // A product tier counts as paid only while its period still runs, which is
  // the rule effectiveProductTier() applies server-side: the floor tier never
  // expires, and a missing paid_until means no period was ever recorded.
  function paidProductTier(tier, paidUntil) {
    var t = String(tier || 'free').toLowerCase();
    if (PRODUCT_LADDER.indexOf(t) < 0) return null;
    if (!paidUntil) return t;
    var ends = Date.parse(paidUntil);
    if (!isNaN(ends) && Date.now() >= ends) return null;
    return t;
  }

  // ── The end of the term that was bought ────────────────────────────────────
  // Same rule and same words as /account: a checkout here buys one month or one
  // year outright, so paid_until_<product> is the day access stops and there is
  // no collection to announce. Two products can hold two dates; the one that
  // matters is the nearest one still ahead, and once they have all passed it is
  // the last one, because that is the day the account fell back to Community.
  var TERM_WARN_DAYS = 7;
  function termState(data, nowMs) {
    var now = typeof nowMs === 'number' ? nowMs : Date.now();
    var ends = [data.paid_until_parasign, data.paid_until_parasend]
      .map(function (v) { return v ? Date.parse(v) : NaN; })
      .filter(function (t) { return !isNaN(t); });
    if (!ends.length) return null;
    var ahead = ends.filter(function (t) { return t > now; });
    // The LAST end still ahead: the day the account actually stops having
    // what it paid for. It used to be the nearest one, so after a Firm to
    // Business upgrade one page said the 5th of one month and the row under it
    // the 6th of the next (betaaltest 05-10, row 8). What runs out earlier on
    // one product is said per product, in the lines under it (plan-terms.js).
    var at = ahead.length ? Math.max.apply(null, ahead) : Math.max.apply(null, ends);
    var days = (at - now) / 86400000;
    return { at: at, ended: at <= now, warn: days > 0 && days <= TERM_WARN_DAYS };
  }

  // One notation, from /js/format-date.js, and not the visitor's locale: the
  // site is in English and the same date has to read the same here, on /account
  // and in the reminder mail.
  function renderTerm(root, data) {
    var line = root.querySelector('#dh-term-line');
    var warn = root.querySelector('#dh-term-warn');
    if (line) line.hidden = true;
    if (warn) warn.hidden = true;
    if (window.paPlanTerms) window.paPlanTerms.render(root.querySelector('#dh-term-products'), data, { onlyIfAdds: true });
    var term = termState(data);
    if (!term) return;
    var when = paramantDate.day(term.at);
    if (line) {
      // The same sentence /account writes (plan-terms.js headline), so the two
      // pages can not word one term in two ways.
      var said = !term.ended && window.paPlanTerms && window.paPlanTerms.headline(data);
      line.textContent = term.ended
        ? nlEn('Afgelopen op ', 'Ended on ') + when + nlEn(', nu op Community.', ', now on Community.')
        : said || (nlEn('Betaald tot ', 'Paid until ') + when + nlEn('. Er wordt niets automatisch verlengd. Verlengen kan vanaf vandaag, je verliest geen dag.', '. Nothing renews automatically. You can renew from today without losing a day.'));
      line.hidden = false;
    }
    if (warn && term.warn && data.auto_renews !== true) {
      var text = warn.querySelector('[data-dh="term-warn"]');
      if (text) text.textContent = nlEn('Je plan loopt af op ', 'Your plan ends on ') + when + nlEn('. Verleng met een maand of een jaar, of laat het terugvallen op Community. Er wordt niets automatisch afgeschreven.', '. Renew for another month or year, or let it fall back to Community. Nothing is charged automatically.');
      warn.hidden = false;
    }
  }

  // What a paying customer already has, per product, quoted from /pricing. It
  // stays keyed per product because the entitlement layer is: the tier keys are
  // still 'pro' and 'business' per product, and a legacy single-product term
  // still lands on one ladder only. Firm writes both at once, so a Firm buyer
  // reads both lines. Nothing here is an upsell. A customer who has paid should
  // read what he bought.
  var PRODUCT_INCLUDES = {
    parasign: {
      pro: nlEn('Ondertekenen: 100 handtekeningen per maand, en een koppeling met je eigen systemen.', 'ParaSign: 100 signatures a month, and a connection you can plug into your own systems.'),
      business: nlEn('Ondertekenen: 1.000 handtekeningen per maand, ondersteuning van een vast persoon die binnen één werkdag antwoordt, hulp bij de beveiligingsvragenlijsten van je klanten, en een overzicht van alle stappen bij het ondertekenen (een audittrail) dat je als bestand kunt downloaden.', 'ParaSign: 1,000 signatures a month, support with a name on it that answers within one business day, help answering your customers\u2019 security questionnaires, and an audit trail you can export as a file.'),
      enterprise: nlEn('Ondertekenen: een eigen server, een aparte server voor zorg, juridisch of financieel, een SLA met compensatie, een licentie om zelf te hosten en hulp bij audits.', 'ParaSign: your own dedicated relay, a sector relay for health, legal or finance, a service level agreement with credits, a self-hosting licence and audit support.')
    },
    parasend: {
      // "and no rate limit" stood here until 2026-10-05 while tiers.js holds
      // Firm to 500 an hour (outbound_per_hour), betaaltest row 9. Every number
      // in these lines is pinned to tiers.js by tests/site-claims.test.mjs.
      pro: nlEn('Versturen: 500 verzendingen per maand en hooguit 500 per uur, tot 30 ontvangers per verzending, links die 24 uur open blijven, via de API tot 10 keer te openen, tot 50 geregistreerde apparaten, en een overzicht van wat je verstuurde.', 'ParaSend: 500 transfers a month and at most 500 an hour, up to 30 recipients per send, links that stay open 24 hours, up to 10 reads each through the API, up to 50 registered devices, and a record of what you sent.'),
      // The same ParaSend Pro, bought as part of Business (besluit 05-10).
      pro_business: nlEn('Versturen: 500 verzendingen per maand en hooguit 500 per uur, tot 30 ontvangers per verzending, links die 24 uur open blijven, via de API tot 10 keer te openen, tot 50 geregistreerde apparaten, en een overzicht van wat je verstuurde.', 'ParaSend: 500 transfers a month and at most 500 an hour, up to 30 recipients per send, links that stay open 24 hours, up to 10 reads each through the API, up to 50 registered devices, and a record of what you sent.'),
      enterprise: nlEn('Versturen: links die 7 dagen open blijven, tot 100 keer te openen, onbeperkt apparaten, een eigen server, een getekende verwerkersovereenkomst en 99,95% beschikbaarheid.', 'ParaSend: links that stay open 7 days, up to 100 reads each, unlimited devices, your own dedicated relay, a signed Data Processing Agreement and 99.95% uptime.')
    }
  };

  // ── Return from the payment provider ────────────────────────────────────────
  // Mollie redirects the buyer to /dashboard?billing=return the moment he is
  // done paying, and calls the webhook separately. The webhook is what grants
  // the plan, so the redirect can easily win the race and land on a dashboard
  // that still says Community. Saying nothing at all was the worst of the
  // options: the buyer had just been charged and got no acknowledgement of it
  // anywhere on the site. So the band says which state we are in, and re-asks a
  // few times while the grant is still on its way.
  var lastAccountIsPaid = false;
  var CAME_FROM_CHECKOUT = isBillingReturn();
  var RETURN_TRIES = 5;
  var RETURN_DELAY_MS = 2000;

  function isBillingReturn() {
    try { return new URLSearchParams(window.location.search).get('billing') === 'return'; }
    catch (e) { return false; }
  }

  // Take the parameter out of the address bar once it has been acted on, so a
  // reload or a shared link does not re-announce a payment.
  function clearBillingParam() {
    try {
      if (!window.history || !window.history.replaceState) return;
      var url = new URL(window.location.href);
      url.searchParams.delete('billing');
      window.history.replaceState({}, '', url.pathname + (url.search || '') + (url.hash || ''));
    } catch (e) { /* address bar is cosmetic; never break the page over it */ }
  }

  // What Mollie says became of the payment the buyer just left, through the
  // admin proxy (GET /api/user/billing/last-payment, relay
  // /v2/billing/last-payment). null when it cannot say: then the band falls
  // back to what the account itself shows.
  function fetchLastPayment() {
    return fetch('/api/user/billing/last-payment', {
      credentials: 'include', headers: { 'Accept': 'application/json' }, cache: 'no-store'
    }).then(function (r) { return r.ok ? r.json() : null; })
      .then(function (j) { return (j && j.payment) || null; })
      .catch(function () { return null; });
  }

  // A payment that did not go through ends in one of three states, and each
  // gets its own words: until 2026-10-05 all three read "being confirmed" and
  // then "you get the plan by itself" (betaaltest 05-10, row 4).
  var NOT_PAID = {
    canceled: {
      kicker: nlEn('Betaling geannuleerd', 'Payment cancelled'),
      lede: nlEn('Je hebt de betaling afgebroken. Er is niets afgeschreven en je plan is niet veranderd.', 'You stopped the payment. Nothing has been charged and your plan has not changed.')
    },
    failed: {
      kicker: nlEn('Betaling mislukt', 'Payment failed'),
      lede: nlEn('De betaling is niet gelukt. Er is niets afgeschreven en je plan is niet veranderd.', 'The payment did not go through. Nothing has been charged and your plan has not changed.')
    },
    expired: {
      kicker: nlEn('Betaling verlopen', 'Payment expired'),
      lede: nlEn('De betaling is niet op tijd afgerond en is verlopen. Er is niets afgeschreven en je plan is niet veranderd.', 'The payment was not completed in time and has expired. Nothing has been charged and your plan has not changed.')
    }
  };

  // "Pay again" presses the same price button again: it leaves the choice
  // where pricing-billing.js picks it up after a sign-in, so there is one way
  // to buy and not two. Business is only sold on the English page.
  function retryButton(band, payment) {
    var btn = band.querySelector('[data-dh="return-retry"]');
    if (!btn) return;
    if (!payment) { btn.style.display = 'none'; return; }
    var href = (nlEn('nl', 'en') === 'en' || payment.plan === 'business') ? '/en/pricing' : '/pricing';
    btn.setAttribute('href', href);
    btn.style.display = '';
    btn.onclick = function () {
      try {
        sessionStorage.setItem('paramant.checkout.intent.v1', JSON.stringify({
          product: payment.product, plan: payment.plan, interval: payment.interval, at: new Date().toISOString()
        }));
      } catch (e) { /* private mode: the pricing page opens and the buyer clicks once more */ }
    };
  }

  function showBillingReturn(tries) {
    var band = document.querySelector('#dh-billing-return');
    if (!band) return;
    fetchLastPayment().then(function (payment) { renderBillingReturn(band, tries, payment); });
  }

  function renderBillingReturn(band, tries, payment) {
    var kicker = band.querySelector('[data-dh="return-kicker"]');
    var lede = band.querySelector('[data-dh="return-lede"]');
    var status = payment && payment.status;
    band.hidden = false;
    retryButton(band, null);
    if (status && NOT_PAID[status]) {
      if (kicker) kicker.textContent = NOT_PAID[status].kicker;
      if (lede) lede.textContent = NOT_PAID[status].lede;
      retryButton(band, payment);
      clearBillingParam();
      return;
    }
    // Paid, or no answer from Mollie and an account that shows a paid plan.
    // A paid payment on an account that does not show it yet is the webhook
    // still on its way: wait for it.
    if (lastAccountIsPaid && (status === 'paid' || !status || status === 'unknown')) {
      if (kicker) kicker.textContent = nlEn('Betaling ontvangen', 'Payment received');
      if (lede) lede.textContent = nlEn('Dank je. Je plan is actief. Wat erbij hoort en tot wanneer het loopt, staat hieronder.', 'Thank you. Your plan is active. What it includes and how long it runs is below.');
      clearBillingParam();
      return;
    }
    if (tries > 0) {
      if (kicker) kicker.textContent = nlEn('Je betaling wordt bevestigd', 'Confirming your payment');
      if (lede) lede.textContent = nlEn('Je bent terug van je bank. We wachten nog op de bevestiging van de betaling. Dat duurt meestal een paar seconden. Deze pagina werkt zichzelf bij.', 'You are back from your bank. We are waiting for the payment to be confirmed. That usually takes a few seconds. This page updates by itself.');
      window.setTimeout(function () { refreshAccount(tries - 1); }, RETURN_DELAY_MS);
      return;
    }
    if (kicker) kicker.textContent = nlEn('Betaling nog niet bevestigd', 'Payment not confirmed yet');
    if (status === 'paid') {
      if (lede) lede.textContent = nlEn('Je betaling is gelukt, maar je plan staat er nog niet. Laad deze pagina over een minuut opnieuw, en mail privacy@paramant.app als het er dan nog niet staat.', 'Your payment went through, but your plan is not showing yet. Reload this page in a minute, and mail privacy@paramant.app if it still has not appeared.');
    } else {
      if (lede) lede.textContent = nlEn('De betaaldienst heeft je betaling nog niet afgerond. Gaat ze alsnog door, dan krijg je het plan vanzelf. Breek je haar af, dan wordt er niets afgeschreven. Laad deze pagina over een minuut opnieuw, en mail privacy@paramant.app als je twijfelt.', 'The payment provider has not finished your payment yet. If it still goes through, the plan is granted by itself. If you stop it, nothing is charged. Reload this page in a minute, and mail privacy@paramant.app if in doubt.');
    }
    clearBillingParam();
  }

  // ── Who is signed in ────────────────────────────────────────────────────────
  var me = null;

  // Two letters for the circle that opens the account: the name the customer
  // gave himself, or else the start of the address. Never a guess at a name.
  function initials(data) {
    var label = data && typeof data.label === 'string' ? data.label.trim() : '';
    if (label && label.indexOf('@') === -1) {
      var parts = label.split(/\s+/).filter(Boolean);
      var two = parts.length > 1 ? parts[0][0] + parts[parts.length - 1][0] : label.slice(0, 2);
      return two.toUpperCase();
    }
    var mail = String((data && data.email) || '').split('@')[0].replace(/[^A-Za-z0-9]/g, '');
    return (mail.slice(0, 2) || '?').toUpperCase();
  }

  // The plan, the term and what was bought. Nothing of it is a block of its own
  // on this screen any more: a band only when something needs doing (a term
  // about to end, a payment just made), and what a paying customer bought one
  // fold down, under "Je plan".
  var planIsFree = true;
  var planName = 'Community';

  function render(data) {
    me = data;
    var email = data.email || '';
    var planId = normalisePlan(data.plan);
    planName = PLAN_NAMES[planId];

    // The unified plan is not the whole answer. A self-serve ParaSign or
    // ParaSend purchase moves only that product's tier, so read those too and
    // let the highest paid one speak for the account.
    var paidTiers = [
      paidProductTier(data.plan_parasign, data.paid_until_parasign),
      paidProductTier(data.plan_parasend, data.paid_until_parasend),
    ].filter(Boolean);
    var topPaid = null;
    for (var pi = 0; pi < paidTiers.length; pi++) {
      if (!topPaid || PRODUCT_LADDER.indexOf(paidTiers[pi]) > PRODUCT_LADDER.indexOf(topPaid)) topPaid = paidTiers[pi];
    }
    var isFree = planId === 'community' && !topPaid;
    if (topPaid && planId === 'community') planName = PRODUCT_NAMES[topPaid] || planName;
    planIsFree = isFree;

    var avatar = document.getElementById('pa-avatar');
    if (avatar) {
      avatar.textContent = initials(data);
      avatar.setAttribute('title', email);
    }
    var who = document.getElementById('pa-acct-who');
    if (who) who.textContent = email;

    // Remembered for the return-from-Mollie band, which has to know whether
    // the webhook has landed yet.
    lastAccountIsPaid = !isFree;

    // A paying account reads what it bought, per product, one fold down.
    var paid = root.querySelector('#dh-plan-paid');
    if (paid) {
      var lines = [];
      var bought = [
        ['parasign', paidProductTier(data.plan_parasign, data.paid_until_parasign)],
        ['parasend', paidProductTier(data.plan_parasend, data.paid_until_parasend)]
      ];
      for (var bi = 0; bi < bought.length; bi++) {
        var key = bought[bi][1];
        if (bought[bi][0] === 'parasend' && key === 'pro' && bought[0][1] === 'business') key = 'pro_business';
        var copy = key && PRODUCT_INCLUDES[bought[bi][0]][key];
        if (copy) lines.push(copy);
      }
      if (!lines.length && planId !== 'community') {
        lines.push(nlEn('Je account staat op het ', 'Your account is on the ') + planName + nlEn('-plan, met de limieten van ', ' plan, with the ') + planName +
                   nlEn(' voor zowel Ondertekenen als Versturen.', ' limits on both ParaSign and ParaSend.'));
      }
      paid.hidden = isFree || !lines.length;
      if (!paid.hidden) {
        txt('paid-name', planName);
        txt('paid-includes', lines.join(' '));
        // "Facturen en verlengen" under a plan with no end date promised a
        // renewal there is nothing to renew for (taal #25).
        var foot = paid.querySelector('[data-dh="paid-foot-lead"]');
        if (foot) {
          var renewable = !window.paPlanTerms || !window.paPlanTerms.hasEnd || window.paPlanTerms.hasEnd(data);
          foot.textContent = renewable
            ? nlEn('Facturen en verlengen vind je onder ', 'Invoices and renewing are under ')
            : nlEn('Facturen vind je onder ', 'Invoices are under ');
        }
      }
    }

    // Outside the paid fold on purpose. An expired term floors every product,
    // which empties that fold, and the one moment a customer most needs the
    // date is the moment the fold that would have carried it disappears.
    renderTerm(root, data);

    // History and audit export: on a paid plan only (js/dashboard-history.js).
    // The audit export is Business and up (the relay answers 403 below it), so
    // Firm reads one sentence instead of two buttons that can only fail.
    var records = root.querySelector('#dh-records');
    if (records) records.hidden = isFree;
    var signTier = paidProductTier(data.plan_parasign, data.paid_until_parasign);
    var canExport = signTier === 'business' || signTier === 'enterprise' || planId === 'business' || planId === 'enterprise';
    var exportRow = root.querySelector('#dh-export-row');
    var exportNote = root.querySelector('#dh-export-note');
    if (exportRow) exportRow.hidden = !canExport;
    if (exportNote) exportNote.hidden = canExport;

    hide(loading);
    hide(errBox);
    show(root);
    root.classList.add('dh-loaded');

    // Not on the way back from the checkout: the pop-up covered the band that
    // says whether the payment went through (acceptatie 3.1.1, betalen).
    if (!keySetupChecked && !CAME_FROM_CHECKOUT) { keySetupChecked = true; checkKeySetup(); }
    loadAll();
  }

  // ── The lists ───────────────────────────────────────────────────────────────
  // undefined = not asked yet, null = asked and failed, [] = asked and empty.
  var L = { documents: undefined, inbox: undefined, sends: undefined, requests: undefined };
  var sendPeople = {};      // send id -> recipients, once fetched
  var tab = 'open';
  var quota = null;

  function getList(url, key) {
    return fetch(url, { credentials: 'include', headers: { 'Accept': 'application/json' }, cache: 'no-store' })
      .then(function (r) {
        if (r.status === 404 && key === 'requests') return { requests: [] };
        if (!r.ok) throw new Error('http_' + r.status);
        return r.json();
      })
      .then(function (body) { return body && Array.isArray(body[key]) ? body[key] : []; })
      .catch(function () { return null; });
  }

  function loadAll() {
    return Promise.all([
      getList('/api/user/documents', 'documents'),
      getList('/api/user/parasign/inbox', 'documents'),
      getList('/api/user/sends', 'sends'),
      getList('/api/user/opvragen', 'requests')
    ]).then(function (got) {
      L.documents = got[0];
      L.inbox = got[1];
      L.sends = got[2];
      L.requests = got[3];
      forgetFinished();
      renderLists();
      openResendFromMail();
      loadOpenSendPeople();
    });
  }

  // Completed, withdrawn or expired: nobody needs the kept signing links or
  // key halves of that request any more, and a finished send has no reminder
  // left (review #573, M4).
  function forgetFinished() {
    (L.documents || []).forEach(function (d) {
      if (!d || !d.id || docState.isOpen(d)) return;
      try {
        localStorage.removeItem('paramant.cosign.links.v1:' + d.id);
        for (var i = localStorage.length - 1; i >= 0; i--) { var k = localStorage.key(i); if (k && k.indexOf('paramant.cosign.share.v1:' + d.id + ':') === 0) localStorage.removeItem(k); }
      } catch (e) { /* storage off */ }
    });
    (L.sends || []).forEach(function (x) {
      if (x && x.id && (x.status === 'expired' || x.outstanding === 0)) { try { localStorage.removeItem('paramant.send.links.v1:' + x.id); } catch (e) { /* storage off */ } }
    });
  }

  // Every card on one timeline, newest first; what waits on the reader first.
  function entries() {
    var out = [];
    (L.inbox || []).forEach(function (x) { out.push({ kind: 'inbox', item: x, at: Date.parse(x.sent_at || '') || 0 }); });
    (L.documents || []).forEach(function (x) { out.push({ kind: 'document', item: x, at: Date.parse(x.created_at || '') || 0 }); });
    (L.sends || []).forEach(function (x) { out.push({ kind: 'send', item: x, at: Date.parse(x.created_at || '') || 0 }); });
    (L.requests || []).forEach(function (x) { out.push({ kind: 'request', item: x, at: Number(x.created_at) || 0 }); });
    out.forEach(function (e) { e.state = docState.stateOf(e.kind, e.item); e.open = docState.isOpenState(e.state); });
    // What waits on the reader comes first, the one that closes soonest on
    // top; the rest newest first.
    out.forEach(function (e) { if (e.kind === 'inbox') e.closes = Date.parse(e.item.signing_closes_at || '') || Infinity; });
    out.sort(function (a, b) {
      if ((a.kind === 'inbox') !== (b.kind === 'inbox')) return a.kind === 'inbox' ? -1 : 1;
      if (a.kind === 'inbox') return a.closes - b.closes;
      return b.at - a.at;
    });
    return out;
  }

  function renderCounts() {
    var t = docState.tally({ documents: L.documents || [], inbox: L.inbox || [], sends: L.sends || [], requests: L.requests || [] });
    var o = document.querySelector('[data-doc-count="open"]');
    var k = document.querySelector('[data-doc-count="klaar"]');
    if (o) o.textContent = String(t.open);
    if (k) k.textContent = String(t.klaar);
    return t;
  }

  function failedLine(key) {
    var what = {
      documents: nlEn('je ondertekenverzoeken', 'your signing requests'),
      inbox: nlEn('wat op je handtekening wacht', 'what waits for your signature'),
      sends: nlEn('je verzendingen', 'your sends'),
      requests: nlEn('je opgevraagde stukken', 'your document requests')
    }[key];
    return '<p class="pa-quiet" role="status">' + nlEn('We konden ', 'We could not load ') + what +
      nlEn(' nu niet laden. Er is niets veranderd. ', ' just now. Nothing has changed. ') +
      '<button type="button" class="pa-btn" data-pa-action="lists-refresh">' + nlEn('Opnieuw proberen', 'Try again') + '</button></p>';
  }

  function setTab(name) {
    tab = name === 'klaar' ? 'klaar' : 'open';
    var bs = document.querySelectorAll('#pa-seg [data-tab]');
    for (var i = 0; i < bs.length; i++) bs[i].setAttribute('aria-selected', bs[i].getAttribute('data-tab') === tab ? 'true' : 'false');
    var po = document.getElementById('pa-open'), pk = document.getElementById('pa-klaar');
    if (po) po.hidden = tab !== 'open';
    if (pk) pk.hidden = tab !== 'klaar';
  }

  function renderLists() {
    var all = entries();
    var t = renderCounts();
    var failed = Object.keys(L).filter(function (k) { return L[k] === null; });
    var nothing = !all.length && !failed.length;
    var seg = document.getElementById('pa-seg');
    var po = document.getElementById('pa-open'), pk = document.getElementById('pa-klaar');
    var empty = document.getElementById('pa-empty');
    if (seg) seg.hidden = nothing;
    if (empty) empty.hidden = !nothing;
    renderPlanLine(nothing);
    if (nothing) { if (po) po.hidden = true; if (pk) pk.hidden = true; return; }
    setTab(tab);

    var open = all.filter(function (e) { return e.open; });
    var done = all.filter(function (e) { return !e.open; });
    var fails = failed.map(failedLine).join('');
    if (po) {
      po.innerHTML = fails + (open.length ? open.map(card).join('')
        : '<p class="pa-quiet">' + nlEn('Er loopt nu niets. Alles staat onder Klaar.', 'Nothing open right now. Everything is under Done.') + '</p>');
    }
    if (pk) {
      pk.innerHTML = fails + (done.length ? '<div class="pa-group">' + done.map(mini).join('') + '</div>'
        : '<p class="pa-quiet">' + nlEn('Wat klaar is, komt hier.', 'What is done shows up here.') + '</p>');
    }
    void t;
  }

  // One line about the plan, and only when there is something to do with it.
  // A new account with nothing yet reads what its plan holds, because that is
  // the start; an account at work reads nothing here unless the month is
  // nearly used up, and that is the band above the tabs (#dh-usage-warn).
  function renderPlanLine(nothing) {
    var line = document.getElementById('pa-plan');
    if (!line) return;
    var caps = quota && quota.caps;
    if (!nothing || !planIsFree) { line.hidden = true; return; }
    // The numbers only when the relay gave them: no guessed allowance.
    var known = caps && typeof caps.signs === 'number' && typeof caps.transfers === 'number';
    line.innerHTML = esc(nlEn('Je zit op Community.', 'You are on Community.') + (known ? ' ' + caps.signs + nlEn(' handtekeningen en ', ' signatures and ') +
      caps.transfers + nlEn(' verzendingen per maand.', ' transfers a month.') : '')) +
      ' <a href="' + LP + '/pricing">' + nlEn('Meer nodig?', 'Need more?') + '</a>';
    line.hidden = false;
    var wrap = document.getElementById('pa-empty');
    if (wrap && line.parentNode !== wrap) wrap.appendChild(line);
  }

  // ── One card ────────────────────────────────────────────────────────────────
  function card(e) {
    if (e.kind === 'inbox') return inboxCard(e.item);
    if (e.kind === 'send') return sendCard(e.item);
    if (e.kind === 'request') return requestCard(e.item);
    return documentCard(e.item, e.state);
  }

  function head(icon, name, sub, pill, pillTone, action, id) {
    var open = action ? '<button type="button" class="pa-ch" data-pa-action="' + action + '" data-document-id="' + esc(id) + '" aria-label="' + esc(nlEn('Details openen van ', 'Open details for ') + name) + '">' : '<div class="pa-ch">';
    var close = action ? '</button>' : '</div>';
    return open + '<span class="pa-ic">' + ico(icon, 18) + '</span>' +
      '<div class="pa-txt"><div class="pa-nm" title="' + esc(name) + '">' + esc(name) + '</div><div class="pa-sub">' + esc(sub) + '</div></div>' +
      (pill ? '<span class="pa-pill' + (pillTone ? ' ' + pillTone : '') + '">' + esc(pill) + '</span>' : '') + close;
  }
  function prog(done, total) {
    var pct = total ? Math.round((done / total) * 100) : 0;
    return '<div class="pa-prog" role="img" aria-label="' + esc(done + nlEn(' van ', ' of ') + total) + '"><i style="width:' + pct + '%"></i></div>';
  }
  // A name or an address in full, never cut off: an address may break after
  // the @ and before a dot, so it wraps where a reader still sees its parts.
  function whoHtml(text) {
    var t = esc(text);
    if (String(text).indexOf('@') === -1) return t;
    return t.replace(/@/g, '@<wbr>').replace(/\./g, '<wbr>.');
  }
  function row(ok, who, meta, extra, full) {
    return '<div class="pa-row' + (ok ? '' : ' miss') + '">' +
      (ok ? '<span class="pa-check ok">' + ico('check', 13) + '</span>' : '<span class="pa-check no"></span>') +
      '<span class="pa-wt"><span class="who" title="' + esc(full || who) + '">' + whoHtml(who) + '</span><span class="meta">' + esc(meta) + '</span></span>' + (extra || '') + '</div>';
  }
  // A recipient by name: the name when the relay knows one, else the address.
  function recipientName(p) {
    var name = String((p && (p.name || p.label)) || '').trim();
    var mail = String((p && p.email) || '').trim();
    if (name && name.toLowerCase() !== mail.toLowerCase()) return name;
    return mail || nlEn('Ontvanger', 'Recipient');
  }
  function recipientFull(p) {
    var name = recipientName(p), mail = String((p && p.email) || '').trim();
    return mail && name !== mail ? name + ' <' + mail + '>' : name;
  }

  // A request a signer refused is "Geweigerd" with the name, not "Geannuleerd":
  // the mail tells the sender "in je documenten zie je wie" (acceptance r2, 2).
  function declinedBy(doc) {
    var parties = doc && Array.isArray(doc.parties) ? doc.parties : [];
    for (var i = 0; i < parties.length; i++) if (parties[i] && parties[i].status === 'declined') return parties[i];
    return null;
  }
  function documentLabel(state, doc) {
    var d = state === 'cancelled' ? declinedBy(doc) : null;
    if (d) return nlEn('Geweigerd door ', 'Declined by ') + (d.label || (nlEn('ondertekenaar ', 'signer ') + (Number(d.index || 0) + 1)));
    return ({
      waiting: nlEn('Wacht op handtekeningen', 'Waiting for signatures'),
      in_progress: nlEn('Bezig', 'In progress'),
      completed: nlEn('Afgerond', 'Completed'),
      cancelled: nlEn('Geannuleerd', 'Cancelled'),
      expired: nlEn('Verlopen', 'Expired')
    })[state] || nlEn('Lopend', 'Open');
  }
  // The account's own place in the list of signers reads "Jij".
  function partyName(p) {
    var label = String((p && p.label) || '').trim();
    if (me && me.email && label.toLowerCase() === String(me.email).toLowerCase()) return nlEn('Jij', 'You');
    return label || (nlEn('Ondertekenaar ', 'Signer ') + (Number((p && p.index) || 0) + 1));
  }

  function documentCard(doc, state) {
    var total = Math.max(0, Number(doc.party_count || 0));
    var signed = Math.max(0, Math.min(total, Number(doc.signed_count || 0)));
    var name = doc.original_filename || nlEn('Ondertekenverzoek', 'Signing request');
    var parties = Array.isArray(doc.parties) ? doc.parties : [];
    var rows = parties.map(function (p) {
      if (p.status === 'signed') return row(true, partyName(p), p.signed_at ? fmtDate(p.signed_at) : nlEn('getekend', 'signed'));
      return row(false, partyName(p), p.status === 'viewed' ? nlEn('geopend, nog niet getekend', 'opened, not signed yet') : nlEn('moet nog tekenen', 'still has to sign'));
    }).join('');
    if (!rows) rows = row(false, signed + nlEn(' van ', ' of ') + total + nlEn(' getekend', ' signed'),
      docState.signUntil(doc) ? nlEn('tekenen kan tot ', 'signing closes ') + fmtDate(docState.signUntil(doc)) : '');
    var id = esc(doc.id || '');
    return '<div class="pa-card dh-document" data-document-id="' + id + '">' +
      head('pen', name, nlEn('Laten tekenen op ', 'Sent for signing on ') + fmtDate(doc.created_at), signed + nlEn(' van ', ' of ') + total, '', 'document-open', doc.id || '') +
      prog(signed, total) + rows +
      '<div class="pa-acts"><button type="button" class="pa-btn" data-pa-action="document-remind" data-document-id="' + id + '">' + ico('bell', 18) + nlEn('Herinnering sturen', 'Send a reminder') + '</button></div>' +
      '<div class="pa-links dh-document-acts" data-document-id="' + id + '">' +
        '<button type="button" data-pa-action="document-open" data-document-id="' + id + '">' + nlEn('Details', 'Details') + '</button>' +
        '<button type="button" data-pa-action="document-withdraw-ask" data-document-id="' + id + '">' + nlEn('Intrekken', 'Withdraw') + '</button>' +
      '</div>' +
      '<p class="pa-say" role="status" data-say="' + id + '" hidden></p>' +
    '</div>';
  }

  // The list route names it total; an older shape said count.
  function sendTotal(s) { return Number(s.total != null ? s.total : s.count) || 0; }
  function sendWaitingLine(s) {
    if (s.status === 'expired') return nlEn('Deze verzending is verlopen. Het bestand is weg.', 'This send has expired. The file is gone.');
    if (s.outstanding === 0) return nlEn('Iedereen heeft het opgehaald.', 'Everyone has collected it.');
    if (s.outstanding === 1) return nlEn('Eén persoon heeft het nog niet opgehaald.', 'One person has not collected yet.');
    return s.outstanding + nlEn(' mensen hebben het nog niet opgehaald.', ' people have not collected yet.');
  }
  var sendAll = {};         // send id -> true when the reader asked for everyone
  function sendName(s) {
    s = { total: sendTotal(s), filename: s.filename };
    var wie = s.total === 1 ? nlEn('1 ontvanger', '1 recipient') : (s.total || 0) + nlEn(' ontvangers', ' recipients');
    return s.filename || (nlEn('Bestand aan ', 'File to ') + wie);
  }
  function sendCard(s) {
    var id = esc(s.id || '');
    var people = sendPeople[s.id];
    var rows;
    if (people === undefined) rows = '<div class="pa-row"><span class="meta" style="margin-left:0">' + nlEn('Even kijken wie het heeft opgehaald...', 'Checking who has collected it...') + '</span></div>';
    else if (people === null) rows = '<div class="pa-row"><span class="meta" style="margin-left:0">' + nlEn('We konden niet zien wie het heeft opgehaald.', 'We could not see who has collected it.') + '</span></div>';
    else {
      // A send to thirty people is thirty rows. Who has not collected is what
      // the sender came for, so those stay; the rest folds into one line.
      var many = people.length > 5 && !sendAll[s.id];
      var shown = many ? people.filter(function (p) { return p.status === 'waiting'; }) : people;
      rows = shown.map(personRow).join('') + (many
        ? '<div class="pa-row"><button type="button" class="x" style="margin:0" data-pa-action="send-open" data-send-id="' + id + '">' +
          nlEn('Toon iedereen (', 'Show everyone (') + people.length + ')</button></div>' : '');
    }
    function personRow(p) {
      var nm = recipientName(p), full = recipientFull(p);
      if (p.status === 'collected') return row(true, nm, p.picked_up_at ? fmtDate(p.picked_up_at) : nlEn('opgehaald', 'collected'), '', full);
      if (p.status === 'revoked') return row(false, nm, nlEn('ingetrokken', 'withdrawn'), '', full);
      return row(false, nm, nlEn('nog niet opgehaald', 'not collected yet'),
        '<button type="button" class="x" data-pa-action="send-revoke" data-send-id="' + id + '" data-email="' + esc(p.email) + '" aria-label="' + esc(nlEn('Intrekken voor ', 'Withdraw for ') + full) + '">' + nlEn('Intrekken', 'Withdraw') + '</button>', full);
    }
    return '<div class="pa-card dh-send-row" data-send-id="' + id + '">' +
      head('send', sendName(s), nlEn('Verstuurd ', 'Sent ') + paramantDate.moment(s.created_at), (s.collected || 0) + nlEn(' van ', ' of ') + sendTotal(s)) +
      prog(s.collected || 0, sendTotal(s)) + '<p class="pa-say dh-send-next">' + esc(sendWaitingLine(s)) + '</p>' +
      '<div data-send-people="' + id + '">' + rows + '</div>' +
      '<div class="pa-acts"><button type="button" class="pa-btn" data-pa-action="send-remind" data-send-id="' + id + '"' +
        nlEn(' title="Stuurt een herinnering met dezelfde link als de eerste mail. De link verandert niet."', ' title="Sends a reminder with the same link as the first mail. The link does not change."') + '>' +
        ico('bell', 18) + nlEn('Herinnering sturen', 'Send a reminder') + '</button></div>' +
      '<p class="pa-say" role="status" data-say="' + id + '" hidden></p>' +
    '</div>';
  }

  function requestCard(r) {
    var id = esc(r.id || '');
    var items = Array.isArray(r.items) ? r.items : [];
    var rows = items.map(function (it) {
      return it.count ? row(true, it.label, it.count > 1 ? it.count + nlEn(' bestanden', ' files') : nlEn('binnen', 'in'))
        : row(false, it.label, nlEn('ontbreekt', 'missing'));
    }).join('');
    var canRemind = !!r.has_email && Number(r.reminders || 0) < Number(r.max_reminders || 0);
    return '<div class="pa-card" data-request-id="' + id + '">' +
      head('inbox', r.client_name || nlEn('Klant', 'Client'), nlEn('Opgevraagd op ', 'Requested on ') + fmtDate(r.created_at), (r.received || 0) + nlEn(' van ', ' of ') + (r.total || 0)) +
      prog(r.received || 0, r.total || 0) + rows +
      '<div class="pa-acts"><button type="button" class="pa-btn" data-pa-action="request-remind" data-request-id="' + id + '"' + (canRemind ? '' : ' disabled') +
        (r.has_email ? '' : ' title="' + esc(nlEn('Geen e-mailadres opgegeven. Deel de link zelf opnieuw.', 'No email address given. Share the link again yourself.')) + '"') + '>' +
        ico('bell', 18) + nlEn('Herinnering sturen', 'Send a reminder') + '</button></div>' +
      '<div class="pa-links"><a href="' + LP + '/opvragen">' + nlEn('Openen en downloaden in Opvragen', 'Open and download in Requests') + '</a></div>' +
      '<p class="pa-say" role="status" data-say="' + id + '" hidden></p>' +
    '</div>';
  }

  // What was sent TO this account. The route hands back a name, a sender and
  // two dates and deliberately never the per-party invite token: that lives
  // only in the invitation mail, which keeps this page from becoming a second
  // way into somebody's document. So the one control asks for that mail again.
  function inboxCard(doc) {
    var name = doc.document || nlEn('Ondertekenverzoek', 'Signing request');
    var from = String(doc.sender || '').trim();
    var bits = [];
    if (from) bits.push(nlEn('Van ', 'From ') + from);
    if (doc.sent_at) bits.push((from ? nlEn('verstuurd ', 'sent ') : nlEn('Verstuurd ', 'Sent ')) + fmtDate(doc.sent_at));
    if (doc.signing_closes_at) bits.push(nlEn('tekenen kan tot ', 'signing closes ') + fmtDate(doc.signing_closes_at));
    var sub = bits.join(' · ');
    sub = sub.charAt(0).toUpperCase() + sub.slice(1);
    return '<div class="pa-card dh-inbox-row">' +
      head('pen', name, sub, nlEn('Wacht op jou', 'Waiting for you')) +
      '<div class="pa-acts"><button class="pa-btn dh-inbox-act" type="button" data-pa-action="inbox-resend" data-document-id="' + esc(doc.id || '') + '">' +
        ico('mail', 18) + nlEn('Stuur mij de link opnieuw', 'Send me the link again') + '</button></div>' +
      '<p class="pa-say">' + nlEn('Je opent het document via de persoonlijke link in de uitnodiging die je per mail kreeg.', 'You open the document from the personal link in the invitation you got by mail.') + '</p>' +
    '</div>';
  }

  // ── Klaar: one line each ────────────────────────────────────────────────────
  function mini(e) {
    var x = e.item;
    var name, sub, end = '', stopped = e.state === 'cancelled' || e.state === 'expired';
    var opener = '';
    if (e.kind === 'document') {
      name = x.original_filename || nlEn('Ondertekenverzoek', 'Signing request');
      sub = e.state === 'completed' ? nlEn('Getekend op ', 'Signed on ') + fmtDate(x.completed_at || x.created_at)
        : e.state === 'expired' ? nlEn('Verlopen op ', 'Expired on ') + fmtDate(docState.signUntil(x))
        : documentLabel(e.state, x) + (x.voided_at ? ' · ' + fmtDate(x.voided_at) : '');
      opener = 'data-pa-action="document-open" data-document-id="' + esc(x.id || '') + '"';
      if (e.state === 'completed') end = '<a class="pa-dl" href="/api/user/documents/' + encodeURIComponent(x.id) + '/receipt" download aria-label="' + esc(nlEn('Bewijs downloaden van ', 'Download proof for ') + name) + '" title="' + nlEn('Bewijs downloaden', 'Download proof') + '">' + ico('down', 20) + '</a>';
    } else if (e.kind === 'send') {
      name = x.filename || (sendTotal(x) ? sendName(x) : nlEn('Verzending', 'Send'));
      sub = e.state === 'completed' ? nlEn('Iedereen heeft het opgehaald', 'Everyone has collected it') + (x.created_at ? ' · ' + fmtDate(x.created_at) : '')
        : nlEn('Verlopen. Het bestand is weg.', 'Expired. The file is gone.');
    } else {
      name = x.client_name || nlEn('Klant', 'Client');
      sub = e.state === 'completed' ? nlEn('Alles binnen', 'Everything is in') + ' · ' + fmtDate(x.created_at)
        : e.state === 'cancelled' ? nlEn('Gesloten', 'Closed') : nlEn('Verlopen', 'Expired');
      end = '<a class="pa-dl" href="' + LP + '/opvragen" aria-label="' + esc(nlEn('Openen in Opvragen: ', 'Open in Requests: ') + name) + '">' + ico('chev', 20) + '</a>';
    }
    var inner = '<div class="pa-nm' + (stopped ? ' stop' : '') + '" title="' + esc(name) + '">' + esc(name) + '</div><div class="pa-sub">' + esc(sub) + '</div>';
    var body = opener ? '<button type="button" class="pa-open" ' + opener + '>' + inner + '</button>' : '<div class="pa-open">' + inner + '</div>';
    return '<div class="pa-mini' + (e.kind === 'document' ? ' dh-document' : '') + '"' + (e.kind === 'document' ? ' data-document-id="' + esc(x.id || '') + '"' : '') + '>' + body + end + '</div>';
  }

  // The people behind each OPEN send, fetched after the list: a finished send
  // needs no names on a card, and a list of twelve sends would otherwise pull
  // twelve recipient lists nobody asked for.
  function loadOpenSendPeople() {
    (L.sends || []).filter(function (s) { return s && s.id && docState.isOpenState(docState.sendState(s)); })
      .slice(0, 12).forEach(function (s) { loadSendPeople(s.id); });
  }
  function loadSendPeople(id) {
    return fetch('/api/user/sends/' + encodeURIComponent(id), {
      credentials: 'include', headers: { 'Accept': 'application/json' }, cache: 'no-store'
    }).then(function (r) { if (!r.ok) throw new Error('http_' + r.status); return r.json(); })
      .then(function (body) { sendPeople[id] = body && Array.isArray(body.recipients) ? body.recipients : []; })
      .catch(function () { sendPeople[id] = null; })
      .then(function () { redrawSend(id); });
  }
  function redrawSend(id) {
    var s = null;
    (L.sends || []).forEach(function (x) { if (x && x.id === id) s = x; });
    var el = document.querySelector('.dh-send-row[data-send-id="' + cssEscape(id) + '"]');
    if (!s || !el) return;
    var keep = el.querySelector('.pa-say');
    var wrap = document.createElement('div');
    wrap.innerHTML = sendCard(s);
    var fresh = wrap.firstChild;
    if (keep && !keep.hidden) {
      var say = fresh.querySelector('.pa-say');
      if (say) { say.className = keep.className; say.textContent = keep.textContent; say.hidden = false; }
    }
    el.parentNode.replaceChild(fresh, el);
  }

  function say(id, text, tone) {
    var el = document.querySelector('[data-say="' + cssEscape(id) + '"]');
    if (!el) return;
    el.className = 'pa-say' + (tone ? ' ' + tone : '');
    el.textContent = text;
    el.hidden = !text;
  }

  // ── Files sent by name: remind and withdraw ────────────────────────────────
  // The recipient's link of a send by name, kept in THIS browser by
  // /parashare (parashare.page.js rememberSendLinks). A reminder is built from
  // it the way the invitation was, so it carries the same working link. The
  // relay never kept it; without it here there is no honest reminder to send.
  function sealMod() { return import('/js/account-seal.js?v=1'); }
  function storedSendTokens(id) {
    return sealMod().then(function (m) { return m.sealGet('paramant.send.links.v1:' + id); }).then(function (rec) {
      var out = {};
      (rec && Array.isArray(rec.links) ? rec.links : []).forEach(function (l) {
        if (l && typeof l.t === 'string' && l.t) out[String(l.e || '').trim().toLowerCase()] = l.t;
      });
      return out;
    }).catch(function () { return {}; });
  }
  var LINK_NOT_HERE_NL = 'De link van deze ontvanger staat niet in deze browser. Open het verzoek in de browser waarmee je het verstuurde, of trek het in en stuur opnieuw.';
  var LINK_NOT_HERE_EN = 'This recipient\'s link is not in this browser. Open the request in the browser you sent it from, or withdraw it and send it again.';

  function sendPost(pad, id, payload) {
    return fetch('/api/user/sends/' + encodeURIComponent(id) + '/' + pad, {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify(payload)
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (b) {
        if (!r.ok) throw new Error(b.error || ('http_' + r.status));
        return b;
      });
    });
  }
  function sendFailText(code) {
    return code === 'already_collected' ? nlEn('Het is al opgehaald.', 'They already collected it.')
      : code === 'reminder_limit' ? nlEn('Er zijn al drie herinneringen gestuurd. Verstuur het bestand liever opnieuw.', 'They have had three reminders. Send the file again instead.')
      : (code === 'link_not_in_browser' || code === 'wrong_link') ? nlEn(LINK_NOT_HERE_NL, LINK_NOT_HERE_EN)
      : code === 'reminder_not_sent' ? nlEn('De mail is niet verstuurd. Er is niets veranderd. Probeer het over een minuut opnieuw.', 'The email did not go out. Nothing changed; try again in a minute.')
      : nlEn('Dat is niet gelukt. Er is niets veranderd.', 'That did not go through. Nothing changed.');
  }

  // One press reminds everyone who has not collected yet, each with the link
  // of their own first mail.
  function remindSend(id, button) {
    var people = sendPeople[id];
    var waiting = (people || []).filter(function (p) { return p && p.status === 'waiting'; });
    if (!waiting.length) { say(id, nlEn('Iedereen heeft het al opgehaald of is ingetrokken.', 'Everyone has collected it or was withdrawn.')); return; }
    if (button) button.disabled = true;
    say(id, nlEn('Bezig...', 'Working...'));
    storedSendTokens(id).then(function (tokens) {
      var sent = [], failed = [];
      var chain = Promise.resolve();
      waiting.forEach(function (p) {
        chain = chain.then(function () {
          var token = tokens[String(p.email || '').trim().toLowerCase()];
          if (!token) { failed.push('link_not_in_browser'); return; }
          return sendPost('reinvite', id, { email: p.email, token: token })
            .then(function () { sent.push(p.email); }, function (err) { failed.push(err.message); });
        });
      });
      return chain.then(function () {
        if (button) button.disabled = false;
        if (sent.length) {
          say(id, nlEn('Herinnering verstuurd naar ', 'Reminder sent to ') + sent.join(', ') +
            nlEn(', met dezelfde link als de eerste mail. Die link opent het bestand ook op een ander apparaat.', ', with the same link as the first mail. That link opens the file on another device too.') +
            (failed.length ? ' ' + sendFailText(failed[0]) : ''), 'ok');
        } else {
          say(id, sendFailText(failed[0]), 'err');
        }
      });
    });
  }

  // Withdrawing is one way, so it asks first, and the safe answer takes the
  // place the Withdraw button just had. Same rule as a signing request.
  function askSendRevoke(id, email, button) {
    var host = button && button.closest ? button.closest('.pa-row') : null;
    if (!host) return;
    var ask = document.createElement('div');
    ask.className = 'pa-ask';
    ask.innerHTML = '<span>' + nlEn('<strong>', 'Withdraw <strong>') + esc(email) + nlEn('</strong> intrekken? ', '</strong>? ') +
      nlEn('Die link werkt dan niet meer. De rest van de groep houdt de eigen link.', 'Their link stops working. The rest of the group keeps theirs.') + '</span>' +
      '<button type="button" class="pa-btn" data-pa-action="send-revoke-no" data-send-id="' + esc(id) + '">' + nlEn('Laten staan', 'Keep it') + '</button>' +
      '<button type="button" class="pa-btn danger" data-pa-action="send-revoke-do" data-send-id="' + esc(id) + '" data-email="' + esc(email) + '">' + nlEn('Ja, intrekken', 'Yes, withdraw') + '</button>';
    host.parentNode.replaceChild(ask, host);
    var safe = ask.querySelector('[data-pa-action="send-revoke-no"]');
    if (safe && safe.focus) safe.focus();
  }
  function revokeSend(id, email, button) {
    if (button) button.disabled = true;
    sendPost('revoke', id, { email: email }).then(function () {
      say(id, nlEn('Ingetrokken. Die link werkt niet meer.', 'Withdrawn. Their link no longer works.'), 'ok');
      return refreshSends(id);
    }, function (err) {
      say(id, sendFailText(err.message), 'err');
      redrawSend(id);
    });
  }
  function refreshSends(id) {
    return getList('/api/user/sends', 'sends').then(function (list) {
      if (list) L.sends = list;
      renderCounts();
      return loadSendPeople(id);
    });
  }

  // ── Signing requests: remind, withdraw, detail ─────────────────────────────
  function documentById(id) {
    var list = L.documents || [];
    for (var i = 0; i < list.length; i++) if (list[i].id === id) return list[i];
    return null;
  }

  // The full signing link per signer (acceptatie r3, A3), sealed under the
  // account key (js/account-seal.js, review #573 M4). The link with the key
  // half (#ks=) was made in the sender's browser and is kept only there
  // (sign-flow.js rememberSignerLinks), never on a server.
  function storedSignerLinks(id) {
    return sealMod().then(function (m) { return m.sealGet('paramant.cosign.links.v1:' + id); }).then(function (rec) {
      if (!rec || !Array.isArray(rec.links)) return null;
      return rec.links.filter(function (l) { return l && typeof l.url === 'string' && /^https?:\/\/[^#]+\/co-sign\?[^#]*#ks=v1\.[A-Za-z0-9_-]{43}$/.test(l.url); });
    }).catch(function () { return null; });
  }
  var SIGNER_LINKS_NOT_HERE_NL = 'De volledige ondertekenlinks staan niet in deze browser. Open het verzoek in de browser waarmee je het verstuurde, of trek het in en stuur opnieuw.';
  var SIGNER_LINKS_NOT_HERE_EN = 'The full signing links are not in this browser. Open the request in the browser you sent it from, or withdraw it and send it again.';

  function linkEmail(link) {
    return link ? String(link.e || (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(link.label || '') ? link.label : '')).trim().toLowerCase() : '';
  }

  // The resend, built in THIS browser exactly like the first invitation
  // (sign-flow.js deliverInviteEmails): the stored link with half A of the
  // key ('#ks='), posted to the same route, which checks the address against
  // the party and refuses any other fragment. Half B stays on the relay; no
  // whole key reaches a server and nothing extra is stored.
  function postInvitations(id, links) {
    return fetch('/api/user/envelopes/' + encodeURIComponent(id) + '/invitations', {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      // reminder: true keeps this body apart from the first invitation's, so
      // the double-click guard on the route does not swallow it. No lang: the
      // first invitation went out Dutch with the English underneath, and the
      // signer gets the same mail again, whatever language the sender reads.
      body: JSON.stringify({ invitations: links.map(function (link) {
        var email = linkEmail(link);
        return { party_index: Number(link.i), email: email, label: link.label && link.label !== email ? link.label : '', invite_url: link.url };
      }), reminder: true })
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (b) { return { ok: r.status === 200 && b && b.ok !== false, b: b }; });
    });
  }
  function inviteFailText(x) {
    return x && x.b && x.b.error === 'rate_limited'
      ? nlEn('Even te vaak geprobeerd. Probeer het over een uur opnieuw.', 'Tried too often. Try again in an hour.')
      : nlEn('De uitnodiging is niet verstuurd. Probeer het over een minuut opnieuw.', 'The invitation did not go out. Try again in a minute.');
  }

  // The card's button: everyone who has not signed gets their own invitation
  // again, with the same link as the first time.
  function remindDocument(id, button) {
    var doc = documentById(id);
    if (!doc) return;
    if (button) button.disabled = true;
    say(id, nlEn('Bezig...', 'Working...'));
    var signedIdx = {};
    (Array.isArray(doc.parties) ? doc.parties : []).forEach(function (p) { if (p && p.status === 'signed') signedIdx[Number(p.index)] = true; });
    storedSignerLinks(id).then(function (links) {
      var todo = (links || []).filter(function (l) { return !signedIdx[Number(l.i)] && linkEmail(l); });
      if (!todo.length) { if (button) button.disabled = false; say(id, nlEn(SIGNER_LINKS_NOT_HERE_NL, SIGNER_LINKS_NOT_HERE_EN), 'err'); return; }
      return postInvitations(id, todo).then(function (x) {
        if (button) button.disabled = false;
        if (x.ok) say(id, nlEn('Herinnering verstuurd naar ', 'Reminder sent to ') + todo.map(linkEmail).join(', ') + nlEn('. Met dezelfde link als de eerste uitnodiging; die opent het document ook op een ander apparaat.', '. With the same link as the first invitation; it opens the document on another device too.'), 'ok');
        else say(id, inviteFailText(x), 'err');
      });
    }).catch(function () {
      if (button) button.disabled = false;
      say(id, inviteFailText(null), 'err');
    });
  }

  // One signer, from the detail.
  function resendSignerInvite(id, partyIndex, button) {
    var out = document.querySelector('[data-resend-say="' + cssEscape(String(partyIndex)) + '"]');
    function tell(text, tone) { if (out) { out.className = 'pa-say ' + (tone || ''); out.textContent = text; } }
    if (button) button.disabled = true;
    tell(nlEn('Bezig...', 'Working...'));
    storedSignerLinks(id).then(function (links) {
      var link = null;
      (links || []).forEach(function (l) { if (Number(l.i) === partyIndex) link = l; });
      var email = linkEmail(link);
      if (!link || !email) { if (button) button.disabled = false; tell(nlEn(SIGNER_LINKS_NOT_HERE_NL, SIGNER_LINKS_NOT_HERE_EN), 'err'); return; }
      return postInvitations(id, [link]).then(function (x) {
        if (x.ok) tell(nlEn('Verstuurd naar ', 'Sent to ') + email + nlEn('. Met dezelfde link als de eerste uitnodiging; die opent het document ook op een ander apparaat.', '. With the same link as the first invitation; it opens the document on another device too.'), 'ok');
        else { if (button) button.disabled = false; tell(inviteFailText(x), 'err'); }
      });
    }).catch(function () {
      if (button) button.disabled = false;
      tell(inviteFailText(null), 'err');
    });
  }

  // Asking before a one-way action, in place, without a browser box. The safe
  // answer takes the place the Withdraw button just had, so a second click in
  // the same spot cannot finish it; the document is named, because a row
  // clicked by accident looks exactly like the row next to it.
  function askWithdraw(id) {
    var host = document.querySelector('.dh-document-acts[data-document-id="' + cssEscape(id) + '"]');
    if (!host) return;
    var doc = documentById(id);
    var name = (doc && doc.original_filename) || nlEn('dit verzoek', 'this request');
    host.className = 'pa-ask dh-document-acts';
    host.innerHTML = '<span>' + nlEn('<strong>', 'Withdraw <strong>') + esc(name) + nlEn('</strong> intrekken? Handtekeningen die al gezet zijn, blijven vastgelegd. Niemand kan er nog een toevoegen.', '</strong>? Signatures already given stay in the record, nobody can add another.') + '</span>' +
      '<button type="button" class="pa-btn" data-pa-action="document-withdraw-no" data-document-id="' + esc(id) + '">' + nlEn('Open laten', 'Keep it open') + '</button>' +
      '<button type="button" class="pa-btn danger" data-pa-action="document-withdraw-do" data-document-id="' + esc(id) + '">' + nlEn('Ja, intrekken', 'Yes, withdraw') + '</button>';
    var safe = host.querySelector('[data-pa-action="document-withdraw-no"]');
    if (safe && safe.focus) safe.focus();
  }
  function cancelWithdrawAsk() { renderLists(); }

  // `asked` is true when the question was already put on the card; from the
  // detail the browser asks once more, as it always did there.
  function cancelDocument(id, button, asked) {
    var doc = documentById(id);
    if (!doc) return;
    if (!asked && !confirm(nlEn('Dit ondertekenverzoek annuleren? Daarna kan niemand nog tekenen.', 'Cancel this signing request? Nobody will be able to add another signature.'))) return;
    if (button) button.disabled = true;
    var message = document.getElementById('dh-doc-message');
    if (message) message.textContent = nlEn('Verzoek wordt geannuleerd...', 'Cancelling request...');
    say(id, nlEn('Bezig met intrekken...', 'Withdrawing...'));
    fetch('/api/user/documents/' + encodeURIComponent(id) + '/cancel', {
      method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: '{}'
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (body) {
        if (!r.ok) throw new Error(body.error || ('http_' + r.status));
        return body;
      });
    }).then(function () {
      doc.status = 'void';
      doc.voided_at = doc.voided_at || new Date().toISOString();
      renderLists();
      // The request moved to Klaar, so the answer goes where the reader is:
      // the detail, opened again with the new state in it.
      openDocumentDialog(id);
      var m = document.getElementById('dh-doc-message');
      if (m) m.textContent = nlEn('Ingetrokken. Niemand kan nog tekenen.', 'Withdrawn. Nobody can add a signature.');
    }).catch(function (err) {
      if (button) button.disabled = false;
      var uitleg = err.message === 'already_complete'
        ? nlEn('Iedereen had al getekend. Er is niets ingetrokken.', 'Everyone had already signed. Nothing was withdrawn.')
        : nlEn('Intrekken is niet gelukt. Het verzoek is niet veranderd.', 'Withdrawing did not go through. The request is unchanged.');
      if (message) message.textContent = uitleg;
      renderLists();
      say(id, uitleg, 'err');
    });
  }

  var documentDialogReturnFocus = null;
  var signerLinksReady = null;
  function closeDocumentDialog() {
    var dialog = document.getElementById('dh-document-dialog');
    if (dialog) dialog.hidden = true;
    if (documentDialogReturnFocus && typeof documentDialogReturnFocus.focus === 'function') documentDialogReturnFocus.focus();
    documentDialogReturnFocus = null;
  }

  function openDocumentDialog(id) {
    var doc = documentById(id);
    var dialog = document.getElementById('dh-document-dialog');
    var title = document.getElementById('dh-document-dialog-title');
    var body = document.getElementById('dh-document-dialog-body');
    if (!doc || !dialog || !body || !title) return;
    if (dialog.hidden) documentDialogReturnFocus = document.activeElement;
    var state = docState.state(doc);
    var total = Math.max(0, Number(doc.party_count || 0));
    var signed = Math.max(0, Math.min(total, Number(doc.signed_count || 0)));
    title.textContent = doc.original_filename || nlEn('Ondertekenverzoek', 'Signing request');
    var parties = Array.isArray(doc.parties) ? doc.parties : [];
    var partyText = parties.length ? parties.map(function (p) {
      return esc(partyName(p)) + ': ' + esc(p.status === 'signed' ? nlEn('getekend', 'signed') : p.status === 'declined' ? nlEn('geweigerd', 'declined') : p.status === 'viewed' ? nlEn('geopend', 'opened') : nlEn('wacht', 'waiting'));
    }).join('<br>') : signed + nlEn(' van ', ' of ') + total + nlEn(' getekend', ' signed');
    var help = state === 'completed'
      ? nlEn('Wij bewaren het bewijs, geen leesbare kopie van je document. Je browser maakt de pdf met alle handtekeningen. Op het apparaat waarmee je het verzoek verstuurde, opent die pdf meteen. Op een ander apparaat kies je eerst je originele bestand. Later controleer je de handtekeningen met het .psign-bewijs en de complete pdf (het origineel zit daarin), of met het originele document.', 'The relay keeps the cryptographic proof, not a plaintext copy of your document. This browser builds the complete PDF with every signature: on the device you sent from it opens straight away, elsewhere you choose your original file. To verify later, use the .psign proof with the complete PDF (the original is embedded in it) or the original document.')
      : state === 'cancelled' && declinedBy(doc)
        ? nlEn('Een ondertekenaar heeft geweigerd te tekenen. Daarmee is dit verzoek gestopt; niemand kan er nog op tekenen. Wil je het opnieuw proberen, stuur dan een nieuw verzoek.', 'A signer declined to sign, so this request has stopped and nobody can sign it any more. To try again, send a new request.')
      : state === 'expired'
        ? nlEn('Dit verzoek is verlopen. Niemand kan er nog op tekenen; gezette handtekeningen blijven in het auditlog. Stuur zo nodig een nieuw verzoek.', 'This request has expired. Nobody can sign it any more; signatures already given stay in the audit record. Send a new request if you still need one.')
      : state === 'cancelled'
        ? nlEn('Dit verzoek is gesloten. Gezette handtekeningen blijven in het auditlog, maar niemand kan nog tekenen.', 'This request is closed. Existing signatures remain in the audit record, but nobody can add another signature.')
        : nlEn('Dit verzoek loopt nog. Paramant bewaart het afgeleverde document versleuteld. Het leesbare document en de sleutel zijn via dit overzicht niet terug te halen.', 'This request is still open. Paramant stores the delivered document encrypted. The plaintext document and its key are not recoverable from the relay dashboard.');
    var actions = '';
    // The complete PDF next to the proof: the result page builds it in this
    // browser from the encrypted document (acceptance test 2026-10-04).
    if (state === 'completed' && parties.length) actions += '<a class="pa-btn primary" href="' + LP + '/co-sign?owner=' + encodeURIComponent(doc.id) + nlEn('">Complete pdf openen</a>', '">Open the complete PDF</a>');
    if (state === 'completed') actions += '<a class="pa-btn" href="/api/user/documents/' + encodeURIComponent(doc.id) + nlEn('/receipt" download>.psign-bewijs downloaden</a>', '/receipt" download>Download .psign proof</a>');
    if (state === 'waiting' || state === 'in_progress') actions += '<button class="pa-btn danger" type="button" data-pa-action="document-cancel" data-document-id="' + esc(doc.id) + nlEn('">Verzoek annuleren</button>', '">Cancel request</button>');
    actions += '<a class="pa-btn" href="' + LP + '/verify">' + nlEn('Een document controleren', 'Verify a document') + '</a>';
    body.innerHTML = '<dl class="pa-kv">' +
      '<dt>Status</dt><dd>' + esc(documentLabel(state, doc)) + '</dd>' +
      nlEn('<dt>Kenmerk</dt><dd>', '<dt>Reference</dt><dd>') + esc(doc.id || '') + '</dd>' +
      nlEn('<dt>Gemaakt</dt><dd>', '<dt>Created</dt><dd>') + esc(fmtDate(doc.created_at)) + '</dd>' +
      ((state === 'completed' || state === 'cancelled') ? '' :
        nlEn('<dt>Tekenen kan tot</dt><dd>', '<dt>Signing closes</dt><dd>') + esc(fmtDate(docState.signUntil(doc))) + '</dd>') +
      nlEn('<dt>Ondertekenaars</dt><dd>', '<dt>Signers</dt><dd>') + partyText + '</dd></dl>' +
      '<p class="pa-help">' + esc(help) + '</p>' +
      ((state === 'waiting' || state === 'in_progress') ? signerLinksHtml(doc) : '') +
      '<div class="pa-dialog-actions">' + actions + '</div><p class="pa-say" id="dh-doc-message" aria-live="polite"></p>';
    dialog.hidden = false;
    var close = dialog.querySelector('[data-pa-action="document-close"]');
    if (close) close.focus();
  }

  function signerLinksHtml(doc) {
    signerLinksReady = storedSignerLinks(doc.id).then(function (links) {
      var host = document.querySelector('[data-signer-links="' + cssEscape(doc.id) + '"]');
      if (host) host.innerHTML = signerLinksInner(doc, links);
    });
    return '<div data-signer-links="' + esc(doc.id) + '"></div>';
  }
  function signerLinksInner(doc, links) {
    var headTxt = '<p class="pa-sub">' + nlEn('Uitnodigingen', 'Invitations') + '</p>';
    if (!links || !links.length) return headTxt + '<p class="pa-help">' + esc(nlEn(SIGNER_LINKS_NOT_HERE_NL, SIGNER_LINKS_NOT_HERE_EN)) + '</p>';
    var signedIdx = {};
    (Array.isArray(doc.parties) ? doc.parties : []).forEach(function (p) { if (p && p.status === 'signed') signedIdx[Number(p.index)] = true; });
    return headTxt + links.filter(function (l) { return !signedIdx[Number(l.i)]; }).map(function (l) {
      var who = l.label || (nlEn('Ondertekenaar ', 'Signer ') + (Number(l.i || 0) + 1));
      return '<div class="pa-linkrow" data-party-row="' + esc(String(Number(l.i))) + '"><span>' + esc(who) + '</span> ' +
        '<button type="button" class="pa-btn" data-pa-action="document-resend-invite" data-document-id="' + esc(doc.id) + '" data-party="' + esc(String(Number(l.i))) + '">' + nlEn('Uitnodiging opnieuw sturen', 'Send the invitation again') + '</button> ' +
        '<button type="button" class="pa-btn" data-pa-action="document-copy-link" data-link="' + esc(l.url) + '">' + nlEn('Link kopiëren', 'Copy link') + '</button>' +
        '<span class="pa-say" role="status" data-resend-say="' + esc(String(Number(l.i))) + '"></span></div>';
    }).join('') + '<p class="pa-help">' + esc(nlEn('De uitnodiging gaat opnieuw naar het uitgenodigde adres, met dezelfde link als de eerste keer. Die link opent het document op elk apparaat, maar alleen voor wie met dat e-mailadres inlogt.', 'The invitation goes to the invited address again, with the same link as the first time. That link opens the document on any device, but only for whoever signs in with that email address.')) + '</p>';
  }

  // The button in "Een ondertekenaar vraagt de link opnieuw" (relay.js
  // notifySenderLinkRequested) lands here: /dashboard?herzend=<id>&p=<i> opens
  // that request with the resend button of that signer in focus. One click,
  // never automatic: a link in a mail must not send mail by itself.
  function openResendFromMail() {
    var q;
    try { q = new URLSearchParams(location.search); } catch (e) { return; }
    var id = q.get('herzend');
    if (!id || !/^[A-Za-z0-9_-]{20,64}$/.test(id) || !documentById(id)) return;
    var p = Number(q.get('p'));
    openDocumentDialog(id);
    try { history.replaceState(null, '', location.pathname); } catch (e) { /* keep the query */ }
    (signerLinksReady || Promise.resolve()).then(function () {
      var btn = document.querySelector('[data-pa-action="document-resend-invite"][data-party="' + cssEscape(String(p)) + '"]');
      var out = document.querySelector('[data-resend-say="' + cssEscape(String(p)) + '"]');
      if (btn) {
        if (out) out.textContent = nlEn('Deze ondertekenaar vroeg om de uitnodiging. Klik op Uitnodiging opnieuw sturen.', 'This signer asked for the invitation. Click Send the invitation again.');
        btn.focus();
      }
    });
  }

  // ── Waiting for your signature ─────────────────────────────────────────────
  // One press, one answer, and the answer stays on the button. Capped at one an
  // hour per document by the server, so the reader is told which of the two
  // things happened rather than left pressing it again.
  function heldShare(id) {
    var prefix = 'paramant.cosign.share.v1:' + id + ':';
    try {
      for (var i = 0; i < localStorage.length; i++) {
        var k = localStorage.key(i);
        if (!k || k.indexOf(prefix) !== 0) continue;
        var rec = JSON.parse(localStorage.getItem(k) || 'null');
        if (rec && rec.v === 2 && Date.now() < Number(rec.exp)) return true;
      }
    } catch (e) { /* storage off */ }
    return false;
  }
  function resendInvitation(id, button) {
    if (!id || !button || button.disabled) return;
    button.disabled = true;
    button.textContent = nlEn('Bezig met versturen', 'Sending');
    fetch('/api/user/parasign/inbox/' + encodeURIComponent(id) + '/resend', {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: '{}', cache: 'no-store'
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (body) {
        if (r.status === 429) throw new Error('rate_limited');
        if (!r.ok) throw new Error(body.error || 'failed');
        return body;
      });
    }).then(function () {
      // No mail goes out from here: the link that opens the document is
      // built in the sender's browser, so the sender has been asked to send
      // the invitation again (admin/server.js, COSIGN-46). Say that.
      button.textContent = nlEn('Gevraagd aan de afzender', 'Asked the sender');
      var note = document.createElement('p');
      note.className = 'pa-say ok dh-inbox-note';
      note.setAttribute('role', 'status');
      note.textContent = nlEn('We hebben de afzender gevraagd je de uitnodiging opnieuw te sturen. Alleen de afzender heeft de sleutel van het document. De nieuwe mail heeft dezelfde link als de eerste en opent het document op elk apparaat.', 'We have asked the sender to send you the invitation again. Only the sender holds the document key. The new mail has the same link as the first one and opens the document on any device.');
      // This browser may hold the key half from the first invitation
      // (js/cosign-share-memory.js): then the first mail's link opens the
      // document here already.
      if (heldShare(id)) note.textContent += ' ' + nlEn('In deze browser opent de link uit je eerste uitnodiging het document nu al.', 'In this browser the link from your first invitation already opens the document.');
      var cardEl = button.closest ? button.closest('.pa-card') : null;
      var prev = cardEl && cardEl.querySelector('.dh-inbox-note');
      if (prev) prev.remove();
      if (cardEl) cardEl.appendChild(note);
    }).catch(function (err) {
      button.textContent = err.message === 'rate_limited'
        ? nlEn('Al gevraagd, probeer het over een uur opnieuw', 'Already asked, try again in an hour')
        : err.message === 'sender_not_reachable'
          ? nlEn('De afzender is nu niet te bereiken, probeer het later opnieuw', 'The sender cannot be reached now, try again later')
          : nlEn('Versturen is niet gelukt, probeer het later opnieuw', 'Could not send, try again later');
      if (err.message !== 'rate_limited') button.disabled = false;
    });
  }

  // ── Requests for documents: remind ─────────────────────────────────────────
  // Opening and downloading what came in happens on /opvragen, where the keys
  // of the request are unlocked; this screen only nudges the client.
  function remindRequest(id, button) {
    if (button) button.disabled = true;
    say(id, nlEn('Bezig...', 'Working...'));
    fetch('/api/user/opvragen/' + encodeURIComponent(id) + '/herinnering', {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' }, body: '{}'
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (b) { return { ok: r.ok, b: b }; });
    }).then(function (x) {
      if (x.ok) {
        say(id, nlEn('Herinnering verstuurd. Daarin staat welke stukken nog ontbreken, geen link of bestand.', 'Reminder sent. It says which documents are still missing, with no link or file in it.'), 'ok');
        (L.requests || []).forEach(function (r) { if (r.id === id) r.reminders = Number(r.reminders || 0) + 1; });
      } else {
        if (button) button.disabled = false;
        say(id, x.b && x.b.error === 'no_email'
          ? nlEn('Geen e-mailadres opgegeven. Deel de link zelf opnieuw.', 'No email address given. Share the link again yourself.')
          : nlEn('De herinnering is niet verstuurd. Probeer het over een minuut opnieuw.', 'The reminder did not go out. Try again in a minute.'), 'err');
      }
    }).catch(function () {
      if (button) button.disabled = false;
      say(id, nlEn('De herinnering is niet verstuurd. Probeer het over een minuut opnieuw.', 'The reminder did not go out. Try again in a minute.'), 'err');
    });
  }

  // ── Wiring ─────────────────────────────────────────────────────────────────
  function wireActions() {
    document.addEventListener('click', function (ev) {
      var t = ev.target.closest && ev.target.closest('[data-pa-action]');
      if (!t) return;
      var act = t.getAttribute('data-pa-action');
      var docId = t.getAttribute('data-document-id');
      var sendId = t.getAttribute('data-send-id');
      if (act === 'lists-refresh') { ev.preventDefault(); loadAll(); return; }
      if (act === 'inbox-resend') { ev.preventDefault(); resendInvitation(docId, t); return; }
      if (act === 'document-open') { ev.preventDefault(); openDocumentDialog(docId); return; }
      if (act === 'document-close') { ev.preventDefault(); closeDocumentDialog(); return; }
      if (act === 'document-remind') { ev.preventDefault(); remindDocument(docId, t); return; }
      if (act === 'document-cancel') { ev.preventDefault(); cancelDocument(docId, t, false); return; }
      if (act === 'document-withdraw-ask') { ev.preventDefault(); askWithdraw(docId); return; }
      if (act === 'document-withdraw-no') { ev.preventDefault(); cancelWithdrawAsk(docId); return; }
      if (act === 'document-withdraw-do') { ev.preventDefault(); cancelDocument(docId, t, true); return; }
      if (act === 'document-resend-invite') { ev.preventDefault(); resendSignerInvite(docId, Number(t.getAttribute('data-party')), t); return; }
      if (act === 'document-copy-link') {
        ev.preventDefault();
        var link = t.getAttribute('data-link') || '';
        var done = function () { t.textContent = nlEn('Gekopieerd', 'Copied'); };
        try { navigator.clipboard.writeText(link).then(done, function () { window.prompt(nlEn('Kopieer de link:', 'Copy the link:'), link); }); }
        catch (e2) { window.prompt(nlEn('Kopieer de link:', 'Copy the link:'), link); }
        return;
      }
      if (act === 'send-open') { ev.preventDefault(); sendAll[sendId] = true; redrawSend(sendId); return; }
      if (act === 'send-remind') { ev.preventDefault(); remindSend(sendId, t); return; }
      if (act === 'send-revoke') { ev.preventDefault(); askSendRevoke(sendId, t.getAttribute('data-email'), t); return; }
      if (act === 'send-revoke-no') { ev.preventDefault(); redrawSend(sendId); return; }
      if (act === 'send-revoke-do') { ev.preventDefault(); revokeSend(sendId, t.getAttribute('data-email'), t); return; }
      if (act === 'request-remind') { ev.preventDefault(); remindRequest(t.getAttribute('data-request-id'), t); }
    });
    var dialog = document.getElementById('dh-document-dialog');
    if (dialog) dialog.addEventListener('click', function (ev) { if (ev.target === dialog) closeDocumentDialog(); });
    document.addEventListener('keydown', function (ev) {
      if (ev.key === 'Escape' && dialog && !dialog.hidden) closeDocumentDialog();
    });
  }

  // Open and Klaar. ?filter= from older links and mails still lands right:
  // open stays Open, completed and cancelled (Gestopt) are Klaar.
  function wireTabs() {
    var asked = '';
    try {
      var q = new URLSearchParams(location.search);
      asked = q.get('tab') || q.get('filter') || '';
    } catch (e) { asked = ''; }
    tab = (asked === 'klaar' || asked === 'completed' || asked === 'cancelled') ? 'klaar' : 'open';
    var seg = document.getElementById('pa-seg');
    if (!seg) return;
    seg.addEventListener('click', function (ev) {
      var b = ev.target.closest && ev.target.closest('[data-tab]');
      if (b) setTab(b.getAttribute('data-tab'));
    });
    seg.addEventListener('keydown', function (ev) {
      if (ev.key !== 'ArrowLeft' && ev.key !== 'ArrowRight') return;
      setTab(tab === 'open' ? 'klaar' : 'open');
      var on = seg.querySelector('[data-tab="' + tab + '"]');
      if (on) on.focus();
    });
  }

  // The circle with the initials opens the account: the address, Account, and
  // the language of this screen.
  function wireAccountMenu() {
    var btn = document.getElementById('pa-avatar');
    var menu = document.getElementById('pa-acct-menu');
    if (!btn || !menu || btn.tagName !== 'BUTTON') return;
    function set(open) { menu.hidden = !open; btn.setAttribute('aria-expanded', open ? 'true' : 'false'); }
    btn.addEventListener('click', function (ev) { ev.stopPropagation(); set(menu.hidden); if (!menu.hidden) { var f = menu.querySelector('a'); if (f) f.focus(); } });
    document.addEventListener('click', function (ev) { if (!menu.hidden && !menu.contains(ev.target)) set(false); });
    document.addEventListener('keydown', function (ev) { if (ev.key === 'Escape' && !menu.hidden) { set(false); btn.focus(); } });
  }

  // One button Nieuw, with the three ways to start something.
  function wireMenu() {
    var btn = document.getElementById('pa-new');
    var menu = document.getElementById('pa-menu');
    if (!btn || !menu) return;
    function set(open) { menu.hidden = !open; btn.setAttribute('aria-expanded', open ? 'true' : 'false'); }
    btn.addEventListener('click', function (ev) { ev.stopPropagation(); set(menu.hidden); if (!menu.hidden) { var f = menu.querySelector('a'); if (f) f.focus(); } });
    document.addEventListener('click', function (ev) { if (!menu.hidden && !menu.contains(ev.target)) set(false); });
    document.addEventListener('keydown', function (ev) { if (ev.key === 'Escape' && !menu.hidden) { set(false); btn.focus(); } });
  }

  // One-time nudge: if the account is missing a signing key and/or a sign-in
  // passkey, surface a dismissible popup that links into /account. Best-effort
  // and tolerant -- we only flag something as missing when the endpoint answers
  // cleanly with an empty list, never on a fetch error (so we never false-nag).
  var keySetupChecked = false;
  function checkKeySetup() {
    try { if (localStorage.getItem(KEYSETUP_KEY) === '1') return; } catch (_) {}

    var modal = document.getElementById('dh-passkey-modal');
    var itemsBox = document.getElementById('dh-pm-items');
    var dismissBtn = document.getElementById('dh-pm-dismiss');
    if (!modal || !itemsBox) return;

    function getJSON(url) {
      return fetch(url, { credentials: 'include', headers: { 'Accept': 'application/json' }, cache: 'no-store' })
        .then(function (r) { return r.ok ? r.json() : null; })
        .catch(function () { return null; });
    }

    Promise.all([
      getJSON('/api/user/account/signing-key'),
      getJSON('/api/user/account/webauthn/credentials')
    ]).then(function (res) {
      var signing = res[0], passkeys = res[1];
      var items = [];
      // No "set up signing" nag: without a stored key everybody signs with the
      // code from the authenticator app, so nothing is missing. And the
      // passkey offer only where this browser can make one (acceptance test
      // 2026-10-04: the pop-up came whether it was relevant or not).
      void signing;
      var canPasskey = typeof window.PublicKeyCredential === 'function';
      if (canPasskey && passkeys && Array.isArray(passkeys.passkeys) && passkeys.passkeys.length === 0) {
        items.push({
          href: LP + '/account#passkey-section',
          title: nlEn('Passkey toevoegen om in te loggen', 'Add a sign-in passkey'),
          body: nlEn('Log in met Face ID, Touch ID of een beveiligingssleutel, zonder code.', 'Use Face ID, Touch ID, or a security key to sign in without a code.')
        });
      }
      if (!items.length) return;

      // Titles/bodies are static literals (no user input) -> safe innerHTML.
      itemsBox.innerHTML = items.map(function (it) {
        return '<a class="dh-pm-item" href="' + it.href + '">'
          + '<strong>' + it.title + '</strong>'
          + '<span>' + it.body + '</span></a>';
      }).join('');
      modal.hidden = false;

      function dismiss() {
        modal.hidden = true;
        try { localStorage.setItem(KEYSETUP_KEY, '1'); } catch (_) {}
      }
      if (dismissBtn) dismissBtn.addEventListener('click', dismiss);
      // Following the link is an answer too; without this the modal came back
      // on every visit until it was clicked away (fase 1, DASH-18-A).
      itemsBox.addEventListener('click', function (ev) {
        if (ev.target.closest && ev.target.closest('a.dh-pm-item')) { try { localStorage.setItem(KEYSETUP_KEY, '1'); } catch (_) {} }
      });
      modal.addEventListener('click', function (ev) { if (ev.target === modal) dismiss(); });
      document.addEventListener('keydown', function (ev) { if (ev.key === 'Escape' && !modal.hidden) dismiss(); });
    });
  }

  // ---- Usage ----
  // There was an operations panel here (live keys, usage bars with an upgrade
  // link at 80%, an activity feed), polled every five seconds. /dashboard has
  // carried no #dh-ops for months, so it never drew and the 80% warning it
  // promised in code was shown to nobody (fase 1, DASH-27-N). The usage bar
  // and the warning live on /developer, which reads the same snapshot once;
  // /dashboard stays without a polling usage feed (DASH-27-A).
  //
  // /developer sits behind an operator allowlist, so an ordinary customer never
  // reached that warning either (eindmatrix DASH-27-N). The overview endpoint
  // is open to every logged-in account and carries the same quota, so the
  // dashboard reads it once per page load and shows one band from 80% of a
  // monthly quota, with the way up. Below 80%, or when the relay cannot say,
  // nothing is shown: no guessed numbers.
  var usageAsked = false;
  function usageWarning(quota) {
    var caps = (quota && quota.caps) || {};
    var rows = [
      { used: Number(quota && quota.signs || 0), cap: caps.signs,
        nl: 'handtekeningen', en: 'signatures' },
      { used: Number(quota && quota.transfers || 0), cap: caps.transfers,
        nl: 'verzendingen', en: 'transfers' },
    ];
    var worst = null;
    rows.forEach(function (r) {
      if (typeof r.cap !== 'number' || !isFinite(r.cap) || r.cap <= 0) return;
      r.pct = Math.min(100, Math.round((r.used / r.cap) * 100));
      if (r.pct >= 80 && (!worst || r.pct > worst.pct)) worst = r;
    });
    if (!worst) return null;
    var left = Math.max(0, worst.cap - worst.used);
    if (worst.pct >= 100) {
      return nlEn('Je tegoed van ' + worst.cap + ' ' + worst.nl + ' is op voor deze maand. Heb je meer nodig?',
                  'Your ' + worst.cap + ' ' + worst.en + ' for this month are used up. Need more?');
    }
    return nlEn('Je hebt ' + worst.used + ' van je ' + worst.cap + ' ' + worst.nl + ' deze maand gebruikt, nog ' + left + ' over. Het is bijna op. Heb je meer nodig?',
                'You have used ' + worst.used + ' of your ' + worst.cap + ' ' + worst.en + ' this month, ' + left + ' left. Almost used up. Need more?');
  }
  function loadUsage() {
    if (usageAsked) return;
    usageAsked = true;
    var band = root && root.querySelector('#dh-usage-warn');
    if (!band) return;
    fetch('/api/user/dashboard/overview', { credentials: 'include', headers: { 'Accept': 'application/json' }, cache: 'no-store' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) {
        var text = data && usageWarning(data.quota);
        if (!text) { band.hidden = true; return; }
        band.querySelector('[data-dh="usage-warn"]').textContent = text;
        band.hidden = false;
      })
      .catch(function () { band.hidden = true; });
  }

  // ---- Usage ----
  // The overview endpoint is open to every logged-in account and carries the
  // month's quota. From 80% of a monthly quota one band says so, with the way
  // up. Below 80%, or when the relay cannot say, nothing is shown: no guessed
  // numbers (eindmatrix DASH-27-N).
  var usageAsked = false;
  function usageWarning(q) {
    var caps = (q && q.caps) || {};
    var rows = [
      { used: Number(q && q.signs || 0), cap: caps.signs,
        nl: 'handtekeningen', en: 'signatures' },
      { used: Number(q && q.transfers || 0), cap: caps.transfers,
        nl: 'verzendingen', en: 'transfers' },
    ];
    var worst = null;
    rows.forEach(function (r) {
      if (typeof r.cap !== 'number' || !isFinite(r.cap) || r.cap <= 0) return;
      r.pct = Math.min(100, Math.round((r.used / r.cap) * 100));
      if (r.pct >= 80 && (!worst || r.pct > worst.pct)) worst = r;
    });
    if (!worst) return null;
    var left = Math.max(0, worst.cap - worst.used);
    if (worst.pct >= 100) {
      return nlEn('Je tegoed van ' + worst.cap + ' ' + worst.nl + ' is op voor deze maand. Heb je meer nodig?',
                  'Your ' + worst.cap + ' ' + worst.en + ' for this month are used up. Need more?');
    }
    return nlEn('Je hebt ' + worst.used + ' van je ' + worst.cap + ' ' + worst.nl + ' deze maand gebruikt, nog ' + left + ' over. Het is bijna op. Heb je meer nodig?',
                'You have used ' + worst.used + ' of your ' + worst.cap + ' ' + worst.en + ' this month, ' + left + ' left. Almost used up. Need more?');
  }
  function loadUsage() {
    if (usageAsked) return;
    usageAsked = true;
    var band = root && root.querySelector('#dh-usage-warn');
    fetch('/api/user/dashboard/overview', { credentials: 'include', headers: { 'Accept': 'application/json' }, cache: 'no-store' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) {
        quota = data && data.quota ? data.quota : null;
        var text = data && usageWarning(data.quota);
        if (band) {
          if (!text) band.hidden = true;
          else { band.querySelector('[data-dh="usage-warn"]').textContent = text; band.hidden = false; }
        }
        if (L.documents !== undefined) renderLists();
      })
      .catch(function () { if (band) band.hidden = true; });
  }

  // Listeners go on once. start() runs again for every poll round after a
  // payment (refreshAccount), and each round used to add another set: one click
  // on "Verzoek annuleren" then asked six times (fase 1, DASH-04-J).
  var wired = false;
  function wireOnce() {
    if (wired) return;
    wired = true;
    wireActions();
    wireTabs();
    wireMenu();
    wireAccountMenu();
  }

  function start(tries) {
    wireOnce();

    var ctrl = ('AbortController' in window) ? new AbortController() : null;
    var timer = ctrl ? setTimeout(function () { ctrl.abort(); }, 10000) : 0;
    var opts = {
      credentials: 'include',
      headers: { 'Accept': 'application/json' },
      cache: 'no-store',
    };
    if (ctrl) opts.signal = ctrl.signal;

    fetch('/api/user/me', opts)
      .then(function (r) {
        if (timer) clearTimeout(timer);
        if (r.status === 401 || r.status === 403) {
          location.replace(LOGIN_URL);
          return null;
        }
        if (!r.ok) {
          showError(r.status === 429 ? 'busy' : 'server');
          return null;
        }
        return r.json();
      })
      .then(function (data) {
        if (data) { render(data); loadUsage(); }
        // Only after render, so lastAccountIsPaid reflects this answer.
        if (isBillingReturn()) showBillingReturn(typeof tries === 'number' ? tries : RETURN_TRIES);
      })
      .catch(function () {
        if (timer) clearTimeout(timer);
        showError('network');
      });
  }

  // Re-ask /api/user/me while a just-made payment is still being confirmed.
  function refreshAccount(tries) { start(tries); }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () { start(); });
  } else {
    start();
  }
})();
