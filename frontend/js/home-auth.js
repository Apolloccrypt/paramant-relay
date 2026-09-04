/* The signed-in homepage: the work, filled in.
 *
 * WHAT THIS PAGE IS
 *
 * The homepage ships the logged-out pitch by default (so it works with JS off
 * and is what link scrapers see). When a valid session is present, swap to the
 * logged-in variant and stamp data-session="in" on <html>, off which index.html
 * hides every section under the hero in CSS: no inline script (CSP
 * script-src 'self'), and a section added tomorrow is covered the day it lands.
 *
 * WHY IT NOW FETCHES ANYTHING AT ALL
 *
 * Until 4 September the signed-in hero was a heading, one paragraph and three
 * buttons over an empty screen. Mick, reading it on his phone: "I see ONLY 3
 * buttons, as if it were a test page. This never passed marketing." The
 * yardstick he set is BeerWeer, which opens on the one reading that matters and
 * lays the rest out quietly under it. A customer who is signed in has real
 * numbers waiting for him one page away; a homepage that shows him none of them
 * is a menu, not a workbench.
 *
 * So this reads three routes that /dashboard and /account already read, and
 * writes the answers into slots the markup owns:
 *
 *   GET /api/user/documents            the account's own signing requests
 *   GET /api/user/dashboard/overview   quota.signs and quota.caps.signs
 *   GET /api/user/billing/status       the plan and the end of the term
 *
 * WHAT IT DOES NOT SAY, and why
 *
 * "2 waiting for YOUR signature" is not a sentence this page can honestly
 * write. /api/user/documents is the SENT list: relay/envelope.js indexes an
 * envelope under its creator (parsign:acct:<id>:envelopes, written once, in
 * create()), and there is no reverse index from a party's email hash to the
 * envelopes it appears in. Nothing on the relay can answer "which documents are
 * waiting for me to sign" without a fleet-wide scan, and an invited signer
 * reaches his document by the capability link in the mail. So the figure counts
 * requests that are open and says exactly that: waiting ON a signature, not FOR
 * yours. The day a party index exists this file gains a fourth fetch and a
 * truer sentence; until then it does not borrow one.
 *
 * NO KEY IN THE BROWSER. All three routes ride the session cookie the same way
 * /dashboard does. Nothing here mints or holds a credential, so #413 stands:
 * the account's pgp_ key never reaches this page.
 *
 * TOLERANT BY DESIGN. Every fetch resolves to null on any failure. A block
 * whose data did not arrive hides itself, one calm line takes the place of the
 * figure, and the three buttons keep working. Nothing here can leave the reader
 * on a raw error, and nothing writes a zero it cannot stand behind.
 *
 * Values go in with textContent and rows are built from nodes, never from a
 * string of markup: a file name is chosen by somebody else and has no business
 * near innerHTML.
 */
(function () {
  'use strict';

  var out = document.querySelector('[data-home="out"]');
  var inn = document.querySelector('[data-home="in"]');
  if (!out || !inn) return;

  function pick(name) { return inn.querySelector('[data-' + name + ']'); }
  function show(node, on) { if (node) node.hidden = !on; }
  function words(node, value) { if (node) node.textContent = value; }

  // One notation for every date a reader sees, from /js/format-date.js:
  // "28 August 2026", never a slashed date. Same file /dashboard and /account
  // use, so the day this page prints and the day they print are one day.
  function day(value) {
    return (window.paramantDate && window.paramantDate.day(value, '')) || '';
  }

  function getJSON(url) {
    return fetch(url, {
      credentials: 'include',
      headers: { Accept: 'application/json' },
      cache: 'no-store'
    }).then(function (r) {
      if (!r.ok) throw new Error('http_' + r.status);
      return r.json();
    }).catch(function () { return null; });
  }

  // ── The state of one signing request ───────────────────────────────────────
  // The same four states /dashboard shows, derived the same way, so a document
  // does not read as "in progress" here and "waiting" one click later.
  function stateOf(doc) {
    if (doc.status === 'complete') return 'completed';
    if (doc.status === 'void') return 'cancelled';
    return Number(doc.signed_count || 0) > 0 ? 'in_progress' : 'waiting';
  }
  var STATE_WORD = {
    waiting: 'Waiting',
    in_progress: 'In progress',
    completed: 'Completed',
    cancelled: 'Cancelled'
  };
  var STATE_DOT = {
    waiting: 'wait',
    in_progress: 'busy',
    completed: 'done',
    cancelled: 'done'
  };
  function isOpen(doc) {
    var s = stateOf(doc);
    return s === 'waiting' || s === 'in_progress';
  }

  // Who a request is still waiting on. The list route hands back party labels
  // and their status and nothing else: no addresses, no invite tokens. A party
  // without a label is counted, never invented.
  function pending(doc) {
    var parties = Array.isArray(doc.parties) ? doc.parties : [];
    var open = parties.filter(function (p) { return p.status !== 'signed'; });
    var named = open.map(function (p) { return String(p.label || '').trim(); }).filter(Boolean);
    if (!named.length) return '';
    if (named.length === 1) return 'Waiting on ' + named[0];
    if (named.length === 2) return 'Waiting on ' + named[0] + ' and ' + named[1];
    return 'Waiting on ' + named[0] + ' and ' + (named.length - 1) + ' others';
  }

  function row(doc, meta, tail, dot) {
    var li = document.createElement('li');
    li.className = 'hw-row';

    var mark = document.createElement('span');
    mark.className = 'hw-dot ' + dot;
    li.appendChild(mark);

    var main = document.createElement('div');
    main.className = 'hw-row-main';
    var name = document.createElement('span');
    name.className = 'hw-name';
    name.textContent = doc.original_filename || 'Signing request';
    name.title = name.textContent;
    main.appendChild(name);
    if (meta) {
      var sub = document.createElement('span');
      sub.className = 'hw-meta';
      sub.textContent = meta;
      main.appendChild(sub);
    }
    li.appendChild(main);

    if (tail) {
      var end = document.createElement('span');
      end.className = 'hw-tail';
      end.textContent = tail;
      li.appendChild(end);
    }
    return li;
  }

  function fill(list, rows) {
    if (!list) return;
    list.textContent = '';
    rows.forEach(function (node) { list.appendChild(node); });
  }

  // ── The strip of secondary readings ────────────────────────────────────────
  // The H / L / humidity row of this page: what did not earn the big number but
  // is still worth a glance. Built from what actually arrived.
  function strip(host, items) {
    if (!host) return;
    host.textContent = '';
    items.forEach(function (item) {
      var wrap = document.createElement('span');
      wrap.className = 'hw-strip-item';
      var lab = document.createElement('span');
      lab.className = 'hw-strip-lab';
      lab.textContent = item[0];
      var val = document.createElement('span');
      val.className = 'hw-strip-val';
      val.textContent = item[1];
      wrap.appendChild(lab);
      wrap.appendChild(val);
      host.appendChild(wrap);
    });
    show(host, items.length > 0);
  }

  // ── The plan, in one line ──────────────────────────────────────────────────
  // Same rule and same words as /account and /dashboard: a checkout here buys
  // one month or one year outright, so paid_until_<product> is the day access
  // stops and there is nothing to cancel. Two products can hold two dates; the
  // one that matters is the nearest one still ahead, and once they have all
  // passed it is the last one, because that is the day the account fell back.
  var TERM_WARN_DAYS = 7;
  var PRODUCT_NAMES = { pro: 'Pro', business: 'Business', enterprise: 'Enterprise' };
  var PLAN_ALIASES = { free: 'community', dev: 'community', licensed: 'enterprise' };
  var PLAN_NAMES = { community: 'Community', pro: 'Pro', business: 'Business', enterprise: 'Enterprise' };

  function normalisePlan(plan) {
    var id = String(plan == null ? '' : plan).toLowerCase();
    if (PLAN_ALIASES[id]) return PLAN_ALIASES[id];
    return PLAN_NAMES[id] ? id : 'community';
  }

  function termState(d, nowMs) {
    var now = typeof nowMs === 'number' ? nowMs : Date.now();
    var ends = [
      ['parasign', d.paid_until_parasign, d.plan_parasign],
      ['parasend', d.paid_until_parasend, d.plan_parasend]
    ].map(function (r) { return { product: r[0], at: r[1] ? Date.parse(r[1]) : NaN, tier: r[2] }; })
      .filter(function (r) { return !isNaN(r.at); });
    if (!ends.length) return null;
    var ahead = ends.filter(function (r) { return r.at > now; });
    var pool = ahead.length ? ahead : ends;
    var chosen = pool.reduce(function (best, r) {
      if (!best) return r;
      return (ahead.length ? r.at < best.at : r.at > best.at) ? r : best;
    }, null);
    var days = (chosen.at - now) / 86400000;
    return {
      at: chosen.at,
      product: chosen.product,
      tier: String(chosen.tier || '').toLowerCase(),
      ended: chosen.at <= now,
      warn: days > 0 && days <= TERM_WARN_DAYS
    };
  }

  function termLabel(term) {
    var tier = PRODUCT_NAMES[term.tier];
    if (!tier) return '';
    return (term.product === 'parasign' ? 'ParaSign ' : 'ParaSend ') + tier;
  }

  function planLine(d) {
    var term = termState(d);
    if (term) {
      var label = termLabel(term);
      if (term.ended) {
        return label
          ? { name: label, rest: ' ended on ' + day(term.at) + '. You are on Community now.', renew: true }
          : { name: 'Community', rest: ', free for good. Your paid term ended on ' + day(term.at) + '.', renew: true };
      }
      if (label) return { name: label, rest: ', ends on ' + day(term.at) + ', nothing renews automatically.', renew: term.warn };
    }
    var id = normalisePlan(d.current_plan);
    if (id === 'community') return { name: 'Community', rest: ', free for good.', renew: false };
    return { name: PLAN_NAMES[id], rest: ', with no term recorded. Nothing renews automatically.', renew: false };
  }

  // ── The one big reading ────────────────────────────────────────────────────
  // Open requests first, because a request nobody has signed is the only thing
  // on this account that is actually waiting. Nothing open, and the reading
  // becomes the month's signature balance, which is the number the buyer review
  // of 5 September found nowhere on the site while the route already had it.
  function renderFigure(docs, overview) {
    var kicker = pick('hw-kicker');
    var read = pick('hw-read');
    var num = pick('hw-num');
    var of = pick('hw-of');
    var cap = pick('hw-cap');
    var sub = pick('hw-sub');
    var quiet = pick('hw-quiet');

    var open = docs ? docs.filter(isOpen) : null;
    var done = docs ? docs.filter(function (d) { return stateOf(d) === 'completed'; }) : null;

    var quota = overview && overview.quota ? overview.quota : null;
    var caps = quota && quota.caps ? quota.caps : {};
    var used = quota ? Math.max(0, Number(quota.signs || 0)) : null;
    var limit = (caps.signs === null || caps.signs === undefined) ? null : Number(caps.signs);
    var capped = quota && limit !== null && isFinite(limit) && limit > 0;
    var left = capped ? Math.max(0, limit - used) : null;

    // The strip only carries readings a reader can do something with. On a
    // brand new account "documents 0, completed 0, open 0" is three zeros in a
    // row, which reads as a counter that failed rather than as an account that
    // is new; the card underneath already says so in words.
    var items = [];
    if (docs && docs.length) {
      items.push(['Documents', String(docs.length)]);
      items.push(['Completed', String(done.length)]);
    }

    if (open && open.length) {
      var oldest = open.reduce(function (best, d) {
        var t = Date.parse(d.created_at || '');
        if (isNaN(t)) return best;
        return (!best || t < best.t) ? { t: t, doc: d } : best;
      }, null);
      show(quiet, false);
      words(kicker, 'Still open');
      words(num, String(open.length));
      show(of, false);
      words(cap, open.length === 1 ? 'request is waiting on a signature' : 'requests are waiting on a signature');
      words(sub, oldest ? 'The oldest went out on ' + day(oldest.t) + '.' : 'Sent from this account.');
      show(read, true); show(cap, true); show(sub, true);
      if (capped) items.push(['Signatures left', left + ' of ' + limit]);
      strip(pick('hw-strip'), items);
      return;
    }

    if (quota) {
      show(quiet, false);
      words(kicker, 'This month');
      if (capped) {
        words(num, String(left));
        words(of, 'of ' + limit);
        show(of, true);
        words(cap, left === 1 ? 'signature left this month' : 'signatures left this month');
      } else {
        words(num, String(used));
        show(of, false);
        words(cap, used === 1 ? 'signature this month' : 'signatures this month');
      }
      words(sub, 'The count resets on ' + day(resetDate()) + '.');
      show(read, true); show(cap, true); show(sub, true);
      if (docs && docs.length) items.push(['Open', String(open ? open.length : 0)]);
      strip(pick('hw-strip'), items);
      return;
    }

    // Neither route answered. One line, no number, no raw error.
    show(read, false); show(cap, false); show(sub, false);
    words(kicker, 'Your account');
    show(quiet, true);
    strip(pick('hw-strip'), items);
  }

  // The signature counters are calendar-month keys in UTC (relay/lib/quota.js
  // writes paramant:quota:signs:<account>:<YYYY-MM>), so the day they start
  // again is the first of the next month, and it is a fact rather than a guess.
  function resetDate() {
    var now = new Date();
    return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1));
  }

  function renderDocuments(docs) {
    var host = pick('hw');
    var waiting = pick('hw-waiting');
    var recent = pick('hw-recent');
    var empty = pick('hw-empty');
    if (host) host.removeAttribute('data-hw-state');

    if (!docs) { show(waiting, false); show(recent, false); show(empty, false); return; }

    // A new account. One card of its own, with its own object and the two
    // first steps in it. index.html drops the action row underneath off
    // data-hw-state, because repeating the same two buttons eight lines lower
    // is the page-of-buttons this whole change exists to end; the nav's user
    // menu keeps carrying Documents either way.
    if (!docs.length) {
      show(waiting, false);
      show(recent, false);
      show(empty, true);
      if (host) host.setAttribute('data-hw-state', 'empty');
      return;
    }
    show(empty, false);

    var open = docs.filter(isOpen).slice(0, 3);
    var listed = {};
    if (open.length) {
      fill(pick('hw-waiting-list'), open.map(function (doc) {
        listed[doc.id] = true;
        var total = Math.max(0, Number(doc.party_count || 0));
        var signed = Math.max(0, Math.min(total, Number(doc.signed_count || 0)));
        var who = pending(doc);
        var when = day(doc.created_at);
        var meta = who ? (when ? who + ' · sent ' + when : who) : (when ? 'Sent ' + when : '');
        return row(doc, meta, total ? signed + ' of ' + total : '', STATE_DOT[stateOf(doc)]);
      }));
    }
    show(waiting, open.length > 0);

    // The last three, minus whatever the card above already shows. A document
    // printed twice on one screen is the fault the buyer review found on
    // /account, where the end of the term was announced three times in three
    // tones; a homepage is not the place to reintroduce it.
    var last = docs.filter(function (doc) { return !listed[doc.id]; }).slice(0, 3);
    fill(pick('hw-recent-list'), last.map(function (doc) {
      var state = stateOf(doc);
      var when = day(state === 'completed' && doc.completed_at ? doc.completed_at : doc.created_at);
      return row(doc, when, STATE_WORD[state], STATE_DOT[state]);
    }));
    show(recent, last.length > 0);
  }

  function renderPlan(billing) {
    var host = pick('hw-plan');
    var text = pick('hw-plan-text');
    var renew = pick('hw-renew');
    if (!billing) { show(host, false); return; }
    var line = planLine(billing);
    if (text) {
      text.textContent = '';
      var name = document.createElement('b');
      name.textContent = line.name;
      text.appendChild(name);
      text.appendChild(document.createTextNode(line.rest));
    }
    show(renew, !!line.renew);
    show(host, true);
  }

  function load() {
    Promise.all([
      getJSON('/api/user/documents'),
      getJSON('/api/user/dashboard/overview'),
      getJSON('/api/user/billing/status')
    ]).then(function (answers) {
      var body = answers[0];
      var docs = body && Array.isArray(body.documents) ? body.documents : null;
      renderFigure(docs, answers[1]);
      renderDocuments(docs);
      renderPlan(answers[2]);
    });
  }

  fetch('/api/user/session/verify', { credentials: 'include', cache: 'no-store' })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (data) {
      if (!data || !data.authenticated) return;

      // Personalise with the email local-part if we have it (textContent, so
      // no markup injection). Falls back to a plain "Your documents." otherwise.
      var nameEl = inn.querySelector('[data-home-name]');
      if (nameEl && data.email) {
        var at = String(data.email).indexOf('@');
        var local = at > 0 ? String(data.email).slice(0, at) : String(data.email);
        if (local) nameEl.textContent = ', ' + local;
      }

      out.hidden = true;
      inn.hidden = false;
      document.documentElement.setAttribute('data-session', 'in');
      load();
    })
    .catch(function () { /* stay on the logged-out pitch */ });
})();
