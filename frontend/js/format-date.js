// format-date.js - one date format for the whole site.
//
// THE BUG THIS EXISTS TO KILL
//
// A buyer read /account on 3 September 2026 and found three notations on one
// screen: "PM-2026-0413 - 8/9/2026" in the invoice list, "Ends on 8 September"
// ten lines above it, and "Access until 9/8/2026" between them. The two slashed
// dates are the same two digits in opposite orders, because
// toLocaleDateString() with no locale follows the VISITOR's machine: a Dutch
// browser renders day/month, an American one month/day, and neither of them is
// what the sentence next to it says. An accountant reading 8/9/2026 as
// 8 September and 9/8/2026 as 9 August, on the same page, about the same term,
// is a mistake the site invited.
//
// THE RULE
//
// One notation everywhere a reader sees a date: day, month in full, year.
//
//     8 September 2026
//
// No slashes, ever. A slashed date cannot be read without knowing which
// convention wrote it, and the site cannot know which one the reader assumes.
// The month written out removes the question.
//
// The year is never dropped. "Ends on 8 September" is unambiguous only while
// the reader assumes this year, and a term that ended in 2025 or renews into
// 2027 reads identically.
//
// Dutch time (Europe/Amsterdam), with the month from our own table rather than
// the browser's locale data, so the output cannot drift with that data, which
// is the whole failure this file replaces. The mails (admin/lib/email-templates.js,
// relay/lib/plan-expiry.js) and the signed pdf use the same clock. It was UTC
// until acceptatie 3.1.1 ronde 2: a request made at 00:46 Dutch time read
// "Gemaakt 5 oktober" on the dashboard while the mail and /co-sign said
// 6 oktober. A browser without the zone data falls back to UTC.
//
// Times carry their zone. "last seen 3/17/2026, 8:48:55 PM" said neither what
// day it was nor where the clock stood.
'use strict';

(function () {
  if (window.paramantDate && window.paramantDate.__paramant) return;

  // Dutch is the site's main language since 23 September 2026: "8 september
  // 2026". The English pages under /en carry <html lang="en"> and keep
  // "8 September 2026". Same shape either way: day, month in full, year.
  var ENGLISH = document.documentElement && document.documentElement.lang === 'en';
  var MONTHS = ENGLISH
    ? ['January', 'February', 'March', 'April', 'May', 'June',
      'July', 'August', 'September', 'October', 'November', 'December']
    : ['januari', 'februari', 'maart', 'april', 'mei', 'juni',
      'juli', 'augustus', 'september', 'oktober', 'november', 'december'];

  function toDate(value) {
    if (value == null || value === '') return null;
    var d = value instanceof Date ? value : new Date(value);
    return isNaN(d.getTime()) ? null : d;
  }

  function pad(n) { return n < 10 ? '0' + n : String(n); }

  // Day, month and year of a moment on Dutch time: { y, m (1-12), d }.
  var NL_DAY = null;
  function amsterdamParts(d) {
    try {
      if (!NL_DAY) NL_DAY = new Intl.DateTimeFormat('en-GB', { timeZone: 'Europe/Amsterdam', year: 'numeric', month: 'numeric', day: 'numeric' });
      var p = {}, parts = NL_DAY.formatToParts(d);
      for (var i = 0; i < parts.length; i++) p[parts[i].type] = parts[i].value;
      if (p.year && p.month && p.day) return { y: Number(p.year), m: Number(p.month), d: Number(p.day) };
    } catch (e) { /* no zone data: UTC below */ }
    return { y: d.getUTCFullYear(), m: d.getUTCMonth() + 1, d: d.getUTCDate() };
  }

  // "8 september 2026". The one format the site shows a reader.
  function day(value, fallback) {
    var d = toDate(value);
    if (!d) return fallback === undefined ? '--' : fallback;
    var p = amsterdamParts(d);
    return p.d + ' ' + MONTHS[p.m - 1] + ' ' + p.y;
  }

  // "8 september 2026 om 22:48". For a moment rather than a day: a session
  // last seen, a key enrolled. 24-hour clock on Dutch time (Europe/Amsterdam),
  // the clock the mails use too, because the reader is being asked to
  // recognise the moment, not to convert it from UTC (acceptatie 3.1.1, taal
  // 52). A browser without the zone data falls back to UTC and says so.
  function moment(value, fallback) {
    var d = toDate(value);
    if (!d) return fallback === undefined ? '--' : fallback;
    try {
      var p = {};
      var parts = new Intl.DateTimeFormat('en-GB', {
        timeZone: 'Europe/Amsterdam', year: 'numeric', month: 'numeric', day: 'numeric',
        hour: '2-digit', minute: '2-digit', hourCycle: 'h23',
      }).formatToParts(d);
      for (var i = 0; i < parts.length; i++) p[parts[i].type] = parts[i].value;
      return Number(p.day) + ' ' + MONTHS[Number(p.month) - 1] + ' ' + p.year
        + (ENGLISH ? ' at ' : ' om ') + p.hour + ':' + p.minute;
    } catch (e) {
      return day(d) + ', ' + pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes()) + ' UTC';
    }
  }

  // "5 oktober 2026 om 18:02 (CEST)". A moment in the reader's OWN clock, with
  // the zone named: the mail about a link says its expiry in local time, and
  // the sender's page said the same moment in UTC, two different clock times
  // for one moment (hertest r2 T4-L4).
  function localMoment(value, fallback) {
    var d = toDate(value);
    if (!d) return fallback === undefined ? '--' : fallback;
    var zone = '';
    try {
      var parts = new Intl.DateTimeFormat(ENGLISH ? 'en-GB' : 'nl-NL', { timeZoneName: 'short' }).formatToParts(d);
      for (var i = 0; i < parts.length; i++) if (parts[i].type === 'timeZoneName') zone = parts[i].value;
    } catch (e) { zone = ''; }
    var when = d.getDate() + ' ' + MONTHS[d.getMonth()] + ' ' + d.getFullYear()
      + (ENGLISH ? ' at ' : ' om ') + pad(d.getHours()) + ':' + pad(d.getMinutes());
    return zone ? when + ' (' + zone + ')' : when;
  }

  window.paramantDate = { __paramant: true, day: day, moment: moment, localMoment: localMoment };
})();
