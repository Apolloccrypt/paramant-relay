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
// UTC, and hand-built from a month table rather than Intl. Same reasoning as
// relay/lib/plan-expiry.js: the date in the reminder mail, the date in the
// expiry line and the date in the invoice row are the same date and have to
// read the same, and a mail is rendered on a server in UTC. Building the string
// ourselves also means the output cannot drift with the browser's locale data,
// which is the whole failure this file replaces.
//
// Times carry their zone. "last seen 3/17/2026, 8:48:55 PM" said neither what
// day it was nor where the clock stood.
'use strict';

(function () {
  if (window.paramantDate && window.paramantDate.__paramant) return;

  var MONTHS = ['January', 'February', 'March', 'April', 'May', 'June',
    'July', 'August', 'September', 'October', 'November', 'December'];

  function toDate(value) {
    if (value == null || value === '') return null;
    var d = value instanceof Date ? value : new Date(value);
    return isNaN(d.getTime()) ? null : d;
  }

  function pad(n) { return n < 10 ? '0' + n : String(n); }

  // "8 September 2026". The one format the site shows a reader.
  function day(value, fallback) {
    var d = toDate(value);
    if (!d) return fallback === undefined ? '--' : fallback;
    return d.getUTCDate() + ' ' + MONTHS[d.getUTCMonth()] + ' ' + d.getUTCFullYear();
  }

  // "8 September 2026, 20:48 UTC". For a moment rather than a day: a session
  // last seen, a key enrolled. 24-hour clock and a named zone, because the
  // reader is being asked to recognise the moment, not to convert it.
  function moment(value, fallback) {
    var d = toDate(value);
    if (!d) return fallback === undefined ? '--' : fallback;
    return day(d) + ', ' + pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes()) + ' UTC';
  }

  window.paramantDate = { __paramant: true, day: day, moment: moment };
})();
