'use strict';
// CSV formula injection guard. A cell that starts with = + - @ (or a tab or
// carriage return) is read as a formula by Excel and LibreOffice, so a label a
// customer typed ("=HYPERLINK(...)") would run when the export is opened. Such
// a cell gets a leading apostrophe, which spreadsheets show as plain text.
// A plain number ("-5,00" on a credit note, "+31") is left alone: it is not a
// formula, and an apostrophe would turn an amount into text.
//
// The browser exports (admin/public/app.js, frontend/js/admin.page.js) carry
// the same two lines inline; tests/csv-injection.test.mjs holds all of them to
// this behaviour.

const FORMULA_START = /^[=+\-@\t\r]/;
const PLAIN_NUMBER = /^[-+]?\d+(?:[.,]\d+)*$/;

function neutralize(value) {
  const s = String(value == null ? '' : value);
  return FORMULA_START.test(s) && !PLAIN_NUMBER.test(s) ? "'" + s : s;
}

module.exports = { neutralize };
