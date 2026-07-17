// Passport machine-readable zone (MRZ), TD3 format: two lines of 44 characters.
// The MRZ is self-checking: every field carries a weighted check digit, plus a
// composite over the whole line 2. If a character is misread, a check digit
// fails, so we never accept a garbled or tampered MRZ. That is the integrity
// guarantee that lets an imperfect camera read still be safe: it simply retries
// until the check digits pass.
'use strict';

// Character value: 0-9 -> 0-9, A-Z -> 10-35, filler '<' -> 0.
function charVal(c) {
  if (c >= '0' && c <= '9') return c.charCodeAt(0) - 48;
  if (c >= 'A' && c <= 'Z') return c.charCodeAt(0) - 55;
  if (c === '<') return 0;
  return -1;
}

// ICAO 9303 check digit: weights cycle 7, 3, 1 over the field, mod 10.
export function checkDigit(field) {
  const w = [7, 3, 1];
  let sum = 0;
  for (let i = 0; i < field.length; i++) {
    const v = charVal(field[i]);
    if (v < 0) return -1;
    sum += v * w[i % 3];
  }
  return sum % 10;
}

function digit(c) { return (c >= '0' && c <= '9') ? c.charCodeAt(0) - 48 : -1; }

// Parse + validate a TD3 MRZ. Returns { valid, errors, fields, checks }.
export function parseTD3(line1, line2) {
  const errors = [];
  const l1 = (line1 || '').toUpperCase().replace(/\s/g, '');
  const l2 = (line2 || '').toUpperCase().replace(/\s/g, '');
  if (l1.length !== 44 || l2.length !== 44) {
    return { valid: false, errors: ['each MRZ line must be exactly 44 characters (got ' + l1.length + ' / ' + l2.length + ')'] };
  }
  if (l1[0] !== 'P') errors.push('line 1 does not start with P (not a passport TD3)');

  const issuingState = l1.slice(2, 5).replace(/</g, '');
  const nameField = l1.slice(5);
  const [surnameRaw, givenRaw] = nameField.split('<<');
  const surname = (surnameRaw || '').replace(/</g, ' ').trim();
  const given = (givenRaw || '').replace(/</g, ' ').trim();

  const docNo = l2.slice(0, 9);
  const docNoChk = digit(l2[9]);
  const nationality = l2.slice(10, 13).replace(/</g, '');
  const dob = l2.slice(13, 19);          // YYMMDD
  const dobChk = digit(l2[19]);
  const sex = l2[20];
  const expiry = l2.slice(21, 27);       // YYMMDD
  const expiryChk = digit(l2[27]);
  const personalNo = l2.slice(28, 42);
  const personalChk = digit(l2[42]);
  const compositeChk = digit(l2[43]);

  const checks = {
    document_number: checkDigit(docNo) === docNoChk,
    date_of_birth: checkDigit(dob) === dobChk,
    expiry: checkDigit(expiry) === expiryChk,
    personal_number: (l2.slice(28, 43).replace(/</g, '') === '') || checkDigit(personalNo) === personalChk,
  };
  // Composite: doc no + its check + DOB + its check + expiry + its check + personal + its check.
  const composite = l2.slice(0, 10) + l2.slice(13, 20) + l2.slice(21, 43);
  checks.composite = checkDigit(composite) === compositeChk;

  for (const [k, ok] of Object.entries(checks)) if (!ok) errors.push('check digit failed: ' + k);

  return {
    valid: errors.length === 0,
    errors,
    checks,
    fields: { issuingState, surname, given, docNo: docNo.replace(/</g, ''), nationality, dob, sex, expiry },
  };
}

// Derive age from a YYMMDD MRZ date, choosing the century so the date is in the
// past and within ~100 years. Returns whole years at the given "today".
export function ageFromMrzDob(dobYYMMDD, today) {
  const yy = parseInt(dobYYMMDD.slice(0, 2), 10);
  const mm = parseInt(dobYYMMDD.slice(2, 4), 10);
  const dd = parseInt(dobYYMMDD.slice(4, 6), 10);
  if (isNaN(yy) || isNaN(mm) || isNaN(dd) || mm < 1 || mm > 12 || dd < 1 || dd > 31) return null;
  const nowYY = today.getFullYear() % 100;
  const century = (yy > nowYY) ? 1900 : 2000;   // a birth year in the future means last century
  const year = century + yy;
  let age = today.getFullYear() - year;
  const m = (today.getMonth() + 1) - mm;
  if (m < 0 || (m === 0 && today.getDate() < dd)) age--;
  return age;
}
