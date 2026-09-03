'use strict';
// A zip file, stored, in about a hundred lines.
//
// WHY NOT A LIBRARY. Same reasoning as lib/invoice-pdf.js. The one thing this
// has to do is hand a bookkeeper the PDFs of one period in a single download,
// and the PDFs are already compressed streams of text: deflating them again
// buys a few percent and costs a dependency on the payment path. So this writes
// the oldest and simplest member of the format, method 0 (stored), which every
// unzip on every platform has read since 1989.
//
// WHAT IT SUPPORTS, deliberately narrowly:
//   - method 0 only, no compression, no encryption, no zip64
//   - flat names, forward slashes, no directory entries
//   - one MS-DOS timestamp per entry
// A zip64 archive starts at 4 GB or 65535 entries. An export of one month of
// invoices is kilobytes and dozens of entries, and buildZip refuses rather than
// writing a header that lies (see the two limits below).
//
// The layout, per the PKWARE APPNOTE:
//   [local header + name + data] per entry
//   [central directory header + name] per entry
//   [end of central directory]
// Nothing is streamed: the whole archive is one Buffer, because the caller has
// every byte in memory already and a Content-Length is worth more here than a
// constant memory profile.

const zlib = require('zlib');

const SIG_LOCAL = 0x04034b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_EOCD = 0x06054b50;

// Version 2.0 in the "version needed" field: the lowest version that names
// method 0 with a data descriptor rule this writer obeys.
const VERSION = 20;

// The two ceilings above which the 32-bit fields in this format stop being
// true. Well beyond any billing export, and a hard error rather than a silent
// truncation: a zip whose central directory claims fewer entries than it holds
// opens fine in one tool and empty in the next.
const MAX_ENTRIES = 0xffff;
const MAX_BYTES = 0xffffffff;

// CRC-32 (IEEE 802.3), the checksum every zip entry carries. Node has had
// zlib.crc32 since v22.2, and that is what runs; the table below is the same
// function for anything older, kept because a wrong checksum here produces an
// archive that every reader rejects with no clue why.
let TABLE = null;
function crc32Fallback(buf) {
  if (!TABLE) {
    TABLE = new Int32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
      TABLE[n] = c;
    }
  }
  let c = -1;
  for (let i = 0; i < buf.length; i++) c = TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}

function crc32(buf) {
  return typeof zlib.crc32 === 'function' ? zlib.crc32(buf) >>> 0 : crc32Fallback(buf);
}

// MS-DOS date and time, the only timestamp the base format carries: two-second
// resolution and an epoch of 1980. A date before that (a clock that never got
// set) is clamped rather than wrapped into a negative year.
function dosDateTime(date) {
  const d = date instanceof Date && !Number.isNaN(date.getTime()) ? date : new Date();
  const year = Math.max(1980, d.getUTCFullYear());
  const time = ((d.getUTCHours() & 0x1f) << 11) | ((d.getUTCMinutes() & 0x3f) << 5) | ((d.getUTCSeconds() / 2) & 0x1f);
  const day = (((year - 1980) & 0x7f) << 9) | (((d.getUTCMonth() + 1) & 0x0f) << 5) | (d.getUTCDate() & 0x1f);
  return { time, day };
}

// Entry names are written as they are handed in, so this is where a name that
// could escape the extraction directory has to be stopped. Backslashes become
// forward slashes (the format says forward), a leading slash and any '..'
// segment are dropped, and what is left is what a reader will create.
function safeName(name) {
  const parts = String(name || '').replace(/\\/g, '/').split('/')
    .filter((p) => p && p !== '.' && p !== '..');
  return parts.join('/');
}

// entries: [{ name, data: Buffer, date?: Date }]
// Returns one Buffer holding the whole archive.
function buildZip(entries) {
  const list = Array.isArray(entries) ? entries : [];
  if (list.length > MAX_ENTRIES) throw new Error('zip_too_many_entries');

  const local = [];
  const central = [];
  let offset = 0;
  let total = 0;

  for (const e of list) {
    const name = safeName(e && e.name);
    if (!name) throw new Error('zip_bad_entry_name');
    const data = Buffer.isBuffer(e.data) ? e.data : Buffer.from(String(e.data == null ? '' : e.data), 'utf8');
    total += data.length;
    if (total > MAX_BYTES || offset > MAX_BYTES) throw new Error('zip_too_large');
    const nameBuf = Buffer.from(name, 'utf8');
    const sum = crc32(data);
    const { time, day } = dosDateTime(e.date);

    // Bit 11 of the general purpose flag: the name is UTF-8. Set unconditionally
    // rather than only for non-ASCII names, because it is true either way and a
    // reader that honours it then never guesses at a code page.
    const flags = 0x0800;

    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(SIG_LOCAL, 0);
    lh.writeUInt16LE(VERSION, 4);
    lh.writeUInt16LE(flags, 6);
    lh.writeUInt16LE(0, 8);            // method 0, stored
    lh.writeUInt16LE(time, 10);
    lh.writeUInt16LE(day, 12);
    lh.writeUInt32LE(sum, 14);
    lh.writeUInt32LE(data.length, 18); // compressed size
    lh.writeUInt32LE(data.length, 22); // uncompressed size
    lh.writeUInt16LE(nameBuf.length, 26);
    lh.writeUInt16LE(0, 28);           // no extra field
    local.push(lh, nameBuf, data);

    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(SIG_CENTRAL, 0);
    ch.writeUInt16LE(VERSION, 4);      // version made by
    ch.writeUInt16LE(VERSION, 6);      // version needed
    ch.writeUInt16LE(flags, 8);
    ch.writeUInt16LE(0, 10);
    ch.writeUInt16LE(time, 12);
    ch.writeUInt16LE(day, 14);
    ch.writeUInt32LE(sum, 16);
    ch.writeUInt32LE(data.length, 20);
    ch.writeUInt32LE(data.length, 24);
    ch.writeUInt16LE(nameBuf.length, 28);
    ch.writeUInt16LE(0, 30);           // extra length
    ch.writeUInt16LE(0, 32);           // comment length
    ch.writeUInt16LE(0, 34);           // disk number
    ch.writeUInt16LE(0, 36);           // internal attributes
    ch.writeUInt32LE(0, 38);           // external attributes
    ch.writeUInt32LE(offset, 42);      // offset of the local header
    central.push(ch, nameBuf);

    offset += lh.length + nameBuf.length + data.length;
  }

  const centralBuf = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(SIG_EOCD, 0);
  eocd.writeUInt16LE(0, 4);                 // this disk
  eocd.writeUInt16LE(0, 6);                 // disk with the central directory
  eocd.writeUInt16LE(list.length, 8);
  eocd.writeUInt16LE(list.length, 10);
  eocd.writeUInt32LE(centralBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20);                // no archive comment

  return Buffer.concat([...local, centralBuf, eocd]);
}

module.exports = { buildZip, crc32, crc32Fallback, safeName, dosDateTime, MAX_ENTRIES, MAX_BYTES };
