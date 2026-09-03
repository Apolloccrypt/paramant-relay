// Where the app screenshots are allowed to land.
//
// tests/app-shots.mjs renders every app screen at two viewports in two themes
// and writes 36 PNGs. Until now it wrote them straight into
// docs/brand/assets/app-2026/, which is tracked. So every local run of the
// browser suites rewrote 36 tracked files, `git status` was never clean after a
// test run, and the next `git commit -a` on that branch carried a pile of
// screenshots nobody meant to send. Two builders reported exactly that.
//
// Rewriting the reference images is a deliberate act, not a side effect of
// running the tests. So the tracked directory is opt-in:
//
//   node tests/app-shots.mjs                          -> a temp dir, repo clean
//   PARAMANT_WRITE_BRAND_SHOTS=1 node tests/app-shots.mjs  -> docs/brand/assets
//
// APP_SHOTS_DIR still names an explicit directory and still wins, with one
// rule: an explicit path that points back inside docs/ is refused without the
// flag. Otherwise the opt-in would be one environment variable away from
// meaning nothing, which is the same hole with a longer name.
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const DOCS_ROOT = path.join(REPO_ROOT, 'docs');
export const TRACKED_DIR = path.join(DOCS_ROOT, 'brand', 'assets', 'app-2026');
export const FLAG = 'PARAMANT_WRITE_BRAND_SHOTS';
export const DIR_VAR = 'APP_SHOTS_DIR';
export const DRY_RUN_VAR = 'APP_SHOTS_DRY_RUN';

// True when `dir` is docs/ itself or anything below it. Compared on resolved
// paths, so ../docs, a symlink-free absolute path and a relative one all give
// the same answer.
export function isUnderDocs(dir) {
  const rel = path.relative(DOCS_ROOT, path.resolve(dir));
  return rel === '' || (!rel.startsWith('..' + path.sep) && rel !== '..' && !path.isAbsolute(rel));
}

// Returns { dir, optIn, source }. Throws only for the refused case above, so a
// caller that never sets APP_SHOTS_DIR can use it without a try.
export function resolveBrandShotsDir(env = process.env) {
  const optIn = env[FLAG] === '1';
  const explicit = env[DIR_VAR];

  if (explicit) {
    const dir = path.resolve(explicit);
    if (isUnderDocs(dir) && !optIn) {
      throw new Error(
        `${DIR_VAR}=${explicit} points inside docs/, which is tracked. ` +
        `Set ${FLAG}=1 if you really mean to refresh the reference images.`,
      );
    }
    return { dir, optIn, source: DIR_VAR };
  }

  if (optIn) return { dir: TRACKED_DIR, optIn, source: FLAG };
  return { dir: path.join(os.tmpdir(), 'paramant-app-shots'), optIn, source: 'default' };
}
