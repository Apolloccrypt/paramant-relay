'use strict';

// ESLint guardrail. Purpose: catch the class of real bugs that a stray comma
// operator or an accidental assignment inside a conditional can hide, not to
// bikeshed formatting. The create-envelope auth gate that matched every POST
// (condition read `path === '/v2/envelopes','/v2/billing'`, which the comma
// operator collapses to the truthy string '/v2/billing') was exactly this
// class and is caught by no-sequences. Only correctness rules are on; style
// rules stay off so the build fails on bugs, not on taste.
const bugRules = {
  // The comma-operator bug: any use of the sequence expression outside a for()
  // header is almost always a mistake in this codebase.
  'no-sequences': 'error',
  // Type-coercing == / != hides real comparison bugs. 'smart' keeps the safe
  // idioms (== null, typeof x == 'string', two literals) so this stays signal.
  eqeqeq: ['error', 'smart'],
  // Assignment where a comparison was meant: `if (x = 5)`. except-parens still
  // allows the deliberate, parenthesised `while ((x = next()))` idiom.
  'no-cond-assign': 'error',
  // A switch case that silently falls through to the next.
  'no-fallthrough': 'error',
  // `!a in b` / `!a instanceof B` where the negation binds the wrong operand.
  'no-unsafe-negation': 'error',
  // `if (true)` / dead conditions. checkLoops:false keeps intentional
  // `for(;;)` / `while(true)` event loops legal.
  'no-constant-condition': ['error', { checkLoops: false }],
};

module.exports = [
  // Vendored, minified and generated code is not ours to lint.
  {
    ignores: [
      'node_modules/**',
      'frontend/vendor/**',
      '**/*.min.js',
      '**/pdf-lib/**',
      // Bundled/generated PQC helper (single-line, identical to the vendored copy).
      '**/paramant-pqc.js',
      'build/**',
      'dist/**',
      'crypto-wasm/**',
    ],
  },
  // Backend relay + admin: Node CommonJS.
  {
    files: ['relay/*.js', 'relay/lib/**/*.js', 'admin/*.js', 'admin/lib/**/*.js'],
    languageOptions: { ecmaVersion: 2023, sourceType: 'commonjs' },
    rules: bugRules,
  },
  // ES-module backend helpers (.mjs).
  {
    files: ['relay/lib/**/*.mjs'],
    languageOptions: { ecmaVersion: 2023, sourceType: 'module' },
    rules: bugRules,
  },
  // Frontend browser scripts (ES modules and classic <script> files).
  {
    files: ['frontend/js/**/*.js'],
    languageOptions: { ecmaVersion: 2023, sourceType: 'module' },
    rules: bugRules,
  },
];
