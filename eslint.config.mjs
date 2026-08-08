// One rule, on purpose: no-undef.
//
// On 2026-08-08 the production relay had restarted 425 times. The cause was a
// single line in an hourly setInterval that swept a Map called
// trialIpRequests, a per-IP trial limiter that had been removed. The name was
// never declared, so every hour the callback threw a ReferenceError, the
// uncaughtException handler shut the relay down and the container came back up.
// The site was briefly dead, every hour, for roughly eighteen days.
//
// Nothing caught it. node --check parses, it does not resolve names. The unit
// suites never run an hourly timer. The heartbeat looks at pages, and a relay
// that is up again two seconds later looks healthy. A dead name inside a timer
// is invisible to every gate we had, and loud to a scope analyser.
//
// So: no style rules, no opinions, no reformatting of 6000 lines. Just the one
// question those gates could not answer. Does every name this code uses
// actually exist?
export default [
  {
    // Hand-written server code only. The vendored bundles (pqc, wasm glue) are
    // generated, single-line, and full of browser globals: linting them says
    // nothing about code anyone edits.
    files: ['relay/*.js', 'relay/lib/*.js', 'admin/*.js', 'admin/lib/*.js'],
    ignores: ['**/node_modules/**', 'relay/lib/paramant-pqc.js', '**/*.min.js'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'commonjs',
      globals: {
        require: 'readonly', module: 'writable', exports: 'writable',
        process: 'readonly', console: 'readonly', Buffer: 'readonly',
        __dirname: 'readonly', __filename: 'readonly', global: 'readonly',
        setTimeout: 'readonly', clearTimeout: 'readonly',
        setInterval: 'readonly', clearInterval: 'readonly',
        setImmediate: 'readonly', queueMicrotask: 'readonly',
        URL: 'readonly', URLSearchParams: 'readonly', TextEncoder: 'readonly',
        TextDecoder: 'readonly', AbortController: 'readonly', AbortSignal: 'readonly',
        fetch: 'readonly', Headers: 'readonly', Request: 'readonly', Response: 'readonly',
        Blob: 'readonly', FormData: 'readonly', WebAssembly: 'readonly',
        crypto: 'readonly', structuredClone: 'readonly', performance: 'readonly',
      },
    },
    linterOptions: { reportUnusedDisableDirectives: true },
    rules: { 'no-undef': 'error' },
  },
];
