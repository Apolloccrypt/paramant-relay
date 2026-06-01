// Flat ESLint config (ESLint 9). Lints the extension source, the shared core, and tests.
const browser = {
  chrome: 'readonly', crypto: 'readonly', fetch: 'readonly', btoa: 'readonly', atob: 'readonly',
  TextEncoder: 'readonly', TextDecoder: 'readonly', console: 'readonly',
  setTimeout: 'readonly', clearTimeout: 'readonly', setInterval: 'readonly', clearInterval: 'readonly',
  document: 'readonly', window: 'readonly', navigator: 'readonly', location: 'readonly',
  URL: 'readonly', URLSearchParams: 'readonly', Blob: 'readonly', File: 'readonly',
  FileReader: 'readonly', AbortSignal: 'readonly', AbortController: 'readonly',
  Response: 'readonly', Request: 'readonly', Headers: 'readonly', structuredClone: 'readonly',
  globalThis: 'readonly', MutationObserver: 'readonly', DataView: 'readonly',
  Uint8Array: 'readonly', ArrayBuffer: 'readonly', Event: 'readonly', Office: 'readonly',
};
const node = { Buffer: 'readonly', process: 'readonly', require: 'readonly', module: 'writable', __dirname: 'readonly' };

module.exports = [
  { ignores: ['dist/**', 'node_modules/**'] },
  {
    files: ['**/*.js'],
    languageOptions: { ecmaVersion: 2023, sourceType: 'module', globals: { ...browser, ...node } },
    rules: {
      'no-undef': 'error',
      'no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      'no-console': 'off',
      'no-empty': ['warn', { allowEmptyCatch: true }],
    },
  },
];
