const path = require('path');
const CopyPlugin = require('copy-webpack-plugin');

module.exports = (env, argv) => ({
  mode: argv.mode || 'development',
  devtool: argv.mode === 'production' ? false : 'cheap-source-map',

  entry: {
    'background/service-worker': './src/background/service-worker.js',
    'content/gmail':             './src/content/gmail.js',
    'content/outlook':           './src/content/outlook.js',
    'popup/popup':               './src/popup/popup.js',
    'options/options':           './src/options/options.js',
  },

  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: '[name].js',
    clean: true,
  },

  plugins: [
    new CopyPlugin({
      patterns: [
        { from: 'manifest.json' },
        { from: 'src/popup/popup.html',          to: 'popup/popup.html' },
        { from: 'src/popup/popup.css',           to: 'popup/popup.css' },
        { from: 'src/options/options.html',      to: 'options/options.html' },
        { from: 'src/options/options.css',       to: 'options/options.css' },
        { from: 'src/content/shared/banner.css', to: 'content/shared/banner.css' },
        { from: 'icons',                         to: 'icons' },
        { from: '_locales',                      to: '_locales' },
      ],
    }),
  ],

  // Each entry must be a self-contained classic script: content scripts and the MV3
  // service worker cannot pull in separate chunks at runtime.
  optimization: { runtimeChunk: false, splitChunks: false },
});
