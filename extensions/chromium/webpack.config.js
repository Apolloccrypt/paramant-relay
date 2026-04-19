const path = require('path');
const CopyPlugin = require('copy-webpack-plugin');

module.exports = (env, argv) => ({
  mode: argv.mode || 'development',
  devtool: argv.mode === 'production' ? false : 'cheap-source-map',

  entry: {
    'background/service-worker': './src/background/service-worker.js',
    'content/gmail':             './src/content/gmail.js',
    'content/outlook':           './src/content/outlook.js',
    'content/shared/banner':     './src/content/shared/banner.js',
    'popup/popup':               './src/popup/popup.js',
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
        { from: 'src/content/shared/banner.css', to: 'content/shared/banner.css' },
        { from: 'icons',                         to: 'icons' },
        { from: '_locales',                      to: '_locales' },
      ],
    }),
  ],

  optimization: { runtimeChunk: false },
});
