const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const CopyWebpackPlugin = require('copy-webpack-plugin');

module.exports = (env, argv) => {
  const isDev = argv.mode === 'development';

  return {
    entry: {
      taskpane: './src/taskpane/taskpane.js',
      commands: './src/commands/commands.js',
    },
    output: {
      path: path.resolve(__dirname, 'dist'),
      // Content hash in the name: addin.paramant.app caches .js for 7 days
      // (deploy/nginx/addin.paramant.app.conf), so a fixed name kept the old
      // build in Outlook for a week after a deploy (fase 1, EXT-16-H).
      filename: isDev ? '[name].js' : '[name].[contenthash:8].js',
      clean: true,
    },
    devtool: isDev ? 'source-map' : false,
    devServer: {
      port: 3000,
      https: true,
      static: path.resolve(__dirname, 'dist'),
    },
    plugins: [
      new HtmlWebpackPlugin({
        filename: 'taskpane.html',
        template: './src/taskpane/taskpane.html',
        chunks: ['taskpane'],
      }),
      new HtmlWebpackPlugin({
        filename: 'commands.html',
        template: './src/commands/commands.html',
        chunks: ['commands'],
      }),
      new CopyWebpackPlugin({
        patterns: [
          { from: 'assets', to: 'assets' },
          { from: '_locales', to: '_locales' },
          { from: 'manifest.xml', to: 'manifest.xml' },
          { from: 'src/taskpane/taskpane.css', to: 'taskpane.css' },
        ],
      }),
    ],
    module: {
      rules: [
        {
          test: /\.css$/,
          use: ['style-loader', 'css-loader'],
        },
      ],
    },
  };
};
