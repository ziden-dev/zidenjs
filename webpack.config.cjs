const path = require('path');
const webpack = require('webpack');
module.exports = {
  entry: path.resolve(__dirname, 'src', 'index.ts'),
  module: {
    rules: [
      {
        test: /\.tsx?$/,
        use: 'ts-loader',
        exclude: /node_modules/,
      },
    ],
  },
  resolve: {
    extensions: ['.ts', '.js'],
    fallback: {
      assert: require.resolve('assert'),
      buffer: require.resolve('buffer'),
      path: require.resolve('path-browserify'),
      os: require.resolve('os-browserify/browser'),
      constants: require.resolve('constants-browserify'),
      crypto: require.resolve('crypto-browserify'),
      stream: require.resolve('stream-browserify'),
      process: false,
    },
  },
  output: {
    filename: 'bundle.js',
    path: path.resolve(__dirname, 'dist'),
    library: {
      name: 'ziden',
      type: 'umd'
    },
  },
  plugins: [
    new webpack.ProvidePlugin({
      process: 'process/browser',
      Buffer: ['buffer', 'Buffer'],
    }),
  ],
};
