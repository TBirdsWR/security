const path = require('path');
const webpack = require('webpack');

module.exports = {
    entry: {
        smAlg: './src/smAlg/index.js',
    },
    output: {
        path: path.resolve(__dirname, 'dist'),
        filename: '[name].js',
        library: '[name]',
        libraryTarget: 'window',
    },
    module: {    
        loaders: [{    
            test: /\.js$/,    
            exclude: /node_modules/,    
            loader: 'babel-loader'    
        }]    
    },
    plugins: [
        new webpack.optimize.UglifyJsPlugin(),
    ]
};
