const path = require('path');

module.exports = {
    entry: {
        "boa-sodium": "./src/index.ts",
        "boa-sodium.min": "./src/index.ts",
    },
    devtool: 'source-map',
    module: {
        rules: [
            {
                test: /\.ts?$/,
                use: 'ts-loader',
                exclude: /node_modules/,
            },
        ],
    },
    resolve: {
        extensions: [ '.ts', '.js' ],
    },
    output: {
        filename: "[name].js",
        path: path.resolve(__dirname, "dist"),
        library: "BoaSdk",
        umdNamedDefine: true,
    },
    node: {fs: "empty"}
};
