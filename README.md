# script2addresses

[![NPM Package](https://img.shields.io/npm/v/script2addresses.svg?style=flat-square)](https://www.npmjs.org/package/script2addresses)
[![Build Status](https://img.shields.io/travis/fanatid/script2addresses.svg?branch=master&style=flat-square)](https://travis-ci.org/fanatid/script2addresses)
[![Coverage Status](https://img.shields.io/coveralls/fanatid/script2addresses.svg?style=flat-square)](https://coveralls.io/r/fanatid/script2addresses)
[![Dependency status](https://img.shields.io/david/fanatid/script2addresses.svg?style=flat-square)](https://david-dm.org/fanatid/script2addresses#info=dependencies)
[![Dev Dependency status](https://img.shields.io/david/fanatid/script2addresses.svg?style=flat-square)](https://david-dm.org/fanatid/script2addresses#info=devDependencies)

[![js-standard-style](https://cdn.rawgit.com/feross/standard/master/badge.svg)](https://github.com/feross/standard)

## Installation

```
npm install script2addresses
```

## Examples

```js
var script2addresses = require('script2addresses')
var bitcoin = require('bitcoinjs-lib')

var script = bitcoin.script.fromASM('OP_2 032069e003dcc548bc7de5e2623a3f3716873cd08764f1ab9e16fc1ca69bee6aa5 0386acd4c6ffd015e71c0e3f535c3b6e70a777908cc31695de660846c87cf88ef3 OP_2 OP_CHECKMULTISIG')
console.log(script2addresses(script))
// {
//   type: 'multisig',
//   addresses: [
//     '17FpX7QDJTpUyd6C7Rk9CywBKs5CyAznvd',
//     '16kUTyxJhwcX1zehx4EY7j2ovHs7U35nyq'
//   ]
// }
```

## License

Code released under [the MIT license](LICENSE).
