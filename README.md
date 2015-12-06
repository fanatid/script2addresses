# script2addresses

[![NPM Package](https://img.shields.io/npm/v/script2addresses.svg?style=flat-square)](https://www.npmjs.org/package/script2addresses)
[![Build Status](https://img.shields.io/travis/fanatid/script2addresses.svg?branch=master&style=flat-square)](https://travis-ci.org/fanatid/script2addresses)
[![Coverage Status](https://img.shields.io/coveralls/fanatid/script2addresses.svg?style=flat-square)](https://coveralls.io/r/fanatid/script2addresses)
[![js-standard-style](https://img.shields.io/badge/code%20style-standard-brightgreen.svg?style=flat-square)](https://github.com/feross/standard)
[![Dependency status](https://img.shields.io/david/fanatid/script2addresses.svg?style=flat-square)](https://david-dm.org/fanatid/script2addresses#info=dependencies)

## Installation

```
npm install script2addresses
```

## Script type and addresses

  - [`pubkey`](#pubkey)
  - [`pubkeyhash`](#pubkeyhash)
  - [`scripthash`](#scripthash)
  - [`multisig`](#multisig)

#####`pubkey`

{PublicKey} OP_CHECKSIG

\**This is only public key, but we can derive P2PKH address*

#####`pubkeyhash`

OP_DUP OP_HASH160 {PublicKeyHash} OP_EQUALVERIFY OP_CHECKSIG

#####`scripthash`

OP_HASH160 {scriptHash} OP_EQUAL

#####`multisig`

m [PublicKeys ...] n OP_CHECKMULTISIG

\**This is only public keys, but we can derive P2PKH addresses*

## API

 - [`script2addresses`](#script2addresses)

----

#####`script2addresses`

Arguments:

  * `script` - output script as string or buffer
  * `network` - network params or string (livenet, mainnet, testnet), mainnet by default
  * `strict` - not allow pushdata opcodes in script, false by default

Returns an object with the following keys:
  * `type` - output script type: unknow, nulldata, pubkeyhash, scripthash, pubkey or multisig
  * `addresses` - array of strings

## Example

```js
var script2addresses = require('script2addresses')

// OP_2 032069e003dcc548bc7de5e2623a3f3716873cd08764f1ab9e16fc1ca69bee6aa5 0386acd4c6ffd015e71c0e3f535c3b6e70a777908cc31695de660846c87cf88ef3 OP_2 OP_CHECKMULTISIG'
var script = '5221032069e003dcc548bc7de5e2623a3f3716873cd08764f1ab9e16fc1ca69bee6aa5210386acd4c6ffd015e71c0e3f535c3b6e70a777908cc31695de660846c87cf88ef352ae'
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

This software is licensed under the MIT License.
