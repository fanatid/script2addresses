var expect = require('chai').expect
var crypto = require('crypto')
var EC = require('elliptic').ec
var bitcoin = require('bitcoinjs-lib')
var bs58check = require('bs58check')

var script2addresses = require('../src')
var isPublicKey = require('../src/publickey')

var ec = new EC('secp256k1')

/**
 * @param {string} s
 * @return {string}
 */
function asm2hex (s) {
  return bitcoin.script.fromASM(s).toString('hex')
}

/**
 * @param {number} [version=0x03]
 * @param {number} [compressed=true]
 * @return {string}
 */
function makeRandom (version, compressed) {
  if (version === undefined) {
    version = 0x03
  }

  if (compressed === undefined) {
    compressed = true
  }

  // probably can return invalid key
  var pk = Buffer.concat([
    new Buffer([version]),
    new Buffer(ec.genKeyPair().getPublic(compressed, 'hex'), 'hex').slice(1)])
  return pk.toString('hex')
}

/**
 * @param {string} pkHex
 * @return {string}
 */
function makeHash (pkHex) {
  return bitcoin.crypto.hash160(new Buffer(pkHex, 'hex')).toString('hex')
}

/**
 * @param {string} hash
 * @return {string}
 */
function makeP2PKHAddress (hash) {
  return bs58check.encode(Buffer.concat([
    new Buffer([bitcoin.networks.bitcoin.pubKeyHash]), new Buffer(hash, 'hex')]))
}

/**
 * @param {string} hash
 * @return {string}
 */
function makeP2SHAddress (hash) {
  return bs58check.encode(Buffer.concat([
    new Buffer([bitcoin.networks.bitcoin.scriptHash]), new Buffer(hash, 'hex')]))
}

describe('isPublicKey', function () {
  describe('strict', function () {
    it('version is 0x01, length is 33', function () {
      var publicKey = new Buffer(makeRandom(0x01, true), 'hex')
      expect(isPublicKey(publicKey, true)).to.be.false
    })

    it('version is 0x05, length is 65', function () {
      var publicKey = new Buffer(makeRandom(0x05, false), 'hex')
      expect(isPublicKey(publicKey, true)).to.be.false
    })

    it('invalid point because x is zero', function () {
      var publicKey = new Buffer(33)
      publicKey[0] = 2
      publicKey.fill(0, 1)
      expect(isPublicKey(publicKey, true)).to.be.false
    })

    it('invalid point because x greater then p', function () {
      var publicKey = new Buffer('03fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30', 'hex')
      expect(isPublicKey(publicKey, true)).to.be.false
    })

    it('invalid point because y is bad', function () {
      var publicKey = new Buffer(makeRandom(0x04, false), 'hex')
      publicKey[publicKey.length - 1] += 1
      expect(isPublicKey(publicKey, true)).to.be.false
    })

    it('invalid point because y is not odd', function () {
      var pair = ec.genKeyPair()
      var publicKey = new Buffer(pair.getPublic(false, 'hex'), 'hex')
      publicKey[0] = pair.getPublic().y.isOdd() ? 0x06 : 0x07
      expect(isPublicKey(publicKey, true)).to.be.false
    })

    it('valid point (compressed)', function () {
      var publicKey = new Buffer(makeRandom(0x03, true), 'hex')
      expect(isPublicKey(publicKey, true)).to.be.true
    })

    it('valid point (uncompressed)', function () {
      var publicKey = new Buffer(makeRandom(0x04, false), 'hex')
      expect(isPublicKey(publicKey, true)).to.be.true
    })
  })

  describe('not strict', function () {
    it('version is 0x01, length is 33', function () {
      var publicKey = new Buffer(makeRandom(0x01, true), 'hex')
      expect(isPublicKey(publicKey, false)).to.be.false
    })

    it('version is 0x02, length is 65', function () {
      var publicKey = new Buffer(makeRandom(0x02, false), 'hex')
      expect(isPublicKey(publicKey, false)).to.be.false
    })

    it('version is 0x03, length is 33', function () {
      var publicKey = new Buffer(makeRandom(0x03, true), 'hex')
      expect(isPublicKey(publicKey, false)).to.be.true
    })

    it('version is 0x04, length is 33', function () {
      var publicKey = new Buffer(makeRandom(0x04, true), 'hex')
      expect(isPublicKey(publicKey, false)).to.be.false
    })

    it('version is 0x06, length is 65', function () {
      var publicKey = new Buffer(makeRandom(0x06, false), 'hex')
      expect(isPublicKey(publicKey, false)).to.be.true
    })

    it('version is 0x07, length is 65', function () {
      var publicKey = new Buffer(makeRandom(0x07, false), 'hex')
      expect(isPublicKey(publicKey, false)).to.be.true
    })
  })
})

describe('script2addresses', function () {
  describe('arguments', function () {
    it('not a buffer and neither a string', function () {
      expect(script2addresses()).to.deep.equal({type: 'unknow', addresses: []})
    })

    it('apply to buffer', function () {
      var pkHex = makeRandom()
      var script = asm2hex(pkHex + ' OP_CHECKSIG')
      expect(script2addresses(new Buffer(script, 'hex'), 'mainnet')).to.deep.equal({
        type: 'pubkey',
        addresses: [makeP2PKHAddress(makeHash(pkHex))]
      })
    })

    it('network as string', function () {
      var pkHex = makeRandom()
      var script = asm2hex(pkHex + ' OP_CHECKSIG')
      expect(script2addresses(script, 'mainnet')).to.deep.equal({
        type: 'pubkey',
        addresses: [makeP2PKHAddress(makeHash(pkHex))]
      })
    })
  })

  describe('pubkeyhash', function () {
    it('OP_DUP OP_HASH160 {data} OP_EQUALVERIFY OP_CHECKSIG', function () {
      var pkHex = makeRandom()
      var script = asm2hex('OP_DUP OP_HASH160 ' + makeHash(pkHex) + ' OP_EQUALVERIFY OP_CHECKSIG')
      expect(script2addresses(script)).to.deep.equal({
        type: 'pubkeyhash',
        addresses: [makeP2PKHAddress(makeHash(pkHex))]
      })
    })

    it('OP_DUP OP_HASH160 {data} OP_EQUALVERIFY OP_CHECKSIG (strict)', function () {
      var pkHex = makeRandom()
      var script = asm2hex('OP_DUP OP_HASH160 ' + makeHash(pkHex) + ' OP_EQUALVERIFY OP_CHECKSIG')
      expect(script2addresses(script, null, true)).to.deep.equal({
        type: 'pubkeyhash',
        addresses: [makeP2PKHAddress(makeHash(pkHex))]
      })
    })

    it('OP_DUP OP_HASH160 OP_PUSHDATA1 {data} OP_EQUALVERIFY OP_CHECKSIG', function () {
      var pkHex = makeRandom()
      var script = asm2hex('OP_DUP OP_HASH160 OP_PUSHDATA1 ' + makeHash(pkHex) + ' OP_EQUALVERIFY OP_CHECKSIG')
      expect(script2addresses(script)).to.deep.equal({
        type: 'pubkeyhash',
        addresses: [makeP2PKHAddress(makeHash(pkHex))]
      })
    })

    it('OP_DUP OP_HASH160 OP_PUSHDATA1 {data (19 bytes)} OP_EQUALVERIFY OP_CHECKSIG', function () {
      var script = asm2hex('OP_DUP OP_HASH160 OP_PUSHDATA1 ' + crypto.randomBytes(19).toString('hex') + ' OP_EQUALVERIFY OP_CHECKSIG')
      expect(script2addresses(script)).to.deep.equal({
        type: 'unknow',
        addresses: []
      })
    })

    it('OP_DUP OP_HASH160 OP_PUSHDATA1 {data} OP_EQUALVERIFY OP_CHECKSIG (strict)', function () {
      var pkHex = makeRandom()
      var script = asm2hex('OP_DUP OP_HASH160 OP_PUSHDATA1 ' + makeHash(pkHex) + ' OP_EQUALVERIFY OP_CHECKSIG')
      expect(script2addresses(script, null, true)).to.deep.equal({
        type: 'unknow',
        addresses: []
      })
    })

    it('OP_DUP OP_HASH160 OP_PUSHDATA2 {data} OP_EQUALVERIFY OP_CHECKSIG', function () {
      var pkHex = makeRandom()
      var script = asm2hex('OP_DUP OP_HASH160 OP_PUSHDATA2 ' + makeHash(pkHex) + ' OP_EQUALVERIFY OP_CHECKSIG')
      script = script.slice(0, 8) + '00' + script.slice(8)
      expect(script2addresses(script)).to.deep.equal({
        type: 'pubkeyhash',
        addresses: [makeP2PKHAddress(makeHash(pkHex))]
      })
    })

    it('OP_DUP OP_HASH160 OP_PUSHDATA4 {data} OP_EQUALVERIFY OP_CHECKSIG', function () {
      var pkHex = makeRandom()
      var script = asm2hex('OP_DUP OP_HASH160 OP_PUSHDATA4 ' + makeHash(pkHex) + ' OP_EQUALVERIFY OP_CHECKSIG')
      script = script.slice(0, 8) + '000000' + script.slice(8)
      expect(script2addresses(script)).to.deep.equal({
        type: 'pubkeyhash',
        addresses: [makeP2PKHAddress(makeHash(pkHex))]
      })
    })
  })

  describe('scripthash', function () {
    it('OP_HASH160 {data} OP_EQUAL', function () {
      var pkHex = makeRandom()
      var script = asm2hex('OP_HASH160 ' + makeHash(pkHex) + ' OP_EQUAL')
      expect(script2addresses(script)).to.deep.equal({
        type: 'scripthash',
        addresses: [makeP2SHAddress(makeHash(pkHex))]
      })
    })

    it('OP_HASH160 {data} OP_EQUAL (strict)', function () {
      var pkHex = makeRandom()
      var script = asm2hex('OP_HASH160 ' + makeHash(pkHex) + ' OP_EQUAL')
      expect(script2addresses(script, null, true)).to.deep.equal({
        type: 'scripthash',
        addresses: [makeP2SHAddress(makeHash(pkHex))]
      })
    })

    it('OP_HASH160 OP_PUSHDATA1 {data} OP_EQUAL', function () {
      var pkHex = makeRandom()
      var script = asm2hex('OP_HASH160 OP_PUSHDATA1 ' + makeHash(pkHex) + ' OP_EQUAL')
      expect(script2addresses(script)).to.deep.equal({
        type: 'scripthash',
        addresses: [makeP2SHAddress(makeHash(pkHex))]
      })
    })

    it('OP_HASH160 OP_PUSHDATA1 {data (19 bytes)} OP_EQUAL', function () {
      var script = asm2hex('OP_HASH160 OP_PUSHDATA1 ' + crypto.randomBytes(19).toString('hex') + ' OP_EQUAL')
      expect(script2addresses(script)).to.deep.equal({
        type: 'unknow',
        addresses: []
      })
    })

    it('OP_HASH160 OP_PUSHDATA1 {data} OP_EQUAL (strict)', function () {
      var pkHex = makeRandom()
      var script = asm2hex('OP_HASH160 OP_PUSHDATA1 ' + makeHash(pkHex) + ' OP_EQUAL')
      expect(script2addresses(script, null, true)).to.deep.equal({
        type: 'unknow',
        addresses: []
      })
    })

    it('OP_HASH160 OP_PUSHDATA2 {data} OP_EQUAL', function () {
      var pkHex = makeRandom()
      var script = asm2hex('OP_HASH160 OP_PUSHDATA2 ' + makeHash(pkHex) + ' OP_EQUAL')
      script = script.slice(0, 6) + '00' + script.slice(6)
      expect(script2addresses(script)).to.deep.equal({
        type: 'scripthash',
        addresses: [makeP2SHAddress(makeHash(pkHex))]
      })
    })

    it('OP_HASH160 OP_PUSHDATA4 {data} OP_EQUAL', function () {
      var pkHex = makeRandom()
      var script = asm2hex('OP_HASH160 OP_PUSHDATA4 ' + makeHash(pkHex) + ' OP_EQUAL')
      script = script.slice(0, 6) + '000000' + script.slice(6)
      expect(script2addresses(script)).to.deep.equal({
        type: 'scripthash',
        addresses: [makeP2SHAddress(makeHash(pkHex))]
      })
    })
  })

  describe('nulldata', function () {
    it('OP_RETURN', function () {
      var script = asm2hex('OP_RETURN')
      expect(script2addresses(script)).to.deep.equal({type: 'nulldata', addresses: []})
    })

    it('OP_RETURN 48656c6c6f20776f726c6421', function () {
      var script = asm2hex('OP_RETURN 48656c6c6f20776f726c6421')
      expect(script2addresses(script)).to.deep.equal({type: 'nulldata', addresses: []})
    })
  })

  describe('pubkey', function () {
    it('{data (33 bytes)} OP_CHECKSIG', function () {
      var pkHex = makeRandom(0x03, true)
      var script = asm2hex(pkHex + ' OP_CHECKSIG')
      expect(script2addresses(script)).to.deep.equal({
        type: 'pubkey',
        addresses: [makeP2PKHAddress(makeHash(pkHex))]
      })
    })

    it('{data (65 bytes)} OP_CHECKSIG', function () {
      var pkHex = makeRandom(0x04, false)
      var script = asm2hex(pkHex + ' OP_CHECKSIG')
      expect(script2addresses(script)).to.deep.equal({
        type: 'pubkey',
        addresses: [makeP2PKHAddress(makeHash(pkHex))]
      })
    })

    it('OP_PUSHDATA1 {data} OP_CHECKSIG', function () {
      var pkHex = makeRandom()
      var script = asm2hex('OP_PUSHDATA1 ' + pkHex + ' OP_CHECKSIG')
      expect(script2addresses(script)).to.deep.equal({
        type: 'pubkey',
        addresses: [makeP2PKHAddress(makeHash(pkHex))]
      })
    })

    it('OP_PUSHDATA1 {data (32 bytes)} OP_CHECKSIG', function () {
      var script = asm2hex('OP_PUSHDATA1 ' + crypto.randomBytes(32).toString('hex') + ' OP_CHECKSIG')
      expect(script2addresses(script)).to.deep.equal({
        type: 'unknow',
        addresses: []
      })
    })

    it('OP_PUSHDATA1 {data} OP_CHECKSIG (strict)', function () {
      var pkHex = makeRandom()
      var script = asm2hex('OP_PUSHDATA1 ' + pkHex + ' OP_CHECKSIG')
      expect(script2addresses(script, null, true)).to.deep.equal({
        type: 'unknow',
        addresses: []
      })
    })

    it('OP_PUSHDATA2 {data} OP_CHECKSIG', function () {
      var pkHex = makeRandom()
      var script = asm2hex('OP_PUSHDATA2 ' + pkHex + ' OP_CHECKSIG')
      script = script.slice(0, 4) + '00' + script.slice(4)
      expect(script2addresses(script)).to.deep.equal({
        type: 'pubkey',
        addresses: [makeP2PKHAddress(makeHash(pkHex))]
      })
    })

    it('OP_PUSHDATA4 {data} OP_CHECKSIG', function () {
      var pkHex = makeRandom()
      var script = asm2hex('OP_PUSHDATA4 ' + pkHex + ' OP_CHECKSIG')
      script = script.slice(0, 4) + '000000' + script.slice(4)
      expect(script2addresses(script)).to.deep.equal({
        type: 'pubkey',
        addresses: [makeP2PKHAddress(makeHash(pkHex))]
      })
    })
  })

  describe('multisig', function () {
    it('OP_2 {data} {data} OP_2 OP_CHECKMULTISIG', function () {
      var pkHex = makeRandom()
      var script = asm2hex('OP_2 ' + pkHex + ' ' + pkHex + ' OP_2 OP_CHECKMULTISIG')
      expect(script2addresses(script)).to.deep.equal({
        type: 'multisig',
        addresses: [makeP2PKHAddress(makeHash(pkHex))]
      })
    })

    it('OP_2 {data1} {data2} OP_2 OP_CHECKMULTISIG', function () {
      var pkHex1 = makeRandom()
      var pkHex2 = makeRandom()
      var script = asm2hex('OP_2 ' + pkHex1 + ' ' + pkHex2 + ' OP_2 OP_CHECKMULTISIG')
      var result = script2addresses(script)
      expect(result).to.have.property('type', 'multisig')
      expect(result).to.have.property('addresses').to.be.an('Array')
      expect(result.addresses.sort()).to.deep.equal([
        makeP2PKHAddress(makeHash(pkHex1)),
        makeP2PKHAddress(makeHash(pkHex2))
      ].sort())
    })

    it('OP_1 OP_PUSHDATA1 {data} OP_1 OP_CHECKMULTISIG', function () {
      var pkHex = makeRandom()
      var script = asm2hex('OP_1 OP_PUSHDATA1 ' + pkHex + ' OP_1 OP_CHECKMULTISIG')
      expect(script2addresses(script)).to.deep.equal({
        type: 'multisig',
        addresses: [makeP2PKHAddress(makeHash(pkHex))]
      })
    })

    it('OP_1 OP_PUSHDATA1 {data (32 bytes)} OP_1 OP_CHECKMULTISIG', function () {
      var script = asm2hex('OP_1 OP_PUSHDATA1 ' + crypto.randomBytes(32).toString('hex') + ' OP_1 OP_CHECKMULTISIG')
      expect(script2addresses(script)).to.deep.equal({
        type: 'unknow',
        addresses: []
      })
    })

    it('OP_1 OP_PUSHDATA1 {data} OP_1 OP_CHECKMULTISIG (strict)', function () {
      var pkHex = makeRandom()
      var script = asm2hex('OP_1 OP_PUSHDATA1 ' + pkHex + ' OP_1 OP_CHECKMULTISIG')
      expect(script2addresses(script, null, true)).to.deep.equal({
        type: 'unknow',
        addresses: []
      })
    })

    it('OP_1 OP_PUSHDATA2 {data} OP_1 OP_CHECKMULTISIG', function () {
      var pkHex = makeRandom()
      var script = asm2hex('OP_1 OP_PUSHDATA2 ' + pkHex + ' OP_1 OP_CHECKMULTISIG')
      script = script.slice(0, 6) + '00' + script.slice(6)
      expect(script2addresses(script)).to.deep.equal({
        type: 'multisig',
        addresses: [makeP2PKHAddress(makeHash(pkHex))]
      })
    })

    it('OP_1 OP_PUSHDATA4 {data} OP_1 OP_CHECKMULTISIG', function () {
      var pkHex = makeRandom()
      var script = asm2hex('OP_1 OP_PUSHDATA4 ' + pkHex + ' OP_1 OP_CHECKMULTISIG')
      script = script.slice(0, 6) + '000000' + script.slice(6)
      expect(script2addresses(script)).to.deep.equal({
        type: 'multisig',
        addresses: [makeP2PKHAddress(makeHash(pkHex))]
      })
    })
  })
})
