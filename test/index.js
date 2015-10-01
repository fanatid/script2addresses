import { expect } from 'chai'
import bitcore from 'bitcore'

import script2addresses from '../src'

let Address = bitcore.Address
let sha256ripemd160 = bitcore.crypto.Hash.sha256ripemd160

describe('script2addresses', () => {
  let pk = bitcore.PrivateKey.fromRandom().toPublicKey()
  let pkHex = pk.toString()
  let pkHash = sha256ripemd160(pk.toBuffer()).toString('hex')
  let pkhAddress = new Address(pk, null, Address.PayToPublicKeyHash)
  let pshAddress = Address.fromScriptHash(new Buffer(pkHash, 'hex'))

  describe('pubkeyhash', () => {
    it('OP_DUP OP_HASH 20 0x{data} OP_EQUALVERIFY OP_CHECKSIG', () => {
      let script = `OP_DUP OP_HASH160 20 0x${pkHash} OP_EQUALVERIFY OP_CHECKSIG`
      expect(script2addresses(script)).to.deep.equal({
        type: 'pubkeyhash',
        addresses: [pkhAddress.toString()]
      })
    })

    it('OP_DUP OP_HASH 20 0x{data} OP_EQUALVERIFY OP_CHECKSIG (strict)', () => {
      let script = `OP_DUP OP_HASH160 20 0x${pkHash} OP_EQUALVERIFY OP_CHECKSIG`
      expect(script2addresses(script, null, true)).to.deep.equal({
        type: 'pubkeyhash',
        addresses: [pkhAddress.toString()]
      })
    })

    it('OP_DUP OP_HASH160 OP_PUSHDATA1 20 0x{data} OP_EQUALVERIFY OP_CHECKSIG', () => {
      let script = `OP_DUP OP_HASH160 OP_PUSHDATA1 20 0x${pkHash} OP_EQUALVERIFY OP_CHECKSIG`
      expect(script2addresses(script)).to.deep.equal({
        type: 'pubkeyhash',
        addresses: [pkhAddress.toString()]
      })
    })

    it('OP_DUP OP_HASH160 OP_PUSHDATA1 20 0x{data} OP_EQUALVERIFY OP_CHECKSIG (strict)', () => {
      let script = `OP_DUP OP_HASH160 OP_PUSHDATA1 20 0x${pkHash} OP_EQUALVERIFY OP_CHECKSIG`
      expect(script2addresses(script, null, true)).to.deep.equal({type: 'unknow'})
    })
  })

  describe('scripthash', () => {
    it(`OP_HASH160 20 0x{data} OP_EQUAL`, () => {
      let script = `OP_HASH160 20 0x${pkHash} OP_EQUAL`
      expect(script2addresses(script)).to.deep.equal({
        type: 'scripthash',
        addresses: [pshAddress.toString()]
      })
    })

    it(`OP_HASH160 20 0x{data} OP_EQUAL (strict)`, () => {
      let script = `OP_HASH160 20 0x${pkHash} OP_EQUAL`
      expect(script2addresses(script, null, true)).to.deep.equal({
        type: 'scripthash',
        addresses: [pshAddress.toString()]
      })
    })

    it(`OP_HASH160 OP_PUSHDATA1 20 0x{data} OP_EQUAL`, () => {
      let script = `OP_HASH160 OP_PUSHDATA1 20 0x${pkHash} OP_EQUAL`
      expect(script2addresses(script)).to.deep.equal({
        type: 'scripthash',
        addresses: [pshAddress.toString()]
      })
    })

    it(`OP_HASH160 OP_PUSHDATA1 20 0x{data} OP_EQUAL (strict)`, () => {
      let script = `OP_HASH160 OP_PUSHDATA1 20 0x${pkHash} OP_EQUAL`
      expect(script2addresses(script, null, true)).to.deep.equal({type: 'unknow'})
    })
  })

  describe('nulldata', () => {
    it('OP_RETURN', () => {
      let script = `OP_RETURN`
      expect(script2addresses(script)).to.deep.equal({type: 'nulldata'})
    })
  })

  describe('pubkey', () => {
    it('33 0x{data} OP_CHECKSIG', () => {
      let script = `33 0x${pkHex} OP_CHECKSIG`
      expect(script2addresses(script)).to.deep.equal({
        type: 'pubkey',
        addresses: [pkhAddress.toString()]
      })
    })

    it('33 0x{data} OP_CHECKSIG (strict)', () => {
      let script = `33 0x${pkHex} OP_CHECKSIG`
      expect(script2addresses(script, null, true)).to.deep.equal({
        type: 'pubkey',
        addresses: [pkhAddress.toString()]
      })
    })

    it('OP_PUSHDATA1 33 0x{data} OP_CHECKSIG', () => {
      let script = `OP_PUSHDATA1 33 0x${pkHex} OP_CHECKSIG`
      expect(script2addresses(script)).to.deep.equal({
        type: 'pubkey',
        addresses: [pkhAddress.toString()]
      })
    })

    it('OP_PUSHDATA1 33 0x{data} OP_CHECKSIG (strict)', () => {
      let script = `OP_PUSHDATA1 33 0x${pkHex} OP_CHECKSIG`
      expect(script2addresses(script, null, true)).to.deep.equal({type: 'unknow'})
    })
  })

  describe('multisig', () => {
    it('OP_2 33 0x{data} 33 0x{data} OP_2 OP_CHECKMULTISIG', () => {
      let script = `OP_2 33 0x${pkHex} 33 0x${pkHex} OP_2 OP_CHECKMULTISIG`
      expect(script2addresses(script)).to.deep.equal({
        type: 'multisig',
        addresses: [pkhAddress.toString()]
      })
    })

    it('OP_1 33 0x{data} OP_2 OP_CHECKMULTISIG', () => {
      let script = `OP_1 33 0x${pkHex} OP_2 OP_CHECKMULTISIG`
      expect(script2addresses(script)).to.deep.equal({type: 'unknow'})
    })

    it('OP_1 65 0x{data} OP_1 OP_CHECKMULTISIG (strict)', () => {
      let script = `OP_1 65 0x06${new Buffer(64).toString('hex')} OP_1 OP_CHECKMULTISIG`
      expect(script2addresses(script, null, true)).to.deep.equal({type: 'unknow'})
    })
  })
})
