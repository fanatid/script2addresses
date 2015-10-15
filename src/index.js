import bitcore from 'bitcore'

let Address = bitcore.Address
let base58encode = bitcore.encoding.Base58Check.encode
let Networks = bitcore.Networks
let Opcode = bitcore.Opcode
let Script = bitcore.Script
let sha256ripemd160 = bitcore.crypto.Hash.sha256ripemd160

/**
 * @param {number} version
 * @param {Buffer} hashBuffer
 * @return {string}
 */
function createAddress (version, hashBuffer) {
  let versionBuffer = new Buffer([version])
  let buffer = Buffer.concat([versionBuffer, hashBuffer])
  return base58encode(buffer)
}

/**
 * @param {Buffer} buffer
 * @param {boolean} strict
 * @return {boolean}
 */
function isPublicKey (buffer, strict) {
  if (!buffer) {
    return false
  }

  switch (buffer[0]) {
    case 0x02:
    case 0x03:
      return buffer.length === 33
    case 0x04:
      return buffer.length === 65
    case 0x06:
    case 0x07:
      return !strict && buffer.length === 65
    default:
      return false
  }
}

/**
 * @param {*} script
 * @param {*} [network=bitcore.Networks.defaultNetwork]
 * @param {boolean} [strict=false]
 * @return {{type: string, addresses: Array.<string>}}
 */
export default function (script, network, strict) {
  try {
    script = new Script(script)
  } catch (err) {
    return {type: 'unknow'}
  }

  let sChunks = script.chunks
  if (sChunks.length === 0) {
    return {type: 'unknow'}
  }

  network = network || Networks.get(network) || Networks.defaultNetwork
  switch (sChunks[0].opcodenum) {
    // pubkeyhash
    case Opcode.OP_DUP:
      if (!(sChunks.length === 5 &&
            sChunks[1].opcodenum === Opcode.OP_HASH160 &&
            sChunks[2].buf &&
            sChunks[2].buf.length === 20 &&
            sChunks[3].opcodenum === Opcode.OP_EQUALVERIFY &&
            sChunks[4].opcodenum === Opcode.OP_CHECKSIG) ||
          (strict && sChunks[2].opcodenum !== 20)) {
        return {type: 'unknow'}
      }

      return {
        type: 'pubkeyhash',
        addresses: [
          createAddress(network[Address.PayToPublicKeyHash], sChunks[2].buf)
        ]
      }

    // scripthash
    case Opcode.OP_HASH160:
      if (!(sChunks.length === 3 &&
            sChunks[1].buf &&
            sChunks[1].buf.length === 20 &&
            sChunks[2].opcodenum === Opcode.OP_EQUAL) ||
          (strict && sChunks[1].opcodenum !== 20)) {
        return {type: 'unknow'}
      }

      return {
        type: 'scripthash',
        addresses: [
          createAddress(network[Address.PayToScriptHash], sChunks[1].buf)
        ]
      }

    // nulldata
    case Opcode.OP_RETURN:
      return {type: 'nulldata'}

    // pubkey & multisig
    default:
      // pubkey
      if ((sChunks.length === 2 &&
           isPublicKey(sChunks[0].buf, strict) &&
           sChunks[1].opcodenum === Opcode.OP_CHECKSIG) &&
          !(strict &&
            sChunks[0].opcodenum !== 33 &&
            sChunks[0].opcodenum !== 65)) {
        let hashBuffer = sha256ripemd160(sChunks[0].buf)
        return {
          type: 'pubkey',
          addresses: [
            createAddress(network[Address.PayToPublicKeyHash], hashBuffer)
          ]
        }
      }

      // multisig
      let mOp = sChunks[0].opcodenum
      let nOp = sChunks[Math.max(sChunks.length - 2, 0)].opcodenum
      if (sChunks.length >= 4 &&
          sChunks[sChunks.length - 1].opcodenum === Opcode.OP_CHECKMULTISIG &&
          mOp >= Opcode.OP_1 &&
          mOp <= Opcode.OP_16 &&
          nOp >= Opcode.OP_1 &&
          nOp <= Opcode.OP_16 &&
          nOp >= mOp &&
          nOp - Opcode.OP_1 === sChunks.length - 4 &&
          sChunks.slice(1, -2).every((o) => isPublicKey(o.buf, strict))) {
        let addresses = sChunks.slice(1, -2).map((o) => {
          let hashBuffer = sha256ripemd160(o.buf)
          return createAddress(network[Address.PayToPublicKeyHash], hashBuffer)
        })
        return {
          type: 'multisig',
          addresses: addresses.filter((addr, index) => {
            return addresses.indexOf(addr) === index
          })
        }
      }

      // unknow output script type
      return {type: 'unknow'}
  }
}
