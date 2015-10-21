var createHash = require('create-hash')
var bs58check = require('bs58check')

var networks = require('./networks.json')
var opcodes = require('./opcodes.json')
var isPublicKey = require('./publickey')

/**
 * @param {Buffer} buf
 * @return {Buffer}
 */
function sha256ripemd160 (buf) {
  buf = createHash('sha256').update(buf).digest()
  return createHash('ripemd160').update(buf).digest()
}

/**
 * @param {number} version
 * @param {Buffer} hashBuffer
 * @return {string}
 */
function createAddress (version, hashBuffer) {
  var versionBuffer = new Buffer([version])
  var buffer = Buffer.concat([versionBuffer, hashBuffer])
  return bs58check.encode(buffer)
}

/**
 * @param {Buffer} buf
 * @param {number} offset
 * @param {boolean} strict
 * @return {?{bytes: number, size: number}}
 */
function readDataSize (buf, offset, strict) {
  var opcode = buf[offset]

  if ((strict && opcode >= opcodes.OP_PUSHDATA1) ||
      opcode > opcodes.OP_PUSHDATA4 ||
      buf.length < offset + opcode - opcodes.OP_PUSHDATA1 + (opcode === opcodes.OP_PUSHDATA4 ? 3 : 2)) {
    return null
  }

  switch (opcode) {
    case opcodes.OP_PUSHDATA4:
      return {bytes: 5, size: buf.readUInt32LE(offset + 1)}
    case opcodes.OP_PUSHDATA2:
      return {bytes: 3, size: buf.readUInt16LE(offset + 1)}
    case opcodes.OP_PUSHDATA1:
      return {bytes: 2, size: buf.readUInt8(offset + 1)}
    default:
      return {bytes: 1, size: opcode}
  }
}

/**
 * @param {(Buffer|string)} buf
 * @param {({pubkeyhash: number, scripthash: number}|string)} [network={pubkeyhash: 0x80, scripthash: 0x05}]
 * @param {boolean} [strict=false]
 * @return {{type: string, addresses: Array.<string>}}
 */
module.exports = function (buf, network, strict) {
  if (!Buffer.isBuffer(buf)) {
    try {
      buf = new Buffer(buf, 'hex')
    } catch (err) {
      return {type: 'unknow', addresses: []}
    }
  }

  if (Object.prototype.toString.call(network) === '[object String]') {
    network = networks[network]
  }

  if (Object.prototype.toString.call(network) !== '[object Object]') {
    network = networks.mainnet
  }

  var dataSize
  switch (buf[0]) {
    // pubkeyhash
    case opcodes.OP_DUP:
      if (buf.length < 25 ||
          buf.length > (strict ? 25 : 29) ||
          buf[1] !== opcodes.OP_HASH160 ||
          buf[buf.length - 2] !== opcodes.OP_EQUALVERIFY ||
          buf[buf.length - 1] !== opcodes.OP_CHECKSIG) {
        break
      }

      dataSize = readDataSize(buf, 2, strict)
      if (dataSize === null || dataSize.size !== 20) {
        break
      }

      buf = buf.slice(2 + dataSize.bytes, buf.length - 2)
      return {
        type: 'pubkeyhash',
        addresses: [createAddress(network.pubkeyhash, buf)]
      }

    // scripthash
    case opcodes.OP_HASH160:
      if (buf.length < 23 ||
          buf.length > (strict ? 23 : 27) ||
          buf[buf.length - 1] !== opcodes.OP_EQUAL) {
        break
      }

      dataSize = readDataSize(buf, 1, strict)
      if (dataSize === null || dataSize.size !== 20) {
        break
      }

      buf = buf.slice(1 + dataSize.bytes, buf.length - 1)
      return {
        type: 'scripthash',
        addresses: [createAddress(network.scripthash, buf)]
      }

    // nulldata
    case opcodes.OP_RETURN:
      return {type: 'nulldata', addresses: []}

    // pubkey & multisig
    default:
      // pubkey
      if (buf[buf.length - 1] === opcodes.OP_CHECKSIG) {
        dataSize = readDataSize(buf, 0, strict)
        if (dataSize === null) {
          break
        }

        buf = buf.slice(dataSize.bytes, buf.length - 1)
        if (!isPublicKey(buf, strict)) {
          break
        }

        return {
          type: 'pubkey',
          addresses: [createAddress(network.pubkeyhash, sha256ripemd160(buf))]
        }
      }

      // multisig
      var mOp = buf[0]
      var nOp = buf[buf.length - 2]
      var isMultisig = (buf[buf.length - 1] === opcodes.OP_CHECKMULTISIG &&
                        mOp >= opcodes.OP_1 &&
                        nOp <= opcodes.OP_16 &&
                        nOp >= mOp)

      var pubKeys = []
      for (var offset = 1, stop = buf.length - 2; isMultisig && offset < stop;) {
        dataSize = readDataSize(buf, offset, strict)
        if (dataSize === null) {
          isMultisig = false
        } else {
          pubKeys.push(buf.slice(offset + dataSize.bytes, offset + dataSize.bytes + dataSize.size))
          isMultisig = isPublicKey(pubKeys[pubKeys.length - 1], strict)
          offset += dataSize.bytes + dataSize.size
        }
      }

      if (isMultisig && pubKeys.length === nOp - opcodes.OP_1 + 1) {
        var addresses = pubKeys.map(function (pubKey) {
          return createAddress(network.pubkeyhash, sha256ripemd160(pubKey))
        })
        return {
          type: 'multisig',
          addresses: addresses.filter(function (addr, index) {
            return addresses.indexOf(addr) === index
          })
        }
      }
  }

  // unknow output script type
  return {type: 'unknow', addresses: []}
}
