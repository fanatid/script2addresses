var secp256k1 = require('secp256k1')

/**
 * @param {Buffer} buf
 * @param {boolean} [strict=false]
 * @return {boolean}
 */
module.exports = function (buf, strict) {
  if (!strict) {
    switch (buf[0]) {
      case 0x02:
      case 0x03:
        return buf.length === 33
      case 0x04:
      case 0x06:
      case 0x07:
        return buf.length === 65
      default:
        return false
    }
  }

  return secp256k1.publicKeyVerify(buf)
}
