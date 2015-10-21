var BN = require('bn.js')
var ec = require('elliptic').curves.secp256k1

var zero = new BN(0)

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

  var point
  if (buf.length === 65 &&
      (buf[0] === 0x04 || buf[0] === 0x06 || buf[0] === 0x07)) {
    point = ec.curve.point(buf.slice(1, 33), buf.slice(33, 65))
  } else if (buf.length === 33 &&
             (buf[0] === 0x02 || buf[0] === 0x03)) {
    point = ec.curve.pointFromX(buf.slice(1), buf[0] === 0x03)
  } else {
    return false
  }

  // Invalid x value for curve, should be 0 < x < p
  if (point.x.cmp(zero) <= 0 ||
      point.x.toString('hex', 64) !== buf.slice(1, 33).toString('hex')) {
    return false
  }

  // Only for uncompressed,
  //   make sure that given y values match with value calculated through x
  //     point.y.cmp(ec.curve.pointFromX(point.x, point.y.isOdd()).y) !== 0
  //     but point.validate() is faster
  //   y should be odd if version 0x07 or not if version is 0x06
  if (buf.length === 65 &&
      (!point.validate() ||
       (buf[0] !== 0x04 && point.y.isOdd() !== (buf[0] === 0x07)))) {
    return false
  }

  // Point times N must be infinity
  if (!(point.mul(ec.curve.n).isInfinity())) {
    return false
  }

  return true
}
