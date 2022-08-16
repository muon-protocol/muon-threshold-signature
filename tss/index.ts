import * as noble from "@noble/secp256k1"
const {buf2bi, keccak256, range} = require('./utils')
const assert = require('assert')
import Polynomial from './polynomial'

const curve = noble.CURVE
const HALF_N = (noble.CURVE.n >> 1n) + 1n;
// /**
//  * Let H be elements of G, such that nobody knows log, h
//  * used for pedersen commitment
//  * @type {Point}
//  */
const H = new noble.Point(
  BigInt('0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'),
  BigInt('0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8')
);

function pointAdd(point1: noble.Point | null, point2: noble.Point | null): noble.Point {
  if (point1 === null)
    return point2;
  if (point2 === null)
    return point1;

  return point1.add(point2);
}

function calcPolyPoint(x: bigint, polynomial: noble.Point[]) {
  if (typeof x !== 'bigint')
    x = BigInt(x);
  let result = null;
  for (let i = 0; i < polynomial.length; i++) {
    result = pointAdd(result, polynomial[i].multiply(x ** BigInt(i)));
  }
  return result;
}

function random():bigint {
  return buf2bi(noble.utils.randomPrivateKey());
}

function shareKey(privateKey: bigint, t, n, indices, polynomial: Polynomial) {
  if(indices){
    assert(indices.length === n)
  }
  else{
    // uniform distribution of indices
    indices = range(1, n + 1)
    // non uniform distribution of indices
    // indices = range(1, n + 1).map(i => i * 10 + Math.floor(Math.random() * 9))
  }
  if(polynomial)
    assert(polynomial.t === t)
  else
    polynomial = new Polynomial(t, null, privateKey);
  return {
    polynomial: polynomial,
    shares: indices.map(i => {
      // TODO: key % n will prevent reconstructing of main key
      let privateKey = polynomial.calc(BigInt(i))
      return {i, key: privateKey}
    })
  }
}

function lagrangeCoef(j, t, shares, index: bigint): bigint {
  let _x = index;
  let prod = arr => arr.reduce((acc, current) => (acc * current), 1n);
  let x_j = BigInt(shares[j].i)
  let arr = range(0, t).filter(k => k!=j).map(k => {
      let x_k = BigInt(shares[k].i)
      // [numerator, denominator]
      return [_x - x_k, x_j - x_k]
  });
  let numerator = prod(arr.map(a => a[0]))
  let denominator = prod(arr.map(a => a[1]))
  return numerator * noble.utils.invert(denominator, noble.CURVE.n);
}

function reconstructKey(shares, t, index=0n) {
  assert(shares.length >= t);
  let sum = 0n;
  for (let j = 0; j < t; j++) {
    let coef = lagrangeCoef(j, t, shares, index)
    let key = shares[j].key
    sum += key * coef
  }
  return noble.utils.mod(sum, noble.CURVE.n);
}

function addKeys(key1: bigint, key2: bigint) {
  return noble.utils.mod(key1 + key2, noble.CURVE.n)
}

function subKeys(key1: bigint, key2: bigint) {
  return noble.utils.mod(key1- key2, noble.CURVE.n)
}

function pub2addr(publicKey: noble.Point) {
  let pubKeyHex = publicKey.toHex(false).substr(2);
  let pub_hash = keccak256(Buffer.from(pubKeyHex, 'hex'))
  return toChecksumAddress('0x' + pub_hash.substr(-40));
}

function toChecksumAddress(address) {
  address = address.toLowerCase().replace(/^0x/i, '')
  let hash = keccak256(address).replace(/^0x/i, '');
  let ret = '0x'
  for (let i = 0; i < address.length; i++) {
    if (parseInt(hash[i], 16) >= 8) {
      ret += address[i].toUpperCase()
    } else {
      ret += address[i]
    }
  }
  return ret
}

function schnorrHash(publicKey: noble.Point, msg) {
  let address = pub2addr(publicKey)
  let addressBuff = Buffer.from(address.replace(/^0x/i, ''), 'hex');
  let msgBuff = Buffer.from(msg.replace(/^0x/i, ''), 'hex');
  let totalBuff = Buffer.concat([addressBuff, msgBuff])
  return keccak256(totalBuff)
}

function schnorrSign(sharedPrivateKey: bigint, sharedK: bigint, kPub: noble.Point, msg) {
  let e = BigInt(schnorrHash(kPub, msg))
  let s = noble.utils.mod(sharedK - (sharedPrivateKey * e), noble.CURVE.n);
  return {s, e}
}

const G = new noble.Point(noble.CURVE.Gx, noble.CURVE.Gy);
Object.freeze(G);

function schnorrVerify(pubKey: noble.Point, msg: string, sig: {s: bigint, e:bigint}) {
  let r_v = pointAdd(G.multiply(sig.s), pubKey.multiply(sig.e))
  let e_v = schnorrHash(r_v, msg)
  if(BigInt(e_v) !== sig.e) {
    console.log({
      msg,
      pubKey: pubKey.toHex(),
      rv: r_v.toHex(),
      e_v: e_v,
      e: sig.e.toString(16)
    })
  }
  return BigInt(e_v) == sig.e;
}

function schnorrAggregateSigs(t, sigs, indices){
  assert(sigs.length >= t);
  let ts = 0n;
  range(0, t).map(j => {
    let coef = lagrangeCoef(j, t, indices.map(i => ({i})), 0n);
    ts += sigs[j].s * coef
  })
  let s = noble.utils.mod(ts, noble.CURVE.n)
  let e = sigs[0].e;
  return {s, e}
}

function sumMod(arr: bigint[], modulo?: bigint) {
  const sum = arr.reduce((sum, val) => (sum + val), 0n);
  return noble.utils.mod(sum, modulo);
}

export {
  curve,
  random,
  sumMod,
  pointAdd,
  calcPolyPoint,
  shareKey,
  lagrangeCoef,
  reconstructKey,
  addKeys,
  subKeys,
  pub2addr,
  schnorrHash,
  schnorrSign,
  schnorrVerify,
  schnorrAggregateSigs,
  // use
  G,
  H,
  HALF_N,
}
