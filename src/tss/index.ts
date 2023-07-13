import {PublicKey, PublicKeyShare} from './types';
import ethJsUtil from 'ethereumjs-util'
import {BN, toBN, keccak256, range, pub2addr} from './utils.js'
import assert from 'assert'
import elliptic from 'elliptic'
const ZERO = toBN(0)
const ONE = toBN(1)
const TWO = toBN(2)
const THREE = toBN(3)

const EC = elliptic.ec;
const curve = new EC('secp256k1');
const HALF_N = curve.n!.shrn(1).addn(1);
/**
 * Let H be elements of G, such that nobody knows log, h
 * used for pedersen commitment
 * @type {Point}
 */
// const H = new Point(
//   '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
//   '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
// );
const H = curve.keyFromPublic("04206ae271fa934801b55f5144bec8416be0b85f22d452ad410f3f0fca1083dc7ae41249696c446f8c5b166760377115943662991c35ff02f9585f892970af89ed", 'hex').getPublic()

function pointAdd(point1?: PublicKey, point2?: PublicKey): PublicKey {
  // if a point is null then return another one as the result of the addition
  if (point1 === null) {
    return point2;
  }
  if (point2 === null) {
    return point1;
  }
  // calculate the addition of the points
  const result = point1?.add(point2);

  // if any of the input points are not valid elliptic curve points return generator as output
  if ((point1.validate() && point2.validate()) === false) {
    return curve.g;
  } else {
    return result;
  }
}

function calcPoly(x, polynomial) {
  if (!BN.isBN(x))
    x = toBN(x);
  let result = toBN(0);
  for (let i = 0; i < polynomial.length; i++) {
    result = result.add(polynomial[i].mul(x.pow(toBN(i))));
  }
  return result.umod(curve.n!)
  // return result;
}

function calcPolyPointOld(x, polynomial): PublicKey {
  if (!BN.isBN(x))
    x = toBN(x);
  let result: PublicKey | null = null;
  for (let i = 0; i < polynomial.length; i++) {
    result = pointAdd(result!, polynomial[i].mul(x.pow(toBN(i))));
  }
  return result!;
}

function calcPolyPoint(x: string|number, polynomial: PublicKey[]): PublicKey {
  const bnx = toBN(x);
  const validated = polynomial.reduce((accumulator, currentValue) => {
    accumulator && currentValue.validate();
  }, true);
  const coefArray = polynomial.map((_,i) => bnx.pow(toBN(i)).umod(curve.n));
  const result = curve.curve._endoWnafMulAdd(polynomial, coefArray, false);
  if (validated === false) {
    return curve.g;
  } else {
    return result;
  }
}

function random() {
  return curve.genKeyPair().getPrivate();
}

function shareKey(privateKey, t, n, indices, polynomial) {
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
    assert(polynomial.length === t)
  else
    polynomial = [privateKey, ...(range(1, t).map(random))]
  return {
    polynomial: polynomial,
    shares: indices.map(i => {
      // TODO: key % n will prevent reconstructing of main key
      let privateKey = calcPoly(i, polynomial)//.umod(curve.n)
      // @ts-ignore
      return {i, key: curve.keyFromPrivate(privateKey)}
    })
  }
}

function lagrangeCoef(j, t, shares, index) {
  let _x = BN.isBN(index) ? index : toBN(index);
  let prod = arr => arr.reduce((acc, current) => acc.mul(current), toBN(1));
  let x_j = toBN(shares[j].i)
  let arr = range(0, t).filter(k => k!==j).map(k => {
    let x_k = toBN(shares[k].i)
    // [numerator, denominator]
    return [_x.sub(x_k), x_j.sub(x_k)]
  });
  let numerator = prod(arr.map(a => a[0]))
  let denominator = prod(arr.map(a => a[1]))
  return numerator.mul(denominator.invm(curve.n));
}

function reconstructKey(shares, t, index=0): BN {
  assert(shares.length >= t);
  let sum = toBN(0);
  for (let j = 0; j < t; j++) {
    let coef = lagrangeCoef(j, t, shares, index)
    let key = shares[j].key.getPrivate()
    sum = sum.add(key.mul(coef))
  }
  return sum.umod(curve.n!);
}

export function reconstructPubKey(shares: PublicKeyShare[], t, index=0): PublicKey {
  assert(shares.length >= t);
  let sum: PublicKey|null = null;
  for (let j = 0; j < t; j++) {
    let coef = lagrangeCoef(j, t, shares, index)
    let pubKey:PublicKey = shares[j].publicKey
    sum = pointAdd(sum, pubKey.mul(coef))
  }
  return sum;
}

function addKeys(key1, key2) {
  return key1.add(key2).umod(curve.n)
}

function subKeys(key1, key2) {
  return key1.sub(key2).umod(curve.n)
}

function keyFromPrivate(prv) {
  if(typeof prv === 'string')
    prv = prv.replace(/^0x/i, '')
  return curve.keyFromPrivate(prv)
}

function keyFromPublic(pubKeyStr, encoding='hex') {
  return curve.keyFromPublic(pubKeyStr, encoding).getPublic()
}

// function key2pub(privateKey) {
//   let _PK = BN.isBN(privateKey) ? privateKey : toBN(privateKey)
//   let {x, y} = curve.g.mul(_PK);
//   return new Point(x, y);
// }

function key2pub(privateKey) {
  let _PK = BN.isBN(privateKey) ? privateKey : toBN(privateKey)
  return curve.g.mul(_PK);
}

function schnorrHash(noncePoint, pubKey, msg) {
  const nonceAddress = pub2addr(noncePoint);
  const nonceAddressBuff = Buffer.from(nonceAddress.replace(/^0x/i, ''), 'hex');

  // calculate public ket address to add to the challenge hash
  const pubKeyAddress = pub2addr(pubKey);
  const pubKeyAddressBuff = Buffer.from(pubKeyAddress.replace(/^0x/i, ''), 'hex');

  const msgBuff = Buffer.from(msg.replace(/^0x/i, ''), 'hex');

  const totalBuff = Buffer.concat([nonceAddressBuff, pubKeyAddressBuff, msgBuff]);
  // @ts-ignore
  return keccak256(totalBuff);
}

function schnorrSign(sharedPrivateKey, sharedK, noncePoint, publicKey, msg) {
  // make _sharedPrivateKey that is the BN from of sharedPrivateKey
  let _sharedPrivateKey: BN;
  if (BN.isBN(sharedPrivateKey)) {
    _sharedPrivateKey = sharedPrivateKey;
  } else {
    _sharedPrivateKey = toBN(sharedPrivateKey);
  }

  // calculate 'e' of the signature consider adding public key to challenge value
  const e = toBN(schnorrHash(noncePoint, publicKey, msg));
  const s = sharedK.sub(_sharedPrivateKey.mul(e)).umod(curve.n);

  return {s, e};
}

export function stringifySignature(sign: {s: BN, e: BN}): string {
  return `0x${sign.e.toString('hex' ,64)}${sign.s.toString('hex',64)}`
}

export function splitSignature(signature: string): {s: BN, e: BN} {
  const bytes = signature.replace('0x','');
  if(bytes.length !== 128)
    throw `invalid schnorr signature string`;
  return {
    e: toBN(`0x${bytes.substr(0, 64)}`),
    s: toBN(`0x${bytes.substr(64, 64)}`),
  }
}

function schnorrVerify(pubKey: PublicKey, msg, sig:{s: BN, e: BN}|string) {
  if(typeof sig === 'string') {
    sig = splitSignature(sig);
  }

  // Prevent denial of service attacks by bounding the 's' and 'e' to values lower than curve.n
  const s = sig.s.umod(curve.n);
  const e = sig.e.umod(curve.n);

  // Calculate verifying values of signature use public key as part of challenge hash
  const rv = pointAdd(curve.g.mul(s), pubKey.mul(e));
  const ev = schnorrHash(rv, pubKey, msg);
  const result = toBN(ev).eq(e);

  // Return only if the public key value is a valid point on curve
  if (pubKey.validate() === false) {
    return false;
  } else {
    return result;
  }
}

function schnorrVerifyWithNonceAddress(hash, signature, nonceAddress, signingPubKey) {
  nonceAddress = nonceAddress.toLowerCase();
  const nonce = toBN(nonceAddress)
  hash = toBN(hash)
  signature = toBN(signature)

  if(!signature.lt(curve.n))
    throw "signature must be reduced modulo N"

  if(nonce.isZero() || signature.isZero() || hash.isZero())
    throw `no zero inputs allowed`

  // @ts-ignore
  const e = toBN(keccak256(Buffer.concat([
    nonce.toBuffer('be', 20),
    hash.toBuffer('be', 32)
  ])))

  let recoveredPubKey = ethJsUtil.ecrecover(
    curve.n!.sub(signingPubKey.getX().mul(signature).umod(curve.n)).toBuffer('be', 32),
    signingPubKey.getY().isEven() ? 27 : 28,
    signingPubKey.getX().toBuffer('be', 32),
    e.mul(signingPubKey.getX()).umod(curve.n!).toBuffer('be', 32)
  );
  const addrBuf = ethJsUtil.pubToAddress(recoveredPubKey);
  const addr    = ethJsUtil.bufferToHex(addrBuf);

  return nonceAddress === addr;
}

function schnorrAggregateSigs(t, sigs, indices){
  assert(sigs.length >= t);
  let ts = toBN(0)
  range(0, t).map(j => {
    let coef = lagrangeCoef(j, t, indices.map(i => ({i})), 0);
    ts.iadd(sigs[j].s.mul(coef))
  })
  let s = ts.umod(curve.n!)
  let e = sigs[0].e.clone();
  return {s, e}
}

export function validatePublicKey(publicKey: string|PublicKey): boolean {
  if(typeof publicKey === 'string')
    publicKey = keyFromPublic(publicKey);
  return curve.curve.validate(publicKey);
}

export {
  curve,
  random,
  pointAdd,
  calcPoly,
  keyFromPrivate,
  keyFromPublic,
  calcPolyPoint,
  shareKey,
  lagrangeCoef,
  reconstructKey,
  toBN,
  addKeys,
  subKeys,
  key2pub,
  pub2addr,
  schnorrHash,
  schnorrSign,
  schnorrVerify,
  schnorrVerifyWithNonceAddress,
  schnorrAggregateSigs,
  // use
  H,
  HALF_N,
}
