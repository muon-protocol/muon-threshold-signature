/**
 * Generate Distributed Key
 * Sign message
 * Verify signature
 */
const {toBN, soliditySha3} = require('web3').utils
const {shuffle, range} = require('lodash')
const Polynomial = require('./tss/polynomial')
const tss = require('./tss/index')

/**
 * Share privateKey between 5 individuals
 * Needs to at least 3 individual's signature to recover global signature
 */
const t = 3, n=9;
const participantIndices = range(1, n+1);

function generateDistributedKey() {
  const shares = participantIndices.reduce((acc, idx) => {
    acc[idx] = {
      index: idx,
      polynomial: new Polynomial(t, tss.curve),
      coefPubKeys: null,
      keyParts: null,
      key: null,
    }
    return acc;
  }, {});

  participantIndices.forEach(index => {
    shares[index].coefPubKeys = shares[index].polynomial.coefPubKeys();
    shares[index].keyParts = participantIndices.map(i => shares[i].polynomial.calc(index))
    shares[index].key = shares[index].keyParts.reduce((sum, val) => sum.add(val).umod(tss.curve.n), toBN(0))
  })

  /**
   * Total publicKey of shared key is sum of coefficient[0] of all polynomials
   * polynomial 1 => y = a1.x^2 + b1.x + c1
   * polynomial 2 => y = a2.x^2 + b2.x + c2
   * polynomial 3 => y = a3.x^2 + b3.x + c3
   *
   * Total public key = PubKey(c1) + PubKey(c2) + PubKey(c3)
   *
   * We display each polynomials like this [c1, b1, a1], ...
   */
  const totalPubKey = participantIndices
    .map(index => shares[index].coefPubKeys)
    .reduce((acc, coefPubKeys) => {
      // return tss.pointAdd(acc, tss.calcPolyPoint('0', coefPubKeys))
      return tss.pointAdd(acc, coefPubKeys[0])
    }, null)

  return {
    totalPubKey,
    shares
  }
}

let tssKey = generateDistributedKey();

/**
 * Total key without reconstruction
 */
let totalKey1 = toBN('0');
let publicKey1;
Object.values(tssKey.shares)
  .map(share => share.polynomial)
  .forEach(poly => {
    totalKey1 = totalKey1.add(poly.calc('0')).umod(tss.curve.n);
  })
publicKey1 = tss.key2pub(totalKey1)
console.log('    Actual TssKey (prv):', totalKey1.toBuffer('be', 32).toString('hex'));
console.log('    Actual TssKey (pub):', publicKey1.encode('hex'));
console.log('Calculated TssKey (pub):', tssKey.totalPubKey.encode('hex'));

/**
 * Total key with reconstruction
 */
let totalKey2, publicKey2;
const sharesToReconstructTotalKey = Object.values(tssKey.shares).map(({index, key}) => ({i: index, key: tss.keyFromPrivate(key)}))
totalKey2 = tss.reconstructKey(sharesToReconstructTotalKey, t, 0);
publicKey2 = tss.key2pub(totalKey2)
console.log('\nReconstructed TssKey (prv):', totalKey2.toBuffer('be', 32).toString('hex'));
console.log('Reconstructed TssKey (pub):', publicKey2.encode('hex'));


/**
 * Signing message using Schnorr Signature
 */
const messageToSign = "sample message to sign"
const messageHash = soliditySha3(messageToSign)
const nonce = generateDistributedKey();
const sigs = Object.values(tssKey.shares).map(({index, key}) => {
  let participantNoncePart = nonce.shares[index];
  return {
    index,
    sign: tss.schnorrSign(key, participantNoncePart.key, nonce.totalPubKey, messageHash)
  };
})

/**
 * Select random subset of signatures to verify signed message
 * Any subset of signatures should verify that message is signed bt total TssKey
 */
console.log("\nVerifying correct message ...")
for(let i=0; i<10 ; i++) {
  const sigsSubSet = shuffle(sigs).slice(0, t);
  const aggregatedSig = tss.schnorrAggregateSigs(t, sigsSubSet.map(s => s.sign), sigsSubSet.map(s => s.index))
  const verified = tss.schnorrVerify(tssKey.totalPubKey, messageHash, aggregatedSig);
  console.log(`subset: [${sigsSubSet.map(s=>s.index).join(',')}], verified:`, verified)
}

console.log("\nVerifying wrong message ...")
for(let i=0; i<10 ; i++) {
  const sigsSubSet = shuffle(sigs).slice(0, t);
  const aggregatedSig = tss.schnorrAggregateSigs(t, sigsSubSet.map(s => s.sign), sigsSubSet.map(s => s.index))
  const verified = tss.schnorrVerify(tssKey.totalPubKey, soliditySha3("wrong message"), aggregatedSig)
  console.log(`subset: [${sigsSubSet.map(s=>s.index).join(',')}], verified:`, verified)
}


