const {toBN, soliditySha3} = require('web3').utils
const {shuffle, range} = require('lodash')
const Polynomial = require('./tss/polynomial')
const tss = require('./tss/index')

/**
 * The private key will be shared between N nodes.
 * Needs at least T nodes to sign a message. 
 */
const tss_t = 3, tss_n=9;

/**
 * There are N network nodes
 * node-1 ... node-(N+1)
 */
const neworkNodesIndices = range(1, tss_n+1);


/**
 * Generates a TSS key with N shares.
 */
function generateDistributedKey() {
  const shares = neworkNodesIndices.reduce((acc, idx) => {
    acc[idx] = {
      index: idx,
      polynomial: new Polynomial(tss_t, tss.curve),
      coefPubKeys: null,
      keyParts: null,
      key: null,
    }
    return acc;
  }, {});

  neworkNodesIndices.forEach(index => {
    shares[index].coefPubKeys = shares[index].polynomial.coefPubKeys();
    shares[index].keyParts = neworkNodesIndices.map(i => shares[i].polynomial.calc(index))
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
  const totalPubKey = neworkNodesIndices
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


/**
 * tssKey.totalPubkey --> global public key
 * tssKey.shares --> N TSS private key shares. Each one
 * will be assigned to one of the nodes
 */
let tssKey = generateDistributedKey();

/**
 * The message to be signed
 */
const messageHex = soliditySha3("hello every body");

/**
 * A random nonce will be generated for signing each message
 * on each node
 */
const nonce = generateDistributedKey();

/**
 * Network nodes sign the message using their own
 * TSS private key share
 */
const sigs = Object.values(tssKey.shares).map(({index, key}) => {
  let nodeNonce = nonce.shares[index];
  return {
    index,
    sign: tss.schnorrSign(key, nodeNonce.key, nonce.totalPubKey, messageHex)
  };
});

/**
 * Select random subset of signatures to verify the 
 * signed message.
 * Any subset of signatures should verify that message
 * is signed by the global TSS key
 */
console.log(`TSS ${tss_t}/${tss_n}`);
console.log('Nodes indices: ', neworkNodesIndices);
console.log("Sigining and verifying the message.");
for(let i=0; i<10 ; i++) {
  const sigsSubSet = shuffle(sigs).slice(0, tss_t);
  const aggregatedSig = tss.schnorrAggregateSigs(tss_t, sigsSubSet.map(s => s.sign), sigsSubSet.map(s => s.index))
  const verified = tss.schnorrVerify(tssKey.totalPubKey, messageHex, aggregatedSig);
  console.log(`Selected nodes: [${sigsSubSet.map(s=>s.index).join(',')}], verified:`, verified)
}
