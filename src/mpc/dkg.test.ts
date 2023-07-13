/**
 * Test Distributed Key Generation module
 * Generate Distributed Key
 * Sign message
 * Verify signature
 */
import {DistKeyJson, DistributedKeyGeneration, DKGOpts} from "./dkg.js";
import FakeNetwork from './fake-network.js';
import {bn2str} from './utils.js'
import Web3 from 'web3'
import * as TssModule from '../tss/index.js'
import lodash from 'lodash'

const {range, uniq} = lodash
const {toBN, randomHex} = Web3.utils

/**
 * Share privateKey between 5 individuals
 * Needs to at least 3 individual's signature to recover global signature
 */
const N = TssModule.curve.n
const threshold = 3;
const nonDealersCount = 2;
const partners = range(threshold+1+nonDealersCount).map(i => `${i+1}`)
console.log('All partners: ', partners)
const random = () => Math.floor(Math.random()*9999999)

export type KeyConstructionData = {
  id: string,
  partners: string[],
  dealers?: string[],
  t: number,
  pk?: string,
}

function resultOk(realKey: string|null, realPubKey: string|null, resultPubKey: string, reconstructedKey, reconstructedPubKey) {
  if(resultPubKey !== reconstructedPubKey)
    return false

  if(realKey) {
    return realKey === reconstructedKey && realPubKey === resultPubKey
  }

  return true
}

async function keyGen(partners: string[], networks: FakeNetwork[], cData: KeyConstructionData): Promise<DistKeyJson[]> {
  const keyGenOpts: DKGOpts = {
    id: cData.id,
    starter: '1',
    partners: cData.partners,
    dealers: cData.dealers,
    t: cData.t,
    value: cData.pk
  }
  let keyGens = partners.map(p => new DistributedKeyGeneration(keyGenOpts))

  let allNodeResults: any[] = await Promise.all(
    partners.map(
      (p, i) => keyGens[i].runByNetwork(networks[i], 20000)
    )
  );

  return allNodeResults.map(r => r.toJson())
}

async function run() {

  const fakeNets:FakeNetwork[] = partners.map(id => new FakeNetwork(id));

  const specialPrivateKeys = [
    /** first 100 private keys */
    ...(new Array(100).fill(0).map((_, i) => bn2str(toBN(i+1).umod(N!)))),

    /** 100 random and unknown private key */
    ...(new Array(100).fill(null)),

    /** 100 random and known private key */
    ...(new Array(100).fill(0).map(() => bn2str(toBN(randomHex(32)).umod(N!)))),

    /** last 100 private keys */
    ...(new Array(100).fill(0).map((_, i) => bn2str(N.subn(100-i)))),
  ]

  const t1 = Date.now()
  for(let i=0 ; i<specialPrivateKeys.length ; i++) {
    const startTime = Date.now();
    // const realPrivateKey = bn2str(toBN(randomHex(32)).umod(N));
    const realPrivateKey = specialPrivateKeys[i];
    const realPubKey = realPrivateKey ? TssModule.keyFromPrivate(realPrivateKey).getPublic().encode("hex", true) : null;

    let keyShares = await keyGen(partners, fakeNets, {
      id: `dkg-${Date.now()}${random()}`,
      partners,
      dealers: partners.slice(0, threshold+1),
      t: threshold,
      pk: realPrivateKey,
    });

    /** check total key reconstruction */
    const shares = keyShares.map(r => ({i: r.index, key: TssModule.keyFromPrivate(r.share)}))
    const reconstructedKey = bn2str(TssModule.reconstructKey(shares.slice(-threshold), threshold, 0))
    const reconstructedPubKey = TssModule.keyFromPrivate(reconstructedKey).getPublic().encode('hex', true)

    const pubKeyList = keyShares.map(key => key.publicKey)
    if(uniq(pubKeyList).length===1 && resultOk(realPrivateKey, realPubKey, keyShares[0].publicKey, reconstructedKey, reconstructedPubKey))
      console.log(`i: ${i+1}/${specialPrivateKeys.length}, match: OK, key party: ${keyShares[0].partners} time: ${Date.now() - startTime} ms`)
    else {
      console.log(`i: ${i+1}/${specialPrivateKeys.length}, match: false`)
      console.log({
        partnersPubKeys: pubKeyList,
        realPrivateKey,
        realPubKey,
        resultPubKey: keyShares[0].publicKey,
        reconstructedKey,
        reconstructedPubKey,
      })
    }
  }
  const t2 = Date.now()
  const dt = t2 - t1
  console.log(`  total time: ${Math.round(dt)} ms`)
  console.log(`average time: ${Math.round(dt/specialPrivateKeys.length)} ms`)
}

run()
  .catch(e => {
    console.log("error when running the test.", e)
  })
  .then(() => {
    process.exit(0)
  })
