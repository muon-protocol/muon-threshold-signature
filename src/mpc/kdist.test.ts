/**
 * Test Distributed Key Generation module
 * Generate Distributed Key
 * Sign message
 * Verify signature
 */
import {DistKeyJson, DistributedKeyGeneration} from "./dkg.js";
import {KeyRedistribution} from "./kdist.js"
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
const nextThreshold = 2;
const partners = range(Math.max(threshold, nextThreshold)+1).map(i => `${i+1}`)
const random = () => Math.floor(Math.random()*9999999)

export type KeyConstructionData = {
  id: string,
  partners: string[],
  t: number,
  pk?: string,
}

export type KeyReDistributeData = KeyConstructionData & {previousT: number};

function resultOk(realKey: string|null, realPubKey: string|null, resultPubKey: string, reconstructedKey, reconstructedPubKey) {
  if(resultPubKey !== reconstructedPubKey)
    return false

  if(realKey) {
    return realKey === reconstructedKey && realPubKey === resultPubKey
  }

  return true
}

async function keyGen(partners: string[], networks: FakeNetwork[], cData: KeyConstructionData): Promise<DistKeyJson[]> {

  let keyGens = partners.map(p => new DistributedKeyGeneration(cData.id, '1', cData.partners, cData.t, cData.pk))

  let allNodeResults: any[] = await Promise.all(
    partners.map(
      (p, i) => keyGens[i].runByNetwork(networks[i], 20000)
    )
  );

  return allNodeResults.map(r => r.toJson())
}

async function keyRedistribute(
  partners: string[],
  networks: FakeNetwork[],
  cData: KeyReDistributeData,
  shares: DistKeyJson[]
): Promise<DistKeyJson[]> {

  let keyReDists = partners.map((p, index) => {
    return new KeyRedistribution(cData.id, '1', cData.partners, cData.t, cData.previousT, shares[index].share)
  })

  let allNodeResults: any[] = await Promise.all(
    partners.map(
      (p, i) => keyReDists[i].runByNetwork(networks[i], 20000)
    )
  );

  return allNodeResults.map(r => r.toJson())
}

async function run() {

  const fakeNets:FakeNetwork[] = partners.map(id => new FakeNetwork(id));

  const specialPrivateKeys = [
    /** first 100 private keys */
    ...(new Array(100).fill(0).map((_, i) => bn2str(toBN(i+1).umod(N!)))),
    //
    /** 100 random and unknown private key */
    ...(new Array(100).fill(null)),
    //
    /** 100 random and known private key */
    ...(new Array(100).fill(0).map(() => bn2str(toBN(randomHex(32)).umod(N!)))),
    //
    /** last 100 private keys */
    ...(new Array(100).fill(0).map((_, i) => bn2str(TssModule.curve.n!.subn(100-i)))),
  ]

  const t1 = Date.now()
  for(let i=0 ; i<specialPrivateKeys.length ; i++) {
    const startTime = Date.now();
    // const realPrivateKey = bn2str(toBN(randomHex(32)).umod(N));
    const realPrivateKey = specialPrivateKeys[i];
    const realPubKey = realPrivateKey ? TssModule.keyFromPrivate(realPrivateKey).getPublic().encode("hex", true) : null;

    let initialKeyShares = await keyGen(partners, fakeNets, {
      id: `dkg-${Date.now()}${random()}`,
      partners,
      t: threshold,
      pk: realPrivateKey,
    });

    let keyShares = await keyRedistribute(
      partners,
      fakeNets,
      {
        id: `kredist-${Date.now()}${random()}`,
        partners,
        previousT: threshold,
        t: nextThreshold,
      },
      initialKeyShares
    );

    /** check total key reconstruction */
    const shares = keyShares.map(r => ({i: r.index, key: TssModule.keyFromPrivate(r.share)}))
    const reconstructedKey = bn2str(TssModule.reconstructKey(shares, nextThreshold, 0))
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
