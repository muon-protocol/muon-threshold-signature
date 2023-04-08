import Web3 from 'web3'
import lodash from 'lodash';
import Polynomial from './tss/polynomial.js'
import * as TssModule from './tss/index.js'
import FakeNetwork from "./mpc/fake-network.js";
import {DistKeyJson, DistributedKeyGeneration} from "./mpc/dkg.js";
import {MapOf} from "./mpc/types";

const {shuffle, range} = lodash
const {toBN, soliditySha3} = Web3.utils
const random = () => Math.floor(Math.random()*9999999)

/**
 * The private key will be shared between N nodes.
 * Needs at least T nodes to sign a message.
 */
const tss_t = 3, tss_n=9;

/**
 * There are N network nodes
 * node-1 ... node-(N+1)
 */
const networkNodesIndices = range(1, tss_n+1).map(n => n.toString());
const fakeNets:FakeNetwork[] = networkNodesIndices.map(id => new FakeNetwork(id));

type KeyConstructionData = {
  id: string,
  partners: string[],
  t: number,
}

async function keyGen(partners: string[], networks: FakeNetwork[], cData: KeyConstructionData): Promise<MapOf<DistKeyJson>> {
  let keyGens = partners.map(p => {
    return new DistributedKeyGeneration(cData.id, '1', cData.partners, cData.t)
  })
  let allNodeResults: any[] = await Promise.all(
    partners.map(
      (p, i) => keyGens[i].runByNetwork(networks[i], 20000)
    )
  );
  return allNodeResults.reduce((obj, r) => {
    const json = r.toJson()
    obj[json.index] = json;
    return obj;
  }, {})
}

async function run() {
  /**
   * distKey[<any-ID>].publicKey --> global public key
   * distKey[<any-ID>].shares --> N TSS private key shares. Each one
   * will be assigned to one of the nodes
   */
  let distKey: MapOf<DistKeyJson> = await keyGen(networkNodesIndices, fakeNets, {
    id: `dkg-${Date.now()}${random()}`,
    partners: networkNodesIndices,
    t: tss_t,
  });

  /**
   * The message to be signed
   */
  const messageHex = soliditySha3("hello every body");

  /**
   * A random nonce will be generated for signing each message
   * on each node
   */
  const distNonce: MapOf<DistKeyJson> = await keyGen(networkNodesIndices, fakeNets, {
    id: `dkg-${Date.now()}${random()}`,
    partners: networkNodesIndices,
    t: tss_t,
  });

  /**
   * Network nodes sign the message using their own
   * TSS private key share
   */
  const sigs = Object.keys(distKey).map(id => {
    const key = toBN(distKey[id].share);
    const nonce = toBN(distNonce[id].share)
    const noncePublicKey = TssModule.keyFromPublic(distNonce[id].publicKey);

    return {
      index: id,
      sign: TssModule.schnorrSign(key, nonce, noncePublicKey, messageHex)
    };
  });

  /**
   * Select random subset of signatures to verify the
   * signed message.
   * Any subset of signatures should verify that message
   * is signed by the global TSS key
   */
  console.log(`TSS ${tss_t}/${tss_n}`);
  console.log('Nodes indices: ', networkNodesIndices);
  console.log(`Message: ${messageHex}`)
  console.log("Signing and verifying the message.");
  const verifyingPublicKey = TssModule.keyFromPublic(distKey["1"].publicKey)
  for(let i=0; i<10 ; i++) {
    const sigsSubSet = shuffle(sigs).slice(0, tss_t);
    const aggregatedSig = TssModule.schnorrAggregateSigs(tss_t, sigsSubSet.map(s => s.sign), sigsSubSet.map(s => s.index))
    const verified = TssModule.schnorrVerify(verifyingPublicKey, messageHex, aggregatedSig);
    console.log(`Selected nodes: [${sigsSubSet.map(s=>s.index).join(',')}], verified:`, verified)
  }
}

run()
  .catch(e => console.log(e))
  .finally(() => {
    process.exit(0);
  })
