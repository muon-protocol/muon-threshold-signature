import Web3 from 'web3'
import lodash from 'lodash'
import * as TssModule from './tss/index.js'
import FakeNetwork from "./mpc/fake-network.js";
import {MapOf} from "./mpc/types";
import {DistKeyJson, DistributedKeyGeneration} from "./mpc/dkg.js";
import {KeyConstructionData} from "./mpc/dkg.test";

const {toBN, soliditySha3} = Web3.utils
const {shuffle, range} = lodash
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

  const ITERATION_COUNT = 1000;
  console.log(`Process start for ${ITERATION_COUNT} iteration ...`)
  const startTime = Date.now();
  const verifyingPublicKey = TssModule.keyFromPublic(distKey["1"].publicKey)
  for (let iteration = 0; iteration < ITERATION_COUNT; iteration++) {
    let t0 = Date.now()
    /**
     * A nonce (distributed key) will be generated for signing the message
     */
    const distNonce: MapOf<DistKeyJson> = await keyGen(networkNodesIndices, fakeNets, {
      id: `dkg-${Date.now()}${random()}`,
      partners: networkNodesIndices,
      t: tss_t,
    });
    const keyGenTime = Date.now()

    /**
     * Network nodes sign the message using their own
     * TSS private key share
     */
    const sigs = Object.keys(distKey).map(id => {
      const key = toBN(distKey[id].share);
      const nonce = toBN(distNonce[id].share)
      const noncePublicKey = TssModule.keyFromPublic(distNonce[id].publicKey);
      const publicKey = TssModule.keyFromPublic(distKey[id].publicKey);

      return {
        index: id,
        sign: TssModule.schnorrSign(key, nonce, noncePublicKey, publicKey, messageHex)
      };
    });
    const signingTime = Date.now();

    /**
     * Select random subset of signatures to verify the
     * signed message.
     * Any subset of signatures should verify that message
     * is signed by the global TSS key
     */
    const sigsSubSet = shuffle(sigs).slice(0, tss_t);
    const aggregatedSig = TssModule.schnorrAggregateSigs(tss_t, sigsSubSet.map(s => s.sign), sigsSubSet.map(s => s.index))
    const verified = TssModule.schnorrVerify(verifyingPublicKey, messageHex, aggregatedSig);
    if (!verified) {
      throw `Selected nodes: [${sigsSubSet.map(s => s.index).join(',')}], verified: ${verified}`
    }
    const verificationTime = Date.now();

    console.log(
      `iteration: ${iteration}/${ITERATION_COUNT}`
      +`, total: ${verificationTime-t0} ms`
      +`, keyGen: ${keyGenTime-t0} ms`
      +`, signing: ${signingTime-keyGenTime} ms`
      +`, verifying: ${verificationTime-signingTime}`
    );
  }
  console.log(`All done in ${(Date.now() - startTime) / 1000} seconds`);
}

run()
  .catch(e => console.log(e))
  .finally(() => {
    process.exit(0)
  })
