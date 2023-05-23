import {MapOf, RoundOutput} from "./types";
import {MultiPartyComputation} from "./base.js";
import {bn2str} from './utils.js'
import Web3 from 'web3'
import Polynomial from "../tss/polynomial.js";
import * as TssModule from "../tss/index.js";
import {PublicKey} from "../tss/types";
import BN from 'bn.js';

const {soliditySha3} = Web3.utils

/**
 * Round1 input/output types
 */
type Round1Result = any
type Round1Broadcast = {
  /** commitment */
  Fx: string[],
  /** proof of possession */
  sig: {
    /** PublicKey of random generated nonce */
    nonce: string,
    /** schnorr signature */
    signature: string,
  },
}

/**
 * Round2 input/output types
 */
type Round2Result = {
  /** key share */
  f: string,
}
type Round2Broadcast = {
  /**
   hash of commitment received from other parties
   will be used in malicious behaviour detection
   */
  allPartiesFxHash: MapOf<string>,
}

/**
 * broadcast malicious partners
 */
type Round3Result = any;
type Round3Broadcast = {
  malicious: string[],
}

export type DistKeyJson = {
  index: string,
  share: string,
  address: string,
  publicKey: string,
  partners: string[],
  curve: {
    t: number,
    Fx: string[]
  }
}

export class DistKey {
  index: string;
  share: BN;
  address: string;
  publicKey: PublicKey;
  partners: string[];
  curve: {
    t: number,
    Fx: PublicKey[]
  };

  constructor(index: string, share: BN, address: string, publicKey : PublicKey, partners: string[], curve: {t: number, Fx: PublicKey[]}) {
    this.index = index;
    this.share = share;
    this.address = address;
    this.publicKey = publicKey;
    this.partners = partners,
      this.curve = curve;
  }

  /**
   * Returns public key of participant with id of [idx]
   * public key calculated from the public key of shamir polynomial coefficients.
   * @param idx {string | BN} - index of participant
   * @returns PublicKey
   */
  getPublicKey(idx: number | string): PublicKey{
    return TssModule.calcPolyPoint(idx, this.curve.Fx)
  }

  publicKeyLargerThanHalfN() {
    return TssModule.HALF_N.lt(this.publicKey.getX())
  }

  toJson(): DistKeyJson {
    return {
      index: this.index,
      share: bn2str(this.share),
      address: this.address,
      publicKey: this.publicKey.encode('hex', true),
      partners: this.partners,
      curve: {
        t: this.curve.t,
        Fx: this.curve.Fx.map(p => p.encode('hex', true))
      }
    }
  }

  static fromJson(key: DistKeyJson): DistKey {
    const publicKey = TssModule.keyFromPublic(key.publicKey)
    const address = TssModule.pub2addr(publicKey)
    if(address.toLowerCase() !== key.address.toLowerCase())
      throw `DistKeyJson address mismatched with publicKey`
    return new DistKey(
      key.index,
      TssModule.toBN(key.share),
      address,
      publicKey,
      key.partners,
      {
        t: key.curve.t,
        Fx: key.curve.Fx.map(p => TssModule.keyFromPublic(p))
      },
    );
  }
}

const pattern_id = "^[1-9][0-9]*$";
const schema_uint32 = {type: 'string', pattern: `^0x[0-9A-Fa-f]{64}$`};
const schema_public_key = {type: 'string', pattern: `^[0-9A-Fa-f]{66}$`};
const InputSchema = {
  'round1': {
    type: 'object',
    properties: {
      broadcast: {
        type: 'object',
        properties: {
          Fx: {
            type: 'array',
            items: schema_public_key
          },
          sig: {
            type: 'object',
            properties:{
              nonce: schema_public_key,
              signature: {type: "string"},
            },
            required:['nonce', 'signature']
          }
        },
        required: ["Fx", "sig"]
      },
    },
    required: ['broadcast']
  },
  'round2':{
    type: 'object',
    properties: {
      send: {
        type: 'object',
        properties: {
          f: schema_uint32,
        },
        required: ['f']
      },
      broadcast: {
        type: "object",
        properties: {
          allPartiesFxHash: {
            type: 'object',
            patternProperties: {
              [pattern_id]: schema_uint32
            }
          }
        },
        required: ['allPartiesFxHash']
      }
    },
    required: ['send', 'broadcast']
  },
  'round3': {
    type: 'object',
    properties: {
      broadcast: {
        type: 'object',
        properties: {
          malicious: {
            type: 'array',
            items: {type: 'string'},
          }
        },
        required: ['malicious'],
      },
    },
    required: ['broadcast'],
  }
}

export class DistributedKeyGeneration extends MultiPartyComputation {

  private readonly value: BN | undefined;
  public readonly extraParams: any;
  protected InputSchema: object = InputSchema;

  constructor(id: string, starter: string, partners: string[], t: number, value?: BN|string, extra: any={}) {
    // @ts-ignore
    super(['round1', 'round2', 'round3'], ...Object.values(arguments));
    // console.log(`${this.ConstructorName} construct with`, {id, partners, t, value});

    this.extraParams = extra;
    this.t = t
    if(!!value) {
      if(BN.isBN(value))
        this.value = value
      else
        this.value = Web3.utils.toBN(value);
    }
  }

  async round1(_, __, networkId: string, qualified: string[]): Promise<RoundOutput<Round1Result, Round1Broadcast>> {
    // @ts-ignore
    let fx = new Polynomial(this.t, TssModule.curve, this.value ? TssModule.toBN(this.value) : undefined);
    const Fx = fx.coefPubKeys();

    const k: BN = TssModule.random();
    const kPublic = TssModule.keyFromPrivate(k).getPublic();

    const popMsg = soliditySha3(
      /** i */
      {type: "uint64", value: networkId},
      /** CTX */
      {type: "string", value: this.id},
      /** g^(ai0) */
      {type: "bytes", value: '0x'+Fx[0].encode('hex', true)},
      /** Ri = g^k */
      {type: "bytes", value: "0x"+kPublic.encode('hex', true)},
    )
    const popSign = TssModule.schnorrSign(fx.coefficients[0].getPrivate(), k, kPublic, TssModule.keyFromPublic(Fx[0]), popMsg);
    const sig = {
      nonce: kPublic.encode('hex', true),
      signature: TssModule.stringifySignature(popSign)
    }

    const store = {fx, Fx, sig}
    const send: Round1Result = {}
    const broadcast:Round1Broadcast = {
      Fx: Fx.map(pubKey => pubKey.encode('hex', true)),
      sig
    }

    return {store, send, broadcast}
  }

  round2(prevStepOutput: MapOf<Round1Result>, prevStepBroadcast: MapOf<Round1Broadcast>, networkId: string, qualified: string[]):
    RoundOutput<Round2Result, Round2Broadcast> {
    /**
     * Check all partners broadcast same commitment to all other parties.
     */
    const r1Msg = this.getRoundReceives('round1')

    const malignant: string[] = [];

    /** check each node's commitments sent to all nodes are the same. */
    qualified.forEach(sender => {
      const {Fx, sig: {nonce, signature}} = prevStepBroadcast[sender];
      const popHash = soliditySha3(
        /** i */
        {type: "uint64", value: sender},
        /** CTX */
        {type: "string", value: this.id},
        /** g^(ai0) */
        {type: "bytes", value: '0x'+Fx[0]},
        /** Ri = g^k */
        {type: "bytes", value: nonce},
      )
      const verified = TssModule.schnorrVerify(
        TssModule.keyFromPublic(Fx[0]),
        popHash,
        signature
      );
      if(!verified) {
        malignant.push(sender)
        return;
      }
    })

    /**
     * Propagate data
     */

    /** exclude malignant from qualified list */
    const newQualified = qualified
      .filter(id => !malignant.includes(id))

    const store = {}
    const send = {}
    const broadcast= {
      allPartiesFxHash: {}
      // Fx: this.getStore('round0').Fx.map(pubKey => pubKey.encode('hex', true)),
      // malignant,
    }
    newQualified.forEach(id => {
      send[id] = {
        f: bn2str(this.getStore('round1').fx.calc(id)),
      }
      broadcast.allPartiesFxHash[id] = soliditySha3(...prevStepBroadcast[id].Fx.map(v => ({t: 'bytes', v})))
    })
    return {store, send, broadcast, qualifieds: newQualified}
  }

  round3(prevStepOutput: MapOf<Round2Result>, preStepBroadcast: MapOf<Round2Broadcast>, networkId: string, qualified: string[]):
    RoundOutput<Round3Result, Round3Broadcast> {
    /**
     * Check all partners broadcast same commitment to all other parties.
     */
    const r1Msgs = this.getRoundReceives('round1')
    const r2Msgs = this.getRoundReceives('round2')

    const malicious: string[] = []

    /** verify round2.broadcast.Fx received from all partners */
    qualified.map(sender => {
      /** sender commitment hash */
      const senderFxHash = soliditySha3(...r1Msgs[sender].broadcast.Fx.map(v => ({t: 'bytes', v})));

      /** check for the same commitment sent to all parties */
      qualified.every(receiver => {
        const senderFxSentToReceiver = r2Msgs[receiver].broadcast.allPartiesFxHash[sender]
        if(senderFxHash !== senderFxSentToReceiver) {
          console.log(`partner [${sender}] founded malignant at round2 comparing commitment with others`)
          malicious.push(sender)
          return false
        }
        return true;
      })

      const Fx = r1Msgs[sender].broadcast.Fx.map(k => TssModule.keyFromPublic(k))
      const p1 = TssModule.calcPolyPoint(networkId, Fx);
      const p2 = TssModule.curve.g.mul(TssModule.toBN(r2Msgs[sender].send.f))
      if(!p1.eq(p2)) {
        console.log(`partner [${sender}] founded malignant at round3 Fx check`)
        malicious.push(sender);
      }
    })

    /**
     * Propagate data
     */
    const newQualified = qualified.filter(id => !malicious.includes(id));

    const store = {}
    const send = {}
    const broadcast= {
      malicious,
    }

    return {store, send, broadcast, qualifieds: newQualified}
  }

  onComplete(roundsArrivedMessages: MapOf<MapOf<{send: any, broadcast: any}>>, networkId: string, qualified: string[]): any {
    // console.log(`mpc complete`, roundsArrivedMessages)
    const r1Msgs = this.getRoundReceives('round1')
    const r2Msgs = this.getRoundReceives('round2')

    if(qualified.length < this.t) {
      throw `Insufficient partner to create the Key.`
    }

    /** share calculation */
    let share = qualified
      .map(from => r2Msgs[from].send.f)
      .reduce((acc, current) => {
        acc.iadd(TssModule.toBN(current))
        return acc
      }, TssModule.toBN('0'))
    const nInv = TssModule.toBN(qualified.length.toString()).invm(TssModule.curve.n!)
    share.imul(nInv)
    share = share.umod(TssModule.curve.n)

    let totalFx: PublicKey[] = []
    qualified.forEach((sender, i) => {
      let Fx = r1Msgs[sender].broadcast.Fx;
      if(i === 0)
        totalFx = Fx.map(pub => TssModule.keyFromPublic(pub))
      else {
        Fx.forEach((pub, i) => {
          pub = TssModule.keyFromPublic(pub)
          return totalFx[i] = TssModule.pointAdd(totalFx[i], pub)
        })
      }
    })
    totalFx.forEach((pubKey, i) => {
      totalFx[i] = pubKey.mul(nInv)
    })

    //console.log(`dkg[${this.id}].onComplete keyId: ${this.extraParams?.keyId}`, {qualified})

    return new DistKey(
      networkId,
      share,
      TssModule.pub2addr(totalFx[0]),
      totalFx[0],
      qualified,
      {
        t: 2,
        Fx: totalFx
      }
    )
  }
}

