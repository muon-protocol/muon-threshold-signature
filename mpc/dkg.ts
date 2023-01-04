import {MapOf, RoundOutput} from "./types";
import {MultiPartyComputation} from "./base";
import * as noble from "@noble/secp256k1"
import Polynomial from "../tss/polynomial";
import * as TssModule from "../tss/index";
import {PublicKey} from "../tss/types";
import lodash from 'lodash'
import {bigint2hex} from "../tss/utils";

const {countBy} = lodash;

/**
 * Round1 input/output types
 */
type Round1Result = {
  f: string,
  h: string
}
type Round1Broadcast = {
  commitment: string[],
}

/**
 * Round2 input/output types
 */
type Round2Result = any
type Round2Broadcast = {
  /** public key of main polynomial coefficients */
  Fx: string[],
  /** list of available partners */
  available: string[],
}

type Round3Result = any;
type Round3Broadcast = {
  /**
   * ID list of malignant partners
   * this nodes will exclude from key generation final round
   * */
  malignant: string[],
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
  share: bigint;
  address: string;
  publicKey: PublicKey;
  partners: string[];
  curve: {
    t: number,
    Fx: PublicKey[]
  };

  constructor(index: string, share: bigint, address: string, publicKey : PublicKey, partners: string[], curve: {t: number, Fx: PublicKey[]}) {
    this.index = index;
    this.share = share;
    this.address = address;
    this.publicKey = publicKey;
    this.partners = partners,
    this.curve = curve;
  }

  publicKeyLargerThanHalfN(): boolean {
    return TssModule.HALF_N < this.publicKey.x
  }

  toJson(): DistKeyJson {
    return {
      index: this.index,
      share: bigint2hex(this.share),
      address: this.address,
      publicKey: this.publicKey.toHex(true),
      partners: this.partners,
      curve: {
        t: this.curve.t,
        Fx: this.curve.Fx.map(p => p.toHex(true))
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
      BigInt(key.share),
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
      send: {
        type: 'object',
        properties: {
          f: schema_uint32,
          h: schema_uint32,
        },
        required: ['f', 'h']
      },
      broadcast: {
        type: 'object',
        properties: {
          commitment: {
            type: 'array',
            items: schema_public_key
          }
        },
        required: []
      },
    },
    required: ['send', 'broadcast']
  },
  'round2': {
    type: 'object',
    properties: {
      broadcast: {
        type: 'object',
        properties: {
          Fx: {
            type: 'array',
            items: schema_public_key
          },
          available: {
            type: 'array',
            items: { type: "string" }
          }
        },
        required: ['Fx']
      }
    },
    required: ['broadcast']
  },
  'round3': {
    type: 'object',
    properties: {
      broadcast: {
        type: 'object',
        properties: {
          malignant: {
            type: 'array',
            items: {
              type: 'string',
              pattern: pattern_id
            }
          }
        },
        required: ['malignant']
      }
    },
    required: ['broadcast']
  }
}

export class DistributedKeyGeneration extends MultiPartyComputation {

  private readonly t: number;
  private readonly value: bigint | undefined;
  public readonly extraParams: any;
  protected InputSchema: object = InputSchema;

  constructor(id: string, partners: string[], t: number, value?: string, extra: any={}) {
    // @ts-ignore
    super(['round1', 'round2', 'round3'], ...Object.values(arguments));
    // console.log(`${this.ConstructorName} construct with`, {id, partners, t, value});

    this.extraParams = extra;
    this.t = t
    if(!!value) {
      this.value = BigInt(value)
    }
  }

  private makeUnique(lists: string[][], threshold) {
    // @ts-ignore
    let arr = [].concat(...lists);
    const counts = countBy(arr);
    return Object.keys(counts).filter(item => counts[item] >= threshold);
  }

  round1(_, __, networkId: string):
    RoundOutput<Round1Result, Round1Broadcast> {
    let fx = new Polynomial(this.t, TssModule.curve, this.value);
    let hx = new Polynomial(this.t, TssModule.curve);

    const Fx = fx.coefPubKeys();
    const Hx = hx.coefPubKeys(TssModule.H)
    const commitment = Fx
      .map((Fxi, i) => TssModule.pointAdd(Fxi, Hx[i]))
      .map(k => k.toHex(true))

    const store = {fx, hx, Fx, Hx, commitment}
    const send = {}

    this.partners.forEach(id => {
      const idn = BigInt(id);
      send[id] = {
        f: bigint2hex(fx.calc(idn)),
        h: bigint2hex(hx.calc(idn)),
      }
    })

    const broadcast= {
      commitment,
    }

    return {store, send, broadcast}
  }

  round2(prevStepOutput: MapOf<Round1Result>, preStepBroadcast: MapOf<Round1Broadcast>, networkId: string):
    RoundOutput<Round2Result, Round2Broadcast> {
    const r1Msg = this.roundsArrivedMessages['round1']
    const available = Object.keys(r1Msg)

    /**
     * Propagate data
     */
    const store = {available}
    const send = {}
    const broadcast= {
      Fx: this.store['round1'].Fx.map(pubKey => pubKey.toHex(true)),
      available,
    }
    return {store, send, broadcast}
  }

  round3(prevStepOutput: MapOf<Round2Result>, preStepBroadcast: MapOf<Round2Broadcast>, networkId: string):
    RoundOutput<Round3Result, Round3Broadcast> {

    const r1Msgs = this.roundsArrivedMessages['round1']
    const r2Msgs = this.roundsArrivedMessages['round2']

    const {available} = this.store['round2']

    const malignant = this.partners.filter(p => !available.includes(p))
    /** verify round2.broadcast.Fx received from all partners */
    available.map(sender => {
      const Fx = r2Msgs[sender].broadcast.Fx.map(k => TssModule.keyFromPublic(k))
      const p1 = TssModule.calcPolyPoint(networkId, Fx);
      const p2 = TssModule.G.multiply(BigInt(r1Msgs[sender].send.f))
      if(!p1.equals(p2)) {
        console.log(`partner [${sender}] founded malignant at round3 Fx check`)
        malignant.push(sender);
      }
    })

    /**
     * Propagate data
     */
    const store = {malignant}
    const send = {}
    const broadcast= {
      malignant
    }

    return {store, send, broadcast}
  }

  onComplete(roundsArrivedMessages: MapOf<MapOf<{send: any, broadcast: any}>>, networkId): any {
    // console.log(`mpc complete`, roundsArrivedMessages)
    const r1Msgs = roundsArrivedMessages['round1'],
    r2Msgs = roundsArrivedMessages['round2'],
    r3Msgs = roundsArrivedMessages['round3']

    const {available} = this.store['round2']
    const malignantList = available.map(sender => r3Msgs[sender].broadcast.malignant);
    const malignant = this.makeUnique(malignantList, this.t);
    const nonMalignant = available.filter(id => !malignant.includes(id))

    if(nonMalignant.length < this.t) {
      throw `Insufficient partner to create the Key.`
    }

    /** share calculation */
    let share = nonMalignant
      .map(from => r1Msgs[from].send.f)
      .reduce((acc, current) => acc + BigInt(current), 0n)
    const nInv = noble.utils.invert(BigInt(nonMalignant.length.toString()), TssModule.curve.n)
    share = noble.utils.mod(share * nInv, TssModule.curve.n)

    let totalFx: PublicKey[] = []
    nonMalignant.forEach((sender, i) => {
      let Fx = r2Msgs[sender].broadcast.Fx;
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
      totalFx[i] = pubKey.multiply(nInv)
    })

    return new DistKey(
      networkId,
      share,
      TssModule.pub2addr(totalFx[0]),
      totalFx[0],
      nonMalignant,
      {
        t: 2,
        Fx: totalFx
      }
    )
  }
}

