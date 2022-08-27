import {Point, Signature} from "@noble/secp256k1";

export type Hex = Uint8Array | string;
export type PrivKey = Hex | bigint | number;
export type PubKey = Hex | Point;
export type Sig = Hex | Signature;
