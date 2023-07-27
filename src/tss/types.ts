import * as Elliptic from 'elliptic'

export type BaseCurve = Elliptic.curve.base

export type KeyPair = Elliptic.ec.KeyPair

export type PublicKey = Elliptic.curve.base.BasePoint

export type PublicKeyShare = {
  i: string,
  publicKey: PublicKey
}

export type PolynomialInfo = {
  t: number,
  Fx: PublicKey[]
}

export type PolynomialInfoJson = {
  t: number,
  Fx: string[]
}
