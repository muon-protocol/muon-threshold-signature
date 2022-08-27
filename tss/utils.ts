const Web3 = require('web3');
const {utils: {BN, toBN, randomHex, sha3, soliditySha3, keccak256}} = Web3;
const {range} = require('lodash');

function buf2bi (buf: Uint8Array): bigint {
  let ret = BigInt(0)
  // @ts-ignore
  for (const i of (buf as Buffer).values()) {
    const bi = BigInt(i)
    ret = (ret << BigInt(8)) + bi
  }
  return ret
}

export const ZERO = toBN(0)
export const ONE = toBN(1)

export {
  buf2bi,
  BN,
  toBN,
  sha3,
  soliditySha3,
  keccak256,
  range,
  randomHex
}
