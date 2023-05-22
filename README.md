# Muon Threshold Signature

This repository contains a TypeScript implementation of a Threshold Signature Scheme (TSS) using Schnorr-like signatures as described in [Stinson & Strobl’s 2001 paper](https://dl.acm.org/doi/10.5555/646038.678297). TSS allows a group of n parties to collaborate on generating a signature, with any t or more of them being able to create a valid signature. This is useful in scenarios where access to a private key needs to be distributed among multiple parties.

This implementaion uses the [Shamir Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing) which is a widely used TSS algorithm based on polynomial interpolation. In this scheme, the private key is represented by a random polynomial of degree t-1, where t is the threshold. The key shares are the evaluations of the polynomial at different points. To generate a partial signature, each party computes the value of the polynomial at their point using a Lagrange interpolation formula. To combine the partial signatures, the parties use another Lagrange interpolation formula to recover the value of the polynomial at zero, which is the signature.

The implementation consists of three main sections:
- **MultiPartyComputation:** a general and flexible class for MPC that encapsulates all common functionality related to MPC and avoids repeating it in the sub-classes.
- **IMpcNetwork:** an interface that specifies the methods and properties that any networking module should have for MPC.
- **DistributedKeyGeneration:** a class for DKG that inherits from the MultiPartyComputation class and implements the DKG protocol in three rounds.

## Audit
Our implementation has undergone an internal audit by [Habib Yajam](https://www.linkedin.com/in/habib-yajam-98b7126a), a trusted third-party auditor. The audit was conducted to ensure the security and correctness of our implementation. The audit suggested:
- Using proof of possession instead of hash commitments for guarding against rogue key attacks to improve 
  performance and maintain same security characteristics. [details](audit/Proof%20of%20Possession%20in%20Schnorr.pdf) | [commit](https://github.com/muon-protocol/muon-threshold-signature/commit/4f304c65aa5d9499504228d6557aebee76704a1e)
- Integrating elliptic curve point validation to the implementation to ensure that all points used in cryptographic 
  operations belong to the intended curve. This improves security against active attackers. [details](audit/Point%20Validation%20in%20Elliptic%20Curve%20Cryptography.pdf) | [commit](https://github.com/muon-protocol/muon-threshold-signature/commit/b2151593c7ba75e63815245fd4f2f2ce7198137d)
- Including the public key in the hashed challenge of Schnorr signatures to enhance the security of the protocol. 
  Accordingly, some theoretical attacks are prevented resulting in stronger security guarantees.
  [details](audit/The%20Challenge%20Value%20in%20Schnorr%20Signature%20Schemes.pdf) | [commit](https://github.com/muon-protocol/muon-threshold-signature/commit/b2151593c7ba75e63815245fd4f2f2ce7198137d)
- Following the guidelines for selecting the threshold value based on the security requirements and efficiency 
  constraints of the protocol. [details](audit/Threshold%20Value%20in%20Threshold%20Signature%20Schemes.pdf)

## Test

#### Installation
```
$ npm install
```
#### Testing Distributed Key Generation
```
$ npm run test
> tss-sample@1.0.0 test
> ./node_modules/.bin/ts-node src/mpc/dkg.test.ts

i: 0, match: OK, key party: 1,2,3,4 time: 426 ms
i: 1, match: OK, key party: 1,2,3,4 time: 275 ms
i: 2, match: OK, key party: 1,2,3,4 time: 186 ms
...
i: 208, match: OK, key party: 1,2,3,4 time: 153 ms
i: 209, match: OK, key party: 1,2,3,4 time: 151 ms
  total time: 34495 ms
average time: 164 ms
```
#### Testing Signing Process

```
$ npm start

> tss-sample@1.0.0 start
> ./node_modules/.bin/ts-node src/muon_network_simulator.ts

TSS 3/9
Nodes indices:  [
  '1', '2', '3',
  '4', '5', '6',
  '7', '8', '9'
]
Message: 0x4d8cfae6c0eec2582cfa3acf65df9af577237356df7c588872c20b7e81a97107
Signing and verifying the message.
Selected nodes: [8,6,2], verified: true
Selected nodes: [1,6,2], verified: true
Selected nodes: [3,7,5], verified: true
Selected nodes: [2,5,9], verified: true
Selected nodes: [9,1,7], verified: true
Selected nodes: [8,7,1], verified: true
Selected nodes: [1,4,7], verified: true
Selected nodes: [2,3,1], verified: true
Selected nodes: [9,8,4], verified: true
Selected nodes: [9,1,8], verified: true
```

