
# Muon Threshold Signature

### Table of Contents  
- [What is Threshold Signature](#what-is-threshold-signature)  
- [Multi Party Computation](#multi-party-computation)  
- [Schnorr Signature](#schnorr-signature)  
    - [How it works](#how-it-works)
    - [Advantages](#advantages)
- [Our Implementation](#our-implementation)  
    - [MultiPartyComputation](#impl-mult)
    - [IMpcNetwork](#impl-network)
    - [DistributedKeyGeneration](#impl-dkg)
- [Run the first test case](#run-the-first-test-case)  
- [Run the second test case](#run-the-second-test-case)  

# What is Threshold Signature

A threshold signature is a type of digital signature protocol that allows a group of parties to jointly sign a message without revealing their individual private keys. The signature is valid if and only if at least a certain number of parties (called the threshold) participate in the signing process. A threshold signature can be used to enhance the security and privacy of transactions in distributed systems, such as blockchain.

A threshold signature works by splitting the private key into several pieces (called key-shares) and distributing them among a group of parties. Each party can use their key-share to generate a partial signature on a message. The partial signatures can then be combined to produce a valid signature that is indistinguishable from a normal signature. The threshold refers to the minimum number of parties that need to cooperate to generate a signature. For example, if the threshold is 3 out of 5, then any 3 parties can sign a message, but any 2 parties cannot.

One example of a threshold signature scheme is the Shamir Secret Sharing Scheme (SSSS), which is based on polynomial interpolation. In this scheme, the private key is represented by a random polynomial of degree t-1, where t is the threshold. The key-shares are the evaluations of the polynomial at different points. To generate a partial signature, each party computes the value of the polynomial at their point using a Lagrange interpolation formula. To combine the partial signatures, the parties use another Lagrange interpolation formula to recover the value of the polynomial at zero, which is the signature.

# Multi Party Computation

Multi-party computation (MPC) is a subfield of cryptography that allows parties to jointly compute a function over their inputs while keeping those inputs private. Distributed Key Generation (DKG) is a multi-party computation (MPC) technique that allows a group of parties to generate a shared secret key without revealing their own private inputs. DKG is an example of MPC because it involves multiple parties who do not trust each other or a third party, and who want to jointly compute a function (the shared secret key) over their inputs (their own secret key shares) while keeping those inputs private. DKG can use cryptographic tools such as verifiable secret sharing, zero-knowledge proofs, or homomorphic encryption to ensure the security and correctness of the protocol. DKG is a building block for many applications that require threshold cryptography, such as distributed signing, threshold encryption, or multiparty computation.

# Schnorr Signature
  Schnorr signature is a digital signature scheme that allows you to prove that you own a message without revealing your secret key. It is based on the mathematical problem of finding discrete logarithms in a finite group.
  
#### How it works
  The Schnorr signature process consists of the following steps:
  
- **Choosing parameters**: All users of the signature scheme agree on a finite group G of prime order q with generator g, and a hash function H that maps bit strings to elements of Z_q (the set of integers modulo q).
  
- **Key generation**: You choose a secret key x from Z_q* (the set of non-zero elements of Z_q) and compute your public key y = g^x mod p, where p is the modulus of G. You publish your public key and keep your secret key private.
  
- **Signing**: To sign a message M, you do the following:
  
    - Choose a random nonce k from Z_q* and compute r = g^k mod p. This is your ephemeral key.
      
    - Compute e = H(r || M), where || denotes concatenation and r is represented as a bit string. This is your challenge.
      
    - Compute s = k - xe mod q. This is your response.
      
    - Your signature is the pair (s, e).
  
- **Verifying**: To verify a signature (s, e) on a message M from a public key y, you do the following:
  
    - Compute r_v = g^s y^e mod p. This is the reconstructed ephemeral key.
      
    - Compute e_v = H(r_v || M). This is the reconstructed challenge.
  
    - Check if e_v == e. If yes, accept the signature. If no, reject it.
  
#### Advantages
  Schnorr signature has some advantages over other signature schemes, such as:
  
- **Simplicity**: It has a simple and elegant design that is easy to understand and implement.
  
- **Efficiency**: It has short signatures (only 2q bits) and fast verification (only one exponentiation).
  
- **Security**: It is provably secure under the random oracle model, assuming the hardness of the discrete logarithm problem.
  
- **Aggregation**: It can combine multiple signatures into one, reducing the space and bandwidth requirements.
  
- **Compatibility**: It can work with different types of messages, such as elliptic curve points or hashes.

# Our Implementation

- **<a href="#impl-mult">MultiPartyComputation</a>**: We designed a general and flexible class for MPC that can be used as a base for creating other more specific and complicated classes like DKG. This class encapsulates all the common functionality related to MPC and avoids repeating it in the sub-classes.

- **<a href="#impl-network">IMpcNetwork</a>**: MPC requires a way to communicate with other parties and exchange information for each round of the protocol. We defined an interface called IMpcNetwork that specifies the methods and properties that any networking module should have. Any class that conforms to this interface can be plugged into the MPC instance and handle the networking operations.

    ```typescript
    interface IMpcNetwork {
      id: string,
      askRoundData: (from: string, mpcId: string, round: number, data?:any) => Promise<PartnerRoundReceive>,
      registerMcp: (mpc: MultiPartyComputation) => void
    }
    ```
- **<a href="#impl-dkg">DistributedKeyGeneration</a>**: We created a class for DKG that inherits from the MultiPartyComputation class. Our class implements the DKG protocol in three rounds. The input and output types of each round are specified at the beginning of the class file. We only need to define the logic of each round and the base class MPC will take care of the rest of the functionality.

    ```typescript
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
    
    //...
  
    export class DistributedKeyGeneration extends MultiPartyComputation {
    
        //...
        
        constructor(id: string, starter: string, partners: string[], t: number, value?: BN|string, extra: any={}) {
          /**
          All rounds defined here in a list.
          Each round method name should have the same name as defined here.
          */
          super(['round1', 'round2', 'round3'], ...Object.values(arguments));  
        }
        
        /**
        Round1 logic implementation.
        It has the same name as defined in the constructor. 
        */
        async round1(_, __, networkId: string, qualified: string[]): Promise<RoundOutput<Round1Result, Round1Broadcast>> {
          
          // ...
        
          const store = {fx, Fx, sig}
          const send: Round1Result = {}
          const broadcast:Round1Broadcast = {
            Fx,
            sig
          }
        
          return {store, send, broadcast}
        }
        
        //...
      
    }
    ```

# Run the first test case
<a name="dkg"/>

```
$ npm run test
```

## Run the second test case

```
$ npm start

TSS 3/9
Nodes indices:  [
  1, 2, 3, 4, 5,
  6, 7, 8, 9
]
Message: 0x4d8cfae6c0eec2582cfa3acf65df9af577237356df7c588872c20b7e81a97107
Signing and verifying the message.
Selected nodes: [3,4,5], verified: true
Selected nodes: [3,4,1], verified: true
Selected nodes: [2,4,6], verified: true
Selected nodes: [9,4,8], verified: true
Selected nodes: [8,6,9], verified: true
Selected nodes: [4,1,5], verified: true
Selected nodes: [5,6,8], verified: true
Selected nodes: [9,1,4], verified: true
Selected nodes: [3,8,9], verified: true
Selected nodes: [1,7,4], verified: true

```
