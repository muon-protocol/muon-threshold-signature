# Muon Threshold Signature

## Run

```
$ npm install
$ nodejs index.js


    Actual TssKey (prv): e9091f6af2509513592c58236...
    Actual TssKey (pub): 04115a1c9e558a906...
Calculated TssKey (pub): 04115a1c9e558a906357...

Reconstructed TssKey (prv): e9091f6af250...
Reconstructed TssKey (pub): 04115a1c9e558a906357....

Verifying correct message ...
subset: [2,4,1], verified: true
subset: [8,5,7], verified: true
subset: [6,9,3], verified: true
subset: [2,9,3], verified: true
subset: [2,7,5], verified: true
subset: [1,4,8], verified: true
subset: [6,5,2], verified: true
subset: [9,7,1], verified: true
subset: [2,5,9], verified: true
subset: [1,9,6], verified: true

Verifying wrong message ...
subset: [5,1,2], verified: false
subset: [1,4,8], verified: false
subset: [6,2,9], verified: false
subset: [1,7,3], verified: false
subset: [8,9,6], verified: false
subset: [6,1,5], verified: false
subset: [9,2,3], verified: false
subset: [8,7,4], verified: false
subset: [8,7,3], verified: false
subset: [6,7,9], verified: false

```
