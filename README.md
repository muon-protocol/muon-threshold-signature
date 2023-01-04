# Muon Threshold Signature

# Install dependencies

```
$ npm install
```

# Test DKG process

```
$ npm run test
```

## Run Signature process

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
