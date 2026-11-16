# Qapsule — post-quantum time-capsules on QoreChain

**Send a message into the future that no quantum computer can open — and nobody can open early.**

Qapsule is an encrypted time-capsule dApp built for the QoreChain *Build Before Q-Day* fest
(Encrypted Apps, Intermediate). A sender seals a message for a chosen future date; the
QoreChain contract is the time gate, and the cryptography is post-quantum end to end.

- **Contract (Diana testnet, chain 9800):** `0xfe5ee7ee9c4820144d7c95f5916722bbcbc492cc`
- **Live demo capsule:** id `0` — created on-chain, an early reveal was rejected by the
  contract (`TooEarly`), Share B was revealed after its 90-second unlock, and the message
  was decrypted from on-chain data alone.

## Why post-quantum, why a time-capsule

Capsules are exactly the data that "harvest now, decrypt later" attacks target: a letter
meant to stay secret for 10–30 years (to a child, a partner, a future self; embargoed
research; a sealed announcement). Classical RSA/ECDH key wrapping will not survive that
horizon. Qapsule wraps its keys with **ML-KEM-1024** (FIPS 203, NIST Category 5 — the
same standard QoreChain itself uses) so a capsule sealed today stays sealed.

## How it works

1. The recipient generates an **ML-KEM-1024** keypair in their browser; the secret key
   never leaves their device.
2. The sender's browser encrypts the message with a random **AES-256-GCM** content key.
   Plaintext never leaves the device; the ciphertext travels in a small "capsule file"
   the recipient can hold immediately.
3. The content key is **XOR-split** into Share A and Share B.
   - Share A is wrapped to the recipient via ML-KEM-1024 (KEM-DEM: the KEM shared secret
     keys an AES-GCM wrap) and stored on-chain.
   - Share B is never published. Only its hash commitment and the SHAKE-256 hash of the
     ciphertext go on-chain, together with the recipient and `unlockTime`.
4. **`Qapsule.sol` refuses to accept the reveal of Share B before `unlockTime`.** The
   recipient, holding Share A and the ciphertext, mathematically cannot decrypt early.
5. After the unlock time, the sender reveals Share B in one transaction. The contract
   verifies it against the commitment and records it as a public, timestamped opening
   event. The recipient combines the shares in their browser and reads the message.

### Honest limits (no overclaiming)

- Time enforcement lives at the **key-reveal layer**: the contract gates the reveal
  transaction and the opening is publicly auditable. This is not trustless time-lock
  encryption, and the sender (releaser) must submit one transaction after the unlock.
- The EVM lane has no SHAKE-256 opcode, so the on-chain reveal check uses keccak256;
  SHAKE-256 (QoreChain's native hash) anchors the ciphertext hash.
- Ciphertext storage is off-chain (the capsule file; IPFS addressing is a stretch goal).

## QoreChain specifics

Every QoreChain EVM transaction needs a **registered ML-DSA-87 key** and a live **EVM
authorisation window** for the sending account (opened on the native lane with a hybrid
signature). Deployments in this repo use the official `@qorechain/evm` helpers; the
window helper ships with the official Hardhat starter template (`window register`,
`window open` — a window lasts 600 blocks, so open it right before sending).

## Repo layout

- `contracts/Qapsule.sol` — the time-gate contract
- `contracts/Qapsule.artifact.ts` — compiled artifact (solc 0.8.28)
- `scripts/deploy-qapsule.ts` — deploy via `@qorechain/evm`
- `scripts/e2e-onchain.ts` — full lifecycle proof against the live testnet contract
- `web/` — the browser app (all crypto runs client-side)
- `qapsule-deployment.json` — deployment record

## Run it

```bash
npm install
# .env: QORE_EVM_RPC_URL=https://evm-testnet.qore.host and QORE_EVM_PRIVATE_KEY=<funded testnet deployer>
npm run deploy:qapsule   # deploy (window must be open)
npm run e2e              # seal -> early reveal blocked -> reveal -> open, on testnet
# web app: serve web/ statically, e.g. npx serve web
```

## Fest

Build Before Q-Day · QoreChain Developer Fest · Category: Encrypted Apps · Level: Intermediate
