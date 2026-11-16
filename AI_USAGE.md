# AI usage

Qapsule was built with substantial AI assistance (an AI agent, "Lux", powered by
Meta's Muse), directed and reviewed by the human builder, Krisna Aji.

What the AI did:
- Protocol design support: the XOR key-split construction, ML-KEM-1024 KEM-DEM
  wrapping layout, and the on-chain commitment scheme were drafted with the AI and
  then verified by local end-to-end cryptographic tests (8/8 checks) before any
  contract code was written.
- Code: `Qapsule.sol`, the deployment and on-chain end-to-end scripts, and the
  zero-build web app were written with the AI, compiled and tested against the
  Diana testnet (capsule id 0: early reveal rejected with `TooEarly`, reveal after
  unlock, message decrypted from on-chain data alone).
- Documentation: the README's architecture and honest-limits sections were drafted
  with the AI and checked against the deployed behaviour.

What the human did:
- Chose the concept and category, made every account and wallet step (hackathon
  registration, QoreX connection, repository creation), and reviewed and approved
  each submission field.

No AI-generated claim in this repository is unverified: every on-chain statement
links to a transaction on the Diana testnet.
