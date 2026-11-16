// Qapsule web app - all cryptography runs locally in this page.
// Imports are pinned ESM builds of the same libraries the proof scripts use.
import { ml_kem1024 } from "https://esm.sh/@noble/post-quantum@0.7.1/ml-kem";
import { shake256 } from "https://esm.sh/@noble/hashes@2.0.1/sha3";
import {
  createPublicClient, createWalletClient, custom, defineChain, http,
  bytesToHex, hexToBytes, keccak256,
} from "https://esm.sh/viem@2.57.19";

export const CONTRACT = "0xfe5ee7ee9c4820144d7c95f5916722bbcbc492cc";
export const RPC = "https://evm-testnet.qore.host";
export const diana = defineChain({
  id: 9800, name: "QoreChain Diana Testnet",
  nativeCurrency: { name: "QOR", symbol: "QOR", decimals: 18 },
  rpcUrls: { default: { http: [RPC] } },
});

// Minimal ABI (matches contracts/Qapsule.sol)
export const qapsuleAbi = [
  { type: "function", name: "createCapsule", stateMutability: "nonpayable",
    inputs: [
      { name: "recipient", type: "address" }, { name: "unlockTime", type: "uint64" },
      { name: "contentHash", type: "bytes32" }, { name: "shareBCommitment", type: "bytes32" },
      { name: "encapsulatedShareA", type: "bytes" }, { name: "storageRef", type: "string" }],
    outputs: [{ name: "id", type: "uint256" }] },
  { type: "function", name: "revealShareB", stateMutability: "nonpayable",
    inputs: [{ name: "id", type: "uint256" }, { name: "shareB", type: "bytes32" }], outputs: [] },
  { type: "function", name: "capsuleCount", stateMutability: "view", inputs: [],
    outputs: [{ name: "", type: "uint256" }] },
  { type: "function", name: "getCapsule", stateMutability: "view",
    inputs: [{ name: "id", type: "uint256" }],
    outputs: [
      { name: "sender", type: "address" }, { name: "recipient", type: "address" },
      { name: "unlockTime", type: "uint64" }, { name: "contentHash", type: "bytes32" },
      { name: "shareBCommitment", type: "bytes32" }, { name: "encapsulatedShareA", type: "bytes" },
      { name: "storageRef", type: "string" }, { name: "revealedShareB", type: "bytes32" },
      { name: "revealed", type: "bool" }] },
];

// ---------- crypto helpers (identical construction to the proven e2e) ----------
const xor = (a, b) => a.map((x, i) => x ^ b[i]);
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0; for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
};
async function aes(keyBytes, mode, iv, data) {
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, [mode]);
  const fn = mode === "encrypt" ? crypto.subtle.encrypt : crypto.subtle.decrypt;
  return new Uint8Array(await fn.call(crypto.subtle, { name: "AES-GCM", iv }, key, data));
}
const sha256 = async (bytes) => new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));

// ---------- recipient keys ----------
export function generateRecipientKeys() {
  const { publicKey, secretKey } = ml_kem1024.keygen();
  return { publicKey: bytesToHex(publicKey), secretKey: bytesToHex(secretKey) };
}

// ---------- create a capsule (returns the capsule file + on-chain params) ----------
export async function buildCapsule({ message, recipientEvm, recipientMlKemPublicKey, unlockTime }) {
  const contentKey = crypto.getRandomValues(new Uint8Array(32));
  const msgIv = crypto.getRandomValues(new Uint8Array(12));
  const msgCt = await aes(contentKey, "encrypt", msgIv, new TextEncoder().encode(message));
  const shareB = crypto.getRandomValues(new Uint8Array(32));
  const shareA = xor(contentKey, shareB);
  const { cipherText: kemCt, sharedSecret } = ml_kem1024.encapsulate(hexToBytes(recipientMlKemPublicKey));
  const wrapIv = crypto.getRandomValues(new Uint8Array(12));
  const wrappedA = await aes(await sha256(sharedSecret), "encrypt", wrapIv, shareA);
  const encapsulatedShareA = concat(kemCt, wrapIv, wrappedA); // 1568 || 12 || 48
  const capsuleFile = {
    version: 1, contract: CONTRACT,
    msgIv: bytesToHex(msgIv), msgCt: bytesToHex(msgCt),
    recipientMlKemPublicKey,
  };
  const params = {
    recipient: recipientEvm, unlockTime: BigInt(unlockTime),
    contentHash: bytesToHex(shake256(msgCt, { dkLen: 32 })),
    shareBCommitment: keccak256(bytesToHex(shareB)),
    encapsulatedShareA: bytesToHex(encapsulatedShareA),
    storageRef: "capsule-file://v1",
  };
  // shareB never leaves the sender until reveal; the page keeps it in the
  // sender's reveal file, downloaded alongside the capsule file.
  const revealFile = { version: 1, contract: CONTRACT, shareB: bytesToHex(shareB) };
  return { capsuleFile, revealFile, params };
}

// ---------- chain helpers ----------
export const publicClient = () =>
  createPublicClient({ chain: diana, transport: http(RPC) });

export async function registerCapsuleOnChain(params) {
  if (!window.ethereum) throw new Error("No EVM wallet found. Open this page in QoreX or a wallet browser.");
  const wallet = createWalletClient({ chain: diana, transport: custom(window.ethereum) });
  const [account] = await wallet.requestAddresses();
  const hash = await wallet.writeContract({
    account, address: CONTRACT, abi: qapsuleAbi, functionName: "createCapsule",
    args: [params.recipient, params.unlockTime, params.contentHash,
           params.shareBCommitment, params.encapsulatedShareA, params.storageRef],
  });
  await publicClient().waitForTransactionReceipt({ hash });
  const count = await publicClient().readContract({
    address: CONTRACT, abi: qapsuleAbi, functionName: "capsuleCount",
  });
  return { hash, capsuleId: count - 1n };
}

export async function revealOnChain(capsuleId, shareBHex) {
  if (!window.ethereum) throw new Error("No EVM wallet found.");
  const wallet = createWalletClient({ chain: diana, transport: custom(window.ethereum) });
  const [account] = await wallet.requestAddresses();
  const hash = await wallet.writeContract({
    account, address: CONTRACT, abi: qapsuleAbi, functionName: "revealShareB",
    args: [BigInt(capsuleId), shareBHex],
  });
  await publicClient().waitForTransactionReceipt({ hash });
  return hash;
}

export async function fetchCapsule(capsuleId) {
  const r = await publicClient().readContract({
    address: CONTRACT, abi: qapsuleAbi, functionName: "getCapsule", args: [BigInt(capsuleId)],
  });
  return {
    sender: r[0], recipient: r[1], unlockTime: Number(r[2]), contentHash: r[3],
    shareBCommitment: r[4], encapsulatedShareA: r[5], storageRef: r[6],
    revealedShareB: r[7], revealed: r[8],
  };
}

// ---------- open a revealed capsule ----------
export async function openCapsule({ capsuleFile, capsule, recipientMlKemSecretKey }) {
  const blob = hexToBytes(capsule.encapsulatedShareA);
  const kemCt = blob.slice(0, 1568), wrapIv = blob.slice(1568, 1580), wrappedA = blob.slice(1580);
  const sharedSecret = ml_kem1024.decapsulate(kemCt, hexToBytes(recipientMlKemSecretKey));
  const shareA = await aes(await sha256(sharedSecret), "decrypt", wrapIv, wrappedA);
  const contentKey = xor(shareA, hexToBytes(capsule.revealedShareB));
  const opened = await aes(contentKey, "decrypt",
    hexToBytes(capsuleFile.msgIv), hexToBytes(capsuleFile.msgCt));
  return new TextDecoder().decode(opened);
}
