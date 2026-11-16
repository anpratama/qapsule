/**
 * e2e-onchain.ts - full Qapsule lifecycle against the deployed contract on
 * Diana testnet: build a real capsule (ML-KEM-1024 + AES-GCM + XOR split),
 * register it on-chain, prove the contract refuses an early reveal, wait for
 * the unlock time, reveal Share B, and decrypt the message from on-chain data.
 */
import {
  createEvmClient,
  evmAccountFromPrivateKey,
  readContract,
  writeContract,
} from "@qorechain/evm";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { shake256 } from "@noble/hashes/sha3.js";
import {
  bytesToHex,
  hexToBytes,
  keccak256,
  type Address,
  type Hex,
} from "viem";
import { readFileSync, writeFileSync } from "node:fs";
import { qapsuleAbi } from "../contracts/Qapsule.artifact.js";

const enc = new TextEncoder();
const dec = new TextDecoder();
const xor = (a: Uint8Array, b: Uint8Array) => a.map((x, i) => x ^ b[i]);
const concat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
};

async function aes(keyBytes: Uint8Array, mode: "encrypt" | "decrypt", iv: Uint8Array, data: Uint8Array) {
  const key = await crypto.subtle.importKey("raw", keyBytes as BufferSource, "AES-GCM", false, [mode]);
  const fn = mode === "encrypt" ? crypto.subtle.encrypt : crypto.subtle.decrypt;
  return new Uint8Array(await fn.call(crypto.subtle, { name: "AES-GCM", iv: iv as BufferSource }, key, data as BufferSource));
}

async function main(): Promise<void> {
  const deployment = JSON.parse(readFileSync("qapsule-deployment.json", "utf8"));
  const contract = deployment.contract as Address;
  const evmRpc = process.env.QORE_EVM_RPC_URL ?? "https://evm-testnet.qore.host";
  const privateKey = process.env.QORE_EVM_PRIVATE_KEY as Hex;
  const client = await createEvmClient({ endpoints: { evmRpc } });
  const account = evmAccountFromPrivateKey(privateKey);
  const wallet = client.getWalletClient(account);
  const pub = client.publicClient;

  // Recipient = the deployer account itself for this proof run (self-capsule).
  const recipientKeys = ml_kem1024.keygen();
  const recipient = account.address;

  // --- Build the capsule (same code path as the browser app) ---
  const message = enc.encode("Qapsule demo: this message was sealed on QoreChain Diana and could not be opened early.");
  const contentKey = crypto.getRandomValues(new Uint8Array(32));
  const msgIv = crypto.getRandomValues(new Uint8Array(12));
  const msgCt = await aes(contentKey, "encrypt", msgIv, message);
  const shareB = crypto.getRandomValues(new Uint8Array(32));
  const shareA = xor(contentKey, shareB);
  const { cipherText: kemCt, sharedSecret } = ml_kem1024.encapsulate(recipientKeys.publicKey);
  const kek = new Uint8Array(await crypto.subtle.digest("SHA-256", sharedSecret as BufferSource));
  const wrapIv = crypto.getRandomValues(new Uint8Array(12));
  const wrappedA = await aes(kek, "encrypt", wrapIv, shareA);
  // Blob layout: kemCt(1568) || wrapIv(12) || wrappedA(48)
  const encapsulatedShareA = concat(kemCt, wrapIv, wrappedA);
  const contentHash = bytesToHex(shake256(msgCt, { dkLen: 32 })) as Hex;
  const shareBCommitment = keccak256(bytesToHex(shareB) as Hex);
  const unlockTime = BigInt(Math.floor(Date.now() / 1000) + 90);
  const storageRef = "capsule-file://demo-1";

  // The ciphertext capsule file (what the recipient holds off-chain).
  writeFileSync("demo-capsule-1.json", JSON.stringify({
    version: 1, contract, storageRef,
    msgIv: bytesToHex(msgIv), msgCt: bytesToHex(msgCt),
    recipientMlKemPublicKey: bytesToHex(recipientKeys.publicKey),
  }, null, 2) + "\n");
  // Recipient secret key stays with the recipient (here: the proof script).
  writeFileSync("demo-recipient-secret.json", JSON.stringify({
    mlKemSecretKey: bytesToHex(recipientKeys.secretKey),
  }) + "\n", { mode: 0o600 });

  console.log("creating capsule on-chain, unlock in 90s...");
  const createHash = await writeContract(wallet, {
    address: contract, abi: qapsuleAbi, functionName: "createCapsule",
    args: [recipient, unlockTime, contentHash, shareBCommitment, bytesToHex(encapsulatedShareA) as Hex, storageRef],
    account: wallet.account ?? null, chain: wallet.chain,
  });
  await pub.waitForTransactionReceipt({ hash: createHash });
  const count = await readContract(pub, { address: contract, abi: qapsuleAbi, functionName: "capsuleCount" });
  const id = (count as bigint) - 1n;
  console.log(`capsule id ${id} created, tx ${createHash}`);

  // --- Early reveal must fail ---
  let earlyBlocked = false;
  try {
    await writeContract(wallet, {
      address: contract, abi: qapsuleAbi, functionName: "revealShareB",
      args: [id, bytesToHex(shareB) as Hex],
      account: wallet.account ?? null, chain: wallet.chain,
    });
  } catch (e) {
    earlyBlocked = true;
    console.log("early reveal correctly rejected:", (e as Error).message.slice(0, 140));
  }
  if (!earlyBlocked) throw new Error("EARLY REVEAL WAS NOT BLOCKED - gate broken");

  // --- Wait for unlock, then reveal ---
  const waitMs = Number(unlockTime) * 1000 - Date.now() + 3000;
  console.log(`waiting ${Math.ceil(waitMs / 1000)}s for unlock...`);
  await new Promise((r) => setTimeout(r, Math.max(0, waitMs)));
  const revealHash = await writeContract(wallet, {
    address: contract, abi: qapsuleAbi, functionName: "revealShareB",
    args: [id, bytesToHex(shareB) as Hex],
    account: wallet.account ?? null, chain: wallet.chain,
  });
  await pub.waitForTransactionReceipt({ hash: revealHash });
  console.log(`share B revealed, tx ${revealHash}`);

  // --- Recipient opens from on-chain data alone (+ capsule file + own key) ---
  const cap = (await readContract(pub, {
    address: contract, abi: qapsuleAbi, functionName: "getCapsule", args: [id],
  })) as readonly unknown[];
  const onchainBlob = hexToBytes(cap[5] as Hex);
  const revealedShareB = hexToBytes(cap[7] as Hex);
  const kemCt2 = onchainBlob.slice(0, 1568);
  const wrapIv2 = onchainBlob.slice(1568, 1580);
  const wrappedA2 = onchainBlob.slice(1580);
  const ss = ml_kem1024.decapsulate(kemCt2, recipientKeys.secretKey);
  const kek2 = new Uint8Array(await crypto.subtle.digest("SHA-256", ss as BufferSource));
  const recoveredA = await aes(kek2, "decrypt", wrapIv2, wrappedA2);
  const recoveredKey = xor(recoveredA, revealedShareB);
  const opened = await aes(recoveredKey, "decrypt", msgIv, msgCt);
  const text = dec.decode(opened);
  console.log("OPENED MESSAGE:", text);
  if (text !== dec.decode(message)) throw new Error("decrypted text mismatch");
  console.log("\nON-CHAIN E2E PASSED: sealed -> early reveal blocked -> revealed at unlock -> opened");
}

main().catch((err: unknown) => {
  console.error("E2E failed:", err instanceof Error ? err.message : err);
  process.exitCode = 1;
});
