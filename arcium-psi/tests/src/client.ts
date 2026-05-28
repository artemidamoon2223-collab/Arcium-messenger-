import { x25519 } from '@noble/curves/ed25519';
import { RescueCipher } from '@arcium-hq/client';

const BATCH_SIZE = 10;

export function generateX25519Keypair(): { privateKey: Uint8Array; publicKey: Uint8Array } {
  const privateKey = x25519.utils.randomSecretKey();
  const publicKey = x25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

export function computeSharedSecret(
  clientPrivate: Uint8Array,
  serverPublic: Uint8Array
): Uint8Array {
  return x25519.getSharedSecret(clientPrivate, serverPublic);
}

export function encryptContacts(
  phoneHashes: bigint[],
  sharedSecret: Uint8Array,
  nonce: Uint8Array
): Uint8Array {
  const padded = phoneHashes.slice(0, BATCH_SIZE);
  while (padded.length < BATCH_SIZE) padded.push(0n);

  // RescueCipher.encrypt: (bigint[], Uint8Array) → number[][] (each inner = 32 bytes)
  const cipher = new RescueCipher(sharedSecret);
  const chunks: number[][] = cipher.encrypt(padded, nonce);

  const flat = new Uint8Array(chunks.length * 32);
  chunks.forEach((chunk, i) => flat.set(chunk, i * 32));
  return flat;
}

export function decryptResult(
  ciphertext: Uint8Array,
  sharedSecret: Uint8Array,
  nonce: Uint8Array
): boolean[] {
  // Split flat bytes back into 32-byte chunks for RescueCipher.decrypt
  const chunks: number[][] = [];
  for (let i = 0; i < ciphertext.length; i += 32) {
    chunks.push(Array.from(ciphertext.slice(i, i + 32)));
  }

  const cipher = new RescueCipher(sharedSecret);
  const decrypted: bigint[] = cipher.decrypt(chunks, nonce);
  return decrypted.map(val => val > 0n);
}
