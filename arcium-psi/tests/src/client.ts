import { x25519 } from '@noble/curves/ed25519';
import { RescueCipher } from '@arcium-hq/client';

export const BATCH_SIZE = 10;

/**
 * Ciphertexts in one encrypted input or result of `psi_intersect`: BATCH_SIZE
 * slots, then the count of real entries (inputs) or the validity flag (result).
 */
export const CIPHERTEXTS = BATCH_SIZE + 1;

const U64_LIMIT = 1n << 64n;
const U128_LIMIT = 1n << 128n;

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

/**
 * The plaintexts of one side's input, in the order the circuit reads
 * `ClientContacts` and `ServerContacts`: BATCH_SIZE hashes with the real ones
 * first, then their count. The circuit compares real entries only, so the
 * padding value does not matter; it is zero here.
 */
export function contactInputPlaintext(phoneHashes: bigint[]): bigint[] {
  if (phoneHashes.length > BATCH_SIZE) {
    throw new Error(`at most ${BATCH_SIZE} contacts per query, got ${phoneHashes.length}`);
  }
  for (const hash of phoneHashes) {
    if (typeof hash !== 'bigint' || hash < 0n || hash >= U64_LIMIT) {
      throw new Error(`contact hash is not a u64: ${String(hash)}`);
    }
  }
  const values = [...phoneHashes];
  while (values.length < BATCH_SIZE) values.push(0n);
  values.push(BigInt(phoneHashes.length));
  return values;
}

/**
 * A query as sent, kept until its result arrives: how many of its slots are
 * real, and the nonce its result must follow. Keeping them lets
 * `decryptResult` read the result; it does not authenticate the result or
 * prove it answers this query.
 */
export interface PsiRequest {
  readonly count: number;
  readonly nonce: Uint8Array;
  /** CIPHERTEXTS × 32 bytes. */
  readonly ciphertexts: Uint8Array;
}

/** An encrypted `MatchResult` as returned by the circuit. */
export interface PsiResult {
  readonly nonce: Uint8Array;
  /** CIPHERTEXTS × 32 bytes. */
  readonly ciphertexts: Uint8Array;
}

export function encryptContacts(
  phoneHashes: bigint[],
  sharedSecret: Uint8Array,
  nonce: Uint8Array
): PsiRequest {
  const values = contactInputPlaintext(phoneHashes);
  // RescueCipher.encrypt: (bigint[], Uint8Array) → number[][] (each inner = 32 bytes)
  const chunks: number[][] = new RescueCipher(sharedSecret).encrypt(values, nonce);
  const ciphertexts = new Uint8Array(chunks.length * 32);
  chunks.forEach((chunk, i) => ciphertexts.set(chunk, i * 32));
  return { count: phoneHashes.length, nonce: Uint8Array.from(nonce), ciphertexts };
}

/**
 * The nonce the circuit encrypts its result with: the request's nonce plus
 * one, as a 128-bit little-endian integer (Arcis `Shared::from_arcis`).
 */
export function resultNonceFor(request: PsiRequest): Uint8Array {
  if (request.nonce.length !== 16) throw new Error('request nonce must be 16 bytes');
  let value = 0n;
  for (let i = 15; i >= 0; i--) value = (value << 8n) | BigInt(request.nonce[i]);
  value = (value + 1n) % U128_LIMIT;
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    out[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return out;
}

/**
 * Decrypts the result of `request` and returns, for each of its real
 * contacts in order, whether the server has it.
 *
 * Throws unless the result uses the nonce that follows the request's, every
 * decrypted value is exactly 0 or 1, the validity flag is 1 (both counts were
 * in range), and every slot past the request's count is 0. These checks
 * reject a malformed, mis-keyed or out-of-contract result. They do not
 * authenticate it: RescueCipher is unauthenticated counter mode, so a changed
 * ciphertext can turn a 0 into a 1 without failing them.
 */
export function decryptResult(
  result: PsiResult,
  sharedSecret: Uint8Array,
  request: PsiRequest
): boolean[] {
  if (!Number.isInteger(request.count) || request.count < 0 || request.count > BATCH_SIZE) {
    throw new Error(`request count out of range: ${request.count}`);
  }
  if (result.ciphertexts.length !== CIPHERTEXTS * 32) {
    throw new Error(`result must be ${CIPHERTEXTS * 32} bytes, got ${result.ciphertexts.length}`);
  }
  const expectedNonce = resultNonceFor(request);
  if (result.nonce.length !== 16 || !expectedNonce.every((b, i) => b === result.nonce[i])) {
    throw new Error('result nonce does not follow the request nonce');
  }

  const chunks: number[][] = [];
  for (let i = 0; i < result.ciphertexts.length; i += 32) {
    chunks.push(Array.from(result.ciphertexts.slice(i, i + 32)));
  }
  const values: bigint[] = new RescueCipher(sharedSecret).decrypt(chunks, result.nonce);

  if (!values.every(v => v === 0n || v === 1n)) {
    throw new Error('result holds a value other than 0 or 1');
  }
  if (values[BATCH_SIZE] !== 1n) {
    throw new Error('the circuit rejected a count: the result is invalid');
  }
  if (values.slice(request.count, BATCH_SIZE).some(v => v !== 0n)) {
    throw new Error('a padding slot is set in the result');
  }
  return values.slice(0, request.count).map(v => v === 1n);
}
