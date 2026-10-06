import { expect } from 'chai';
import { Keypair } from '@solana/web3.js';
import { RescueCipher } from '@arcium-hq/client';
import { hashPhoneWithTruncation } from './utils';
import {
  BATCH_SIZE, CIPHERTEXTS, PsiRequest,
  generateX25519Keypair, computeSharedSecret,
  contactInputPlaintext, encryptContacts, decryptResult, resultNonceFor,
} from './client';
import { buildSubmitPsiQueryIx, serializeSharedEncrypted } from './program';

const P = (1n << 255n) - 19n;
const H1 = hashPhoneWithTruncation('+1234567890');
const H2 = hashPhoneWithTruncation('+0987654321');
const H3 = hashPhoneWithTruncation('+1111111111');

function sharedSecret(): Uint8Array {
  const a = generateX25519Keypair();
  const b = generateX25519Keypair();
  return computeSharedSecret(a.privateKey, b.publicKey);
}

function toBytes(chunks: number[][]): Uint8Array {
  const out = new Uint8Array(chunks.length * 32);
  chunks.forEach((c, i) => out.set(c, i * 32));
  return out;
}

function fromBytes(bytes: Uint8Array): number[][] {
  const chunks: number[][] = [];
  for (let i = 0; i < bytes.length; i += 32) chunks.push(Array.from(bytes.slice(i, i + 32)));
  return chunks;
}

/** Encrypts a MatchResult plaintext (BATCH_SIZE flags, then the validity flag) as the circuit would. */
function circuitResult(values: bigint[], secret: Uint8Array, request: PsiRequest) {
  const nonce = resultNonceFor(request);
  return { nonce, ciphertexts: toBytes(new RescueCipher(secret).encrypt(values, nonce)) };
}

function flags(trueSlots: number[], valid = 1n): bigint[] {
  const v: bigint[] = Array(BATCH_SIZE).fill(0n);
  trueSlots.forEach(i => (v[i] = 1n));
  return [...v, valid];
}

describe('Client Crypto (local, no devnet)', () => {

  it('hash truncation is deterministic and LE', () => {
    const a = hashPhoneWithTruncation('+1234567890');
    const b = hashPhoneWithTruncation('+1234567890');
    expect(a).to.equal(b);           // deterministic
    expect(typeof a).to.equal('bigint');
    // Cross-language canonical vector — must match Rust contact_hash::hash_contact("+1234567890").
    // sha256("+1234567890")[0..8] as little-endian u64
    expect(a).to.equal(5364562789390625858n);
  });

  it('X25519 ECDH is symmetric', () => {
    const alice = generateX25519Keypair();
    const bob = generateX25519Keypair();
    const aliceShared = computeSharedSecret(alice.privateKey, bob.publicKey);
    const bobShared = computeSharedSecret(bob.privateKey, alice.publicKey);
    expect(aliceShared).to.deep.equal(bobShared);
  });
});

describe('PSI request', () => {

  it('encrypts the hashes, zero padding and the count, and keeps count and nonce', () => {
    const secret = sharedSecret();
    const nonce = new Uint8Array(16).fill(7);
    const request = encryptContacts([H1, 0n, H3], secret, nonce);
    nonce.fill(9); // the request keeps its own copy
    expect(request.count).to.equal(3);
    expect(Array.from(request.nonce)).to.deep.equal(Array(16).fill(7));
    expect(request.ciphertexts.length).to.equal(CIPHERTEXTS * 32);
    const plain = new RescueCipher(secret).decrypt(fromBytes(request.ciphertexts), request.nonce);
    expect(plain).to.deep.equal([H1, 0n, H3, ...Array(7).fill(0n), 3n]);
  });

  it('accepts 0 and 10 contacts and the whole u64 range', () => {
    expect(contactInputPlaintext([])).to.deep.equal([...Array(BATCH_SIZE).fill(0n), 0n]);
    const ten = Array.from({ length: 10 }, (_, i) => BigInt(i));
    expect(contactInputPlaintext(ten)).to.deep.equal([...ten, 10n]);
    const edges = [0n, (1n << 64n) - 1n];
    expect(contactInputPlaintext(edges)).to.deep.equal([...edges, ...Array(8).fill(0n), 2n]);
  });

  it('rejects more than ten contacts instead of dropping some (R5)', () => {
    const eleven = Array.from({ length: 11 }, (_, i) => BigInt(i + 1));
    expect(() => contactInputPlaintext(eleven)).to.throw(/at most 10 contacts/);
    expect(() => encryptContacts(eleven, sharedSecret(), new Uint8Array(16))).to.throw(/at most 10/);
  });

  it('rejects hashes outside the u64 range (R6)', () => {
    for (const bad of [-1n, 1n << 64n, (1n << 64n) + 5n, P - 1n]) {
      expect(() => contactInputPlaintext([H1, bad]), String(bad)).to.throw(/not a u64/);
    }
    expect(() => contactInputPlaintext([5 as unknown as bigint])).to.throw(/not a u64/);
  });
});

describe('PSI result', () => {
  const secret = sharedSecret();
  const request = encryptContacts([H1, H2, H3], secret, new Uint8Array(16).fill(3));

  it('returns one answer per real contact', () => {
    expect(decryptResult(circuitResult(flags([0, 2]), secret, request), secret, request))
      .to.deep.equal([true, false, true]);
  });

  it('handles counts 0 and 10', () => {
    const empty = encryptContacts([], secret, new Uint8Array(16).fill(4));
    expect(decryptResult(circuitResult(flags([]), secret, empty), secret, empty)).to.deep.equal([]);
    const all = Array.from({ length: 10 }, (_, i) => BigInt(i));
    const full = encryptContacts(all, secret, new Uint8Array(16).fill(5));
    const every = Array.from({ length: 10 }, (_, i) => i);
    expect(decryptResult(circuitResult(flags(every), secret, full), secret, full))
      .to.deep.equal(Array(10).fill(true));
  });

  it('rejects a result the circuit marked invalid', () => {
    expect(() => decryptResult(circuitResult(flags([], 0n), secret, request), secret, request))
      .to.throw(/rejected a count/);
  });

  it('rejects any value other than 0 or 1, in a real slot, a padding slot or the flag (R8)', () => {
    for (const slot of [0, 2, 7, BATCH_SIZE]) {
      const values = flags([0]);
      values[slot] = 2n;
      expect(() => decryptResult(circuitResult(values, secret, request), secret, request), `slot ${slot}`)
        .to.throw(/other than 0 or 1/);
    }
  });

  it('rejects a set padding slot', () => {
    expect(() => decryptResult(circuitResult(flags([0, 3]), secret, request), secret, request))
      .to.throw(/padding slot/);
  });

  it('rejects a result of the wrong size or with a nonce that does not follow the request', () => {
    const good = circuitResult(flags([0]), secret, request);
    for (const n of [0, BATCH_SIZE * 32, CIPHERTEXTS * 32 + 32]) {
      expect(() => decryptResult({ ...good, ciphertexts: new Uint8Array(n) }, secret, request)).to.throw(/must be 352 bytes/);
    }
    expect(() => decryptResult({ ...good, nonce: request.nonce }, secret, request)).to.throw(/nonce/);
    const bad: PsiRequest = { ...request, count: 11 };
    expect(() => decryptResult(good, secret, bad)).to.throw(/count out of range/);
  });

  it('computes the result nonce as request nonce + 1, wrapping at 2^128', () => {
    const r = (nonce: number[]) => Array.from(resultNonceFor({ ...request, nonce: Uint8Array.from(nonce) }));
    expect(r([0, ...Array(15).fill(0)])).to.deep.equal([1, ...Array(15).fill(0)]);
    expect(r([255, 1, ...Array(14).fill(0)])).to.deep.equal([0, 2, ...Array(14).fill(0)]);
    expect(r(Array(16).fill(255))).to.deep.equal(Array(16).fill(0));
  });

  // Evidence for this sample only: a wrong key decrypts to field elements that
  // are almost never 0 or 1. It does not show every wrong key is rejected.
  it('rejects a sample result decrypted with the wrong key', () => {
    const result = circuitResult(flags([0]), secret, request);
    expect(() => decryptResult(result, sharedSecret(), request)).to.throw(/other than 0 or 1/);
  });

  // The checks are not authentication: adding 1 to a ciphertext adds 1 to its
  // plaintext, so a "no" can become a "yes" and still pass.
  it('does not detect a ciphertext changed from 0 to 1', () => {
    const result = circuitResult(flags([0]), secret, request);
    const chunk = result.ciphertexts.slice(32, 64);
    let v = 0n;
    for (let i = 31; i >= 0; i--) v = (v << 8n) | BigInt(chunk[i]);
    v = (v + 1n) % P;
    const tampered = Uint8Array.from(result.ciphertexts);
    for (let i = 0; i < 32; i++) { tampered[32 + i] = Number(v & 0xffn); v >>= 8n; }
    expect(decryptResult({ ...result, ciphertexts: tampered }, secret, request))
      .to.deep.equal([true, true, false]);
  });
});

describe('PSI serialization', () => {

  it('SharedEncryptedStruct<11> is 400 bytes and needs 11 ciphertexts', () => {
    const key = new Uint8Array(32).fill(1);
    const nonce = new Uint8Array(16).fill(2);
    const out = serializeSharedEncrypted(key, nonce, new Uint8Array(CIPHERTEXTS * 32).fill(3));
    expect(out.length).to.equal(400);
    expect(Array.from(out.subarray(0, 32))).to.deep.equal(Array(32).fill(1));
    expect(Array.from(out.subarray(32, 48))).to.deep.equal(Array(16).fill(2));
    expect(() => serializeSharedEncrypted(key, nonce, new Uint8Array(BATCH_SIZE * 32))).to.throw(/352 bytes/);
  });

  it('submit_psi_query data is discriminator + two inputs + offset (816 bytes)', () => {
    const c = new Uint8Array(CIPHERTEXTS * 32);
    const ix = buildSubmitPsiQueryIx(
      Keypair.generate().publicKey,
      new Uint8Array(32).fill(1), new Uint8Array(16), c,
      new Uint8Array(32).fill(2), new Uint8Array(16), c,
      7n,
    );
    expect(ix.data.length).to.equal(8 + 400 + 400 + 8);
    expect(ix.data.readBigUInt64LE(816 - 8)).to.equal(7n);
  });
});
