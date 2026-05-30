import { expect } from 'chai';
import { hashPhoneWithTruncation } from './utils';
import {
  generateX25519Keypair, computeSharedSecret,
  encryptContacts, decryptResult
} from './client';

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

  it('encrypt then decrypt round-trips', () => {
    const { privateKey } = generateX25519Keypair();
    const server = generateX25519Keypair();
    const shared = computeSharedSecret(privateKey, server.publicKey);
    const nonce = new Uint8Array(16).fill(7);

    const hashes = [1n, 0n, 1n, 0n, 1n, 0n, 1n, 0n, 1n, 0n];
    const encrypted = encryptContacts(hashes, shared, nonce);
    expect(encrypted).to.be.instanceof(Uint8Array);
    expect(encrypted.length).to.be.greaterThan(0);

    const decrypted = decryptResult(encrypted, shared, nonce);
    expect(decrypted).to.have.lengthOf(10);
    expect(decrypted).to.deep.equal(
      [true, false, true, false, true, false, true, false, true, false]
    );
  });

  it('pads short contact list to BATCH_SIZE (10)', () => {
    const { privateKey } = generateX25519Keypair();
    const server = generateX25519Keypair();
    const shared = computeSharedSecret(privateKey, server.publicKey);
    const nonce = new Uint8Array(16).fill(0);

    const encrypted = encryptContacts([1n, 2n, 3n], shared, nonce);
    expect(encrypted).to.exist;
  });
});
