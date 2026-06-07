import { expect } from 'chai';
import { sha256 } from '@noble/hashes/sha256';
import { PublicKey, Keypair } from '@solana/web3.js';
import { AnchorProvider } from '@coral-xyz/anchor';
import { hashPhoneWithTruncation } from './utils';
import {
  PROGRAM_ID,
  serializeSharedEncrypted,
  getUserStatePda,
  getSignPda,
  getPsiCompDefAccount,
  buildInitUserIx,
  buildSubmitPsiQueryIx,
  buildInitPsiCompDefIx,
} from './program';

// ── Known constants ───────────────────────────────────────────────────────────
const CONTACT_HASH_TEST_VECTOR = 5364562789390625858n;
// TODO at devnet deploy: verify this matches sha256(psi_intersect.arcis.ir) from fresh `arcis build`
const CIRCUIT_HASH = '1e1b485ae0a279683f2b39f7a3dd01570e8968b250234b6a7452e0aef9d5a767';
const BATCH_SIZE = 10;
const SERIALIZED_SIZE = 368;

// ── Block 1: Contact Hash Consistency ────────────────────────────────────────

describe('OFFLINE — Contact Hash Consistency', () => {

  it('Rust==TS test vector: +1234567890 = 5364562789390625858', () => {
    expect(hashPhoneWithTruncation('+1234567890')).to.equal(CONTACT_HASH_TEST_VECTOR);
  });

  it('hash is Little-Endian truncation of SHA256', () => {
    const hash = sha256(new TextEncoder().encode('+1234567890'));
    const view = new DataView(hash.buffer, hash.byteOffset, 8);
    const result = view.getBigUint64(0, true); // little-endian
    expect(result).to.equal(CONTACT_HASH_TEST_VECTOR);
  });

  it('different phones produce different hashes', () => {
    expect(hashPhoneWithTruncation('+1')).to.not.equal(hashPhoneWithTruncation('+2'));
  });

  it('CIRCUIT_HASH is a valid 64-char hex string (32-byte SHA256)', () => {
    expect(CIRCUIT_HASH).to.match(/^[0-9a-f]{64}$/);
  });

});

// ── Block 2: Serialization ────────────────────────────────────────────────────

describe('OFFLINE — Serialization', () => {

  it('serializeSharedEncrypted returns exactly 368 bytes', () => {
    const key        = new Uint8Array(32).fill(1);
    const nonce      = new Uint8Array(16).fill(2);
    const ciphertexts = new Uint8Array(BATCH_SIZE * 32).fill(3);
    const result = serializeSharedEncrypted(key, nonce, ciphertexts);
    expect(result.length).to.equal(SERIALIZED_SIZE);
  });

  it('different inputs produce different bytes', () => {
    const nonce       = new Uint8Array(16).fill(0);
    const ciphertexts = new Uint8Array(BATCH_SIZE * 32).fill(0);
    const r1 = serializeSharedEncrypted(new Uint8Array(32).fill(1), nonce, ciphertexts);
    const r2 = serializeSharedEncrypted(new Uint8Array(32).fill(2), nonce, ciphertexts);
    expect(Array.from(r1)).to.not.deep.equal(Array.from(r2));
  });

});

// ── Block 3: PDA Derivation & Instruction Builders ───────────────────────────

describe('OFFLINE — PDA Derivation & Instruction Builders', () => {

  it('getUserStatePda returns deterministic PDA for same owner', () => {
    const owner = Keypair.generate().publicKey;
    expect(getUserStatePda(owner).toBase58()).to.equal(getUserStatePda(owner).toBase58());
  });

  it('getUserStatePda returns different PDA for different owners', () => {
    const pda1 = getUserStatePda(Keypair.generate().publicKey).toBase58();
    const pda2 = getUserStatePda(Keypair.generate().publicKey).toBase58();
    expect(pda1).to.not.equal(pda2);
  });

  it('getSignPda is deterministic', () => {
    expect(getSignPda().toBase58()).to.equal(getSignPda().toBase58());
  });

  it('getPsiCompDefAccount is deterministic', () => {
    expect(getPsiCompDefAccount().toBase58()).to.equal(getPsiCompDefAccount().toBase58());
  });

  it('buildInitUserIx returns valid TransactionInstruction', () => {
    const payer = Keypair.generate().publicKey;
    const ix = buildInitUserIx(payer);
    expect(ix.programId.toBase58()).to.equal(PROGRAM_ID.toBase58());
    expect(ix.keys.length).to.be.greaterThan(0);
    expect(ix.data).to.be.instanceof(Buffer);
  });

  it('buildSubmitPsiQueryIx accepts BATCH_SIZE=10 hashes', () => {
    const user            = Keypair.generate();
    const dummyKey        = new Uint8Array(32).fill(1);
    const dummyNonce      = new Uint8Array(16).fill(2);
    const dummyCiphertexts = new Uint8Array(BATCH_SIZE * 32).fill(3);
    const ix = buildSubmitPsiQueryIx(
      user.publicKey,
      dummyKey, dummyNonce, dummyCiphertexts,
      dummyKey, dummyNonce, dummyCiphertexts,
      0n,
    );
    expect(ix.programId.toBase58()).to.equal(PROGRAM_ID.toBase58());
  });

  it('buildInitPsiCompDefIx builds instruction (lutOffset=BN(0) placeholder)', async () => {
    // TODO at devnet deploy: replace lutOffset=new BN(0)
    // with real mxeAccount.lutLastSlot read from on-chain
    const mockProvider = {
      connection: {
        getAccountInfo: async () => null,
      },
    } as unknown as AnchorProvider;
    const authority = Keypair.generate().publicKey;
    const ix = await buildInitPsiCompDefIx(mockProvider, authority);
    expect(ix.programId.toBase58()).to.equal(PROGRAM_ID.toBase58());
  });

});

// ── Block 4: Full PSI Flow (requires devnet) ──────────────────────────────────

describe('ONLINE — Full PSI Flow (requires devnet)', () => {
  let skipOnline = true;

  before(async () => {
    // Skip all online tests if no RPC available (network blocked in CI sandbox)
    try {
      const rpc = process.env.ANCHOR_PROVIDER_URL ?? 'https://api.devnet.solana.com';
      skipOnline = !rpc || rpc === '';
    } catch { skipOnline = true; }
  });

  it('initUser — creates user state PDA on devnet', async function (this: Mocha.Context) {
    if (skipOnline) return;
    // TODO after devnet deploy:
    // 1. Load payer from ANCHOR_WALLET env
    // 2. Call initUser(connection, payer)
    // 3. Fetch getUserStatePda(payer.publicKey) account
    // 4. Assert account exists (not null)
    this.skip();
  });

  it('submitPsiQuery — runs full PSI flow on devnet', async function (this: Mocha.Context) {
    if (skipOnline) return;
    // TODO after devnet deploy:
    // Alice contacts: ["+1234567890", "+0987654321", "+1111111111"]
    // Bob contacts:   ["+1234567890", "+9999999999", "+1111111111"]
    // Expected intersection: ["+1234567890", "+1111111111"]
    //
    // Steps:
    // 1. Hash all contacts with hashPhoneWithTruncation
    // 2. Encrypt Alice's hashes with RescueCipher (see client.ts)
    // 3. Call submitPsiQuery(provider, user, encryptedHashes)
    // 4. Await awaitComputationFinalization
    // 5. Decrypt and verify intersection
    this.skip();
  });

  it('contact hash in PSI result matches test vector', async function (this: Mocha.Context) {
    if (skipOnline) return;
    // After real run: verify +1234567890 is in intersection
    this.skip();
  });

});
