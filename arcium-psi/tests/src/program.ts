import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  TransactionInstruction,
  Transaction,
  AddressLookupTableProgram,
} from '@solana/web3.js';
import { AnchorProvider, BN } from '@coral-xyz/anchor';
import { sha256 } from '@noble/hashes/sha256';
import {
  getMXEAccAddress,
  getCompDefAccAddress,
  getComputationAccAddress,
  getMempoolAccAddress,
  getExecutingPoolAccAddress,
  getFeePoolAccAddress,
  getClockAccAddress,
  getClusterAccAddress,
  getArciumProgramId,
  getLookupTableAddress,
  awaitComputationFinalization,
} from '@arcium-hq/client';

// ── Constants ──────────────────────────────────────────────────────────────────

export const PROGRAM_ID = new PublicKey('PSiArc1um1111111111111111111111111111111111');

const ARCIUM_PROGRAM_ID = getArciumProgramId();

// Cluster offset used by this MXE — 1 is the default on devnet.
const CLUSTER_OFFSET = 1;

const BATCH_SIZE = 10;

// ── Discriminators (SHA256("global:<name>")[0..8]) ────────────────────────────

function ixDisc(name: string): Buffer {
  const h = sha256(new TextEncoder().encode(`global:${name}`));
  return Buffer.from(h.slice(0, 8));
}

const DISC_INIT_USER                = ixDisc('init_user');
const DISC_SUBMIT_QUERY             = ixDisc('submit_query');
const DISC_INIT_PSI_COMP_DEF        = ixDisc('init_psi_intersect_comp_def');
const DISC_SUBMIT_PSI_QUERY         = ixDisc('submit_psi_query');

// ── Arcium comp_def_offset (SHA256("<name>")[0..4] as LE u32) ─────────────────

function compDefOffset(name: string): number {
  const h = sha256(new TextEncoder().encode(name));
  return new DataView(h.buffer, h.byteOffset, 4).getUint32(0, true);
}

export const PSI_COMP_DEF_OFFSET = compDefOffset('psi_intersect');

// ── PDA derivation ─────────────────────────────────────────────────────────────

export function getUserStatePda(owner: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from('user'), owner.toBuffer()],
    PROGRAM_ID,
  )[0];
}

// SIGN_PDA_SEED = stringify!(ArciumSignerAccount) = b"ArciumSignerAccount"
export function getSignPda(): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from('ArciumSignerAccount')],
    PROGRAM_ID,
  )[0];
}

export function getPsiCompDefAccount(): PublicKey {
  return getCompDefAccAddress(PROGRAM_ID, PSI_COMP_DEF_OFFSET);
}

// ── SharedEncryptedStruct<10> serialization ───────────────────────────────────
// Borsh layout:
//   [u8; 32]       encryption_key
//   u128 (16 bytes LE)  nonce
//   [[u8;32]; 10]  ciphertexts  (10 × 32 = 320 bytes)
// Total: 368 bytes

export function serializeSharedEncrypted(
  encryptionKey: Uint8Array,  // 32 bytes — X25519 public key
  nonce: Uint8Array,          // 16 bytes LE — RescueCipher nonce
  ciphertexts: Uint8Array,    // 320 bytes — 10 × 32-byte encrypted u64s
): Buffer {
  if (encryptionKey.length !== 32)  throw new Error('encryptionKey must be 32 bytes');
  if (nonce.length !== 16)          throw new Error('nonce must be 16 bytes');
  if (ciphertexts.length !== BATCH_SIZE * 32) throw new Error(`ciphertexts must be ${BATCH_SIZE * 32} bytes`);
  const buf = Buffer.alloc(368);
  buf.set(encryptionKey, 0);
  buf.set(nonce,         32);
  buf.set(ciphertexts,   48);
  return buf;
}

// ── init_user ──────────────────────────────────────────────────────────────────
// Accounts: userState (init, PDA), payer (mut signer), systemProgram

export function buildInitUserIx(payer: PublicKey): TransactionInstruction {
  const userState = getUserStatePda(payer);
  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: userState,               isSigner: false, isWritable: true  },
      { pubkey: payer,                   isSigner: true,  isWritable: true  },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: DISC_INIT_USER,
  });
}

export async function initUser(connection: Connection, payer: Keypair): Promise<string> {
  const ix  = buildInitUserIx(payer.publicKey);
  const { blockhash } = await connection.getLatestBlockhash();
  const tx  = new Transaction({ recentBlockhash: blockhash, feePayer: payer.publicKey }).add(ix);
  tx.sign(payer);
  const sig = await connection.sendRawTransaction(tx.serialize());
  await connection.confirmTransaction(sig, 'confirmed');
  return sig;
}

// ── submit_query (legacy, pre-MPC) ────────────────────────────────────────────
// Accounts: userState (mut, has_one = owner), owner (signer)

export function buildSubmitQueryIx(
  owner: PublicKey,
  encryptedContacts: Uint8Array,
  nonce: bigint,
): TransactionInstruction {
  const userState = getUserStatePda(owner);

  // Args: encrypted_contacts (Vec<u8>): 4-byte LE length prefix + bytes
  //       nonce (u64): 8 bytes LE
  const contactsBuf = Buffer.from(encryptedContacts);
  const lenBuf      = Buffer.alloc(4);
  lenBuf.writeUInt32LE(contactsBuf.length, 0);
  const nonceBuf    = Buffer.alloc(8);
  nonceBuf.writeBigUInt64LE(nonce, 0);

  const data = Buffer.concat([DISC_SUBMIT_QUERY, lenBuf, contactsBuf, nonceBuf]);
  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: userState, isSigner: false, isWritable: true  },
      { pubkey: owner,     isSigner: true,  isWritable: false },
    ],
    data,
  });
}

// ── init_psi_intersect_comp_def ───────────────────────────────────────────────
// One-time setup: registers the PSI circuit definition on-chain.
// Accounts: authority (mut signer), mxeAccount (mut), compDefAccount (mut),
//           addressLookupTable (mut), lutProgram, systemProgram, arciumProgram

export async function buildInitPsiCompDefIx(
  provider: AnchorProvider,
  authority: PublicKey,
): Promise<TransactionInstruction> {
  const mxeAccount    = getMXEAccAddress(PROGRAM_ID);
  const compDefAccount = getPsiCompDefAccount();

  // Lookup table address comes from the MXE account's lut_last_slot field.
  const arciumMxe = await provider.connection.getAccountInfo(mxeAccount);
  // lut_offset lives at byte 8 (discriminator) + layout offset. For now derive with BN(0).
  // Update lutOffset to mxeAccount.lutLastSlot once the account is on-chain.
  const lutOffset = new BN(0);
  const addressLookupTable = getLookupTableAddress(PROGRAM_ID, lutOffset);

  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: authority,             isSigner: true,  isWritable: true  },
      { pubkey: mxeAccount,            isSigner: false, isWritable: true  },
      { pubkey: compDefAccount,        isSigner: false, isWritable: true  },
      { pubkey: addressLookupTable,    isSigner: false, isWritable: true  },
      { pubkey: AddressLookupTableProgram.programId, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId,             isSigner: false, isWritable: false },
      { pubkey: ARCIUM_PROGRAM_ID,                   isSigner: false, isWritable: false },
    ],
    data: DISC_INIT_PSI_COMP_DEF,
  });
}

// ── submit_psi_query ──────────────────────────────────────────────────────────
// Queues a blind PSI computation on the Arcium MPC cluster.
// Accounts (order matches SubmitPsiQuery struct):
//   user (mut signer), mxeAccount, signPdaAccount (mut),
//   mempoolAccount (mut), executingPool (mut), computationAccount (mut),
//   compDefAccount, clusterAccount (mut), poolAccount (mut),
//   clockAccount (mut), systemProgram, arciumProgram

export function buildSubmitPsiQueryIx(
  user: PublicKey,
  clientEncKey: Uint8Array,
  clientNonce: Uint8Array,
  clientCiphertexts: Uint8Array,
  serverEncKey: Uint8Array,
  serverNonce: Uint8Array,
  serverCiphertexts: Uint8Array,
  computationOffset: bigint,
): TransactionInstruction {
  const compOffsetBN   = new BN(computationOffset.toString());
  const mxeAccount     = getMXEAccAddress(PROGRAM_ID);
  const signPda        = getSignPda();
  const mempoolAccount = getMempoolAccAddress(CLUSTER_OFFSET);
  const executingPool  = getExecutingPoolAccAddress(CLUSTER_OFFSET);
  const computationAccount = getComputationAccAddress(CLUSTER_OFFSET, compOffsetBN);
  const compDefAccount = getPsiCompDefAccount();
  const clusterAccount = getClusterAccAddress(CLUSTER_OFFSET);
  const poolAccount    = getFeePoolAccAddress();
  const clockAccount   = getClockAccAddress();

  // Data: disc (8) + clientData (368) + serverData (368) + computation_offset u64 (8) = 752 bytes
  const offsetBuf = Buffer.alloc(8);
  offsetBuf.writeBigUInt64LE(computationOffset, 0);
  const data = Buffer.concat([
    DISC_SUBMIT_PSI_QUERY,
    serializeSharedEncrypted(clientEncKey, clientNonce, clientCiphertexts),
    serializeSharedEncrypted(serverEncKey, serverNonce, serverCiphertexts),
    offsetBuf,
  ]);

  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: user,               isSigner: true,  isWritable: true  },
      { pubkey: mxeAccount,         isSigner: false, isWritable: false },
      { pubkey: signPda,            isSigner: false, isWritable: true  },
      { pubkey: mempoolAccount,     isSigner: false, isWritable: true  },
      { pubkey: executingPool,      isSigner: false, isWritable: true  },
      { pubkey: computationAccount, isSigner: false, isWritable: true  },
      { pubkey: compDefAccount,     isSigner: false, isWritable: false },
      { pubkey: clusterAccount,     isSigner: false, isWritable: true  },
      { pubkey: poolAccount,        isSigner: false, isWritable: true  },
      { pubkey: clockAccount,       isSigner: false, isWritable: true  },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      { pubkey: ARCIUM_PROGRAM_ID,       isSigner: false, isWritable: false },
    ],
    data,
  });
}

export async function submitPsiQuery(
  provider: AnchorProvider,
  user: Keypair,
  clientEncKey: Uint8Array,
  clientNonce: Uint8Array,
  clientCiphertexts: Uint8Array,
  serverEncKey: Uint8Array,
  serverNonce: Uint8Array,
  serverCiphertexts: Uint8Array,
  computationOffset: bigint,
): Promise<{ txSig: string; callbackSig: string }> {
  const ix = buildSubmitPsiQueryIx(
    user.publicKey,
    clientEncKey, clientNonce, clientCiphertexts,
    serverEncKey, serverNonce, serverCiphertexts,
    computationOffset,
  );

  const { blockhash } = await provider.connection.getLatestBlockhash();
  const tx = new Transaction({
    recentBlockhash: blockhash,
    feePayer: user.publicKey,
  }).add(ix);
  tx.sign(user);

  const txSig = await provider.connection.sendRawTransaction(tx.serialize());
  await provider.connection.confirmTransaction(txSig, 'confirmed');

  // Wait for Arcium Arx nodes to deliver the psi_intersect_callback.
  const callbackSig = await awaitComputationFinalization(
    provider,
    new BN(computationOffset.toString()),
    PROGRAM_ID,
  );

  return { txSig, callbackSig };
}
