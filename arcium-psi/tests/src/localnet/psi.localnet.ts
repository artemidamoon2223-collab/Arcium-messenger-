// Localnet integration test for the Arcium PSI program. Run only through
// `arcium test` (Anchor.toml [scripts] test), which starts a local validator
// with the Arcium programs, the Arx MPC nodes, and this program at genesis.
// Every step talks to that environment; nothing here is mocked or skipped.
//
// Follows the Arcium 0.10.4 example tests (arcium-hq/examples, coinflip at the
// v0.10.4 tag): init the computation definition, upload the circuit, encrypt
// inputs to the MXE key, queue the computation, await finalization.

import * as anchor from '@anchor-lang/core';
import {
  AddressLookupTableProgram,
  PublicKey,
  TransactionMessage,
  VersionedTransaction,
} from '@solana/web3.js';
import { expect } from 'chai';
import { randomBytes } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import {
  awaitComputationFinalization,
  deserializeLE,
  getArciumEnv,
  getArciumProgram,
  getClockAccAddress,
  getClusterAccAddress,
  getCompDefAccAddress,
  getCompDefAccOffset,
  getComputationAccAddress,
  getExecutingPoolAccAddress,
  getFeePoolAccAddress,
  getLookupTableAddress,
  getMempoolAccAddress,
  getMXEAccAddress,
  getMXEPublicKey,
  getRawCircuitAccAddress,
  RescueCipher,
  uploadCircuit,
  x25519,
} from '@arcium-hq/client';
import { hashPhoneWithTruncation } from '../utils';

const ROOT = path.resolve(__dirname, '../../..');
const IDL_PATH = path.join(ROOT, 'target/idl/arcium_psi.json');
const CIRCUIT_PATH = path.join(ROOT, 'build/psi_intersect.arcis');
const BATCH_SIZE = 10;

describe('LOCALNET — Arcium PSI program', function () {
  this.timeout(600_000);

  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const idl = JSON.parse(fs.readFileSync(IDL_PATH, 'utf8'));
  // Untyped: the IDL is read at runtime from the build output, so there are
  // no generated types to check the method and account names against.
  const program: any = new anchor.Program(idl, provider);
  const programId: PublicKey = program.programId;
  const owner = provider.wallet.publicKey;
  const clusterOffset = getArciumEnv().arciumClusterOffset;
  const mxeAccount = getMXEAccAddress(programId);
  const compDefAccount = getCompDefAccAddress(
    programId,
    Buffer.from(getCompDefAccOffset('psi_intersect')).readUInt32LE(),
  );

  // `arcium build` (anchor build) syncs declare_id! and Anchor.toml to the
  // program keypair it generates, so the ID is the one in the built IDL,
  // not the constant in the repository.
  it('the built program is deployed and executable at its IDL address', async () => {
    const info = await provider.connection.getAccountInfo(programId);
    expect(info, `no account at ${programId.toBase58()}`).to.not.equal(null);
    expect(info!.executable).to.equal(true);
  });

  it('init_user creates the user state PDA', async () => {
    await program.methods
      .initUser()
      .accounts({ payer: owner })
      .rpc({ commitment: 'confirmed' });

    const [userState] = PublicKey.findProgramAddressSync(
      [Buffer.from('user'), owner.toBuffer()],
      programId,
    );
    const state = await program.account.userState.fetch(userState);
    expect(state.owner.toBase58()).to.equal(owner.toBase58());
    expect(state.queriesMade.toNumber()).to.equal(0);
  });

  // The program does not check who registers the computation definition; the
  // Arcium program does, against the MXE authority. Whoever registers it
  // becomes the circuit upload authority, so an outside signer must not be
  // able to register it first or write circuit data.
  it('rejects computation definition registration by a non-MXE-authority signer', async () => {
    const arcium: any = getArciumProgram(provider);
    const mxe = await arcium.account.mxeAccount.fetch(mxeAccount);
    expect(mxe.authority?.toBase58(), 'MXE authority').to.equal(owner.toBase58());

    const outsider = await fundedKeypair(provider);
    const error = await rejection(
      program.methods
        .initPsiIntersectCompDef()
        .accounts({
          authority: outsider.publicKey,
          mxeAccount,
          compDefAccount,
          addressLookupTable: getLookupTableAddress(programId, mxe.lutOffsetSlot),
          lutProgram: AddressLookupTableProgram.programId,
        })
        .signers([outsider])
        .rpc({ commitment: 'confirmed' }),
    );
    expect(error).to.include('InvalidAuthority');
    expect(await provider.connection.getAccountInfo(compDefAccount)).to.equal(null);
  });

  it('registers the psi_intersect computation definition', async () => {
    const arcium: any = getArciumProgram(provider);
    const mxe = await arcium.account.mxeAccount.fetch(mxeAccount);
    await program.methods
      .initPsiIntersectCompDef()
      .accounts({
        authority: owner,
        mxeAccount,
        compDefAccount,
        addressLookupTable: getLookupTableAddress(programId, mxe.lutOffsetSlot),
        lutProgram: AddressLookupTableProgram.programId,
      })
      .rpc({ commitment: 'confirmed' });

    const compDef = await arcium.account.computationDefinitionAccount.fetch(compDefAccount);
    const onChain = compDef.circuitSource.onChain?.[0];
    expect(onChain, 'circuit source is not OnChain').to.not.equal(undefined);
    expect(onChain.uploadAuth.toBase58()).to.equal(owner.toBase58());
    expect(onChain.isCompleted).to.equal(false);

    // An outside signer can neither write circuit data nor finalize the
    // definition. `arcium test` pre-creates the raw circuit account at
    // genesis, so this rewrites its first chunk with the bytes it already
    // holds: accepted or not, the stored circuit is unchanged.
    const outsider = await fundedKeypair(provider);
    const offset = Buffer.from(getCompDefAccOffset('psi_intersect')).readUInt32LE();
    const raw = await provider.connection.getAccountInfo(getRawCircuitAccAddress(compDefAccount, 0));
    expect(raw, 'no raw circuit account').to.not.equal(null);
    const sameBytes = Array.from(raw!.data.subarray(9, 9 + 814));
    const uploadError = await rejection(
      arcium.methods
        .uploadCircuit(offset, programId, 0, sameBytes, 0)
        .accounts({ signer: outsider.publicKey })
        .signers([outsider])
        .rpc({ commitment: 'confirmed' }),
    );
    expect(uploadError).to.include('InvalidAuthority');
    const finalizeError = await rejection(
      arcium.methods
        .finalizeComputationDefinition(offset, programId)
        .accounts({ signer: outsider.publicKey })
        .signers([outsider])
        .rpc({ commitment: 'confirmed' }),
    );
    expect(finalizeError).to.include('InvalidAuthority');

    await uploadCircuit(
      provider,
      'psi_intersect',
      programId,
      fs.readFileSync(CIRCUIT_PATH),
      true,
    );
    const finalized = await arcium.account.computationDefinitionAccount.fetch(compDefAccount);
    expect(finalized.circuitSource.onChain[0].isCompleted).to.equal(true);
  });

  // Builds a signed v0 submit_psi_query transaction. `overrides` replaces
  // accounts, to check that the program rejects substituted ones.
  async function psiQueryTx(overrides: Record<string, PublicKey> = {}) {
    const mxePublicKey = await mxePublicKeyWithRetry(provider, programId);
    const client = encryptSide(
      ['+1234567890', '+0987654321', '+1111111111'].map(hashPhoneWithTruncation),
      mxePublicKey,
    );
    const server = encryptSide(
      ['+1234567890', '+9999999999', '+1111111111'].map(hashPhoneWithTruncation),
      mxePublicKey,
    );
    const computationOffset = new anchor.BN(randomBytes(8), 'hex');

    const ix = await program.methods
      .submitPsiQuery(client, server, computationOffset)
      .accountsPartial({
        user: owner,
        mxeAccount,
        mempoolAccount: getMempoolAccAddress(clusterOffset),
        executingPool: getExecutingPoolAccAddress(clusterOffset),
        computationAccount: getComputationAccAddress(clusterOffset, computationOffset),
        compDefAccount,
        clusterAccount: getClusterAccAddress(clusterOffset),
        poolAccount: getFeePoolAccAddress(),
        clockAccount: getClockAccAddress(),
        ...overrides,
      })
      .instruction();

    // Two SharedEncryptedStruct<10> plus the Arcium accounts exceed a legacy
    // transaction (1286 > 1232 bytes). A v0 transaction resolves the Arcium
    // accounts through the MXE's address lookup table.
    const mxe = await getArciumProgram(provider).account.mxeAccount.fetch(mxeAccount);
    const lutAddress = getLookupTableAddress(programId, mxe.lutOffsetSlot);
    const lut = (await provider.connection.getAddressLookupTable(lutAddress)).value;
    expect(lut, `no lookup table at ${lutAddress.toBase58()}`).to.not.equal(null);
    const { blockhash } = await provider.connection.getLatestBlockhash('confirmed');
    const tx = new VersionedTransaction(
      new TransactionMessage({
        payerKey: owner,
        recentBlockhash: blockhash,
        instructions: [ix],
      }).compileToV0Message([lut!]),
    );
    const signed = await provider.wallet.signTransaction(tx);
    return { raw: signed.serialize(), computationOffset };
  }

  it('rejects a query whose Arcium account is substituted', async () => {
    const { raw } = await psiQueryTx({ mempoolAccount: anchor.web3.Keypair.generate().publicKey });
    let error = '';
    try {
      await sendAndCheck(provider, raw);
    } catch (e: any) {
      error = String(e?.message ?? e);
    }
    expect(error, 'substituted mempool_account was accepted').to.not.equal('');
    expect(error).to.include('mempool_account');
    expect(error).to.include('ConstraintAddress');
  });

  it('runs a PSI computation on the MPC cluster and delivers the callback', async () => {
    const { raw, computationOffset } = await psiQueryTx();
    // Sent through the connection, not AnchorProvider.sendAndConfirm: on a
    // failed v0 transaction the latter throws "Unknown action 'undefined'"
    // (@anchor-lang/core provider.ts:196) and hides the program error.
    const queueSig = await sendAndCheck(provider, raw);
    console.log('    submit_psi_query:', queueSig);

    await awaitComputationFinalization(
      provider,
      computationOffset,
      programId,
      'confirmed',
      300_000,
    );

    // The callback does not store or emit the result yet (finding F-14), so the
    // intersection cannot be decrypted here. What can be checked is that the
    // callback ran: verify_output passed (BLS signature) and it logged.
    const logs = await callbackLogs(provider, programId);
    expect(logs, 'no successful psi_intersect_callback transaction found').to.not.equal(null);
    expect(logs!.some((l) => l.includes('PSI result delivered'))).to.equal(true);
  });
});

async function fundedKeypair(provider: anchor.AnchorProvider) {
  const kp = anchor.web3.Keypair.generate();
  const sig = await provider.connection.requestAirdrop(kp.publicKey, 10_000_000_000);
  const latest = await provider.connection.getLatestBlockhash('confirmed');
  await provider.connection.confirmTransaction({ signature: sig, ...latest }, 'confirmed');
  return kp;
}

// Awaits a transaction that must fail; returns its error message and logs.
async function rejection(tx: Promise<unknown>): Promise<string> {
  try {
    await tx;
  } catch (e: any) {
    return `${e?.message ?? e}\n${(e?.logs ?? []).join('\n')}`;
  }
  throw new Error('transaction from an outside signer was accepted');
}

function encryptSide(hashes: bigint[], mxePublicKey: Uint8Array) {
  const values = hashes.slice(0, BATCH_SIZE);
  while (values.length < BATCH_SIZE) values.push(0n);
  const secret = x25519.utils.randomSecretKey();
  const cipher = new RescueCipher(x25519.getSharedSecret(secret, mxePublicKey));
  const nonce = randomBytes(16);
  return {
    encryptionKey: Array.from(x25519.getPublicKey(secret)),
    nonce: new anchor.BN(deserializeLE(nonce).toString()),
    ciphertexts: cipher.encrypt(values, nonce).map((c) => Array.from(c)),
  };
}

async function mxePublicKeyWithRetry(
  provider: anchor.AnchorProvider,
  programId: PublicKey,
): Promise<Uint8Array> {
  for (let attempt = 1; attempt <= 20; attempt++) {
    const key = await getMXEPublicKey(provider, programId).catch(() => null);
    if (key) return key;
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error('MXE public key not available after 20 attempts');
}

// Logs of the most recent successful transaction that ran psi_intersect_callback.
async function callbackLogs(
  provider: anchor.AnchorProvider,
  programId: PublicKey,
): Promise<string[] | null> {
  const sigs = await provider.connection.getSignaturesForAddress(
    programId,
    { limit: 50 },
    'confirmed',
  );
  for (const { signature, err } of sigs) {
    if (err) continue;
    const tx = await provider.connection.getTransaction(signature, {
      commitment: 'confirmed',
      maxSupportedTransactionVersion: 0,
    });
    const logs = tx?.meta?.logMessages ?? [];
    if (logs.some((l) => l.includes('Instruction: PsiIntersectCallback'))) return logs;
  }
  return null;
}

// Send with preflight so a failing instruction reports its program logs,
// then require the confirmed transaction to have no error.
async function sendAndCheck(
  provider: anchor.AnchorProvider,
  raw: Uint8Array,
): Promise<string> {
  let sig: string;
  try {
    sig = await provider.connection.sendRawTransaction(raw, {
      preflightCommitment: 'confirmed',
    });
  } catch (e: any) {
    const logs = typeof e?.getLogs === 'function'
      ? await e.getLogs(provider.connection).catch(() => e.logs)
      : e?.logs;
    throw new Error(`${e?.message ?? e}\n${(logs ?? []).join('\n')}`);
  }
  const latest = await provider.connection.getLatestBlockhash('confirmed');
  const res = await provider.connection.confirmTransaction(
    { signature: sig, ...latest },
    'confirmed',
  );
  if (res.value.err) {
    const tx = await provider.connection.getTransaction(sig, {
      commitment: 'confirmed',
      maxSupportedTransactionVersion: 0,
    });
    throw new Error(
      `transaction ${sig} failed: ${JSON.stringify(res.value.err)}\n` +
        (tx?.meta?.logMessages ?? []).join('\n'),
    );
  }
  return sig;
}
