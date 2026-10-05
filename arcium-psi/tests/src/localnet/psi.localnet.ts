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
  PACKET_DATA_SIZE,
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
  getComputationsInMempool,
  getExecutingPoolAccAddress,
  getExecutingPoolAccInfo,
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
import { BATCH_SIZE, CIPHERTEXTS, PsiRequest, contactInputPlaintext, decryptResult } from '../client';

const ROOT = path.resolve(__dirname, '../../..');
const IDL_PATH = path.join(ROOT, 'target/idl/arcium_psi.json');
const CIRCUIT_PATH = path.join(ROOT, 'build/psi_intersect.arcis');

const ALICE = ['+1234567890', '+0987654321', '+1111111111'].map(hashPhoneWithTruncation);
const BOB = ['+1234567890', '+9999999999', '+1111111111'].map(hashPhoneWithTruncation);

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

  async function mxeLookupTable() {
    const mxe = await getArciumProgram(provider).account.mxeAccount.fetch(mxeAccount);
    const lutAddress = getLookupTableAddress(programId, mxe.lutOffsetSlot);
    const lut = (await provider.connection.getAddressLookupTable(lutAddress)).value;
    expect(lut, `no lookup table at ${lutAddress.toBase58()}`).to.not.equal(null);
    return lut!;
  }

  // Builds a signed v0 submit_psi_query transaction from the plaintexts of
  // both sides (see `side`). `overrides` replaces accounts, to check that the
  // program rejects substituted ones.
  async function psiQueryTx(
    clientValues = side(ALICE),
    serverValues = side(BOB),
    overrides: Record<string, PublicKey> = {},
  ) {
    const mxePublicKey = await mxePublicKeyWithRetry(provider, programId);
    const client = encryptSide(clientValues, mxePublicKey);
    const server = encryptSide(serverValues, mxePublicKey);
    const computationOffset = new anchor.BN(randomBytes(8), 'hex');
    const computationAccount = getComputationAccAddress(clusterOffset, computationOffset);

    const ix = await program.methods
      .submitPsiQuery(client.arg, server.arg, computationOffset)
      .accountsPartial({
        user: owner,
        mxeAccount,
        mempoolAccount: getMempoolAccAddress(clusterOffset),
        executingPool: getExecutingPoolAccAddress(clusterOffset),
        computationAccount,
        compDefAccount,
        clusterAccount: getClusterAccAddress(clusterOffset),
        poolAccount: getFeePoolAccAddress(),
        clockAccount: getClockAccAddress(),
        ...overrides,
      })
      .instruction();

    // Two SharedEncryptedStruct<11> plus the Arcium accounts exceed a legacy
    // transaction. A v0 transaction resolves the Arcium accounts through the
    // MXE's address lookup table.
    const lut = await mxeLookupTable();
    const { blockhash } = await provider.connection.getLatestBlockhash('confirmed');
    const tx = new VersionedTransaction(
      new TransactionMessage({
        payerKey: owner,
        recentBlockhash: blockhash,
        instructions: [ix],
      }).compileToV0Message([lut]),
    );
    const signed = await provider.wallet.signTransaction(tx);
    const raw = signed.serialize();
    console.log(`    submit_psi_query transaction: ${raw.length} bytes (limit ${PACKET_DATA_SIZE})`);
    expect(raw.length).to.be.at.most(PACKET_DATA_SIZE);
    return { raw, computationOffset, computationAccount, client };
  }

  // Queues a query, waits for the cluster, and returns the client's view of
  // the encrypted result the cluster passed to the callback.
  async function runQuery(clientValues: bigint[], serverValues: bigint[]) {
    const query = await psiQueryTx(clientValues, serverValues);
    // Sent through the connection, not AnchorProvider.sendAndConfirm: on a
    // failed v0 transaction the latter throws "Unknown action 'undefined'"
    // (@anchor-lang/core provider.ts:196) and hides the program error.
    const signature = await sendAndCheck(provider, query.raw);
    console.log('    submit_psi_query:', signature);
    await traceComputation(provider, clusterOffset, query, signature, () =>
      awaitComputationFinalization(
        provider,
        query.computationOffset,
        programId,
        'confirmed',
        300_000,
      ),
    );
    const output = await callbackOutput(provider, programId, idl, query.computationAccount);
    // The result is encrypted to the client's key, with the nonce after its own.
    expect(Array.from(output.encryptionKey)).to.deep.equal(Array.from(query.client.publicKey));
    const plain: bigint[] = new RescueCipher(query.client.shared).decrypt(
      chunks(output.ciphertexts),
      output.nonce,
    );
    console.log(`    decrypted MatchResult: [${plain.join(', ')}]`);
    return { ...query, output, plain };
  }

  it('rejects a query whose Arcium account is substituted', async () => {
    // Another address from the MXE's lookup table: a key outside it would
    // add 32 bytes and push the transaction past the size limit, so the
    // rejection would no longer be the program's.
    const mempool = getMempoolAccAddress(clusterOffset);
    const wrong = (await mxeLookupTable()).state.addresses.find((a) => !a.equals(mempool));
    expect(wrong, 'no other address in the lookup table').to.not.equal(undefined);
    const { raw } = await psiQueryTx(undefined, undefined, { mempoolAccount: wrong! });
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

  // These read the output from the callback transaction: the program does
  // not store or emit it (finding F-14). They check what the cluster
  // computed, not a way for a client to receive it.
  it('runs a PSI computation on the MPC cluster and returns the expected matches', async () => {
    const run = await runQuery(side(ALICE), side(BOB));
    const logs = await callbackLogs(provider, programId);
    expect(logs, 'no successful psi_intersect_callback transaction found').to.not.equal(null);
    expect(logs!.some((l) => l.includes('PSI result delivered'))).to.equal(true);
    expect(decryptResult(run.output, run.client.shared, run.client.request))
      .to.deep.equal([true, false, true]);
  });

  // Client: a real zero hash, a hash the server has only as padding, a real
  // match; client padding equal to a real server hash and to server padding.
  // Server padding equal to a real client hash and zero.
  it('compares real entries only, including a real zero hash', async () => {
    const [a, b, c] = BOB;
    const run = await runQuery(side([0n, a, b], [c, 0n]), side([b, c], [a, 0n]));
    // decryptResult also requires every client padding slot to be 0.
    expect(decryptResult(run.output, run.client.shared, run.client.request))
      .to.deep.equal([false, false, true]);
  });

  // A count of 11 sent past client.ts: the circuit marks the result invalid
  // and sets no match, and the client rejects it.
  it('fails closed on an invalid count inside the circuit', async () => {
    const run = await runQuery(side(ALICE, [0n], BigInt(BATCH_SIZE + 1)), side(BOB));
    expect(run.plain).to.deep.equal(Array(CIPHERTEXTS).fill(0n));
    expect(() => decryptResult(run.output, run.client.shared, run.client.request))
      .to.throw(/rejected a count/);
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

// One side's plaintexts: real hashes first, then the padding values in turn,
// then the count. `count` replaces the count, to send one that client.ts
// would never produce.
function side(real: bigint[], pads: bigint[] = [0n], count = BigInt(real.length)): bigint[] {
  const values = contactInputPlaintext(real);
  for (let i = real.length; i < BATCH_SIZE; i++) values[i] = pads[(i - real.length) % pads.length];
  values[BATCH_SIZE] = count;
  return values;
}

function encryptSide(values: bigint[], mxePublicKey: Uint8Array) {
  const secret = x25519.utils.randomSecretKey();
  const publicKey = x25519.getPublicKey(secret);
  const shared = x25519.getSharedSecret(secret, mxePublicKey);
  const nonce = randomBytes(16);
  const ciphertexts: number[][] = new RescueCipher(shared).encrypt(values, nonce);
  const flat = new Uint8Array(ciphertexts.length * 32);
  ciphertexts.forEach((c, i) => flat.set(c, i * 32));
  const request: PsiRequest = {
    count: Math.min(Number(values[BATCH_SIZE]), BATCH_SIZE),
    nonce: Uint8Array.from(nonce),
    ciphertexts: flat,
  };
  return {
    publicKey,
    shared,
    request,
    arg: {
      encryptionKey: Array.from(publicKey),
      nonce: new anchor.BN(deserializeLE(nonce).toString()),
      ciphertexts: ciphertexts.map((c) => Array.from(c)),
    },
  };
}

function chunks(bytes: Uint8Array): number[][] {
  const out: number[][] = [];
  for (let i = 0; i < bytes.length; i += 32) out.push(Array.from(bytes.subarray(i, i + 32)));
  return out;
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

// The encrypted MatchResult the cluster passed to psi_intersect_callback for
// the computation at `computationAccount`, read from that callback
// instruction's data: discriminator (8), SignedComputationOutputs variant
// (1, Success = 0), SharedEncryptedStruct<11> (32 + 16 + 11 × 32), BLS
// signature (64).
async function callbackOutput(
  provider: anchor.AnchorProvider,
  programId: PublicKey,
  idl: any,
  computationAccount: PublicKey,
) {
  const spec = idl.instructions.find((i: any) => i.name === 'psi_intersect_callback');
  expect(spec?.discriminator, 'no psi_intersect_callback discriminator in the IDL').to.not.equal(undefined);
  const disc = Buffer.from(spec.discriminator);
  const outputSize = 48 + CIPHERTEXTS * 32;
  const sigs = await provider.connection.getSignaturesForAddress(programId, { limit: 100 }, 'confirmed');
  for (const { signature, err } of sigs) {
    if (err) continue;
    const tx = await provider.connection.getTransaction(signature, {
      commitment: 'confirmed',
      maxSupportedTransactionVersion: 0,
    });
    if (!tx) continue;
    const message: any = tx.transaction.message;
    const keys = message.getAccountKeys({ accountKeysFromLookups: tx.meta?.loadedAddresses ?? undefined });
    const instructions = [
      ...message.compiledInstructions.map((i: any) => ({
        program: i.programIdIndex as number,
        accounts: i.accountKeyIndexes as number[],
        data: Buffer.from(i.data),
      })),
      ...(tx.meta?.innerInstructions ?? []).flatMap((group) =>
        group.instructions.map((i) => ({
          program: i.programIdIndex,
          accounts: i.accounts,
          data: Buffer.from(anchor.utils.bytes.bs58.decode(i.data)),
        })),
      ),
    ];
    for (const ix of instructions) {
      if (!keys.get(ix.program)?.equals(programId)) continue;
      if (!ix.data.subarray(0, 8).equals(disc)) continue;
      if (!ix.accounts.some((a: number) => keys.get(a)?.equals(computationAccount))) continue;
      expect(ix.data.length, 'callback data size').to.equal(8 + 1 + outputSize + 64);
      expect(ix.data[8], 'callback output is not Success').to.equal(0);
      const out = ix.data.subarray(9, 9 + outputSize);
      return {
        encryptionKey: Uint8Array.from(out.subarray(0, 32)),
        nonce: Uint8Array.from(out.subarray(32, 48)),
        ciphertexts: Uint8Array.from(out.subarray(48)),
      };
    }
  }
  throw new Error(`no psi_intersect_callback for ${computationAccount.toBase58()}`);
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

// When the previous computation of this run finalized, for the trace below.
let lastFinalizedAt: number | null = null;

// Runs `wait` (the finalization check) unchanged while recording, once a
// second, what the cluster shows for this computation: its account status,
// whether its offset is in the mempool or the executing pool, and the slot.
// Afterwards it lists every transaction that touched the computation account,
// with the logs of failed ones. The trace goes to LOCALNET_DIAG_DIR when that
// is set (CI uploads it), and is printed when `wait` fails. It records
// accounts, offsets, signatures and states only: no keys or plaintexts.
async function traceComputation(
  provider: anchor.AnchorProvider,
  clusterOffset: number,
  query: { computationOffset: anchor.BN; computationAccount: PublicKey },
  submitSignature: string,
  wait: () => Promise<unknown>,
) {
  const conn = provider.connection;
  const arcium: any = getArciumProgram(provider);
  const offset = query.computationOffset.toString();
  const start = Date.now();
  const observations: Record<string, unknown>[] = [];
  const observe = async () => {
    const at = Date.now();
    try {
      const [slot, account, mempool, execpool] = await Promise.all([
        conn.getSlot('confirmed'),
        arcium.account.computationAccount.fetchNullable(query.computationAccount, 'confirmed'),
        getComputationsInMempool(arcium, getMempoolAccAddress(clusterOffset)),
        getExecutingPoolAccInfo(provider, getExecutingPoolAccAddress(clusterOffset)),
      ]);
      const executing = (execpool as any).currentlyExecuting as any[];
      observations.push({
        t: new Date(at).toISOString(),
        ms: at - start,
        slot,
        status: account === null ? 'missing' : Object.keys(account.status)[0],
        callbacksSubmitted: account?.callbackTransactionsSubmittedBm,
        inMempool: mempool.some((r: any) => r.computationOffset.toString() === offset),
        mempoolSize: mempool.length,
        inExecpool: executing.some((r: any) => r.computationOffset.toString() === offset),
        execpoolSize: executing.filter((r: any) => !r.computationOffset.isZero()).length,
      });
    } catch (e: any) {
      observations.push({ t: new Date(at).toISOString(), ms: at - start, error: String(e?.message ?? e) });
    }
  };

  let done = false;
  const observer = (async () => {
    while (!done) {
      await observe();
      await new Promise((r) => setTimeout(r, 1000));
    }
  })();
  let failure: unknown = null;
  try {
    await wait();
  } catch (e) {
    failure = e;
  } finally {
    done = true;
    await observer;
  }
  const finishedAt = Date.now();
  await observe();

  const touching = await conn.getSignaturesForAddress(query.computationAccount, { limit: 50 }, 'confirmed');
  const transactions = [];
  for (const { signature, slot, err, blockTime } of touching.reverse()) {
    const entry: Record<string, unknown> = { signature, slot, blockTime, err };
    if (err) {
      const tx = await conn.getTransaction(signature, { commitment: 'confirmed', maxSupportedTransactionVersion: 0 });
      entry.logs = tx?.meta?.logMessages ?? [];
    }
    transactions.push(entry);
  }
  const submitted = await conn.getTransaction(submitSignature, { commitment: 'confirmed', maxSupportedTransactionVersion: 0 });
  const trace = {
    computationAccount: query.computationAccount.toBase58(),
    computationOffset: offset,
    submitSignature,
    submitSlot: submitted?.slot ?? null,
    submitErr: submitted?.meta?.err ?? null,
    startedAt: new Date(start).toISOString(),
    msSincePreviousFinalization: lastFinalizedAt === null ? null : start - lastFinalizedAt,
    outcome: failure === null ? 'finalized' : String((failure as any)?.message ?? failure),
    waitedMs: finishedAt - start,
    observations,
    transactions,
  };
  if (failure === null) lastFinalizedAt = finishedAt;
  const dir = process.env.LOCALNET_DIAG_DIR;
  if (dir) {
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, `computation-${offset}.json`), JSON.stringify(trace, null, 2));
  }
  if (failure !== null) {
    const last = observations[observations.length - 1];
    console.log(`    computation ${trace.computationAccount} (offset ${offset}) did not finalize:`);
    console.log(`      submitted in slot ${trace.submitSlot}, ${trace.msSincePreviousFinalization} ms after the previous computation finalized`);
    console.log(`      last observation: ${JSON.stringify(last)}`);
    console.log(`      transactions on the computation account: ${JSON.stringify(transactions)}`);
    throw failure;
  }
}
