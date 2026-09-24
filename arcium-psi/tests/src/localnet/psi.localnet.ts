// Localnet integration test for the Arcium PSI program. Run only through
// `arcium test` (Anchor.toml [scripts] test), which starts a local validator
// with the Arcium programs, the Arx MPC nodes, and this program at genesis.
// Every step talks to that environment; nothing here is mocked or skipped.
//
// Follows the Arcium 0.10.4 example tests (arcium-hq/examples, coinflip at the
// v0.10.4 tag): init the computation definition, upload the circuit, encrypt
// inputs to the MXE key, queue the computation, await finalization.

import * as anchor from '@anchor-lang/core';
import { AddressLookupTableProgram, PublicKey } from '@solana/web3.js';
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
  RescueCipher,
  uploadCircuit,
  x25519,
} from '@arcium-hq/client';
import { PROGRAM_ID } from '../program';
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

  it('runs the program built from this checkout, at the declared ID', () => {
    expect(programId.toBase58()).to.equal(PROGRAM_ID.toBase58());
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

  it('registers the psi_intersect computation definition', async () => {
    const mxe = await getArciumProgram(provider).account.mxeAccount.fetch(mxeAccount);
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

    await uploadCircuit(
      provider,
      'psi_intersect',
      programId,
      fs.readFileSync(CIRCUIT_PATH),
      true,
    );
  });

  it('runs a PSI computation on the MPC cluster and delivers the callback', async () => {
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

    await program.methods
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
      })
      .rpc({ skipPreflight: true, commitment: 'confirmed' });

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
