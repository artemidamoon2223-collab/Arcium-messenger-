import {
  Connection, Keypair, PublicKey, LAMPORTS_PER_SOL
} from '@solana/web3.js';
import { sleep, exponentialBackoff, formatSol } from './utils';

const DEVNET_RPC = 'https://api.devnet.solana.com';

export function initConnection(rpcUrl: string = DEVNET_RPC): Connection {
  return new Connection(rpcUrl, 'confirmed');
}

export function generateKeypair(): Keypair {
  return Keypair.generate();
}

export async function getBalance(
  connection: Connection,
  pubkey: PublicKey
): Promise<number> {
  return connection.getBalance(pubkey);
}

export async function ensureFunded(
  connection: Connection,
  pubkey: PublicKey,
  minSol: number = 1
): Promise<void> {
  const minLamports = minSol * LAMPORTS_PER_SOL;
  const current = await getBalance(connection, pubkey);

  if (current >= minLamports) return;

  const maxAttempts = 5;
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    try {
      const sig = await connection.requestAirdrop(pubkey, minLamports);
      await confirmSignature(connection, sig);
      return;
    } catch (err) {
      if (attempt === maxAttempts - 1) {
        throw new Error(
          `Airdrop failed after ${maxAttempts} attempts. ` +
          `Devnet may be rate-limited. Current balance: ${formatSol(current)}. ` +
          `Try manual airdrop: solana airdrop 1 ${pubkey.toBase58()} --url devnet`
        );
      }
      await sleep(exponentialBackoff(attempt));
    }
  }
}

export async function confirmSignature(
  connection: Connection,
  signature: string
): Promise<void> {
  const latest = await connection.getLatestBlockhash();
  await connection.confirmTransaction({
    signature,
    blockhash: latest.blockhash,
    lastValidBlockHeight: latest.lastValidBlockHeight,
  }, 'confirmed');
}
