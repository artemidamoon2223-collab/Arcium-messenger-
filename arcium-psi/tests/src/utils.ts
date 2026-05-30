import { sha256 } from '@noble/hashes/sha256';

export function bytesToU64LE(bytes: Uint8Array): bigint {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return view.getBigUint64(0, true); // little-endian
}

// Canonical: sha256(utf8(phone))[0..8] as little-endian u64.
// Rust side MUST use: u64::from_le_bytes(sha256(phone.as_bytes())[0..8].try_into().unwrap())
export function hashPhoneWithTruncation(phone: string): bigint {
  const hash = sha256(new TextEncoder().encode(phone));
  return bytesToU64LE(hash.slice(0, 8));
}

export function formatSol(lamports: number): string {
  return (lamports / 1e9).toFixed(4) + ' SOL';
}

export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export function exponentialBackoff(attempt: number): number {
  return Math.min(1000 * (2 ** attempt), 30000);
}
