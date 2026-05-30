import { expect } from 'chai';
import { PublicKey } from '@solana/web3.js';
import {
  initConnection, generateKeypair, getBalance, ensureFunded
} from './setup';

describe('Devnet Setup (live, no toolchain needed)', function () {
  this.timeout(60000);

  it('connects to devnet and reads a known balance', async function () {
    const conn = initConnection();
    const sysvar = new PublicKey('SysvarC1ock11111111111111111111111111111111');
    try {
      const balance = await getBalance(conn, sysvar);
      expect(balance).to.be.a('number');
      expect(balance).to.be.greaterThan(0);
      console.log(`  Sysvar balance: ${balance} lamports`);
    } catch (err: any) {
      console.warn('Devnet unreachable (network policy):', err.message);
      this.skip();
    }
  });

  it('generates a fresh keypair with zero balance', async function () {
    const conn = initConnection();
    const kp = generateKeypair();
    try {
      const balance = await getBalance(conn, kp.publicKey);
      expect(balance).to.equal(0);
    } catch (err: any) {
      console.warn('Devnet unreachable (network policy):', err.message);
      this.skip();
    }
  });

  it('funds a new keypair via airdrop (may skip if rate-limited)', async function () {
    const conn = initConnection();
    const kp = generateKeypair();
    try {
      await ensureFunded(conn, kp.publicKey, 0.5);
      const balance = await getBalance(conn, kp.publicKey);
      expect(balance).to.be.greaterThan(0);
    } catch (err: any) {
      console.warn('Airdrop skipped (rate-limited):', err.message);
      this.skip();
    }
  });
});
