use anchor_lang::prelude::*;

declare_id!("PSiArc1um1111111111111111111111111111111111");

#[program]
pub mod arcium_psi {
    use super::*;

    pub fn init_user(ctx: Context<InitUser>) -> Result<()> {
        let user_state = &mut ctx.accounts.user_state;
        user_state.owner = ctx.accounts.payer.key();
        user_state.queries_made = 0;
        user_state.bump = ctx.bumps.user_state;
        Ok(())
    }

    pub fn submit_query(
        ctx: Context<SubmitQuery>,
        encrypted_contacts: Vec<u8>,
        nonce: u64,
    ) -> Result<()> {
        let user_state = &mut ctx.accounts.user_state;
        require!(nonce > user_state.last_nonce, PsiError::NonceReused);
        user_state.last_nonce = nonce;
        user_state.queries_made = user_state.queries_made.saturating_add(1);
        let _ = encrypted_contacts;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct InitUser<'info> {
    #[account(
        init, payer = payer,
        space = 8 + UserState::SIZE,
        seeds = [b"user", payer.key().as_ref()],
        bump,
    )]
    pub user_state: Account<'info, UserState>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SubmitQuery<'info> {
    #[account(mut, has_one = owner)]
    pub user_state: Account<'info, UserState>,
    pub owner: Signer<'info>,
}

#[account]
pub struct UserState {
    pub owner: Pubkey,
    pub queries_made: u64,
    pub last_nonce: u64,
    pub bump: u8,
}

impl UserState {
    pub const SIZE: usize = 32 + 8 + 8 + 1;
}

#[error_code]
pub enum PsiError {
    #[msg("nonce already used")]
    NonceReused,
}

// ── v1.0 PSI types ────────────────────────────────────────────────────────────

/// Stores an off-chain Arcis circuit reference (IPFS/CDN) instead of
/// embedding the circuit on-chain. Saves ~100x in transaction fees.
#[account]
pub struct OffChainCircuitSource {
    /// IPFS or CDN URL pointing to the compiled .arcis file.
    pub url: String,
    /// SHA-256 of the circuit content — verified before execution.
    pub hash: [u8; 32],
    pub version: u32,
}

/// Client-side PSI query: contact hashes encrypted with RescueCipher
/// before submission to the Arcium MPC cluster.
#[derive(AnchorSerialize, AnchorDeserialize, Debug, Clone)]
pub struct PsiQuery {
    /// Ephemeral client X25519 public key for RescueCipher key agreement.
    pub client_pubkey: [u8; 32],
    /// RescueCipher-encrypted SHA-256 contact hashes.
    pub encrypted_hashes: Vec<u8>,
    pub nonce: [u8; 16],
    /// Hash of the Arcis circuit used — must match OffChainCircuitSource.hash.
    pub circuit_hash: [u8; 32],
}

/// MPC result returned after PSI intersection on the Arcium cluster.
#[derive(AnchorSerialize, AnchorDeserialize, Debug, Clone)]
pub struct PsiResult {
    pub query_id: [u8; 32],
    /// RescueCipher-encrypted boolean match vector.
    pub encrypted_matches: Vec<u8>,
    /// Arcium MPC node aggregate signature over (query_id || encrypted_matches).
    pub mpc_signature: [u8; 64],
}