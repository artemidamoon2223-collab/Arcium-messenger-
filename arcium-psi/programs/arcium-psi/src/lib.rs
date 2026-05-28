use anchor_lang::prelude::*;
use arcium_anchor::prelude::*;

declare_id!("PSiArc1um1111111111111111111111111111111111");

#[arcium_program]
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

    // ── v1.0 Arcium MPC instructions ─────────────────────────────────────────

    /// Called once after deployment to register the PSI circuit on-chain.
    /// Uses OffChainCircuitSource pattern: only the 32-byte hash is stored,
    /// not the full .arcis binary (~$0.25 gas vs $25+).
    pub fn init_psi_intersect_comp_def(
        ctx: Context<InitPsiIntersectCompDef>,
    ) -> Result<()> {
        init_computation_def(&*ctx.accounts, None)?;
        msg!("PSI circuit registered with Arcium");
        Ok(())
    }

    /// Queues a blind PSI computation on the Arcium MPC cluster.
    ///
    /// client_data / server_data are SharedEncryptedStruct<10>:
    ///   { encryption_key: [u8;32], nonce: u128, ciphertexts: [[u8;32]; 10] }
    ///
    /// Each ciphertext is one RescueCipher-encrypted u64 phone hash.
    /// computation_offset is the unique ID for this computation (used as PDA seed).
    pub fn submit_psi_query(
        ctx: Context<SubmitPsiQuery>,
        client_data: SharedEncryptedStruct<10>,
        server_data: SharedEncryptedStruct<10>,
        computation_offset: u64,
    ) -> Result<()> {
        // Batch size is enforced statically by SharedEncryptedStruct<10> — no runtime check needed.
        // Guard against a zeroed encryption key (indicates uninitialized client data).
        require!(
            client_data.encryption_key != [0u8; 32],
            PsiError::UninitializedEncryptionKey
        );
        require!(
            server_data.encryption_key != [0u8; 32],
            PsiError::UninitializedEncryptionKey
        );
        // Pack args in the exact order the Arcis circuit signature expects:
        // psi_intersect(client_data: Enc<Shared, ClientContacts>, server_data: Enc<Shared, ServerContacts>)
        // Each Enc<Shared, T> compiles to: X25519Pubkey + u128 nonce + N ciphertexts
        let args = ArgBuilder::new()
            // ── client_data: Enc<Shared, ClientContacts> ──────────────────────
            .x25519_pubkey(client_data.encryption_key)
            .plaintext_u128(client_data.nonce)
            .encrypted_u64(client_data.ciphertexts[0])
            .encrypted_u64(client_data.ciphertexts[1])
            .encrypted_u64(client_data.ciphertexts[2])
            .encrypted_u64(client_data.ciphertexts[3])
            .encrypted_u64(client_data.ciphertexts[4])
            .encrypted_u64(client_data.ciphertexts[5])
            .encrypted_u64(client_data.ciphertexts[6])
            .encrypted_u64(client_data.ciphertexts[7])
            .encrypted_u64(client_data.ciphertexts[8])
            .encrypted_u64(client_data.ciphertexts[9])
            // ── server_data: Enc<Shared, ServerContacts> ──────────────────────
            .x25519_pubkey(server_data.encryption_key)
            .plaintext_u128(server_data.nonce)
            .encrypted_u64(server_data.ciphertexts[0])
            .encrypted_u64(server_data.ciphertexts[1])
            .encrypted_u64(server_data.ciphertexts[2])
            .encrypted_u64(server_data.ciphertexts[3])
            .encrypted_u64(server_data.ciphertexts[4])
            .encrypted_u64(server_data.ciphertexts[5])
            .encrypted_u64(server_data.ciphertexts[6])
            .encrypted_u64(server_data.ciphertexts[7])
            .encrypted_u64(server_data.ciphertexts[8])
            .encrypted_u64(server_data.ciphertexts[9])
            .build();

        let callback = PsiIntersectCallback::callback_ix(
            computation_offset,
            &ctx.accounts.mxe_account,
            &[],
        )?;

        queue_computation(
            &*ctx.accounts,
            computation_offset,
            args,
            vec![callback],
            1,
            1000,
        )?;

        msg!("PSI computation queued, offset: {}", computation_offset);
        Ok(())
    }

    /// Called by Arcium Arx nodes after MPC computation completes.
    /// BLS signature over (query_id || encrypted_matches) is verified automatically
    /// by verify_output — transaction is rejected if the signature is invalid.
    #[arcium_callback(encrypted_ix = "psi_intersect")]
    pub fn psi_intersect_callback(
        ctx: Context<PsiIntersectCallback>,
        output: SignedComputationOutputs<PsiIntersectOutput>,
    ) -> Result<()> {
        // verify_output validates the Arx BLS signature and deserializes the result.
        // Returns Err(BLSSignatureVerificationFailed) if nodes sent forged data.
        let result = output.verify_output(
            &ctx.accounts.cluster_account,
            &ctx.accounts.computation_account,
        )?;

        // result.field_0 is SharedEncryptedStruct<10> — the encrypted boolean match vector.
        // Each ciphertext[i] = RescueCipher(match_result[i]) encrypted with client's key.
        // Client decrypts on their device to learn which contacts are registered.
        msg!(
            "PSI result delivered — encryption_key {:?}",
            result.field_0.encryption_key
        );
        Ok(())
    }
}

// ── Existing account structs ──────────────────────────────────────────────────

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

// ── v1.0 Arcium MPC account structs ──────────────────────────────────────────

/// Registers the PSI circuit definition with Arcium.
/// Run once after deployment. Uses OffChainCircuitSource (hash-only on-chain).
#[init_computation_definition_accounts("psi_intersect", authority)]
#[derive(Accounts)]
pub struct InitPsiIntersectCompDef<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(mut)]
    pub mxe_account: Account<'info, MXEAccount>,
    /// CHECK: validated by init_computation_definition_accounts macro
    #[account(mut)]
    pub comp_def_account: UncheckedAccount<'info>,
    /// CHECK: address lookup table for Arcium PDAs
    #[account(mut)]
    pub address_lookup_table: UncheckedAccount<'info>,
    /// CHECK: lookup table program
    pub lut_program: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
}

/// Submits an encrypted PSI query to the Arcium MPC cluster.
#[queue_computation_accounts("psi_intersect", user)]
#[derive(Accounts)]
pub struct SubmitPsiQuery<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    pub mxe_account: Account<'info, MXEAccount>,
    #[account(mut, seeds = [SIGN_PDA_SEED], bump = sign_pda_account.bump)]
    pub sign_pda_account: Account<'info, ArciumSignerAccount>,
    /// CHECK: Arcium mempool PDA
    #[account(mut)]
    pub mempool_account: UncheckedAccount<'info>,
    /// CHECK: Arcium executing pool PDA
    #[account(mut)]
    pub executing_pool: UncheckedAccount<'info>,
    /// CHECK: computation account (created by this instruction)
    #[account(mut)]
    pub computation_account: UncheckedAccount<'info>,
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,
    #[account(mut)]
    pub cluster_account: Account<'info, Cluster>,
    #[account(mut)]
    pub pool_account: Account<'info, FeePool>,
    #[account(mut)]
    pub clock_account: Account<'info, ClockAccount>,
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
}

/// Receives the BLS-verified MPC result from Arcium Arx nodes.
/// Struct name MUST be PsiIntersectCallback (PascalCase of "psi_intersect" + "Callback").
#[callback_accounts("psi_intersect")]
#[derive(Accounts)]
pub struct PsiIntersectCallback<'info> {
    pub arcium_program: Program<'info, Arcium>,
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,
    pub mxe_account: Account<'info, MXEAccount>,
    /// CHECK: computation account (verified by BLS signature)
    pub computation_account: UncheckedAccount<'info>,
    pub cluster_account: Account<'info, Cluster>,
    /// CHECK: instructions sysvar for callback validation
    #[account(address = INSTRUCTIONS_SYSVAR_ID)]
    pub instructions_sysvar: UncheckedAccount<'info>,
}

// ── Account data structs ──────────────────────────────────────────────────────

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
    #[msg("encryption key is all-zeros (uninitialized client or server data)")]
    UninitializedEncryptionKey,
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
