#![allow(unexpected_cfgs)]
use anchor_lang::prelude::*;
use arcium_anchor::prelude::*;
use arcium_client::idl::arcium::types::CircuitSource;

const COMP_DEF_OFFSET_PSI_INTERSECT: u32 = comp_def_offset("psi_intersect");

// ── Off-chain circuit source ──────────────────────────────────────────────────
// The computation definition stores where the Arx nodes download the compiled
// circuit and its SHA-256, not the circuit. Both are constants of this program,
// so no caller of `init_psi_intersect_comp_def` chooses them.

/// SHA-256 of the compiled circuit `build/psi_intersect.arcis`, the file the
/// Arx nodes download and check against this hash before they run it. It is
/// the value `arcium build` writes to `build/psi_intersect.hash`, and not the
/// hash of `psi_intersect.arcis.ir`. The arcium-build CI job fails if the
/// build produces a different circuit.
const PSI_INTERSECT_CIRCUIT_HASH: [u8; 32] = [
    0x24, 0xe7, 0xf6, 0x13, 0x30, 0x43, 0xd3, 0x03, 0x56, 0x22, 0xd7, 0x44, 0x7e, 0xa0, 0x50, 0xf0,
    0x42, 0x9f, 0x71, 0x7d, 0x3b, 0x7f, 0x6a, 0x3b, 0xb8, 0xda, 0x3a, 0x21, 0x11, 0x43, 0x16, 0xef,
];

/// Where the Arx nodes download the circuit: a release asset of this
/// repository, under a tag named after the first 16 hex digits of the hash,
/// so a new circuit gets a new URL. The file must be published at this URL
/// before `init_psi_intersect_comp_def` runs (docs/HOME-DEPLOY.md): the
/// Arcium program has no instruction that changes the source of a registered
/// definition.
const PSI_INTERSECT_CIRCUIT_URL: &str = "https://github.com/artemidamoon2223-collab/Arcium-messenger-/releases/download/psi-intersect-24e7f6133043d303/psi_intersect.arcis";

/// Localnet only: `tests/src/localnet/psi.localnet.ts` serves
/// `build/psi_intersect.arcis` here, the host as seen from the Docker network
/// of the localnet Arx nodes. The hash stays `PSI_INTERSECT_CIRCUIT_HASH`.
const PSI_INTERSECT_LOCALNET_CIRCUIT_URL: &str = "http://172.20.0.1:18080/psi_intersect.arcis";

/// The circuit URL this build registers, chosen at compile time: the localnet
/// URL only when ARCIUM_PSI_LOCALNET_CIRCUIT is set (to any value) in the
/// environment of the build, as the arcium-test CI job sets it for
/// `arcium test`. A deploy build must run without it; the arcium-build CI job
/// checks that the program it builds holds the release URL and not the
/// localnet one.
const PSI_INTERSECT_CIRCUIT_SOURCE_URL: &str = match option_env!("ARCIUM_PSI_LOCALNET_CIRCUIT") {
    Some(_) => PSI_INTERSECT_LOCALNET_CIRCUIT_URL,
    None => PSI_INTERSECT_CIRCUIT_URL,
};

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

    /// Called once after deployment to register the psi_intersect computation
    /// definition with an off-chain circuit source: the definition stores the
    /// circuit URL and SHA-256 (program constants, above), not the circuit.
    pub fn init_psi_intersect_comp_def(
        ctx: Context<InitPsiIntersectCompDef>,
    ) -> Result<()> {
        // Arcium's OffChainCircuitSource, not the unused account struct of the
        // same name at the end of this file.
        let source = arcium_client::idl::arcium::types::OffChainCircuitSource {
            source: PSI_INTERSECT_CIRCUIT_SOURCE_URL.to_string(),
            hash: PSI_INTERSECT_CIRCUIT_HASH,
        };
        init_computation_def(&*ctx.accounts, Some(CircuitSource::OffChain(source)))?;
        msg!("PSI circuit registered with Arcium");
        Ok(())
    }

    /// Queues a blind PSI computation on the Arcium MPC cluster.
    ///
    /// client_data / server_data are SharedEncryptedStruct<11>:
    ///   { encryption_key: [u8;32], nonce: u128, ciphertexts: [[u8;32]; 11] }
    ///
    /// ciphertexts[0..10] are RescueCipher-encrypted u64 phone hashes, real
    /// entries first; ciphertexts[10] is the encrypted number of real entries.
    /// The circuit checks that number and compares real entries only.
    /// computation_offset is the unique ID for this computation (used as PDA seed).
    /// `#[check_args]` checks the arguments against build/psi_intersect.idarc
    /// at compile time.
    #[check_args]
    pub fn submit_psi_query(
        ctx: Context<SubmitPsiQuery>,
        client_data: SharedEncryptedStruct<11>,
        server_data: SharedEncryptedStruct<11>,
        computation_offset: u64,
    ) -> Result<()> {
        // Batch size is enforced statically by SharedEncryptedStruct<11> — no runtime check needed.
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
        // Each Enc<Shared, T> compiles to: X25519Pubkey + u128 nonce + N ciphertexts.
        // The count is a field element in the circuit; every encrypted_* call
        // fills one ciphertext slot (arcium-anchor arg_match_param), so
        // encrypted_u64 here does not limit its range.
        #[args("psi_intersect")]
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
            .encrypted_u64(client_data.ciphertexts[10])
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
            .encrypted_u64(server_data.ciphertexts[10])
            .build();

        ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;

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

        // result.field_0 is SharedEncryptedStruct<11>: ciphertexts[0..10] are the
        // match flags, ciphertexts[10] the validity flag, encrypted with the client's key.
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

/// Registers the PSI computation definition with Arcium.
/// Run once after deployment. The circuit source is off chain: URL and hash.
#[init_computation_definition_accounts("psi_intersect", authority)]
#[derive(Accounts)]
pub struct InitPsiIntersectCompDef<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(mut, address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    /// CHECK: checked by the Arcium program; not initialized yet.
    #[account(mut)]
    pub comp_def_account: UncheckedAccount<'info>,
    /// CHECK: the MXE's address lookup table, checked by the Arcium program.
    #[account(mut, address = derive_mxe_lut_pda!(mxe_account.lut_offset_slot))]
    pub address_lookup_table: UncheckedAccount<'info>,
    /// CHECK: the Address Lookup Table program.
    #[account(address = LUT_PROGRAM_ID)]
    pub lut_program: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
}

/// Submits an encrypted PSI query to the Arcium MPC cluster.
#[queue_computation_accounts("psi_intersect", user)]
#[derive(Accounts)]
#[instruction(
    client_data: SharedEncryptedStruct<11>,
    server_data: SharedEncryptedStruct<11>,
    computation_offset: u64,
)]
pub struct SubmitPsiQuery<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    // Created on first use, as in the Arcium 0.10.4 examples. Nothing else
    // initializes this PDA, so requiring it to exist made every query fail
    // with AccountNotInitialized.
    #[account(
        init_if_needed,
        space = 9,
        payer = user,
        seeds = [&SIGN_PDA_SEED],
        bump,
        address = derive_sign_pda!(),
    )]
    pub sign_pda_account: Account<'info, ArciumSignerAccount>,
    /// CHECK: Arcium mempool PDA, checked by the Arcium program.
    #[account(mut, address = derive_mempool_pda!(mxe_account))]
    pub mempool_account: UncheckedAccount<'info>,
    /// CHECK: Arcium executing pool PDA, checked by the Arcium program.
    #[account(mut, address = derive_execpool_pda!(mxe_account))]
    pub executing_pool: UncheckedAccount<'info>,
    /// CHECK: computation account, created by the Arcium program.
    #[account(mut, address = derive_comp_pda!(computation_offset, mxe_account))]
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_PSI_INTERSECT))]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    #[account(mut, address = derive_cluster_pda!(mxe_account))]
    pub cluster_account: Box<Account<'info, Cluster>>,
    #[account(mut, address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS)]
    pub pool_account: Account<'info, FeePool>,
    #[account(mut, address = ARCIUM_CLOCK_ACCOUNT_ADDRESS)]
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
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_PSI_INTERSECT))]
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Account<'info, MXEAccount>,
    /// CHECK: computation account, checked by the Arcium program through the
    /// callback context.
    pub computation_account: UncheckedAccount<'info>,
    // Pinned to this MXE's cluster: verify_output checks the BLS signature
    // against this account, so it must not be caller-chosen.
    #[account(address = derive_cluster_pda!(mxe_account))]
    pub cluster_account: Box<Account<'info, Cluster>>,
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

#[cfg(test)]
mod borsh_tests {
    use super::*;
    use anchor_lang::{AnchorDeserialize, AnchorSerialize};

    #[test]
    fn off_chain_circuit_source_round_trip() {
        let source = OffChainCircuitSource {
            url: "https://ipfs.io/ipfs/QmTest".to_string(),
            hash: [1u8; 32],
            version: 1,
        };
        let mut buf = Vec::new();
        source.serialize(&mut buf).unwrap();
        let back = OffChainCircuitSource::deserialize(&mut &buf[..]).unwrap();
        assert_eq!(source.url, back.url);
        assert_eq!(source.hash, back.hash);
        assert_eq!(source.version, back.version);
    }

    #[test]
    fn psi_query_round_trip() {
        let query = PsiQuery {
            client_pubkey: [2u8; 32],
            encrypted_hashes: vec![10u8, 20u8, 30u8],
            nonce: [3u8; 16],
            circuit_hash: [4u8; 32],
        };
        let mut buf = Vec::new();
        query.serialize(&mut buf).unwrap();
        let back = PsiQuery::deserialize(&mut &buf[..]).unwrap();
        assert_eq!(query.client_pubkey, back.client_pubkey);
        assert_eq!(query.encrypted_hashes, back.encrypted_hashes);
        assert_eq!(query.nonce, back.nonce);
        assert_eq!(query.circuit_hash, back.circuit_hash);
    }

    #[test]
    fn psi_result_round_trip() {
        let result = PsiResult {
            query_id: [5u8; 32],
            encrypted_matches: vec![7u8, 8u8, 9u8],
            mpc_signature: [6u8; 64],
        };
        let mut buf = Vec::new();
        result.serialize(&mut buf).unwrap();
        let back = PsiResult::deserialize(&mut &buf[..]).unwrap();
        assert_eq!(result.query_id, back.query_id);
        assert_eq!(result.encrypted_matches, back.encrypted_matches);
        assert_eq!(result.mpc_signature, back.mpc_signature);
    }
}
