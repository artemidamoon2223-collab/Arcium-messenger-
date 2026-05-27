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