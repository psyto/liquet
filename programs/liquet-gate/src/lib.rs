//! # liquet-gate
//!
//! The on-chain enforcement point of the Liquet story: an **independent verdict,
//! signed off-chain, is enforced at the moment a Solana escrow releases funds.**
//!
//! The Liquet verifier (cross-VM re-execution + Custos malice screen) decides
//! `Settle` / `Hold` off-chain and signs a [`ReleaseAuthorization`]. This program
//! releases escrowed SPL tokens **only** when it can verify, on-chain, that the
//! pinned Liquet signer authorized *this exact* payout. A `Hold` is simply the
//! absence of a `Settle` authorization: nothing moves.
//!
//! ## Honest scope (hackathon MVP)
//!
//! This program gates the **escrow release**. It does not, and does not claim to,
//! physically prevent an already-executed delivery. The accurate demo claim is:
//! *"unsafe delivery detected → release denied → escrow balance unchanged."*
//!
//! ## Two load-bearing guards (see the sibling modules)
//! - ① [`ed25519`]: verify the *binding* of the signature, not merely its presence.
//! - ② [`authorization`]: the transfer parameters are read from the **signed
//!   message**, never from separately-supplied instruction arguments.
//!
//! REVIEW(codex): this is a CC scaffold for adversarial review, not yet built
//! with the Anchor/SBF toolchain. Priorities: the two guards above, replay via
//! the receipt PDA, expiry, and the `invoke_signed` transfer authority.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::sysvar::instructions::ID as INSTRUCTIONS_SYSVAR_ID;
use anchor_spl::token::{transfer_checked, Mint, Token, TokenAccount, TransferChecked};

pub mod authorization;
pub mod ed25519;

use authorization::{ReleaseAuthorization, DECISION_SETTLE, RELEASE_AUTH_LEN, VERSION};

// REVIEW(codex): placeholder program id — replace with `anchor keys sync` output
// before any deploy. `program_id` inside a ReleaseAuthorization must equal this.
declare_id!("GaTe1111111111111111111111111111111111111111");

#[program]
pub mod liquet_gate {
    use super::*;

    /// One-time config: pin the Liquet verdict signer and a pause authority.
    pub fn initialize(ctx: Context<Initialize>, trusted_signer: Pubkey, pause_authority: Pubkey) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        cfg.trusted_signer = trusted_signer;
        cfg.pause_authority = pause_authority;
        cfg.paused = false;
        cfg.bump = ctx.bumps.config;
        Ok(())
    }

    /// Fund the escrow token account (authority = the `vault` PDA). Any depositor
    /// (the LP / PSP / custodian) can top it up; refunds go back to `depositor`.
    ///
    /// REVIEW(codex): scaffold records the depositor for `refund`. A production
    /// version needs per-deposit accounting; here we keep one escrow per (config,
    /// mint) for the demo.
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let cpi = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            TransferChecked {
                from: ctx.accounts.depositor_token.to_account_info(),
                mint: ctx.accounts.mint.to_account_info(),
                to: ctx.accounts.escrow_token.to_account_info(),
                authority: ctx.accounts.depositor.to_account_info(),
            },
        );
        transfer_checked(cpi, amount, ctx.accounts.mint.decimals)?;
        ctx.accounts.escrow.depositor = ctx.accounts.depositor.key();
        ctx.accounts.escrow.mint = ctx.accounts.mint.key();
        ctx.accounts.escrow.bump = ctx.bumps.vault;
        Ok(())
    }

    /// The core: release escrowed funds iff a `Settle` authorization signed by the
    /// pinned Liquet signer verifies for *this exact* payout.
    ///
    /// `auth_bytes` is the canonical `ReleaseAuthorization`; `settlement_id` is
    /// passed explicitly only to seed the replay-marker PDA and is asserted equal
    /// to the value inside `auth_bytes`. `ed25519_ix_index` locates the Ed25519
    /// verify instruction that must precede this one in the same transaction.
    pub fn release(
        ctx: Context<Release>,
        auth_bytes: Vec<u8>,
        settlement_id: [u8; 32],
        ed25519_ix_index: u8,
    ) -> Result<()> {
        let cfg = &ctx.accounts.config;
        require!(!cfg.paused, GateError::Paused);
        require!(auth_bytes.len() == RELEASE_AUTH_LEN, GateError::BadAuthorizationLength);

        // ① The signature must BIND the pinned signer over exactly these bytes.
        ed25519::verify_signed_message(
            &ctx.accounts.instructions_sysvar,
            ed25519_ix_index,
            &cfg.trusted_signer,
            &auth_bytes,
        )?;

        // ② Every enforced parameter is read from the signed message.
        let auth = ReleaseAuthorization::from_bytes(&auth_bytes)?;
        require!(auth.version == VERSION, GateError::BadVersion);
        require!(auth.decision == DECISION_SETTLE, GateError::NotSettle);
        require_keys_eq!(auth.program_id, crate::ID, GateError::WrongProgramBinding);
        require!(auth.settlement_id == settlement_id, GateError::SettlementIdMismatch);
        require_keys_eq!(auth.vault, ctx.accounts.vault.key(), GateError::VaultMismatch);
        require_keys_eq!(auth.mint, ctx.accounts.mint.key(), GateError::MintMismatch);
        require_keys_eq!(
            auth.recipient,
            ctx.accounts.recipient_token.key(),
            GateError::RecipientMismatch
        );

        // Expiry — the verdict is only good for a bounded window.
        let now = Clock::get()?.unix_timestamp;
        require!(now <= auth.expiry, GateError::AuthorizationExpired);

        // Sufficient escrow balance for the signed amount.
        require!(
            ctx.accounts.escrow_token.amount >= auth.amount,
            GateError::InsufficientEscrow
        );

        // Replay: the receipt PDA (seeded by settlement_id) is `init` in the
        // accounts context, so a second release for the same settlement fails to
        // create it. Record for audit.
        let receipt = &mut ctx.accounts.receipt;
        receipt.settlement_id = settlement_id;
        receipt.amount = auth.amount;
        receipt.bump = ctx.bumps.receipt;

        // Transfer with the vault PDA authority via invoke_signed.
        let config_key = cfg.key();
        let mint_key = ctx.accounts.mint.key();
        let vault_bump = ctx.accounts.escrow.bump;
        let seeds: &[&[u8]] = &[b"vault", config_key.as_ref(), mint_key.as_ref(), &[vault_bump]];
        let signer_seeds: &[&[&[u8]]] = &[seeds];

        let cpi = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            TransferChecked {
                from: ctx.accounts.escrow_token.to_account_info(),
                mint: ctx.accounts.mint.to_account_info(),
                to: ctx.accounts.recipient_token.to_account_info(),
                authority: ctx.accounts.vault.to_account_info(),
            },
            signer_seeds,
        );
        transfer_checked(cpi, auth.amount, ctx.accounts.mint.decimals)?;

        emit!(Released {
            settlement_id,
            recipient: ctx.accounts.recipient_token.key(),
            amount: auth.amount,
        });
        Ok(())
    }

    /// Return escrowed funds to the original depositor after expiry / on pause.
    /// REVIEW(codex): scaffold — expiry semantics and authority checks need the
    /// full design (depositor-only vs pause-authority emergency path).
    pub fn refund(_ctx: Context<Refund>) -> Result<()> {
        err!(GateError::NotImplemented)
    }

    /// Emergency stop, gated by the multisig pause authority set at initialize.
    pub fn set_pause(ctx: Context<SetPause>, paused: bool) -> Result<()> {
        require_keys_eq!(
            ctx.accounts.pause_authority.key(),
            ctx.accounts.config.pause_authority,
            GateError::Unauthorized
        );
        ctx.accounts.config.paused = paused;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[account]
pub struct GateConfig {
    pub trusted_signer: Pubkey,
    pub pause_authority: Pubkey,
    pub paused: bool,
    pub bump: u8,
}
impl GateConfig {
    pub const LEN: usize = 32 + 32 + 1 + 1;
}

#[account]
pub struct Escrow {
    pub depositor: Pubkey,
    pub mint: Pubkey,
    pub bump: u8, // vault PDA bump
}
impl Escrow {
    pub const LEN: usize = 32 + 32 + 1;
}

/// Existence == "this settlement already released". `init` blocks replay.
#[account]
pub struct ReceiptMarker {
    pub settlement_id: [u8; 32],
    pub amount: u64,
    pub bump: u8,
}
impl ReceiptMarker {
    pub const LEN: usize = 32 + 8 + 1;
}

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = payer,
        space = 8 + GateConfig::LEN,
        seeds = [b"config"],
        bump
    )]
    pub config: Account<'info, GateConfig>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, GateConfig>,

    #[account(
        init_if_needed,
        payer = depositor,
        space = 8 + Escrow::LEN,
        seeds = [b"escrow", config.key().as_ref(), mint.key().as_ref()],
        bump
    )]
    pub escrow: Account<'info, Escrow>,

    /// CHECK: PDA authority over the escrow token account; never signs off-chain.
    #[account(seeds = [b"vault", config.key().as_ref(), mint.key().as_ref()], bump)]
    pub vault: UncheckedAccount<'info>,

    #[account(mut, token::mint = mint, token::authority = vault)]
    pub escrow_token: Account<'info, TokenAccount>,

    #[account(mut, token::mint = mint, token::authority = depositor)]
    pub depositor_token: Account<'info, TokenAccount>,

    pub mint: Account<'info, Mint>,

    #[account(mut)]
    pub depositor: Signer<'info>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(auth_bytes: Vec<u8>, settlement_id: [u8; 32])]
pub struct Release<'info> {
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, GateConfig>,

    #[account(
        seeds = [b"escrow", config.key().as_ref(), mint.key().as_ref()],
        bump
    )]
    pub escrow: Account<'info, Escrow>,

    /// CHECK: PDA authority over the escrow token account; verified by seeds.
    #[account(seeds = [b"vault", config.key().as_ref(), mint.key().as_ref()], bump)]
    pub vault: UncheckedAccount<'info>,

    #[account(mut, token::mint = mint, token::authority = vault)]
    pub escrow_token: Account<'info, TokenAccount>,

    #[account(mut, token::mint = mint)]
    pub recipient_token: Account<'info, TokenAccount>,

    pub mint: Account<'info, Mint>,

    /// Replay marker — `init` fails if this settlement already released.
    #[account(
        init,
        payer = relayer,
        space = 8 + ReceiptMarker::LEN,
        seeds = [b"receipt", settlement_id.as_ref()],
        bump
    )]
    pub receipt: Account<'info, ReceiptMarker>,

    /// CHECK: address-checked Instructions sysvar for Ed25519 introspection (①).
    #[account(address = INSTRUCTIONS_SYSVAR_ID)]
    pub instructions_sysvar: UncheckedAccount<'info>,

    /// Anyone can relay a signed Settle; the signature is the authority.
    #[account(mut)]
    pub relayer: Signer<'info>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Refund<'info> {
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, GateConfig>,
    // REVIEW(codex): fill in escrow/vault/depositor_token + expiry gate.
}

#[derive(Accounts)]
pub struct SetPause<'info> {
    #[account(mut, seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, GateConfig>,
    pub pause_authority: Signer<'info>,
}

// ---------------------------------------------------------------------------
// Events + errors
// ---------------------------------------------------------------------------

#[event]
pub struct Released {
    pub settlement_id: [u8; 32],
    pub recipient: Pubkey,
    pub amount: u64,
}

#[error_code]
pub enum GateError {
    #[msg("gate is paused")]
    Paused,
    #[msg("authorization byte length is wrong")]
    BadAuthorizationLength,
    #[msg("authorization layout version mismatch")]
    BadVersion,
    #[msg("decision is not Settle — nothing is released")]
    NotSettle,
    #[msg("authorization program_id does not bind to this gate")]
    WrongProgramBinding,
    #[msg("settlement_id in the seed does not match the signed authorization")]
    SettlementIdMismatch,
    #[msg("vault does not match the signed authorization")]
    VaultMismatch,
    #[msg("mint does not match the signed authorization")]
    MintMismatch,
    #[msg("recipient does not match the signed authorization")]
    RecipientMismatch,
    #[msg("authorization has expired")]
    AuthorizationExpired,
    #[msg("escrow balance is insufficient for the signed amount")]
    InsufficientEscrow,
    #[msg("preceding instruction is not the native Ed25519 program")]
    NotEd25519Program,
    #[msg("malformed Ed25519 instruction data")]
    MalformedEd25519,
    #[msg("expected exactly one signature in the Ed25519 instruction")]
    UnexpectedSignatureCount,
    #[msg("Ed25519 offsets reference another instruction")]
    CrossInstructionRef,
    #[msg("signer is not the pinned Liquet signer")]
    WrongSigner,
    #[msg("verified message does not match the authorization bytes")]
    MessageMismatch,
    #[msg("not authorized")]
    Unauthorized,
    #[msg("not implemented in this scaffold")]
    NotImplemented,
}
