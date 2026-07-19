//! Guard ① — Ed25519 signature-instruction introspection.
//!
//! We do **not** trust that "an Ed25519 verify instruction is present". A native
//! Ed25519 verify only proves *some* (pubkey, message, signature) triple checks
//! out — an attacker can append a perfectly valid verification over **their own**
//! key and **their own** message and it would pass a naive presence check.
//!
//! So `release()` binds the verification: it reads the preceding Ed25519
//! instruction and asserts
//!   (a) it is the native Ed25519 program,
//!   (b) the verified public key == our pinned `trusted_signer`,
//!   (c) the verified message == the exact `ReleaseAuthorization` bytes we enforce,
//!   (d) the signature/pubkey/message are self-contained in that instruction
//!       (no cross-instruction reference we did not parse).
//!
//! # Native Ed25519 instruction data layout
//!
//! ```text
//! count:   u8          number of signatures (we require exactly 1)
//! padding: u8
//! offsets: Ed25519SignatureOffsets * count   (14 bytes each)
//!   signature_offset:            u16
//!   signature_instruction_index: u16
//!   public_key_offset:           u16
//!   public_key_instruction_index:u16
//!   message_data_offset:         u16
//!   message_data_size:           u16
//!   message_instruction_index:   u16
//! ...referenced signature (64) / pubkey (32) / message bytes follow
//! ```
//!
//! REVIEW(codex): the "current instruction" sentinel for the `*_instruction_index`
//! fields is `u16::MAX` in the Solana Ed25519 program. Please double-check this
//! against the exact program version we target and confirm we reject every
//! cross-instruction form (`index != u16::MAX`) — that is the crux of guard ①.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::sysvar::instructions::load_instruction_at_checked;

use crate::GateError;

/// Native Ed25519 signature-verification program id
/// (`Ed25519SigVerify111111111111111111111111111`). Hardcoded as bytes because
/// neither the `ed25519_program` module nor the `pubkey!` macro is reachable
/// through `anchor_lang::solana_program` in this solana version.
const ED25519_PROGRAM_ID: Pubkey = Pubkey::new_from_array([
    3, 125, 70, 214, 124, 147, 251, 190, 18, 249, 66, 143, 131, 141, 64, 255, 5, 112, 116, 73,
    39, 244, 138, 100, 252, 202, 112, 68, 128, 0, 0, 0,
]);

const COUNT_OFFSET: usize = 0;
const OFFSETS_START: usize = 2;
const OFFSETS_LEN: usize = 14;
const SIG_LEN: usize = 64;
const PUBKEY_LEN: usize = 32;

/// `*_instruction_index` sentinel meaning "this same instruction".
const CURRENT_INSTRUCTION: u16 = u16::MAX;

/// Verify that instruction `ed25519_ix_index` is a native Ed25519 verification
/// that binds `expected_signer` over exactly `expected_message`.
pub fn verify_signed_message(
    instructions_sysvar: &AccountInfo,
    ed25519_ix_index: u8,
    expected_signer: &Pubkey,
    expected_message: &[u8],
) -> Result<()> {
    let ix = load_instruction_at_checked(ed25519_ix_index as usize, instructions_sysvar)?;

    // (a) native Ed25519 program only.
    require_keys_eq!(ix.program_id, ED25519_PROGRAM_ID, GateError::NotEd25519Program);

    let data = &ix.data;
    require!(
        data.len() >= OFFSETS_START + OFFSETS_LEN,
        GateError::MalformedEd25519
    );
    require!(data[COUNT_OFFSET] == 1, GateError::UnexpectedSignatureCount);

    let o = OFFSETS_START;
    let read_u16 = |i: usize| u16::from_le_bytes([data[i], data[i + 1]]);
    let signature_offset = read_u16(o) as usize;
    let signature_ix_index = read_u16(o + 2);
    let public_key_offset = read_u16(o + 4) as usize;
    let public_key_ix_index = read_u16(o + 6);
    let message_offset = read_u16(o + 8) as usize;
    let message_size = read_u16(o + 10) as usize;
    let message_ix_index = read_u16(o + 12);

    // (d) everything must live in THIS instruction's data. A cross-instruction
    // reference would let an attacker point the verifier at bytes we never
    // inspected.
    require!(
        signature_ix_index == CURRENT_INSTRUCTION
            && public_key_ix_index == CURRENT_INSTRUCTION
            && message_ix_index == CURRENT_INSTRUCTION,
        GateError::CrossInstructionRef
    );

    // (b) pinned signer.
    let pk = data
        .get(public_key_offset..public_key_offset + PUBKEY_LEN)
        .ok_or(GateError::MalformedEd25519)?;
    require!(pk == expected_signer.as_ref(), GateError::WrongSigner);

    // (c) exact message — size and bytes.
    require!(message_size == expected_message.len(), GateError::MessageMismatch);
    let msg = data
        .get(message_offset..message_offset + message_size)
        .ok_or(GateError::MalformedEd25519)?;
    require!(msg == expected_message, GateError::MessageMismatch);

    // sanity: the signature bytes are actually present.
    require!(
        data.get(signature_offset..signature_offset + SIG_LEN).is_some(),
        GateError::MalformedEd25519
    );

    Ok(())
}
