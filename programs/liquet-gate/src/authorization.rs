//! `ReleaseAuthorization` — the exact, fixed-length bytes the Liquet gate signs
//! off-chain and this program verifies on-chain.
//!
//! # Why a hand-rolled fixed layout (not borsh/serde)
//!
//! This byte layout is the **single source of truth** shared with the off-chain
//! signer (`liquet`'s `attest.rs` path). It is deliberately a hand-rolled
//! fixed-offset encoding so the off-chain producer and the on-chain verifier can
//! never drift across serialization-library versions. Any change here MUST be
//! mirrored byte-for-byte in the off-chain signer and MUST bump [`VERSION`].
//!
//! # What the signature commits to
//!
//! The gate signs `ReleaseAuthorization::to_bytes()`. The program enforces the
//! transfer using the fields **read from these verified bytes** — never from
//! separately-supplied instruction arguments (guard ② in the README). That
//! prevents "sign for vault A, execute against vault B".
//!
//! REVIEW(codex): confirm the field set is complete for the threat model. In
//! particular `program_id` binds the authorization to THIS deployed program so a
//! signature minted for one gate cannot be replayed against another.

use anchor_lang::prelude::*;

use crate::GateError;

/// Layout version. Bump on ANY change to the byte layout below.
pub const VERSION: u8 = 1;

/// `decision` byte values.
pub const DECISION_HOLD: u8 = 0;
pub const DECISION_SETTLE: u8 = 1;

/// Fixed serialized length. Field offsets are asserted by the layout below.
///
/// ```text
/// off  len  field
///   0    1  version
///   1    1  decision            (0 = Hold, 1 = Settle)
///   2   32  vault               (escrow authority PDA)
///  34   32  mint
///  66   32  recipient           (recipient SPL token account)
///  98    8  amount              (u64 LE)
/// 106   32  settlement_id       (unique per settlement; replay key)
/// 138    8  expiry              (i64 LE, unix seconds)
/// 146   32  program_id          (binds to THIS gate program)
/// 178                            total
/// ```
pub const RELEASE_AUTH_LEN: usize = 178;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseAuthorization {
    pub version: u8,
    pub decision: u8,
    pub vault: Pubkey,
    pub mint: Pubkey,
    pub recipient: Pubkey,
    pub amount: u64,
    pub settlement_id: [u8; 32],
    pub expiry: i64,
    pub program_id: Pubkey,
}

impl ReleaseAuthorization {
    /// Canonical serialization. This is exactly what the off-chain gate signs.
    pub fn to_bytes(&self) -> [u8; RELEASE_AUTH_LEN] {
        let mut b = [0u8; RELEASE_AUTH_LEN];
        b[0] = self.version;
        b[1] = self.decision;
        b[2..34].copy_from_slice(self.vault.as_ref());
        b[34..66].copy_from_slice(self.mint.as_ref());
        b[66..98].copy_from_slice(self.recipient.as_ref());
        b[98..106].copy_from_slice(&self.amount.to_le_bytes());
        b[106..138].copy_from_slice(&self.settlement_id);
        b[138..146].copy_from_slice(&self.expiry.to_le_bytes());
        b[146..178].copy_from_slice(self.program_id.as_ref());
        b
    }

    /// Parse the verified message bytes back into the typed authorization.
    /// Only ever call this on bytes that [`crate::ed25519`] has already bound to
    /// the pinned signer — otherwise the fields are attacker-controlled.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        require!(b.len() == RELEASE_AUTH_LEN, GateError::BadAuthorizationLength);
        Ok(Self {
            version: b[0],
            decision: b[1],
            vault: pubkey_at(b, 2),
            mint: pubkey_at(b, 34),
            recipient: pubkey_at(b, 66),
            amount: u64::from_le_bytes(b[98..106].try_into().unwrap()),
            settlement_id: b[106..138].try_into().unwrap(),
            expiry: i64::from_le_bytes(b[138..146].try_into().unwrap()),
            program_id: pubkey_at(b, 146),
        })
    }
}

#[inline]
fn pubkey_at(b: &[u8], off: usize) -> Pubkey {
    let mut k = [0u8; 32];
    k.copy_from_slice(&b[off..off + 32]);
    Pubkey::new_from_array(k)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ReleaseAuthorization {
        ReleaseAuthorization {
            version: VERSION,
            decision: DECISION_SETTLE,
            vault: Pubkey::new_from_array([1u8; 32]),
            mint: Pubkey::new_from_array([2u8; 32]),
            recipient: Pubkey::new_from_array([3u8; 32]),
            amount: 1_000_000,
            settlement_id: [4u8; 32],
            expiry: 1_800_000_000,
            program_id: Pubkey::new_from_array([5u8; 32]),
        }
    }

    #[test]
    fn roundtrip_is_stable() {
        let a = sample();
        let bytes = a.to_bytes();
        assert_eq!(bytes.len(), RELEASE_AUTH_LEN);
        let b = ReleaseAuthorization::from_bytes(&bytes).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(ReleaseAuthorization::from_bytes(&[0u8; RELEASE_AUTH_LEN - 1]).is_err());
    }

    #[test]
    fn field_offsets_are_fixed() {
        // A golden byte or two so a layout change is caught by a failing test,
        // not silently by a drifting off-chain signer.
        let bytes = sample().to_bytes();
        assert_eq!(bytes[0], VERSION);
        assert_eq!(bytes[1], DECISION_SETTLE);
        assert_eq!(&bytes[98..106], &1_000_000u64.to_le_bytes());
    }
}
