//! A reference **check**, not an escrow and not Liquet custody.
//!
//! A custodian, PSP, or solver calls [`check_release`] immediately before its
//! own payout code. Liquet only returns `Release` or `Hold`; the caller keeps
//! custody and decides how its own payment system executes a permitted release.

use std::time::{SystemTime, UNIX_EPOCH};

use liquet::{verify_decision, LiquetDecision, SignedDecision};
use serde::{Deserialize, Serialize};

/// The payout the relying party is about to make from its own custody.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentToRelease {
    pub recipient: String,
    pub amount: u64,
    pub mint: String,
    pub settlement_id: String,
}

/// A pinned Ed25519 public key, encoded as the 32 raw key bytes used by
/// `liquet::attest::verify_decision`. This is deliberately not a Solana account
/// address: it identifies the Liquet operator whose verdicts the custodian has
/// chosen to trust.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pubkey([u8; 32]);

impl Pubkey {
    pub fn from_hex(value: &str) -> Result<Self, String> {
        let bytes: [u8; 32] = hex::decode(value)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| "pinned signer must be a 32-byte hex Ed25519 public key".to_string())?;
        Ok(Self(bytes))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// The only outcome this reference returns to a custody release path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "lowercase")]
pub enum ReleaseDecision {
    Release,
    Hold { reason: String },
}

impl ReleaseDecision {
    pub fn is_release(&self) -> bool {
        matches!(self, Self::Release)
    }
}

/// Check a Liquet verdict immediately before the relying party's own payout.
///
/// The existing `attest.rs` Ed25519 verification remains the single signature
/// implementation. This function adds only the relying party's final binding:
/// its impending `recipient`, `amount`, `mint`, and `settlement_id` must equal
/// fields inside the already-signed `release_payment` binding.
pub fn check_release(
    payment: &PaymentToRelease,
    verdict: &SignedDecision,
    pinned_signer: &Pubkey,
) -> ReleaseDecision {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(i64::MAX);
    check_release_at(payment, verdict, pinned_signer, now)
}

/// Time-injectable form of [`check_release`] for deterministic callers and
/// tests. Production callers normally use [`check_release`].
pub fn check_release_at(
    payment: &PaymentToRelease,
    verdict: &SignedDecision,
    pinned_signer: &Pubkey,
    now_unix_seconds: i64,
) -> ReleaseDecision {
    if let Err(error) = verify_decision(verdict, &pinned_signer.to_hex()) {
        return hold(format!("verdict signature rejected: {error:?}"));
    }

    let binding = match verdict.binding.release_payment.as_ref() {
        Some(binding) => binding,
        None => return hold("verdict has no signed release-payment binding"),
    };

    // The duplicated settlement id prevents an otherwise well-signed generic
    // decision from being repurposed through a contradictory release attachment.
    if binding.settlement_id != verdict.binding.settlement_id {
        return hold("verdict settlement_id conflicts with its signed release-payment binding");
    }
    if binding.settlement_id != payment.settlement_id {
        return hold("settlement_id does not match the payment about to be released");
    }
    if binding.recipient != payment.recipient {
        return hold("recipient does not match the payment about to be released");
    }
    if binding.amount != payment.amount {
        return hold("amount does not match the payment about to be released");
    }
    if binding.mint != payment.mint {
        return hold("mint does not match the payment about to be released");
    }
    if now_unix_seconds > binding.expires_at {
        return hold("verdict has expired");
    }

    match &verdict.binding.decision {
        LiquetDecision::Settle { .. } => ReleaseDecision::Release,
        LiquetDecision::Hold { reasons } => {
            let detail = if reasons.is_empty() {
                "no reason supplied".to_string()
            } else {
                reasons.join("; ")
            };
            hold(format!("Liquet verdict is Hold: {detail}"))
        }
    }
}

fn hold(reason: impl Into<String>) -> ReleaseDecision {
    ReleaseDecision::Hold {
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use liquet::{
        sign_decision, CrossVmProof, DecisionBinding, GatePolicy, InvariantVerdict,
        ReconcileVerdict, ReleasePaymentBinding,
    };

    use super::*;

    const EXPIRY: i64 = 2_000_000_000;

    fn payment() -> PaymentToRelease {
        PaymentToRelease {
            recipient: "recipient-token-account".into(),
            amount: 4_000_000,
            mint: "USDC-mint".into(),
            settlement_id: "settlement-42".into(),
        }
    }

    fn signer() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn pinned() -> Pubkey {
        Pubkey::from_hex(&hex::encode(signer().verifying_key().to_bytes())).unwrap()
    }

    fn signed(decision: LiquetDecision) -> SignedDecision {
        let payment = payment();
        let proof = CrossVmProof {
            reconcile: ReconcileVerdict::Matched,
            reasons: vec![],
            legs: vec![],
            claim_hash: "claim".into(),
            settlement_id: payment.settlement_id.clone(),
        };
        let binding = DecisionBinding::new(
            &proof,
            &InvariantVerdict::green(),
            &GatePolicy::default(),
            &decision,
        )
        .with_release_payment(ReleasePaymentBinding {
            settlement_id: payment.settlement_id,
            recipient: payment.recipient,
            amount: payment.amount,
            mint: payment.mint,
            expires_at: EXPIRY,
        });
        sign_decision(binding, &signer())
    }

    #[test]
    fn signed_settle_bound_to_the_payment_releases() {
        assert_eq!(
            check_release_at(
                &payment(),
                &signed(LiquetDecision::Settle { caveats: vec![] }),
                &pinned(),
                1
            ),
            ReleaseDecision::Release
        );
    }

    #[test]
    fn hold_verdict_never_releases() {
        let decision = check_release_at(
            &payment(),
            &signed(LiquetDecision::Hold {
                reasons: vec!["half-open".into()],
            }),
            &pinned(),
            1,
        );
        assert!(
            matches!(decision, ReleaseDecision::Hold { reason } if reason.contains("half-open"))
        );
    }

    #[test]
    fn every_payment_field_is_bound() {
        let verdict = signed(LiquetDecision::Settle { caveats: vec![] });
        let mut wrong = payment();
        wrong.amount += 1;
        assert!(
            matches!(check_release_at(&wrong, &verdict, &pinned(), 1), ReleaseDecision::Hold { reason } if reason.contains("amount"))
        );
        wrong = payment();
        wrong.recipient = "attacker".into();
        assert!(
            matches!(check_release_at(&wrong, &verdict, &pinned(), 1), ReleaseDecision::Hold { reason } if reason.contains("recipient"))
        );
        wrong = payment();
        wrong.mint = "different-mint".into();
        assert!(
            matches!(check_release_at(&wrong, &verdict, &pinned(), 1), ReleaseDecision::Hold { reason } if reason.contains("mint"))
        );
        wrong = payment();
        wrong.settlement_id = "other-settlement".into();
        assert!(
            matches!(check_release_at(&wrong, &verdict, &pinned(), 1), ReleaseDecision::Hold { reason } if reason.contains("settlement_id"))
        );
    }

    #[test]
    fn unknown_signer_expired_and_legacy_verdict_hold() {
        let verdict = signed(LiquetDecision::Settle { caveats: vec![] });
        let stranger = Pubkey::from_hex(&hex::encode(
            SigningKey::from_bytes(&[9u8; 32])
                .verifying_key()
                .to_bytes(),
        ))
        .unwrap();
        assert!(
            matches!(check_release_at(&payment(), &verdict, &stranger, 1), ReleaseDecision::Hold { reason } if reason.contains("signature"))
        );
        assert!(
            matches!(check_release_at(&payment(), &verdict, &pinned(), EXPIRY + 1), ReleaseDecision::Hold { reason } if reason.contains("expired"))
        );

        let legacy_proof = CrossVmProof {
            reconcile: ReconcileVerdict::Matched,
            reasons: vec![],
            legs: vec![],
            claim_hash: "claim".into(),
            settlement_id: payment().settlement_id,
        };
        let legacy = sign_decision(
            DecisionBinding::new(
                &legacy_proof,
                &InvariantVerdict::green(),
                &GatePolicy::default(),
                &LiquetDecision::Settle { caveats: vec![] },
            ),
            &signer(),
        );
        assert!(
            matches!(check_release_at(&payment(), &legacy, &pinned(), 1), ReleaseDecision::Hold { reason } if reason.contains("release-payment"))
        );
    }
}
