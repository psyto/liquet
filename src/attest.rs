//! Non-repudiation for the Liquet verdict.
//!
//! A [`LiquetDecision`] on its own is just a struct — anyone could claim Liquet
//! said "settle". This layer binds a decision to the EXACT re-executed legs and
//! intent it was computed over (per-leg reexec digests + claim hash + both
//! verdicts), then signs that binding with an ed25519 key. A relying party (a
//! solver's LP, a counterparty) verifies the signature with Liquet's public key
//! and checks the digests match the settlement they expected — so the verdict
//! cannot be forged, cannot be repudiated, and cannot be replayed against a
//! different settlement.
//!
//! Pure: no producer crates, no network — operates on the seam types only.

use crate::decide::LiquetDecision;
use crate::seam::{CrossVmProof, InvariantVerdict, ReconcileVerdict, Severity, Vm};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The exact facts a signed decision commits to. Binding a decision to the
/// per-leg reexec digests + claim hash means a signature over it cannot be
/// reused for any other settlement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionBinding {
    pub settlement_id: String,
    pub claim_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evm_reexec_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub svm_reexec_digest: Option<String>,
    pub reconcile: ReconcileVerdict,
    pub invariant_level: Severity,
    pub decision: LiquetDecision,
}

impl DecisionBinding {
    /// Assemble the binding from the two slots and the gate decision.
    pub fn new(
        proof: &CrossVmProof,
        invariant: &InvariantVerdict,
        decision: &LiquetDecision,
    ) -> Self {
        let digest_for = |vm: Vm| {
            proof
                .legs
                .iter()
                .find(|l| l.vm == vm)
                .map(|l| l.poststate_digest.clone())
        };
        Self {
            settlement_id: proof.settlement_id.clone(),
            claim_hash: proof.claim_hash.clone(),
            evm_reexec_digest: digest_for(Vm::Evm),
            svm_reexec_digest: digest_for(Vm::Svm),
            reconcile: proof.reconcile,
            invariant_level: invariant.level,
            decision: decision.clone(),
        }
    }

    /// Domain-separated 32-byte hash the signature commits to. Deterministic:
    /// serde_json serializes these scalar/string/enum fields in a stable order.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"liquet/decision/v1\0");
        h.update(serde_json::to_vec(self).expect("DecisionBinding is serializable"));
        h.finalize().into()
    }
}

/// A decision plus the signature that makes it non-repudiable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedDecision {
    pub binding: DecisionBinding,
    /// Hex ed25519 public key of the signer (the Liquet operator).
    pub signer: String,
    /// Hex ed25519 signature over `binding.digest()`.
    pub signature: String,
}

/// Sign a decision binding with `key`, producing a non-repudiable receipt.
pub fn sign_decision(binding: DecisionBinding, key: &SigningKey) -> SignedDecision {
    let signature = key.sign(&binding.digest());
    SignedDecision {
        signer: hex::encode(key.verifying_key().to_bytes()),
        signature: hex::encode(signature.to_bytes()),
        binding,
    }
}

/// Why a signed decision failed verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// `expected_signer` did not match the signature's signer key.
    SignerMismatch,
    /// The signer key or signature was not valid hex / the wrong length.
    Malformed,
    /// The signature did not verify against the binding under the signer key —
    /// the decision was forged or the binding was tampered with.
    BadSignature,
}

/// Verify a signed decision. If `expected_signer` is given, the signer key must
/// match it (hex, case-insensitive). Returns `Ok(())` only when the signature is
/// valid over the binding — i.e. the decision is authentic and unmodified.
pub fn verify_decision(
    signed: &SignedDecision,
    expected_signer: Option<&str>,
) -> Result<(), VerifyError> {
    if let Some(expected) = expected_signer {
        if !expected.eq_ignore_ascii_case(&signed.signer) {
            return Err(VerifyError::SignerMismatch);
        }
    }
    let pk: [u8; 32] = hex::decode(&signed.signer)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(VerifyError::Malformed)?;
    let vk = VerifyingKey::from_bytes(&pk).map_err(|_| VerifyError::Malformed)?;
    let sig_bytes = hex::decode(&signed.signature).map_err(|_| VerifyError::Malformed)?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| VerifyError::Malformed)?;
    // Strict verification rejects non-canonical signatures — no malleability for
    // a non-repudiable receipt.
    vk.verify_strict(&signed.binding.digest(), &sig)
        .map_err(|_| VerifyError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seam::{FactsSource, ReexecProof};

    fn leg(vm: Vm, digest: &str) -> ReexecProof {
        ReexecProof {
            vm,
            executed: true,
            poststate_digest: digest.into(),
            covered_accounts: vec![],
            facts_source: FactsSource::ProducerRecovered,
            asset: None,
            amount: None,
            recipient: None,
            unverifiable_reason: None,
        }
    }

    fn proof() -> CrossVmProof {
        CrossVmProof {
            reconcile: ReconcileVerdict::Matched,
            reasons: vec![],
            legs: vec![leg(Vm::Evm, "evm-dig"), leg(Vm::Svm, "svm-dig")],
            claim_hash: "claim-abc".into(),
            settlement_id: "settlement-1".into(),
        }
    }

    fn binding() -> DecisionBinding {
        DecisionBinding::new(
            &proof(),
            &InvariantVerdict::green(),
            &LiquetDecision::Settle { caveats: vec![] },
        )
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn binding_captures_both_leg_digests() {
        let b = binding();
        assert_eq!(b.evm_reexec_digest.as_deref(), Some("evm-dig"));
        assert_eq!(b.svm_reexec_digest.as_deref(), Some("svm-dig"));
    }

    #[test]
    fn sign_then_verify_ok() {
        let signed = sign_decision(binding(), &key());
        assert_eq!(verify_decision(&signed, None), Ok(()));
        let signer = signed.signer.clone();
        assert_eq!(verify_decision(&signed, Some(&signer)), Ok(()));
    }

    #[test]
    fn tampered_decision_fails() {
        let mut signed = sign_decision(binding(), &key());
        signed.binding.decision = LiquetDecision::Hold { reasons: vec!["forged".into()] };
        assert_eq!(verify_decision(&signed, None), Err(VerifyError::BadSignature));
    }

    #[test]
    fn replay_against_different_leg_fails() {
        // Take a valid signature and try to pass it off for a different execution.
        let mut signed = sign_decision(binding(), &key());
        signed.binding.svm_reexec_digest = Some("some-other-svm-execution".into());
        assert_eq!(verify_decision(&signed, None), Err(VerifyError::BadSignature));
    }

    #[test]
    fn wrong_expected_signer_rejected() {
        let signed = sign_decision(binding(), &key());
        assert_eq!(
            verify_decision(&signed, Some("00ff")),
            Err(VerifyError::SignerMismatch)
        );
    }
}
