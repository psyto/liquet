//! Non-repudiation for the Liquet verdict.
//!
//! A [`LiquetDecision`] on its own is just a struct — anyone could claim Liquet
//! said "settle". This layer binds a decision to the EXACT re-executed legs,
//! intent, invariant screen, and policy it was computed under, then signs that
//! binding with an ed25519 key. A relying party (a solver's LP, a counterparty)
//! calls [`verify_decision`] with the TRUSTED operator key and checks the
//! digests match the settlement they expected — so the verdict cannot be forged,
//! cannot be repudiated, and cannot be replayed against a different settlement.
//!
//! Pure: no producer crates, no network — operates on the seam types only.

use crate::decide::{GatePolicy, LiquetDecision};
use crate::seam::{CrossVmProof, InvariantVerdict, ReconcileVerdict, Severity, Vm};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// One re-executed leg's identity, committed in full (not just the first per VM).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegDigest {
    pub vm: Vm,
    pub executed: bool,
    pub poststate_digest: String,
}

/// The gate policy a decision was made under — so a recipient can audit *why* a
/// borderline (Info/Yellow) case settled or held.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySnapshot {
    pub max_settle_severity: Severity,
    pub require_executed: bool,
    pub require_recovered_facts: bool,
}

/// The exact payment a relying party is about to release from *its own* system.
///
/// This is optional for backwards-compatible generic Liquet attestations, but a
/// custody / PSP release path MUST require it. When present it is serialized
/// inside [`DecisionBinding`] and therefore covered by the existing Ed25519
/// signature and `liquet/decision/v2\0` digest — it is not a second signature
/// format.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleasePaymentBinding {
    pub settlement_id: String,
    pub recipient: String,
    pub amount: u64,
    pub mint: String,
    /// Unix seconds. A release gate must Hold after this time.
    pub expires_at: i64,
}

impl PolicySnapshot {
    pub fn of(p: &GatePolicy) -> Self {
        Self {
            max_settle_severity: p.max_settle_severity,
            require_executed: p.require_executed,
            require_recovered_facts: p.require_recovered_facts,
        }
    }
}

/// The exact facts a signed decision commits to. Binding to every leg's reexec
/// digest, the full invariant verdict, and the policy means a signature over it
/// cannot be reused for another settlement, nor paired with a false explanation
/// of why Liquet settled or held.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionBinding {
    pub settlement_id: String,
    pub claim_hash: String,
    /// ALL legs, in the producer's order — not a first-per-VM projection.
    pub legs: Vec<LegDigest>,
    pub reconcile: ReconcileVerdict,
    /// The complete invariant verdict (level + every finding), not just severity.
    pub invariant: InvariantVerdict,
    pub policy: PolicySnapshot,
    pub decision: LiquetDecision,
    /// Optional only for generic attestations. A model-(b) release gate rejects
    /// an absent binding rather than guessing payment fields from claim hashes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_payment: Option<ReleasePaymentBinding>,
}

impl DecisionBinding {
    /// Assemble the binding from the two slots, the policy, and the decision.
    pub fn new(
        proof: &CrossVmProof,
        invariant: &InvariantVerdict,
        policy: &GatePolicy,
        decision: &LiquetDecision,
    ) -> Self {
        Self {
            settlement_id: proof.settlement_id.clone(),
            claim_hash: proof.claim_hash.clone(),
            legs: proof
                .legs
                .iter()
                .map(|l| LegDigest {
                    vm: l.vm,
                    executed: l.executed,
                    poststate_digest: l.poststate_digest.clone(),
                })
                .collect(),
            reconcile: proof.reconcile,
            invariant: invariant.clone(),
            policy: PolicySnapshot::of(policy),
            decision: decision.clone(),
            release_payment: None,
        }
    }

    /// Bind this signed verdict to one exact relying-party payout. The caller
    /// must supply the same values its own release logic will compare before it
    /// moves money. This builder preserves the legacy generic constructor while
    /// making the stronger model-(b) contract explicit.
    pub fn with_release_payment(mut self, payment: ReleasePaymentBinding) -> Self {
        self.release_payment = Some(payment);
        self
    }

    /// Domain-separated 32-byte hash the signature commits to. Deterministic:
    /// every field is an ordered struct / enum / scalar / string (no maps, no
    /// floats), so `serde_json` output is stable. NOTE: `serde_json` is not a
    /// formal cross-version wire canon — the golden-vector test locks today's
    /// encoding; bump the domain version if the encoding ever changes.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"liquet/decision/v2\0");
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
    /// The receipt was not signed by the trusted signer.
    SignerMismatch,
    /// The signer key or signature was not valid hex / the wrong length.
    Malformed,
    /// The signature did not verify against the binding — forged or tampered.
    BadSignature,
}

/// Verify a signed decision **against a trusted signer** (hex ed25519 public
/// key, case-insensitive). This is the authentication path: `Ok(())` means the
/// receipt was signed by `trusted_signer` over exactly this binding. Anyone can
/// sign a binding with their own key, so pinning the trusted key is mandatory
/// for non-repudiation — use [`verify_self_consistent`] only when you explicitly
/// do not need to establish *who* signed.
pub fn verify_decision(signed: &SignedDecision, trusted_signer: &str) -> Result<(), VerifyError> {
    if !trusted_signer.eq_ignore_ascii_case(&signed.signer) {
        return Err(VerifyError::SignerMismatch);
    }
    verify_self_consistent(signed)
}

/// Check that `signed.signature` is a valid signature over `signed.binding` by
/// the key embedded in `signed.signer`. This proves internal consistency ONLY —
/// it does NOT establish that the signer is trusted. Not authentication; use
/// [`verify_decision`] for that.
pub fn verify_self_consistent(signed: &SignedDecision) -> Result<(), VerifyError> {
    let pk: [u8; 32] = hex::decode(&signed.signer)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(VerifyError::Malformed)?;
    let vk = VerifyingKey::from_bytes(&pk).map_err(|_| VerifyError::Malformed)?;
    let sig_bytes = hex::decode(&signed.signature).map_err(|_| VerifyError::Malformed)?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| VerifyError::Malformed)?;
    // Strict verification rejects non-canonical / small-order signatures and weak
    // keys — no malleability for a non-repudiable receipt.
    vk.verify_strict(&signed.binding.digest(), &sig)
        .map_err(|_| VerifyError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seam::{FactsSource, Finding, ReexecProof};

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
            &GatePolicy::default(),
            &LiquetDecision::Settle { caveats: vec![] },
        )
    }

    fn operator() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn binding_captures_all_legs() {
        let b = binding();
        assert_eq!(b.legs.len(), 2);
        assert_eq!(b.legs[0].vm, Vm::Evm);
        assert_eq!(b.legs[0].poststate_digest, "evm-dig");
        assert_eq!(b.legs[1].vm, Vm::Svm);
    }

    #[test]
    fn verify_against_trusted_signer_ok() {
        let signed = sign_decision(binding(), &operator());
        let operator_pk = signed.signer.clone();
        assert_eq!(verify_decision(&signed, &operator_pk), Ok(()));
        assert_eq!(verify_self_consistent(&signed), Ok(()));
    }

    #[test]
    fn attacker_key_is_self_consistent_but_not_trusted() {
        // P1-a: an attacker signs the same binding with their own key. It is
        // internally consistent, but verification against the trusted operator
        // key must reject it.
        let operator_pk = hex::encode(operator().verifying_key().to_bytes());
        let attacker = SigningKey::from_bytes(&[9u8; 32]);
        let forged = sign_decision(binding(), &attacker);
        assert_eq!(verify_self_consistent(&forged), Ok(())); // consistent...
        assert_eq!(verify_decision(&forged, &operator_pk), Err(VerifyError::SignerMismatch)); // ...but not trusted
    }

    #[test]
    fn tampered_decision_fails() {
        let mut signed = sign_decision(binding(), &operator());
        let pk = signed.signer.clone();
        signed.binding.decision = LiquetDecision::Hold { reasons: vec!["forged".into()] };
        assert_eq!(verify_decision(&signed, &pk), Err(VerifyError::BadSignature));
    }

    #[test]
    fn changed_invariant_finding_fails() {
        // P1-b: same level (Info), different findings → the signature must not
        // carry over, so a false "why it settled" cannot ride a valid signature.
        let signed = sign_decision(binding(), &operator());
        let pk = signed.signer.clone();
        let mut swapped = signed.clone();
        swapped.binding.invariant = InvariantVerdict {
            level: Severity::Green,
            findings: vec![Finding {
                severity: Severity::Green,
                code: "injected".into(),
                account: None,
                message: "not what was screened".into(),
            }],
        };
        assert_eq!(verify_decision(&swapped, &pk), Err(VerifyError::BadSignature));
    }

    #[test]
    fn replay_against_different_leg_fails() {
        let signed = sign_decision(binding(), &operator());
        let pk = signed.signer.clone();
        let mut swapped = signed.clone();
        swapped.binding.legs[1].poststate_digest = "some-other-svm-execution".into();
        assert_eq!(verify_decision(&swapped, &pk), Err(VerifyError::BadSignature));
    }

    #[test]
    fn extra_leg_changes_binding() {
        // P2: an added same-VM leg must not produce the same binding.
        let mut p = proof();
        p.legs.push(leg(Vm::Svm, "sneaky-extra-leg"));
        let b2 = DecisionBinding::new(
            &p,
            &InvariantVerdict::green(),
            &GatePolicy::default(),
            &LiquetDecision::Settle { caveats: vec![] },
        );
        assert_ne!(binding().digest(), b2.digest());
    }

    #[test]
    fn malformed_signer_or_signature_rejected() {
        let mut signed = sign_decision(binding(), &operator());
        let pk = signed.signer.clone();
        signed.signature = "zz".into();
        assert_eq!(verify_decision(&signed, &pk), Err(VerifyError::Malformed));
    }

    #[test]
    fn digest_is_stable_golden_vector() {
        // Locks today's wire encoding. If this changes intentionally, bump the
        // domain version in `digest()` and update this vector.
        assert_eq!(
            hex::encode(binding().digest()),
            "dd2c88522195119e465419b67cdaaf0257d42d1d0526653c3be4d3e47c9995b4"
        );
    }
}
