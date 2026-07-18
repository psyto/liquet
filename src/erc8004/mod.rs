//! ERC-8004 Validation Registry surface — turn a signed Liquet decision into the
//! fields a validator publishes via `validationResponse(requestHash, response,
//! responseURI, responseHash, tag)`.
//!
//! This is the OUTPUT surface described in `STAGE_ERC8004_VALIDATOR.md`. It is
//! pure — no chain, no `alloy`, no network (those live behind `wire-erc8004`
//! later). It only maps the already-computed, already-signed decision onto the
//! registry's fields, so it ships in the standalone core and is covered by the
//! default `cargo test`.
//!
//! The load-bearing fact (SEAM §1): Liquet already produces a non-repudiable
//! commitment — [`crate::attest::DecisionBinding::digest`] — over the exact legs,
//! reconcile verdict, full invariant verdict, policy, and decision. That digest
//! IS the ERC-8004 `responseHash`. This module adds no new trust; it gives the
//! existing verdict an on-chain home.
//!
//! ## What grounds the score (why this fills the empty Validation seat)
//! ERC-8004's Reputation Registry is Sybil-forgeable because feedback is not
//! grounded in a verifiable interaction (arXiv 2606.26028). Here the `response`
//! is derived from a re-executed settle/hold decision whose `responseHash`
//! commits to both legs' re-exec digests — a relying party can fetch the evidence
//! bundle, recompute the hash, and verify the signature. That is the grounding.

use crate::attest::{verify_decision, SignedDecision, VerifyError};
use crate::seam::ReconcileVerdict;
use serde::{Deserialize, Serialize};

/// Content-addressed evidence store: pin the bundle at a stable `responseURI`.
pub mod store;
/// Chain-agnostic validator orchestration: request → decision → response/abstain.
pub mod validator;
/// Step 5 — the real `SettlementValidator` (wired Liquet pipeline), behind `wire-xvm`.
#[cfg(feature = "wire-xvm")]
pub mod liquet_validator;
#[cfg(feature = "wire-xvm")]
pub use liquet_validator::{LiquetValidator, SettlementRequest};

/// Score for a verified-good action (`uint8` in the registry). Binary by design
/// so `getSummary`'s `averageResponse` stays a clean trust signal.
pub const PASS: u8 = 100;
/// Score for a verified-bad action (half-open / mismatch / malice).
pub const FAIL: u8 = 0;

/// Tag for a clean, atomic, intent-matching settlement.
pub const TAG_MATCHED: &str = "matched";
/// Tag for a half-settled cross-VM position (exactly one leg executed).
pub const TAG_HALF_OPEN: &str = "half-open";
/// Tag for both legs executed but terms diverge from the claimed intent.
pub const TAG_MISMATCH: &str = "mismatch";
/// Tag for a reconcile-`Matched` action that the invariant screen still held on
/// (atomic, but a malice/safety finding on a leg). Distinct failure from a
/// terms/leg divergence — different evidence.
pub const TAG_UNSAFE: &str = "unsafe";
/// Tag for an action a leg of which could not be deterministically reconstructed.
/// We ABSTAIN on-chain rather than post a `0` that would average as "failed".
pub const TAG_UNVERIFIABLE: &str = "unverifiable";

/// The ERC-8004 `validationResponse` payload our validator would submit, derived
/// purely from a [`SignedDecision`].
///
/// `response == None` means **abstain**: post nothing on-chain. Posting `FAIL`
/// for an unverifiable action would conflate "we checked, it failed" with "we
/// could not check", poisoning `averageResponse`. See `STAGE_ERC8004_VALIDATOR.md`
/// §3.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationResponse {
    /// `uint8` score 0..=100, or `None` to abstain (do not call
    /// `validationResponse` at all for this request).
    pub response: Option<u8>,
    /// Categorization tag. **Consumers must read this**, not just
    /// `averageResponse`: `half-open`, `mismatch`, and `unsafe` are all `FAIL`
    /// but are different failures with different evidence.
    pub tag: String,
    /// Hex SHA-256 = [`crate::attest::DecisionBinding::digest`]; equals the
    /// on-chain `responseHash` and the hash a relying party recomputes from the
    /// evidence bundle.
    pub response_hash: String,
}

impl ValidationResponse {
    /// Whether this response is published on-chain (`false` = abstain).
    pub fn is_published(&self) -> bool {
        self.response.is_some()
    }
}

/// Map a signed Liquet decision onto the ERC-8004 `validationResponse` fields.
///
/// The score is driven by the FINAL decision (settle → [`PASS`], hold →
/// [`FAIL`]), and the tag by *why*, so an atomic-but-malicious action (reconcile
/// `Matched` yet held on the invariant screen) is a `FAIL`/`unsafe`, never a
/// `matched` pass. Reconcile `Unverifiable` abstains regardless of the decision.
pub fn validation_response(signed: &SignedDecision) -> ValidationResponse {
    let response_hash = hex::encode(signed.binding.digest());
    let (response, tag): (Option<u8>, &str) = match signed.binding.reconcile {
        // We could not deterministically reconstruct a leg — abstain, do not
        // pollute the average. The requester can route to another validator.
        ReconcileVerdict::Unverifiable => (None, TAG_UNVERIFIABLE),
        ReconcileVerdict::HalfOpen => (Some(FAIL), TAG_HALF_OPEN),
        ReconcileVerdict::Mismatch => (Some(FAIL), TAG_MISMATCH),
        // Both legs executed and bound to the intent. Only a clean gate (Custos
        // malice screen within policy) is a real pass; otherwise the action was
        // atomic but unsafe.
        ReconcileVerdict::Matched => {
            if signed.binding.decision.is_settle() {
                (Some(PASS), TAG_MATCHED)
            } else {
                (Some(FAIL), TAG_UNSAFE)
            }
        }
    };
    ValidationResponse { response, tag: tag.to_string(), response_hash }
}

/// The off-chain evidence bundle a validator pins at `responseURI`: the full
/// signed decision. A relying party fetches this, recomputes
/// `binding.digest()`, checks it equals the on-chain `responseHash`, and
/// verifies the signature — end-to-end tamper-evident.
pub fn evidence_bundle_json(signed: &SignedDecision) -> String {
    serde_json::to_string(signed).expect("SignedDecision is serializable")
}

/// Why a relying-party bundle check failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BundleError {
    /// The bundle JSON did not parse into a `SignedDecision`.
    Malformed,
    /// The bundle's `binding.digest()` did not equal the on-chain `responseHash`
    /// — the evidence does not correspond to the on-chain response.
    HashMismatch,
    /// The signature / trusted-signer check failed.
    Verify(VerifyError),
}

/// The relying-party check (DoD: "fetch responseURI, recompute the hash, verify
/// it equals the on-chain responseHash, check the signature"). Pure: this is the
/// exact routine an on-chain consumer or an off-chain risk desk runs to trust our
/// validation response without re-executing anything themselves.
///
/// On success returns the [`ValidationResponse`] re-derived from the bundle, so
/// the caller can also confirm the on-chain `response`/`tag` match what the
/// evidence implies.
pub fn verify_bundle(
    bundle_json: &str,
    onchain_response_hash: &str,
    trusted_signer: &str,
) -> Result<ValidationResponse, BundleError> {
    let signed: SignedDecision =
        serde_json::from_str(bundle_json).map_err(|_| BundleError::Malformed)?;
    // 1. The evidence must be the evidence the on-chain response committed to.
    let recomputed = hex::encode(signed.binding.digest());
    if !recomputed.eq_ignore_ascii_case(onchain_response_hash) {
        return Err(BundleError::HashMismatch);
    }
    // 2. The bundle must be signed by the trusted validator key.
    verify_decision(&signed, trusted_signer).map_err(BundleError::Verify)?;
    Ok(validation_response(&signed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attest::{sign_decision, DecisionBinding};
    use crate::decide::{GatePolicy, LiquetDecision};
    use crate::seam::{
        CrossVmProof, FactsSource, Finding, InvariantVerdict, ReexecProof, Severity, Vm,
    };
    use ed25519_dalek::SigningKey;

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

    /// The SAME proof the `attest.rs` golden vector is built from, so the
    /// `response_hash` here is locked to that already-frozen encoding.
    fn proof(reconcile: ReconcileVerdict) -> CrossVmProof {
        CrossVmProof {
            reconcile,
            reasons: vec![],
            legs: vec![leg(Vm::Evm, "evm-dig"), leg(Vm::Svm, "svm-dig")],
            claim_hash: "claim-abc".into(),
            settlement_id: "settlement-1".into(),
        }
    }

    fn operator() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn signed(
        reconcile: ReconcileVerdict,
        invariant: InvariantVerdict,
        decision: LiquetDecision,
    ) -> SignedDecision {
        let binding =
            DecisionBinding::new(&proof(reconcile), &invariant, &GatePolicy::default(), &decision);
        sign_decision(binding, &operator())
    }

    fn matched_settle() -> SignedDecision {
        signed(
            ReconcileVerdict::Matched,
            InvariantVerdict::green(),
            LiquetDecision::Settle { caveats: vec![] },
        )
    }

    #[test]
    fn matched_settle_is_pass_matched() {
        let r = validation_response(&matched_settle());
        assert_eq!(r.response, Some(PASS));
        assert_eq!(r.tag, TAG_MATCHED);
        assert!(r.is_published());
    }

    #[test]
    fn half_open_is_fail_and_published() {
        let r = validation_response(&signed(
            ReconcileVerdict::HalfOpen,
            InvariantVerdict::green(),
            LiquetDecision::Hold { reasons: vec!["half-open".into()] },
        ));
        assert_eq!(r.response, Some(FAIL));
        assert_eq!(r.tag, TAG_HALF_OPEN);
    }

    #[test]
    fn mismatch_is_fail() {
        let r = validation_response(&signed(
            ReconcileVerdict::Mismatch,
            InvariantVerdict::green(),
            LiquetDecision::Hold { reasons: vec!["mismatch".into()] },
        ));
        assert_eq!(r.response, Some(FAIL));
        assert_eq!(r.tag, TAG_MISMATCH);
    }

    #[test]
    fn matched_but_held_on_invariant_is_fail_unsafe_not_matched() {
        // reconcile Matched (atomic) but the malice screen tripped → the action
        // is NOT a pass. This is the precision fix over the §3 table.
        let malicious = InvariantVerdict {
            level: Severity::Red,
            findings: vec![Finding {
                severity: Severity::Red,
                code: "F2-delegate".into(),
                account: None,
                message: "unlimited delegate on delivery leg".into(),
            }],
        };
        let r = validation_response(&signed(
            ReconcileVerdict::Matched,
            malicious,
            LiquetDecision::Hold { reasons: vec!["[F2-delegate] ...".into()] },
        ));
        assert_eq!(r.response, Some(FAIL));
        assert_eq!(r.tag, TAG_UNSAFE);
    }

    #[test]
    fn unverifiable_abstains() {
        let r = validation_response(&signed(
            ReconcileVerdict::Unverifiable,
            InvariantVerdict::green(),
            LiquetDecision::Hold { reasons: vec!["unverifiable".into()] },
        ));
        assert_eq!(r.response, None);
        assert_eq!(r.tag, TAG_UNVERIFIABLE);
        assert!(!r.is_published(), "unverifiable must not be posted on-chain");
    }

    #[test]
    fn response_hash_equals_attest_golden_vector() {
        // Ties the ERC-8004 responseHash to the frozen `attest.rs` encoding: the
        // matched/settle signed decision built from the golden proof MUST hash to
        // the same value locked in attest.rs::digest_is_stable_golden_vector.
        let r = validation_response(&matched_settle());
        assert_eq!(
            r.response_hash,
            "dd2c88522195119e465419b67cdaaf0257d42d1d0526653c3be4d3e47c9995b4"
        );
    }

    #[test]
    fn verify_bundle_roundtrips_for_trusted_signer() {
        let s = matched_settle();
        let bundle = evidence_bundle_json(&s);
        let onchain_hash = hex::encode(s.binding.digest());
        let signer = s.signer.clone();

        let r = verify_bundle(&bundle, &onchain_hash, &signer).expect("valid bundle");
        assert_eq!(r.response, Some(PASS));
        assert_eq!(r.tag, TAG_MATCHED);
        assert_eq!(r.response_hash, onchain_hash);
    }

    #[test]
    fn verify_bundle_rejects_wrong_onchain_hash() {
        let s = matched_settle();
        let bundle = evidence_bundle_json(&s);
        let signer = s.signer.clone();
        let wrong = "00".repeat(32);
        assert_eq!(
            verify_bundle(&bundle, &wrong, &signer),
            Err(BundleError::HashMismatch)
        );
    }

    #[test]
    fn verify_bundle_rejects_untrusted_signer() {
        let s = matched_settle();
        let bundle = evidence_bundle_json(&s);
        let onchain_hash = hex::encode(s.binding.digest());
        let attacker_pk =
            hex::encode(SigningKey::from_bytes(&[9u8; 32]).verifying_key().to_bytes());
        assert_eq!(
            verify_bundle(&bundle, &onchain_hash, &attacker_pk),
            Err(BundleError::Verify(VerifyError::SignerMismatch))
        );
    }

    #[test]
    fn verify_bundle_rejects_tampered_evidence() {
        // Flip the decision in the bundle but keep the original on-chain hash:
        // the recomputed digest no longer matches → HashMismatch (caught before
        // the signature check even runs).
        let s = matched_settle();
        let onchain_hash = hex::encode(s.binding.digest());
        let signer = s.signer.clone();
        let mut tampered = s.clone();
        tampered.binding.decision = LiquetDecision::Hold { reasons: vec!["forged".into()] };
        let bundle = evidence_bundle_json(&tampered);
        assert_eq!(
            verify_bundle(&bundle, &onchain_hash, &signer),
            Err(BundleError::HashMismatch)
        );
    }

    #[test]
    fn verify_bundle_rejects_malformed_json() {
        assert_eq!(
            verify_bundle("{not json", "00", "00"),
            Err(BundleError::Malformed)
        );
    }
}
