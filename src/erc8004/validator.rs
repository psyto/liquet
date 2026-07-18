//! The validator brain — chain-agnostic orchestration of one ERC-8004 validation
//! request through Liquet to an on-chain action.
//!
//! This is the deterministic core of steps 3–4 in `STAGE_ERC8004_VALIDATOR.md`,
//! kept free of `alloy` and of the heavy producer crates (revm/solana) so it is
//! unit-testable in the default build. Two seams keep it pure:
//!
//! - [`SettlementValidator`] — "re-execute + reconcile + gate + sign this
//!   request." The real impl (behind `wire-xvm`) runs probatio-xvm + Custos +
//!   `decide_crossvm` + `attest`; a mock drives these tests.
//! - [`EvidenceStore`](super::store::EvidenceStore) — pins the evidence bundle.
//!
//! The concrete `alloy` client (watch `ValidationRequest` events → resolve
//! `requestURI` → build a [`ResolvedRequest`] → call [`handle_request`] → submit
//! the [`OnChainAction`]) is the one remaining I/O shell; it implements no policy,
//! only transport.

use super::store::EvidenceStore;
use super::validation_response;
use crate::attest::SignedDecision;

/// A `ValidationRequest` event resolved off-chain: its on-chain identity plus the
/// claim payload fetched from `requestURI`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedRequest {
    /// The on-chain `requestHash` (commitment to the claim). Echoed in the response.
    pub request_hash: String,
    /// The agent (Identity Registry NFT) whose action is being validated.
    pub agent_id: u64,
    /// The claim payload fetched from `requestURI`: the `(evm_tx, svm_tx, claim /
    /// AP2 Intent Mandate)` bundle, opaque to the orchestration — the concrete
    /// [`SettlementValidator`] parses and re-executes it.
    pub claim_json: String,
}

/// Re-execute + reconcile + gate + sign a resolved request. The concrete impl is
/// the wired Liquet pipeline; the orchestration only needs the signed decision.
pub trait SettlementValidator {
    fn validate(&self, request: &ResolvedRequest) -> Result<SignedDecision, ValidateError>;
}

/// Why a request could not be turned into an on-chain action.
#[derive(Debug)]
pub enum ValidateError {
    /// The claim could not be resolved / re-executed into a decision at all
    /// (distinct from a reconcile `Unverifiable`, which is a real, signed verdict
    /// that we deliberately abstain on).
    Unresolvable(String),
    /// Pinning the evidence bundle failed.
    Store(std::io::Error),
}

impl From<std::io::Error> for ValidateError {
    fn from(e: std::io::Error) -> Self {
        ValidateError::Store(e)
    }
}

/// What the on-chain client should do for a request. This is the whole output of
/// the policy layer; the `alloy` shell just executes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OnChainAction {
    /// Call `validationResponse(request_hash, response, response_uri,
    /// response_hash, tag)`.
    Respond {
        request_hash: String,
        response: u8,
        response_uri: String,
        response_hash: String,
        tag: String,
    },
    /// Post nothing (reconcile `Unverifiable`). Recorded off-chain only, so the
    /// registry's `averageResponse` is never polluted by "could not check".
    Abstain { request_hash: String, tag: String },
}

/// Drive one request: validate → map to the ERC-8004 response → (on a real
/// score) pin the evidence and emit a `Respond`, else `Abstain`. Deterministic
/// and side-effect-free except for the evidence `put`.
pub fn handle_request(
    req: &ResolvedRequest,
    validator: &impl SettlementValidator,
    store: &mut impl EvidenceStore,
) -> Result<OnChainAction, ValidateError> {
    let signed = validator.validate(req)?;
    let vr = validation_response(&signed);
    match vr.response {
        // Abstain BEFORE touching the store — nothing to pin, nothing to post.
        None => Ok(OnChainAction::Abstain { request_hash: req.request_hash.clone(), tag: vr.tag }),
        Some(response) => {
            let uri = store.put(&signed)?; // evidence must exist before we point at it
            Ok(OnChainAction::Respond {
                request_hash: req.request_hash.clone(),
                response,
                response_uri: uri.0,
                response_hash: vr.response_hash,
                tag: vr.tag,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attest::{sign_decision, DecisionBinding};
    use crate::decide::{GatePolicy, LiquetDecision};
    use crate::erc8004::store::MemStore;
    use crate::erc8004::{verify_bundle, FAIL, PASS, TAG_HALF_OPEN, TAG_MATCHED, TAG_UNVERIFIABLE};
    use crate::seam::{
        CrossVmProof, FactsSource, InvariantVerdict, ReconcileVerdict, ReexecProof, Vm,
    };
    use ed25519_dalek::SigningKey;

    fn signed_for(reconcile: ReconcileVerdict, decision: LiquetDecision) -> SignedDecision {
        let leg = |vm, d: &str| ReexecProof {
            vm,
            executed: true,
            poststate_digest: d.into(),
            covered_accounts: vec![],
            facts_source: FactsSource::ProducerRecovered,
            asset: None,
            amount: None,
            recipient: None,
            unverifiable_reason: None,
        };
        let proof = CrossVmProof {
            reconcile,
            reasons: vec![],
            legs: vec![leg(Vm::Evm, "evm-dig"), leg(Vm::Svm, "svm-dig")],
            claim_hash: "claim-abc".into(),
            settlement_id: "settlement-1".into(),
        };
        let binding =
            DecisionBinding::new(&proof, &InvariantVerdict::green(), &GatePolicy::default(), &decision);
        sign_decision(binding, &SigningKey::from_bytes(&[7u8; 32]))
    }

    /// A mock that returns a preset signed decision (stands in for the wired
    /// probatio-xvm + Custos + decide + attest pipeline).
    struct MockValidator(SignedDecision);
    impl SettlementValidator for MockValidator {
        fn validate(&self, _req: &ResolvedRequest) -> Result<SignedDecision, ValidateError> {
            Ok(self.0.clone())
        }
    }

    struct FailingValidator;
    impl SettlementValidator for FailingValidator {
        fn validate(&self, _req: &ResolvedRequest) -> Result<SignedDecision, ValidateError> {
            Err(ValidateError::Unresolvable("missing prestate".into()))
        }
    }

    fn req() -> ResolvedRequest {
        ResolvedRequest {
            request_hash: "0xreq".into(),
            agent_id: 42,
            claim_json: "{}".into(),
        }
    }

    #[test]
    fn matched_settle_produces_verifiable_respond() {
        let signer;
        let onchain_hash;
        let action;
        {
            let signed = signed_for(ReconcileVerdict::Matched, LiquetDecision::Settle { caveats: vec![] });
            signer = signed.signer.clone();
            onchain_hash = hex::encode(signed.binding.digest());
            let mut store = MemStore::new();
            action = handle_request(&req(), &MockValidator(signed), &mut store).unwrap();

            // The Respond points at pinned evidence that a relying party can verify
            // using ONLY the on-chain fields (request_hash echoed, response_hash,
            // response_uri) + the trusted signer.
            match &action {
                OnChainAction::Respond {
                    request_hash,
                    response,
                    response_uri,
                    response_hash,
                    tag,
                } => {
                    assert_eq!(request_hash, "0xreq");
                    assert_eq!(*response, PASS);
                    assert_eq!(response_hash, &onchain_hash);
                    assert_eq!(tag, TAG_MATCHED);
                    let bundle = store.get(&super::super::store::ResponseUri(response_uri.clone())).unwrap();
                    let vr = verify_bundle(&bundle, response_hash, &signer).expect("verifies");
                    assert_eq!(vr.response, Some(PASS));
                }
                _ => panic!("expected Respond"),
            }
        }
        let _ = action;
    }

    #[test]
    fn half_open_responds_fail_and_pins_evidence() {
        let signed = signed_for(
            ReconcileVerdict::HalfOpen,
            LiquetDecision::Hold { reasons: vec!["half-open".into()] },
        );
        let mut store = MemStore::new();
        let action = handle_request(&req(), &MockValidator(signed), &mut store).unwrap();
        match action {
            OnChainAction::Respond { response, tag, .. } => {
                assert_eq!(response, FAIL);
                assert_eq!(tag, TAG_HALF_OPEN);
            }
            _ => panic!("expected Respond"),
        }
        assert_eq!(store.len(), 1, "failing verdicts still pin evidence");
    }

    #[test]
    fn unverifiable_abstains_and_pins_nothing() {
        let signed = signed_for(
            ReconcileVerdict::Unverifiable,
            LiquetDecision::Hold { reasons: vec!["unverifiable".into()] },
        );
        let mut store = MemStore::new();
        let action = handle_request(&req(), &MockValidator(signed), &mut store).unwrap();
        match action {
            OnChainAction::Abstain { request_hash, tag } => {
                assert_eq!(request_hash, "0xreq");
                assert_eq!(tag, TAG_UNVERIFIABLE);
            }
            _ => panic!("expected Abstain"),
        }
        assert!(store.is_empty(), "abstain must not pin evidence");
    }

    #[test]
    fn unresolvable_request_propagates_error() {
        let mut store = MemStore::new();
        let err = handle_request(&req(), &FailingValidator, &mut store).unwrap_err();
        assert!(matches!(err, ValidateError::Unresolvable(_)));
        assert!(store.is_empty());
    }
}
