//! Step 5 — the real [`SettlementValidator`] impl: the wired Liquet pipeline.
//!
//! Behind `wire-xvm` (needs probatio-xvm + Custos). Parses a resolved request's
//! `(evm, svm, claim)` bundle, re-executes both legs (in-process revm + LiteSVM),
//! reconciles them (Slot 1), screens the SVM delivery leg for malice on its exact
//! execution (Slot 2, Custos), gates, and signs — returning the `SignedDecision`
//! the orchestration ([`super::validator::handle_request`]) maps to an ERC-8004
//! `validationResponse`.
//!
//! This is the whole point of the standard fit: a Matched-but-held (backdoored)
//! delivery lands as `FAIL`/`unsafe` — a *grounded* verdict where a Reputation
//! Registry star rating cannot see the malice at all.

use super::validator::{ResolvedRequest, SettlementValidator, ValidateError};
use crate::adapters::probatio::crossvm_from_receipt;
use crate::adapters::xvm_custos::invariant_from_svm_leg;
use crate::attest::{sign_decision, DecisionBinding, SignedDecision};
use crate::decide::{decide_crossvm, GatePolicy};
use ed25519_dalek::SigningKey;
use probatio_xvm::{
    reconcile, reconstruct_evm_leg, reconstruct_svm_leg_with_malice, Claim, EvmPaySpec, SvmMalice,
    SvmTransferSpec,
};
use serde::{Deserialize, Serialize};

/// The claim payload fetched from `requestURI` and parsed by the validator: the
/// agent's cross-VM action as an `(evm pay-leg, svm delivery-leg, intent)` bundle.
/// `malice` models an approve the agent's real delivery tx carried (default: none).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettlementRequest {
    pub evm: EvmPaySpec,
    pub svm: SvmTransferSpec,
    pub claim: Claim,
    #[serde(default = "no_malice")]
    pub malice: SvmMalice,
}

fn no_malice() -> SvmMalice {
    SvmMalice::None
}

/// The wired Liquet validator. Holds the operator signing key and the gate policy
/// the signed decision commits to.
pub struct LiquetValidator {
    signing_key: SigningKey,
    policy: GatePolicy,
}

impl LiquetValidator {
    pub fn new(signing_key: SigningKey, policy: GatePolicy) -> Self {
        Self { signing_key, policy }
    }

    /// Hex ed25519 public key a relying party pins as the trusted signer.
    pub fn signer_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }
}

impl SettlementValidator for LiquetValidator {
    fn validate(&self, request: &ResolvedRequest) -> Result<SignedDecision, ValidateError> {
        let sr: SettlementRequest = serde_json::from_str(&request.claim_json)
            .map_err(|e| ValidateError::Unresolvable(format!("parse claim_json: {e}")))?;

        // Slot 1 — re-execute both legs and reconcile against the intent.
        let evm = reconstruct_evm_leg(&sr.evm)
            .map_err(|e| ValidateError::Unresolvable(format!("evm leg: {e}")))?;
        let svm = reconstruct_svm_leg_with_malice(&sr.svm, &sr.malice)
            .map_err(|e| ValidateError::Unresolvable(format!("svm leg: {e}")))?;
        let receipt = reconcile(&evm.leg, &svm.leg, &sr.claim);
        let cross = crossvm_from_receipt(&receipt, &evm.leg, &svm.leg);

        // Slot 2 — Custos malice screen on the SVM leg's EXACT execution.
        let invariant = invariant_from_svm_leg(&svm)
            .map_err(|e| ValidateError::Unresolvable(format!("custos screen: {e}")))?;

        // Gate + sign. The binding is what the ERC-8004 `responseHash` commits to.
        let decision = decide_crossvm(&cross, &invariant, &self.policy);
        let binding = DecisionBinding::new(&cross, &invariant, &self.policy, &decision);
        Ok(sign_decision(binding, &self.signing_key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::erc8004::store::{EvidenceStore, MemStore};
    use crate::erc8004::validator::{handle_request, OnChainAction};
    use crate::erc8004::{verify_bundle, FAIL, PASS, TAG_HALF_OPEN, TAG_MATCHED, TAG_MISMATCH, TAG_UNSAFE};
    use solana_address::Address;

    const SETTLEMENT_ID: &str = "settlement-1";
    const AMOUNT: u64 = 25;
    const EVM_PAYER: &str = "0x1000000000000000000000000000000000000001";
    const EVM_SETTLEMENT: &str = "0x2000000000000000000000000000000000000002";

    fn evm_spec() -> EvmPaySpec {
        EvmPaySpec {
            payer: EVM_PAYER.to_string(),
            settlement_contract: EVM_SETTLEMENT.to_string(),
            asset: "ETH".to_string(),
            amount: AMOUNT,
            payer_start_balance_wei: 1_000,
            settlement_start_balance_wei: 0,
            recovered_settlement_id: Some(SETTLEMENT_ID.to_string()),
            settlement_binding_mode: probatio_xvm::SettlementBindingMode::Slot0,
        }
    }

    fn svm_spec(mint: Address, recipient: Address, amount: u64) -> SvmTransferSpec {
        SvmTransferSpec {
            source_owner_seed: [0x11; 32],
            recipient_owner: recipient,
            mint,
            amount,
            decimals: 0,
            source_start_amount: 1_000,
            recipient_start_amount: 0,
            recovered_settlement_id: Some(SETTLEMENT_ID.to_string()),
            memo_mode: probatio_xvm::MemoMode::SettlementOnly,
        }
    }

    fn claim(mint: Address, recipient: Address) -> Claim {
        Claim {
            payer: EVM_PAYER.to_string(),
            asset: "ETH".to_string(),
            amount: AMOUNT,
            good: probatio_xvm::GoodClaim {
                spl_mint: mint.to_string(),
                amount: AMOUNT,
                recipient: recipient.to_string(),
            },
            settlement_id: SETTLEMENT_ID.to_string(),
            mandate: probatio_xvm::Mandate { atomic: true },
        }
    }

    fn request_json(svm: SvmTransferSpec, claim: Claim, malice: SvmMalice) -> String {
        serde_json::to_string(&SettlementRequest { evm: evm_spec(), svm, claim, malice }).unwrap()
    }

    fn resolved(claim_json: String) -> ResolvedRequest {
        ResolvedRequest { request_hash: "0xreq".into(), agent_id: 7, claim_json }
    }

    fn validator() -> LiquetValidator {
        LiquetValidator::new(SigningKey::from_bytes(&[7u8; 32]), GatePolicy::default())
    }

    fn run(svm: SvmTransferSpec, claim: Claim, malice: SvmMalice) -> OnChainAction {
        let v = validator();
        let mut store = MemStore::new();
        handle_request(&resolved(request_json(svm, claim, malice)), &v, &mut store).unwrap()
    }

    #[test]
    fn benign_settlement_responds_pass_matched_with_verifiable_evidence() {
        let mint = Address::new_unique();
        let recipient = Address::new_unique();
        let v = validator();
        let signer = v.signer_hex();
        let mut store = MemStore::new();
        let action = handle_request(
            &resolved(request_json(svm_spec(mint, recipient, AMOUNT), claim(mint, recipient), SvmMalice::None)),
            &v,
            &mut store,
        )
        .unwrap();
        match action {
            OnChainAction::Respond { response, response_uri, response_hash, tag, .. } => {
                assert_eq!(response, PASS);
                assert_eq!(tag, TAG_MATCHED);
                let bundle = store.get(&crate::erc8004::store::ResponseUri(response_uri)).unwrap();
                let vr = verify_bundle(&bundle, &response_hash, &signer).expect("evidence verifies");
                assert_eq!(vr.response, Some(PASS));
            }
            _ => panic!("expected Respond"),
        }
    }

    #[test]
    fn mis_delivery_responds_fail_mismatch() {
        let mint = Address::new_unique();
        let recipient = Address::new_unique();
        let attacker = Address::new_unique();
        match run(svm_spec(mint, attacker, AMOUNT), claim(mint, recipient), SvmMalice::None) {
            OnChainAction::Respond { response, tag, .. } => {
                assert_eq!(response, FAIL);
                assert_eq!(tag, TAG_MISMATCH);
            }
            _ => panic!("expected Respond"),
        }
    }

    #[test]
    fn half_open_responds_fail_half_open() {
        let mint = Address::new_unique();
        let recipient = Address::new_unique();
        match run(svm_spec(mint, recipient, 0), claim(mint, recipient), SvmMalice::None) {
            OnChainAction::Respond { response, tag, .. } => {
                assert_eq!(response, FAIL);
                assert_eq!(tag, TAG_HALF_OPEN);
            }
            _ => panic!("expected Respond"),
        }
    }

    #[test]
    fn backdoored_delivery_responds_fail_unsafe() {
        // The crown case: reconcile Matched (tokens delivered correctly) but the
        // same tx grants an attacker an unlimited delegate → the malice screen
        // holds → FAIL/unsafe. Reputation stars cannot see this.
        let mint = Address::new_unique();
        let recipient = Address::new_unique();
        let attacker = Address::new_unique();
        match run(
            svm_spec(mint, recipient, AMOUNT),
            claim(mint, recipient),
            SvmMalice::ApproveUnlimited { delegate: attacker },
        ) {
            OnChainAction::Respond { response, tag, .. } => {
                assert_eq!(response, FAIL);
                assert_eq!(tag, TAG_UNSAFE);
            }
            _ => panic!("expected Respond"),
        }
    }
}
