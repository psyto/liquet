//! Cross-VM producer adapter: probatio-xvm fills Slot 1.
//!
//! probatio-xvm re-executes the EVM leg (in-process revm) and the SVM leg
//! (LiteSVM), recovers each leg's facts, and reconciles them against the claim.
//! We map its `XvmReceipt` + the two `ReconstructedLeg`s onto the seam's
//! [`CrossVmProof`]. Facts are producer-recovered, so a `Matched` reconcile is
//! real value-binding — no caveat. Slot 1 (probatio) and Slot 2 (Custos) are now
//! DIFFERENT producers, so there is no common-mode blind spot.
//!
//! Target API (from /Users/hiroyusai/src/probatio/probatio-xvm, re-exported at
//! src/lib.rs:9-17 — verify names against the crate):
//!   probatio_xvm::reconstruct_evm_leg(&EvmPaySpec)    -> Result<EvmReconstruction, String>  (.leg)
//!   probatio_xvm::reconstruct_svm_leg(&SvmTransferSpec)-> Result<SvmReconstruction, String>  (.leg)
//!   probatio_xvm::reconcile(&ReconstructedLeg, &ReconstructedLeg, &Claim) -> XvmReceipt
//!   XvmVerdict { Matched, HalfOpen, Mismatch, Unverifiable }
//!   XvmReceipt { verdict, reasons, evm_reexec_digest, svm_reexec_digest, claim_hash, settlement_id }
//!   ReconstructedLeg { vm: Vm{Evm,Svm}, executed, reexec_digest, asset, amount,
//!                      recipient, unverifiable_reason, .. }

use crate::seam::{CrossVmProof, FactsSource, ReconcileVerdict, ReexecProof, Vm};
use probatio_xvm::{ReconstructedLeg, Vm as PVm, XvmReceipt, XvmVerdict};

/// probatio-xvm `XvmVerdict` -> seam [`ReconcileVerdict`].
pub fn reconcile_verdict(v: &XvmVerdict) -> ReconcileVerdict {
    match v {
        XvmVerdict::Matched => ReconcileVerdict::Matched,
        XvmVerdict::HalfOpen => ReconcileVerdict::HalfOpen,
        XvmVerdict::Mismatch => ReconcileVerdict::Mismatch,
        XvmVerdict::Unverifiable => ReconcileVerdict::Unverifiable,
    }
}

/// A single `ReconstructedLeg` -> seam [`ReexecProof`] (producer-recovered facts).
pub fn proof_from_leg(leg: &ReconstructedLeg) -> ReexecProof {
    ReexecProof {
        vm: if matches!(leg.vm, PVm::Evm) { Vm::Evm } else { Vm::Svm },
        executed: leg.executed,
        poststate_digest: leg.reexec_digest.clone(),
        // probatio legs bind via reexec_digest + recovered facts, not an account set.
        covered_accounts: Vec::new(),
        facts_source: FactsSource::ProducerRecovered,
        asset: leg.asset.clone(),
        amount: leg.amount,
        recipient: leg.recipient.clone(),
        unverifiable_reason: leg.unverifiable_reason.clone(),
    }
}

/// Full reconcile output -> seam [`CrossVmProof`].
pub fn crossvm_from_receipt(
    receipt: &XvmReceipt,
    evm_leg: &ReconstructedLeg,
    svm_leg: &ReconstructedLeg,
) -> CrossVmProof {
    CrossVmProof {
        reconcile: reconcile_verdict(&receipt.verdict),
        reasons: receipt.reasons.clone(),
        legs: vec![proof_from_leg(evm_leg), proof_from_leg(svm_leg)],
        claim_hash: receipt.claim_hash.clone(),
        settlement_id: receipt.settlement_id.clone(),
    }
}
