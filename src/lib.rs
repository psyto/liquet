//! Liquet — the neutral re-execution + invariant gate for cross-VM settlement.
//!
//! Liquet does not issue money and is not a chain. It consumes the outputs of
//! independent verification primitives (Custos, probatio-xvm, intentio) through
//! one stable SEAM contract and answers a single question before funds move:
//! *did this settlement execute as specified, and is it safe to release?*
//!
//! # Phase 1 (this slice)
//! SVM-only, single leg, driven entirely by `custos-engine` — which both
//! re-executes a transaction in LiteSVM (giving us the poststate) and evaluates
//! invariants F1–F5 (giving us the verdict). Probatio (SVM/cross-VM re-exec
//! witness) and intentio (EVM leg) dock later, behind the same seam, when a
//! flow actually needs them. See `SEAM.md`.
//!
//! # Shape
//! - [`seam`]   — the contract every folded primitive targets. Stable.
//! - [`decide`] — pure gate logic: two slots -> settle / hold.
//! - [`adapters`] — one adapter per primitive; add/remove without touching core.

pub mod adapters;
pub mod attest;
pub mod decide;
pub mod seam;

pub use attest::{sign_decision, verify_decision, DecisionBinding, SignedDecision, VerifyError};
pub use decide::{decide, decide_crossvm, GatePolicy, LiquetDecision};
pub use seam::{
    CrossVmProof, FactsSource, Finding, InvariantVerdict, ReconcileVerdict, ReexecProof, Severity,
    SettlementIntent, Vm,
};
