//! The Liquet SEAM contract — the single source of truth every folded primitive
//! targets. Primitives keep evolving in their own repos/windows; they only have
//! to emit these shapes. Liquet consumes, never absorbs. Changing the set of
//! folded primitives means adding/removing an adapter — these types stay put.

use serde::{Deserialize, Serialize};

/// Which execution environment a settlement leg ran in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Vm {
    Svm,
    Evm,
}

/// How the transfer facts in a [`ReexecProof`] were obtained.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactsSource {
    /// The re-execution engine independently recovered these facts from the
    /// poststate. Trustworthy for binding the proof against an intent.
    ProducerRecovered,
    /// The caller asserted these facts; the producer could not recover them.
    /// NOT trustworthy for binding — the producer cannot vouch for them.
    CallerAsserted,
}

/// SLOT 1 — proof, from a re-execution engine.
///
/// A witness that a settlement leg *actually executed as specified*. The raw
/// poststate stays inside the producer; here we keep only a chain-agnostic
/// digest plus the observable settlement facts the gate needs.
///
/// Phase-1 producer: Custos `Outcome` (LiteSVM pre/post snapshots).
/// Later producers: `probatio_xvm::ReconstructedLeg`, `intentio_reexec::ExecResult`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReexecProof {
    pub vm: Vm,
    /// Did the leg execute to completion (vs revert / no-op)?
    pub executed: bool,
    /// SHA-256 (hex) over the canonical poststate the producer captured.
    pub poststate_digest: String,
    /// Accounts the producer had in scope (watched / touched). Lets the gate
    /// verify an intent's `required_accounts` were actually covered.
    #[serde(default)]
    pub covered_accounts: Vec<String>,
    /// Whether the transfer facts below were producer-recovered or caller-asserted.
    /// Only `ProducerRecovered` facts are trusted for intent-binding.
    pub facts_source: FactsSource,
    /// Observed transfer facts, when the producer could recover them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,
    /// Set when the producer could NOT verify the leg, with the reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unverifiable_reason: Option<String>,
}

/// What the solver asked to happen. The gate binds the [`ReexecProof`] to THIS.
///
/// Phase 1: an unauthenticated struct — the honesty it buys is coverage +
/// (when facts are producer-recovered) value-binding. Phase 2 carries a
/// signature / tx-hash / state-context commitment so the intent itself is
/// unforgeable and bound to the exact executed leg.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementIntent {
    pub vm: Vm,
    pub asset: String,
    pub amount: u64,
    pub recipient: String,
    /// Accounts the producer MUST have had in scope for the check to be valid.
    #[serde(default)]
    pub required_accounts: Vec<String>,
}

/// The cross-VM reconciliation verdict — did the legs of a chain-abstract
/// settlement collectively honor the intent? Mirrors probatio-xvm `XvmVerdict`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconcileVerdict {
    /// Every leg executed and all recovered facts agree with the intent/claim.
    Matched,
    /// Exactly one leg executed — a half-settled cross-VM position (the
    /// "in-flight" state a bridge leaves you praying about).
    HalfOpen,
    /// Legs executed but a recovered fact (amount, recipient, settlement id, …)
    /// disagrees with the intent, or neither leg executed.
    Mismatch,
    /// A leg could not be verified (wrong VM tag, missing witness).
    Unverifiable,
}

/// SLOT 1 (cross-VM form) — output of a cross-VM re-execution + reconcile
/// producer (probatio-xvm). Supersedes per-leg caller-asserted facts: the
/// reconcile checks EVERY leg's producer-recovered facts against the intent, so
/// a `Matched` verdict is real value-binding with no caveat.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossVmProof {
    pub reconcile: ReconcileVerdict,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
    /// Per-leg re-execution witnesses (facts producer-recovered).
    pub legs: Vec<ReexecProof>,
    pub claim_hash: String,
    pub settlement_id: String,
}

/// Ordered severity. Mirrors Custos `Level` (Green < Info < Yellow < Red).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Green,
    Info,
    Yellow,
    Red,
}

/// A single invariant hit, carried up from a producer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    /// Producer's invariant code, e.g. "F2-delegate".
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    pub message: String,
}

/// SLOT 2 — gate verdict, from an invariant engine.
///
/// Phase-1 producer: Custos `Verdict` (F1–F5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantVerdict {
    /// Worst severity across `findings` (Green if none).
    pub level: Severity,
    pub findings: Vec<Finding>,
}

impl InvariantVerdict {
    /// A clean, empty, passing verdict.
    pub fn green() -> Self {
        Self { level: Severity::Green, findings: Vec::new() }
    }
}
