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
