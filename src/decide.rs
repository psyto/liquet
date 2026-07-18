//! The gate. Two seam slots in, one settle/hold decision out. Pure — no I/O,
//! no producer types. This is the only place the "does money move?" policy
//! lives, and it never changes when a primitive is added or swapped.

use crate::seam::{InvariantVerdict, ReexecProof, Severity};
use serde::{Deserialize, Serialize};

/// Policy that turns the two slots into a settle/hold decision.
#[derive(Clone, Copy, Debug)]
pub struct GatePolicy {
    /// Highest invariant severity still allowed to settle. Default: `Info`
    /// (Green/Info settle; Yellow/Red hold).
    pub max_settle_severity: Severity,
    /// Require the re-exec proof to show the leg executed.
    pub require_executed: bool,
}

impl Default for GatePolicy {
    fn default() -> Self {
        Self { max_settle_severity: Severity::Info, require_executed: true }
    }
}

/// The gate output: does money move? `Hold` carries *every* reason so the
/// caller (a solver, its LP/risk desk) sees exactly why funds were withheld.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "lowercase")]
pub enum LiquetDecision {
    /// Both slots passed — safe to release funds.
    Settle,
    /// Blocked before any money moved.
    Hold { reasons: Vec<String> },
}

impl LiquetDecision {
    pub fn is_settle(&self) -> bool {
        matches!(self, LiquetDecision::Settle)
    }
}

/// Combine a re-exec proof and an invariant verdict under `policy`.
pub fn decide(
    proof: &ReexecProof,
    verdict: &InvariantVerdict,
    policy: &GatePolicy,
) -> LiquetDecision {
    let mut reasons = Vec::new();

    if let Some(why) = &proof.unverifiable_reason {
        reasons.push(format!("re-exec unverifiable: {why}"));
    }
    if policy.require_executed && !proof.executed {
        reasons.push("re-exec proof shows the leg did not execute".to_string());
    }
    if verdict.level > policy.max_settle_severity {
        let offending: Vec<_> = verdict
            .findings
            .iter()
            .filter(|f| f.severity > policy.max_settle_severity)
            .map(|f| format!("[{}] {}", f.code, f.message))
            .collect();
        if offending.is_empty() {
            reasons.push(format!(
                "invariant level {:?} exceeds settle threshold {:?}",
                verdict.level, policy.max_settle_severity
            ));
        } else {
            reasons.extend(offending);
        }
    }

    if reasons.is_empty() {
        LiquetDecision::Settle
    } else {
        LiquetDecision::Hold { reasons }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seam::{Finding, Vm};

    fn ok_proof() -> ReexecProof {
        ReexecProof {
            vm: Vm::Svm,
            executed: true,
            poststate_digest: "deadbeef".into(),
            asset: Some("USDC".into()),
            amount: Some(1_000_000),
            recipient: Some("Rcpt111".into()),
            unverifiable_reason: None,
        }
    }

    #[test]
    fn benign_settlement_settles() {
        let d = decide(&ok_proof(), &InvariantVerdict::green(), &GatePolicy::default());
        assert_eq!(d, LiquetDecision::Settle);
    }

    #[test]
    fn drain_finding_holds_with_reason() {
        let verdict = InvariantVerdict {
            level: Severity::Red,
            findings: vec![Finding {
                severity: Severity::Red,
                code: "F1-drain".into(),
                account: Some("Tok111".into()),
                message: "user token account fully drained".into(),
            }],
        };
        let d = decide(&ok_proof(), &verdict, &GatePolicy::default());
        match d {
            LiquetDecision::Hold { reasons } => {
                assert!(reasons.iter().any(|r| r.contains("F1-drain")));
            }
            _ => panic!("expected Hold"),
        }
    }

    #[test]
    fn unexecuted_leg_holds() {
        let mut p = ok_proof();
        p.executed = false;
        let d = decide(&p, &InvariantVerdict::green(), &GatePolicy::default());
        assert!(!d.is_settle());
    }

    #[test]
    fn unverifiable_proof_holds_even_when_invariants_green() {
        let mut p = ok_proof();
        p.unverifiable_reason = Some("missing recipient ATA in prestate".into());
        let d = decide(&p, &InvariantVerdict::green(), &GatePolicy::default());
        assert!(!d.is_settle());
    }

    #[test]
    fn yellow_holds_but_info_settles_under_default_policy() {
        let info = InvariantVerdict { level: Severity::Info, findings: vec![] };
        assert!(decide(&ok_proof(), &info, &GatePolicy::default()).is_settle());

        let yellow = InvariantVerdict {
            level: Severity::Yellow,
            findings: vec![Finding {
                severity: Severity::Yellow,
                code: "F5-unknown-program".into(),
                account: None,
                message: "invoked program not on allowlist".into(),
            }],
        };
        assert!(!decide(&ok_proof(), &yellow, &GatePolicy::default()).is_settle());
    }
}
