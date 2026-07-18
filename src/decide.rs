//! The gate. An intent + two seam slots in, one settle/hold decision out. Pure —
//! no I/O, no producer types. This is the only place the "does money move?"
//! policy lives, and it never changes when a primitive is added or swapped.

use crate::seam::{FactsSource, InvariantVerdict, ReexecProof, Severity, SettlementIntent};
use serde::{Deserialize, Serialize};

/// Policy that turns the intent + two slots into a settle/hold decision.
#[derive(Clone, Copy, Debug)]
pub struct GatePolicy {
    /// Highest invariant severity still allowed to settle. Default: `Info`
    /// (Green/Info settle; Yellow/Red hold).
    pub max_settle_severity: Severity,
    /// Require the re-exec proof to show the leg executed.
    pub require_executed: bool,
    /// Require the proof to carry PRODUCER-RECOVERED transfer facts that match
    /// the intent. Phase 1 (Custos-only) has no recovering producer, so the
    /// default is `false`: caller-asserted facts settle with a caveat rather
    /// than a hold. Flip to `true` once a recovering producer (probatio) fills
    /// Slot 1 and value-binding becomes trustworthy.
    pub require_recovered_facts: bool,
}

impl Default for GatePolicy {
    fn default() -> Self {
        Self {
            max_settle_severity: Severity::Info,
            require_executed: true,
            require_recovered_facts: false,
        }
    }
}

/// The gate output: does money move? `Hold` carries *every* reason so the
/// caller (a solver, its LP/risk desk) sees exactly why funds were withheld.
/// `Settle` carries `caveats` — checks that could NOT be performed (empty means
/// a fully-bound settle); this keeps the decision honest about its own limits.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "lowercase")]
pub enum LiquetDecision {
    Settle {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        caveats: Vec<String>,
    },
    Hold {
        reasons: Vec<String>,
    },
}

impl LiquetDecision {
    pub fn is_settle(&self) -> bool {
        matches!(self, LiquetDecision::Settle { .. })
    }
}

/// Bind a re-exec proof and an invariant verdict to what the solver `intent`ed,
/// under `policy`.
pub fn decide(
    intent: &SettlementIntent,
    proof: &ReexecProof,
    verdict: &InvariantVerdict,
    policy: &GatePolicy,
) -> LiquetDecision {
    let mut reasons = Vec::new();
    let mut caveats = Vec::new();

    // --- re-exec proof ---
    if let Some(why) = &proof.unverifiable_reason {
        reasons.push(format!("re-exec unverifiable: {why}"));
    }
    if policy.require_executed && !proof.executed {
        reasons.push("re-exec proof shows the leg did not execute".to_string());
    }

    // --- invariants ---
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

    // --- coverage: the producer must have had every intent-required account in scope ---
    for acct in &intent.required_accounts {
        if !proof.covered_accounts.iter().any(|c| c == acct) {
            reasons.push(format!(
                "required account {acct} was not in the producer's scope (coverage gap)"
            ));
        }
    }

    // --- intent binding ---
    match proof.facts_source {
        FactsSource::ProducerRecovered => {
            if proof.vm != intent.vm {
                reasons.push(format!(
                    "executed vm {:?} does not match intent vm {:?}",
                    proof.vm, intent.vm
                ));
            }
            bind(&mut reasons, "asset", proof.asset.as_deref(), &intent.asset);
            bind(
                &mut reasons,
                "amount",
                proof.amount.map(|a| a.to_string()).as_deref(),
                &intent.amount.to_string(),
            );
            bind(
                &mut reasons,
                "recipient",
                proof.recipient.as_deref(),
                &intent.recipient,
            );
        }
        FactsSource::CallerAsserted => {
            let note = "intent-binding unverified: producer could not recover transfer facts \
                        (Phase 1, Custos-only)"
                .to_string();
            if policy.require_recovered_facts {
                reasons.push(note);
            } else {
                caveats.push(note);
            }
        }
    }

    if reasons.is_empty() {
        LiquetDecision::Settle { caveats }
    } else {
        LiquetDecision::Hold { reasons }
    }
}

/// Bind one producer-recovered fact against the intent. A missing fact is a
/// hold (a producer that claims to recover facts must supply them).
fn bind(reasons: &mut Vec<String>, field: &str, observed: Option<&str>, intended: &str) {
    match observed {
        Some(v) if v != intended => {
            reasons.push(format!("executed {field} {v} does not match intent {intended}"))
        }
        None => reasons.push(format!(
            "producer-recovered proof is missing {field} required for binding"
        )),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seam::{Finding, Vm};

    fn intent() -> SettlementIntent {
        SettlementIntent {
            vm: Vm::Svm,
            asset: "USDC".into(),
            amount: 1_000_000,
            recipient: "Rcpt111".into(),
            required_accounts: vec!["Acct1".into(), "Acct2".into()],
        }
    }

    fn caller_asserted_proof() -> ReexecProof {
        ReexecProof {
            vm: Vm::Svm,
            executed: true,
            poststate_digest: "deadbeef".into(),
            covered_accounts: vec!["Acct1".into(), "Acct2".into(), "Acct3".into()],
            facts_source: FactsSource::CallerAsserted,
            asset: None,
            amount: None,
            recipient: None,
            unverifiable_reason: None,
        }
    }

    fn recovered_proof() -> ReexecProof {
        ReexecProof {
            facts_source: FactsSource::ProducerRecovered,
            asset: Some("USDC".into()),
            amount: Some(1_000_000),
            recipient: Some("Rcpt111".into()),
            ..caller_asserted_proof()
        }
    }

    #[test]
    fn benign_settles_with_binding_caveat_under_custos() {
        let d = decide(
            &intent(),
            &caller_asserted_proof(),
            &InvariantVerdict::green(),
            &GatePolicy::default(),
        );
        match d {
            LiquetDecision::Settle { caveats } => {
                assert!(caveats.iter().any(|c| c.contains("intent-binding unverified")))
            }
            _ => panic!("expected Settle with caveat"),
        }
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
        let d = decide(&intent(), &caller_asserted_proof(), &verdict, &GatePolicy::default());
        match d {
            LiquetDecision::Hold { reasons } => {
                assert!(reasons.iter().any(|r| r.contains("F1-drain")))
            }
            _ => panic!("expected Hold"),
        }
    }

    #[test]
    fn unexecuted_leg_holds() {
        let mut p = caller_asserted_proof();
        p.executed = false;
        let d = decide(&intent(), &p, &InvariantVerdict::green(), &GatePolicy::default());
        assert!(!d.is_settle());
    }

    #[test]
    fn coverage_gap_holds() {
        let mut p = caller_asserted_proof();
        p.covered_accounts = vec!["Acct1".into()]; // missing Acct2
        let d = decide(&intent(), &p, &InvariantVerdict::green(), &GatePolicy::default());
        match d {
            LiquetDecision::Hold { reasons } => {
                assert!(reasons.iter().any(|r| r.contains("Acct2") && r.contains("coverage gap")))
            }
            _ => panic!("expected Hold on coverage gap"),
        }
    }

    #[test]
    fn producer_recovered_match_settles_without_caveat() {
        let d = decide(
            &intent(),
            &recovered_proof(),
            &InvariantVerdict::green(),
            &GatePolicy::default(),
        );
        assert_eq!(d, LiquetDecision::Settle { caveats: vec![] });
    }

    #[test]
    fn producer_recovered_recipient_mismatch_holds() {
        let mut p = recovered_proof();
        p.recipient = Some("Attacker999".into());
        let d = decide(&intent(), &p, &InvariantVerdict::green(), &GatePolicy::default());
        match d {
            LiquetDecision::Hold { reasons } => {
                assert!(reasons.iter().any(|r| r.contains("recipient") && r.contains("does not match")))
            }
            _ => panic!("expected Hold on recipient mismatch"),
        }
    }

    #[test]
    fn require_recovered_facts_turns_caveat_into_hold() {
        let policy = GatePolicy { require_recovered_facts: true, ..GatePolicy::default() };
        let d = decide(&intent(), &caller_asserted_proof(), &InvariantVerdict::green(), &policy);
        assert!(!d.is_settle());
    }

    #[test]
    fn yellow_holds_but_info_settles_under_default_policy() {
        let info = InvariantVerdict { level: Severity::Info, findings: vec![] };
        assert!(decide(&intent(), &caller_asserted_proof(), &info, &GatePolicy::default()).is_settle());

        let yellow = InvariantVerdict {
            level: Severity::Yellow,
            findings: vec![Finding {
                severity: Severity::Yellow,
                code: "F5-unknown-program".into(),
                account: None,
                message: "invoked program not on allowlist".into(),
            }],
        };
        assert!(!decide(&intent(), &caller_asserted_proof(), &yellow, &GatePolicy::default()).is_settle());
    }
}
