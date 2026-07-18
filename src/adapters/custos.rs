//! Phase-1 adapter: Custos is the sole producer for BOTH seam slots.
//!
//! `custos-engine` simulates a tx in LiteSVM (giving us the re-execution /
//! poststate) and evaluates invariants F1–F5 (giving us the verdict). We map
//! its `Verdict` -> [`InvariantVerdict`] and its `Outcome` -> [`ReexecProof`].
//!
//! NOTE FOR THE CODEX CONVERGENCE PASS
//! -----------------------------------
//! The custos-engine paths, type names and field names below are transcribed
//! from exploration of `/Users/hiroyusai/src/custos` and MUST be verified
//! against the crate. Adjust imports/fields until
//! `cargo build --features wire-custos` is green. Target surface (from
//! `engine/src/lib.rs`, `engine/src/sim.rs`):
//!   custos_engine::Level   { Green, Info, Yellow, Red }        // lib.rs:109
//!   custos_engine::Finding { level, code:&'static str, account: Pubkey, message: String } // lib.rs:117
//!   custos_engine::Verdict { level: Level, findings: Vec<Finding> }                        // lib.rs:307
//!   custos_engine::evaluate(&Outcome, &Bank) -> Verdict        // lib.rs:323
//!   custos_engine::default_bank() -> Bank                      // lib.rs:313
//!   custos_engine::sim::capture(&mut LiteSVM, tx, user, watch, token_id, system_id) -> Outcome // sim.rs:28

use crate::seam::{FactsSource, Finding, InvariantVerdict, ReexecProof, Severity, Vm};
use sha2::{Digest, Sha256};

/// Map a custos severity level onto the seam's [`Severity`].
pub fn severity_from_level(level: custos_engine::Level) -> Severity {
    match level {
        custos_engine::Level::Green => Severity::Green,
        custos_engine::Level::Info => Severity::Info,
        custos_engine::Level::Yellow => Severity::Yellow,
        custos_engine::Level::Red => Severity::Red,
    }
}

/// SLOT 2: custos `Verdict` -> [`InvariantVerdict`].
pub fn verdict_from_custos(v: &custos_engine::Verdict) -> InvariantVerdict {
    InvariantVerdict {
        level: severity_from_level(v.level),
        findings: v
            .findings
            .iter()
            .map(|f| Finding {
                severity: severity_from_level(f.level),
                code: f.code.to_string(),
                account: Some(f.account.to_string()),
                message: f.message.clone(),
            })
            .collect(),
    }
}

/// SLOT 1: custos `Outcome` (LiteSVM pre/post snapshots) -> [`ReexecProof`].
///
/// `executed`         = the capture applied the tx without transaction error.
/// `poststate_digest` = SHA-256 over a *canonical* serialization of the post
///                      snapshots (deterministic account ordering).
/// transfer facts      = supplied by the caller from the settlement spec when
///                      known (the raw Outcome does not name asset/recipient).
///
pub fn proof_from_outcome(outcome: &custos_engine::Outcome) -> ReexecProof {
    let mut accounts: Vec<_> = outcome.post.iter().collect();
    accounts.sort_unstable_by_key(|(pubkey, _)| pubkey.to_bytes());
    let covered_accounts: Vec<String> =
        accounts.iter().map(|(pubkey, _)| pubkey.to_string()).collect();

    let mut hasher = Sha256::new();
    // Versioned domain separator plus fixed-width/length-prefixed fields make
    // the tuple encoding unambiguous. `None` records a watched account that
    // does not exist after execution, rather than silently omitting it.
    hasher.update(b"liquet/custos/poststate/v1");
    for (pubkey, snapshot) in accounts {
        hasher.update(pubkey.to_bytes());
        match snapshot {
            Some(snapshot) => {
                hasher.update([1]);
                hasher.update(snapshot.lamports.to_le_bytes());
                hasher.update(snapshot.owner.to_bytes());
                hasher.update((snapshot.data.len() as u64).to_le_bytes());
                hasher.update(&snapshot.data);
            }
            None => hasher.update([0]),
        }
    }

    ReexecProof {
        vm: Vm::Svm,
        executed: outcome.success,
        poststate_digest: format!("{:x}", hasher.finalize()),
        covered_accounts,
        // Custos re-executes but does NOT recover the settlement facts (asset /
        // amount / recipient) from the poststate, so they are caller-asserted
        // and untrusted for intent-binding until a recovering producer (probatio)
        // fills Slot 1. The gate surfaces this as a caveat, not silent trust.
        facts_source: FactsSource::CallerAsserted,
        asset: None,
        amount: None,
        recipient: None,
        unverifiable_reason: None,
    }
}
