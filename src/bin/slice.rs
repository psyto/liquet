//! Phase-1 walking skeleton.
//!
//! Runs two SVM transactions through the full Liquet gate and prints the
//! decision for each:
//!   * a benign stablecoin transfer (a solver settling an intent leg) -> SETTLE
//!   * a hidden-approve / drainer transfer                            -> HOLD
//!
//! Both are driven entirely by `custos-engine` (no RPC, no EVM). This is the
//! demo that IS the pitch: "the settlement gets settled; the drainer gets held
//! before any money moves."
//!
//! Build/run:  cargo run --features wire-custos --bin liquet-slice
//!
//! TODO(codex): wire the two scenarios against custos-engine's local
//! (no-RPC) path. Target builders from `engine/src/loader.rs` /
//! `engine/src/scenarios.rs`:
//!   custos_engine::loader::build_benign_b64()        -> String (base64 tx)
//!   custos_engine::loader::build_hidden_approve_b64() -> String (base64 tx)
//! Prefer the programmatic `scenarios` path (builds LiteSVM + tx locally) so
//! the slice needs no network. For each scenario:
//!   1. build LiteSVM + tx (scenarios.rs)
//!   2. outcome = custos_engine::sim::capture(...)
//!   3. verdict = custos_engine::evaluate(&outcome, &custos_engine::default_bank())
//!   4. proof   = adapters::custos::proof_from_outcome(&outcome)  (fill transfer facts)
//!   5. iv      = adapters::custos::verdict_from_custos(&verdict)
//!   6. decision = liquet::decide(&proof, &iv, &GatePolicy::default())
//!   7. print scenario name + serde_json of `decision`

use liquet::{decide, GatePolicy};

fn main() {
    let policy = GatePolicy::default();
    let _ = &policy;

    // TODO(codex): replace with the two real custos-driven scenarios above.
    eprintln!(
        "liquet-slice: scaffold only. Wire the custos scenarios (see this file's \
         TODO and SEAM.md), then this prints SETTLE for the benign transfer and \
         HOLD for the drainer."
    );
    let _ = decide; // keep the gate entry point referenced
    std::process::exit(2);
}
