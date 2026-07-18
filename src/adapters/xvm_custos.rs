//! Live Slot 2 for the cross-VM path: run Custos's malice screen against the
//! EXACT SVM delivery transaction probatio-xvm re-executed, on a byte-identical
//! prestate — so the invariant verdict is bound to *that* leg, not a lookalike.
//!
//! Requires probatio task 021 (widen `SvmReconstruction` to expose `transaction`,
//! `prestate`, `payer`, `payer_airdrop_lamports`, `watch`). Custos replays on a
//! bare `LiteSVM::new()` to use the SAME built-in SPL Token + Memo programs
//! probatio used (probatio loads no ELFs); injecting Custos's own `spl_token.so`
//! would diverge from probatio's execution.
//!
//! This replaces the demo's stubbed-green Slot 2 with a real, bound screen.

use crate::seam::InvariantVerdict;
use litesvm::LiteSVM;
use probatio_xvm::SvmReconstruction;

/// Run Custos over the delivery leg and return the invariant verdict, bound to
/// probatio's execution. `Err` if the replay diverges from the leg (i.e. Custos
/// did not reproduce the same execution — the screen would be meaningless).
pub fn invariant_from_svm_leg(recon: &SvmReconstruction) -> Result<InvariantVerdict, String> {
    let mut svm = LiteSVM::new();

    // Byte-identical prestate (probatio task 021 exposes these).
    for (addr, account) in &recon.prestate {
        svm.set_account(*addr, account.clone())
            .map_err(|e| format!("seed prestate {addr}: {e:?}"))?;
    }
    svm.airdrop(&recon.payer, recon.payer_airdrop_lamports)
        .map_err(|e| format!("airdrop payer: {e:?}"))?;

    // capture MUTATES svm — it runs the tx itself, snapshotting pre/post.
    // TODO(codex): reconcile Address vs Pubkey types across probatio (solana_address)
    // and custos (solana_pubkey) for `payer` and `watch`; convert if not identical.
    let outcome = custos_engine::sim::capture(
        &mut svm,
        recon.transaction.clone(),
        recon.payer,
        &recon.watch,
        custos_engine::spl_token_id(),
        custos_engine::system_id(),
    );

    // Binding: Custos must have reproduced probatio's execution. Cheap invariant —
    // both agree on whether the leg executed. (A deeper bind — matching the
    // delivered amount against `recon.leg.amount` — can be added once we decode the
    // recipient token account from `outcome.post`.)
    if outcome.success != recon.leg.executed {
        return Err(format!(
            "replay diverged from leg: custos success={}, probatio executed={}",
            outcome.success, recon.leg.executed
        ));
    }

    let verdict = custos_engine::evaluate(&outcome, &custos_engine::default_bank());
    Ok(super::custos::verdict_from_custos(&verdict))
}
