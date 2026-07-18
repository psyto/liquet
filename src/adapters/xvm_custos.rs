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
use solana_pubkey::Pubkey;

/// Run Custos over the delivery leg and return the invariant verdict, bound to
/// probatio's execution. `Err` if the replay diverges from the leg (i.e. Custos
/// did not reproduce the same execution — the screen would be meaningless).
pub fn invariant_from_svm_leg(recon: &SvmReconstruction) -> Result<InvariantVerdict, String> {
    let mut svm = LiteSVM::new();

    // Byte-identical prestate (probatio task 021 exposes these).
    for (addr, account) in &recon.prestate {
        svm.set_account(Pubkey::new_from_array(addr.to_bytes()), account.clone())
            .map_err(|e| format!("seed prestate {addr}: {e:?}"))?;
    }
    let payer = Pubkey::new_from_array(recon.payer.to_bytes());
    let watch: Vec<_> = recon
        .watch
        .iter()
        .map(|address| Pubkey::new_from_array(address.to_bytes()))
        .collect();
    svm.airdrop(&payer, recon.payer_airdrop_lamports)
        .map_err(|e| format!("airdrop payer: {e:?}"))?;

    // capture MUTATES svm — it runs the tx itself, snapshotting pre/post.
    let outcome = custos_engine::sim::capture(
        &mut svm,
        recon.transaction.clone(),
        payer,
        &watch,
        custos_engine::spl_token_id(),
        custos_engine::system_id(),
    );

    if !outcome.success {
        return Err("Custos replay transaction failed".to_string());
    }

    // A successful memo-only transaction is a valid replay of a half-open leg,
    // so bind the producer semantics through the captured recipient delta rather
    // than equating transaction success with `leg.executed`.
    let recipient = *watch
        .get(1)
        .ok_or_else(|| "probatio delivery leg exposed no recipient watch account".to_string())?;
    let amount = |snapshot: Option<&custos_engine::AccountSnapshot>, phase| {
        snapshot
            .and_then(custos_engine::TokenAccount::parse)
            .map(|account| account.amount)
            .ok_or_else(|| format!("Custos replay has no decodable recipient token account {phase}"))
    };
    let before = amount(outcome.pre.get(&recipient).and_then(Option::as_ref), "before")?;
    let after = amount(outcome.post.get(&recipient).and_then(Option::as_ref), "after")?;
    let delivered = after.saturating_sub(before);
    let expected = recon.leg.amount.unwrap_or(0);
    if delivered != expected || (delivered > 0) != recon.leg.executed {
        return Err(format!(
            "replay diverged from leg: Custos delivered={delivered}, Probatio delivered={expected}, Probatio executed={}",
            recon.leg.executed
        ));
    }

    let verdict = custos_engine::evaluate(&outcome, &custos_engine::default_bank());
    Ok(super::custos::verdict_from_custos(&verdict))
}
