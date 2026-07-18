//! Cross-VM intent-lifecycle demo — the "動くもの".
//!
//! Tells the story that separates Liquet from a bridge:
//!
//!   intent  : "payer pays X on EVM  →  recipient receives the good on Solana"
//!             (chain-abstract — the user never names a chain)
//!   solver  : executes an EVM pay-leg and an SVM delivery-leg
//!   Liquet  : re-executes BOTH legs (in-process revm + LiteSVM) and reconciles
//!             them against the intent, then gates:
//!
//!     Matched   -> SETTLE   proof the intent was honored on both chains
//!     Mismatch  -> HOLD     wrong recipient / amount / settlement-id caught
//!     HalfOpen  -> HOLD     only one leg settled — the "in-flight" state a
//!                           bridge leaves you praying about — caught before
//!                           any money is released
//!
//! Fully self-contained: no RPC, no server, no fixtures.
//! Run:  cargo run --features wire-probatio --bin liquet-xvm-demo
//!
//! ---------------------------------------------------------------------------
//! TODO(codex): this spec construction mirrors probatio-xvm's own integration
//! test `tests/xvm.rs` (helpers `real_evm_leg` / `real_svm_leg` / `claim`) and
//! its `examples/demo_receipts.rs`. Align the exact field values, enum variants
//! and the `Address` import with the real crate until
//! `cargo build --features wire-probatio` is green and this runs. If `Address`
//! is not re-exported by probatio_xvm, add `solana-address` to the wire-probatio
//! feature deps (that is the type of `SvmTransferSpec.recipient_owner` / `.mint`).
//! With `wire-xvm`, Custos independently replays Probatio's exact SVM
//! delivery-leg as the live Slot-2 malice screen. `wire-probatio` alone keeps
//! this demo usable with the green placeholder invariant.

use liquet::{
    adapters::probatio::crossvm_from_receipt, decide_crossvm, GatePolicy, ReconcileVerdict,
};
#[cfg(feature = "wire-xvm")]
use liquet::adapters::xvm_custos::invariant_from_svm_leg;
#[cfg(not(feature = "wire-xvm"))]
use liquet::InvariantVerdict;
use probatio_xvm::{
    reconcile, reconstruct_evm_leg, reconstruct_svm_leg, Claim, EvmPaySpec, GoodClaim, Mandate,
    MemoMode, SettlementBindingMode, SvmTransferSpec,
};
// TODO(codex): confirm the origin of `Address` (probatio re-export vs solana_address).
use solana_address::Address;

const SETTLEMENT_ID: &str = "settlement-1";
const AMOUNT: u64 = 25;
const EVM_PAYER: &str = "0x1000000000000000000000000000000000000001";
const EVM_SETTLEMENT: &str = "0x2000000000000000000000000000000000000002";

fn evm_spec(amount: u64) -> EvmPaySpec {
    EvmPaySpec {
        payer: EVM_PAYER.to_string(),
        settlement_contract: EVM_SETTLEMENT.to_string(),
        asset: "ETH".to_string(),
        amount,
        payer_start_balance_wei: 1_000,
        settlement_start_balance_wei: 0,
        recovered_settlement_id: Some(SETTLEMENT_ID.to_string()),
        settlement_binding_mode: SettlementBindingMode::Slot0,
    }
}

fn svm_spec(mint: Address, recipient: Address, amount: u64) -> SvmTransferSpec {
    SvmTransferSpec {
        source_owner_seed: [0x11; 32],
        recipient_owner: recipient,
        mint,
        amount,
        decimals: 0,
        source_start_amount: 1_000,
        recipient_start_amount: 0,
        recovered_settlement_id: Some(SETTLEMENT_ID.to_string()),
        memo_mode: MemoMode::SettlementOnly,
    }
}

fn claim(mint: Address, recipient: Address) -> Claim {
    Claim {
        payer: EVM_PAYER.to_string(),
        asset: "ETH".to_string(),
        amount: AMOUNT,
        good: GoodClaim {
            spl_mint: mint.to_string(),
            amount: AMOUNT,
            recipient: recipient.to_string(),
        },
        settlement_id: SETTLEMENT_ID.to_string(),
        mandate: Mandate { atomic: true },
    }
}

fn run(name: &str, gloss: &str, evm: EvmPaySpec, svm: SvmTransferSpec, claim: Claim) {
    let evm_leg = reconstruct_evm_leg(&evm).expect("evm leg");
    let svm_leg = reconstruct_svm_leg(&svm).expect("svm leg");
    let receipt = reconcile(&evm_leg.leg, &svm_leg.leg, &claim);
    let cross = crossvm_from_receipt(&receipt, &evm_leg.leg, &svm_leg.leg);

    #[cfg(feature = "wire-xvm")]
    let invariant = invariant_from_svm_leg(&svm_leg).expect("Custos replay of SVM delivery leg");
    #[cfg(not(feature = "wire-xvm"))]
    let invariant = InvariantVerdict::green();
    let decision = decide_crossvm(&cross, &invariant, &GatePolicy::default());

    println!("── {name}");
    println!("   reconcile : {:?}", cross.reconcile);
    #[cfg(feature = "wire-xvm")]
    println!("   custos    : {:?} (real replay)", invariant.level);
    println!("   decision  : {}", serde_json::to_string(&decision).expect("json"));
    println!("   {gloss}");
    println!();
}

fn main() {
    let mint = Address::new_unique();
    let recipient = Address::new_unique();
    let attacker = Address::new_unique();

    run(
        "benign atomic settlement",
        "intent honored on both chains → safe to release funds",
        evm_spec(AMOUNT),
        svm_spec(mint, recipient, AMOUNT),
        claim(mint, recipient),
    );

    run(
        "mis-delivery (wrong recipient)",
        "solver delivered to the wrong account → caught, funds held",
        evm_spec(AMOUNT),
        svm_spec(mint, attacker, AMOUNT), // delivered to attacker, claim expects recipient
        claim(mint, recipient),
    );

    run(
        "half-open (pay leg only, no delivery)",
        "EVM paid but Solana delivery never happened (the bridge nightmare) → held",
        evm_spec(AMOUNT),
        svm_spec(mint, recipient, 0), // amount 0 → not delivered → executed=false
        claim(mint, recipient),
    );

    // Sanity: assert the story holds so the demo is also a self-check.
    let ok = {
        let e = reconstruct_evm_leg(&evm_spec(AMOUNT)).unwrap();
        let s = reconstruct_svm_leg(&svm_spec(mint, recipient, AMOUNT)).unwrap();
        let r = reconcile(&e.leg, &s.leg, &claim(mint, recipient));
        crossvm_from_receipt(&r, &e.leg, &s.leg).reconcile == ReconcileVerdict::Matched
    };
    if !ok {
        eprintln!("WARNING: benign scenario did not reconcile as Matched — check spec construction");
        std::process::exit(1);
    }
}
