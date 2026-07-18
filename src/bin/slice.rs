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
use base64::Engine as _;
use custos_engine::{default_bank, evaluate, sim, spl, spl_token_id, system_id};
use liquet::{
    adapters::custos::{proof_from_outcome, verdict_from_custos},
    decide, GatePolicy, SettlementIntent, Vm,
};
use litesvm::LiteSVM;
use solana_account::Account;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const INITIAL_USDC: u64 = 1_000_000_000;
const PAYMENT_USDC: u64 = 5_000_000;

struct Env {
    svm: LiteSVM,
    user: Keypair,
    attacker: Keypair,
    user_ata: Pubkey,
    token: Pubkey,
    usdc: Pubkey,
}

fn artifacts() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../custos/gate/artifacts")
}

fn token_account(account: Pubkey, mint: &Pubkey, owner: &Pubkey, amount: u64) -> Account {
    Account {
        lamports: 2_039_280,
        data: spl::token_account_bytes(mint, owner, amount),
        owner: account,
        executable: false,
        rent_epoch: u64::MAX,
    }
}

fn fresh_env() -> Env {
    let token = spl_token_id();
    let usdc: Pubkey = USDC.parse().expect("valid USDC mint");
    let mut svm = LiteSVM::new();
    let mint_json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(artifacts().join("usdc_mint.json")).expect("USDC mint fixture"),
    )
    .expect("valid USDC mint JSON");
    let mint_data = base64::engine::general_purpose::STANDARD
        .decode(
            mint_json["account"]["data"][0]
                .as_str()
                .expect("base64 mint data"),
        )
        .expect("decode USDC mint");
    svm.set_account(
        usdc,
        Account {
            lamports: 1_000_000,
            data: mint_data,
            owner: token,
            executable: false,
            rent_epoch: u64::MAX,
        },
    )
    .expect("install USDC mint");
    svm.add_program(
        token,
        &std::fs::read(artifacts().join("spl_token.so")).expect("SPL Token fixture"),
    )
    .expect("install SPL Token program");

    let user = Keypair::new();
    let attacker = Keypair::new();
    svm.airdrop(&user.pubkey(), 1_000_000_000)
        .expect("fund user");
    svm.airdrop(&attacker.pubkey(), 1_000_000_000)
        .expect("fund attacker");
    let user_ata = Keypair::new().pubkey();
    svm.set_account(
        user_ata,
        token_account(token, &usdc, &user.pubkey(), INITIAL_USDC),
    )
    .expect("install user token account");

    Env {
        svm,
        user,
        attacker,
        user_ata,
        token,
        usdc,
    }
}

fn print_decision(name: &str, outcome: custos_engine::Outcome, intent: SettlementIntent) {
    let verdict = evaluate(&outcome, &default_bank());
    let proof = proof_from_outcome(&outcome);
    let decision = decide(
        &intent,
        &proof,
        &verdict_from_custos(&verdict),
        &GatePolicy::default(),
    );
    println!(
        "{name} {}",
        serde_json::to_string(&decision).expect("serialize decision")
    );
}

fn main() {
    let mut benign = fresh_env();
    let merchant_ata = Keypair::new().pubkey();
    let merchant = Keypair::new().pubkey();
    benign
        .svm
        .set_account(
            merchant_ata,
            token_account(benign.token, &benign.usdc, &merchant, 0),
        )
        .expect("install merchant token account");
    let tx = Transaction::new_signed_with_payer(
        &[spl::transfer(
            benign.token,
            benign.user_ata,
            merchant_ata,
            benign.user.pubkey(),
            PAYMENT_USDC,
        )],
        Some(&benign.user.pubkey()),
        &[&benign.user],
        benign.svm.latest_blockhash(),
    );
    let outcome = sim::capture(
        &mut benign.svm,
        tx,
        benign.user.pubkey(),
        &[benign.user_ata, merchant_ata, benign.user.pubkey()],
        benign.token,
        system_id(),
    );
    print_decision(
        "benign-stablecoin-transfer",
        outcome,
        SettlementIntent {
            vm: Vm::Svm,
            asset: "USDC".to_string(),
            amount: PAYMENT_USDC,
            recipient: merchant.to_string(),
            required_accounts: vec![benign.user_ata.to_string(), merchant_ata.to_string()],
        },
    );

    let mut drainer = fresh_env();
    let intended_merchant = Keypair::new().pubkey();
    let tx = Transaction::new_signed_with_payer(
        &[spl::approve(
            drainer.token,
            drainer.user_ata,
            drainer.attacker.pubkey(),
            drainer.user.pubkey(),
            u64::MAX,
        )],
        Some(&drainer.user.pubkey()),
        &[&drainer.user],
        drainer.svm.latest_blockhash(),
    );
    let outcome = sim::capture(
        &mut drainer.svm,
        tx,
        drainer.user.pubkey(),
        &[drainer.user_ata, drainer.user.pubkey()],
        drainer.token,
        system_id(),
    );
    // The solver *intended* a benign USDC settlement; the submitted tx is an
    // unlimited approve to the attacker instead. F2 catches it before funds move.
    print_decision(
        "hidden-approve-drainer",
        outcome,
        SettlementIntent {
            vm: Vm::Svm,
            asset: "USDC".to_string(),
            amount: PAYMENT_USDC,
            recipient: intended_merchant.to_string(),
            required_accounts: vec![drainer.user_ata.to_string()],
        },
    );
}
