//! Live-cluster reference driver for `liquet-gate`.
//!
//! This is host-only code. It exercises a deployed reference release gate with
//! real native-Ed25519 verification and real classic SPL Token transfers. The
//! gate is not Liquet custody: it is a stand-in for a relying party's release
//! point. Swap `LIQUET_GATE_RPC_URL` (or the first CLI argument) to move from a
//! local validator to devnet.

use std::{env, path::PathBuf, thread, time::Duration};

use anyhow::{anyhow, bail, ensure, Context, Result};
use anchor_lang::{AccountDeserialize, InstructionData, ToAccountMetas};
use liquet_gate::authorization::{ReleaseAuthorization, DECISION_HOLD, DECISION_SETTLE, VERSION};
use solana_client::{
    rpc_client::RpcClient,
    rpc_config::RpcSendTransactionConfig,
};
use solana_sdk::{
    commitment_config::CommitmentConfig,
    ed25519_program,
    instruction::Instruction,
    program_pack::Pack,
    pubkey::Pubkey,
    signature::{read_keypair_file, Keypair, Signature, Signer},
    system_instruction, system_program, sysvar,
    transaction::Transaction,
};

const DEFAULT_RPC_URL: &str = "http://localhost:8899";
const DECIMALS: u8 = 6;
const ESCROW_START: u64 = 10_000_000;
const RELEASE_AMOUNT: u64 = 4_000_000;
const MIN_LOCAL_BALANCE: u64 = solana_sdk::native_token::LAMPORTS_PER_SOL;

#[derive(Clone, Copy)]
enum GateCase {
    Settle,
    /// A valid signer signs a `Settle` bound to a different recipient account.
    /// The gate must reject the submitted account mismatch before transfer.
    RecipientMismatch,
    Hold,
}

struct Scenario {
    name: &'static str,
    mode: GateCase,
}

const SCENARIOS: [Scenario; 4] = [
    Scenario { name: "01 benign atomic settlement", mode: GateCase::Settle },
    Scenario { name: "02 wrong recipient", mode: GateCase::RecipientMismatch },
    Scenario { name: "03 half-open (pay leg only)", mode: GateCase::Hold },
    Scenario { name: "04 backdoored delivery (F2-delegate)", mode: GateCase::Hold },
];

fn main() -> Result<()> {
    let rpc_url = env::args()
        .nth(1)
        .or_else(|| env::var("LIQUET_GATE_RPC_URL").ok())
        .unwrap_or_else(|| DEFAULT_RPC_URL.to_owned());
    let client = RpcClient::new_with_commitment(rpc_url.clone(), CommitmentConfig::confirmed());
    let is_local = rpc_url.contains("localhost") || rpc_url.contains("127.0.0.1");
    let is_devnet = rpc_url.contains("devnet");

    println!("Liquet Gate live reference driver");
    println!("RPC: {rpc_url}");
    if is_local {
        println!("cluster: local validator (automatic airdrops enabled when needed)");
    } else {
        println!("cluster: remote (payer/bootstrap keys must already be funded)");
    }

    let keys_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join(".keys");
    let payer = read_key(&keys_dir, "payer")?;
    let bootstrap = read_key(&keys_dir, "bootstrap")?;
    let verdict_signer = read_key(&keys_dir, "signer")?;
    let program = read_key(&keys_dir, "program")?;

    ensure!(program.pubkey() == liquet_gate::ID, "program key does not match declare_id!: expected {}, found {}", liquet_gate::ID, program.pubkey());
    ensure!(bootstrap.pubkey() == liquet_gate::BOOTSTRAP_AUTHORITY, "bootstrap key does not match BOOTSTRAP_AUTHORITY");
    let deployed = client.get_account(&liquet_gate::ID).context("gate program is not deployed at declare_id!")?;
    ensure!(deployed.executable, "gate program account is not executable");

    ensure_funded(&client, &payer, MIN_LOCAL_BALANCE, is_local)?;
    let (config, _) = config_pda();
    ensure_config(&client, &bootstrap, &verdict_signer, config, is_local)?;

    let mint = Keypair::new();
    let recipient_owner = Keypair::new();
    let (vault, _) = vault_pda(&config, &mint.pubkey());
    let escrow = ata(&vault, &mint.pubkey());
    let depositor_token = ata(&payer.pubkey(), &mint.pubkey());
    let recipient = ata(&recipient_owner.pubkey(), &mint.pubkey());

    create_mint_and_accounts(&client, &payer, &mint, &recipient_owner.pubkey(), &depositor_token, &recipient)?;
    mint_and_deposit(&client, &payer, config, vault, escrow, depositor_token, mint.pubkey())?;

    println!("\nReference gate setup complete");
    println!("mint:      {}", mint.pubkey());
    println!("vault PDA: {vault}");
    println!("escrow:    {escrow} ({})", token_amount(&client, escrow)?);
    println!("recipient: {recipient} ({})", token_amount(&client, recipient)?);

    for (index, scenario) in SCENARIOS.iter().enumerate() {
        run_scenario(
            &client,
            &rpc_url,
            is_devnet,
            &payer,
            &verdict_signer,
            scenario,
            index as u8,
            config,
            vault,
            escrow,
            recipient,
            mint.pubkey(),
        )?;
    }

    println!("\nPASS: real native Ed25519 + real SPL Token gate flow completed.");
    Ok(())
}

fn read_key(keys_dir: &PathBuf, name: &str) -> Result<Keypair> {
    let path = keys_dir.join(format!("{name}.json"));
    read_keypair_file(&path).map_err(|err| anyhow!("read key {}: {err}", path.display()))
}

fn ensure_funded(client: &RpcClient, key: &Keypair, minimum: u64, is_local: bool) -> Result<()> {
    let balance = client.get_balance(&key.pubkey())?;
    if balance >= minimum {
        return Ok(());
    }
    if !is_local {
        bail!("{} has {} lamports; fund it before running the remote driver", key.pubkey(), balance);
    }
    let signature = client.request_airdrop(&key.pubkey(), minimum.saturating_sub(balance) + MIN_LOCAL_BALANCE)?;
    ensure!(client.confirm_transaction(&signature)?, "local airdrop was not confirmed");
    Ok(())
}

fn ensure_config(
    client: &RpcClient,
    bootstrap: &Keypair,
    verdict_signer: &Keypair,
    config: Pubkey,
    is_local: bool,
) -> Result<()> {
    if let Some(account) = client.get_account_with_commitment(&config, CommitmentConfig::confirmed())?.value {
        let mut data: &[u8] = &account.data;
        let current = liquet_gate::GateConfig::try_deserialize(&mut data)?;
        ensure!(current.trusted_signer == verdict_signer.pubkey(), "existing config pins {}, not signer key {}", current.trusted_signer, verdict_signer.pubkey());
        ensure!(!current.paused, "existing gate config is paused");
        println!("using existing config: {config}");
        return Ok(());
    }

    ensure_funded(client, bootstrap, MIN_LOCAL_BALANCE / 10, is_local)?;
    let accounts = liquet_gate::accounts::Initialize {
        config,
        authority: bootstrap.pubkey(),
        system_program: system_program::ID,
    };
    let ix = Instruction {
        program_id: liquet_gate::ID,
        accounts: accounts.to_account_metas(None),
        data: liquet_gate::instruction::Initialize {
            trusted_signer: verdict_signer.pubkey(),
            pause_authority: bootstrap.pubkey(),
        }
        .data(),
    };
    let signature = submit_and_observe(client, &[ix], bootstrap, &[bootstrap])?;
    expect_success(&signature, "initialize")?;
    println!("initialized config: {config}");
    Ok(())
}

fn create_mint_and_accounts(
    client: &RpcClient,
    payer: &Keypair,
    mint: &Keypair,
    recipient_owner: &Pubkey,
    depositor_token: &Pubkey,
    recipient: &Pubkey,
) -> Result<()> {
    let mint_rent = client.get_minimum_balance_for_rent_exemption(spl_token::state::Mint::LEN)?;
    let create_mint = system_instruction::create_account(
        &payer.pubkey(),
        &mint.pubkey(),
        mint_rent,
        spl_token::state::Mint::LEN as u64,
        &spl_token::ID,
    );
    let init_mint = spl_token::instruction::initialize_mint2(
        &spl_token::ID,
        &mint.pubkey(),
        &payer.pubkey(),
        None,
        DECIMALS,
    )?;
    expect_success(&submit_and_observe(client, &[create_mint, init_mint], payer, &[payer, mint])?, "create mint")?;

    let create_depositor_ata = spl_associated_token_account::instruction::create_associated_token_account(
        &payer.pubkey(),
        &payer.pubkey(),
        &mint.pubkey(),
        &spl_token::ID,
    );
    let create_recipient_ata = spl_associated_token_account::instruction::create_associated_token_account(
        &payer.pubkey(),
        recipient_owner,
        &mint.pubkey(),
        &spl_token::ID,
    );
    expect_success(&submit_and_observe(client, &[create_depositor_ata, create_recipient_ata], payer, &[payer])?, "create token accounts")?;
    ensure!(*depositor_token == ata(&payer.pubkey(), &mint.pubkey()), "unexpected depositor ATA");
    ensure!(*recipient == ata(recipient_owner, &mint.pubkey()), "unexpected recipient ATA");
    Ok(())
}

fn mint_and_deposit(
    client: &RpcClient,
    payer: &Keypair,
    config: Pubkey,
    vault: Pubkey,
    escrow: Pubkey,
    depositor_token: Pubkey,
    mint: Pubkey,
) -> Result<()> {
    let mint_tokens = spl_token::instruction::mint_to_checked(
        &spl_token::ID,
        &mint,
        &depositor_token,
        &payer.pubkey(),
        &[],
        ESCROW_START,
        DECIMALS,
    )?;
    expect_success(&submit_and_observe(client, &[mint_tokens], payer, &[payer])?, "mint demo tokens")?;

    let accounts = liquet_gate::accounts::Deposit {
        config,
        vault,
        escrow_token: escrow,
        depositor_token,
        mint,
        depositor: payer.pubkey(),
        token_program: spl_token::ID,
        associated_token_program: spl_associated_token_account::ID,
        system_program: system_program::ID,
    };
    let ix = Instruction {
        program_id: liquet_gate::ID,
        accounts: accounts.to_account_metas(None),
        data: liquet_gate::instruction::Deposit { amount: ESCROW_START }.data(),
    };
    expect_success(&submit_and_observe(client, &[ix], payer, &[payer])?, "deposit escrow")?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_scenario(
    client: &RpcClient,
    rpc_url: &str,
    is_devnet: bool,
    payer: &Keypair,
    signer: &Keypair,
    scenario: &Scenario,
    index: u8,
    config: Pubkey,
    vault: Pubkey,
    escrow: Pubkey,
    recipient: Pubkey,
    mint: Pubkey,
) -> Result<()> {
    let settlement_id = settlement_id(mint, index);
    let expiry = client.get_block_time(client.get_slot()?)? + 600;
    let before_escrow = token_amount(client, escrow)?;
    let before_recipient = token_amount(client, recipient)?;

    let (decision, signed_recipient) = match scenario.mode {
        GateCase::Settle => (DECISION_SETTLE, recipient),
        GateCase::RecipientMismatch => (DECISION_SETTLE, Pubkey::new_unique()),
        GateCase::Hold => (DECISION_HOLD, recipient),
    };
    let auth = ReleaseAuthorization {
        version: VERSION,
        decision,
        vault,
        mint,
        recipient: signed_recipient,
        amount: RELEASE_AMOUNT,
        settlement_id,
        expiry,
        program_id: liquet_gate::ID,
    };
    let auth_bytes = auth.to_bytes().to_vec();
    let signature: [u8; 64] = signer.sign_message(&auth_bytes).as_ref().try_into().map_err(|_| anyhow!("unexpected ed25519 signature length"))?;
    let ed = ed25519_ix(&signer.pubkey().to_bytes(), &signature, &auth_bytes);
    let release = release_ix(config, vault, escrow, recipient, mint, settlement_id, auth_bytes, payer.pubkey());

    println!("\n{}", scenario.name);
    let submitted = submit_and_observe(client, &[ed, release], payer, &[payer])?;
    print_transaction("release attempt", &submitted.signature, rpc_url, is_devnet);

    let after_escrow = token_amount(client, escrow)?;
    let after_recipient = token_amount(client, recipient)?;
    match scenario.mode {
        GateCase::Settle => {
            expect_success(&submitted, scenario.name)?;
            ensure!(after_escrow == before_escrow - RELEASE_AMOUNT, "Settle did not debit escrow by signed amount");
            ensure!(after_recipient == before_recipient + RELEASE_AMOUNT, "Settle did not credit recipient by signed amount");
            println!("  SETTLE enforced: {} -> {} escrow; {} -> {} recipient", before_escrow, after_escrow, before_recipient, after_recipient);
        }
        GateCase::RecipientMismatch | GateCase::Hold => {
            ensure!(submitted.result.is_err(), "{} unexpectedly released", scenario.name);
            ensure!(after_escrow == before_escrow, "{} changed escrow balance", scenario.name);
            ensure!(after_recipient == before_recipient, "{} changed recipient balance", scenario.name);
            println!("  RELEASE REJECTED: {}", submitted.result.unwrap_err());
            println!("  escrow unchanged: {after_escrow}; recipient unchanged: {after_recipient}");
        }
    }
    Ok(())
}

struct Submitted {
    signature: Signature,
    result: Result<(), String>,
}

fn submit_and_observe(client: &RpcClient, ixs: &[Instruction], fee_payer: &Keypair, signers: &[&Keypair]) -> Result<Submitted> {
    let blockhash = client.get_latest_blockhash()?;
    let signer_refs: Vec<&dyn Signer> = signers.iter().map(|signer| *signer as &dyn Signer).collect();
    let transaction = Transaction::new_signed_with_payer(ixs, Some(&fee_payer.pubkey()), &signer_refs, blockhash);
    let signature = client.send_transaction_with_config(
        &transaction,
        RpcSendTransactionConfig { skip_preflight: true, ..RpcSendTransactionConfig::default() },
    )?;
    for _ in 0..120 {
        if let Some(status) = client.get_signature_status(&signature)? {
            return Ok(Submitted { signature, result: status.map_err(|err| format!("{err:?}")) });
        }
        thread::sleep(Duration::from_millis(250));
    }
    bail!("transaction {signature} was not observed within 30 seconds")
}

fn expect_success(submitted: &Submitted, label: &str) -> Result<()> {
    submitted.result.as_ref().map(|_| ()).map_err(|err| anyhow!("{label} failed: {err}"))
}

fn print_transaction(label: &str, signature: &Signature, _rpc_url: &str, is_devnet: bool) {
    if is_devnet {
        println!("  {label}: https://solscan.io/tx/{signature}?cluster=devnet");
    } else {
        println!("  {label}: {signature}");
    }
}

fn token_amount(client: &RpcClient, address: Pubkey) -> Result<u64> {
    let account = client.get_account(&address)?;
    Ok(spl_token::state::Account::unpack(&account.data)?.amount)
}

fn config_pda() -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"config"], &liquet_gate::ID)
}

fn vault_pda(config: &Pubkey, mint: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"vault", config.as_ref(), mint.as_ref()], &liquet_gate::ID)
}

fn receipt_pda(settlement_id: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"receipt", settlement_id.as_ref()], &liquet_gate::ID)
}

fn ata(owner: &Pubkey, mint: &Pubkey) -> Pubkey {
    spl_associated_token_account::get_associated_token_address(owner, mint)
}

fn settlement_id(mint: Pubkey, index: u8) -> [u8; 32] {
    solana_sdk::hash::hashv(&[b"liquet-gate-driver", mint.as_ref(), &[index]]).to_bytes()
}

fn ed25519_ix(pubkey: &[u8; 32], signature: &[u8; 64], message: &[u8]) -> Instruction {
    // Native Ed25519 layout with one fully self-contained signature. These
    // u16::MAX sentinels are the exact self-contained binding the gate parses.
    const HEADER: u16 = 2 + 14;
    let pk_off = HEADER;
    let sig_off = HEADER + 32;
    let msg_off = HEADER + 32 + 64;
    let mut data = Vec::with_capacity(msg_off as usize + message.len());
    data.push(1);
    data.push(0);
    data.extend_from_slice(&sig_off.to_le_bytes());
    data.extend_from_slice(&u16::MAX.to_le_bytes());
    data.extend_from_slice(&pk_off.to_le_bytes());
    data.extend_from_slice(&u16::MAX.to_le_bytes());
    data.extend_from_slice(&msg_off.to_le_bytes());
    data.extend_from_slice(&(message.len() as u16).to_le_bytes());
    data.extend_from_slice(&u16::MAX.to_le_bytes());
    data.extend_from_slice(pubkey);
    data.extend_from_slice(signature);
    data.extend_from_slice(message);
    Instruction { program_id: ed25519_program::ID, accounts: vec![], data }
}

fn release_ix(
    config: Pubkey,
    vault: Pubkey,
    escrow: Pubkey,
    recipient: Pubkey,
    mint: Pubkey,
    settlement_id: [u8; 32],
    auth_bytes: Vec<u8>,
    relayer: Pubkey,
) -> Instruction {
    let (receipt, _) = receipt_pda(&settlement_id);
    let accounts = liquet_gate::accounts::Release {
        config,
        vault,
        escrow_token: escrow,
        recipient_token: recipient,
        mint,
        receipt,
        instructions_sysvar: sysvar::instructions::ID,
        relayer,
        token_program: spl_token::ID,
        system_program: system_program::ID,
    };
    Instruction {
        program_id: liquet_gate::ID,
        accounts: accounts.to_account_metas(None),
        data: liquet_gate::instruction::Release { auth_bytes, settlement_id, ed25519_ix_index: 0 }.data(),
    }
}
