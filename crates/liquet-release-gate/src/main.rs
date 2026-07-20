use std::{env, fs};

use liquet::SignedDecision;
use liquet_release_gate::{check_release, PaymentToRelease, Pubkey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: liquet-release-gate <payment.json> <signed-decision.json> <pinned-ed25519-pubkey-hex>");
        std::process::exit(2);
    }
    let payment: PaymentToRelease = serde_json::from_slice(&fs::read(&args[1])?)?;
    let verdict: SignedDecision = serde_json::from_slice(&fs::read(&args[2])?)?;
    let signer = Pubkey::from_hex(&args[3]).map_err(std::io::Error::other)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&check_release(&payment, &verdict, &signer))?
    );
    Ok(())
}
