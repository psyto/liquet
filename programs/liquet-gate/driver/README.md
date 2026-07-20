# Liquet Gate live-cluster driver

This host-only reference driver proves a Liquet-signed verdict is enforced at a
real Solana release point using the native Ed25519 program and classic SPL
Token. The included escrow is **not Liquet custody**: it is a reference stand-in
for the custodian / PSP / LP's own release path.

It creates a fresh mint and reference escrow on every run, then submits four
release attempts:

1. `Settle` — accepted; tokens move from the vault ATA to the recipient ATA.
2. Wrong recipient — a pinned-signer authorization bound to a different
   recipient is rejected; balances stay unchanged.
3. Half-open — a signed `Hold` is rejected; balances stay unchanged.
4. Backdoored delivery — a signed `Hold` is rejected; balances stay unchanged.

The program must already be deployed at `liquet_gate::ID`. The local validator
rejects the legacy artifact, so build it with SBF v3 before deploying:

```sh
cd programs/liquet-gate
cargo build-sbf --arch v3
solana program deploy --url localhost --program-id .keys/program.json target/deploy/liquet_gate.so
cargo run --manifest-path driver/Cargo.toml
```

The driver reads the gitignored keys in `programs/liquet-gate/.keys/`:
`payer.json`, `bootstrap.json`, `signer.json`, and `program.json`. On localhost
it airdrops the payer and bootstrap account if needed. On devnet, fund those
keys first, then change only the RPC URL:

```sh
LIQUET_GATE_RPC_URL=https://api.devnet.solana.com \
  cargo run --manifest-path programs/liquet-gate/driver/Cargo.toml
```

For devnet, each submitted release transaction is printed as a Solscan URL.
