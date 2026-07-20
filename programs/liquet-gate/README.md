# liquet-gate

**A reference on-chain enforcement gate for a Liquet verdict.** Liquet itself is a
**non-custodial verifier** (see the [repo README](../../README.md)) — it holds no
funds and executes no payouts. This program is a **reference / demo** stand-in for
a release path that *requires* the verdict: an independent, ed25519-signed
`Settle` / `Hold` — produced off-chain by Liquet's cross-VM re-execution + Custos
malice screen — is enforced at the exact moment funds would be released. It is not
the product and not custody. The model-(b) drop-in for your *own* release path is
[`crates/liquet-release-gate`](../../crates/liquet-release-gate).

```
Liquet verifier (off-chain)
  re-exec both legs · reconcile · Custos screen  →  Settle / Hold
                                                     ↓  Ed25519-signed ReleaseAuthorization
Solana transaction:
  ix[i]   Ed25519 verify   (native program)
  ix[i+1] liquet_gate::release(auth_bytes, settlement_id, i)
            ├─ ① bind: pinned signer signed EXACTLY these bytes
            ├─ ② enforce fields FROM the signed message (vault/mint/amount/recipient/expiry)
            ├─ replay: receipt PDA (init, seeded by settlement_id)
            └─ Settle → invoke_signed TransferChecked from escrow PDA
                Hold / no valid Settle → nothing moves
```

## Honest scope

This gates the **release**. It does **not** claim to reverse an already-executed
delivery. The accurate claim is:

> unsafe delivery detected → `release()` denied → **escrow balance unchanged**.

The money-shot: a delivery that reconciles `Matched` across both chains but hides
an unlimited-delegate grant → the independent Custos screen returns `Hold` → no
`Settle` is ever signed → `release()` cannot fire → funds intact.

## The two load-bearing guards

- **① Ed25519 introspection** (`src/ed25519.rs`) — we verify the *binding*, not the
  presence, of a signature: native Ed25519 program, pinned signer, exact message,
  self-contained offsets. A naive "an Ed25519 verify exists" check is exploitable.
- **② Fields from the signed message** (`src/authorization.rs`) — every enforced
  transfer parameter is read from the verified `ReleaseAuthorization` bytes, never
  from separately-supplied instruction args. Prevents "sign for A, execute B".

Plus: `program_id` binding (no cross-gate replay), `settlement_id` replay marker,
`expiry`, and an emergency `pause` authority.

## Status — live on devnet, proven end-to-end

Deployed on devnet and driven end-to-end with **real native Ed25519 + real SPL
Token** by [`./driver`](./driver): a pinned-signer `Settle` releases funds, and
wrong-recipient / half-open / backdoored cases are held on-chain with the escrow
unchanged. Every case is a publicly verifiable transaction — program id, deploy,
and demo tx links are in [`DEPLOYMENTS.md`](./DEPLOYMENTS.md).

Adversarially reviewed by Codex; round-1 P0/P1 findings reflected:

- **P0-1** — `initialize` gated to `BOOTSTRAP_AUTHORITY` (no front-run of config).
- **P0-2** — the escrow token account pinned to the canonical ATA of `(vault, mint)`.
- **P1** — `refund` as a pause-authority emergency withdraw; the `Escrow` state
  account dropped (removing the depositor-overwrite footgun).
- Ed25519 restricted to a *preceding* instruction; signing via `ctx.bumps.vault`.

## Build & toolchain

- **`cargo build-sbf --arch v3`** — the default `v0` is rejected by current
  validators. Built with Solana platform-tools ≥ v1.54 (Rust ≥ 1.85; older
  toolchains cannot parse the edition-2024 crates in `anchor-spl 0.32`'s tree).
- The Ed25519 program id is hardcoded as bytes (`src/ed25519.rs`) because neither
  the `ed25519_program` module nor the `pubkey!` macro resolves through
  `anchor_lang::solana_program` at this version.
- Program keypairs live under `.keys/` and are **gitignored** — never commit them.

Run the reference gate against a cluster:

```sh
# local
solana program deploy --url localhost --program-id .keys/program.json target/deploy/liquet_gate.so
cargo run --manifest-path driver/Cargo.toml
# devnet (fund the payer/bootstrap keys first)
LIQUET_GATE_RPC_URL=https://api.devnet.solana.com cargo run --manifest-path driver/Cargo.toml
```

## Next

- **Real cross-VM verdict** — replace the driver's off-chain signer stand-in with
  the live `probatio-xvm` re-execution + `Custos` screen, so the on-chain
  enforcement is fed by an actual re-run of both legs.
- Token-2022 (`token_interface`) if a demo mint uses extensions.
