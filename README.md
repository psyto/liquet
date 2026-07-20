# Liquet

**A non-custodial verifier for cross-chain settlement.**

A payment often crosses two chains — paid on one, delivered on another. A bridge
moves the money and hopes it lands. Liquet **re-runs both legs**, checks the two
sides actually match, screens the delivery for hidden malice, and answers one
question before any money moves:

> *did this settlement execute as specified, and is it safe to release?*

Liquet is **not a chain, not a custodian, and issues no money.** It holds no
funds and executes no payouts. It produces a single ed25519-**signed** `Settle`
or `Hold` verdict that **your own release path requires** before it pays out. The
judge is independent of the executor — that is the whole point.

## How you use it (non-custodial)

Liquet's product is the **signed verdict**. You make it a required condition on
your release. You never hand Liquet custody.

- **[`crates/liquet-release-gate`](./crates/liquet-release-gate)** — the drop-in a
  custodian / PSP / solver puts in its **own** release path.
  `check_release(payment, signed_verdict, pinned_signer) -> Release | Hold{reason}`.
  It releases **only** for a pinned-signer, unexpired `Settle` bound to the exact
  settlement id, recipient, amount, and mint; every other case (bad signature,
  absent binding, any field mismatch, expiry, non-`Settle`) is a **fail-closed
  Hold**. Rust check + CLI, a TypeScript verifier, and a custodian-facing
  [`INTEGRATION.md`](./crates/liquet-release-gate/INTEGRATION.md). It holds no funds.
- **[`programs/liquet-gate`](./programs/liquet-gate)** — a **reference** on-chain
  enforcement gate (a stand-in for a release path that requires the verdict). It
  is a demo/reference for greenfield users, **not the product and not custody**.
  It is **live on devnet** and every enforcement is publicly verifiable — see
  [`programs/liquet-gate/DEPLOYMENTS.md`](./programs/liquet-gate/DEPLOYMENTS.md).

An interactive **settlement release console** (`web/settlement-release-console.html`)
shows the felt moment from the operator's side: a payment that reconciles across
both chains but hides a trap is caught and held before the money leaves.

## How it decides

Liquet **consumes** independent verification primitives through one stable seam
and combines them into the verdict — it folds primitives in, never absorbs their
code (see [`SEAM.md`](./SEAM.md)):

- **Slot 1 — re-execution + reconcile** (`probatio-xvm`): re-run the EVM pay-leg
  (revm) and the Solana delivery-leg (LiteSVM) in-process and reconcile both
  against the intent. Verdict: `Matched` / `Mismatch` / `HalfOpen`.
- **Slot 2 — independent malice screen** (`Custos`): screen the delivery for a
  hidden authority grab / drain the reconcile can't see.

Two independent producers, so no component both executes and judges. The combined
decision is signed by `attest.rs` and bound to the exact payment
(`ReleasePaymentBinding`: recipient, amount, mint, settlement id, expiry).

| scenario | reconcile | screen | decision |
|---|---|---|---|
| benign atomic settlement | `Matched` | clean | **Settle** |
| wrong recipient | `Mismatch` | clean | **Hold** |
| half-open (paid, never delivered) | `HalfOpen` | clean | **Hold** — the bridge nightmare |
| backdoored delivery (correct transfer + hidden approve) | `Matched` | `F2-delegate` | **Hold** — the independent screen catches it |

## Proven on devnet

The reference gate is deployed on devnet and driven end-to-end with **real native
Ed25519 + real SPL Token** by [`programs/liquet-gate/driver`](./programs/liquet-gate/driver):
a pinned-signer `Settle` releases funds, and wrong-recipient / half-open /
backdoored cases are **held on-chain with the escrow unchanged**. Every case is a
publicly verifiable transaction — links in
[`DEPLOYMENTS.md`](./programs/liquet-gate/DEPLOYMENTS.md).

## Trust model

Liquet is **open-core**: the verification and product layers (this repo, `custos`,
`probatio`, `liquet-release-gate`) are public; the EVM re-execution engine
(`intentio-reexec`) is a closed commercial core. That is a deliberate boundary.

External trust does not require rebuilding the engine. Every verdict is an
ed25519-signed, content-addressed decision (`attest.rs`): a relying party fetches
the evidence bundle, recomputes the hash, and verifies the signature against the
validator's **pinned** key — confirming the verdict is authentic, unmodified, and
bound to the exact settlement, **without** access to the engine.

Honest boundary: this is *authenticated attestation*, not *trustless
re-derivation*. A verifier confirms the signed verdict; it does not independently
re-run the engine to re-derive it. Full trustlessness (an open engine, or a ZK
proof of the re-execution) is deferred.

## Layout

```
src/seam.rs            contract types (stable, serde)      — Slot 1 / Slot 2
src/decide.rs          pure gate: two slots -> settle/hold
src/attest.rs          ed25519 non-repudiation + ReleasePaymentBinding
src/adapters/          one module per folded primitive (custos, probatio, xvm_custos)
src/erc8004/           ERC-8004 Validation Registry validator surface
src/bin/xvm_demo.rs    the cross-VM decision demo
crates/liquet-release-gate/   model-(b) drop-in: verdict required in YOUR release path
programs/liquet-gate/         reference on-chain enforcement gate (devnet-live) + driver
web/settlement-release-console.html   interactive operator-side demo
SEAM.md                the contract + producer registry
```

## Build & test

- Core / verifier: `cargo test` (40 passing; more with `--features wire-xvm`).
- Release gate: `cd crates/liquet-release-gate && cargo test`.
- On-chain program: **`cargo build-sbf --arch v3`** (default `v0` is rejected by
  current validators). See [`programs/liquet-gate`](./programs/liquet-gate).

> The `wire-*` features use path dependencies on sibling repos cloned adjacent
> (`../custos`, `../probatio`). The default build (seam + gate + `cargo test`) is
> standalone and fully public.

## Roadmap

- **Real cross-VM verdict end to end** — replace the reference driver's signer
  stand-in with the live `probatio-xvm` re-execution + `Custos` screen, so the
  on-chain enforcement is fed by an actual re-run of both legs.
- **First design partner** — a custodian / PSP / solver with cross-chain
  settlement exposure that requires the verdict in its own release path.

License: Apache-2.0.
