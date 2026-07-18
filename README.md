# Liquet

**The neutral re-execution + invariant gate for cross-VM settlement.**

Liquet is not a chain and does not issue money. It sits at the boundary where
regulated stablecoins (JPY / RMB / HKD) meet crypto-native execution, and
answers one question before funds move:

> *did this settlement execute as specified, and is it safe to release?*

It does this by **consuming** independent verification primitives through one
stable seam — a re-execution engine for Slot 1 (proof) and an invariant engine
for Slot 2 (gate) — and combining them into a single `Settle` / `Hold` decision.
Liquet folds primitives in; it never absorbs their code. See [`SEAM.md`](./SEAM.md).

## Status — v0.3, cross-VM flagship (runnable)

Liquet re-executes a chain-abstract settlement across an **EVM pay-leg** and an
**SVM delivery-leg**, reconciles both against the intent, and gates settle/hold:

| scenario | reconcile | decision |
|---|---|---|
| benign atomic settlement | `Matched` | **settle** |
| mis-delivery (wrong recipient) | `Mismatch` | **hold** |
| half-open (pay leg only, no delivery) | `HalfOpen` | **hold** — the bridge nightmare |
| backdoored delivery (correct transfer + hidden approve) | `Matched` | **hold** — the malice screen catches it |

- **Core** (`src/seam.rs`, `src/decide.rs`, `src/attest.rs`) — the seam contract,
  gate, and ed25519 non-repudiation, zero heavy deps: `cargo test` (40 passing;
  44 with `--features wire-xvm`).
- **Cross-VM demo** (`--features wire-probatio`) — fully self-contained,
  in-process revm + LiteSVM, no network, no fixtures:
  `cargo run --features wire-probatio --bin liquet-xvm-demo`
- **Live malice screen** (`--features wire-xvm`) — Custos re-runs probatio's exact
  SVM delivery tx as Slot 2; a Matched-but-backdoored delivery is held (`FAIL/unsafe`).
- **ERC-8004 validator** (`src/erc8004/`) — maps a signed decision onto a
  Validation Registry `validationResponse` (pure core; real pipeline behind `wire-xvm`).

Two independent producers — probatio-xvm (Slot 1: cross-VM re-exec + reconcile)
and Custos (Slot 2: SVM malice screen) — so no component both executes and judges.

> **Building the features.** The default build (seam + gate + `cargo test`) is
> standalone and fully public. The `wire-*` features use path dependencies on
> sibling repos cloned adjacent (`../custos`, `../probatio`, …):
>
> - `wire-custos` (single-VM slice) — needs public
>   [`psyto/custos`](https://github.com/psyto/custos) (the crate + runtime
>   fixtures under `custos/gate/artifacts`).
> - `wire-probatio` (cross-VM demo) — uses
>   [`mppsol/probatio`](https://github.com/mppsol/probatio). Its EVM re-execution
>   engine (`intentio-reexec`, `fabrknt/intentio`) is a **deliberately closed
>   commercial core** — the verification and product layers are open, the engine
>   is not (see [Trust model](#trust-model)). The cross-VM behaviour is shown in
>   the [walkthrough](web/index.html) and, in production, published as a signed
>   ERC-8004 verdict anyone can verify **without** the engine.

## Trust model

Liquet is **open-core**: the verification and product layers (this repo, `custos`,
`probatio`) are public; the EVM re-execution engine (`intentio-reexec`) is a closed
commercial core. That is a deliberate boundary, not a gap to be closed.

External trust does not require rebuilding the engine. Every verdict is an
ed25519-**signed**, content-addressed decision (`attest.rs`): the ERC-8004
`responseHash` commits to both legs' re-exec digests, the full invariant verdict,
the policy, and the decision. A relying party fetches the evidence bundle,
recomputes the hash, and verifies the signature against the validator's pinned
key — confirming the verdict is authentic, unmodified, and bound to the exact
settlement, **without** access to the engine.

Honest boundary: this is *authenticated attestation*, not *trustless
re-derivation*. A verifier can confirm the signed verdict; it cannot independently
re-run the engine to re-derive it. Full trustlessness (an open engine, or a ZK
proof of the re-execution) is deferred.

## Layout

```
src/seam.rs         contract types (stable, serde)      — Slot 1 / Slot 2
src/decide.rs       pure gate: two slots -> settle/hold
src/attest.rs       ed25519 non-repudiation of the verdict
src/adapters/       one module per folded primitive (custos, probatio, xvm_custos)
src/erc8004/        Validation Registry validator surface
src/bin/xvm_demo.rs the cross-VM demo (the pitch)
SEAM.md             the contract + producer registry
```

## Roadmap

Done: live invariant slot (Custos on probatio's exact SVM tx), non-repudiation
(ed25519-signed decisions), ERC-8004 validator core + wired pipeline.

- **On-chain validator shell** — `alloy` client: watch `ValidationRequest`, run the
  pipeline, submit the `validationResponse` (Base Sepolia). See
  [`STAGE_ERC8004_VALIDATOR.md`](./STAGE_ERC8004_VALIDATOR.md).
- **First design partner** — a grounded verdict a relying party actually consumes.
  The only test that matters.

License: Apache-2.0.
