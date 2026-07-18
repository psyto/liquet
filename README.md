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

- **Core** (`src/seam.rs`, `src/decide.rs`) — the seam contract + gate, zero
  heavy deps: `cargo test` (12 passing).
- **Cross-VM demo** (`--features wire-probatio`) — fully self-contained,
  in-process revm + LiteSVM, no network, no fixtures:
  `cargo run --features wire-probatio --bin liquet-xvm-demo`
- **Single-VM slice** (`--features wire-custos`) — the SVM-only Custos path.

Two independent producers — probatio-xvm (Slot 1: cross-VM re-exec + reconcile)
and Custos (Slot 2: SVM malice screen) — so no component both executes and judges.

> The `wire-*` features use path dependencies on the public sibling repos
> [`psyto/probatio`](https://github.com/psyto/probatio) and
> [`psyto/custos`](https://github.com/psyto/custos); clone them adjacent to this
> repo to build those features. The default build (core + tests) is standalone.

## Layout

```
src/seam.rs        contract types (stable, serde)      — Slot 1 / Slot 2
src/decide.rs      pure gate: two slots -> settle/hold  (+ unit tests)
src/adapters/      one module per folded primitive
  custos.rs        Phase-1 producer (behind `wire-custos`)
src/bin/slice.rs   the demo that is the pitch
SEAM.md            the contract + producer registry
```

## Roadmap

- **Live invariant slot** — run Custos against the same SVM tx probatio replayed,
  bound by its re-exec digest.
- **Non-repudiation** — bind intent + proof to the exact leg / state context
  (signature, state-root).
- **First design partner** — gate real solver capital release. The only test
  that matters.

License: Apache-2.0.
