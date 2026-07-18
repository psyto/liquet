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

## Status — Phase 1 (walking skeleton)

- **Scope:** SVM-only, single leg, no RPC, no EVM.
- **Producer:** `custos-engine` fills both slots (re-execution + invariants F1–F5).
- **Core** (`src/seam.rs`, `src/decide.rs`) compiles and tests with zero heavy
  deps: `cargo test`.
- **Wiring** (`--features wire-custos`): the Custos adapter and the demo slice
  are scaffolded with `TODO(codex)` markers — the convergence pass wires them
  against the real crate until `cargo build --features wire-custos` is green and
  `cargo run --features wire-custos --bin liquet-slice` prints SETTLE for a
  benign transfer and HOLD for a drainer.

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

- **Phase 2:** dock `probatio-xvm` (SVM/cross-VM re-exec witness) when a real
  cross-VM leg appears; add the EVM leg via `intentio-reexec`.
- **Phase 3:** add a `ComplianceAttestation` slot (Tessera) as the regulated-rail
  pull. Track (personal vs SBI/institutional) TBD.

License: Apache-2.0.
