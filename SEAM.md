# Liquet SEAM contract

The seam is the **single source of truth** that every folded primitive targets.
Primitives (Custos, probatio-xvm, intentio, …) keep evolving in their own repos
and their own dev windows. They only have to emit the shapes below. Liquet
**consumes, never absorbs**. Changing the set of folded primitives means
adding/removing an *adapter* — the seam types and the gate do not change.

This file is versioned. When a slot shape must change, bump the version, change
`src/seam.rs`, and update every adapter to match. Do this deliberately — it is
the one coordination point across windows.

**Version: 0.1 (Phase 1, SVM-only)**

## Two slots

### Slot 1 — `ReexecProof` (from a re-execution engine)
Witness that a settlement leg *executed as specified*. Raw poststate stays in
the producer; the seam keeps a chain-agnostic digest + observable facts.

| field | meaning |
|---|---|
| `vm` | `svm` \| `evm` |
| `executed` | leg ran to completion (not reverted / no-op) |
| `poststate_digest` | SHA-256 hex over the producer's canonical poststate |
| `asset` / `amount` / `recipient` | transfer facts, when recoverable |
| `unverifiable_reason` | set iff the producer could NOT verify the leg |

### Slot 2 — `InvariantVerdict` (from an invariant engine)
| field | meaning |
|---|---|
| `level` | worst `Severity` across findings (`green<info<yellow<red`) |
| `findings[]` | `{ severity, code, account?, message }` |

## The gate — `decide(proof, verdict, policy) -> LiquetDecision`
Pure. `Settle` iff: proof is verifiable, `executed` is true (when
`require_executed`), and `verdict.level <= max_settle_severity`
(default `Info`). Otherwise `Hold { reasons }` with every reason listed.

## Producer registry (living, demand-driven)

| primitive | repo | slot(s) | status |
|---|---|---|---|
| **Custos** | `../custos` (`custos-engine`) | 1 + 2 | **Phase 1 — wiring** |
| probatio-xvm | `../probatio/probatio-xvm` | 1 (SVM / cross-VM) | Phase 2 — dock when a cross-VM leg appears |
| intentio | `../intentio` (`intentio-reexec`) | 1 (EVM leg) | Phase 3 — dock when an EVM leg appears |
| Tessera | `../tessera` | (new slot) `ComplianceAttestation` | Phase 3 — track TBD (SBI/institutional vs personal); see below |

Add a primitive **only when a real flow needs it** (demand-not-feasibility). Do
not fold speculatively.

## custos adapter contract (Phase 1)
Custos alone fills BOTH slots for a single SVM leg: it re-executes in LiteSVM
(`Outcome` -> Slot 1) and evaluates F1–F5 (`Verdict` -> Slot 2). Target API
(transcribed from `/Users/hiroyusai/src/custos`, verify before relying):

```
custos_engine::Level   { Green, Info, Yellow, Red }                          // engine/src/lib.rs:109
custos_engine::Finding { level, code:&'static str, account: Pubkey, message } // engine/src/lib.rs:117
custos_engine::Verdict { level: Level, findings: Vec<Finding> }              // engine/src/lib.rs:307
custos_engine::evaluate(&Outcome, &Bank) -> Verdict                          // engine/src/lib.rs:323
custos_engine::default_bank() -> Bank                                        // engine/src/lib.rs:313
custos_engine::sim::capture(&mut LiteSVM, tx, user, watch, token_id, system_id) -> Outcome // engine/src/sim.rs:28
custos_engine::loader::build_benign_b64() / build_hidden_approve_b64()       // engine/src/loader.rs
```

Notes:
- Custos core `Verdict`/`Finding`/`Level` are **not** serde — map them in the
  adapter (done in `verdict_from_custos`). The serde `ScanReport`/`FindingDto`
  DTOs also exist but carry `level` as a String; prefer mapping the enum.
- `poststate_digest`: hash a canonical serialization of the `Outcome` post
  snapshots (sort accounts by pubkey; hash `(pubkey, lamports, owner, data)`).

## Deferred / dropped (do not wire now)
- **intentio EVM re-exec** — blocked on paid debug RPC; not needed for SVM slice.
- **zkReceipt** — no demand path; excluded.
