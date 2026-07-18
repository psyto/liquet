# Liquet SEAM contract

The seam is the **single source of truth** that every folded primitive targets.
Primitives (Custos, probatio-xvm, intentio, …) keep evolving in their own repos
and their own dev windows. They only have to emit the shapes below. Liquet
**consumes, never absorbs**. Changing the set of folded primitives means
adding/removing an *adapter* — the seam types and the gate do not change.

This file is versioned. When a slot shape must change, bump the version, change
`src/seam.rs`, and update every adapter to match. Do this deliberately — it is
the one coordination point across windows.

**Version: 0.2 (Phase 1, SVM-only)** — adds intent as a gate input (coverage +
value-binding). See "Changelog" at the bottom.

## Inputs

### Intent — `SettlementIntent` (what the solver asked to happen)
The gate binds the proof to THIS. Phase 1: unauthenticated struct. Phase 2:
carries a signature / tx-hash / state-context commitment so the intent itself is
unforgeable and bound to the exact executed leg.

| field | meaning |
|---|---|
| `vm` | `svm` \| `evm` |
| `asset` / `amount` / `recipient` | the intended transfer |
| `required_accounts[]` | accounts the producer MUST have had in scope |

### Slot 1 — `ReexecProof` (from a re-execution engine)
Witness that a settlement leg *executed as specified*. Raw poststate stays in
the producer; the seam keeps a chain-agnostic digest + observable facts.

| field | meaning |
|---|---|
| `vm` | `svm` \| `evm` |
| `executed` | leg ran to completion (not reverted / no-op) |
| `poststate_digest` | SHA-256 hex over the producer's canonical poststate |
| `covered_accounts[]` | accounts the producer had in scope (for coverage check) |
| `facts_source` | `producer_recovered` (trusted for binding) \| `caller_asserted` (not) |
| `asset` / `amount` / `recipient` | transfer facts, when recoverable |
| `unverifiable_reason` | set iff the producer could NOT verify the leg |

### Slot 2 — `InvariantVerdict` (from an invariant engine)
| field | meaning |
|---|---|
| `level` | worst `Severity` across findings (`green<info<yellow<red`) |
| `findings[]` | `{ severity, code, account?, message }` |

## The gate — `decide(intent, proof, verdict, policy) -> LiquetDecision`
Pure. Holds if any of: proof unverifiable; `executed` false (when
`require_executed`); `verdict.level > max_settle_severity` (default `Info`); an
`intent.required_account` is missing from `proof.covered_accounts` (coverage
gap); or — when `facts_source == producer_recovered` — the proof's
asset/amount/recipient/vm do not match the intent. When `facts_source ==
caller_asserted`, value-binding is not trusted: it becomes a **caveat** on
`Settle` (or a hold if `policy.require_recovered_facts`). Output is
`Settle { caveats }` or `Hold { reasons }` — every reason/caveat listed.

**Honesty of the Phase-1 settle:** with a Custos-only producer, a `Settle`
carries the caveat *"intent-binding unverified"* — it attests "executed + no
F1–F5 malice + required accounts covered", NOT "the money matched the intended
recipient/amount". Value-binding turns real (caveat disappears) once a
fact-recovering producer fills Slot 1 — see Phase 2.

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

## Known limitations (Phase 1)
- **Common-mode producer.** Custos fills BOTH slots — simulation capture, watch
  selection, and invariant interpretation all come from one producer. The
  two-slot separation is *structural* now; it becomes *independently protective*
  only when a second producer attests Slot 1.
- **Unauthenticated intent.** `SettlementIntent` is not yet bound to the exact
  leg/state context or signed, so it establishes coverage + (when recovered)
  value-binding, not non-repudiation.

## Phase 2 requirements (from the v0.2 review)
1. Authenticated binding of the proof to the exact leg and state context
   (tx-hash / state-root / signature), so intent + proof are non-repudiable.
2. A fact-recovering producer for Slot 1 (probatio-xvm `ReconstructedLeg`) so
   `facts_source = producer_recovered` and value-binding is real — then flip
   `policy.require_recovered_facts`.
3. Explicit cross-VM identity / finality semantics for the probatio proof.

## Changelog
- **v0.2** — added `SettlementIntent` as a gate input; `ReexecProof` gained
  `covered_accounts` + `facts_source`; gate does coverage + producer-recovered
  value-binding; `LiquetDecision::Settle` gained `caveats`.
- **v0.1** — initial two-slot contract (`ReexecProof`, `InvariantVerdict`) + gate.

## Deferred / dropped (do not wire now)
- **intentio EVM re-exec** — blocked on paid debug RPC; not needed for SVM slice.
- **zkReceipt** — no demand path; excluded.
