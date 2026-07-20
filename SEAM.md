# Liquet SEAM contract

The seam is the **single source of truth** that every folded primitive targets.
Primitives (Custos, probatio-xvm, intentio, …) keep evolving in their own repos
and their own dev windows. They only have to emit the shapes below. Liquet
**consumes, never absorbs**. Changing the set of folded primitives means
adding/removing an *adapter* — the seam types and the gate do not change.

This file is versioned. When a slot shape must change, bump the version, change
`src/seam.rs`, and update every adapter to match. Do this deliberately — it is
the one coordination point across windows.

**Version: 0.3** — adds the CROSS-VM flagship path: a reconcile-based Slot 1
(probatio-xvm) that binds every leg's producer-recovered facts to the intent,
with Custos as an independent Slot 2. See "Changelog" at the bottom.

## Flagship path — cross-VM settlement

The product IS cross-VM. A chain-abstract intent settles across an EVM pay-leg
and an SVM delivery-leg; Liquet re-executes both and reconciles them:

- **Slot 1 — `CrossVmProof`** (from probatio-xvm): `reconcile ∈ {Matched,
  HalfOpen, Mismatch, Unverifiable}` + per-leg `ReexecProof`s with
  producer-recovered facts. `Matched` = real value-binding, no caveat.
- **Slot 2 — `InvariantVerdict`** (from Custos on the SVM leg): malice screen.
- Gate: `decide_crossvm(cross_vm, invariant, policy)` — `Matched` + invariants
  within threshold → `Settle`; otherwise `Hold` (half-open / mismatch / malice).

Because Slot 1 (probatio) and Slot 2 (Custos) are now DIFFERENT producers, the
v0.2 common-mode blind spot is resolved. The single-leg v0.2 path (`decide`,
Custos-only, caller-asserted caveat) remains for SVM-only flows.

Below documents the single-leg (v0.2) inputs; the cross-VM path reuses
`ReexecProof` per leg and supersedes caller-asserted facts with reconcile.

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
| **probatio-xvm** | `../probatio/probatio-xvm` | 1 (cross-VM reconcile + EVM/SVM re-exec) | **Docked (v0.3) — Codex wiring** |
| **Custos** | `../custos` (`custos-engine`) | 2 (SVM malice screen); 1+2 in single-leg path | Docked (v0.2) |
| intentio | `../intentio` (`intentio-reexec`) | 1 (standalone EVM leg) | in-process via probatio-xvm; standalone dock later |
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

## Known witness-fidelity gaps (cross-VM, from the v0.3 review)
- The per-leg `ReexecProof` carries `asset`/`amount`/`recipient` but NOT the
  leg's `recovered_settlement_id` / `payer_or_source`. Liquet therefore *trusts*
  probatio's `Matched` verdict but cannot *independently replay* every reconcile
  check. Fine while probatio is the trusted Slot-1 producer; add these to the leg
  proof when independent replay / non-repudiation is needed (see Phase 2).
- `covered_accounts` is empty for probatio legs (probatio does not yet expose the
  full witness account set). `decide_crossvm` does not use coverage, so this is
  inert — deliberately NOT faked with owner/mint addresses, which would overclaim.
- Custos Slot-2 on the cross-VM path is stubbed green in the demo. Real wiring
  must: (1) have probatio expose the exact SVM delivery tx + state scope, (2) run
  Custos against that same context, (3) bind the Custos verdict to probatio's SVM
  reexec digest before using it as Slot 2 (else a fresh common-mode reappears).

## Phase 2 requirements (from the v0.2 review)
1. Authenticated binding of the proof to the exact leg and state context
   (tx-hash / state-root / signature), so intent + proof are non-repudiable.
2. A fact-recovering producer for Slot 1 (probatio-xvm `ReconstructedLeg`) so
   `facts_source = producer_recovered` and value-binding is real — then flip
   `policy.require_recovered_facts`.
3. Explicit cross-VM identity / finality semantics for the probatio proof.

## Non-repudiation (v0.4)

`attest.rs` binds a `LiquetDecision` to the exact settlement it was computed over
and signs it (ed25519, `verify_strict`). `DecisionBinding` commits to
`settlement_id`, `claim_hash`, **all** legs' reexec digests, the reconcile
verdict, the **full invariant verdict** (level + every finding), the **gate
policy**, and the decision. `verify_decision` authenticates against a **pinned
trusted signer** — a receipt signed with any other key is rejected;
`verify_self_consistent` is the explicitly-unpinned check and is *not*
authentication. Because every leg digest + the full verdict are bound, a
signature cannot be replayed against a different settlement, nor paired with a
false explanation of why Liquet settled/held. Pure — verifiable with `cargo test`
(a golden vector locks the wire encoding; domain `v2`).

Phase-2 requirement #1 addressed. Still open: (a) anchoring the digests to
*canonical chain state* (exact tx-hash / state-root at the producer, probatio),
and (b) a length-prefixed canonical encoding before any external verifier
implementation.

## Changelog
- **v0.5** — non-custodial release binding: `attest.rs` gains a signed
  `ReleasePaymentBinding` (recipient / amount / mint / settlement id / expiry),
  carried inside `DecisionBinding` so it is covered by the same signed digest
  (`skip_serializing_if` preserves the legacy digest when absent). Consumed by
  the model-(b) [`crates/liquet-release-gate`](./crates/liquet-release-gate):
  a relying party's own release path releases only for a pinned-signer,
  unexpired `Settle` bound to the exact payment. Liquet holds no funds;
  [`programs/liquet-gate`](./programs/liquet-gate) is a devnet-live *reference*
  enforcement gate, not custody. Additive; seam types and `decide` unchanged.
- **v0.4** — non-repudiation: `attest.rs` — ed25519-signed verdicts bound to all
  leg reexec digests + full invariant verdict + policy + claim hash;
  `verify_decision` pins a trusted signer (`verify_self_consistent` is the
  unpinned, non-authenticating check). Hardened per the Codex adversarial review
  (P1 signer pinning, P1 full-verdict binding, P2 all-legs/policy/golden-vector).
  Additive; seam types and `decide` unchanged.
- **v0.3** — cross-VM flagship: `ReconcileVerdict` + `CrossVmProof` (Slot 1 from
  probatio-xvm, producer-recovered facts); `decide_crossvm`; probatio (Slot 1) +
  Custos (Slot 2) are independent producers → common-mode blind spot resolved.
- **v0.2** — added `SettlementIntent` as a gate input; `ReexecProof` gained
  `covered_accounts` + `facts_source`; gate does coverage + producer-recovered
  value-binding; `LiquetDecision::Settle` gained `caveats`.
- **v0.1** — initial two-slot contract (`ReexecProof`, `InvariantVerdict`) + gate.

## Deferred / dropped (do not wire now)
- **intentio EVM re-exec** — blocked on paid debug RPC; not needed for SVM slice.
- **zkReceipt** — no demand path; excluded.
