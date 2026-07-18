# Stage — ERC-8004 Validation Registry validator (Liquet as the objective validator)

Status: DESIGN v0 (2026-07-18). Fixes scope, the field mapping, trust model, DoD.
Depends on: [`SEAM.md`](./SEAM.md) (v0.4 signed `LiquetDecision`), `attest.rs`
(ed25519 `DecisionBinding`), `../probatio/probatio-xvm` (Slot 1 reconcile),
`../custos` (Slot 2). ERC-8004 spec: `eips.ethereum.org/EIPS/eip-8004`.

The engine is **not** new. This stage adds one output surface: turn Liquet's
already-signed settle/hold decision into an on-chain `validationResponse`.

---

## 0. Why this exists (the market seam)

ERC-8004 ships three registries (Identity / Reputation / **Validation**). The
empirical record (arXiv 2606.26028) is that the **Reputation Registry is not a
trust signal**: feedback is *not grounded in verifiable interactions*, and
73.5% / 59.2% / 90.6% of reviewers (ETH/BSC/Base) are coordinated Sybils —
reputation is manipulable at near-zero cost. The **Validation Registry** exists
to fix exactly this: it is a hook for a validator to publish a result grounded
in *actually checking the work*. But the hook is mostly empty — there is no
validator that re-executes an agent's economic action and returns an objective
verdict.

That empty slot is Liquet's. Liquet already answers "did this settlement execute
as specified, and is it safe to release?" by **re-executing** both legs and
reconciling them against the intent. Publishing that verdict as a
`validationResponse` is the one thing that grounds an agent's reputation in a
verifiable interaction. We are not proposing a new standard (do not fight
AP2/x402/ERC-8004 — [[project_gtm_public_strategy]]); we fill the validator seat
the standard left open.

**The one slide that sells:** a Reputation Registry star rating backed by nothing
(Sybil-forgeable) next to a Validation Registry response backed by a re-executed
verdict whose `responseHash` commits to both leg digests + the full invariant
verdict + the policy — recomputable by anyone.

---

## 1. The fit (this is the crux — mapping is real, not invented)

Every ERC-8004 `validationResponse` field already has a producer in the engine:

| ERC-8004 field (`validationResponse`) | Source in the existing engine |
|---|---|
| `requestHash` (commitment to the claim) | hash of the `(evm_tx, svm_tx, claim/AP2-intent)` bundle = probatio's `claim_hash` domain |
| `response` (uint8 0–100) | verdict map: `Matched`→**100**, `HalfOpen`/`Mismatch`→**0**, `Unverifiable`→**abstain** (§3) |
| `responseHash` (commitment to evidence) | **`attest.rs` `DecisionBinding` hash** — already binds `settlement_id`, `claim_hash`, all legs' reexec digests, reconcile verdict, full invariant verdict, policy, decision |
| `responseURI` (off-chain evidence) | the evidence bundle: `reasons[]`, per-leg `evm/svm_reexec_digest`, reconcile table, Custos findings, the ed25519 signature |
| `tag` (categorization) | the precise verdict: `"matched"` / `"half-open"` / `"mismatch"` / `"unverifiable"` (consumers read tag, not just averageResponse — §3) |
| `agentId` (from `validationRequest`) | the agent whose cross-VM action is under validation (Identity Registry NFT) |
| `requestURI` (from `validationRequest`) | pointer to the agent's claimed action = the settlement claim / AP2 Intent Mandate |

`responseHash` is the load-bearing line: Liquet **already** produces a
non-repudiable commitment over exactly the fields a relying party needs. ERC-8004
gives it an on-chain home and a discovery/aggregation surface for free.

---

## 2. Architecture — reuse vs new

```
        on-chain (EVM testnet, e.g. Base Sepolia)          off-chain (our validator service)
   ┌──────────────────────────────────────────┐     ┌──────────────────────────────────────────┐
   │ IdentityRegistry   (agent NFT)            │     │  event watcher                            │
   │ ValidationRegistry                        │     │    ↓ on ValidationRequest(ourAddr, ...)   │
   │   validationRequest(ourAddr, agentId,     │────▶│  fetch requestURI → (evm_tx, svm_tx,      │
   │       requestURI, requestHash)            │     │      claim / AP2 Intent Mandate)          │
   │                                           │     │    ↓                                       │
   │                                           │     │  ── LIQUET (unchanged) ──                 │
   │                                           │     │   probatio-xvm  → Slot 1 CrossVmProof      │
   │                                           │     │   Custos        → Slot 2 InvariantVerdict  │
   │                                           │     │   decide_crossvm→ LiquetDecision           │
   │                                           │     │   attest.rs     → signed DecisionBinding   │
   │                                           │     │    ↓                                        │
   │   validationResponse(requestHash,         │◀────│  map verdict→(response,tag);              │
   │       response, responseURI, responseHash,│     │  pin evidence bundle at responseURI;      │
   │       tag)                                │     │  responseHash = DecisionBinding hash      │
   └──────────────────────────────────────────┘     └──────────────────────────────────────────┘
```

- **Reused unchanged:** the entire re-exec + gate + signing stack
  (`probatio-xvm`, `custos`, `src/decide.rs`, `src/attest.rs`). No change to the
  frozen seam contract.
- **New (thin):** (a) an EVM client that watches `ValidationRequest` for our
  validator address and submits `validationResponse`; (b) a `requestURI` resolver
  → claim bundle; (c) an evidence store serving `responseURI`; (d) a verdict→
  `(response, tag)` map. Rust `alloy` for the EVM client; the service is one
  `watch → run liquet → respond` loop.
- **Trust model = off-chain attestor (architecture A).** ERC-8004's Validation
  Registry explicitly supports off-chain validators publishing results — no
  TEE/ZK required for v0. Trust = re-execution + the pinned ed25519 signer
  (Phase 2: independent replay from `responseURI`; Phase 3: TEE/ZK if demanded).

**Cross-VM note (the white space):** the request/response live on an **EVM**
registry, but the *validated work spans SVM + EVM*. So the PoC is an EVM-anchored
attestation *about a cross-VM event* — exactly the gap ERC-8004 leaves (no Solana
side). This sets up the Phase-2 contribution: a Solana-side validation registry
that mirrors this response. See §9.

---

## 3. Score / tag semantics (freeze for cross-impl consistency)

`response` is `uint8` and `getSummary` averages it, so it must stay a clean trust
signal. Binary, with `tag` carrying the precise verdict:

| reconcile verdict | `response` | `tag` | meaning |
|---|---|---|---|
| `Matched` | `100` | `"matched"` | both legs executed, terms bind to one `settlement_id`, invariants within policy → the agent's claim is true |
| `HalfOpen` | `0` | `"half-open"` | exactly one leg executed — paid-but-undelivered / delivered-but-unpaid |
| `Mismatch` | `0` | `"mismatch"` | both legs settled but terms diverge from the claimed intent (amount/asset/recipient/mint substitution, or unbindable id) |
| `Unverifiable` | **no response** | (`"unverifiable"` off-chain log) | a leg could not be deterministically reconstructed — **we abstain on-chain** rather than post a `0` that averages as "fail" |

Rules:
- **Abstain ≠ fail.** Posting `response=0` for `Unverifiable` would poison
  `averageResponse` by conflating "we checked, it failed" with "we couldn't
  check." So `Unverifiable` posts nothing on-chain (documented; the requester
  sees no response from us and can route to another validator). Optional: a
  distinct `tag="unverifiable"` response gated behind a consumer opt-in, but
  default = abstain.
- **Consumers must read `tag`, not just `averageResponse`.** Documented in the
  validator's agent card. `half-open` and `mismatch` are both `0` but are
  different failures with different evidence.
- **Progressive validation (future).** ERC-8004 permits multiple responses per
  request ("soft finality"). Maps to: a preliminary response before chain
  finality, a final one after. v0 = single final response only.

---

## 4. What the on-chain response commits to (non-repudiation)

`responseHash = DecisionBinding` (attest.rs, domain `v2`) binds: `settlement_id`,
`claim_hash`, **every** leg's reexec digest, the reconcile verdict, the **full**
invariant verdict (level + every finding), the **gate policy**, and the decision
— signed ed25519, verified against a **pinned** trusted signer. Consequences on
the registry:

- A relying party fetches `responseURI`, recomputes the bundle hash, checks it
  equals the on-chain `responseHash`, and verifies the signature against our
  pinned key. Tamper-evident end to end.
- The signature **cannot be replayed** against a different settlement (all leg
  digests are bound) nor paired with a false explanation (the full verdict is
  bound). This is the property the Reputation Registry lacks.
- Phase 2 upgrade: publish enough witness state at `responseURI` that a third
  party can **independently replay** each leg and reproduce the digest — turning
  "trust our re-execution" into "reproduce our re-execution." (SEAM §Phase-2 #1.)

---

## 5. Slice scope (one flow only — demand-not-feasibility)

Input: one `(evm_tx, svm_tx, claim)` triple asserted by an agent as a single
atomic cross-VM commerce event, referenced by a `ValidationRequest` on an EVM
testnet. `claim` carries `{ payer, asset, amount, good=(spl_mint,amount,recipient),
settlement_id, mandate.atomic }` (probatio STAGE0_XVM §Q2/Q4 shape); Phase 2
replaces `claim` with a signed **AP2 Intent Mandate** as the intent input.

Output: one on-chain `validationResponse` per request, plus the pinned evidence
bundle at `responseURI`. Nothing else — no LLM, no red-team loop, no on-chain
fund settlement, no reputation-registry writes.

---

## 6. The demo = the sales artifact (reuse the 5-case matrix, now on-chain)

Reuse probatio STAGE0_XVM §6 matrix; each row now ends in a real
`validationResponse` on a testnet registry:

| Case | Injected | reconcile | on-chain `response` / `tag` |
|---|---|---|---|
| normal | pay & good consistent | `Matched` | `100` / `matched` |
| non-delivery fraud | pay settles, Solana good withheld | `HalfOpen` | `0` / `half-open` |
| empty pay | good delivered, EVM pay reverts/absent | `HalfOpen` | `0` / `half-open` |
| substitution | good mint/amount ≠ claim | `Mismatch` | `0` / `mismatch` |
| amount tamper | pay amount ≠ claim | `Mismatch` | `0` / `mismatch` |

**Killer row:** agent (or its operator) submits a request asserting a clean
settlement; Liquet re-executes and posts `response=0, tag="half-open"` with a
`responseHash` a verifier can independently check. "The agent said it delivered;
the registry now carries a re-executed proof it did not."

---

## 7. Build order (smallest green first)

1. ✅ **DONE** — **Verdict→response map + evidence-bundle serializer** (pure).
   `src/erc8004/mod.rs`: `validation_response` (5-verdict map incl. the
   `Matched`-but-held → `unsafe` precision fix), `evidence_bundle_json`,
   `verify_bundle` (relying-party check). `responseHash` == the frozen `attest.rs`
   `DecisionBinding` golden vector (`dd2c…95b4`). 11 tests.
2. ✅ **DONE** — **Evidence store**: `src/erc8004/store.rs`: `EvidenceStore`
   trait, `MemStore` + `FileStore`, content-addressed by `responseHash`
   (`mem://{hash}` / `file://…/{hash}.json`). store→fetch→`verify_bundle` loop
   locked for both backends. 5 tests.
3–4-core. ✅ **DONE** — **Validator orchestration** (chain-agnostic):
   `src/erc8004/validator.rs`: `handle_request` = validate → map → pin evidence →
   `Respond` | `Abstain`, behind two seams (`SettlementValidator`,
   `EvidenceStore`) so it is pure/testable without `alloy` or revm/solana. 4 tests.
   **40 tests green in the default build.**
3–4-shell. **TODO (needs live chain)** — `alloy` `Erc8004Client` behind a
   `wire-erc8004` feature: watch `ValidationRequest(ourAddr, …)` on anvil / Base
   Sepolia, resolve `requestURI` → `ResolvedRequest`, call `handle_request`, submit
   the `OnChainAction` via `validationResponse`. Transport only — no policy.
5. **TODO** — **Wire real Liquet** as the `SettlementValidator` impl (behind
   `wire-xvm`: probatio-xvm + Custos + `decide_crossvm` + `attest`). Deploy the
   ERC-8004 reference `ValidationRegistry` + `IdentityRegistry`, register one
   agent, run all 5 cases end-to-end.

Steps 1–2 and the 3–4 **core** are done and pure-tested. What remains is the two
I/O shells: the `alloy` transport (3–4-shell) and the wired producer pipeline as
`SettlementValidator::validate` (step 5) — both need a chain / the heavy producer
crates, so they land behind features, not in the default `cargo test`.

---

## 8. Definition of Done (Stage 0)

- `cargo test` green: 5 Liquet decisions → correct `(response, tag, responseHash)`,
  with `responseHash` == `DecisionBinding` hash (golden vector locks it).
- On a testnet (or anvil fork of Base Sepolia) with the ERC-8004 reference
  `ValidationRegistry`: one registered `agentId`, all 5 cases produce the correct
  on-chain `validationResponse`, at least one (HalfOpen) driven by **real
  re-execution divergence**, not a stubbed digest.
- A relying-party script fetches `responseURI`, recomputes the hash, verifies it
  equals the on-chain `responseHash`, and checks the ed25519 signature — all pass.
- `Unverifiable` case abstains (no on-chain response) as specified.
- No paid RPC, no ZK, no reputation-registry write.

---

## 9. Explicitly out of scope (interfaces only — [[feedback_primitive_vs_business_focus]])

- **AP2 Intent Mandate as the intent input.** v0 uses the native `claim`; Phase 2
  swaps in a signed AP2 Intent Mandate so the "declared intent" is a standard VC,
  not our struct. Leave a typed seam at the claim boundary.
- **Solana-side validation registry.** ERC-8004 is EVM-only. The Phase-2
  standardization contribution (SBISG / Solana-Foundation channel) is a Solana
  program mirroring this response so the cross-VM verdict is anchored on both
  sides. Design only; do not build in v0.
- **Reputation Registry writes / discovery.** We only fill the Validation seat.
- **On-chain trustless settlement / ZK (`architecture B`).** Off-chain attestor
  is sufficient and is what ERC-8004's validator path expects. Moon-shot, not now.
- **Economics (who pays the validator, staking/slashing the validator).** Real,
  but a demand question, not a PoC question. Note and defer.

---

## 10. Open decisions (need a call before build)

1. **Deploy target.** Base Sepolia (ERC-8004 reference impl is live there) vs
   local anvil fork for the demo. Recommend: build on anvil (fast, free), record
   the demo on Base Sepolia (credible, public).
2. **Who submits `validationRequest`.** In ERC-8004 the *agent owner* requests
   validation. For the demo we script both roles (agent-op + validator), and flag
   the real-world flow (relying party or marketplace requests it) as the demand
   surface.
3. **`Unverifiable` handling.** Default = abstain (recommended). Confirm no
   consumer needs an explicit on-chain "unverifiable" signal in v0.
4. **Repo home.** This surface consumes Liquet's signed decision → belongs as a
   Liquet surface (`src/erc8004/` + this doc) OR a thin sibling `liquet-erc8004`
   crate. Recommend: in-repo module behind a `wire-erc8004` feature, mirroring
   the existing `wire-custos` / `wire-probatio` pattern. **Resolved:** pure core
   (mod/store/validator) ships in the default build; only the `alloy` shell +
   wired producer go behind features.

---

## 11. `wire-erc8004` shell — recorded design intent (before build)

The pure core (§7 steps 1–2 + 3–4-core) is done. This section fixes the
non-obvious decisions for the remaining `alloy` transport shell so a builder does
not re-derive them. The shell is **transport only** — it MUST NOT compute any
`response`/`tag`/decision; all policy lives in `handle_request`. If a change
needs verdict logic, it belongs in the core, not here.

**D1 — Registry chain ≠ settlement chains (three RPCs).** The
`ValidationRequest`/`Response` live on an **EVM registry chain** (Base Sepolia,
chainId **84532**). The *validated work* is a cross-VM event whose pay-leg and
delivery-leg live on **other** chains (e.g. a Tempo/Ethereum pay-leg + a Solana
delivery-leg). So the shell holds three connections: (a) registry EVM RPC — read
events, submit responses; (b) pay-leg chain RPC/prestate; (c) Solana RPC for the
delivery leg. The `requestURI` claim MUST carry each leg's chain id + tx ref so
the validator knows where to re-execute. Do not assume the work is on the
registry chain — that conflation is the trap.

**D2 — Two keys, explicitly bound.** The **EVM secp256k1 key** submits the tx and
IS the on-chain `validatorAddress` (ERC-8004's discovery/trust anchor + gas
payer). The **ed25519 key** signs the evidence bundle (`attest.rs`, the portable
non-repudiation). They are different curves and different roles — keep them
separate. **Bind them** so a relying party has one trust anchor, not two: the
validator's ERC-8004 registration / agent-card advertises its ed25519 signer key;
a consumer trusts `validatorAddress` on-chain, fetches the advertised ed25519 key,
and checks the bundle's `signer` matches it. Without this binding, `verify_bundle`
authenticates *a* signer but not *our* validator.

**D3 — Input integrity mirrors output.** Before acting on a `ValidationRequest`,
fetch `requestURI` and verify its content hashes to the on-chain `requestHash`.
Mismatch → ignore/abstain (a malformed or spoofed request), never re-execute
against unverified input. This is the input-side twin of the `responseHash` check
`verify_bundle` does on the output side.

**D4 — Determinism / reorg safety.** Re-execution MUST run against a **pinned,
finalized block** for each leg (the tx ref + block in the claim), never "latest"
— otherwise the verdict is non-deterministic and the `responseHash` is not
reproducible by an independent replayer (the whole point). On the registry chain:
wait N confirmations before treating a `ValidationRequest` as real, and before
treating our own submitted `validationResponse` as landed. L2 reorgs on Base
Sepolia are expected.

**D5 — Idempotency (the contract will not dedupe for us).** ERC-8004 *permits
multiple responses per request* ("progressive validation"), so a re-submitted
response is not rejected — it pollutes. The shell dedupes itself: (a) persist a
last-processed-block cursor so restarts neither rescan from genesis nor miss
events; (b) before submitting, call `getValidationStatus(requestHash)` and skip if
our `validatorAddress` already has a response with the same `responseHash`.
Because the verdict is content-addressed and deterministic (D4), re-processing the
same request is safe once this check is in place.

**D6 — `responseURI` must be publicly fetchable, and reachable *before* the
response lands.** The `mem://` / `file://` `EvidenceStore` schemes are
demo/local-only. Production needs an `EvidenceStore` impl that returns a public
URL or IPFS CID (HTTP gateway or `ipfs add`). Ordering constraint at the transport
level: **publish the bundle and confirm it is fetchable, THEN submit
`validationResponse`** — otherwise the registry points at evidence no one can
retrieve. (`handle_request` already pins before returning `Respond`; the shell
must additionally confirm reachability before the on-chain call.)

**D7 — Abstain must be recorded off-chain.** `Abstain` = do not call
`validationResponse`. But an invisible abstain is indistinguishable from "never
saw the request." The shell logs every `Abstain` (request_hash, tag, reason) to a
local record so the operator can see "we saw X, abstained: unverifiable." Optional:
a private evidence entry for the abstain, not linked on-chain.

**D8 — Minimal `sol!` surface.** Bind only what the shell touches: the
`ValidationRequest` event (read/watch), `validationResponse(...)` (write), and
`getValidationStatus(requestHash)` (read, for D5). Do not bind the Reputation
Registry or the rest of the Validation Registry.

**D9 — Config surface.** `registry_rpc` + `registry_chain_id` (84532) +
`validation_registry_addr` + `identity_registry_addr`; `validator_evm_key`
(secp256k1, gas + validatorAddress); `evidence_signer` (ed25519); per-leg RPCs
(pay-leg, Solana); `evidence_gateway_base` (how `responseURI` is formed);
`confirmations` (D4); `cursor_path` (D5). Dev = anvil fork of Base Sepolia; the
recorded demo = the live reference `ValidationRegistry` on Base Sepolia.

**D10 — `SettlementValidator::validate` is the other shell (step 5), not this
one.** This shell resolves the request and submits the action; producing the
signed decision (probatio-xvm + Custos + `decide_crossvm` + `attest`, behind
`wire-xvm`) is a separate impl injected via the `SettlementValidator` seam. Keep
the two shells independent so the transport can be tested against a mock validator
(as the core tests already do) before the heavy producer pipeline is wired.
