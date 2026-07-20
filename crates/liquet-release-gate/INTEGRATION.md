# Require a Liquet verdict in your release path

Liquet does not hold your funds and does not execute your payout. Your custody,
PSP, or risk system remains the only system that can move money. This reference
adds one check directly before that action:

```text
your payout request → Liquet release-gate check → your existing release call
                                      ├─ Release: continue
                                      └─ Hold: do not send
```

## Contract

Before paying, construct `PaymentToRelease` from the values your system is
actually about to use: `recipient`, `amount`, `mint`, and `settlement_id`. Pass
it with the complete Liquet `SignedDecision` and an Ed25519 signer key that you
pin in your own configuration.

`check_release` returns `Release` only when all of these are true:

1. The verdict signature verifies against **your pinned Liquet signer**.
2. The verdict says `Settle`.
3. Its signed `release_payment` has the exact same settlement ID, recipient,
   amount, and mint as your impending payout.
4. The verdict is not expired.

Anything else returns `Hold { reason }`. Log that reason for operations, keep
the funds in your existing system, and resolve or re-check the settlement.

The Rust and TypeScript references deliberately expose the same contract:

```rust
let outcome = liquet_release_gate::check_release(&payment, &verdict, &pinned_signer);
if outcome.is_release() {
    // Call your existing custody / PSP payout here.
} // Otherwise retain the funds and surface the Hold reason to operations.
```

```ts
import { checkRelease } from "./ts/src/index.ts";

const outcome = checkRelease(payment, verdict, pinnedSignerHex);
if (outcome.decision === "release") {
  // Call your existing custody / PSP payout here.
}
```

## Pin the signer

Store the 32-byte Ed25519 Liquet operator key as a hex string in your own secure
configuration. Do not accept a key supplied alongside a verdict. Rotating a key
is your change-control event: add the new pinned key deliberately, then retire
the old one.

## Binding prevents replay

The `release_payment` object is inside Liquet's signed `DecisionBinding`; it is
not metadata next to the verdict. A valid verdict for recipient A / amount 10
cannot authorize recipient B / amount 100. A generic or older verdict without
this object is deliberately held rather than inferred from a claim hash.

## Release rule and scope

Call the check in the same request/transaction boundary as your own payout, and
execute your release only on `Release`. This integration **decides** release or
hold; it does not custody funds, move tokens, reverse an already-executed
delivery, or replace your own authorization, compliance, or recovery controls.

## CLI reference

```sh
cargo run --manifest-path crates/liquet-release-gate/Cargo.toml -- \
  payment.json signed-decision.json <pinned-ed25519-pubkey-hex>
```

The JSON output is either `{ "decision": "release" }` or
`{ "decision": "hold", "reason": "…" }`.
