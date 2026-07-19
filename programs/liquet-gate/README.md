# liquet-gate

**The on-chain enforcement point of the Liquet story.** An independent verdict —
produced off-chain by Liquet's cross-VM re-execution + Custos malice screen — is
signed and enforced at the exact moment a Solana escrow would release funds.

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

## Honest scope (hackathon MVP)

This gates the **escrow release**. It does **not** claim to physically stop an
already-executed delivery. The accurate demo claim is:

> unsafe delivery detected → `release()` denied → **escrow balance unchanged**.

The money-shot (Card 4): a delivery that reconciles `Matched` across both chains
but hides an unlimited-delegate grant → Custos screen returns `Hold` → no `Settle`
authorization is ever signed → `release()` cannot fire → escrow intact.

## The two load-bearing guards

- **① Ed25519 introspection** (`src/ed25519.rs`) — we verify the *binding*, not the
  presence, of a signature: native Ed25519 program, pinned signer, exact message,
  self-contained offsets. A naive "an Ed25519 verify exists" check is exploitable.
- **② Fields from the signed message** (`src/authorization.rs`) — every enforced
  transfer parameter is read from the verified `ReleaseAuthorization` bytes, never
  from separately-supplied instruction args. Prevents "sign for A, execute B".

Plus: `program_id` binding (no cross-gate replay), `settlement_id` replay marker,
`expiry`, and an emergency `pause` authority.

## Status — CC scaffold, pending Codex review + SBF build

Written by CC for adversarial review; **not yet built** with the Anchor/SBF
toolchain. `src/authorization.rs` has host unit tests (roundtrip / offsets).

Open items flagged inline as `REVIEW(codex):`
- Ed25519 `*_instruction_index` sentinel (`u16::MAX`) vs the exact program version.
- `declare_id!` placeholder — run `anchor keys sync` before deploy.
- `refund` handler + per-deposit accounting (scaffold is one escrow per config,mint).
- Anchor workspace layout vs the existing `cargo test` (isolated `[workspace]`).
- Token-2022 (`token_interface`) if the demo mint uses extensions; scaffold is classic SPL.

## Next increments

1. Off-chain: emit the canonical `ReleaseAuthorization` bytes + Ed25519 signature
   from the `liquet` verdict (single-source the layout — shared crate).
2. Devnet demo: Settle → release succeeds; F2-delegate Hold → release rejected,
   escrow balance unchanged (the pair).
