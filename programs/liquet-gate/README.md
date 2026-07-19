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

## Status — Codex review round 1 reflected; SBF build pending

CC scaffold, adversarially reviewed by Codex (no self-merge). Round-1 findings
reflected on this branch:

- **P0-1 fixed** — `initialize` is gated to `BOOTSTRAP_AUTHORITY`, so an attacker
  cannot front-run config creation and pin their own `trusted_signer`.
- **P0-2 fixed** — the escrow token account is pinned to the canonical ATA of
  `(vault, mint)`; a `Settle` for one pool can no longer debit another.
- **P1** — `refund` implemented as a pause-authority emergency withdraw (no more
  permanently-stuck funds); the `Escrow` state account was dropped (removing the
  depositor-overwrite footgun).
- Ed25519 restricted to a **preceding** instruction (`load_current_index_checked`).
- Signing uses `ctx.bumps.vault` (less state dependence).
- Toolchain: anchor pinned to **0.32.1**; `[profile.release] overflow-checks` added
  to both the Anchor-root and program manifests (unblocks `anchor build`).

Still open / for Codex:
- **SBF build not yet green.** The previous lockfile pulled `block-buffer 0.12.1`
  (edition 2024), which SBF Rust 1.79 rejects. `Cargo.lock` is removed here —
  regenerate with the SBF toolchain (pin `block-buffer` to an edition-2021 version
  if needed) and commit the authoritative lockfile.
- `declare_id!` + `BOOTSTRAP_AUTHORITY` placeholders — set real keys before deploy.
- Ed25519 malicious-offset + Settle / Hold / double-release **SBF integration tests**.
- Token-2022 (`token_interface`) only if the demo mint uses extensions.

## Next increments

1. Off-chain: emit the canonical `ReleaseAuthorization` bytes + Ed25519 signature
   from the `liquet` verdict (single-source the layout — shared crate).
2. Devnet demo: Settle → release succeeds; F2-delegate Hold → release rejected,
   escrow balance unchanged (the pair).
