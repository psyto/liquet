# Signed release-payment binding

The existing Liquet signature is unchanged:

```text
SHA-256("liquet/decision/v2\0" || serde_json(DecisionBinding))
Ed25519-sign(digest)
```

For a custody/PSP release path, the signed `binding` JSON **must** include this
additional field, in the same field order shown below (after `decision`):

```json
"release_payment": {
  "settlement_id": "custodian-settlement-id",
  "recipient": "the exact destination account",
  "amount": 4000000,
  "mint": "the exact asset or mint identifier",
  "expires_at": 2000000000
}
```

`src/attest.rs` is the source of truth for `DecisionBinding` serialization and
the digest domain. `release_payment` is optional only so generic, pre-existing
Liquet attestations remain readable; a release gate must Hold when it is absent.
The duplicated `release_payment.settlement_id` must equal the top-level signed
`binding.settlement_id`.

The TypeScript implementation receives the JSON emitted by Liquet, reconstructs
the top-level binding object in the Rust field order, hashes its compact JSON,
and verifies raw Ed25519 public-key bytes. It must not use a custom payload or
accept unsigned payment fields beside the signed verdict.

JavaScript `number` is exact only through `2^53 - 1`. The supplied TS reference
fails closed for a larger `amount`; production PSPs that need the full Rust
`u64` range must use a lossless JSON/decimal-integer adapter before recreating
the signed JSON bytes.
