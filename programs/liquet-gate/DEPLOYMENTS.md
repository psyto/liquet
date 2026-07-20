# liquet-gate — deployments

Liquet is a **non-custodial verifier**: it holds no funds and executes no
payouts. It issues an ed25519-signed `Settle` / `Hold` that a relying party's
own release path requires (see [`crates/liquet-release-gate`](../../crates/liquet-release-gate)).

`liquet-gate` (this program) is a **reference enforcement gate** — a stand-in
for a release path that requires the Liquet verdict. It is a demo/reference, not
the product and not custody.

Build the program with `cargo build-sbf --arch v3` (the default `v0` is rejected
by current validators).

## Devnet (live)

| | |
|---|---|
| Program id | `2Dt3t8PnHdZzWMxUfsoo7VyrDCCzc5mYAFoSqXhwJ6rx` |
| Cluster | devnet |
| Loader | BPFLoaderUpgradeable |
| Explorer | https://solscan.io/account/2Dt3t8PnHdZzWMxUfsoo7VyrDCCzc5mYAFoSqXhwJ6rx?cluster=devnet |

Program keypairs (id, bootstrap authority, verdict signer, payer) live under
`.keys/` and are **gitignored** — never commit them.

### Reference-gate run (real native Ed25519 + real SPL Token)

Driven end-to-end by [`./driver`](./driver):

```sh
LIQUET_GATE_RPC_URL=https://api.devnet.solana.com \
  cargo run --manifest-path driver/Cargo.toml
```

A recorded run — every case is a real, publicly verifiable devnet transaction:

| # | case | outcome | tx |
|---|---|---|---|
| 01 | benign settlement | **SETTLE** — escrow 10,000,000 → 6,000,000; recipient 0 → 4,000,000 (real SPL transfer) | [`5iYGuNtX…`](https://solscan.io/tx/5iYGuNtXoBoSRiwBs2TQUgYSormzkKUKK74qMc7VjrxqAgMXBQj5jKFVYUGey3gxKqnXQnR3qkHHjVjSzddcdWrE?cluster=devnet) |
| 02 | wrong recipient | **HOLD** — `6008 RecipientMismatch`; balances unchanged | [`3AHfw6N8…`](https://solscan.io/tx/3AHfw6N8qqAgANEvsLPyGM1XfBYr6J7f3a4Q4cCv3FnWQBSCRf9Ra82Y4gUVGQAcrz23PvN3Lt9CSEYpKVK1ZEqK?cluster=devnet) |
| 03 | half-open (paid, not delivered) | **HOLD** — `6003 NotSettle`; balances unchanged | [`pXbFUr3R…`](https://solscan.io/tx/pXbFUr3RKkpH2GSdFrpXx5smCp1LiVNieiAFkrVoNFCVnhtTX3Bag4B6hqkpvSeGoynzPb68z1A6Sn292EVP3Yp?cluster=devnet) |
| 04 | backdoored delivery (F2-delegate) | **HOLD** — `6003 NotSettle`; balances unchanged | [`2Yh738Ck…`](https://solscan.io/tx/2Yh738CkoaosKSAgGHUiMUkQ4FTStf512QmVF6G8Qjeyj4y3gaNnLqD86gM4ZYqTBmUxgHjztsmY7oYAx2g6EgY8?cluster=devnet) |

Only a pinned-signer, unexpired `Settle` bound to the exact settlement id,
recipient, amount, and mint releases funds. Every other case is a fail-closed
hold, on-chain, with the escrow unchanged.

> The config PDA (`seeds = [b"config"]`) is a singleton and is already
> initialized on devnet, so a re-run must skip `initialize`.
