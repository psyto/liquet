/**
 * Host-side TypeScript mirror of the Rust `liquet-release-gate` contract.
 * It decides only whether the caller's own release path may proceed.
 */
import { createHash, createPublicKey, verify } from "node:crypto";

export type PaymentToRelease = {
  recipient: string;
  amount: number;
  mint: string;
  settlement_id: string;
};

export type SignedDecision = {
  binding: Record<string, unknown> & {
    settlement_id: string;
    decision: { decision: "settle" | "hold"; reasons?: string[] };
    release_payment?: {
      settlement_id: string;
      recipient: string;
      amount: number;
      mint: string;
      expires_at: number;
    };
  };
  signer: string;
  signature: string;
};

export type ReleaseDecision =
  | { decision: "release" }
  | { decision: "hold"; reason: string };

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const DOMAIN = Buffer.from("liquet/decision/v2\0", "utf8");

/** Exact compact top-level field order used by Rust `DecisionBinding`. */
export function canonicalBindingJson(binding: SignedDecision["binding"]): string {
  const ordered: Record<string, unknown> = {
    settlement_id: binding.settlement_id,
    claim_hash: binding.claim_hash,
    legs: binding.legs,
    reconcile: binding.reconcile,
    invariant: binding.invariant,
    policy: binding.policy,
    decision: binding.decision,
  };
  if (binding.release_payment !== undefined) ordered.release_payment = binding.release_payment;
  return JSON.stringify(ordered);
}

function digest(binding: SignedDecision["binding"]): Buffer {
  return createHash("sha256").update(DOMAIN).update(canonicalBindingJson(binding), "utf8").digest();
}

function held(reason: string): ReleaseDecision {
  return { decision: "hold", reason };
}

/**
 * Verify a Liquet decision against a caller-pinned Ed25519 signer, then bind it
 * to the exact payout the caller is about to execute. `nowUnixSeconds` makes
 * test and batch use deterministic; production defaults to the local clock.
 */
export function checkRelease(
  payment: PaymentToRelease,
  verdict: SignedDecision,
  pinnedSignerHex: string,
  nowUnixSeconds = Math.floor(Date.now() / 1000),
): ReleaseDecision {
  if (!/^[0-9a-f]{64}$/i.test(pinnedSignerHex) || !/^[0-9a-f]{64}$/i.test(verdict.signer)) {
    return held("verdict signature rejected: malformed signer");
  }
  if (verdict.signer.toLowerCase() !== pinnedSignerHex.toLowerCase()) {
    return held("verdict signature rejected: signer mismatch");
  }
  try {
    const key = createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(pinnedSignerHex, "hex")]), format: "der", type: "spki" });
    if (!verify(null, digest(verdict.binding), key, Buffer.from(verdict.signature, "hex"))) {
      return held("verdict signature rejected: bad signature");
    }
  } catch {
    return held("verdict signature rejected: malformed signature");
  }

  const bound = verdict.binding.release_payment;
  if (!bound) return held("verdict has no signed release-payment binding");
  // Rust signs a u64. Plain JavaScript numbers cannot safely represent every
  // u64, so fail closed rather than rounding a custody amount during comparison.
  if (!Number.isSafeInteger(payment.amount) || !Number.isSafeInteger(bound.amount)) {
    return held("amount exceeds JavaScript safe-integer range; use a lossless JSON adapter");
  }
  if (bound.settlement_id !== verdict.binding.settlement_id) return held("verdict settlement_id conflicts with its signed release-payment binding");
  if (bound.settlement_id !== payment.settlement_id) return held("settlement_id does not match the payment about to be released");
  if (bound.recipient !== payment.recipient) return held("recipient does not match the payment about to be released");
  if (bound.amount !== payment.amount) return held("amount does not match the payment about to be released");
  if (bound.mint !== payment.mint) return held("mint does not match the payment about to be released");
  if (nowUnixSeconds > bound.expires_at) return held("verdict has expired");

  if (verdict.binding.decision.decision !== "settle") {
    return held(`Liquet verdict is Hold: ${(verdict.binding.decision.reasons ?? ["no reason supplied"]).join("; ")}`);
  }
  return { decision: "release" };
}
