/**
 * The four DID event kinds and their kind-specific validation (DESIGN.md §3–§4,
 * verification step 4).
 *
 * The kind numbers are PROVISIONAL (DESIGN.md §8). They live here, in one place,
 * so that a reassignment through the NIP process is a one-line change.
 */

import type { NostrEvent } from "./event.js";

export const KIND_IDENTITY_ATTESTATION = 30100;
export const KIND_GUARDIAN_SET = 30101;
export const KIND_ROTATION_ATTESTATION = 30102;
export const KIND_ROTATION_CLAIM = 30103;

export const DID_KINDS = [
  KIND_IDENTITY_ATTESTATION,
  KIND_GUARDIAN_SET,
  KIND_ROTATION_ATTESTATION,
  KIND_ROTATION_CLAIM,
] as const;

/** §3.2 verification methods. Unknown methods are treated as no stronger than `asserted`. */
export const METHODS = [
  "in-person",
  "qr",
  "existing-channel",
  "guardian",
  "asserted",
] as const;
export type Method = (typeof METHODS)[number] | string;

/** §3.3 reserved claim attributes. `claim` attributes are otherwise open. */
export const CLAIM_ATTRIBUTES = ["name", "same-as", "nip05", "not"] as const;

/** §4.2 rotation reasons. */
export const ROTATION_REASONS = ["lost", "compromised", "planned"] as const;
export type RotationReason = (typeof ROTATION_REASONS)[number];

const HEX64 = /^[0-9a-f]{64}$/;

const first = (ev: NostrEvent, name: string): string | undefined => {
  const t = ev.tags.find((t) => t[0] === name);
  return t && t.length > 1 ? t[1] : undefined;
};
const all = (ev: NostrEvent, name: string): string[] =>
  ev.tags.filter((t) => t.length > 1 && t[0] === name).map((t) => t[1]);
const has = (ev: NostrEvent, name: string): boolean =>
  ev.tags.some((t) => t[0] === name);

export interface KindCheck {
  ok: boolean;
  reason?: string;
}

/**
 * Step 4: kind-specific validation. An event whose `kind` is not one of the DID
 * kinds passes here unconditionally — this library does not police generic
 * Nostr events.
 */
export function validateKind(ev: NostrEvent): KindCheck {
  switch (ev.kind) {
    case KIND_IDENTITY_ATTESTATION:
      return validateAttestation(ev);
    case KIND_GUARDIAN_SET:
      return validateGuardianSet(ev);
    case KIND_ROTATION_ATTESTATION:
      return validateRotationAttestation(ev);
    case KIND_ROTATION_CLAIM:
      return validateRotationClaim(ev);
    default:
      return { ok: true };
  }
}

function validateAttestation(ev: NostrEvent): KindCheck {
  const d = first(ev, "d");
  const p = first(ev, "p");
  if (!d || !HEX64.test(d)) return { ok: false, reason: "kind 30100: `d` MUST be the subject pubkey (64 lowercase hex)" };
  if (!p || !HEX64.test(p)) return { ok: false, reason: "kind 30100: `p` MUST be the subject pubkey (64 lowercase hex)" };
  if (d !== p) return { ok: false, reason: "kind 30100: `d` and `p` MUST both be the subject pubkey" };

  const revoked = has(ev, "revoked");
  const claims = ev.tags.filter((t) => t[0] === "claim");

  if (revoked) {
    if (claims.length > 0) {
      return { ok: false, reason: "kind 30100: a revocation MUST carry no `claim` tags" };
    }
    return { ok: true };
  }
  if (claims.length < 1) {
    return { ok: false, reason: "kind 30100: requires >=1 `claim` tag" };
  }
  for (const c of claims) {
    if (c.length < 3) {
      return { ok: false, reason: "kind 30100: each `claim` tag is [\"claim\", <attribute>, <value>]" };
    }
  }
  if (!has(ev, "method")) {
    return { ok: false, reason: "kind 30100: requires a `method` tag" };
  }
  return { ok: true };
}

function validateGuardianSet(ev: NostrEvent): KindCheck {
  if (first(ev, "d") !== "guardians") {
    return { ok: false, reason: 'kind 30101: `d` MUST be the literal "guardians"' };
  }
  const guardians = all(ev, "p");
  if (guardians.length < 1) {
    return { ok: false, reason: "kind 30101: requires >=1 `p` (guardian) tag" };
  }
  if (guardians.some((g) => !HEX64.test(g))) {
    return { ok: false, reason: "kind 30101: guardian pubkeys MUST be 64 lowercase hex" };
  }
  if (new Set(guardians).size !== guardians.length) {
    return { ok: false, reason: "kind 30101: duplicate guardian pubkey" };
  }
  const mRaw = first(ev, "threshold");
  if (mRaw === undefined || !/^\d+$/.test(mRaw)) {
    return { ok: false, reason: "kind 30101: requires an integer `threshold`" };
  }
  const m = Number(mRaw);
  if (m < 1 || m > guardians.length) {
    return { ok: false, reason: "kind 30101: requires 1 <= M <= N" };
  }
  return { ok: true };
}

function validateRotationAttestation(ev: NostrEvent): KindCheck {
  const d = first(ev, "d");
  const p = first(ev, "p");
  const n = first(ev, "new");
  if (!d || !HEX64.test(d)) return { ok: false, reason: "kind 30102: `d` MUST be the old pubkey (64 lowercase hex)" };
  if (!p || !HEX64.test(p)) return { ok: false, reason: "kind 30102: `p` MUST be the old pubkey (64 lowercase hex)" };
  if (!n || !HEX64.test(n)) return { ok: false, reason: "kind 30102: `new` MUST be the endorsed pubkey (64 lowercase hex)" };
  if (!has(ev, "method")) return { ok: false, reason: "kind 30102: requires a `method` tag" };
  return { ok: true };
}

function validateRotationClaim(ev: NostrEvent): KindCheck {
  const d = first(ev, "d");
  const p = first(ev, "p");
  if (!d || !HEX64.test(d)) return { ok: false, reason: "kind 30103: `d` MUST be the old pubkey (64 lowercase hex)" };
  if (!p || !HEX64.test(p)) return { ok: false, reason: "kind 30103: `p` MUST be the old pubkey (64 lowercase hex)" };
  const reason = first(ev, "reason");
  if (reason === undefined || !(ROTATION_REASONS as readonly string[]).includes(reason)) {
    return { ok: false, reason: "kind 30103: `reason` MUST be lost|compromised|planned" };
  }
  return { ok: true };
}
