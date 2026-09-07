/**
 * Guardians, rotation and recovery (DESIGN.md §4, drafts/social-recovery.md).
 *
 *   - kind 30101 Guardian Set        — signed by the root identity
 *   - kind 30103 Rotation Claim      — signed by the new key
 *   - kind 30102 Rotation Attestation — signed by a guardian, one per guardian
 *
 * Plus {@link evaluateRotation}, the normative acceptance rule (§4.3). This is a
 * direct port of `did-vectors/acceptance.py`; the two are kept in step.
 */

import {
  signEvent,
  schnorrSignRaw,
  schnorrVerifyRaw,
  type NostrEvent,
} from "./event.js";
import {
  KIND_GUARDIAN_SET,
  KIND_ROTATION_ATTESTATION,
  KIND_ROTATION_CLAIM,
  type Method,
  type RotationReason,
} from "./kinds.js";
import { normalizePubkey, publicKeyFromSecret } from "./keys.js";

/** Default guardian-set cool-down: 7 days, in seconds (§4.3 clause 5). */
export const DEFAULT_COOLDOWN_SECONDS = 7 * 24 * 60 * 60;

/** Small allowance for a Rotation Claim dated slightly ahead of the verifier's clock. */
export const DEFAULT_CLOCK_SKEW_SECONDS = 5 * 60;

// --- builders ----------------------------------------------------------

export interface GuardianSetInput {
  guardians: string[]; // hex or npub
  threshold: number;
  created_at?: number;
}

/** Build and sign a kind 30101 Guardian Set. */
export function createGuardianSet(
  input: GuardianSetInput,
  rootSecretHex: string,
  auxRand?: Uint8Array,
): NostrEvent {
  const guardians = input.guardians.map(normalizePubkey);
  if (guardians.length < 1) throw new TypeError("a guardian set needs at least one guardian");
  if (new Set(guardians).size !== guardians.length) throw new TypeError("duplicate guardian");
  if (!Number.isInteger(input.threshold) || input.threshold < 1 || input.threshold > guardians.length) {
    throw new TypeError("threshold must be an integer in 1..N");
  }
  return signEvent(
    {
      kind: KIND_GUARDIAN_SET,
      tags: [
        ["d", "guardians"],
        ...guardians.map((g) => ["p", g]),
        ["threshold", String(input.threshold)],
      ],
      content: "",
      created_at: input.created_at,
    },
    rootSecretHex,
    auxRand,
  );
}

export interface RotationClaimInput {
  oldPubkey: string; // hex or npub
  reason: RotationReason;
  /** Include a `prev-sig` when the old key is still held (self-authorised, §4.3). */
  oldSecretHexForPrevSig?: string;
  created_at?: number;
}

/** Build and sign a kind 30103 Rotation Claim (signed by the NEW key). */
export function createRotationClaim(
  input: RotationClaimInput,
  newSecretHex: string,
  auxRand?: Uint8Array,
): NostrEvent {
  const old = normalizePubkey(input.oldPubkey);
  const tags: string[][] = [
    ["d", old],
    ["p", old],
    ["reason", input.reason],
  ];
  if (input.oldSecretHexForPrevSig) {
    const newPubkey = publicKeyFromSecret(newSecretHex);
    tags.push(["prev-sig", schnorrSignRaw(newPubkey, input.oldSecretHexForPrevSig)]);
  }
  return signEvent(
    { kind: KIND_ROTATION_CLAIM, tags, content: "", created_at: input.created_at },
    newSecretHex,
    auxRand,
  );
}

export interface RotationAttestationInput {
  oldPubkey: string; // hex or npub
  newPubkey: string; // hex or npub
  method: Method;
  created_at?: number;
}

/** Build and sign a kind 30102 Rotation Attestation (signed by a GUARDIAN). */
export function createRotationAttestation(
  input: RotationAttestationInput,
  guardianSecretHex: string,
  auxRand?: Uint8Array,
): NostrEvent {
  const old = normalizePubkey(input.oldPubkey);
  return signEvent(
    {
      kind: KIND_ROTATION_ATTESTATION,
      tags: [
        ["d", old],
        ["p", old],
        ["new", normalizePubkey(input.newPubkey)],
        ["method", String(input.method)],
      ],
      content: "",
      created_at: input.created_at,
    },
    guardianSecretHex,
    auxRand,
  );
}

/** Compute a `prev-sig`: BIP-340 by the old key over the 32 raw new-pubkey bytes. */
export function prevSig(newPubkeyHex: string, oldSecretHex: string): string {
  return schnorrSignRaw(normalizePubkey(newPubkeyHex), oldSecretHex);
}

// --- the acceptance rule (§4.3) --------------------------------------

export interface RotationVerdict {
  accepted: boolean;
  reason: string;
  /** On acceptance: the successor key a client should migrate to. */
  new?: string;
  /** On acceptance: the key being rotated away from. */
  old?: string;
}

export interface EvaluateOptions {
  cooldownSeconds?: number;
  /** Verifier's notion of "now"; a claim dated beyond this + skew is rejected. */
  now?: number;
  clockSkewSeconds?: number;
}

const tag = (ev: NostrEvent, name: string): string | undefined => {
  const t = ev.tags.find((t) => t[0] === name);
  return t && t.length > 1 ? t[1] : undefined;
};
const tagValues = (ev: NostrEvent, name: string): string[] =>
  ev.tags.filter((t) => t.length > 1 && t[0] === name).map((t) => t[1]);

/**
 * Decide whether some `new` key is the accepted successor of some `old` key,
 * given a bag of events. Assumes every event is already well-formed and its
 * signature and id verified — run {@link verifyEvent} on each first.
 *
 * Mirrors `did-vectors/acceptance.py`.
 */
export function evaluateRotation(
  events: NostrEvent[],
  opts: EvaluateOptions = {},
): RotationVerdict {
  const cooldown = opts.cooldownSeconds ?? DEFAULT_COOLDOWN_SECONDS;
  const skew = opts.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;

  // clause 4: a Rotation Claim (kind 30103). Take the earliest.
  const claims = events
    .filter((e) => e.kind === KIND_ROTATION_CLAIM)
    .sort((a, b) => a.created_at - b.created_at);
  if (claims.length === 0) {
    return { accepted: false, reason: "clause 4: no kind 30103 Rotation Claim" };
  }
  const claim = claims[0];
  const old = tag(claim, "d");
  const next = claim.pubkey;
  const ct = claim.created_at;
  if (!old) {
    return { accepted: false, reason: "clause 4: Rotation Claim has no `d` (old pubkey)" };
  }
  if (next === old) {
    return { accepted: false, reason: "clause 4: Rotation Claim does not name a distinct successor key" };
  }
  if (opts.now !== undefined && ct > opts.now + skew) {
    return { accepted: false, reason: "clause 5: Rotation Claim is dated in the future" };
  }

  // clause 4 (self-authorised): a valid prev-sig by old over the new pubkey.
  const ps = tag(claim, "prev-sig");
  if (ps !== undefined) {
    if (schnorrVerifyRaw(ps, next, old)) {
      return {
        accepted: true,
        reason: "self-authorised: valid prev-sig by old over new",
        new: next,
        old,
      };
    }
    // invalid prev-sig -> ignored; fall through to the guardian path
  }

  // clause 1: a Guardian Set (kind 30101, d=guardians) signed by old.
  const gsets = events.filter(
    (e) => e.kind === KIND_GUARDIAN_SET && e.pubkey === old && tag(e, "d") === "guardians",
  );
  if (gsets.length === 0) {
    return { accepted: false, reason: "clause 1: no Guardian Set signed by old" };
  }

  // clause 5: use the most recent set that is both current at the claim and past its cool-down.
  const eligible = gsets.filter((g) => g.created_at + cooldown <= ct);
  if (eligible.length === 0) {
    return {
      accepted: false,
      reason: "clause 5: no Guardian Set is both current at the claim and past its cool-down",
    };
  }
  const gset = eligible.reduce((a, b) => (b.created_at > a.created_at ? b : a));
  const guardians = new Set(tagValues(gset, "p"));
  const mRaw = tag(gset, "threshold");
  const threshold = mRaw !== undefined && /^\d+$/.test(mRaw) ? Number(mRaw) : NaN;
  if (!Number.isFinite(threshold)) {
    return { accepted: false, reason: "clause 1: Guardian Set has no valid threshold" };
  }
  if (!(threshold >= 1 && threshold <= guardians.size)) {
    return { accepted: false, reason: "clause 1: Guardian Set threshold out of range 1..N" };
  }

  // clauses 2 + 3: >= M distinct guardians, each signing their own kind 30102
  //                for this old, all naming an identical new.
  const endorsers = new Map<string, Set<string>>();
  let ignoredNonGuardian = 0;
  for (const a of events) {
    if (a.kind !== KIND_ROTATION_ATTESTATION || tag(a, "d") !== old) continue;
    if (!guardians.has(a.pubkey)) {
      ignoredNonGuardian += 1;
      continue;
    }
    const n = tag(a, "new");
    if (n === undefined) continue;
    if (!endorsers.has(n)) endorsers.set(n, new Set());
    endorsers.get(n)!.add(a.pubkey);
  }

  const have = endorsers.get(next)?.size ?? 0;
  if (have >= threshold) {
    return {
      accepted: true,
      reason: `guardian path: ${have} of ${threshold} distinct guardians endorsed new`,
      new: next,
      old,
    };
  }
  const note = ignoredNonGuardian
    ? ` (${ignoredNonGuardian} endorsement(s) ignored: not in guardian set)`
    : "";
  return {
    accepted: false,
    reason: `clause 2: ${have} distinct guardians endorsed the claimed new key, need ${threshold}${note}`,
  };
}
