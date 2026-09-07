/**
 * Identity attestations — the `vouch` primitive (DESIGN.md §3, drafts/attestations.md).
 *
 * Kind 30100, signed by the attester, addressable on the subject's pubkey so an
 * attester holds exactly one current attestation per subject.
 */

import { signEvent, type NostrEvent } from "./event.js";
import { KIND_IDENTITY_ATTESTATION, type Method } from "./kinds.js";
import { normalizePubkey } from "./keys.js";

export interface Claim {
  /** e.g. "name", "same-as", "nip05", "not" — the list is open (§3.3). */
  attribute: string;
  value: string;
}

export interface AttestationInput {
  /** The key being vouched for (hex or npub). */
  subject: string;
  /** At least one claim. */
  claims: Claim[];
  /** How the attester verified (§3.2). */
  method: Method;
  /** Optional NIP-40 expiration, unix seconds. */
  expiration?: number;
  created_at?: number;
}

/** Build and sign a kind 30100 Identity Attestation. */
export function createAttestation(
  input: AttestationInput,
  attesterSecretHex: string,
  auxRand?: Uint8Array,
): NostrEvent {
  if (input.claims.length < 1) {
    throw new TypeError("an attestation needs at least one claim");
  }
  const subject = normalizePubkey(input.subject);
  const tags: string[][] = [
    ["d", subject],
    ["p", subject],
    ...input.claims.map((c) => ["claim", c.attribute, c.value]),
    ["method", String(input.method)],
  ];
  if (input.expiration !== undefined) {
    tags.push(["expiration", String(input.expiration)]);
  }
  return signEvent(
    { kind: KIND_IDENTITY_ATTESTATION, tags, content: "", created_at: input.created_at },
    attesterSecretHex,
    auxRand,
  );
}

/**
 * Build and sign a revocation: the addressable event is replaced with one that
 * carries `["revoked", <reason>]` and no `claim` tags (§3.4). A verifier MUST
 * treat this differently from a missing attestation.
 */
export function revokeAttestation(
  subject: string,
  reason: string,
  attesterSecretHex: string,
  created_at?: number,
  auxRand?: Uint8Array,
): NostrEvent {
  const s = normalizePubkey(subject);
  return signEvent(
    {
      kind: KIND_IDENTITY_ATTESTATION,
      tags: [["d", s], ["p", s], ["revoked", reason]],
      content: "",
      created_at,
    },
    attesterSecretHex,
    auxRand,
  );
}

// --- reading -----------------------------------------------------------

export interface ParsedAttestation {
  attester: string;
  subject: string;
  claims: Claim[];
  method?: string;
  expiration?: number;
  revoked?: string;
}

/** Structured view of a kind 30100 event. Does not verify — call {@link verifyEvent} first. */
export function parseAttestation(ev: NostrEvent): ParsedAttestation {
  if (ev.kind !== KIND_IDENTITY_ATTESTATION) {
    throw new TypeError(`not a kind ${KIND_IDENTITY_ATTESTATION} event`);
  }
  const get = (n: string) => ev.tags.find((t) => t[0] === n)?.[1];
  const revoked = get("revoked");
  const exp = get("expiration");
  return {
    attester: ev.pubkey,
    subject: get("d") ?? "",
    claims: ev.tags
      .filter((t) => t[0] === "claim" && t.length >= 3)
      .map((t) => ({ attribute: t[1], value: t[2] })),
    method: get("method"),
    expiration: exp !== undefined ? Number(exp) : undefined,
    revoked,
  };
}

/** Is this attestation past its NIP-40 `expiration` at `at` (default: now)? */
export function isExpired(ev: NostrEvent, at: number = Math.floor(Date.now() / 1000)): boolean {
  const exp = ev.tags.find((t) => t[0] === "expiration")?.[1];
  return exp !== undefined && Number(exp) <= at;
}
