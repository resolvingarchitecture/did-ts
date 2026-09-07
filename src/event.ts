/**
 * Signed records (DESIGN.md §2): Nostr events with a BIP-340 Schnorr signature,
 * and the normative four-step verification order.
 */

import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import {
  computeId,
  preimageBytes,
  type EventTemplate,
} from "./serialize.js";
import { isValidPubkey, publicKeyFromSecret } from "./keys.js";
import { validateKind } from "./kinds.js";

export interface NostrEvent {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig: string;
}

/** Fields a caller supplies; `pubkey`, `id` and `sig` are filled in by {@link signEvent}. */
export interface UnsignedEvent {
  created_at?: number;
  kind: number;
  tags?: string[][];
  content?: string;
}

const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;

/** Current unix time in whole seconds. */
export const now = (): number => Math.floor(Date.now() / 1000);

/**
 * Sign an event with a 32-byte secret hex.
 *
 * `auxRand` defaults to 32 zero bytes, which makes signatures byte-for-byte
 * reproducible (this is how `did-vectors` is generated). Pass real randomness in
 * production if you prefer; verification never depends on how a signature was
 * produced.
 */
export function signEvent(
  ev: UnsignedEvent,
  secretHex: string,
  auxRand: Uint8Array = new Uint8Array(32),
): NostrEvent {
  const template: EventTemplate = {
    pubkey: publicKeyFromSecret(secretHex),
    created_at: ev.created_at ?? now(),
    kind: ev.kind,
    tags: ev.tags ?? [],
    content: ev.content ?? "",
  };
  const id = computeId(template);
  const sig = bytesToHex(
    schnorr.sign(hexToBytes(id), hexToBytes(secretHex), auxRand),
  );
  return { id, ...template, sig };
}

export interface VerifyResult {
  ok: boolean;
  /** The verification step (1–4) that failed; absent on success. */
  step?: 1 | 2 | 3 | 4;
  reason?: string;
}

/**
 * Verify an event against DESIGN.md §2.2. Steps run in order and the first
 * failure is returned:
 *
 *   1. `pubkey` is 64 lowercase hex over a valid x-only point
 *   2. the recomputed `id` equals the stated `id` (and the stated `id` is
 *      itself 64 lowercase hex)
 *   3. the Schnorr signature verifies over the 32 raw `id` bytes
 *   4. kind-specific validation (§3, §4)
 *
 * Step 2 is not optional: an event whose `id` does not match its content is
 * malformed even if the signature verifies against the stated `id`.
 */
export function verifyEvent(ev: NostrEvent): VerifyResult {
  // Step 1
  if (typeof ev.pubkey !== "string" || !HEX64.test(ev.pubkey)) {
    return { ok: false, step: 1, reason: "pubkey is not 64 lowercase hex chars" };
  }
  if (!isValidPubkey(ev.pubkey)) {
    return { ok: false, step: 1, reason: "pubkey is not a valid x-only point" };
  }

  // Step 2
  if (typeof ev.id !== "string" || !HEX64.test(ev.id)) {
    return { ok: false, step: 2, reason: "id is not 64 lowercase hex chars" };
  }
  const recomputed = computeId(ev);
  if (recomputed !== ev.id) {
    return { ok: false, step: 2, reason: `id mismatch: computed ${recomputed}` };
  }

  // Step 3
  if (typeof ev.sig !== "string" || !HEX128.test(ev.sig)) {
    return { ok: false, step: 3, reason: "sig is not 128 lowercase hex chars" };
  }
  let sigOk = false;
  try {
    sigOk = schnorr.verify(
      hexToBytes(ev.sig),
      hexToBytes(ev.id),
      hexToBytes(ev.pubkey),
    );
  } catch {
    sigOk = false;
  }
  if (!sigOk) {
    return { ok: false, step: 3, reason: "Schnorr signature does not verify" };
  }

  // Step 4
  const kc = validateKind(ev);
  if (!kc.ok) {
    return { ok: false, step: 4, reason: kc.reason };
  }

  return { ok: true };
}

/** Convenience wrapper: throws with the failing step if verification fails. */
export function assertValid(ev: NostrEvent): void {
  const r = verifyEvent(ev);
  if (!r.ok) {
    throw new Error(`event verification failed at step ${r.step}: ${r.reason}`);
  }
}

/** BIP-340 verify of an arbitrary 32-byte message (used by `prev-sig`, §4.2). */
export function schnorrVerifyRaw(
  sigHex: string,
  msg32Hex: string,
  pubkeyHex: string,
): boolean {
  if (!HEX128.test(sigHex) || !HEX64.test(msg32Hex) || !HEX64.test(pubkeyHex)) {
    return false;
  }
  try {
    return schnorr.verify(
      hexToBytes(sigHex),
      hexToBytes(msg32Hex),
      hexToBytes(pubkeyHex),
    );
  } catch {
    return false;
  }
}

/** BIP-340 sign of an arbitrary 32-byte message (used to build a `prev-sig`). */
export function schnorrSignRaw(
  msg32Hex: string,
  secretHex: string,
  auxRand: Uint8Array = new Uint8Array(32),
): string {
  if (!HEX64.test(msg32Hex) || !HEX64.test(secretHex)) {
    throw new TypeError("message and secret key must each be 64 lowercase hex chars");
  }
  return bytesToHex(schnorr.sign(hexToBytes(msg32Hex), hexToBytes(secretHex), auxRand));
}

export { computeId, preimageBytes };
