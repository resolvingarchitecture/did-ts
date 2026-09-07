/**
 * The identity primitive (DESIGN.md §1): one secp256k1 keypair, x-only public
 * key per BIP-340, and its encodings.
 *
 *   - lowercase hex (64 chars) — canonical; the only form used in preimages
 *   - `npub1…` / `nsec1…` — Bech32 (NIP-19), for display and export only
 *   - `did:nostr:<hex>` — the W3C view (§5)
 *
 * `@noble/curves` provides BIP-340 Schnorr; `@scure/base` provides Bech32.
 * There is no hand-rolled secp256k1 here and there must never be.
 */

import { schnorr } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { bech32 } from "@scure/base";

const HEX64 = /^[0-9a-f]{64}$/;
const BECH32_LIMIT = 1_000; // NIP-19 keys exceed the default limit of 90

export interface Identity {
  /** 32-byte secret scalar, lowercase hex. Treat as sensitive — see §6.3. */
  readonly secretHex: string;
  /** 32-byte x-only public key, lowercase hex. The canonical identifier. */
  readonly pubkey: string;
}

/** True if `s` is 64 lowercase hex chars over a valid x-only curve point. */
export function isValidPubkey(s: string): boolean {
  if (!HEX64.test(s)) return false;
  try {
    schnorr.utils.lift_x(BigInt("0x" + s));
    return true;
  } catch {
    return false;
  }
}

/** Generate a fresh identity from the platform CSPRNG. */
export function generateIdentity(): Identity {
  const sk = schnorr.utils.randomSecretKey();
  return {
    secretHex: bytesToHex(sk),
    pubkey: bytesToHex(schnorr.getPublicKey(sk)),
  };
}

/** Derive the x-only public key (lowercase hex) from a 32-byte secret hex. */
export function publicKeyFromSecret(secretHex: string): string {
  if (!HEX64.test(secretHex)) {
    throw new TypeError("secret key must be 64 lowercase hex chars");
  }
  return bytesToHex(schnorr.getPublicKey(hexToBytes(secretHex)));
}

// --- encodings -----------------------------------------------------------

/** hex → `npub1…` */
export function hexToNpub(pubkeyHex: string): string {
  if (!HEX64.test(pubkeyHex)) {
    throw new TypeError("pubkey must be 64 lowercase hex chars");
  }
  return bech32.encode("npub", bech32.toWords(hexToBytes(pubkeyHex)), BECH32_LIMIT);
}

/** `npub1…` → hex. Rejects any other prefix. */
export function npubToHex(npub: string): string {
  const { prefix, words } = bech32.decode(npub as `npub1${string}`, BECH32_LIMIT);
  if (prefix !== "npub") throw new TypeError(`expected an npub, got ${prefix}`);
  const hex = bytesToHex(bech32.fromWords(words));
  if (!HEX64.test(hex)) throw new TypeError("npub does not decode to a 32-byte key");
  return hex;
}

/**
 * secret hex → `nsec1…`.
 *
 * Per §1.1 / §6.3 an implementation MUST NOT surface `nsec` incidentally. This
 * function exists so an export flow can call it deliberately; it is never used
 * by the library itself and callers must gate it behind explicit confirmation.
 */
export function secretToNsec(secretHex: string): string {
  if (!HEX64.test(secretHex)) {
    throw new TypeError("secret key must be 64 lowercase hex chars");
  }
  return bech32.encode("nsec", bech32.toWords(hexToBytes(secretHex)), BECH32_LIMIT);
}

/** `nsec1…` → secret hex. */
export function nsecToSecret(nsec: string): string {
  const { prefix, words } = bech32.decode(nsec as `nsec1${string}`, BECH32_LIMIT);
  if (prefix !== "nsec") throw new TypeError(`expected an nsec, got ${prefix}`);
  const hex = bytesToHex(bech32.fromWords(words));
  if (!HEX64.test(hex)) throw new TypeError("nsec does not decode to a 32-byte key");
  return hex;
}

/** hex or `npub1…` → canonical lowercase hex. Accepts what §1.1 says to accept. */
export function normalizePubkey(input: string): string {
  const s = input.trim();
  if (s.startsWith("npub1")) return npubToHex(s);
  const lower = s.toLowerCase();
  if (!HEX64.test(lower)) {
    throw new TypeError("expected 64 hex chars or an npub");
  }
  return lower;
}

/** hex → `did:nostr:<hex>` (§5.1 — hex, not npub). */
export function hexToDid(pubkeyHex: string): string {
  if (!HEX64.test(pubkeyHex)) {
    throw new TypeError("pubkey must be 64 lowercase hex chars");
  }
  return "did:nostr:" + pubkeyHex;
}

/** `did:nostr:<hex>` → hex. */
export function didToHex(did: string): string {
  const m = /^did:nostr:([0-9a-f]{64})$/.exec(did);
  if (!m) throw new TypeError("expected did:nostr:<64 lowercase hex>");
  return m[1];
}
