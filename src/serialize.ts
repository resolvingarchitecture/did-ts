/**
 * Canonical NIP-01 / DESIGN.md §2.1 serialisation.
 *
 * The signature preimage is the UTF-8 encoding of
 *
 *     [0,<pubkey>,<created_at>,<kind>,<tags>,<content>]
 *
 * serialised as compact JSON with **no whitespace anywhere**. In strings, only
 * the seven escapes below are emitted; every other character, including all
 * multi-byte UTF-8, is written literally (no `\/`, no `\uXXXX`).
 *
 * This is hand-rolled rather than delegated to `JSON.stringify` on purpose:
 * `JSON.stringify` also escapes lone control characters as `\uXXXX`, which the
 * spec forbids. Getting this exactly right is what makes signatures reproduce
 * across the four language ports.
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";

/** The unsigned fields of an event, in canonical order. */
export interface EventTemplate {
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
}

const ESCAPES: Record<number, string> = {
  0x22: '\\"',
  0x5c: "\\\\",
  0x0a: "\\n",
  0x0d: "\\r",
  0x09: "\\t",
  0x08: "\\b",
  0x0c: "\\f",
};

/** Serialise one JSON string with the seven allowed escapes and nothing else. */
export function serializeString(s: string): string {
  let out = '"';
  for (const ch of s) {
    const cp = ch.codePointAt(0)!;
    out += ESCAPES[cp] ?? ch;
  }
  return out + '"';
}

function serializeInt(n: number): string {
  if (!Number.isInteger(n)) {
    throw new TypeError(`expected an integer, got ${n}`);
  }
  return String(n);
}

function serializeTags(tags: string[][]): string {
  return (
    "[" +
    tags
      .map((tag) => "[" + tag.map(serializeString).join(",") + "]")
      .join(",") +
    "]"
  );
}

/** The exact string that gets hashed to produce the event `id`. */
export function serializeEvent(ev: EventTemplate): string {
  return (
    "[0," +
    serializeString(ev.pubkey) +
    "," +
    serializeInt(ev.created_at) +
    "," +
    serializeInt(ev.kind) +
    "," +
    serializeTags(ev.tags) +
    "," +
    serializeString(ev.content) +
    "]"
  );
}

/** UTF-8 bytes of the canonical preimage. */
export function preimageBytes(ev: EventTemplate): Uint8Array {
  return new TextEncoder().encode(serializeEvent(ev));
}

/** The event id: lowercase hex of sha256 over the canonical preimage. */
export function computeId(ev: EventTemplate): string {
  return bytesToHex(sha256(preimageBytes(ev)));
}
