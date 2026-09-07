/**
 * `did:nostr` compatibility (DESIGN.md §5).
 *
 * RA does not define a DID method. This produces the `did:nostr` *view* of a key
 * it already holds, offline, from the public key alone — the draft's "minimal
 * resolution". No HTTP `.well-known` tier (§5.3): that reintroduces a domain as a
 * trust anchor, which §3 exists to remove.
 *
 * The `did:nostr` method is an unratified community draft. Re-verify these
 * details against the current draft before relying on them.
 */

import { normalizePubkey } from "./keys.js";

export interface VerificationMethod {
  id: string;
  type: "Multikey";
  controller: string;
  publicKeyMultibase: string;
}

export interface DidDocument {
  "@context": string[];
  id: string;
  type: "DIDNostr";
  verificationMethod: VerificationMethod[];
  authentication: string[];
  assertionMethod: string[];
  service?: { id: string; type: string; serviceEndpoint: string | string[] }[];
}

/**
 * Multikey encoding of an x-only key (§5.2):
 *
 *   1. x-only (32 bytes) -> compressed secp256k1 (33 bytes) by prepending 0x02
 *   2. prepend the multicodec varint for secp256k1-pub: 0xe7 0x01
 *   3. multibase base16-lower: prefix `f`, then lowercase hex
 *
 * i.e. `publicKeyMultibase` = `f` + `e701` + `02` + `<x-only hex>`.
 */
export function xonlyToMultikey(pubkeyHex: string): string {
  const hex = normalizePubkey(pubkeyHex);
  return "f" + "e701" + "02" + hex;
}

/** Decode a Multikey string back to x-only hex, or throw if it is not the expected shape. */
export function multikeyToXonly(multikey: string): string {
  const m = /^fe70102([0-9a-f]{64})$/.exec(multikey);
  if (!m) throw new TypeError("not an x-only secp256k1 Multikey (f e701 02 <hex>)");
  return m[1];
}

export interface DidDocumentOptions {
  /** Optional relay endpoints for a `service` entry ("enhanced resolution", OPTIONAL for RA). */
  relays?: string[];
}

/** Produce the `did:nostr` document for a public key, offline. */
export function didDocument(pubkey: string, opts: DidDocumentOptions = {}): DidDocument {
  const hex = normalizePubkey(pubkey);
  const did = "did:nostr:" + hex;
  const vmId = did + "#0";
  const doc: DidDocument = {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/multikey/v1",
    ],
    id: did,
    type: "DIDNostr",
    verificationMethod: [
      {
        id: vmId,
        type: "Multikey",
        controller: did,
        publicKeyMultibase: xonlyToMultikey(hex),
      },
    ],
    authentication: [vmId],
    assertionMethod: [vmId],
  };
  if (opts.relays && opts.relays.length > 0) {
    doc.service = [
      {
        id: did + "#relays",
        type: "NostrRelays",
        serviceEndpoint: opts.relays.length === 1 ? opts.relays[0] : opts.relays,
      },
    ];
  }
  return doc;
}
