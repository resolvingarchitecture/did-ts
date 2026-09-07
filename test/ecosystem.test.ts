/**
 * Ecosystem check (DESIGN.md §10): an event produced by did-ts MUST validate in
 * an unmodified third-party Nostr library. Here that library is nostr-tools.
 *
 * This is what "Nostr-compatible" has to mean in practice — software that has
 * never heard of Resolving Architecture can still check the signature.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { verifyEvent as nostrVerify } from "nostr-tools";

import {
  generateIdentity,
  signEvent,
  createAttestation,
  createGuardianSet,
  createRotationClaim,
  type NostrEvent,
} from "../src/index.js";

const events = JSON.parse(
  readFileSync(fileURLToPath(new URL("./vectors/events.json", import.meta.url)), "utf8"),
);

test("did-ts events verify under nostr-tools", () => {
  const alice = generateIdentity();
  const bob = generateIdentity();

  const note = signEvent({ kind: 1, content: "móving to a new 🔑", tags: [["t", "did"]] }, alice.secretHex);
  const attestation = createAttestation(
    { subject: alice.pubkey, claims: [{ attribute: "name", value: "alice" }], method: "in-person" },
    bob.secretHex,
  );
  const gset = createGuardianSet(
    { guardians: [generateIdentity().pubkey, generateIdentity().pubkey], threshold: 2 },
    alice.secretHex,
  );
  const claim = createRotationClaim({ oldPubkey: alice.pubkey, reason: "planned" }, generateIdentity().secretHex);

  for (const ev of [note, attestation, gset, claim]) {
    assert.ok(nostrVerify(ev as never), `nostr-tools rejected a did-ts ${ev.kind} event`);
  }
});

test("shared valid_events verify under nostr-tools", () => {
  for (const c of events.valid_events) {
    assert.ok(nostrVerify(c.event as never), `nostr-tools rejected vector ${c.name}`);
  }
});

test("nostr-tools also rejects the 'any' invalid_events", () => {
  for (const c of events.invalid_events) {
    if (c.rejected_by !== "any") continue; // 'did'-only cases: a permissive verifier accepts them
    assert.equal(nostrVerify(c.event as NostrEvent as never), false, `nostr-tools accepted ${c.name}`);
  }
});
