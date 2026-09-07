/**
 * Library-level round trips that do not depend on the shared vectors:
 * encodings, the attestation and rotation builders, and the did:nostr view.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  generateIdentity,
  publicKeyFromSecret,
  hexToNpub,
  npubToHex,
  secretToNsec,
  nsecToSecret,
  normalizePubkey,
  hexToDid,
  didToHex,
  verifyEvent,
  createAttestation,
  revokeAttestation,
  parseAttestation,
  createGuardianSet,
  createRotationClaim,
  createRotationAttestation,
  evaluateRotation,
  didDocument,
  xonlyToMultikey,
  multikeyToXonly,
  DEFAULT_COOLDOWN_SECONDS,
} from "../src/index.js";

test("identity generation and derivation agree", () => {
  const id = generateIdentity();
  assert.match(id.pubkey, /^[0-9a-f]{64}$/);
  assert.equal(publicKeyFromSecret(id.secretHex), id.pubkey);
});

test("npub / nsec / did round trips", () => {
  const { secretHex, pubkey } = generateIdentity();
  assert.equal(npubToHex(hexToNpub(pubkey)), pubkey);
  assert.equal(nsecToSecret(secretToNsec(secretHex)), secretHex);
  assert.equal(didToHex(hexToDid(pubkey)), pubkey);
  assert.equal(normalizePubkey(hexToNpub(pubkey)), pubkey);
  assert.equal(normalizePubkey(pubkey.toUpperCase()), pubkey);
});

test("npubToHex rejects an nsec", () => {
  const { secretHex } = generateIdentity();
  assert.throws(() => npubToHex(secretToNsec(secretHex)));
});

test("attestation builds, verifies and parses", () => {
  const attester = generateIdentity();
  const subject = generateIdentity();
  const ev = createAttestation(
    {
      subject: subject.pubkey,
      claims: [
        { attribute: "name", value: "alice" },
        { attribute: "nip05", value: "alice@example.com" },
      ],
      method: "in-person",
    },
    attester.secretHex,
  );
  assert.ok(verifyEvent(ev).ok);
  const p = parseAttestation(ev);
  assert.equal(p.attester, attester.pubkey);
  assert.equal(p.subject, subject.pubkey);
  assert.equal(p.method, "in-person");
  assert.equal(p.claims.length, 2);
});

test("revocation verifies and carries no claims", () => {
  const attester = generateIdentity();
  const subject = generateIdentity();
  const ev = revokeAttestation(subject.pubkey, "key rotated", attester.secretHex);
  assert.ok(verifyEvent(ev).ok);
  assert.equal(parseAttestation(ev).revoked, "key rotated");
  assert.equal(parseAttestation(ev).claims.length, 0);
});

test("attestation needs at least one claim", () => {
  const a = generateIdentity();
  assert.throws(() =>
    createAttestation({ subject: a.pubkey, claims: [], method: "asserted" }, a.secretHex),
  );
});

test("guardian rotation: happy path accepts past the cool-down", () => {
  const old = generateIdentity();
  const next = generateIdentity();
  const g1 = generateIdentity();
  const g2 = generateIdentity();
  const g3 = generateIdentity();

  const t0 = 1_700_000_000;
  const claimAt = t0 + DEFAULT_COOLDOWN_SECONDS + 3600;

  const events = [
    createGuardianSet(
      { guardians: [g1.pubkey, g2.pubkey, g3.pubkey], threshold: 2, created_at: t0 },
      old.secretHex,
    ),
    createRotationClaim({ oldPubkey: old.pubkey, reason: "lost", created_at: claimAt }, next.secretHex),
    createRotationAttestation(
      { oldPubkey: old.pubkey, newPubkey: next.pubkey, method: "in-person", created_at: claimAt + 60 },
      g1.secretHex,
    ),
    createRotationAttestation(
      { oldPubkey: old.pubkey, newPubkey: next.pubkey, method: "existing-channel", created_at: claimAt + 120 },
      g2.secretHex,
    ),
  ];
  for (const ev of events) {
    const r = verifyEvent(ev);
    assert.ok(r.ok, r.reason ?? "verify failed");
  }

  const verdict = evaluateRotation(events);
  assert.equal(verdict.accepted, true, verdict.reason);
  assert.equal(verdict.new, next.pubkey);
  assert.equal(verdict.old, old.pubkey);
});

test("guardian rotation: a fresh guardian set inside its cool-down does not count", () => {
  const old = generateIdentity();
  const next = generateIdentity();
  const g1 = generateIdentity();
  const g2 = generateIdentity();

  const claimAt = 1_800_000_000;
  const events = [
    // installed only an hour before the claim
    createGuardianSet(
      { guardians: [g1.pubkey, g2.pubkey], threshold: 2, created_at: claimAt - 3600 },
      old.secretHex,
    ),
    createRotationClaim({ oldPubkey: old.pubkey, reason: "compromised", created_at: claimAt }, next.secretHex),
    createRotationAttestation(
      { oldPubkey: old.pubkey, newPubkey: next.pubkey, method: "existing-channel", created_at: claimAt + 60 },
      g1.secretHex,
    ),
    createRotationAttestation(
      { oldPubkey: old.pubkey, newPubkey: next.pubkey, method: "existing-channel", created_at: claimAt + 90 },
      g2.secretHex,
    ),
  ];
  assert.equal(evaluateRotation(events).accepted, false);
});

test("self-authorised rotation via prev-sig needs no guardians", () => {
  const old = generateIdentity();
  const next = generateIdentity();
  const claim = createRotationClaim(
    { oldPubkey: old.pubkey, reason: "planned", oldSecretHexForPrevSig: old.secretHex },
    next.secretHex,
  );
  assert.ok(verifyEvent(claim).ok);
  const verdict = evaluateRotation([claim]);
  assert.equal(verdict.accepted, true, verdict.reason);
  assert.equal(verdict.new, next.pubkey);
});

test("did:nostr document and Multikey round trip", () => {
  const { pubkey } = generateIdentity();
  const doc = didDocument(pubkey, { relays: ["wss://relay.example"] });
  assert.equal(doc.id, "did:nostr:" + pubkey);
  assert.equal(doc.type, "DIDNostr");
  assert.equal(doc.verificationMethod[0].publicKeyMultibase, "fe70102" + pubkey);
  assert.equal(multikeyToXonly(xonlyToMultikey(pubkey)), pubkey);
  assert.equal(doc.authentication[0], "did:nostr:" + pubkey + "#0");
  assert.ok(doc.service && doc.service.length === 1);
});
