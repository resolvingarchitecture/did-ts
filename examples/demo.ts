/**
 * End-to-end walkthrough of did-ts. Run with:
 *
 *     npm run example
 *
 * It creates identities, has one vouch for another, produces the did:nostr view,
 * then loses a key and recovers it through guardians — printing each signed event
 * so you can see exactly what goes on the wire.
 */

import {
  generateIdentity,
  hexToNpub,
  hexToDid,
  verifyEvent,
  createAttestation,
  parseAttestation,
  createGuardianSet,
  createRotationClaim,
  createRotationAttestation,
  evaluateRotation,
  didDocument,
  DEFAULT_COOLDOWN_SECONDS,
  type NostrEvent,
} from "../src/index.js";

const rule = (s: string) => console.log("\n" + "─".repeat(4) + " " + s + " " + "─".repeat(40 - s.length));
const show = (label: string, ev: NostrEvent) => {
  const v = verifyEvent(ev);
  console.log(`${label}  [kind ${ev.kind}]  verify: ${v.ok ? "ok" : `FAIL step ${v.step} (${v.reason})`}`);
  console.log(JSON.stringify(ev));
};

// 1. Identities ---------------------------------------------------------
rule("identities");
const alice = generateIdentity();
const bob = generateIdentity();
console.log("alice  hex ", alice.pubkey);
console.log("       npub", hexToNpub(alice.pubkey));
console.log("       did ", hexToDid(alice.pubkey));
console.log("bob    hex ", bob.pubkey);

// 2. Attestation: bob vouches for alice's name, in person ------------
rule("attestation (bob -> alice)");
const attestation = createAttestation(
  {
    subject: alice.pubkey,
    claims: [
      { attribute: "name", value: "Alice" },
      { attribute: "nip05", value: "alice@example.com" },
    ],
    method: "in-person",
  },
  bob.secretHex,
);
show("bob's attestation", attestation);
const parsed = parseAttestation(attestation);
console.log("parsed:", JSON.stringify(parsed));

// 3. The did:nostr view of alice -------------------------------------
rule("did:nostr document for alice");
console.log(JSON.stringify(didDocument(alice.pubkey, { relays: ["wss://relay.example.com"] }), null, 2));

// 4. Alice designates guardians ------------------------------------
rule("guardian set");
const [g1, g2, g3] = [generateIdentity(), generateIdentity(), generateIdentity()];
const t0 = 1_700_000_000; // pretend the set has been in place a long time
const guardianSet = createGuardianSet(
  { guardians: [g1.pubkey, g2.pubkey, g3.pubkey], threshold: 2, created_at: t0 },
  alice.secretHex,
);
show("alice's guardian set (M=2 of 3)", guardianSet);

// 5. Alice loses her key. A new key claims succession, two guardians endorse.
rule("recovery");
const aliceNew = generateIdentity();
const claimAt = t0 + DEFAULT_COOLDOWN_SECONDS + 86_400; // well past the cool-down
const claim = createRotationClaim(
  { oldPubkey: alice.pubkey, reason: "lost", created_at: claimAt },
  aliceNew.secretHex,
);
const endorse1 = createRotationAttestation(
  { oldPubkey: alice.pubkey, newPubkey: aliceNew.pubkey, method: "in-person", created_at: claimAt + 3600 },
  g1.secretHex,
);
const endorse2 = createRotationAttestation(
  { oldPubkey: alice.pubkey, newPubkey: aliceNew.pubkey, method: "existing-channel", created_at: claimAt + 7200 },
  g2.secretHex,
);
show("rotation claim (signed by the new key)", claim);
show("guardian 1 endorses", endorse1);
show("guardian 2 endorses", endorse2);

const verdict = evaluateRotation([guardianSet, claim, endorse1, endorse2]);
rule("verdict");
console.log(verdict);
console.log(
  verdict.accepted
    ? `\nalice's identity is now ${hexToNpub(verdict.new!)}\n(a client migrates follows, contacts and prior attestations, and shows the identity as rotated)`
    : "\nrotation NOT accepted",
);
