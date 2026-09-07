# did-ts

A small, dependency-light **reference implementation** of [Resolving
Architecture](https://resolvingarchitecture.io)'s DID design:

- one **secp256k1 / BIP-340** keypair as an identity, with `hex` / `npub` /
  `nsec` / `did:nostr` encodings;
- **Nostr-compatible signed records** with the exact canonical serialisation that
  makes signatures reproduce across implementations;
- **attestations** — the `vouch` primitive, a decentralised replacement for
  NIP-05;
- **guardian-based key recovery and rotation**, including the normative
  acceptance rule;
- the thin **`did:nostr`** document view.

It exists to be **read, copied, and checked against** — the first independent
implementation of the spec, and the thing that proves the
[test vectors](https://github.com/resolvingarchitecture/did-vectors) are right
before the other language ports follow. TypeScript first because that is where
Nostr client developers work.

Spec: [`DESIGN.md`](https://github.com/resolvingarchitecture) (`../DESIGN.md` in
the DID workspace). Drafts: identity attestations, and social recovery + key
rotation, published on Nostr as long-form articles.

**Status:** `0.1.0`, pre-release. Kind numbers `30100`–`30103` are **provisional**
(`DESIGN.md` §8) and held in one module so a reassignment is a one-line change.

## Install

```sh
npm install @resolvingarchitecture/did-ts
```

Runtime dependencies, and nothing else:
[`@noble/curves`](https://github.com/paulmillr/noble-curves) (BIP-340 Schnorr),
[`@noble/hashes`](https://github.com/paulmillr/noble-hashes) (SHA-256),
[`@scure/base`](https://github.com/paulmillr/scure-base) (Bech32). No hand-rolled
cryptography.

## Use

```ts
import {
  generateIdentity,
  createAttestation,
  verifyEvent,
  createGuardianSet,
  createRotationClaim,
  createRotationAttestation,
  evaluateRotation,
  didDocument,
} from "@resolvingarchitecture/did-ts";

// an identity is one keypair
const alice = generateIdentity();
const bob = generateIdentity();

// bob vouches for alice's name, having checked in person
const attestation = createAttestation(
  {
    subject: alice.pubkey,
    claims: [{ attribute: "name", value: "Alice" }],
    method: "in-person",
  },
  bob.secretHex,
);
verifyEvent(attestation); // { ok: true }

// the did:nostr view, produced offline from the public key alone
didDocument(alice.pubkey);

// alice names guardians, then recovers to a new key when the old one is lost
const guardianSet = createGuardianSet(
  { guardians: [g1.pubkey, g2.pubkey, g3.pubkey], threshold: 2 },
  alice.secretHex,
);
const claim = createRotationClaim(
  { oldPubkey: alice.pubkey, reason: "lost" },
  aliceNew.secretHex,
);
const e1 = createRotationAttestation(
  { oldPubkey: alice.pubkey, newPubkey: aliceNew.pubkey, method: "in-person" },
  g1.secretHex,
);
const e2 = createRotationAttestation(
  { oldPubkey: alice.pubkey, newPubkey: aliceNew.pubkey, method: "existing-channel" },
  g2.secretHex,
);

evaluateRotation([guardianSet, claim, e1, e2]);
// { accepted: true, new: "<aliceNew.pubkey>", old: "<alice.pubkey>", reason: "..." }
```

A full end-to-end walkthrough that prints every signed event:

```sh
npm run example
```

## API

| Area | Exports |
|------|---------|
| Keys & encodings | `generateIdentity`, `publicKeyFromSecret`, `isValidPubkey`, `hexToNpub` / `npubToHex`, `secretToNsec` / `nsecToSecret`, `hexToDid` / `didToHex`, `normalizePubkey` |
| Serialisation | `serializeEvent`, `serializeString`, `preimageBytes`, `computeId` |
| Events | `signEvent`, `verifyEvent` (four-step order, returns the failing step), `assertValid`, `schnorrSignRaw` / `schnorrVerifyRaw` |
| Kinds | `KIND_IDENTITY_ATTESTATION` … `KIND_ROTATION_CLAIM`, `DID_KINDS`, `METHODS`, `ROTATION_REASONS`, `validateKind` |
| Attestations | `createAttestation`, `revokeAttestation`, `parseAttestation`, `isExpired` |
| Rotation | `createGuardianSet`, `createRotationClaim`, `createRotationAttestation`, `prevSig`, `evaluateRotation`, `DEFAULT_COOLDOWN_SECONDS` |
| `did:nostr` | `didDocument`, `xonlyToMultikey`, `multikeyToXonly` |

`signEvent` uses BIP-340 `aux_rand = 0` by default, so events are byte-for-byte
reproducible (this is how the vectors are generated); pass your own randomness if
you prefer. Verification never depends on how a signature was produced.

`nsec` export lives behind `secretToNsec` and is never called by the library
itself — per `DESIGN.md` §6.3 a caller MUST gate it behind an explicit,
separately-confirmed user action and MUST NOT surface `nsec` incidentally.

## Conformance

The [`did-vectors`](https://github.com/resolvingarchitecture/did-vectors)
conformance suite is vendored (copied, not a submodule) at
[`test/vectors/`](test/vectors/) and re-copied when it changes upstream. The test
suite:

- checks canonical serialisation, `id` derivation and signature reproduction
  against `events.json`;
- verifies every valid vector and rejects every invalid one **at the stated
  step**;
- runs the rotation acceptance rule against all 19 scenarios in `rotation.json`;
- cross-verifies did-ts output with **`nostr-tools`**, unmodified, so
  "Nostr-compatible" is checked and not just asserted.

```sh
npm install
npm test         # node --test
npm run typecheck
npm run build
```

## License

**Public domain** — [CC0 1.0 Universal](https://creativecommons.org/publicdomain/zero/1.0/),
see [`LICENSE`](LICENSE). Copy any of it into any implementation, ship it with a
NIP, no attribution required. That is the point: a spec meant to be adopted, and
reference code meant to be copied, should carry nothing to comply with.
