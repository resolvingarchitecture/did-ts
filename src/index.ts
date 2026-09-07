/**
 * did-ts — a small, dependency-light reference implementation of Resolving
 * Architecture's DID design: secp256k1 / BIP-340 identities, Nostr-compatible
 * signed records, attestations as a decentralised replacement for NIP-05, and
 * guardian-based key recovery and rotation.
 *
 * Spec: ../DESIGN.md. Conformance suite: did-vectors (vendored in test/vectors).
 *
 * Public domain (CC0 1.0).
 */

export {
  serializeString,
  serializeEvent,
  preimageBytes,
  computeId,
  type EventTemplate,
} from "./serialize.js";

export {
  type Identity,
  isValidPubkey,
  generateIdentity,
  publicKeyFromSecret,
  hexToNpub,
  npubToHex,
  secretToNsec,
  nsecToSecret,
  normalizePubkey,
  hexToDid,
  didToHex,
} from "./keys.js";

export {
  type NostrEvent,
  type UnsignedEvent,
  type VerifyResult,
  now,
  signEvent,
  verifyEvent,
  assertValid,
  schnorrSignRaw,
  schnorrVerifyRaw,
} from "./event.js";

export {
  KIND_IDENTITY_ATTESTATION,
  KIND_GUARDIAN_SET,
  KIND_ROTATION_ATTESTATION,
  KIND_ROTATION_CLAIM,
  DID_KINDS,
  METHODS,
  CLAIM_ATTRIBUTES,
  ROTATION_REASONS,
  validateKind,
  type Method,
  type RotationReason,
  type KindCheck,
} from "./kinds.js";

export {
  type Claim,
  type AttestationInput,
  type ParsedAttestation,
  createAttestation,
  revokeAttestation,
  parseAttestation,
  isExpired,
} from "./attestation.js";

export {
  DEFAULT_COOLDOWN_SECONDS,
  DEFAULT_CLOCK_SKEW_SECONDS,
  type GuardianSetInput,
  type RotationClaimInput,
  type RotationAttestationInput,
  type RotationVerdict,
  type EvaluateOptions,
  createGuardianSet,
  createRotationClaim,
  createRotationAttestation,
  prevSig,
  evaluateRotation,
} from "./rotation.js";

export {
  type DidDocument,
  type VerificationMethod,
  type DidDocumentOptions,
  xonlyToMultikey,
  multikeyToXonly,
  didDocument,
} from "./diddoc.js";
