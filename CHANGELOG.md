# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

The first version of krypt: the cryptography and security library of Davils as an open source library under the
Apache License 2.0, for Kotlin on the JVM and on `wasmJs`, built with Kreate 5.4.1 on Kore 2.3.2, konfetti 1.0.0 and
kollect 1.0.0. The code comes from the security library of an internal Davils project and is hardened on the way.

### Added

- **The build** of krypt with Kreate 5.4.1: one module per concern and a bill of materials, one convention plugin per
  concern, strict dependency locking and verification, Detekt with every rule over main and test sources, Kover at
  97 %, the API and semver check, Trivy, the standards audit and the assurance gate.
- **The core**: `SecretBytes` and `SecretText` that wipe themselves, compare in constant time and never show their
  content, constant-time comparison, strict constant-time hex and Base64 codecs, `RandomSource` over the secure
  randomness of the platform, the catalogue of algorithms, key types and curves, the `CryptoPolicy` with the `Modern`,
  `Compatible`, `Cnsa2` and `Fips` profiles and a DSL of its own, `@LegacyCryptography`, bounded byte sources and
  sinks, the environment with randomness, clock, policy, konfetti events, kollect meters and a tracer, and the audit
  trail over an `AuditSink` of the application.
- **ASN.1**: a strict DER reader and writer that refuses every non-canonical encoding within `DerLimits`, object
  identifiers, integers, bit strings, every string type, UTCTime and GeneralizedTime by RFC 5280, and PEM by RFC 7468.
- **The primitives** behind one `Crypto` facade over JCA with a selectable provider and over WebCrypto: key generation
  and SPKI, PKCS #8, PKCS #1 and SEC 1 keys, encrypted PKCS #8 with PBES2 and bounded iterations, keys of a JCA
  provider such as an HSM, fingerprints and a proof that two keys form a pair; SHA-2 and SHA-3 digests, HMAC, HKDF and
  PBKDF2; AES-GCM and ChaCha20-Poly1305 with sealed boxes, AES key wrap and RSA-OAEP; Ed25519, Ed448, ECDSA, RSA-PSS,
  RSA PKCS #1 and ML-DSA signatures in DER and raw form; X25519, X448 and ECDH key agreement, ML-KEM and DHKEM, HPKE of
  RFC 9180 in every mode; password hashing with PBKDF2 in the PHC format; and the capabilities of the platform.
- **Key sets**: keys with ids, a primary key and the lifecycle enabled, disabled and destroyed; rotation, staged keys
  and promotion; authenticated encryption, MACs, signatures and HPKE that name their key in every output; keys derived
  per purpose with HKDF; envelope encryption; key management services over a master key, a key set or, on the JVM, a
  key of a JCA provider such as an HSM; encrypted key sets bound to their name in a vault with optimistic concurrency;
  every change audited and sent as an event.
- **Bulk data**: the `KRYPT/1` container with segmented streaming encryption by the STREAM construction, AES-256-GCM
  or ChaCha20-Poly1305, a fresh data key for several recipients (key sets, HPKE, key management services and
  passwords), key commitment, a MAC over the header, random access to any segment, rewrapping for new recipients
  without encrypting again, a Merkle tree of the encrypted segments, and signed manifests for containers and plain
  data with several signers, countersignatures and time-stamp tokens.
- **Encrypted storage**: a blob store over a store of the application with names blinded by a MAC, encrypted
  metadata, objects bound to their name and version, rollback detection with a version ledger and rewrapping after a
  rotation; field encryption bound to table, column and row; blind indexes per column; and one key set per subject
  for shredding by crypto.
- **Test support**: deterministic and replayed randomness, an audit log and test environments.
