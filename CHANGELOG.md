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
  PBKDF2; AES-GCM and ChaCha20-Poly1305 with sealed boxes, AES key wrap and RSA-OAEP, AES-192 included; Ed25519,
  Ed448, ECDSA, RSA-PSS, RSA PKCS #1 and ML-DSA signatures in DER and raw form; X25519, X448 and ECDH key agreement,
  ML-KEM and DHKEM, HPKE of RFC 9180 in every mode; password hashing with PBKDF2 in the PHC format; and the
  capabilities of the platform.
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
- **X.509**: a strict parser and builder of certificates with every common extension, distinguished names by RFC 4514
  compared by RFC 5280, every general name, certification requests of PKCS #10, revocation lists with delta lists
  and issuing distribution points, path building and validation by RFC 5280 with policies, name constraints,
  purposes and a revocation checker, revocation by CRL, service identity by RFC 9525, pins and key identifiers by
  RFC 7093.
- **Key stores**: PKCS #12 read and written strictly with PBES2, a classic MAC or PBMAC1 by RFC 9579, the legacy
  protection refused; PEM bundles; identities of a key and its chain, proven to belong together; and the loading and
  writing of material through sources and sinks of the application, so krypt never opens a file.
- **OCSP**: requests with nonces by RFC 9654, strict responses, their verification against the issuer or a delegated
  responder, a revocation checker for path validation with stapled responses, the encodings for GET and POST and the
  logic of a responder with a bounded cache.
- **Certificate Transparency**: signed certificate timestamps from the certificate, TLS and OCSP, their verification
  against log lists with a rebuilt precertificate, and a CT policy by the number of logs and operators.
- **A certificate authority** without state of its own: roots and intermediates whose keys stay behind a signer,
  profiles for TLS servers and clients, mutual TLS, code signing, OCSP responders, time stamping, email and SPIFFE,
  an issuance policy for names, keys and validity, enrollment by request, 159-bit random serial numbers, revocation
  with full and delta lists, the status source of an OCSP responder, a repository of the application and an audit
  of every issuance and revocation.
- **COSE**: a strict, bounded CBOR codec that writes the deterministic encoding of RFC 8949 and refuses every other
  encoding by default; COSE_Sign1, COSE_Sign, COSE_Mac0, COSE_Mac, COSE_Encrypt0 and COSE_Encrypt by RFC 9052, tagged
  or untagged, with detached content, external data, crit and the certificates of RFC 9360; ECDSA, EdDSA and the fully
  specified algorithms of RFC 9864, RSA-PSS, HMAC, AES-GCM and ChaCha20-Poly1305, and recipients by direct keys, AES
  key wrap and ECDH-ES with HKDF; verification and decryption with an explicit allowlist of algorithms and one failure
  for every wrong key or tag; COSE_Key and COSE_KeySet with thumbprints by RFC 9679; and CBOR Web Tokens by RFC 8392,
  validated by a DSL of algorithms, issuer, audience, required claims and clock skew.
- **Test support**: deterministic and replayed randomness, an audit log and test environments.
