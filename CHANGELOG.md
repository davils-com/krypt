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
- **Test support**: deterministic and replayed randomness, an audit log and test environments.
