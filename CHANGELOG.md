# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 1.1.0 - 2026-11-26

### Added

- **A `MaterialReloader` is a health indicator of kollect.** It is Down while a certificate in use has expired or is
  not valid yet, Degraded while one expires within the warning time, and Up otherwise.

### Changed

- **The OCSP response cache keeps its entries in a cache of kontinuity.** Every operation takes constant time however
  full the cache is, instead of searching three lists, and the entry used least recently makes room when it is full.
- **IP addresses in names, name constraints, service identities and ACME identifiers are read by Konnect 1.1.0.** The
  canonical text of an IPv4-mapped IPv6 address ends in its IPv4 address, such as `IP:::ffff:192.0.2.1`.
- **Secure randomness comes from `SecureEntropy` of Kore 2.5.0** behind the unchanged `RandomSource`, instead of a copy
  of the platform code of the JVM and of WebCrypto.
- **Events reach the bus through the `Emitter` of konfetti 1.1.0.** A bus that declares the topic of a component for
  another event type no longer fails the component; its events then reach the flow only.
- **Built with Kreate 5.5.2 and Gradle 9.9.2 on Kore 2.5.0, konfetti 1.1.0, kollect 1.1.0, kontinuity 1.1.0 and
  Konnect 1.1.0**, with kotlinx-io 0.9.3 and the version floors of the build tools raised.

## 1.0.0 - 2026-11-23

The first version of krypt: the cryptography and security library of Davils as an open source library under the
Apache License 2.0, for Kotlin on the JVM and on `wasmJs`, built with Kreate 5.4.1 on Kore 2.3.2, konfetti 1.0.0 and
kollect 1.0.0 and published to `https://repo.davils.com`. The code comes from the security library of an internal
Davils project and is hardened for critical infrastructure on the way, including an independent security audit of
every module before this release.

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
- **JOSE**: a strict and bounded JSON parser by RFC 8259 and I-JSON; JSON Web Keys and key sets of RFC 7517 and RFC
  8037 converted to and from the keys of krypt, with `x5c` chains, thumbprints by RFC 7638 and thumbprint URIs by RFC
  9278; JSON Web Signatures in the compact and JSON serializations with detached and unencoded payloads, verified
  with an algorithm allowlist and optionally with an `x5c` chain; JSON Web Encryption with `dir`, AES key wrap, AES-GCM
  key wrap, ECDH-ES, RSA-OAEP-256 and, behind an opt-in, PBES2, and AES-GCM and AES-CBC-HMAC content encryption with
  one failure for every wrong key, tag or padding; and JSON Web Tokens, signed, encrypted or nested, validated by the
  best current practice of RFC 8725.
- **TLS** for the JVM over JSSE: a `tls { }` DSL for clients and servers with TLS 1.3 by default and TLS 1.2 by
  opt-in, allowlists of cipher suites, groups and signature schemes from the crypto policy with the hybrid group
  `X25519MLKEM768` first where the JDK offers it, ALPN, server name indication and session settings; rotating key
  and trust managers that choose identities by server name and key type and validate peers with the path validation
  of krypt, with the anchors of the JDK only on request and together with those of the application; revocation by
  stapled OCSP, OCSP and CRL sources and a bounded cache, soft or hard, with must-staple; Certificate Transparency;
  mutual TLS with a peer policy for SPIFFE ids and names; hot reload of material with debounce, hold-down and the
  last good version kept; contexts, engines, socket factories and STARTTLS over sockets of the application.
- **CMS**: signed data of RFC 5652 with ECDSA, RSA-PSS, RSA PKCS #1, Ed25519, Ed448 and ML-DSA through a `Signer`,
  attached or detached, signed attributes with the ESS signing-certificate-v2, several signers, countersignatures,
  certificates and revocation lists, and its verification with a path validator; enveloped and authenticated-enveloped
  data with AES-CBC and AES-GCM for RSA-OAEP, ECDH, X25519, X448, key-encryption-key, password and ML-KEM recipients,
  with one failure for every wrong key; encrypted data; and RFC 3161 time stamps with requests, verified responses,
  the logic of an authority and signature time stamps. Every message is read as strict DER within limits. PBKDF2 with
  HMAC-SHA-1 of krypt-primitive reads the password recipients OpenSSL writes, behind `@LegacyCryptography`.
- **COSE**: a strict, bounded CBOR codec that writes the deterministic encoding of RFC 8949 and refuses every other
  encoding by default; COSE_Sign1, COSE_Sign, COSE_Mac0, COSE_Mac, COSE_Encrypt0 and COSE_Encrypt by RFC 9052, tagged
  or untagged, with detached content, external data, crit and the certificates of RFC 9360; ECDSA, EdDSA and the fully
  specified algorithms of RFC 9864, RSA-PSS, HMAC, AES-GCM and ChaCha20-Poly1305, and recipients by direct keys, AES
  key wrap and ECDH-ES with HKDF; verification and decryption with an explicit allowlist of algorithms and one failure
  for every wrong key or tag; COSE_Key and COSE_KeySet with thumbprints by RFC 9679; and CBOR Web Tokens by RFC 8392,
  validated by a DSL of algorithms, issuer, audience, required claims and clock skew.
- **SPIFFE**: SPIFFE ids and trust domains by a strict hand-written parser of the SPIFFE ID specification;
  X.509-SVIDs checked by the rules of the X509-SVID specification and validated by RFC 5280 against the X.509
  authorities of the bundle of their own trust domain only; JWT-SVIDs over krypt-jose, compact JWS with RSA, RSA-PSS
  and ECDSA only, a required `kid` looked up in the bundle of the trust domain of `sub`, `aud`, `exp` and a bounded
  clock skew, and their signing; SPIFFE bundles and bundle maps as JWK sets of RFC 7517 with `x509-svid` and
  `jwt-svid` keys, `spiffe_sequence` and `spiffe_refresh_hint`, a bounded `BundleSet` per trust domain for
  federation, `SvidSource` and `BundleSource` the application implements and an `X509Source` that swaps the SVIDs and
  bundles it is pushed atomically and refuses rollbacks; and a `SpiffeAuthorizer` for mutual TLS in krypt-tls.
- **ACME**: the client logic of RFC 8555 over an `AcmeTransport` of the application, so krypt opens no socket: the
  directory with its meta object, a bounded nonce pool with a bounded retry after `badNonce`, flattened JWS requests
  with `kid` or `jwk`, accounts with contacts, terms agreement, external account binding, lookup by key, update,
  deactivation and key rollover; orders for DNS names and IP addresses of RFC 8738 with `notBefore` and `notAfter`,
  authorizations and their deactivation, the key authorization, the `http-01` path, the `dns-01` record and the
  `tls-alpn-01` validation certificate of RFC 8737; finalization with a certification request of krypt-x509, the
  download of PEM chains with their alternates, revocation by the account or by the key of the certificate, polling
  by `Retry-After` in helpers the caller invokes, and the renewal information of RFC 9773 with certificate
  identifiers and `replaces`. Problem documents of RFC 9457 become typed failures, every response and URL is checked
  against limits, and test support gains an in-memory ACME server.
- **Test support**: deterministic and replayed randomness, an audit log, test environments and an in-memory ACME
  server.
- **Benchmarks**: `krypt-benchmark`, a module that is never published, measures with JMH on the JVM the throughput of
  the `KRYPT/1` container (encryption, decryption and random access with AES-256-GCM and ChaCha20-Poly1305 at 1 MiB
  and 64 MiB), the encrypted blob store, field encryption and blind indexes, and the raw AES-256-GCM and SHA-256
  beneath them. It runs through Kreate's benchmark support with a `main` and a `smoke` profile and a regression gate
  against a recorded baseline; `check` compiles the benchmarks but never runs them.

### Security

- **Core, ASN.1 and primitives hardened after an audit**: a refusal of JCA or WebCrypto for a key or an input, such as
  an HPKE encapsulation of small order or an RSA key JCA does not take, is the documented failure (null,
  `Verification.Invalid` or a `CryptoException` without the message of the platform), never an exception of the
  platform; RSA keys with a negative or even modulus, an exponent outside 3 to 2^256 or other than NULL parameters are
  malformed; `Keys.decodePrivate` is suspending and refuses a PKCS #8 whose embedded public key does not belong to it,
  and derives the public key of X25519 and X448, so `CoseKeys.decode` and `decodeSet` are suspending too; the key types
  have private constructors only; `Cnsa2` permits exactly the CNSA 2.0 suite, with RSA for verification only; a policy
  that demands a FIPS provider refuses to run without one; a key is generated only if the policy permits an algorithm
  that uses it; the DER reader refuses an unsorted SET OF, with `readSetInAnyOrder` and `readListInAnyOrder` for the
  SETs the JDK writes unsorted, and object identifiers padded with 0x80; passwords with an unpaired surrogate are
  refused and PHC parameters must be canonical.
- **Bulk data and storage** after an audit: the blob store treats its version ledger as the authority, so an old,
  deleted or rotated-away object put back under any blinded key is a rollback, and a put after a rotation of the names
  key set works; the key set vault binds the revision and takes an optional `RevisionLedger`, so a destroyed or deleted
  key does not come back; a container holds at most one password recipient and asks a key management service at most
  once, which bounds the work a hostile container causes, and `StreamLimits.maximumIterations` has a hard ceiling; a
  container of a suite the policy forbids is refused instead of thrown; hostile public key sets with a password KDF or
  AES-192-GCM in their HPKE suite are refused; failures of the store, the ledger, the repository and the key management
  service become the typed failures `StorageFailure.Unavailable` and `KeysetFailure.Unavailable`; and key sets, keys
  and their primitives check their invariants however they are built.
- **PKI hardening** (X.509, key stores, OCSP, CT, authority): path building is bounded in work, deduplicates and
  orders its candidates and refuses more than `maximumIntermediates`; certificate policies run through the policy
  tree of RFC 5280 within `maximumPolicyNodes`; a revocation list counts only where its distribution point covers
  the certificate, a revocation in any applicable list wins, and lists with unknown critical extensions are not used;
  name constraints cover every name a wildcard stands for and ignore trailing dots; a trust anchor as the end entity
  is checked for validity, purpose and key usage, and the key usage of every end entity must suit `serverAuth` and
  `clientAuth`; explicitly encoded DER defaults are refused; the password work of a PKCS #12 file is bounded by
  `maximumPasswordIterations`; sources, sinks and repositories of the application are contained; the authority
  checks the subject of a request against `subjectAttributes` and `fixedAttribute` of its policy, validates DNS
  names, wildcards and URI prefixes strictly and lets delta lists reach back `DEFAULT_OVERLAP`; and the
  constructors of decoded values and results are no longer reachable from Java.
- **Message formats hardened after an audit**: CWT validation requires a signature, a MAC or an encryption under a
  pre-shared key (`isAuthenticationRequired`) and `exp` (`isExpirationRequired`) by default, COSE reads `alg` only from
  the protected bucket and HMAC keys must be as long as the hash; `Jwt.validate` accepts only the compact
  serialization, a JWS needs `b64` in `crit` to use an unencoded payload, a JWK keeps `use`, `key_ops` and `alg` on its
  `JoseKey`, and PBES2 and PWRI derive at most once per password and message; CMS requires signed attributes and
  authenticated attributes for content other than id-data, binds the content type and tag length of
  AuthEnvelopedData, verifies time stamps without throwing, and reads or writes AES-CBC only with
  `isUnauthenticatedCbcAllowed`.
- **Identity and transport**: a cached revocation status in krypt-tls keeps the expiry it got when its source decided
  it, capped at the `nextUpdate` of the OCSP response or revocation list, so later handshakes no longer extend it;
  every `SpiffeAuthorizer` takes the bundles and binds a SPIFFE id to the bundle of its own trust domain; a path to an
  anchor of the JDK must also pass the PKIX trust manager of the JDK, so its CA distrust policies and disabled
  algorithms keep applying; `X509Source` keeps a high-water mark of `spiffe_sequence` per trust domain and refuses a
  bundle without a sequence after one with a sequence; an `x509-svid` key whose `x5c` holds more than one certificate
  refuses the bundle; and Java can no longer construct checked SPIFFE values, `PeerIdentity`, `RotatingTrustManager`
  or `AcmeSession` around their validation.
