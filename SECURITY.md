# Security Policy

## Supported Versions

Security fixes are released for the latest minor version of the current major release.

| Version | Supported |
|---------|-----------|
| 1.2.x   | Yes       |
| < 1.2   | No        |

## Reporting a Vulnerability

**Do not open a public issue for a security problem.**

Report it privately through GitHub's
[private vulnerability reporting](https://github.com/davils-com/krypt/security/advisories/new),
or by email to development@davils.com.

Please include the affected krypt version, module and target (JVM or Wasm), the provider on the JVM, a description of
the impact, the steps to reproduce it, ideally as a Kotlin test, and any mitigation you are aware of. We acknowledge a
report within three working days and agree on a disclosure date with you.

## Threat Model

krypt is a library: it runs in the process and with the privileges of the application that uses it, and it trusts the
platform below it, the JDK with its providers on the JVM and the WebCrypto of the JavaScript host on Wasm. It assumes
that an attacker controls:

- every **encoded value** krypt reads: public and private keys in DER, PEM, JWK and COSE_Key form, encrypted private
  keys, PKCS #12 files, certificates, requests, revocation lists, OCSP responses, signed certificate timestamps,
  signatures, ciphertexts, containers of `KRYPT/1`, JOSE, COSE and CMS messages, tokens, SPIFFE bundles and SVIDs,
  ACME responses and every field of every protocol message,
- the **size and shape** of that input, up to deeply nested, overlong, truncated, reordered and non-canonical
  encodings, and certificate chains built to make path building expensive,
- **what the application stores**: the blob store, the key set repository and the authority repository may be read
  and rewritten by the attacker, who may also put back older versions, unless a ledger the attacker cannot rewrite
  is given (see below),
- **the network peers** of a TLS connection, an OCSP responder, a CRL distribution point and an ACME server,
- **passwords and texts** that come from users,
- the **timing** of its own requests, so that it can measure how long an operation takes.

The properties that must hold are the confidentiality and integrity of protected data, the secrecy of keys, the
correctness of every verification and authorization, the freshness of what a ledger protects, the availability of the
application under hostile input, and the safety of `toString` output, exception messages, events, meters and audit
entries.

krypt defends against this attacker with decoders that are strict and bounded by limits with hard ceilings, a crypto
policy that is checked on every creation, decoding and verification, budgets for password derivations and path
building, constant-time comparison of secrets and tags, failures that carry no detail, secrets that wipe themselves,
code of the application that runs contained, and text from callers that is escaped through `SafeText` of Kore.

### What the application is responsible for

- **The policy.** `Modern` is the default. A weaker policy, an opt-in to `@LegacyCryptography`, an opt-in such as
  `isUnauthenticatedCbcAllowed` of CMS or `isPasswordAllowed` of JOSE, or a raised limit is the application's choice.
- **The provider.** On the JVM, the provider decides how constant-time and how certified the primitives are. A FIPS
  deployment hands in a validated provider and uses the `Fips` policy, which refuses to run without one.
- **Where secrets go.** krypt hands out key material only through `SecretBytes`, which the application should `use`
  and `destroy`. A secret the application copies into a `String` or an array of its own is outside krypt's control.
- **The interfaces it implements.** krypt opens no file and no socket: the audit sink, the material sources and
  sinks, the blob store, the version and revision ledgers, the key set and authority repositories, the key management
  services, the revocation list and OCSP sources, the SVID and bundle sources and the ACME transport are the
  application's. They must keep the contracts their KDoc states, such as atomic replacement and compare-and-set.
  krypt contains their exceptions; their latency is theirs, and a TLS handshake waits for them.
- **Rollback protection needs a ledger.** The blob store detects an older or deleted object put back only with a
  `VersionLedger`, the key set vault an older key set only with a `RevisionLedger`. A ledger must live where the
  attacker of the store cannot rewrite it; without one, the store decides what is current.
- **Revocation needs a checker.** A `PathValidator` without a `RevocationChecker` checks no revocation, whatever
  `isRevocationRequired` says. Soft-fail accepts a certificate whose status is unknown.
- **Nonces with explicit control.** `Aeads.encrypt` with a caller's nonce is for protocols that define the nonce; a
  repeated nonce under one key breaks AES-GCM. `Aeads.seal` draws a fresh nonce itself.

## Guarantees

- No krypt module opens a file, a socket or a process, starts a thread or a timer, or writes a log.
- Every computation on a secret runs in JCA or WebCrypto; krypt implements only encodings and protocols on top.
- Every decoder refuses non-canonical DER, PEM, hex, Base64, JSON and CBOR and enforces its limits before it
  allocates or derives. The documented exceptions read some SET OF elements in any order: the bag attributes of
  PKCS #12 and the certificate, revocation list, signer, recipient and unsigned attribute sets of CMS, as the JDK and
  OpenSSL write them.
- Hostile input yields the documented failure, never an exception of the platform or a message of it.
- Authenticated decryption has a single failure, so there is no padding or timing oracle through its result.
- Verification returns `Verification.Valid` only when the signature is valid for the key, the data and the algorithm
  the caller named; the algorithm never comes from the input alone, and a key declared for another use or algorithm
  is not used.
- Comparisons of secrets, tags and password hashes run in constant time.
- The work a single input can cause is bounded: one password derivation per password and container or message, a
  budget of iterations per PKCS #12 file, a budget of attempts and intermediates for path building, a node limit for
  the policy tree and a bound on calls to a key management service.
- Every message, event, meter and `toString` shows algorithm names, sizes and escaped names, never key material.
- Under the Java module system, the values krypt validates cannot be constructed around their validation: their
  constructors take types of packages that no `module-info.java` of krypt exports.

## Scope

The following are **in scope**:

- input within the configured limits that makes krypt use unbounded memory or CPU, crash or hang,
- a verification or authorization that accepts what it must refuse, or a decryption that returns data that was
  tampered with,
- an older or deleted object, key set or bundle accepted although a ledger or a sequence records a newer one,
- an operation that uses an algorithm, a key size, a curve or an iteration count the policy forbids,
- key material or secret-dependent detail that reaches a message, an event, a meter, an audit entry or a `toString`,
- a timing difference in krypt's own code that depends on a secret,
- a decoder that accepts a non-canonical encoding outside the documented exceptions, or a limit beyond its hard
  ceiling.

The following are **not** vulnerabilities in krypt:

- a vulnerability in the JDK, its providers, the JavaScript host or its WebCrypto, the Kotlin standard library,
  kotlinx.coroutines, kotlinx-io, Kore, konfetti or kollect,
- an application that opts into legacy cryptography, unauthenticated CBC, password-based JOSE, a weaker policy or
  raised limits and is attacked through it,
- an application whose own interfaces break their contracts, such as a ledger the attacker can rewrite,
- reflection with `setAccessible` or a class path without the Java module system, which reach any constructor,
- a secret that the application copied out of `SecretBytes` and kept.

## Known Limitations

- **Zeroisation is best effort.** On the JVM, the garbage collector may copy arrays before they are wiped, and JCA
  keeps its own copies, for example in `SecretKeySpec` and inside providers; `destroy()` wipes what krypt holds. Some
  intermediate values still pass through `ByteString`, which cannot be wiped, such as the plaintext of an AEAD
  primitive, and the PEM text of a private key passes through a `String`. On Wasm, a key imported into WebCrypto lives
  in the host. Use non-extractable keys, an HSM or a KMS where this matters.
- **The platforms differ.** WebCrypto lacks incremental digests, SHA-3, ChaCha20-Poly1305, Ed448, X448, ML-KEM and
  ML-DSA, and some hosts lack AES-192; `Crypto.capabilities` reports what is available, and an unavailable algorithm
  throws `UnsupportedAlgorithmException`. Bulk data is hashed in segments, so it works on both targets.
- **Password hashing is PBKDF2.** Neither JCA nor WebCrypto offers Argon2 or scrypt, and krypt implements no primitive
  of its own. The stored hash records its parameters, so a verification reports `ValidButOutdated` when a stronger
  setting is due.
- **Blind indexes leak equality.** A `BlindIndex` is deterministic per column: whoever reads the index learns which
  rows share a value and how often a value occurs, and may guess common values by their frequency. Truncation trades
  false matches against this leakage; use it only for columns where that is acceptable.
- **Unauthenticated CBC.** EnvelopedData and EncryptedData of CMS with AES-CBC are not authenticated; reading them is
  an opt-in that exposes a padding oracle wherever the outcome is observable. Use AuthEnvelopedData.
- **TLS over JSSE.** A resumed session skips path validation, revocation and the authorizer until `sessionTimeout`
  or `TlsContext.rotate`. A server cannot staple a response the application provides, Certificate Transparency sees
  only embedded SCTs and those of a stapled response, and session tickets are configured JVM-wide. Trust checks run
  synchronously on the handshake thread, so sources and authorizers bound their own time.
- **Formats.** krypt refuses BER, such as indefinite lengths, in CMS and PKCS #12. JOSE offers no A192 variants,
  RSA1_5 or `zip`; COSE no AES-CCM, AES-MAC or countersignatures; CMS no RSA PKCS #1 v1.5 key transport, and Ed448
  only without signed attributes. Time-stamp tokens in signed manifests of `KRYPT/1` are carried, not verified.
- **Protocols.** The ACME client has no pre-authorization and no CAA account binding, and its polling is bounded per
  call, not in total: wrap it in `withTimeout`. krypt-spiffe speaks no Workload API and validates JWT-SVIDs with RSA,
  RSA-PSS and ECDSA only.
- **HPKE with ML-KEM** uses the identifiers of the current Internet-Draft and may change with the final RFC.
- `@DavilsInternal` is a compile-time opt-in, not an access boundary, and Kotlin `internal` is public in JVM bytecode.
  No `module-info.java` of krypt exports an `internal` package.

## Verifying a Release

Releases are signed with the Davils release key `36F578E8AD2D4391E0FA6C18154C625FAD370063` and attested by the
pipeline. Verify the signature of every artifact before you use it.
