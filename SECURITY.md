# Security Policy

## Supported Versions

Security fixes are released for the latest minor version of the current major release.

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes       |
| < 1.0   | No        |

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

- every **encoded value** krypt reads: public and private keys in DER and PEM, encrypted private keys and their
  parameters, signatures, ciphertexts, sealed boxes, encapsulations, stored password hashes and every field of every
  protocol message,
- the **size and shape** of that input, up to deeply nested, overlong, truncated and non-canonical encodings,
- **passwords and texts** that come from users,
- the **timing** of its own requests, so that it can measure how long an operation takes.

The properties that must hold are the confidentiality and integrity of protected data, the secrecy of keys, the
correctness of every verification, the availability of the application under hostile input, and the safety of
`toString` output, exception messages, events, meters and audit entries.

krypt defends against this attacker with decoders that are strict and bounded by limits with hard ceilings, a crypto
policy that is checked on every creation, decoding and verification, iteration bounds for password-based keys in both
directions, constant-time comparison of secrets and tags, failures that carry no detail, secrets that wipe themselves,
and text from callers that is escaped through `SafeText` of Kore.

### What the application is responsible for

- **The policy.** `Modern` is the default. A weaker policy, an opt-in to `@LegacyCryptography` or a raised limit is
  the application's choice.
- **The provider.** On the JVM, the provider decides how constant-time and how certified the primitives are. A FIPS
  deployment hands in a validated provider and uses the `Fips` policy.
- **Where secrets go.** krypt hands out key material only through `SecretBytes`, which the application should `use`
  and `destroy`. A secret the application copies into a `String` or an array of its own is outside krypt's control.
- **The audit sink and other SPIs.** They run in the application. A required audit refuses operations it could not
  record; a best-effort audit only counts the failure.
- **Nonces with explicit control.** `Aeads.encrypt` with a caller's nonce is for protocols that define the nonce; a
  repeated nonce under one key breaks AES-GCM. `Aeads.seal` draws a fresh nonce itself.

## Guarantees

- No krypt module opens a file, a socket or a process, starts a thread or a timer, or writes a log.
- Every computation on a secret runs in JCA or WebCrypto; krypt implements only encodings and protocols on top.
- Every decoder refuses non-canonical DER, PEM, hex and Base64 and enforces its limits before it allocates.
- Decryption has a single failure, so there is no padding or timing oracle through its result.
- Verification returns `Verification.Valid` only when the signature is valid for the key, the data and the algorithm
  the caller named; the algorithm never comes from the input alone.
- Comparisons of secrets, tags and password hashes run in constant time.
- Every message, event, meter and `toString` shows algorithm names, sizes and escaped names, never key material.

## Scope

The following are **in scope**:

- input within the configured limits that makes krypt use unbounded memory or CPU, crash or hang,
- a verification that accepts what it must refuse, or a decryption that returns data that was tampered with,
- an operation that uses an algorithm, a key size, a curve or an iteration count the policy forbids,
- key material or secret-dependent detail that reaches a message, an event, a meter, an audit entry or a `toString`,
- a timing difference in krypt's own code that depends on a secret,
- a decoder that accepts a non-canonical encoding, or a limit beyond its hard ceiling.

The following are **not** vulnerabilities in krypt:

- a vulnerability in the JDK, its providers, the JavaScript host or its WebCrypto, the Kotlin standard library,
  kotlinx.coroutines, kotlinx-io, Kore, konfetti or kollect,
- an application that opts into legacy cryptography or a weaker policy and is attacked through it,
- a secret that the application copied out of `SecretBytes` and kept.

## Known Limitations

- **Zeroisation is best effort.** On the JVM, the garbage collector may copy arrays before they are wiped, and JCA
  keeps its own copies, for example in `SecretKeySpec` and inside providers; `destroy()` wipes what krypt holds. On
  Wasm, a key imported into WebCrypto lives in the host. Use non-extractable keys, an HSM or a KMS where this matters.
- **The platforms differ.** WebCrypto lacks incremental digests, SHA-3, ChaCha20-Poly1305, Ed448, X448, ML-KEM and
  ML-DSA; `Crypto.capabilities` reports what is available, and an unavailable algorithm throws
  `UnsupportedAlgorithmException`. Bulk data is hashed in segments, so it works on both targets.
- **Password hashing is PBKDF2.** Neither JCA nor WebCrypto offers Argon2 or scrypt, and krypt implements no primitive
  of its own. The stored hash records its parameters, so a verification reports `ValidButOutdated` when a stronger setting is due.
- **HPKE with ML-KEM** uses the identifiers of the current Internet-Draft and may change with the final RFC.
- `@DavilsInternal` is a compile-time opt-in, not an access boundary, and Kotlin `internal` is public in JVM bytecode.
  No `module-info.java` of krypt exports an `internal` package.

## Verifying a Release

Releases are signed with the Davils release key `36F578E8AD2D4391E0FA6C18154C625FAD370063` and attested by the
pipeline. Verify the signature of every artifact before you use it.
