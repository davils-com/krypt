# AGENTS.md

Binding rules for every agent and every person working in this repository. krypt is the cryptography and security
library of Davils: secrets that wipe themselves, a crypto policy with profiles, every modern primitive over JCA and
WebCrypto, DER and PEM, and, as it grows, key sets, encrypted storage of bulk data, X.509 and a certificate authority,
OCSP, Certificate Transparency, JOSE, COSE, CMS, SPIFFE, ACME and mutual TLS. It runs on the JVM and on WebAssembly
(`wasmJs`), reports through events on [konfetti](https://github.com/davils-com/konfetti) topics and meters in
[kollect](https://github.com/davils-com/kollect), and is built on [Kore](https://github.com/davils-com/kore). It is
published under the Apache License 2.0 and is built for enterprise and critical infrastructure, with security and
correctness first.

## Repository

| Module | Artifact | Purpose |
|---|---|---|
| `krypt-core` | `com.davils:krypt-core` | `SecretBytes`, `SecretText`, constant-time comparison, strict hex and Base64, randomness, the algorithm catalogue, the crypto policy and its profiles, byte streams, the audit trail and the event and meter plumbing |
| `krypt-asn1` | `com.davils:krypt-asn1` | The strict DER reader and writer, object identifiers, times and PEM |
| `krypt-primitive` | `com.davils:krypt-primitive` | The `Crypto` facade: keys, digests, MACs, HKDF and PBKDF2, AEADs, key wraps, RSA-OAEP, signatures, key agreement, KEMs, HPKE and password hashing over JCA and WebCrypto |
| `krypt-keyset` | `com.davils:krypt-keyset` | Key sets with ids, a primary key, rotation and a lifecycle; their primitives; envelope encryption; key management services; encrypted key sets in a vault |
| `krypt-stream` | `com.davils:krypt-stream` | The `KRYPT/1` container for bulk data: segmented streaming encryption, random access, several recipients, key commitment, rewrapping, Merkle trees and signed manifests |
| `krypt-storage` | `com.davils:krypt-storage` | The encrypted blob store with blinded names and rollback detection, field encryption, blind indexes and per-subject keys for shredding by crypto |
| `krypt-x509` | `com.davils:krypt-x509` | X.509 certificates, names and extensions, certification requests, revocation lists, path validation by RFC 5280, service identity by RFC 9525 and pins |
| `krypt-keystore` | `com.davils:krypt-keystore` | PKCS #12 and PEM bundles, identities of a key and its chain, and the loading and writing of material through sources and sinks of the application |
| `krypt-ocsp` | `com.davils:krypt-ocsp` | OCSP requests and responses, their verification, a revocation checker for path validation and the logic of a responder |
| `krypt-ct` | `com.davils:krypt-ct` | Signed certificate timestamps from certificates, TLS and OCSP, log lists and a CT policy |
| `krypt-authority` | `com.davils:krypt-authority` | A stateless certificate authority: roots and intermediates behind a signer, profiles, an issuance policy, revocation lists and the status of an OCSP responder |
| `krypt-jose` | `com.davils:krypt-jose` | JSON Web Keys and key sets with thumbprints, JSON Web Signatures, JSON Web Encryption and JSON Web Tokens validated by the best current practice, over a strict and bounded JSON parser |
| `krypt-cose` | `com.davils:krypt-cose` | A strict deterministic CBOR codec, COSE signatures, MACs and encryption with recipients, COSE keys and key sets with thumbprints, and CBOR Web Tokens |
| `krypt-cms` | `com.davils:krypt-cms` | CMS: signed, enveloped, authenticated-enveloped and encrypted data with every common recipient, and RFC 3161 time-stamp requests, responses, tokens and the logic of a time-stamping authority |
| `krypt-spiffe` | `com.davils:krypt-spiffe` | SPIFFE ids and trust domains, X.509-SVIDs validated against the bundle of their trust domain, JWT-SVIDs over JOSE, trust bundles and bundle maps for federation, and sources of SVIDs and bundles the application feeds |
| `krypt-acme` | `com.davils:krypt-acme` | The client logic of ACME by RFC 8555 over a transport of the application: the directory, nonces, accounts with external account binding and key rollover, orders, the `http-01`, `dns-01` and `tls-alpn-01` challenges, finalization, alternate chains, revocation, problem documents and renewal information |
| `krypt-tls` | `com.davils:krypt-tls` | TLS over JSSE, for the JVM only: the `tls { }` DSL, contexts, engines and socket factories, rotating key and trust managers on the path validation of krypt, revocation, Certificate Transparency, mutual TLS with a peer policy and hot reload of material |
| `krypt-testing` | `com.davils:krypt-testing` | Test support: deterministic and replayed randomness, audit logs, test environments and an in-memory ACME server |
| `krypt-bom` | `com.davils:krypt-bom` | The bill of materials of every module |
| `build-logic` | - | One convention plugin per concern, composed by `krypt.kotlin-library` for a library module, `krypt.jvm-library` for a module only the JVM offers, `krypt.bom` for the BOM and `krypt.root` for the root project; they hold nothing but `plugins { }` and `kreate { }` |

`krypt-core` builds on `com.davils:kore-core`, `com.davils:konfetti-core`, `com.davils:kollect-core`,
`kotlinx-coroutines-core` and `kotlinx-io-bytestring`; `krypt-asn1` builds on `krypt-core`, `krypt-primitive` on
both, and `krypt-keyset`, `krypt-stream` and `krypt-storage` each on the one before. `krypt-x509` builds on
`krypt-primitive`; `krypt-keystore`, `krypt-ocsp`, `krypt-ct`, `krypt-jose`, `krypt-cose` and `krypt-cms` on
`krypt-x509`; `krypt-spiffe` and `krypt-acme` on `krypt-jose`; `krypt-authority` on `krypt-ocsp` and
`krypt-keystore`; and `krypt-tls` on `krypt-keystore`, `krypt-ocsp`, `krypt-ct` and `krypt-spiffe`. The code is
ported from the security library of an internal Davils project and hardened on the way.

The package of a module is `com.davils.krypt.<module>` without dashes, and its Java module has the same name. It is
declared in `src/jvmMain/java/module-info.java` of the module, which exports only packages with public API, never an
`internal` package. `krypt-testing` has no `module-info.java`, because `kore-testing` is an automatic module.

## Targets

Every library module is Kotlin Multiplatform with two targets: `jvm` and `wasmJs`. The Wasm tests run under Node.js.
A module that only the JVM can offer, such as TLS over JSSE, applies `krypt.jvm-library` instead.

- Code lives in `src/commonMain/kotlin`. What differs per platform hides behind an `internal expect fun` in
  `<Role>.kt` with its `actual` in `<Role>.jvm.kt` and `<Role>.wasmJs.kt`, or behind the internal backend of
  `krypt-primitive`, and a parity test proves that both targets behave the same. krypt declares no `expect` or `actual`
  class: they are a Beta language feature.
- The JVM backend is JCA. The caller may choose the provider, such as a FIPS provider or PKCS #11 for an HSM, with
  `provider(...)` on the environment. The Wasm backend is WebCrypto through guarded `@JsFun` externals.
- Every cryptographic operation is `suspend`, because WebCrypto answers asynchronously. On the JVM it runs on the
  caller's thread; krypt never chooses a dispatcher and never starts a thread or a timer of its own.

## Verify

```bash
./gradlew check
```

Nothing is done until it is green. `check` compiles with warnings as errors (Kotlin with progressive mode and extra
warnings, javac with `-Xlint:all -Werror`), runs Detekt with type resolution, the Kreate rule set and `allRules` over
the main and the test sources, the tests on the JVM and on Wasm, Kover verification at 97 % of lines, branches and
instructions, the API and semver check, the license header check, the changelog check, every Trivy scan, the
standards audit and the Kreate assurance gate, which blocks on every finding. The gate reads OSV.dev and deps.dev and
Trivy downloads its database, so `check` needs the network. The build runs on JDK 25; toolchains are never downloaded.

## Code rules

Enforced by Detekt with the Kreate rule set, the `libraries` rule set, `allRules` and warnings as errors, without a
baseline, for main and test sources alike. Build scripts and `build-logic` follow the same rules.

- **License header first.** Every `.kt`, `.kts`, `.java`, `.properties` and YAML file starts with the Apache 2.0
  header, byte for byte as in the existing files.
- **No comments.** No `//`, no `/* */` other than the license header. Names, types and tests carry the intent.
- **KDoc on public API only**, with `@param`, `@return`, `@throws` and `@since`. A new declaration gets the version it
  first ships in; existing `@since` values never change. KDoc states behaviour on invalid input, the limits that apply,
  thread safety and every security consideration.
- **No `else`.** Return early; a `when` over a sealed type or an enum is exhaustive without `else ->`. At most two
  `return` statements per function.
- **At most two chained calls.** Name intermediate results and computed conditions.
- **Named arguments** for every call with more than three arguments or with several arguments of one type.
- **One top-level type per file**, named after it; a file of functions is named after its role.
- **No package for a single file**, except the root package and `internal` packages.
- **No `!!`, no `lateinit`.**
- **Explicit API.** Everything is `internal` unless a consumer needs it. What another krypt module needs but a
  consumer does not is public and annotated with Kore's `@DavilsInternal`.
- **Names.** No type, file, function or property carries the name of the library as a prefix: `Crypto`, never
  `KryptCrypto`. The ids of the Gradle plugins keep their `krypt.` prefix. krypt uses the annotations of Kore, such as
  `DavilsInternal` and `DavilsDsl`; its only own annotation is `LegacyCryptography`.
- **Immutable values.** Public types are immutable. No public `data class`: a public value writes `equals`,
  `hashCode` and `toString` by hand and is listed in the `UseDataClass` excludes of `detekt.yaml`; `value class` stays
  allowed.
- **Kotlin first.** Suspending calls are the primary API, configuration is a DSL of `ValidatingBuilder`s, and typed
  results are `Outcome`s of Kore with sealed failures. Atomics come from `kotlin.concurrent.atomics` through a local
  `@OptIn(ExperimentalAtomicApi::class)`; experimental API never appears in a public signature.
- **Nothing global.** No mutable singletons, no static configuration, no global registry, no global caches, no
  threads or timers of the library's own.
- **No logging.** krypt has no logger and no log types. Telemetry runs only through events on konfetti topics, meters
  in kollect and the `AuditSink` of the caller.

## Crypto rules

- **No file system, no network.** krypt never opens a file, a socket or a process. Persistence and transport run only
  through suspending `fun interface`s the caller implements, such as `AuditSink`; in-memory implementations live in
  `krypt-testing` only.
- **No hand-rolled primitives.** Every computation on a secret runs in JCA or WebCrypto. krypt implements only
  encodings and protocols on top: DER, PEM, X.509, CBOR, JOSE, CMS, HKDF over HMAC, HPKE over the KEMs and AEADs,
  path validation and its container format.
- **Agility with safe defaults.** Every operation asks the `CryptoPolicy` of its environment first, on creation, on
  decoding and on verification: `Modern` by default, `Compatible`, `Cnsa2` and `Fips`, or a policy of its own DSL. It
  bounds RSA sizes, the curves and the iterations of PBKDF2 in both directions.
- **Legacy is opt-in and read only.** SHA-1, MD5, RSA PKCS #1 v1.5 encryption, PBES1 and the old ciphers of PKCS #12
  sit behind `@LegacyCryptography`, an opt-in at error level, and are offered for reading only.
- **Secrets wipe themselves.** Key material lives in `SecretBytes` or `SecretText`: zeroisable, `use { }`, a redacted
  `toString`, a constant-time `equals` and no content-based `hashCode`. Private keys are opaque handles with
  `destroy()`; they may be non-extractable, in WebCrypto or in an HSM.
- **Failures reveal nothing.** Decryption has exactly one failure, so there is no padding or timing oracle.
  Verification returns a sealed `Verification`, never a `Boolean`. Exceptions of JCA and WebCrypto are translated,
  never passed through; their messages never reach the caller.
- **Comparisons of secrets and tags run in constant time** through `ConstantTime`.
- **Randomness comes from the environment.** Every key, nonce, salt and serial is drawn from
  `Environment.random`, which is secure by default.

## Security rules

Every input of krypt may come from an attacker: encoded keys, certificates, signatures, ciphertexts, PEM text,
passwords, names and every field of every protocol message.

- **Limits before work.** Every decoder has limits with hard ceilings, such as `DerLimits`: depth, length, element
  counts, PEM size, chain length, iterations of PBKDF2 and the amount of data per key. Nothing is truncated silently.
- **No input decides the complexity.** Grammars are hand-written parsers, never regular expressions. Maps keyed by
  input are bounded and use `OrderedMap` or `OrderedIndex` of Kore, because the hash maps of Wasm have no tree bins.
- **Strict decoding.** DER is canonical or refused: minimal lengths and integers, sorted sets, no indefinite lengths.
  Base64 and hex refuse every non-canonical input.
- **Escape untrusted text exactly once, at the sink.** Every `toString` and exception message that shows text from a
  caller writes it through `SafeText` of Kore.
- **Foreign code is contained.** Sinks and repositories of the caller run inside `contained` or `attempted` of Kore.
- **Hide what Java must not reach.** The runtime lives in `internal` packages that `module-info.java` never exports.
- **Every decoder has hostile tests**: truncated, overlong, non-canonical and nested input, every limit at the limit
  and one past it, and known-answer vectors of the standards.

## Tests

- Kotest `FunSpec` only, Kotest assertions only, no mocking library.
- Tests live in `src/commonUnitTest/kotlin`, which runs on the JVM and on Wasm, in the package of the code they test.
  Tests that need the JDK, such as provider choice or interop with `java.security`, live in `src/jvmUnitTest/kotlin`.
  A `fixture` folder holds at least two files. Shared test support lives in `krypt-testing`, never in main code.
- Known-answer vectors and fixtures made by OpenSSL are checked in as hex constants; tests start no processes. No
  private key in PEM form appears in a source file.
- Every change ships with its tests; a fixed weakness ships with a test that would have caught it.

## Build

- A library module applies exactly one plugin, `id("krypt.kotlin-library")` or, for a module only the JVM offers,
  `id("krypt.jvm-library")`, and declares nothing but its description
  and its dependencies; the BOM applies `id("krypt.bom")`.
- `build-logic` holds no Kotlin classes, no tasks and no Gradle API calls beyond reading the version catalog. Every
  plugin configures one concern and applies `krypt.base`:

  | Plugin | Configures |
  |---|---|
  | `krypt.base` | The Kreate plugin, the group and the version |
  | `krypt.dependency-locking` | Strict locking of every configuration |
  | `krypt.git-hooks` | The Git hooks |
  | `krypt.trivy` | Every Trivy scan |
  | `krypt.assurance` | The assurance gate and its `ignore` rules |
  | `krypt.standards` | The standards krypt follows, reviewed in `standards.lock` |
  | `krypt.platform` | The JDK, the Kotlin compiler, the targets and the Java module name |
  | `krypt.web-tools` | Node.js and Yarn for the Wasm target |
  | `krypt.testing` | Kotest and the test suites |
  | `krypt.detekt` | Detekt and its reports |
  | `krypt.coverage` | Kover and its verification |
  | `krypt.api-validation` | The API dump and the semver check |
  | `krypt.docs` | Dokka |
  | `krypt.publish` | The POM, the release guard and the Davils repository |
  | `krypt.archives` | The legal files and the manifest of every archive |
  | `krypt.tool-classpaths` | The version floors on the class paths of the build tools |
  | `krypt.changelog` | The changelog check |
  | `krypt.license-header` | The license header check |
  | `krypt.bom` | The Java platform of the BOM and its publication |

- Dependencies are declared in `gradle/libs.versions.toml`. Libraries of JetBrains, Kore, konfetti and kollect may be
  added when they are needed; every other dependency needs the approval of a maintainer. krypt depends on no
  cryptography library: a provider such as BouncyCastle is the caller's choice.
- Only `repo.davils.com` serves `com.davils`, through `exclusiveContent`; nothing is resolved from `mavenLocal()`.
- After a dependency changes, refresh the locks and the verification metadata in one run and review what changed:

  ```bash
  ./gradlew kreateResolveAndLockAll :build-logic:dependencies --write-locks --write-verification-metadata pgp,sha256 --export-keys --no-configuration-cache
  ```

- krypt builds only with released versions of Kreate, Kore, konfetti and kollect, trusted by the Davils release key
  `36F578E8AD2D4391E0FA6C18154C625FAD370063`; no trust rule for unsigned snapshots is ever added.
- An `ignore` rule of the assurance gate has a reason, the exact module and an expiry no more than six months ahead.
  CRITICAL and HIGH findings can never be ignored.
- Every standard krypt names is declared in `build-logic/src/main/kotlin/krypt.standards.gradle.kts` and reviewed with
  `./gradlew kreateStandardsReview --standard=<id> --note="..."`. Prefer `rfc()`, `draft()` and `github()` over
  `document()`, whose fingerprints differ between machines.

## Kore internals

krypt opts into these `@DavilsInternal` declarations of Kore; Kore changes them only in a major version:
`SafeText.text`, `SafeText.REDACTED`, `immutableSet`, and `OrderedMap` and `OrderedSet` for the maps and sets keyed
by input. A new use is added here and to the table of Kore's `AGENTS.md`.

## Public API

The `api/*.api` dumps are the contract. `kreateApiCheck` fails on every unrecorded change and `kreateApiSemverCheck`
on a version that does not match it. A deliberate change is recorded with `./gradlew kreateApiDump` and gets a
`CHANGELOG.md` entry. A breaking change needs a major version and a commit marked as breaking. Deprecate before
removing: `@Deprecated` with a `ReplaceWith`, for at least one minor release. Every module carries the same version.

## Releases

The version lives in `gradle.properties` and nowhere else; `kreateReleaseGuard` refuses every other version. Every
build without a release tag is a `-SNAPSHOT`. A release is a tag without a `v`, such as `1.0.0`, on a commit of `main`.
Snapshots go to `https://repo.davils.com/snapshots`, releases to `https://repo.davils.com/releases`, never to Maven
Central. The pipeline publishes with `publishAllPublicationsToDavilsRepository --no-configuration-cache` and signs
with `ORG_GRADLE_PROJECT_signingInMemoryKey`, `…KeyId` and `…KeyPassword`.

## Git

Work on `develop`, release from `main`. Conventional Commits in English with the module as scope, such as
`feat(primitive): ...` or `build: ...`. Small commits, one concern each. Commit only when asked. No `Co-Authored-By`
trailer and no other attribution to tools or AI assistants.
