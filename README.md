# krypt

krypt is the cryptography and security library of Davils for Kotlin on the JVM and on WebAssembly (`wasmJs`): secrets
that wipe themselves, a crypto policy with profiles for modern, compatible, CNSA 2.0 and FIPS use, and every modern
primitive over JCA on the JVM and WebCrypto in the browser and in Node.js. It never touches the file system or the
network, reports through events on [konfetti](https://github.com/davils-com/konfetti) topics, meters in
[kollect](https://github.com/davils-com/kollect) and an audit sink of the application, and is built on
[Kore](https://github.com/davils-com/kore) for use in enterprise and critical infrastructure. It is published under the
[Apache License 2.0](LICENSE).

| Module | Artifact | What it holds |
|---|---|---|
| `krypt-core` | `com.davils:krypt-core` | Secrets, constant-time comparison, strict hex and Base64, randomness, the algorithm catalogue, the crypto policy, byte streams and the audit trail |
| `krypt-asn1` | `com.davils:krypt-asn1` | The strict DER reader and writer, object identifiers, times and PEM |
| `krypt-primitive` | `com.davils:krypt-primitive` | Keys, digests, MACs, HKDF and PBKDF2, AEADs, key wraps, RSA-OAEP, signatures, key agreement, ML-KEM, HPKE and password hashing |
| `krypt-testing` | `com.davils:krypt-testing` | Deterministic and replayed randomness, audit logs and test environments |
| `krypt-bom` | `com.davils:krypt-bom` | The bill of materials of every module |

krypt is a Kotlin Multiplatform library for `jvm` and `wasmJs`, written for Kotlin 2.4 or newer. On the JVM it
requires JDK 25 and uses its providers, or one the application chooses, such as a FIPS provider or PKCS #11 for an
HSM; krypt itself depends on no cryptography library. Every module is a named Java module, such as
`com.davils.krypt.primitive`. On Wasm it is tested under Node.js.

## Installation

krypt is published to the Davils repository, not to Maven Central. Declare it for the `com.davils` group only:

```kotlin
// settings.gradle.kts
dependencyResolutionManagement {
    repositories {
        exclusiveContent {
            forRepository { maven("https://repo.davils.com/releases") }
            filter { includeGroupAndSubgroups("com.davils") }
        }
        mavenCentral()
    }
}
```

```kotlin
// build.gradle.kts
dependencies {
    implementation(platform("com.davils:krypt-bom:1.0.0"))
    implementation("com.davils:krypt-primitive")
    testImplementation("com.davils:krypt-testing")
}
```

A Maven build names the JVM artifacts directly, such as `com.davils:krypt-primitive-jvm`.

## A short tour

```kotlin
val crypto = Crypto(environment {
    policy = CryptoPolicy.Modern
    events(bus)
    meters(meterRegistry)
    audit(auditSink)
})

val key = crypto.keys.generateSecret()
val box = crypto.aead.seal(key, plaintext, associatedData = recordId)
val opened = crypto.aead.open(key, box, associatedData = recordId) ?: error("tampered")

val signing = crypto.keys.generate(KeyType.Ed25519)
val signature = crypto.signatures.sign(signing.privateKey, document)
crypto.signatures.verify(signing.publicKey, document, signature) // Verification.Valid

val recipient = crypto.keys.generate(KeyType.X25519)
val sealed = crypto.hpke.seal(HpkeSuite.X25519Aes256Gcm, recipient.publicKey, message)

val stored = crypto.passwords.hash(SecretText.of(password))
```

Every operation is `suspend`, because WebCrypto answers asynchronously; on the JVM it runs on the caller's thread.
Every operation asks the policy first and throws `PolicyViolationException` for a forbidden algorithm. A failure that
depends on the data, such as a wrong tag, a wrong password or a malformed key, is a value: `null`, a `Verification` or
an `Outcome` with a sealed failure, never an exception with details an attacker could use.

## Security

krypt assumes that every key, ciphertext, signature, PEM text and password it reads may come from an attacker. Every
decoder is strict and bounded by limits with hard ceilings, secrets wipe themselves, comparisons of secrets run in
constant time, legacy algorithms need an explicit opt-in and are offered for reading only, and failures reveal
nothing. [SECURITY.md](SECURITY.md) describes the threat model, the known limitations and how to report a
vulnerability.

## Building

```bash
./gradlew check
```

It needs JDK 25 and network access. [AGENTS.md](AGENTS.md) holds the rules every change follows and
[CONTRIBUTING.md](CONTRIBUTING.md) how a change gets in.

## License

Copyright 2026 Davils. Licensed under the [Apache License, Version 2.0](LICENSE).
