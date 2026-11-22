# Contributing to krypt

Thank you for helping to build krypt. This document explains how a change gets in. The binding rules for code,
tests and the build are in [AGENTS.md](AGENTS.md); read it before your first change.

## Code of Conduct

Everyone who takes part follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## How to Contribute

1. Open an issue for anything larger than a small fix, so the approach can be agreed on first. Security problems are
   never reported as an issue; see [SECURITY.md](SECURITY.md).
2. Branch from `develop` and keep the change to one concern.
3. Run `./gradlew check` until it is green. It needs JDK 25 and network access.
4. Open a pull request against `develop` and describe what changed and why.

## Development Standards

### One command before you push

```bash
./gradlew check
```

It compiles with warnings as errors, runs Detekt, the tests on the JVM and on Wasm, coverage, the API check, the
license header check, the changelog check, Trivy, the standards audit and the Kreate assurance gate. A pull request is
only merged when it is green.

### Correct before fast

krypt protects keys and data. A change to a primitive, an encoding or a protocol ships with the known-answer vectors of
its standard, runs on both targets with the same result, and proves that tampered, truncated and non-canonical input
is refused. krypt implements no primitive of its own; a computation on a secret belongs to JCA or WebCrypto.

### Security first

Every key, ciphertext, signature, PEM text and password may come from an attacker. A change checks its input against
the limits of krypt first, refuses what the policy forbids, compares secrets in constant time, returns failures without
detail and never shows key material. It ships with tests that run every new limit up to its bound and past it.

### The public API is a gate

The `api` folder of every module records its binary API, for the JVM and for the klib. A deliberate change is
recorded with `./gradlew kreateApiDump`, gets an entry in [CHANGELOG.md](CHANGELOG.md) and, when it breaks
compatibility, waits for the next major version.

### Documentation

Every public declaration has KDoc with `@since`. Internal and private declarations have none, and there are no other
comments.

## Benchmarks

`krypt-benchmark` measures the throughput of the `KRYPT/1` container, the encrypted blob store, field encryption,
blind indexes and, as a baseline, the raw AES-256-GCM and SHA-256 beneath them, with JMH on the JVM. `check` only
compiles and analyses the benchmarks; running them takes minutes and needs a quiet machine.

```bash
./gradlew :krypt-benchmark:smokeBenchmark            # short profile: 1 warm-up and 3 iterations of 0.5 s, one fork
./gradlew :krypt-benchmark:benchmark                 # main profile: 5 warm-ups and 10 iterations of 1 s, two forks
./gradlew :krypt-benchmark:kreateBenchmarkBaseline   # runs the main profile and records benchmarks/baseline.json
./gradlew :krypt-benchmark:kreateBenchmarkCheck      # runs the main profile and compares it with the baseline
```

JMH writes its reports to `krypt-benchmark/build/reports/benchmarks/<profile>`; the comparison lands in
`krypt-benchmark/build/reports/kreate/benchmark/comparison.md`. The check fails when a benchmark loses more than 10 %
beyond its measurement error or disappears from the run. Scores are in operations per second; a benchmark over a fixed
payload reads as bytes per second when multiplied by its size. A baseline holds only on the machine that recorded it,
so record one before a change and compare after it on the same machine, and commit it only for a machine the team
shares.

## Changing a Dependency

Every dependency, the classpath of `build-logic` included, is locked and verified. After changing
`gradle/libs.versions.toml`, refresh both in one run and review what changed:

```bash
./gradlew kreateResolveAndLockAll :build-logic:dependencies --write-locks --write-verification-metadata pgp,sha256 --export-keys --no-configuration-cache
```

A new dependency other than a library of JetBrains, Kore, konfetti or kollect needs the approval of a maintainer.
Kore, konfetti, kollect and Kreate are used in released versions only, never as snapshots.

## Snapshots and Releases

`gradle.properties` holds the version in development. Every push to `develop` publishes it as a `-SNAPSHOT` to
`https://repo.davils.com/snapshots`. A release is the tag of that version without a `v`, such as `1.0.0`, pushed on a
commit of `main`; the pipeline signs it, publishes it to `https://repo.davils.com/releases` and attests it. Before the
tag, the version gets its section in [CHANGELOG.md](CHANGELOG.md).

## Commit Messages

Conventional Commits in English with the module as scope, such as `feat(primitive): add HPKE in PSK mode` or
`fix(asn1): refuse a non-minimal length`. A breaking change is marked with `!` and a `BREAKING CHANGE:`
footer.
