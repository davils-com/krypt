/*
 * Copyright 2026 Davils
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.davils.krypt.stream.manifest

import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.io.asByteSource
import com.davils.krypt.keyset.KeyPurpose
import com.davils.krypt.primitive.Verification
import com.davils.krypt.stream.Credential
import com.davils.krypt.stream.Recipient
import com.davils.krypt.stream.StreamFailure
import com.davils.krypt.stream.StreamLimits
import com.davils.krypt.stream.fixture.SEGMENT
import com.davils.krypt.stream.fixture.aeadKeyset
import com.davils.krypt.stream.fixture.bytes
import com.davils.krypt.stream.fixture.containers
import com.davils.krypt.stream.fixture.crypto
import com.davils.krypt.stream.fixture.flipped
import com.davils.krypt.stream.fixture.keysets
import com.davils.krypt.stream.fixture.manifests
import com.davils.krypt.stream.fixture.utf8
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import kotlinx.io.bytestring.ByteString

private const val SEGMENTS: Long = 6L
private const val MISSING: Int = 7
private const val SHA256_BYTES: Int = 32
private const val SIZE: Int = 5 * SEGMENT + 3
private const val TOKEN: String = "a time-stamp token"

class ManifestsTest : FunSpec({
    test("a manifest describes data in segments and finds every change") {
        val manifest = manifests.of(source = bytes(SIZE).asByteSource(), segmentSize = SEGMENT)
        manifest.segments shouldBe SEGMENTS
        manifest.length shouldBe SIZE.toLong()
        manifest.kind shouldBe ManifestKind.Data
        manifests.matches(manifest, bytes(SIZE).asByteSource()) shouldBe true
        manifests.matches(manifest, flipped(bytes(SIZE), SIZE - 1).asByteSource()) shouldBe false
        manifests.matches(manifest, bytes(SIZE - 1).asByteSource()) shouldBe false
        val empty = manifests.of(ByteString().asByteSource())
        empty.segments shouldBe 0L
        empty.root shouldBe crypto.digests.digest(ByteString())
        val sha512 = manifests.of(source = bytes(SIZE).asByteSource(), digest = DigestAlgorithm.Sha512)
        sha512.root.size shouldBe DigestAlgorithm.Sha512.outputBytes
        shouldThrow<IllegalArgumentException> { manifests.of(source = ByteString().asByteSource(), segmentSize = 1) }
        shouldThrow<IllegalArgumentException> {
            manifests.of(source = ByteString().asByteSource(), digest = DigestAlgorithm.Sha3256)
        }
    }

    test("several signers sign, countersign and time-stamp a manifest") {
        val first = keysets.generate(KeyPurpose.Signing())
        val second = keysets.generate(KeyPurpose.Signing())
        val auditor = keysets.generate(KeyPurpose.Signing())
        val manifest = manifests.of(bytes(SIZE).asByteSource())
        val signed = manifests.sign(manifest, listOf(keysets.signer(first), keysets.signer(second)))
        val verifiers = listOf(first, second).map { keyset -> keysets.verifier(keysets.publicKeyset(keyset)) }
        manifests.verifyAll(signed, verifiers) shouldBe Verification.Valid
        manifests.verify(signed, keysets.verifier(auditor)) shouldBe Verification.Invalid
        manifests.verifyAll(signed, verifiers + keysets.verifier(auditor)) shouldBe Verification.Invalid
        val countersigned = manifests.countersign(signed = signed, index = 1, signer = keysets.signer(auditor))
        manifests.verifyCountersignature(countersigned, 2, keysets.verifier(auditor)) shouldBe Verification.Valid
        manifests.verifyCountersignature(countersigned, 2, verifiers.first()) shouldBe Verification.Invalid
        manifests.verifyCountersignature(countersigned, 0, keysets.verifier(auditor)) shouldBe Verification.Invalid
        manifests.verifyCountersignature(
            countersigned,
            MISSING,
            keysets.verifier(auditor),
        ) shouldBe Verification.Invalid
        manifests.verify(countersigned, keysets.verifier(auditor)) shouldBe Verification.Invalid
        val stamped = manifests.timestamp(signed = countersigned, index = 0, token = utf8(TOKEN))
        stamped.signatures.first().timestamp shouldBe utf8(TOKEN)
        stamped.signatures[1].timestamp shouldBe null
        val decoded = checkNotNull(manifests.decode(manifests.encode(stamped)).getOrNull())
        decoded shouldBe stamped
        manifests.verifyAll(decoded, verifiers) shouldBe Verification.Valid
        shouldThrow<IllegalArgumentException> { manifests.sign(manifest, emptyList()) }
        shouldThrow<IllegalArgumentException> { manifests.countersign(signed, 2, keysets.signer(auditor)) }
        shouldThrow<IllegalArgumentException> { manifests.timestamp(signed, 2, utf8(TOKEN)) }
        shouldThrow<IllegalArgumentException> { manifests.verifyAll(signed, emptyList()) }
        val full = Manifests(crypto, StreamLimits(maximumSignatures = 2))
        shouldThrow<IllegalArgumentException> { full.countersign(signed, 0, keysets.signer(auditor)) }
    }

    test("a container is signed once and checked without decrypting it") {
        val signing = keysets.generate(KeyPurpose.Signing())
        val keyset = aeadKeyset()
        val container = containers.encrypt(
            plaintext = bytes(SIZE),
            recipients = listOf(Recipient.Key(keysets.aead(keyset))),
        )
        val seal = checkNotNull(containers.inspect(container.asByteSource()).getOrNull())
        val signed = manifests.sign(seal.manifest, listOf(keysets.signer(signing)))
        val received = checkNotNull(containers.inspect(container.asByteSource()).getOrNull())
        received.manifest shouldBe signed.manifest
        manifests.verify(signed, keysets.verifier(signing)) shouldBe Verification.Valid
        val changed = checkNotNull(
            containers.inspect(flipped(container, container.size - 1).asByteSource()).getOrNull(),
        )
        changed.manifest shouldNotBe signed.manifest
        shouldThrow<IllegalArgumentException> { manifests.matches(seal.manifest, container.asByteSource()) }
        val outcome1 = containers.decrypt(
            container = container,
            credentials = listOf(Credential.Key(keysets.aead(keyset))),
        )
        outcome1.getOrNull() shouldBe
            bytes(SIZE)
    }

    test("hostile signed manifests are refused") {
        val signing = keysets.generate(KeyPurpose.Signing())
        val signed = manifests.sign(manifests.of(bytes(1).asByteSource()), listOf(keysets.signer(signing)))
        val encoded = manifests.encode(signed)
        manifests.decode(utf8("junk")).failureOrNull() shouldBe StreamFailure.Malformed
        manifests.decode(flipped(encoded, encoded.size - 1)).getOrNull() shouldNotBe signed
        val strict = Manifests(crypto, StreamLimits(maximumSegments = 1))
        val big = manifests.sign(manifests.of(bytes(SIZE).asByteSource(), SEGMENT), listOf(keysets.signer(signing)))
        strict.decode(manifests.encode(big)).failureOrNull() shouldBe StreamFailure.Malformed
        val counter = manifests.countersign(signed, 0, keysets.signer(signing))
        val reordered = SignedManifest(counter.manifest, counter.signatures.reversed())
        manifests.decode(manifests.encode(reordered)).failureOrNull() shouldBe StreamFailure.Malformed
        val unsigned = SignedManifest(signed.manifest, emptyList())
        manifests.decode(manifests.encode(unsigned)).failureOrNull() shouldBe StreamFailure.Malformed
        manifests.toString() shouldContain "Manifests("
    }

    test("manifests and signatures are values") {
        val manifest = manifests.of(bytes(1).asByteSource())
        val signature = ManifestSignature(signature = utf8(TOKEN), countersigns = 0, timestamp = utf8(TOKEN))
        manifest shouldBe manifests.of(bytes(1).asByteSource())
        manifest shouldNotBe manifests.of(bytes(2).asByteSource())
        manifest shouldNotBe Any()
        manifest.hashCode() shouldBe manifest.root.hashCode()
        manifest.toString() shouldContain "Manifest(Data, SHA-256"
        signature shouldBe ManifestSignature(signature = utf8(TOKEN), countersigns = 0, timestamp = utf8(TOKEN))
        signature shouldNotBe ManifestSignature(utf8(TOKEN))
        signature shouldNotBe Any()
        signature.hashCode() shouldBe utf8(TOKEN).hashCode()
        signature.toString() shouldBe "ManifestSignature(bytes=18, countersigns=0, timestamped=true)"
        val signed = SignedManifest(manifest, listOf(signature))
        signed shouldBe SignedManifest(manifest, listOf(signature))
        signed shouldNotBe SignedManifest(manifest, emptyList())
        signed shouldNotBe SignedManifest(manifests.of(bytes(2).asByteSource()), listOf(signature))
        signed shouldNotBe Any()
        signed.hashCode() shouldBe manifest.hashCode()
        signed.toString() shouldContain "signatures=1"
        shouldThrow<IllegalArgumentException> { ManifestSignature(signature = utf8(TOKEN), countersigns = -1) }
        shouldThrow<IllegalArgumentException> {
            Manifest(
                kind = ManifestKind.Data,
                digest = DigestAlgorithm.Sha3256,
                segmentSize = 1,
                length = 0L,
                segments = 0L,
                root = ByteString(ByteArray(SHA256_BYTES)),
            )
        }
        shouldThrow<IllegalArgumentException> {
            Manifest(
                kind = ManifestKind.Data,
                digest = DigestAlgorithm.Sha256,
                segmentSize = 1,
                length = 0L,
                segments = 0L,
                root = ByteString(),
            )
        }
        shouldThrow<IllegalArgumentException> {
            Manifest(
                kind = ManifestKind.Data,
                digest = DigestAlgorithm.Sha256,
                segmentSize = 0,
                length = 0L,
                segments = 0L,
                root = ByteString(ByteArray(SHA256_BYTES)),
            )
        }
    }
})
