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
import com.davils.krypt.asn1.Der
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.io.asByteSource
import com.davils.krypt.keyset.KeyPurpose
import com.davils.krypt.primitive.Verification
import com.davils.krypt.stream.StreamFailure
import com.davils.krypt.stream.StreamLimits
import com.davils.krypt.stream.fixture.bytes
import com.davils.krypt.stream.fixture.crypto
import com.davils.krypt.stream.fixture.keysets
import com.davils.krypt.stream.fixture.manifests
import com.davils.krypt.stream.fixture.utf8
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString

private const val SEGMENT: Long = 65_536L
private const val ROOT_BYTES: Int = 32
private const val DANGLING: Int = 5
private const val NAME: String = "Sha256"

private fun encoded(
    digest: String = NAME,
    length: Long = 0L,
    segments: Long = 0L,
    root: ByteString = ByteString(ByteArray(ROOT_BYTES)),
    tooLong: Boolean = false,
): ByteString = Der.encode {
    sequence {
        sequence {
            integer(1L)
            integer(1L)
            utf8String(digest)
            integer(SEGMENT)
            listOf(length).forEach { value ->
                when (tooLong) {
                    true -> integer(
                        com.davils.krypt.asn1.DerInteger
                            .ofMagnitude(ByteString(ByteArray(ROOT_BYTES) { 1 })),
                    )

                    false -> integer(value)
                }
            }
            integer(segments)
            octetString(root)
            octetString(ByteString())
        }
        sequence { sequence { octetString(ByteString(1)) } }
    }
}

class ManifestEdgeTest : FunSpec({
    test("hostile manifests are refused field by field") {
        manifests.decode(encoded()).failureOrNull() shouldBe null
        manifests.decode(encoded(digest = "Md5")).failureOrNull() shouldBe StreamFailure.Malformed
        manifests.decode(encoded(root = ByteString(1))).failureOrNull() shouldBe StreamFailure.Malformed
        manifests.decode(encoded(length = -1L)).failureOrNull() shouldBe StreamFailure.Malformed
        manifests.decode(encoded(segments = -1L)).failureOrNull() shouldBe StreamFailure.Malformed
        manifests.decode(encoded(tooLong = true)).failureOrNull() shouldBe StreamFailure.Malformed
    }

    test("arguments out of range are refused") {
        val signing = keysets.generate(KeyPurpose.Signing())
        val manifest = manifests.of(bytes(1).asByteSource())
        val signed = manifests.sign(manifest, listOf(keysets.signer(signing)))
        shouldThrow<IllegalArgumentException> {
            manifests.of(
                source = bytes(1).asByteSource(),
                segmentSize = Int.MAX_VALUE,
            )
        }
        val one = Manifests(crypto, StreamLimits(maximumSignatures = 1))
        shouldThrow<IllegalArgumentException> { one.sign(manifest, List(2) { keysets.signer(signing) }) }
        shouldThrow<IllegalArgumentException> { manifests.countersign(signed, -1, keysets.signer(signing)) }
        shouldThrow<IllegalArgumentException> { manifests.timestamp(signed, -1, utf8(NAME)) }
        shouldThrow<IllegalArgumentException> {
            Manifest(
                kind = ManifestKind.Data,
                digest = DigestAlgorithm.Sha256,
                segmentSize = 1,
                length = -1L,
                segments = 0L,
                root = manifest.root,
            )
        }
        shouldThrow<IllegalArgumentException> {
            Manifest(
                kind = ManifestKind.Data,
                digest = DigestAlgorithm.Sha256,
                segmentSize = 1,
                length = 0L,
                segments = -1L,
                root = manifest.root,
            )
        }
        val dangling = SignedManifest(
            manifest,
            listOf(ManifestSignature(signature = utf8(NAME), countersigns = DANGLING)),
        )
        manifests.verifyCountersignature(dangling, 0, keysets.verifier(signing)) shouldBe Verification.Invalid
    }
})
