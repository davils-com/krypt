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

package com.davils.krypt.stream

import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.SecretText
import com.davils.krypt.core.io.BufferSink
import com.davils.krypt.core.io.asByteSource
import com.davils.krypt.keyset.KeyPurpose
import com.davils.krypt.stream.fixture.ITERATIONS
import com.davils.krypt.stream.fixture.MemoryKms
import com.davils.krypt.stream.fixture.SEGMENT
import com.davils.krypt.stream.fixture.ShortKms
import com.davils.krypt.stream.fixture.aeadKeyset
import com.davils.krypt.stream.fixture.bytes
import com.davils.krypt.stream.fixture.containers
import com.davils.krypt.stream.fixture.keysets
import com.davils.krypt.stream.fixture.limited
import com.davils.krypt.stream.fixture.password
import com.davils.krypt.stream.internal.Header
import com.davils.krypt.stream.internal.HeaderCodec
import com.davils.krypt.stream.internal.Octets
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.io.bytestring.ByteString

private const val SIZE: Int = 100
private const val PASSWORD_KIND: Int = 4
private const val SALT: Int = 16
private const val LONG_LABEL: Int = 2_000
private const val SHORT_KEY: Int = 16

private suspend fun forged(change: (Header) -> Header): Pair<ByteString, Credential> {
    val keyset = aeadKeyset()
    val container = containers.encrypt(
        plaintext = bytes(SIZE),
        recipients = listOf(Recipient.Key(keysets.aead(keyset))),
    )
    val header = HeaderCodec.read(container.asByteSource(), containers.limits)
    val body = container.substring(startIndex = header.encoded.size)
    return Octets.concat(change(header).encoded, body) to Credential.Key(keysets.aead(keyset))
}

private suspend fun failureOf(forgery: Pair<ByteString, Credential>): StreamFailure? {
    val outcome = containers.decrypt(container = forgery.first, credentials = listOf(forgery.second))
    return outcome.failureOrNull()
}

class EdgeTest : FunSpec({
    test("a header with sizes out of range is malformed") {
        failureOf(forged { header -> header.copy(segmentSize = 1) }) shouldBe StreamFailure.Malformed
        failureOf(forged { header -> header.copy(recipients = emptyList()) }) shouldBe StreamFailure.Malformed
        failureOf(
            forged { header -> header.copy(recipients = header.recipients.map { it.copy(label = bytes(LONG_LABEL)) }) },
        ) shouldBe StreamFailure.Malformed
        failureOf(forged { header -> header.copy(recipients = header.recipients + header.recipients) }) shouldBe
            StreamFailure.DecryptionFailed
    }

    test("strangers of every kind meet recipients of every kind") {
        val recipients = listOf(
            Recipient.Key(keysets.aead(aeadKeyset())),
            Recipient.Hybrid(keysets.encrypter(keysets.generate(KeyPurpose.Hybrid()))),
            Recipient.Service(MemoryKms("kms://one")),
            Recipient.Password(password = password(), iterations = ITERATIONS),
        )
        val container = containers.encrypt(plaintext = bytes(SIZE), recipients = recipients)
        val strangers = listOf(
            Credential.Key(keysets.aead(aeadKeyset())),
            Credential.Hybrid(keysets.decrypter(keysets.generate(KeyPurpose.Hybrid()))),
            Credential.Service(MemoryKms("kms://two")),
            Credential.Password(
                SecretText.of("wrong"),
            ),
        )
        containers.decrypt(container = container, credentials = strangers).failureOrNull() shouldBe
            StreamFailure.NotARecipient
        val broken = forged { header ->
            header.copy(
                recipients = listOf(
                    header.recipients.single().copy(
                        kind = PASSWORD_KIND,
                        label = Octets.concat(bytes(SALT), Octets.u32(ITERATIONS.toLong())),
                        wrapped = bytes(1),
                    ),
                ),
            )
        }
        val wrongBox = containers.decrypt(
            container = broken.first,
            credentials = listOf(Credential.Password(password())),
        )
        wrongBox.failureOrNull() shouldBe StreamFailure.NotARecipient
    }

    test("a service that returns a data key of the wrong size opens nothing") {
        val kms = ShortKms()
        val container = containers.encrypt(plaintext = bytes(SIZE), recipients = listOf(Recipient.Service(kms)))
        val outcome = containers.decrypt(container = container, credentials = listOf(Credential.Service(kms)))
        outcome.failureOrNull() shouldBe StreamFailure.NotARecipient
    }

    test("encryption checks its recipients and its segment size") {
        val recipient = Recipient.Key(keysets.aead(aeadKeyset()))
        val two = List(2) { recipient }
        shouldThrow<IllegalArgumentException> {
            limited(StreamLimits(maximumRecipients = 1)).encrypt(plaintext = bytes(1), recipients = two)
        }
        shouldThrow<IllegalArgumentException> {
            containers.encrypt(
                source = bytes(1).asByteSource(),
                sink = BufferSink(Int.MAX_VALUE),
                recipients = listOf(recipient),
                segmentSize = Int.MAX_VALUE,
            )
        }
    }

    test("a container opened for random access checks its layout") {
        val keyset = aeadKeyset()
        val credentials = listOf(Credential.Key(keysets.aead(keyset)))
        val container = containers.encrypt(
            plaintext = bytes(3 * SEGMENT),
            recipients = listOf(Recipient.Key(keysets.aead(keyset))),
        )
        val small = containers.encrypt(
            plaintext = bytes(SEGMENT),
            recipients = listOf(Recipient.Key(keysets.aead(keyset))),
        )
        val header = HeaderCodec.read(small.asByteSource(), containers.limits)
        val headerOnly = small.substring(startIndex = 0, endIndex = header.encoded.size + 1)
        containers.open(headerOnly.asRandomAccessSource(), credentials).failureOrNull() shouldBe StreamFailure.Malformed
        val strict = limited(StreamLimits(maximumSegments = 1))
        val large = containers.encrypt(
            plaintext = bytes(SEGMENT * SEGMENT / SHORT_KEY),
            recipients = listOf(Recipient.Key(keysets.aead(keyset))),
        )
        strict.open(large.asRandomAccessSource(), credentials).failureOrNull() shouldBe StreamFailure.Malformed
        val reader = checkNotNull(containers.open(container.asRandomAccessSource(), credentials).getOrNull())
        shouldThrow<IllegalArgumentException> { reader.segment(-1L) }
        shouldThrow<IllegalArgumentException> { reader.read(0L, -1) }
        shouldThrow<IllegalArgumentException> { reader.read(0L, Int.MAX_VALUE) }
    }

    test("seals compare by their manifest and their plaintext") {
        val keyset = aeadKeyset()
        val recipient = Recipient.Key(keysets.aead(keyset))
        val container = containers.encrypt(plaintext = bytes(SIZE), recipients = listOf(recipient))
        val seal = checkNotNull(containers.inspect(container.asByteSource()).getOrNull())
        val again = containers.encrypt(plaintext = bytes(SIZE), recipients = listOf(recipient))
        val other = checkNotNull(containers.inspect(again.asByteSource()).getOrNull())
        seal shouldNotBe other
        val sameManifest = ContainerSeal(
            headerDigest = seal.headerDigest,
            segmentSize = seal.segmentSize,
            segments = seal.segments,
            ciphertextBytes = seal.ciphertextBytes,
            plaintextBytes = seal.plaintextBytes + 1,
            root = seal.root,
        )
        seal shouldNotBe sameManifest
    }
})
