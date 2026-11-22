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
import com.davils.krypt.core.environment
import com.davils.krypt.core.io.BufferSink
import com.davils.krypt.core.io.ByteLimitException
import com.davils.krypt.core.io.asByteSource
import com.davils.krypt.core.policy.cryptoPolicy
import com.davils.krypt.keyset.KeyPurpose
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.stream.fixture.ITERATIONS
import com.davils.krypt.stream.fixture.MemoryKms
import com.davils.krypt.stream.fixture.SEGMENT
import com.davils.krypt.stream.fixture.aeadKeyset
import com.davils.krypt.stream.fixture.bytes
import com.davils.krypt.stream.fixture.containers
import com.davils.krypt.stream.fixture.flipped
import com.davils.krypt.stream.fixture.keysets
import com.davils.krypt.stream.fixture.limited
import com.davils.krypt.stream.fixture.password
import com.davils.krypt.stream.fixture.utf8
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import kotlinx.io.bytestring.ByteString

private val HEADER_POSITIONS: List<Int> = listOf(7, 12, 45, 60)
private const val HEADER_TAIL: Int = 40
private const val THREE: Long = 3L
private const val VERSION_BYTE: Int = 5
private const val SUITE_BYTE: Int = 6
private const val TAG: Int = 16
private const val CONTEXT: String = "invoice 7"
private const val THREE_SEGMENTS: Int = 3 * SEGMENT

private suspend fun encrypted(
    plaintext: ByteString,
    recipients: List<Recipient>,
    context: String = CONTEXT,
): ByteString {
    val sink = BufferSink(Int.MAX_VALUE)
    containers.encrypt(
        source = plaintext.asByteSource(),
        sink = sink,
        recipients = recipients,
        associatedData = utf8(context),
        segmentSize = SEGMENT,
    )
    return sink.toByteString()
}

class ContainersTest : FunSpec({
    test("plaintexts of every size survive the round trip") {
        val keyset = aeadKeyset()
        val recipient = Recipient.Key(keysets.aead(keyset))
        val credential = Credential.Key(keysets.aead(keyset))
        listOf(0, 1, SEGMENT - 1, SEGMENT, SEGMENT + 1, THREE_SEGMENTS).forEach { size ->
            val container = encrypted(bytes(size), listOf(recipient))
            val opened = containers.decrypt(
                container = container,
                credentials = listOf(credential),
                associatedData = utf8(CONTEXT),
            )
            opened.getOrNull() shouldBe bytes(size)
        }
    }

    test("every kind of recipient opens the same container") {
        val symmetric = aeadKeyset()
        val hybrid = keysets.generate(KeyPurpose.Hybrid())
        val kms = MemoryKms("kms://master")
        val recipients = listOf(
            Recipient.Key(keysets.aead(symmetric)),
            Recipient.Hybrid(keysets.encrypter(keysets.publicKeyset(hybrid))),
            Recipient.Service(kms),
            Recipient.Password(password = password(), iterations = ITERATIONS),
        )
        val container = encrypted(bytes(SEGMENT + 1), recipients)
        val credentials = listOf(
            Credential.Key(keysets.aead(keysets.rotate(symmetric))),
            Credential.Hybrid(keysets.decrypter(hybrid)),
            Credential.Service(kms),
            Credential.Password(password()),
        )
        credentials.forEach { credential ->
            val opened = containers.decrypt(
                container = container,
                credentials = listOf(credential),
                associatedData = utf8(CONTEXT),
            )
            opened.getOrNull() shouldBe bytes(SEGMENT + 1)
        }
        recipients.map { recipient -> recipient.toString() }.forEach { text -> text shouldContain "Recipient." }
        credentials.map { credential -> credential.toString() }.forEach { text -> text shouldContain "Credential." }
    }

    test("a credential of nobody on the list opens nothing") {
        val container = encrypted(bytes(1), listOf(Recipient.Key(keysets.aead(aeadKeyset()))))
        val strangers = listOf(
            Credential.Key(keysets.aead(aeadKeyset())),
            Credential.Hybrid(keysets.decrypter(keysets.generate(KeyPurpose.Hybrid()))),
            Credential.Service(MemoryKms("kms://other")),
            Credential.Password(password()),
        )
        val opened = containers.decrypt(container = container, credentials = strangers, associatedData = utf8(CONTEXT))
        opened.failureOrNull() shouldBe StreamFailure.NotARecipient
        val kms = MemoryKms("kms://same")
        val other = encrypted(bytes(1), listOf(Recipient.Service(kms)))
        val impostor = containers.decrypt(
            container = other,
            credentials = listOf(Credential.Service(MemoryKms("kms://same"))),
            associatedData = utf8(CONTEXT),
        )
        impostor.failureOrNull() shouldBe StreamFailure.NotARecipient
    }

    test("every change to a container is detected") {
        val keyset = aeadKeyset()
        val credentials = listOf(Credential.Key(keysets.aead(keyset)))
        val container = encrypted(bytes(THREE_SEGMENTS), listOf(Recipient.Key(keysets.aead(keyset))))

        suspend fun failure(changed: ByteString, context: String = CONTEXT): StreamFailure? {
            val outcome1 = containers.decrypt(
                container = changed,
                credentials = credentials,
                associatedData = utf8(context),
            )
            return outcome1.failureOrNull()
        }
        failure(container, "another context") shouldBe StreamFailure.DecryptionFailed
        failure(flipped(container, container.size - 1)) shouldBe StreamFailure.DecryptionFailed
        failure(flipped(container, container.size - SEGMENT)) shouldBe StreamFailure.DecryptionFailed
        val chunk = SEGMENT + TAG
        val body = container.size - THREE_SEGMENTS - 3 * TAG
        val headerEnd = body
        failure(
            container.substring(startIndex = 0, endIndex = container.size - chunk),
        ) shouldBe StreamFailure.DecryptionFailed
        failure(
            container.substring(startIndex = 0, endIndex = container.size - 1),
        ) shouldBe StreamFailure.DecryptionFailed
        failure(container.substring(startIndex = 0, endIndex = headerEnd)) shouldBe StreamFailure.Malformed
        failure(ByteString(container.toByteArray() + bytes(TAG).toByteArray())) shouldBe StreamFailure.DecryptionFailed
        val first = container.substring(startIndex = headerEnd, endIndex = headerEnd + chunk)
        val second = container.substring(startIndex = headerEnd + chunk, endIndex = headerEnd + 2 * chunk)
        val swapped = ByteString(
            container.substring(startIndex = 0, endIndex = headerEnd).toByteArray() +
                second.toByteArray() +
                first.toByteArray() +
                container.substring(startIndex = headerEnd + 2 * chunk).toByteArray(),
        )
        failure(swapped) shouldBe StreamFailure.DecryptionFailed
        HEADER_POSITIONS +
            listOf(headerEnd - 1, headerEnd - HEADER_TAIL).forEach { index ->
                failure(flipped(container, index)) shouldNotBe null
            }
        failure(utf8("KRYPT")) shouldBe StreamFailure.Malformed
        failure(flipped(container, 0)) shouldBe StreamFailure.Malformed
        failure(flipped(container, VERSION_BYTE)) shouldBe StreamFailure.Unsupported
        failure(flipped(container, SUITE_BYTE)) shouldBe StreamFailure.Unsupported
        failure(ByteString()) shouldBe StreamFailure.Malformed
    }

    test("the limits bound what is written and read") {
        val keyset = aeadKeyset()
        val recipient = Recipient.Key(keysets.aead(keyset))
        val small = limited(StreamLimits(maximumSegments = 1))
        val sink = BufferSink(Int.MAX_VALUE)
        shouldThrow<ByteLimitException> {
            small.encrypt(
                source = bytes(THREE_SEGMENTS).asByteSource(),
                sink = sink,
                recipients = listOf(recipient),
                segmentSize = SEGMENT,
            )
        }
        val container = encrypted(bytes(THREE_SEGMENTS), listOf(recipient))
        val opened = small.decrypt(
            container = container,
            credentials = listOf(Credential.Key(keysets.aead(keyset))),
            associatedData = utf8(CONTEXT),
        )
        opened.failureOrNull() shouldBe StreamFailure.Malformed
        val one = limited(StreamLimits(maximumRecipients = 1))
        val outcome2 = one.decrypt(
            container = encrypted(bytes(1), listOf(recipient, recipient)),
            credentials = emptyList(),
        )
        outcome2.failureOrNull() shouldBe
            StreamFailure.Malformed
        shouldThrow<IllegalArgumentException> { containers.encrypt(plaintext = bytes(1), recipients = emptyList()) }
        shouldThrow<IllegalArgumentException> {
            containers.encrypt(
                source = bytes(1).asByteSource(),
                sink = sink,
                recipients = listOf(recipient),
                segmentSize = 1,
            )
        }
        containers.toString() shouldContain "maximumRecipients=16"
    }

    test("a password asks for no more iterations than the policy and the limits allow") {
        val container = encrypted(bytes(1), listOf(Recipient.Password(password = password(), iterations = ITERATIONS)))
        val strict = limited(StreamLimits(maximumIterations = ITERATIONS - 1))
        val refused = strict.decrypt(
            container = container,
            credentials = listOf(Credential.Password(password())),
            associatedData = utf8(CONTEXT),
        )
        refused.failureOrNull() shouldBe StreamFailure.Refused
        val demanding = Crypto(
            environment {
                policy = cryptoPolicy {
                    minimumIterations = ITERATIONS + 1
                    minimumVerifiedIterations = ITERATIONS + 1
                }
            },
        )
        val modern = Containers(demanding)
        val outcome3 = modern.decrypt(
            container = container,
            credentials = listOf(Credential.Password(password())),
            associatedData = utf8(CONTEXT),
        )
        outcome3.failureOrNull() shouldBe StreamFailure.Refused
    }

    test("the seal of a container is found again without its keys") {
        val keyset = aeadKeyset()
        val sink = BufferSink(Int.MAX_VALUE)
        val seal = containers.encrypt(
            source = bytes(THREE_SEGMENTS).asByteSource(),
            sink = sink,
            recipients = listOf(Recipient.Key(keysets.aead(keyset))),
            segmentSize = SEGMENT,
        )
        seal.segments shouldBe THREE
        seal.plaintextBytes shouldBe THREE_SEGMENTS.toLong()
        seal.ciphertextBytes shouldBe sink.size.toLong()
        containers.inspect(sink.toByteString().asByteSource()).getOrNull() shouldBe seal
        val decrypted = BufferSink(Int.MAX_VALUE)
        val opened = containers.decrypt(
            source = sink.toByteString().asByteSource(),
            sink = decrypted,
            credentials = listOf(Credential.Key(keysets.aead(keyset))),
        )
        opened.getOrNull() shouldBe seal
        seal.hashCode() shouldBe seal.root.hashCode()
        seal.toString() shouldContain "segments=3"
        seal shouldNotBe Any()
        containers.inspect(utf8("junk").asByteSource()).failureOrNull() shouldBe StreamFailure.Malformed
    }
})
