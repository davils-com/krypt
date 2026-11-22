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

import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.core.SecretText
import com.davils.krypt.core.io.BufferSink
import com.davils.krypt.core.io.asByteSource
import com.davils.krypt.stream.fixture.CountingKms
import com.davils.krypt.stream.fixture.FailingKms
import com.davils.krypt.stream.fixture.ITERATIONS
import com.davils.krypt.stream.fixture.MemoryKms
import com.davils.krypt.stream.fixture.aeadKeyset
import com.davils.krypt.stream.fixture.bytes
import com.davils.krypt.stream.fixture.containers
import com.davils.krypt.stream.fixture.keysets
import com.davils.krypt.stream.fixture.password
import com.davils.krypt.stream.internal.Header
import com.davils.krypt.stream.internal.HeaderCodec
import com.davils.krypt.stream.internal.Octets
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString

private const val SIZE: Int = 100
private const val HOSTILE_ENTRIES: Int = 16
private const val KEY_URI: String = "kms://counted"

private suspend fun replaced(container: ByteString, change: (Header) -> Header): ByteString {
    val header = HeaderCodec.read(container.asByteSource(), containers.limits)
    val body = container.substring(startIndex = header.encoded.size)
    return Octets.concat(change(header).encoded, body)
}

class RecipientWorkTest : FunSpec({
    test("a container with several password recipients is malformed before any PBKDF2 runs") {
        val container = containers.encrypt(
            plaintext = bytes(SIZE),
            recipients = listOf(Recipient.Password(password = password(), iterations = ITERATIONS)),
        )
        val hostile = replaced(container) { header ->
            header.copy(recipients = List(HOSTILE_ENTRIES) { header.recipients.single() })
        }
        val wrong = listOf(Credential.Password(SecretText.of("wrong")))
        containers.decrypt(container = hostile, credentials = wrong) shouldBe Outcome.Failure(StreamFailure.Malformed)
        containers.decrypt(container = container, credentials = wrong) shouldBe
            Outcome.Failure(StreamFailure.NotARecipient)
    }

    test("a container gets at most one password recipient") {
        val twice = listOf(
            Recipient.Password(password = password(), iterations = ITERATIONS),
            Recipient.Password(password = SecretText.of("other"), iterations = ITERATIONS),
        )
        shouldThrow<IllegalArgumentException> { containers.encrypt(plaintext = bytes(SIZE), recipients = twice) }
        val keyset = aeadKeyset()
        val container = containers.encrypt(
            plaintext = bytes(SIZE),
            recipients = listOf(Recipient.Key(keysets.aead(keyset))),
        )
        shouldThrow<IllegalArgumentException> {
            containers.rewrap(
                source = container.asByteSource(),
                sink = BufferSink(Int.MAX_VALUE),
                credentials = listOf(Credential.Key(keysets.aead(keyset))),
                recipients = twice,
            )
        }
    }

    test("a service is asked once per container, for the first entry that names its key") {
        val kms = CountingKms(MemoryKms(KEY_URI))
        val container = containers.encrypt(plaintext = bytes(SIZE), recipients = listOf(Recipient.Service(kms)))
        val hostile = replaced(container) { header ->
            val entry = header.recipients.single()
            header.copy(recipients = List(HOSTILE_ENTRIES - 1) { entry.copy(wrapped = bytes(SIZE)) } + entry)
        }
        val credentials = listOf(Credential.Service(kms))
        containers.decrypt(container = hostile, credentials = credentials) shouldBe
            Outcome.Failure(StreamFailure.NotARecipient)
        kms.decryptions shouldBe 1
        containers.decrypt(container = container, credentials = credentials) shouldBe
            Outcome.Success(bytes(SIZE))
        kms.decryptions shouldBe 2
    }

    test("a service that throws is contained and the next credential is tried") {
        val keyset = aeadKeyset()
        val container = containers.encrypt(
            plaintext = bytes(SIZE),
            recipients = listOf(Recipient.Service(MemoryKms(KEY_URI)), Recipient.Key(keysets.aead(keyset))),
        )
        val failing = Credential.Service(FailingKms(KEY_URI))
        containers.decrypt(container = container, credentials = listOf(failing)) shouldBe
            Outcome.Failure(StreamFailure.NotARecipient)
        val opened = containers.decrypt(
            container = container,
            credentials = listOf(failing, Credential.Key(keysets.aead(keyset))),
        )
        opened shouldBe Outcome.Success(bytes(SIZE))
    }
})
