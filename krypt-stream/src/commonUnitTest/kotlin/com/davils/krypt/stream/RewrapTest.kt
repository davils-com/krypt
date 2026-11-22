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
import com.davils.krypt.core.io.BufferSink
import com.davils.krypt.core.io.asByteSource
import com.davils.krypt.keyset.KeyPurpose
import com.davils.krypt.stream.fixture.aeadKeyset
import com.davils.krypt.stream.fixture.bytes
import com.davils.krypt.stream.fixture.containers
import com.davils.krypt.stream.fixture.flipped
import com.davils.krypt.stream.fixture.keysets
import com.davils.krypt.stream.fixture.utf8
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

private const val SIZE: Int = 70_000
private const val CONTEXT: String = "archive"

class RewrapTest : FunSpec({
    test("a container moves to new recipients without encrypting its data again") {
        val old = aeadKeyset()
        val person = keysets.generate(KeyPurpose.Hybrid())
        val container = containers.encrypt(
            plaintext = bytes(SIZE),
            recipients = listOf(Recipient.Key(keysets.aead(old))),
            associatedData = utf8(CONTEXT),
        )
        val sink = BufferSink(Int.MAX_VALUE)
        val seal = containers.rewrap(
            source = container.asByteSource(),
            sink = sink,
            credentials = listOf(Credential.Key(keysets.aead(old))),
            recipients = listOf(Recipient.Hybrid(keysets.encrypter(person))),
            associatedData = utf8(CONTEXT),
        )
        val before = checkNotNull(containers.inspect(container.asByteSource()).getOrNull())
        checkNotNull(seal.getOrNull()).root shouldBe before.root
        seal.getOrNull()?.headerDigest shouldNotBe before.headerDigest
        val rewrapped = sink.toByteString()
        val opened = containers.decrypt(
            container = rewrapped,
            credentials = listOf(Credential.Hybrid(keysets.decrypter(person))),
            associatedData = utf8(CONTEXT),
        )
        opened.getOrNull() shouldBe bytes(SIZE)
        val outcome = containers.decrypt(
            container = rewrapped,
            credentials = listOf(Credential.Key(keysets.aead(old))),
            associatedData = utf8(CONTEXT),
        )
        outcome.failureOrNull() shouldBe StreamFailure.NotARecipient
    }

    test("a changed segment is not copied") {
        val keyset = aeadKeyset()
        val container = containers.encrypt(
            plaintext = bytes(SIZE),
            recipients = listOf(Recipient.Key(keysets.aead(keyset))),
        )
        val outcome = containers.rewrap(
            source = flipped(container, container.size - 1).asByteSource(),
            sink = BufferSink(Int.MAX_VALUE),
            credentials = listOf(Credential.Key(keysets.aead(keyset))),
            recipients = listOf(Recipient.Key(keysets.aead(keyset))),
        )
        outcome.failureOrNull() shouldBe StreamFailure.DecryptionFailed
        shouldThrow<IllegalArgumentException> {
            containers.rewrap(
                source = container.asByteSource(),
                sink = BufferSink(Int.MAX_VALUE),
                credentials = emptyList(),
                recipients = emptyList(),
            )
        }
    }
})
