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
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.io.asByteSource
import com.davils.krypt.stream.fixture.aeadKeyset
import com.davils.krypt.stream.fixture.bytes
import com.davils.krypt.stream.fixture.containers
import com.davils.krypt.stream.fixture.crypto
import com.davils.krypt.stream.fixture.keysets
import com.davils.krypt.stream.fixture.password
import com.davils.krypt.stream.internal.HeaderCodec
import com.davils.krypt.stream.internal.KeySchedule
import com.davils.krypt.stream.internal.Octets
import com.davils.krypt.stream.internal.Wrapping
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

private const val SIZE: Int = 100

class CommitmentTest : FunSpec({
    test("a recipient that hides another data key is refused for everyone") {
        val honest = aeadKeyset()
        val attacker = aeadKeyset()
        val container = containers.encrypt(
            plaintext = bytes(SIZE),
            recipients = listOf(Recipient.Key(keysets.aead(honest))),
        )
        val header = HeaderCodec.read(container.asByteSource(), containers.limits)
        val context = Octets.concat(KeySchedule.RECIPIENT_LABEL, header.core)
        val otherKey = SecretBytes.random(size = KeySchedule.DATA_KEY_BYTES, random = crypto.environment.random)
        val planted = Wrapping(crypto, containers.limits).wrap(
            recipient = Recipient.Key(keysets.aead(attacker)),
            dataKey = otherKey,
            context = context,
        )
        val forged = header.copy(recipients = header.recipients + planted)
        val body = container.substring(startIndex = header.encoded.size)
        val tampered = Octets.concat(forged.encoded, body)
        val asAttacker = containers.decrypt(
            container = tampered,
            credentials = listOf(Credential.Key(keysets.aead(attacker))),
        )
        asAttacker.failureOrNull() shouldBe StreamFailure.DecryptionFailed
        val asHonest = containers.decrypt(
            container = tampered,
            credentials = listOf(Credential.Key(keysets.aead(honest))),
        )
        asHonest.failureOrNull() shouldBe StreamFailure.DecryptionFailed
        val reMac = forged.copy(commitment = header.commitment)
        val outcome1 = containers.decrypt(
            container = Octets.concat(reMac.encoded, body),
            credentials = listOf(Credential.Key(keysets.aead(attacker))),
        )
        outcome1.failureOrNull() shouldBe StreamFailure.DecryptionFailed
    }

    test("a password recipient with a malformed label is malformed") {
        val container = containers.encrypt(
            plaintext = bytes(SIZE),
            recipients = listOf(
                Recipient.Password(
                    com.davils.krypt.stream.fixture
                        .password(),
                    1_000,
                ),
            ),
        )
        val header = HeaderCodec.read(container.asByteSource(), containers.limits)
        val entry = header.recipients.single()
        val forged = header.copy(recipients = listOf(entry.copy(label = bytes(1))))
        val tampered = Octets.concat(forged.encoded, container.substring(startIndex = header.encoded.size))
        val opened = containers.decrypt(
            container = tampered,
            credentials = listOf(
                Credential.Password(
                    com.davils.krypt.stream.fixture
                        .password(),
                ),
            ),
        )
        opened.failureOrNull() shouldBe StreamFailure.Malformed
    }
})
