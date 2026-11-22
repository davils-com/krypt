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
import com.davils.krypt.core.algorithm.AeadAlgorithm
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.cryptoPolicy
import com.davils.krypt.keyset.Keyset
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.stream.fixture.aeadKeyset
import com.davils.krypt.stream.fixture.bytes
import com.davils.krypt.stream.fixture.containers
import com.davils.krypt.stream.fixture.keysets
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString

private const val SIZE: Int = 100

private suspend fun containerFor(keyset: Keyset): ByteString =
    containers.encrypt(plaintext = bytes(SIZE), recipients = listOf(Recipient.Key(keysets.aead(keyset))))

class SuitePolicyTest : FunSpec({
    test("a container of a suite the policy forbids is refused before any key is unwrapped") {
        val keyset = aeadKeyset()
        val container = containerFor(keyset)
        val strict = Containers(Crypto(environment { policy = cryptoPolicy { forbid(AeadAlgorithm.Aes256Gcm) } }))
        val credentials = listOf(Credential.Key(keysets.aead(keyset)))
        strict.decrypt(container = container, credentials = credentials) shouldBe
            Outcome.Failure(StreamFailure.Refused)
        strict.open(source = container.asRandomAccessSource(), credentials = credentials) shouldBe
            Outcome.Failure(StreamFailure.Refused)
    }

    test("a policy that forbids a primitive of the key schedule refuses the container instead of throwing") {
        val keyset = aeadKeyset()
        val container = containerFor(keyset)
        val strict = Containers(Crypto(environment { policy = cryptoPolicy { forbid(DigestAlgorithm.Sha256) } }))
        val opened = strict.decrypt(container = container, credentials = listOf(Credential.Key(keysets.aead(keyset))))
        opened shouldBe Outcome.Failure(StreamFailure.Refused)
    }
})
