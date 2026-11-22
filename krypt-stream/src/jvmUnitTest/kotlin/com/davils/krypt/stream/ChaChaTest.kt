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

import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.io.BufferSink
import com.davils.krypt.core.io.asByteSource
import com.davils.krypt.keyset.KeyPurpose
import com.davils.krypt.keyset.Keysets
import com.davils.krypt.primitive.Crypto
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString

private const val SIZE: Int = 10_000
private const val SEGMENT: Int = 4_096

class ChaChaTest : FunSpec({
    test("a container of ChaCha20-Poly1305 survives the round trip") {
        val crypto = Crypto()
        val keysets = Keysets(crypto)
        val containers = Containers(crypto)
        val keyset = keysets.generate(KeyPurpose.Aead())
        val plaintext = ByteString(ByteArray(SIZE) { index -> index.toByte() })
        val sink = BufferSink(Int.MAX_VALUE)
        containers.encrypt(
            source = plaintext.asByteSource(),
            sink = sink,
            recipients = listOf(Recipient.Key(keysets.aead(keyset))),
            suite = StreamSuite.ChaCha20Poly1305,
            segmentSize = SEGMENT,
        )
        val opened = containers.decrypt(
            container = sink.toByteString(),
            credentials = listOf(Credential.Key(keysets.aead(keyset))),
        )
        opened.getOrNull() shouldBe plaintext
    }
})
