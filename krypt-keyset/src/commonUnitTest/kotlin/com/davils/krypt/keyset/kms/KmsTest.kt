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

package com.davils.krypt.keyset.kms

import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.algorithm.AeadAlgorithm
import com.davils.krypt.keyset.KeyPurpose
import com.davils.krypt.keyset.fixture.crypto
import com.davils.krypt.keyset.fixture.flipped
import com.davils.krypt.keyset.fixture.keysets
import com.davils.krypt.keyset.fixture.utf8
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlinx.io.bytestring.ByteString

private const val SECRET: String = "a data key"
private const val CONTEXT: String = "tenant 7"
private const val MESSAGE: String = "a large document"
private const val HEADER_BYTES: Int = 4
private const val OVERSIZED: Int = 5_000

private suspend fun opened(kms: KeyManagementService, ciphertext: ByteString, context: String): String? =
    kms.decrypt(ciphertext = ciphertext, associatedData = utf8(context))?.reveal { bytes -> bytes.decodeToString() }

class KmsTest : FunSpec({
    test("a local service seals secrets under its master key") {
        val kms = LocalKms(crypto, crypto.keys.generateSecret())
        val ciphertext = kms.encrypt(plaintext = SecretBytes.copyOf(utf8(SECRET)), associatedData = utf8(CONTEXT))
        opened(kms, ciphertext, CONTEXT) shouldBe SECRET
        opened(kms, ciphertext, SECRET) shouldBe null
        opened(kms, ByteString(), CONTEXT) shouldBe null
        kms.keyUri shouldBe "local"
        kms.algorithm shouldBe AeadAlgorithm.Aes256Gcm
        kms.toString() shouldBe "LocalKms(local, AES-256-GCM)"
    }

    test("a key set service keeps decrypting after its key set rotates") {
        val keyset = keysets.generate(KeyPurpose.Aead())
        val before = KeysetKms(keysets.aead(keyset), "keyset://master")
        val ciphertext = before.encrypt(plaintext = SecretBytes.copyOf(utf8(SECRET)), associatedData = utf8(CONTEXT))
        val after = KeysetKms(keysets.aead(keysets.rotate(keyset)), "keyset://master")
        opened(after, ciphertext, CONTEXT) shouldBe SECRET
        opened(after, ciphertext, SECRET) shouldBe null
        after.toString() shouldBe "KeysetKms(keyset://master)"
    }

    test("an envelope carries its own data key and refuses every change") {
        val kms = LocalKms(crypto, crypto.keys.generateSecret())
        val envelopes = Envelopes(crypto, kms)
        val envelope = envelopes.seal(plaintext = utf8(MESSAGE), associatedData = utf8(CONTEXT))
        envelopes.open(envelope = envelope, associatedData = utf8(CONTEXT)) shouldBe utf8(MESSAGE)
        envelopes.open(envelope) shouldBe null
        envelopes.open(envelope = flipped(envelope, envelope.size - 1), associatedData = utf8(CONTEXT)) shouldBe null
        envelopes.open(envelope = flipped(envelope, HEADER_BYTES), associatedData = utf8(CONTEXT)) shouldBe null
        envelopes.open(envelope = flipped(envelope, 0), associatedData = utf8(CONTEXT)) shouldBe null
        envelopes.open(envelope = flipped(envelope, 2), associatedData = utf8(CONTEXT)) shouldBe null
        envelopes.open(
            envelope = envelope.substring(startIndex = 0, endIndex = HEADER_BYTES),
            associatedData = utf8(CONTEXT),
        ) shouldBe null
        envelopes.open(ByteString()) shouldBe null
        val chacha = Envelopes(crypto = crypto, kms = kms, algorithm = AeadAlgorithm.Aes128Gcm)
        chacha.open(envelope = envelope, associatedData = utf8(CONTEXT)) shouldBe null
        chacha.open(chacha.seal(utf8(MESSAGE))) shouldBe utf8(MESSAGE)
        envelopes.toString() shouldContain "Envelopes(LocalKms"
    }

    test("an envelope refuses a data key the service made too large") {
        val bloated = object : KeyManagementService {
            override val keyUri: String = "bloated"

            override suspend fun encrypt(plaintext: SecretBytes, associatedData: ByteString): ByteString =
                ByteString(ByteArray(OVERSIZED))

            override suspend fun decrypt(ciphertext: ByteString, associatedData: ByteString): SecretBytes? = null
        }
        shouldThrow<IllegalStateException> { Envelopes(crypto, bloated).seal(utf8(MESSAGE)) }
    }
})
