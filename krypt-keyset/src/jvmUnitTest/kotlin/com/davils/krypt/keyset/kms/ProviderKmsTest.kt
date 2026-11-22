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
import com.davils.krypt.core.environment
import com.davils.krypt.core.provider
import com.davils.krypt.primitive.Crypto
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString
import java.security.Security
import javax.crypto.KeyGenerator

private const val SECRET: String = "a data key"
private const val CONTEXT: String = "tenant 7"
private const val AES_BITS: Int = 256
private const val NONCE_BYTES: Int = 12

private fun utf8(text: String): ByteString = ByteString(text.encodeToByteArray())

class ProviderKmsTest : FunSpec({
    val generator = KeyGenerator.getInstance("AES").apply { init(AES_BITS) }
    val key = generator.generateKey()

    test("a key of a provider seals secrets it never hands out") {
        val kms = ProviderKms(crypto = Crypto(), key = key, keyUri = "pkcs11:object=master")
        val ciphertext = kms.encrypt(plaintext = SecretBytes.copyOf(utf8(SECRET)), associatedData = utf8(CONTEXT))
        val opened = kms.decrypt(ciphertext = ciphertext, associatedData = utf8(CONTEXT))
        opened?.reveal { bytes -> bytes.decodeToString() } shouldBe SECRET
        kms.decrypt(ciphertext = ciphertext, associatedData = utf8(SECRET)) shouldBe null
        kms.decrypt(
            ciphertext = ciphertext.substring(startIndex = 0, endIndex = NONCE_BYTES),
            associatedData = utf8(CONTEXT),
        ) shouldBe null
        kms.toString() shouldBe "ProviderKms(pkcs11:object=master)"
    }

    test("the provider of the environment is used when it names one") {
        val sunJce = checkNotNull(Security.getProvider("SunJCE"))
        val crypto = Crypto(environment { provider(sunJce) })
        crypto.environment.provider shouldBe sunJce
        val kms = ProviderKms(crypto = crypto, key = key, keyUri = "jce")
        val ciphertext = kms.encrypt(plaintext = SecretBytes.copyOf(utf8(SECRET)), associatedData = utf8(CONTEXT))
        kms.decrypt(ciphertext = ciphertext, associatedData = utf8(CONTEXT))?.size shouldBe SECRET.length
    }
})
