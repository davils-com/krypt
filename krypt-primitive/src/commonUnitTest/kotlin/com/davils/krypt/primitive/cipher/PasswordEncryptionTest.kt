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

@file:OptIn(DavilsInternal::class)

package com.davils.krypt.primitive.cipher

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.SecretText
import com.davils.krypt.primitive.fixture.fastCrypto
import com.davils.krypt.primitive.fixture.utf8
import com.davils.krypt.primitive.key.KeyFailure
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

private const val CONTENT: String = "certificate bags"
private const val ITERATIONS: Int = 2_048

class PasswordEncryptionTest : FunSpec({
    test("content encrypted with a password is decrypted with it only") {
        val password = SecretText.of("p12 password")
        val (algorithm, ciphertext) = PasswordEncryption.encrypt(
            crypto = fastCrypto,
            plaintext = SecretBytes.copyOf(utf8(CONTENT)),
            password = password,
            iterations = ITERATIONS,
        )
        val opened = PasswordEncryption.decrypt(
            crypto = fastCrypto,
            algorithm = algorithm,
            ciphertext = ciphertext,
            password = password,
        )
        opened.getOrNull()?.reveal { bytes -> bytes.decodeToString() } shouldBe CONTENT
        val wrong = PasswordEncryption.decrypt(
            crypto = fastCrypto,
            algorithm = algorithm,
            ciphertext = ciphertext,
            password = SecretText.of("wrong"),
        )
        wrong.failureOrNull() shouldBe KeyFailure.WrongPassword
        val malformed = PasswordEncryption.decrypt(
            crypto = fastCrypto,
            algorithm = utf8(CONTENT),
            ciphertext = ciphertext,
            password = password,
        )
        malformed.failureOrNull() shouldBe KeyFailure.UnsupportedEncryption
    }
})
