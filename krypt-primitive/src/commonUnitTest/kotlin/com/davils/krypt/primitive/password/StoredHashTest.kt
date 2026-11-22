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

package com.davils.krypt.primitive.password

import com.davils.krypt.core.SecretText
import com.davils.krypt.primitive.fixture.fastCrypto
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe

private const val PASSWORD: String = "correct horse"
private const val CANONICAL: String = "i=1000,l=32"

class StoredHashTest : FunSpec({
    context("a stored hash whose parameters are not canonical decimals in the canonical order is malformed") {
        withData(
            listOf(
                "i=01000,l=32",
                "i=+1000,l=32",
                "i=1000,l=032",
                "i=1000,l=+32",
                "i=-1000,l=32",
                "i=,l=32",
                "i=1000,l=",
                "l=32,i=1000",
                "i=1000,l=32,i=1000",
                "i=1000",
                "i=99999999999,l=32",
                "i=1e3,l=32",
                "x=1000,l=32",
            ),
        ) { parameters ->
            val password = SecretText.of(PASSWORD)
            val stored = fastCrypto.passwords.hash(password)
            val altered = stored.replace(CANONICAL, parameters)
            fastCrypto.passwords.verify(password, altered) shouldBe PasswordVerification.Malformed
        }
    }

    test("the canonical stored hash verifies") {
        val password = SecretText.of(PASSWORD)
        val stored = fastCrypto.passwords.hash(password)
        stored.contains(CANONICAL) shouldBe true
        fastCrypto.passwords.verify(password, stored) shouldBe PasswordVerification.Valid
    }

    test("a password with an unpaired surrogate is never hashed and never right") {
        val stored = fastCrypto.passwords.hash(SecretText.of("pass?word"))
        shouldThrow<IllegalArgumentException> { fastCrypto.passwords.hash(SecretText.of("pass\uD800word")) }
        fastCrypto.passwords.verify(SecretText.of("pass\uD800word"), stored) shouldBe PasswordVerification.Invalid
    }
})
