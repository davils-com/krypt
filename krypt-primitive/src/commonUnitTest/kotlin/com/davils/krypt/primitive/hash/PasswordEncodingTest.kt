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

@file:OptIn(LegacyCryptography::class, DavilsInternal::class)

package com.davils.krypt.primitive.hash

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.core.LegacyCryptography
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.SecretText
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.cryptoPolicy
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.fixture.fastCrypto
import com.davils.krypt.primitive.fixture.hex
import com.davils.krypt.primitive.fixture.hexOf
import com.davils.krypt.primitive.key.KeyFailure
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe

private const val SALT: String = "000102030405060708090a0b0c0d0e0f"
private const val ITERATIONS: Int = 1_000
private const val LENGTH: Int = 32
private const val UNICODE_PASSWORD: String = "pässwörd😀"
private const val UNICODE_DERIVED: String = "e1604554369ac856adf59d2723fd72a03fb319e2121db76a935e49bb2b2ba299"

private val legacyCrypto: Crypto = Crypto(
    environment {
        policy = cryptoPolicy {
            acceptLegacy(DigestAlgorithm.Sha1)
            minimumIterations = ITERATIONS
            minimumVerifiedIterations = ITERATIONS
        }
    },
)

private suspend fun derived(text: String): SecretBytes = fastCrypto.derivations.pbkdf2(
    password = SecretText.of(text),
    salt = hex(SALT),
    iterations = ITERATIONS,
    length = LENGTH,
)

class PasswordEncodingTest : FunSpec({
    test("a password with surrogate pairs derives its strict UTF-8 on every platform") {
        hexOf(derived(UNICODE_PASSWORD)) shouldBe UNICODE_DERIVED
    }

    context("a password with an unpaired surrogate is refused before any derivation") {
        withData(listOf("pass\uD800word", "pass\uDC00word", "password\uD800", "\uDC00\uD800")) { password ->
            shouldThrow<IllegalArgumentException> { derived(password) }
            shouldThrow<IllegalArgumentException> {
                LegacyDerivations.pbkdf2Sha1(
                    crypto = legacyCrypto,
                    password = SecretText.of(password),
                    salt = hex(SALT),
                    iterations = ITERATIONS,
                    length = LENGTH,
                )
            }
        }
    }

    test("an encrypted private key neither takes nor opens with a password with an unpaired surrogate") {
        val pair = fastCrypto.keys.generate(KeyType.Ed25519)
        val lone = SecretText.of("pass\uD800word")
        shouldThrow<IllegalArgumentException> { fastCrypto.keys.encrypt(key = pair.privateKey, password = lone) }
        val encrypted = fastCrypto.keys.encrypt(key = pair.privateKey, password = SecretText.of("pass?word"))
        fastCrypto.keys.decrypt(encrypted = encrypted, password = lone) shouldBe
            Outcome.Failure(KeyFailure.WrongPassword)
    }
})
