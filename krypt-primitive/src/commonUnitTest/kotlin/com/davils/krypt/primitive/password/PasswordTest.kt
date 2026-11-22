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
import com.davils.krypt.core.algorithm.KdfAlgorithm
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.cryptoPolicy
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.fixture.fastCrypto
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldStartWith

private const val PASSWORD: String = "correct horse battery staple"
private const val STRONGER: Int = 2_000
private const val FIELDS_SALT: String = "AAAAAAAAAAAAAAAAAAAAAA"
private const val FIELDS_HASH: String = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

class PasswordTest : FunSpec({
    test("a password hash verifies the right password only") {
        val hash = fastCrypto.passwords.hash(SecretText.of(PASSWORD))
        hash shouldStartWith "\$pbkdf2-sha256\$i=1000,l=32\$"
        fastCrypto.passwords.verify(SecretText.of(PASSWORD), hash) shouldBe PasswordVerification.Valid
        fastCrypto.passwords.verify(SecretText.of("wrong"), hash) shouldBe PasswordVerification.Invalid
        PasswordVerification.Valid.isValid shouldBe true
        PasswordVerification.Invalid.isValid shouldBe false
        val sha512 = fastCrypto.passwords.hash(
            password = SecretText.of(PASSWORD),
            algorithm = KdfAlgorithm.Pbkdf2Sha512,
        )
        sha512 shouldStartWith "\$pbkdf2-sha512\$"
        shouldThrow<IllegalArgumentException> {
            fastCrypto.passwords.hash(
                password = SecretText.of(PASSWORD),
                algorithm = KdfAlgorithm.HkdfSha256,
            )
        }
    }

    test("a weaker hash asks to be replaced after a successful check") {
        val hash = fastCrypto.passwords.hash(SecretText.of(PASSWORD))
        val stronger = Crypto(environment { policy = cryptoPolicy { minimumIterations = STRONGER } })
        val verification = stronger.passwords.verify(SecretText.of(PASSWORD), hash)
        verification shouldBe PasswordVerification.ValidButOutdated
        verification.isValid shouldBe true
    }

    context("malformed and excessive hashes are refused unchecked") {
        withData(
            listOf(
                "plain text",
                "\$pbkdf2-sha256\$i=1000,l=32\$$FIELDS_SALT",
                "\$md5\$i=1000,l=32\$$FIELDS_SALT\$$FIELDS_HASH",
                "\$pbkdf2-sha256\$i=x,l=32\$$FIELDS_SALT\$$FIELDS_HASH",
                "\$pbkdf2-sha256\$i=1000,l=31\$$FIELDS_SALT\$$FIELDS_HASH",
                "\$pbkdf2-sha256\$i=1000,l=32\$AAAA\$$FIELDS_HASH",
                "\$pbkdf2-sha256\$i=1000,l=32,x=1\$$FIELDS_SALT\$$FIELDS_HASH",
                "\$pbkdf2-sha256\$i=99999999,l=32\$$FIELDS_SALT\$$FIELDS_HASH",
                "\$pbkdf2-sha256\$i=1000,l=32\$!!!\$$FIELDS_HASH",
                "x".repeat(SIZE_PAST_LIMIT),
            ),
        ) { encoded ->
            fastCrypto.passwords.verify(
                SecretText.of(PASSWORD),
                encoded,
            ) shouldBe PasswordVerification.Malformed
        }
    }
})

private const val SIZE_PAST_LIMIT: Int = 513
