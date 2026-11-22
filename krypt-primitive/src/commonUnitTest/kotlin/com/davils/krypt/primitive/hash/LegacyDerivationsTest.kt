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

@file:OptIn(DavilsInternal::class, LegacyCryptography::class)

package com.davils.krypt.primitive.hash

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.LegacyCryptography
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.SecretText
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.encoding.Hex
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.cryptoPolicy
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.PolicyViolationException
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString

private const val SALT: String = "saltSALTsaltSALTsaltSALTsaltSALTsalt"
private const val EXPECTED: String = "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"
private const val ITERATIONS: Int = 4_096
private const val LENGTH: Int = 25

private val password: SecretText = SecretText.of("passwordPASSWORDpassword")

private suspend fun derive(crypto: Crypto, salt: ByteString, iterations: Int, length: Int): SecretBytes =
    LegacyDerivations.pbkdf2Sha1(
        crypto = crypto,
        password = password,
        salt = salt,
        iterations = iterations,
        length = length,
    )

class LegacyDerivationsTest : FunSpec({
    val legacy = Crypto(environment { policy = cryptoPolicy { acceptLegacy(DigestAlgorithm.Sha1) } })

    test("PBKDF2 with HMAC-SHA-1 matches RFC 6070") {
        val derived = LegacyDerivations.pbkdf2Sha1(
            crypto = legacy,
            password = password,
            salt = SALT.encodeToByteString(),
            iterations = ITERATIONS,
            length = LENGTH,
        )
        derived.reveal { bytes -> ByteString(bytes) } shouldBe checkNotNull(Hex.decode(EXPECTED).getOrNull())
    }

    test("the policy, the salt, the length and the iterations are checked") {
        val salt = SALT.encodeToByteString()
        shouldThrow<PolicyViolationException> {
            derive(crypto = Crypto(), salt = salt, iterations = ITERATIONS, length = LENGTH)
        }
        shouldThrow<PolicyViolationException> {
            derive(crypto = legacy, salt = salt, iterations = 1, length = LENGTH)
        }
        shouldThrow<IllegalArgumentException> {
            derive(crypto = legacy, salt = ByteString(1), iterations = ITERATIONS, length = LENGTH)
        }
        shouldThrow<IllegalArgumentException> {
            derive(crypto = legacy, salt = salt, iterations = ITERATIONS, length = 1)
        }
        shouldThrow<IllegalArgumentException> {
            derive(crypto = legacy, salt = salt, iterations = ITERATIONS, length = Int.MAX_VALUE)
        }
    }
})
