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

package com.davils.krypt.jose.jwe

import com.davils.krypt.core.SecretText
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.CryptoProfile
import com.davils.krypt.core.policy.cryptoPolicy
import com.davils.krypt.jose.JoseFailure
import com.davils.krypt.jose.JoseKey
import com.davils.krypt.jose.JsonValue
import com.davils.krypt.jose.fixture.FixedClock
import com.davils.krypt.jose.fixture.failure
import com.davils.krypt.jose.fixture.utf8
import com.davils.krypt.jose.fixture.value
import com.davils.krypt.primitive.Crypto
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

private const val ITERATIONS: Int = 1_000

private val jwe: Jwe = Jwe(
    crypto = Crypto(
        environment {
            clock = FixedClock
            policy = cryptoPolicy(CryptoProfile.Compatible) { minimumIterations = ITERATIONS }
        },
    ),
    isPasswordAllowed = true,
)

private val algorithms: Set<JweAlgorithm> = setOf(JweAlgorithm.Pbes2Hs256A128KW, JweAlgorithm.A128KW)

private val encryptions: Set<JweEncryption> = setOf(JweEncryption.A128GCM)

private val alice: JoseKey.Password = JoseKey.Password(SecretText.of("alice's password"))

private val bob: JoseKey.Password = JoseKey.Password(SecretText.of("bob's password"))

private fun recipient(password: JoseKey.Password, keyId: String? = null): JweRecipient {
    val header = keyId?.let { found -> JsonValue.Object.of("kid" to JsonValue.Text(found)) } ?: JsonValue.Object.Empty
    return JweRecipient(
        key = password,
        algorithm = JweAlgorithm.Pbes2Hs256A128KW,
        header = header,
        iterations = ITERATIONS,
    )
}

private suspend fun encrypted(recipients: List<JweRecipient>): String =
    jwe.encryptJson(plaintext = utf8("x"), recipients = recipients, encryption = JweEncryption.A128GCM)

private suspend fun decrypted(text: String, vararg keys: JoseKey) =
    jwe.decrypt(text = text, keys = keys.toList(), algorithms = algorithms, encryptions = encryptions)

class JwePasswordTest : FunSpec({
    test("a message with more PBES2 recipients than the bound is refused before any derivation") {
        val bound = List(Jwe.MAXIMUM_PASSWORD_RECIPIENTS) { recipient(alice) }
        decrypted(encrypted(bound), alice).value().plaintext shouldBe utf8("x")
        val tooMany = encrypted(bound + recipient(alice))
        decrypted(tooMany, alice).failure() shouldBe JoseFailure.LimitExceeded
        decrypted(tooMany).failure() shouldBe JoseFailure.LimitExceeded
    }

    test("a password key derives once per message, with the first PBES2 recipient its kid fits") {
        val anonymous = encrypted(listOf(recipient(alice), recipient(bob)))
        decrypted(anonymous, alice).value().plaintext shouldBe utf8("x")
        decrypted(anonymous, bob).failure() shouldBe JoseFailure.DecryptionFailed
        decrypted(anonymous, bob, alice).value().key shouldBe alice
        val named = encrypted(listOf(recipient(alice, keyId = "alice"), recipient(bob, keyId = "bob")))
        val bobWithId = JoseKey.Password(SecretText.of("bob's password"), keyId = "bob")
        decrypted(named, bobWithId).value().key shouldBe bobWithId
    }
})
