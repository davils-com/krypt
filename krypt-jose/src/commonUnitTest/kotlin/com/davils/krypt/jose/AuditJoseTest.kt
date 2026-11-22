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

package com.davils.krypt.jose

import com.davils.krypt.core.SecretText
import com.davils.krypt.core.algorithm.MacAlgorithm
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.CryptoProfile
import com.davils.krypt.core.policy.cryptoPolicy
import com.davils.krypt.jose.fixture.FixedClock
import com.davils.krypt.jose.fixture.NOW
import com.davils.krypt.jose.fixture.base64
import com.davils.krypt.jose.fixture.compatible
import com.davils.krypt.jose.fixture.failure
import com.davils.krypt.jose.fixture.utf8
import com.davils.krypt.jose.jwe.Jwe
import com.davils.krypt.jose.jwe.JweAlgorithm
import com.davils.krypt.jose.jwe.JweEncryption
import com.davils.krypt.jose.jwe.JweRecipient
import com.davils.krypt.jose.jws.Jws
import com.davils.krypt.jose.jws.JwsAlgorithm
import com.davils.krypt.jose.jwt.Jwt
import com.davils.krypt.jose.jwt.jwtClaims
import com.davils.krypt.jose.jwt.jwtValidator
import com.davils.krypt.primitive.Crypto
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlin.time.Duration.Companion.minutes
import kotlin.time.TimeSource

private const val ISSUER: String = "https://issuer.example"
private const val ACCESS: String = "at+jwt"
private const val ITERATIONS: Int = 100_000
private const val RECIPIENTS: Int = 16

class AuditJoseTest : FunSpec({
    test("a JWE in the JSON serialization cannot carry an unprotected typ into JWT validation") {
        val key = JoseKey.Secret(compatible.keys.generateSecret())
        val jwt = Jwt(compatible)
        val claims = jwtClaims {
            issuer = ISSUER
            expiresAt = NOW + 10.minutes
        }
        val compact = jwt.encrypt(
            claims = claims,
            recipient = JweRecipient(key, JweAlgorithm.Dir),
            encryption = JweEncryption.A256GCM,
            type = null,
        )
        val validator = jwtValidator {
            issuer = ISSUER
            type = ACCESS
            isSignatureRequired = false
            encryption(setOf(JweAlgorithm.Dir), setOf(JweEncryption.A256GCM))
        }
        jwt.validate(token = compact, validator = validator, keys = emptyList(), decryptionKeys = listOf(key))
            .failure() shouldBe JoseFailure.WrongType
        val parts = compact.split('.')
        val retyped = "{\"protected\":\"${parts[0]}\",\"unprotected\":{\"typ\":\"$ACCESS\",\"x\":\"....\"}," +
            "\"iv\":\"${parts[2]}\",\"ciphertext\":\"${parts[3]}\",\"tag\":\"${parts[4]}\"}"
        jwt.validate(token = retyped, validator = validator, keys = emptyList(), decryptionKeys = listOf(key))
            .failure() shouldNotBe null
    }

    test("the PBES2 iterations of all recipients of one JWE are bounded together") {
        val engine = Crypto(
            environment {
                clock = FixedClock
                policy = cryptoPolicy(CryptoProfile.Compatible) { minimumIterations = 1_000 }
            },
        )
        val limits = JoseLimits(maximumIterations = ITERATIONS)
        val jwe = Jwe(engine, limits = limits, isPasswordAllowed = true)
        val password = JoseKey.Password(SecretText.of("correct horse"))
        val recipients = List(RECIPIENTS) {
            JweRecipient(password, JweAlgorithm.Pbes2Hs256A128KW, iterations = ITERATIONS)
        }
        val one = jwe.encryptJson(plaintext = utf8("x"), recipients = recipients.take(1), encryption = JweEncryption.A128GCM)
        val many = jwe.encryptJson(plaintext = utf8("x"), recipients = recipients, encryption = JweEncryption.A128GCM)
        val wrong = listOf<JoseKey>(JoseKey.Password(SecretText.of("wrong")))
        val algorithms = setOf(JweAlgorithm.Pbes2Hs256A128KW)
        val encryptions = setOf(JweEncryption.A128GCM)
        val single = TimeSource.Monotonic.markNow()
        jwe.decrypt(text = one, keys = wrong, algorithms = algorithms, encryptions = encryptions)
        val singleTime = single.elapsedNow()
        val start = TimeSource.Monotonic.markNow()
        val failure = jwe.decrypt(text = many, keys = wrong, algorithms = algorithms, encryptions = encryptions).failure()
        val manyTime = start.elapsedNow()
        println("PBES2: 1 recipient ${singleTime.inWholeMilliseconds} ms, $RECIPIENTS recipients ${manyTime.inWholeMilliseconds} ms, ${many.length} chars")
        failure shouldBe JoseFailure.LimitExceeded
    }

    test("an unencoded payload is only accepted when b64 is listed in crit") {
        val key = JoseKey.Secret(compatible.keys.generateSecret())
        val header = base64("{\"alg\":\"HS256\",\"b64\":false}")
        val input = "$header.hello"
        val tag = compatible.macs.mac(key = key.key, data = utf8(input), algorithm = MacAlgorithm.HmacSha256)
        val token = "$input.${base64(tag)}"
        Jws(compatible).verify(text = token, keys = listOf(key), algorithms = setOf(JwsAlgorithm.HS256))
            .failure() shouldNotBe null
    }
})
