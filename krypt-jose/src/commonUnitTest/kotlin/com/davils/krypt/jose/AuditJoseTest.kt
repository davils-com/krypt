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

import com.davils.krypt.core.algorithm.MacAlgorithm
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
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlin.time.Duration.Companion.minutes

private const val ISSUER: String = "https://issuer.example"
private const val ACCESS: String = "at+jwt"

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
