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

package com.davils.krypt.jose.jwt

import com.davils.krypt.jose.JoseFailure
import com.davils.krypt.jose.JoseKey
import com.davils.krypt.jose.fixture.NOW
import com.davils.krypt.jose.fixture.compatible
import com.davils.krypt.jose.fixture.failure
import com.davils.krypt.jose.fixture.value
import com.davils.krypt.jose.jwe.JweAlgorithm
import com.davils.krypt.jose.jwe.JweEncryption
import com.davils.krypt.jose.jwe.JweRecipient
import com.davils.krypt.jose.jws.JwsAlgorithm
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlin.time.Duration.Companion.minutes

private const val ISSUER: String = "https://issuer.example"
private const val ACCESS: String = "at+jwt"

private val jwt: Jwt = Jwt(compatible)

private val claims: JwtClaims = jwtClaims {
    issuer = ISSUER
    expiresAt = NOW + 10.minutes
}

private val validator: JwtValidator = jwtValidator {
    issuer = ISSUER
    type = ACCESS
    isSignatureRequired = false
    algorithms(JwsAlgorithm.HS256)
    encryption(setOf(JweAlgorithm.Dir), setOf(JweEncryption.A256GCM))
}

private fun flattened(compact: String, unprotected: String): String {
    val parts = compact.split('.').iterator()
    val header = parts.next()
    parts.next()
    return listOf(
        """{"protected":"$header","unprotected":$unprotected,""",
        """"iv":"${parts.next()}","ciphertext":"${parts.next()}","tag":"${parts.next()}"}""",
    ).joinToString(separator = "")
}

private suspend fun validated(token: String, decryptionKeys: List<JoseKey>) =
    jwt.validate(token = token, validator = validator, keys = emptyList(), decryptionKeys = decryptionKeys)

class JwtCompactTest : FunSpec({
    test("a JWE in the JSON serialization cannot carry an unprotected typ into JWT validation") {
        val key = JoseKey.Secret(compatible.keys.generateSecret())
        val compact = jwt.encrypt(
            claims = claims,
            recipient = JweRecipient(key, JweAlgorithm.Dir),
            encryption = JweEncryption.A256GCM,
            type = null,
        )
        val decryptionKeys = listOf(key)
        validated(compact, decryptionKeys).failure() shouldBe JoseFailure.WrongType
        val retyped = flattened(compact, unprotected = """{"typ":"$ACCESS","x":"...."}""")
        validated(retyped, decryptionKeys).failure() shouldBe JoseFailure.Malformed
        val typed = jwt.encrypt(
            claims = claims,
            recipient = JweRecipient(key, JweAlgorithm.Dir),
            encryption = JweEncryption.A256GCM,
            type = ACCESS,
        )
        validated(typed, decryptionKeys).value().claims shouldBe claims
    }

    test("only the compact serialization with two or four dots and Base64url parts is a JWT") {
        val key = JoseKey.Secret(compatible.keys.generateSecret())
        val signed = jwt.sign(claims = claims, key = key, algorithm = JwsAlgorithm.HS256, type = ACCESS)
        val keys = listOf(key)
        jwt.validate(signed, validator, keys).value().claims shouldBe claims
        listOf("$signed=", "$signed.", " $signed", "$signed+", "a.b.c.d", "abc").forEach { token ->
            jwt.validate(token, validator, keys).failure() shouldBe JoseFailure.Malformed
        }
    }
})
