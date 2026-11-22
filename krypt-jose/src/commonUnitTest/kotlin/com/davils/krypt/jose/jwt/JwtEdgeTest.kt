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

import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.jose.JoseKey
import com.davils.krypt.jose.JsonValue
import com.davils.krypt.jose.fixture.NOW
import com.davils.krypt.jose.fixture.compatible
import com.davils.krypt.jose.fixture.value
import com.davils.krypt.jose.jwe.Jwe
import com.davils.krypt.jose.jwe.JweAlgorithm
import com.davils.krypt.jose.jwe.JweEncryption
import com.davils.krypt.jose.jwe.JweRecipient
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlin.time.Duration.Companion.hours

private const val NAME = "edge"

class JwtEdgeTest : FunSpec({
    test("builders show what they were given") {
        val claims = jwtClaims {
            issuer = NAME
            tokenSubject = NAME
            jwtId = NAME
            notBefore = NOW
            issuedAt = NOW
            expiresAt = null
            issuer shouldBe NAME
            tokenSubject shouldBe NAME
            jwtId shouldBe NAME
            notBefore shouldBe NOW
            issuedAt shouldBe NOW
            expiresAt shouldBe null
            audience shouldBe emptyList()
        }
        claims.expiresAt shouldBe null
        val validator = jwtValidator {
            isSignatureRequired = false
            maximumAge = 1.hours
            type shouldBe null
            issuer shouldBe null
            clockSkew.isPositive() shouldBe true
            maximumAge shouldBe 1.hours
            isExpirationRequired shouldBe true
            isSignatureRequired shouldBe false
        }
        validator.toString() shouldContain "1h"
    }

    test("encrypts a token with the default type") {
        val pair = compatible.keys.generate(KeyType.X25519)
        val recipient = JweRecipient(JoseKey.Public(pair.publicKey), JweAlgorithm.EcdhEs)
        val jwt = Jwt(compatible)
        val token = jwt.encrypt(jwtClaims { issuer = NAME }, recipient, JweEncryption.A128GCM)
        val jwe = Jwe(compatible)
        val decoded = jwe.decode(token).value()
        decoded.protectedHeader["typ"] shouldBe JsonValue.Text("JWT")
    }
})
