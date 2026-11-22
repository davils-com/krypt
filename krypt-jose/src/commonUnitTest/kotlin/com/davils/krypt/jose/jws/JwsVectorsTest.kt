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

package com.davils.krypt.jose.jws

import com.davils.krypt.jose.JoseFailure
import com.davils.krypt.jose.fixture.Rfc7520
import com.davils.krypt.jose.fixture.Vectors
import com.davils.krypt.jose.fixture.compatible
import com.davils.krypt.jose.fixture.failure
import com.davils.krypt.jose.fixture.keyOf
import com.davils.krypt.jose.fixture.publicOf
import com.davils.krypt.jose.fixture.unbase64
import com.davils.krypt.jose.fixture.utf8
import com.davils.krypt.jose.fixture.value
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

private val jws = Jws(compatible)
private val payload = unbase64(Rfc7520.PAYLOAD)

class JwsVectorsTest : FunSpec({
    test("RFC 7520 4.1 signs RS256 deterministically and verifies every serialization") {
        val signer = JwsSigner(key = keyOf(Rfc7520.RSA_PRIVATE), algorithm = JwsAlgorithm.RS256)
        jws.sign(payload = payload, signer = signer) shouldBe Rfc7520.JWS_RS256_COMPACT
        val keys = listOf(publicOf(Rfc7520.RSA_PRIVATE))
        val algorithms = setOf(JwsAlgorithm.RS256)
        jws.verify(text = Rfc7520.JWS_RS256_COMPACT, keys = keys, algorithms = algorithms).value().payload shouldBe
            payload
        jws.verify(text = Rfc7520.JWS_RS256_FLATTENED, keys = keys, algorithms = algorithms).value().algorithm shouldBe
            JwsAlgorithm.RS256
    }

    test("RFC 7520 4.2 and 4.3 verify RSA-PSS and ECDSA P-521 signatures") {
        val rsa = listOf(publicOf(Rfc7520.RSA_PRIVATE))
        val outcome1 = jws.verify(
            text = Rfc7520.JWS_PS384_COMPACT,
            keys = rsa,
            algorithms = setOf(JwsAlgorithm.PS384),
        )
        outcome1.value().payload shouldBe payload
        val outcome2 = jws.verify(
            text = Rfc7520.JWS_PS384_GENERAL,
            keys = rsa,
            algorithms = setOf(JwsAlgorithm.PS384),
        )
        outcome2.value().payload shouldBe payload
        val ec = listOf(publicOf(Rfc7520.EC_P521_PRIVATE))
        val outcome3 = jws.verify(
            text = Rfc7520.JWS_ES512_COMPACT,
            keys = ec,
            algorithms = setOf(JwsAlgorithm.ES512),
        )
        outcome3.value().payload shouldBe payload
        val outcome4 = jws.verify(
            text = Rfc7520.JWS_ES512_FLATTENED,
            keys = ec,
            algorithms = setOf(JwsAlgorithm.ES512),
        )
        outcome4.value().payload shouldBe payload
        val outcome5 = jws.verify(
            text = Rfc7520.JWS_ES512_COMPACT,
            keys = ec,
            algorithms = setOf(JwsAlgorithm.ES256),
        )
        outcome5.failure() shouldBe
            JoseFailure.AlgorithmNotAllowed
    }

    test("RFC 7520 4.4 to 4.7 sign HS256 deterministically and verify every header placement") {
        val key = keyOf(Rfc7520.HMAC_KEY)
        val hs256 = setOf(JwsAlgorithm.HS256)
        jws.sign(
            payload = payload,
            signer = JwsSigner(key = key, algorithm = JwsAlgorithm.HS256),
        ) shouldBe Rfc7520.JWS_HS256_COMPACT
        val outcome6 = jws.verify(
            text = Rfc7520.JWS_HS256_GENERAL,
            keys = listOf(key),
            algorithms = hs256,
        )
        outcome6.value().payload shouldBe payload
        val detached = jws.sign(
            payload = payload,
            signer = JwsSigner(key = key, algorithm = JwsAlgorithm.HS256),
            isDetached = true,
        )
        detached shouldBe Rfc7520.JWS_DETACHED_COMPACT
        val outcome7 = jws.verify(
            text = detached,
            keys = listOf(key),
            algorithms = hs256,
            detachedPayload = payload,
        )
        outcome7.value().payload shouldBe payload
        val outcome8 = jws.verify(
            text = Rfc7520.JWS_DETACHED_FLATTENED,
            keys = listOf(key),
            algorithms = hs256,
            detachedPayload = payload,
        )
        outcome8.value()
        val outcome9 = jws.verify(
            text = Rfc7520.JWS_DETACHED_COMPACT,
            keys = listOf(key),
            algorithms = hs256,
        )
        outcome9.failure() shouldBe JoseFailure.BadSignature
        val outcome10 = jws.verify(
            text = Rfc7520.JWS_PROTECTED_FIELDS_GENERAL,
            keys = listOf(key),
            algorithms = hs256,
        )
        val fields = outcome10.value()
        fields.header.keyId shouldBe "018c0ae5-4d9b-471b-bfd6-eef314bc7037"
        val outcome11 = jws.verify(
            text = Rfc7520.JWS_CONTENT_ONLY_FLATTENED,
            keys = listOf(key),
            algorithms = hs256,
        )
        outcome11.value().payload shouldBe payload
    }

    test("RFC 7520 4.8 verifies each of several signatures with its own key") {
        val all = setOf(JwsAlgorithm.RS256, JwsAlgorithm.ES512, JwsAlgorithm.HS256)
        val outcome12 = jws.verify(
            text = Rfc7520.JWS_MULTIPLE_GENERAL,
            keys = listOf(publicOf(Rfc7520.RSA_PRIVATE)),
            algorithms = all,
        )
        val rsa = outcome12.value()
        rsa.algorithm shouldBe JwsAlgorithm.RS256
        val outcome13 = jws.verify(
            text = Rfc7520.JWS_MULTIPLE_GENERAL,
            keys = listOf(publicOf(Rfc7520.EC_P521_PRIVATE)),
            algorithms = all,
        )
        val ec = outcome13.value()
        ec.algorithm shouldBe JwsAlgorithm.ES512
        val outcome14 = jws.verify(
            text = Rfc7520.JWS_MULTIPLE_GENERAL,
            keys = listOf(keyOf(Rfc7520.HMAC_KEY)),
            algorithms = all,
        )
        val hmac = outcome14.value()
        hmac.algorithm shouldBe JwsAlgorithm.HS256
    }

    test("RFC 7515 A.1, A.3 and E verify HS256 and ES256 and refuse an unknown critical extension") {
        val hmac = listOf(keyOf(Vectors.RFC7515_HMAC_KEY))
        val verification = jws.verify(
            text = Vectors.RFC7515_HMAC_JWS,
            keys = hmac,
            algorithms = setOf(JwsAlgorithm.HS256),
        )
        val claims = verification.value()
        claims.header.type shouldBe "JWT"
        val ec = jws.verify(
            text = Vectors.RFC7515_EC_JWS,
            keys = listOf(publicOf(Vectors.RFC7515_EC_KEY)),
            algorithms = setOf(JwsAlgorithm.ES256),
        )
        ec.value().payload shouldBe claims.payload
        val critical = jws.verify(
            text = Vectors.RFC7515_CRITICAL_JWS,
            keys = hmac,
            algorithms = setOf(JwsAlgorithm.HS256),
        )
        critical.failure() shouldBe JoseFailure.UnknownCritical
    }

    test("RFC 7797 signs and verifies an unencoded detached payload") {
        val key = keyOf(Vectors.RFC7515_HMAC_KEY)
        val content = utf8(Vectors.RFC7797_PAYLOAD)
        val signer = JwsSigner(key = key, algorithm = JwsAlgorithm.HS256)
        jws.sign(
            payload = content,
            signer = signer,
            isDetached = true,
            isPayloadEncoded = false,
        ) shouldBe Vectors.RFC7797_JWS
        val outcome15 = jws.verify(
            text = Vectors.RFC7797_JWS,
            keys = listOf(key),
            algorithms = setOf(JwsAlgorithm.HS256),
            detachedPayload = content,
        )
        val verified = outcome15.value()
        verified.payload shouldBe content
    }

    test("RFC 8037 A.4 and A.5 sign Ed25519 deterministically and verify it") {
        val signer = JwsSigner(key = keyOf(Vectors.RFC8037_PRIVATE), algorithm = JwsAlgorithm.EdDSA)
        jws.sign(payload = utf8(Vectors.RFC8037_PAYLOAD), signer = signer) shouldBe Vectors.RFC8037_JWS
        val keys = listOf(publicOf(Vectors.RFC8037_PRIVATE))
        val outcome16 = jws.verify(
            text = Vectors.RFC8037_JWS,
            keys = keys,
            algorithms = setOf(JwsAlgorithm.EdDSA),
        )
        outcome16.value().payload shouldBe
            utf8(Vectors.RFC8037_PAYLOAD)
        jws.verify(text = Vectors.RFC8037_JWS, keys = keys, algorithms = setOf(JwsAlgorithm.Ed25519)).failure() shouldBe
            JoseFailure.AlgorithmNotAllowed
    }
})
