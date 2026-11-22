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

package com.davils.krypt.spiffe.jwt

import com.davils.krypt.core.encoding.Base64
import com.davils.krypt.core.encoding.Base64Alphabet
import com.davils.krypt.jose.JoseKey
import com.davils.krypt.jose.JsonValue
import com.davils.krypt.jose.jws.Jws
import com.davils.krypt.jose.jws.JwsAlgorithm
import com.davils.krypt.jose.jws.JwsSigner
import com.davils.krypt.jose.jwt.Jwt
import com.davils.krypt.jose.jwt.JwtClaims
import com.davils.krypt.jose.jwt.JwtClaimsBuilder
import com.davils.krypt.jose.jwt.jwtClaims
import com.davils.krypt.spiffe.SpiffeLimits
import com.davils.krypt.spiffe.fixture.AUDIENCE
import com.davils.krypt.spiffe.fixture.Minted
import com.davils.krypt.spiffe.fixture.Minted.Companion.KEY_ID
import com.davils.krypt.spiffe.fixture.NOW
import com.davils.krypt.spiffe.fixture.WORKLOAD
import com.davils.krypt.spiffe.fixture.crypto
import com.davils.krypt.spiffe.fixture.failureOf
import com.davils.krypt.spiffe.fixture.svidOf
import com.davils.krypt.spiffe.fixture.workload
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.encodeToByteString
import kotlin.time.Duration.Companion.minutes

private const val HEADER: String = """{"alg":"ES256","kid":"key-1","typ":"JWT"}"""
private const val SUBJECT: String = """"sub":"spiffe://example.org/ns/prod/sa/api""""
private const val REST: String = """"aud":"reports","exp":1800000300"""
private const val CLAIMS: String = "{$SUBJECT,$REST}"
private const val ROLE: String = "role"

private fun encoded(text: String): String =
    Base64.encode(bytes = text.encodeToByteString(), alphabet = Base64Alphabet.Url, padding = false)

private fun token(header: String = HEADER, claims: String = CLAIMS): String =
    encoded(header) + "." + encoded(claims) + ".c2ln"

private fun claims(configure: JwtClaimsBuilder.() -> Unit): JwtClaims = jwtClaims {
    tokenSubject = WORKLOAD
    audience = listOf(AUDIENCE)
    expiresAt = NOW + 5.minutes
    configure()
}

class JwtSvidHostileTest : FunSpec({
    test("tokens that are no compact JWS with encoded claims are malformed") {
        val minted = Minted.of()
        val validator = JwtSvidValidator(crypto, minted.bundles)
        val good = minted.token()
        val parts = good.split('.')
        val cases = listOf(
            "",
            "a.b",
            "a.b.c.d",
            "a.b.c.d.e",
            "!!!.b.c",
            parts[0] + "." + parts[1],
            parts[0] + ".." + parts[2],
            token(claims = "not json"),
            token(claims = "[]"),
            token(header = """{"alg":"ES256","kid":"key-1""""),
            token(header = """{"alg":"ES256","kid":"key-1","b64":false,"crit":["b64"]}"""),
            """{"payload":"a.b","signatures":[]}""",
        )
        cases.forEach { case -> validator.failureOf(case) shouldBe JwtSvidFailure.Malformed }
        validator.failureOf(good.dropLast(2) + "AA") shouldBe JwtSvidFailure.BadSignature
    }

    test("a token is refused one byte past its limit") {
        val minted = Minted.of()
        val good = minted.token()
        val exact = JwtSvidValidator(crypto, minted.bundles, limits = SpiffeLimits(maximumTokenBytes = good.length))
        exact.svidOf(good).id shouldBe workload
        val short = JwtSvidValidator(crypto, minted.bundles, limits = SpiffeLimits(maximumTokenBytes = good.length - 1))
        short.failureOf(good) shouldBe JwtSvidFailure.LimitExceeded
    }

    test("the header holds only alg, kid and typ, with an allowed algorithm, a key id and a JWT type") {
        val validator = JwtSvidValidator(crypto, Minted.of().bundles)
        val cases = listOf(
            """{"alg":"ES256","kid":"key-1","jku":"https://evil.example"}""" to JwtSvidFailure.UnsupportedHeader,
            """{"alg":"ES256","kid":"key-1","cty":"JWT"}""" to JwtSvidFailure.UnsupportedHeader,
            """{"alg":"HS256","kid":"key-1"}""" to JwtSvidFailure.UnsupportedAlgorithm,
            """{"alg":"EdDSA","kid":"key-1"}""" to JwtSvidFailure.UnsupportedAlgorithm,
            """{"alg":"XS256","kid":"key-1"}""" to JwtSvidFailure.UnsupportedAlgorithm,
            """{"alg":"ES256","kid":"key-1","typ":"at+jwt"}""" to JwtSvidFailure.WrongType,
            """{"alg":"ES256","kid":"key-1","typ":"jwt"}""" to JwtSvidFailure.WrongType,
            """{"alg":"ES256"}""" to JwtSvidFailure.MissingKeyId,
            """{"alg":"ES256","kid":"key-1","typ":"JOSE"}""" to JwtSvidFailure.BadSignature,
            """{"alg":"ES256","kid":"key-1"}""" to JwtSvidFailure.BadSignature,
        )
        cases.forEach { (header, failure) -> validator.failureOf(token(header = header)) shouldBe failure }
    }

    test("the subject is a SPIFFE id") {
        val validator = JwtSvidValidator(crypto, Minted.of().bundles)
        val cases = listOf(
            "{$REST}",
            """{"sub":1,$REST}""",
            """{"sub":"spiffe://example.org/",$REST}""",
            """{"sub":"alice",$REST}""",
        )
        cases.forEach { case -> validator.failureOf(token(claims = case)) shouldBe JwtSvidFailure.InvalidSubject }
    }

    test("signed tokens without exp or aud, or with other headers, are refused") {
        val minted = Minted.of()
        val validator = JwtSvidValidator(crypto, minted.bundles)
        val key = JoseKey.Private(key = minted.pair.privateKey, keyId = KEY_ID)
        val jwt = Jwt(crypto)
        val es256 = JwsAlgorithm.ES256
        val unexpiring = jwt.sign(claims = claims { expiresAt = null }, key = key, algorithm = es256)
        validator.failureOf(unexpiring) shouldBe JwtSvidFailure.MissingExpiration
        val unaddressed = jwt.sign(claims = claims { audience = emptyList() }, key = key, algorithm = es256)
        validator.failureOf(unaddressed) shouldBe JwtSvidFailure.WrongAudience
        val roled = claims { claim(name = ROLE, value = JsonValue.Text("x")) }
        val untyped = jwt.sign(claims = roled, key = key, algorithm = es256, type = null)
        val accepted = validator.svidOf(untyped)
        accepted.claims[ROLE] shouldBe JsonValue.Text("x")
        val early = jwt.sign(claims = claims { notBefore = NOW + 2.minutes }, key = key, algorithm = es256)
        validator.failureOf(early) shouldBe JwtSvidFailure.NotYetValid
        val headed = JwsSigner(key = key, algorithm = es256, header = JsonValue.Object.of("x5t" to JsonValue.Text("A")))
        val encodedClaims = claims {}.encode()
        val payload = encodedClaims.encodeToByteString()
        val jws = Jws(crypto)
        validator.failureOf(jws.sign(payload = payload, signer = headed)) shouldBe JwtSvidFailure.UnsupportedHeader
        val plain = JwsSigner(key = key, algorithm = es256)
        val stringly = """{$SUBJECT,"aud":"reports","exp":"soon"}""".encodeToByteString()
        validator.failureOf(jws.sign(payload = stringly, signer = plain)) shouldBe JwtSvidFailure.Malformed
        val json = jws.signJson(payload = payload, signers = listOf(headed))
        validator.failureOf(json) shouldBe JwtSvidFailure.Malformed
    }
})
