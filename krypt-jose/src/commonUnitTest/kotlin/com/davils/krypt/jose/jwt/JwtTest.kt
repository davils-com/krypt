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

import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.validation.report.ValidationException
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.jose.JoseFailure
import com.davils.krypt.jose.JoseKey
import com.davils.krypt.jose.JsonValue
import com.davils.krypt.jose.fixture.NOW
import com.davils.krypt.jose.fixture.base64
import com.davils.krypt.jose.fixture.compatible
import com.davils.krypt.jose.fixture.failure
import com.davils.krypt.jose.fixture.value
import com.davils.krypt.jose.jwe.Jwe
import com.davils.krypt.jose.jwe.JweAlgorithm
import com.davils.krypt.jose.jwe.JweEncryption
import com.davils.krypt.jose.jwe.JweRecipient
import com.davils.krypt.jose.jws.Jws
import com.davils.krypt.jose.jws.JwsAlgorithm
import com.davils.krypt.jose.jws.JwsSigner
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

private const val ISSUER = "https://issuer.example"
private const val AUDIENCE = "api"
private const val SUBJECT = "alice"
private const val SCOPE = "scope"
private const val ACCESS = "at+jwt"
private const val OTHER = "other"
private val jwt = Jwt(compatible)
private val jws = Jws(compatible)
private val hmac = JoseKey.Secret(compatible.keys.generateSecret())

private val baseValidator: JwtValidatorBuilder.() -> Unit = {
    algorithms(JwsAlgorithm.HS256)
    issuer = ISSUER
    audience(AUDIENCE)
}

private fun claims(configure: JwtClaimsBuilder.() -> Unit = {}): JwtClaims = jwtClaims {
    issuer = ISSUER
    tokenSubject = SUBJECT
    audience = listOf(AUDIENCE)
    expiresAt = NOW + 10.minutes
    configure()
}

private suspend fun validate(
    token: String,
    configure: JwtValidatorBuilder.() -> Unit = {},
): Outcome<ValidatedJwt, JoseFailure> = jwt.validate(
    token = token,
    validator = jwtValidator {
        baseValidator()
        configure()
    },
    keys = listOf(hmac),
)

private suspend fun signed(claims: JwtClaims, type: String? = "JWT"): String =
    jwt.sign(claims = claims, key = hmac, algorithm = JwsAlgorithm.HS256, type = type)

private suspend fun rawToken(payload: String): String =
    jws.sign(payload = payload.encodeToByteString(), signer = JwsSigner(key = hmac, algorithm = JwsAlgorithm.HS256))

class JwtTest : FunSpec({
    test("signs and validates a token with every registered claim") {
        val claims = claims {
            notBefore = NOW - 1.minutes
            issuedAt = NOW - 1.minutes
            jwtId = "id-1"
            claim(SCOPE, JsonValue.Text("read"))
        }
        val validated = validate(signed(claims)) {
            maximumAge = 1.hours
            require("jti", SCOPE)
        }.value()
        validated.claims shouldBe claims
        validated.claims.issuer shouldBe ISSUER
        validated.claims.subject shouldBe SUBJECT
        validated.claims.audience shouldBe listOf(AUDIENCE)
        validated.claims.expiresAt shouldBe NOW + 10.minutes
        validated.claims.notBefore shouldBe NOW - 1.minutes
        validated.claims.issuedAt shouldBe NOW - 1.minutes
        validated.claims.jwtId shouldBe "id-1"
        validated.claims[SCOPE] shouldBe JsonValue.Text("read")
        validated.algorithm shouldBe JwsAlgorithm.HS256
        validated.key shouldBe hmac
        validated.isEncrypted shouldBe false
        validated.header.type shouldBe "JWT"
        validated shouldBe validate(signed(claims)).value()
        val again = validate(signed(claims)).value()
        validated.hashCode() shouldBe again.hashCode()
        validated shouldNotBe AUDIENCE
        validated.toString() shouldContain "HS256"
        validated.toString() shouldNotContain SUBJECT
        jwt.toString() shouldContain "Jwt"
    }

    test("checks the explicit type") {
        val access = signed(claims(), type = "application/at+jwt")
        validate(access) { type = ACCESS }.value()
        validate(access) { type = "AT+JWT" }.value()
        validate(signed(claims(), type = ACCESS)) { type = "application/at+jwt" }.value()
        validate(signed(claims())) { type = ACCESS }.failure() shouldBe JoseFailure.WrongType
        validate(signed(claims(), type = null)) { type = ACCESS }.failure() shouldBe JoseFailure.WrongType
        validate(signed(claims(), type = "a/b+jwt")) { type = "application/a/b+jwt" }.failure() shouldBe
            JoseFailure.WrongType
        validate(signed(claims(), type = "text/x")) { type = "text/x" }.value()
    }

    test("checks the times with the skew") {
        validate(signed(claims { expiresAt = NOW - 2.minutes })).failure() shouldBe JoseFailure.Expired
        validate(signed(claims { expiresAt = NOW - 30.seconds })).value()
        validate(signed(claims { expiresAt = NOW - 30.seconds })) { clockSkew = 0.seconds }.failure() shouldBe
            JoseFailure.Expired
        validate(signed(claims { notBefore = NOW + 2.minutes })).failure() shouldBe JoseFailure.NotYetValid
        validate(signed(claims { notBefore = NOW + 30.seconds })).value()
        validate(signed(claims { issuedAt = NOW + 2.minutes })).failure() shouldBe JoseFailure.NotYetValid
        validate(signed(claims { issuedAt = NOW - 2.hours })) { maximumAge = 1.hours }.failure() shouldBe
            JoseFailure.Expired
        validate(signed(claims())) { maximumAge = 1.hours }.failure() shouldBe JoseFailure.MissingClaim
        validate(signed(claims { expiresAt = null })).failure() shouldBe JoseFailure.MissingClaim
        validate(signed(claims { expiresAt = null })) { isExpirationRequired = false }.value()
        validate(signed(claims())) { require("jti") }.failure() shouldBe JoseFailure.MissingClaim
    }

    test("checks the issuer and the audience") {
        validate(signed(claims { issuer = OTHER })).failure() shouldBe JoseFailure.WrongIssuer
        validate(signed(claims { issuer = null })).failure() shouldBe JoseFailure.WrongIssuer
        val many = signed(claims { audience = listOf(OTHER, AUDIENCE) })
        validate(many).value().claims.audience shouldBe listOf(OTHER, AUDIENCE)
        validate(signed(claims { audience = listOf(OTHER) })).failure() shouldBe JoseFailure.WrongAudience
        validate(signed(claims { audience = emptyList() })).failure() shouldBe JoseFailure.WrongAudience
        val unexpected = jwt.validate(
            token = signed(claims()),
            validator = jwtValidator { algorithms(JwsAlgorithm.HS256) },
            keys = listOf(hmac),
        )
        unexpected.failure() shouldBe JoseFailure.WrongAudience
        val open = jwt.validate(
            token = signed(claims { audience = emptyList() }),
            validator = jwtValidator { algorithms(JwsAlgorithm.HS256) },
            keys = listOf(hmac),
        )
        open.value().claims.audience shouldBe emptyList()
    }

    test("refuses claims of the wrong type and tokens that are no compact JWS") {
        val expiry = (NOW + 10.minutes).epochSeconds
        val outcome1 = listOf(
            """{"exp":"$expiry"}""",
            """{"exp":$expiry,"aud":[]}""",
            """{"exp":$expiry,"aud":[1]}""",
            """{"exp":$expiry,"aud":1}""",
            """{"exp":$expiry,"iss":1}""",
            "[]",
            "not json",
        )
        outcome1.forEach { payload -> validate(rawToken(payload)).failure() shouldBe JoseFailure.Malformed }
        validate(rawToken("""{"exp":$expiry,"iss":"$ISSUER","aud":["$AUDIENCE"]}""")).value()
        val unencoded = jws.sign(
            "{}".encodeToByteString(),
            JwsSigner(hmac, JwsAlgorithm.HS256),
            isPayloadEncoded = false,
        )
        validate(unencoded).failure() shouldBe JoseFailure.Malformed
        val encoded = claims().encode()
        val json = jws.signJson(
            payload = encoded.encodeToByteString(),
            signers = listOf(JwsSigner(hmac, JwsAlgorithm.HS256)),
        )
        validate(json).failure() shouldBe JoseFailure.Malformed
        validate("a.b").failure() shouldBe JoseFailure.Malformed
        val other = JoseKey.Secret(compatible.keys.generateSecret())
        jwt.validate(signed(claims()), jwtValidator(baseValidator), listOf(other)).failure() shouldBe
            JoseFailure.BadSignature
        validate(signed(claims())) {
            algorithms(JwsAlgorithm.HS512)
        }.value()
        jwt.validate(signed(claims()), jwtValidator { algorithms(JwsAlgorithm.HS512) }, listOf(hmac)).failure() shouldBe
            JoseFailure.AlgorithmNotAllowed
    }

    test("signs and encrypts a nested token and validates it") {
        val pair = compatible.keys.generate(KeyType.P256)
        val recipient = JweRecipient(JoseKey.Public(pair.publicKey), JweAlgorithm.EcdhEsA256KW)
        val nested = jwt.signAndEncrypt(
            claims = claims(),
            key = hmac,
            algorithm = JwsAlgorithm.HS256,
            recipient = recipient,
            encryption = JweEncryption.A256GCM,
        )
        val validator = jwtValidator {
            baseValidator()
            encryption(setOf(JweAlgorithm.EcdhEsA256KW), setOf(JweEncryption.A256GCM))
        }
        val decryptionKeys = listOf(JoseKey.Private(pair.privateKey))
        val outcome1 = jwt.validate(
            token = nested,
            validator = validator,
            keys = listOf(hmac),
            decryptionKeys = decryptionKeys,
        )
        val validated = outcome1.value()
        validated.isEncrypted shouldBe true
        validated.claims shouldBe claims()
        val outcome2 = jwt.validate(
            token = nested,
            validator = jwtValidator(baseValidator),
            keys = listOf(hmac),
            decryptionKeys = decryptionKeys,
        )
        outcome2.failure() shouldBe
            JoseFailure.AlgorithmNotAllowed
        val stranger = JoseKey.Private(compatible.keys.generate(KeyType.P256).privateKey)
        val outcome3 = jwt.validate(
            token = nested,
            validator = validator,
            keys = listOf(hmac),
            decryptionKeys = listOf(stranger),
        )
        outcome3.failure() shouldBe
            JoseFailure.DecryptionFailed
        val encrypted = jwt.encrypt(claims(), recipient, JweEncryption.A256GCM)
        val outcome4 = jwt.validate(
            token = encrypted,
            validator = validator,
            keys = emptyList(),
            decryptionKeys = decryptionKeys,
        )
        outcome4.failure() shouldBe
            JoseFailure.SignatureRequired
        val unsigned = jwtValidator {
            issuer = ISSUER
            audience(AUDIENCE)
            isSignatureRequired = false
            encryption(setOf(JweAlgorithm.EcdhEsA256KW), setOf(JweEncryption.A256GCM))
        }
        val outcome5 = jwt.validate(
            token = encrypted,
            validator = unsigned,
            keys = emptyList(),
            decryptionKeys = decryptionKeys,
        )
        val opened = outcome5.value()
        opened.algorithm shouldBe null
        opened.isEncrypted shouldBe true
        opened.toString() shouldContain "unsigned"
        val jwe = Jwe(compatible)
        val garbage = jwe.encrypt(
            plaintext = "not a token".encodeToByteString(),
            recipient = recipient,
            encryption = JweEncryption.A256GCM,
            header = JsonValue.Object.of("cty" to JsonValue.Text("jwt")),
        )
        val outcome6 = jwt.validate(
            token = garbage,
            validator = validator,
            keys = listOf(hmac),
            decryptionKeys = decryptionKeys,
        )
        outcome6.failure() shouldBe JoseFailure.Malformed
        val binary = jwe.encrypt(
            plaintext = ByteString(byteArrayOf(-1)),
            recipient = recipient,
            encryption = JweEncryption.A256GCM,
            header = JsonValue.Object.of("cty" to JsonValue.Text("JWT")),
        )
        val outcome7 = jwt.validate(
            token = binary,
            validator = validator,
            keys = listOf(hmac),
            decryptionKeys = decryptionKeys,
        )
        outcome7.failure() shouldBe JoseFailure.Malformed
    }

    test("builds claims and validators and refuses inconsistent ones") {
        val claims = claims {
            audience = listOf(AUDIENCE, OTHER)
            issuedAt = NOW
            claim("nested", JsonValue.Object.Empty)
        }
        claims.audience shouldBe listOf(AUDIENCE, OTHER)
        claims.encode() shouldContain """"aud":["api","$OTHER"]"""
        claims shouldBe claims {
            audience = listOf(AUDIENCE, OTHER)
            issuedAt = NOW
            claim("nested", JsonValue.Object.Empty)
        }
        claims.hashCode() shouldNotBe 0
        claims shouldNotBe claims()
        claims shouldNotBe AUDIENCE
        claims.toString() shouldContain "aud"
        claims.toString() shouldNotContain SUBJECT
        shouldThrow<IllegalArgumentException> { jwtClaims { claim("exp", JsonValue.Null) } }
        shouldThrow<IllegalArgumentException> {
            jwtClaims {
                claim("x", JsonValue.Null)
                claim("x", JsonValue.Null)
            }
        }
        shouldThrow<ValidationException> { claims { notBefore = NOW + 20.minutes } }
        shouldThrow<ValidationException> { claims { issuedAt = NOW + 20.minutes } }
        jwtClaims { expiresAt = NOW }.expiresAt shouldBe NOW
        val builder = JwtClaimsBuilder()
        builder.build()
        shouldThrow<IllegalStateException> { builder.issuer = ISSUER }
        shouldThrow<IllegalStateException> { builder.claim("x", JsonValue.Null) }
        listOf<JwtValidatorBuilder.() -> Unit>(
            { clockSkew = (-1).seconds },
            { clockSkew = JwtValidator.MAXIMUM_SKEW + 1.seconds },
            { maximumAge = 0.seconds },
            { algorithms.clear() },
            { encryption(setOf(JweAlgorithm.Dir), emptySet()) },
        ).forEach { change ->
            shouldThrow<ValidationException> {
                jwtValidator {
                    algorithms(JwsAlgorithm.HS256)
                    change()
                }
            }
        }
        val validator = jwtValidator {
            baseValidator()
            type = "JWT"
            critical("x")
        }
        validator shouldBe jwtValidator {
            baseValidator()
            type = "JWT"
            critical("x")
        }
        validator.hashCode() shouldBe jwtValidator {
            baseValidator()
            type = "JWT"
            critical("x")
        }.hashCode()
        validator shouldNotBe jwtValidator(baseValidator)
        validator shouldNotBe AUDIENCE
        validator.toString() shouldContain "HS256"
        validator.critical shouldBe setOf("x")
        jwtValidator { isSignatureRequired = false }.toString() shouldContain "none"
        val open = JwtValidatorBuilder()
        open.algorithms(JwsAlgorithm.HS256)
        open.build()
        shouldThrow<IllegalStateException> { open.type = "x" }
        shouldThrow<IllegalStateException> { open.audience("x") }
        shouldThrow<IllegalStateException> { open.algorithms(JwsAlgorithm.HS384) }
        base64("x") shouldBe "eA"
    }
})
