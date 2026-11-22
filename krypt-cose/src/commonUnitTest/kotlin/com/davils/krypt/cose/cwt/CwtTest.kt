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

package com.davils.krypt.cose.cwt

import com.davils.kore.core.validation.report.ValidationException
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.cose.CoseAlgorithm
import com.davils.krypt.cose.CoseMessageType
import com.davils.krypt.cose.CoseRecipientSpec
import com.davils.krypt.cose.CoseSigner
import com.davils.krypt.cose.cbor.Cbor
import com.davils.krypt.cose.cbor.CborArray
import com.davils.krypt.cose.cbor.CborBytes
import com.davils.krypt.cose.cbor.CborFloat
import com.davils.krypt.cose.cbor.CborInteger
import com.davils.krypt.cose.cbor.CborMap
import com.davils.krypt.cose.cbor.CborSimple
import com.davils.krypt.cose.cbor.CborTag
import com.davils.krypt.cose.cbor.CborText
import com.davils.krypt.cose.fixture.CWT_A_3
import com.davils.krypt.cose.fixture.CWT_A_3_KEY_0
import com.davils.krypt.cose.fixture.CWT_A_3_PLAINTEXT
import com.davils.krypt.cose.fixture.CWT_A_4
import com.davils.krypt.cose.fixture.CWT_A_4_KEY_0
import com.davils.krypt.cose.fixture.CWT_A_7
import com.davils.krypt.cose.fixture.NOW
import com.davils.krypt.cose.fixture.cose
import com.davils.krypt.cose.fixture.crypto
import com.davils.krypt.cose.fixture.failure
import com.davils.krypt.cose.fixture.hex
import com.davils.krypt.cose.fixture.key
import com.davils.krypt.cose.fixture.utf8
import com.davils.krypt.cose.fixture.value
import com.davils.krypt.cose.key.CoseKey
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import kotlinx.io.bytestring.ByteString
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

private const val ISSUER: String = "coap://as.example.com"
private const val AUDIENCE: String = "coap://light.example.com"
private const val SUBJECT_NAME: String = "erikw"
private const val EXPIRES: Long = 1_444_064_944L
private const val ISSUED: Long = 1_443_944_944L
private const val HALF_SECOND: Int = 500
private const val HMAC_512_KEY_BYTES: Int = 64
private val EXAMPLE_TIME: Instant = Instant.fromEpochSeconds(1_444_000_000L)
private val cwt: Cwt = Cwt(cose)

private val validation: CwtValidation = cwtValidation {
    algorithms(CoseAlgorithm.Es256, CoseAlgorithm.Hmac256Truncated64)
    issuer = ISSUER
    audience = AUDIENCE
    at = EXAMPLE_TIME
    require(CwtClaims.EXPIRATION, CwtClaims.CWT_ID)
}

private val EVERYTHING: Set<CoseAlgorithm> = CoseAlgorithm.entries.toSet()

private fun everything(configure: CwtValidationBuilder.() -> Unit = {}): CwtValidation = cwtValidation {
    EVERYTHING.forEach { algorithm -> algorithms(algorithm) }
    configure()
}

private val claims: CwtClaims = CwtClaims.of(
    issuer = ISSUER,
    subject = SUBJECT_NAME,
    audience = listOf(AUDIENCE),
    expiration = NOW + 1.hours,
    notBefore = NOW - 1.hours,
    issuedAt = NOW,
    cwtId = utf8("id"),
)

class CwtTest : FunSpec({
    test("the examples of RFC 8392 validate") {
        val outcome1 = cwt.validate(
            encoded = hex(CWT_A_3),
            keys = listOf(key(CWT_A_3_KEY_0)),
            validation = validation,
        )
        val signed = outcome1.value()
        signed.claims shouldBe Cbor.decode(hex(CWT_A_3_PLAINTEXT)).value()
        signed.issuer shouldBe ISSUER
        signed.subject shouldBe SUBJECT_NAME
        signed.audience shouldBe listOf(AUDIENCE)
        signed.expiration shouldBe Instant.fromEpochSeconds(EXPIRES)
        signed.notBefore shouldBe Instant.fromEpochSeconds(ISSUED)
        signed.issuedAt shouldBe Instant.fromEpochSeconds(ISSUED)
        signed.cwtId shouldBe hex("0B71")
        val outcome2 = cwt.validate(
            encoded = hex(CWT_A_4),
            keys = listOf(key(CWT_A_4_KEY_0)),
            validation = validation,
        )
        outcome2.value() shouldBe signed
        val floating = cwt.validate(
            encoded = hex(CWT_A_7),
            keys = listOf(key(CWT_A_4_KEY_0)),
            validation = everything {
                at = EXAMPLE_TIME
                isExpirationRequired = false
            },
        )
        floating.value().issuedAt shouldBe Instant.fromEpochSeconds(ISSUED) + HALF_SECOND.milliseconds
    }

    test("CWTs are signed, MACed and encrypted and validate") {
        val pair = crypto.keys.generate(KeyType.Ed25519)
        val signer = CoseSigner(key = CoseKey.of(pair.privateKey), algorithm = CoseAlgorithm.Ed25519)
        val verifier = CoseKey.of(pair.publicKey)
        val secret = CoseKey.of(crypto.keys.generateSecret())
        val long = CoseKey.of(crypto.keys.generateSecret(HMAC_512_KEY_BYTES))
        listOf(
            Triple(cwt.sign(claims = claims, signer = signer, isCwtTagged = true), verifier, CwtFailure.KeyNotFound),
            Triple(cwt.sign(claims = claims, signer = signer), verifier, CwtFailure.KeyNotFound),
            Triple(
                cwt.mac(claims = claims, key = secret, algorithm = CoseAlgorithm.Hmac256, isCwtTagged = true),
                secret,
                CwtFailure.KeyNotFound,
            ),
            Triple(
                cwt.mac(claims = claims, key = long, algorithm = CoseAlgorithm.Hmac512),
                long,
                CwtFailure.KeyNotFound,
            ),
            Triple(
                cwt.encrypt(claims = claims, key = secret, algorithm = CoseAlgorithm.A256Gcm, isCwtTagged = true),
                secret,
                CwtFailure.DecryptionFailed,
            ),
            Triple(
                cwt.encrypt(claims = claims, key = secret, algorithm = CoseAlgorithm.A256Gcm),
                secret,
                CwtFailure.DecryptionFailed,
            ),
        ).forEach { (encoded, key, failure) ->
            cwt.validate(encoded = encoded, keys = listOf(key), validation = everything()).value() shouldBe claims
            cwt.validate(encoded = encoded, keys = emptyList(), validation = everything()).failure() shouldBe failure
        }
        val payload = Cbor.encode(claims.claims)
        val multiple = cose.sign(payload = payload, signers = listOf(signer)).encode()
        cwt.validate(encoded = multiple, keys = listOf(verifier), validation = everything()).value() shouldBe claims
        val outcome3 = cose.mac(
            payload = payload,
            algorithm = CoseAlgorithm.Hmac256,
            recipients = listOf(CoseRecipientSpec(key = secret, algorithm = CoseAlgorithm.Direct)),
        )
        val mac = outcome3.encode()
        cwt.validate(encoded = mac, keys = listOf(secret), validation = everything()).value() shouldBe claims
        val outcome4 = cose.encrypt(
            plaintext = payload,
            algorithm = CoseAlgorithm.A256Gcm,
            recipients = listOf(CoseRecipientSpec(key = secret, algorithm = CoseAlgorithm.Direct)),
        )
        val encrypted = outcome4.encode()
        cwt.validate(encoded = encrypted, keys = listOf(secret), validation = everything()).value() shouldBe claims
        cwt.toString() shouldContain "Cwt("
    }

    test("a signed CWT nested in an encrypted one validates with both keys") {
        val pair = crypto.keys.generate(KeyType.P256)
        val signer = CoseSigner(key = CoseKey.of(pair.privateKey), algorithm = CoseAlgorithm.Esp256)
        val secret = CoseKey.of(crypto.keys.generateSecret())
        val inner = cwt.sign(claims = claims, signer = signer)
        val outer = cose.encrypt0(plaintext = inner, key = secret, algorithm = CoseAlgorithm.A256Gcm).encode()
        val outcome5 = cwt.validate(
            encoded = outer,
            keys = listOf(secret, CoseKey.of(pair.publicKey)),
            validation = everything(),
        )
        outcome5.value() shouldBe claims
        val outcome6 = cwt.validate(
            encoded = outer,
            keys = listOf(secret),
            validation = everything(),
        )
        outcome6.failure() shouldBe CwtFailure.KeyNotFound
        val deep = (1..Cwt.MAXIMUM_LAYERS).fold(inner) { content, _ ->
            cose.encrypt0(plaintext = content, key = secret, algorithm = CoseAlgorithm.A256Gcm).encode()
        }
        val outcome7 = cwt.validate(
            encoded = deep,
            keys = listOf(secret, CoseKey.of(pair.publicKey)),
            validation = everything(),
        )
        outcome7.failure() shouldBe
            CwtFailure.Malformed
    }

    test("the claims are checked against the validation") {
        val secret = CoseKey.of(crypto.keys.generateSecret())
        val encoded = cwt.mac(claims = claims, key = secret, algorithm = CoseAlgorithm.Hmac256)
        val keys = listOf(secret)
        cwt.validate(encoded, keys, everything { issuer = "other" }).failure() shouldBe CwtFailure.WrongIssuer
        cwt.validate(encoded, keys, everything { audience = "other" }).failure() shouldBe CwtFailure.WrongAudience
        cwt.validate(encoded, keys, everything { require(CborText("private")) }).failure() shouldBe
            CwtFailure.MissingClaim
        cwt.validate(encoded, keys, everything { at = NOW + 2.hours }).failure() shouldBe CwtFailure.Expired
        cwt.validate(encoded, keys, everything { at = NOW + 1.hours + 5.minutes }).failure() shouldBe CwtFailure.Expired
        cwt.validate(encoded, keys, everything { at = NOW + 1.hours + 4.minutes }).value() shouldBe claims
        cwt.validate(encoded, keys, everything { at = NOW - 2.hours }).failure() shouldBe CwtFailure.NotYetValid
        cwt.validate(encoded, keys, everything { at = NOW - 1.hours - 1.minutes }).failure() shouldBe
            CwtFailure.IssuedInFuture
        val future = CwtClaims.of(issuedAt = NOW + 1.hours)
        val fresh = cwt.mac(claims = future, key = secret, algorithm = CoseAlgorithm.Hmac256)
        val lasting = everything { isExpirationRequired = false }
        val outcome8 = cwt.validate(
            encoded = fresh,
            keys = keys,
            validation = lasting,
        )
        outcome8.failure() shouldBe CwtFailure.IssuedInFuture
        val bare = cwt.mac(claims = CwtClaims.of(), key = secret, algorithm = CoseAlgorithm.Hmac256)
        cwt.validate(encoded = bare, keys = keys, validation = everything()).failure() shouldBe CwtFailure.MissingClaim
        cwt.validate(encoded = bare, keys = keys, validation = lasting).value() shouldBe CwtClaims.of()
        cwt.validate(bare, keys, everything { audience = AUDIENCE }).failure() shouldBe CwtFailure.MissingClaim
        val anywhere = everything {
            audience = AUDIENCE
            isExpirationRequired = false
        }
        cwt.validate(bare, keys, anywhere).failure() shouldBe CwtFailure.WrongAudience
        everything().isExpirationRequired shouldBe true
        lasting.isExpirationRequired shouldBe false
        (lasting == everything()) shouldBe false
        lasting.toString() shouldContain "expirationRequired=false"
        cwt.validate(encoded, keys, cwtValidation { algorithms(CoseAlgorithm.Hmac384) }).failure() shouldBe
            CwtFailure.AlgorithmNotPermitted
    }

    test("untagged CWTs need the type of the validation") {
        val secret = CoseKey.of(crypto.keys.generateSecret())
        val payload = Cbor.encode(claims.claims)
        val outcome9 = cose.mac0(
            payload = payload,
            key = secret,
            algorithm = CoseAlgorithm.Hmac256,
        )
        val untagged = outcome9.encode(isTagged = false)
        val outcome10 = cwt.validate(
            encoded = untagged,
            keys = listOf(secret),
            validation = everything(),
        )
        outcome10.failure() shouldBe CwtFailure.Malformed
        val outcome11 = cwt.validate(
            untagged,
            listOf(secret),
            everything { untaggedType = CoseMessageType.Mac0 },
        )
        outcome11.value() shouldBe claims
        val cwtTagged = Cbor.encode(CborTag(number = Cwt.TAG, content = Cbor.decode(untagged).value()))
        cwt.validate(cwtTagged, listOf(secret), everything { untaggedType = CoseMessageType.Mac0 }).failure() shouldBe
            CwtFailure.Malformed
    }

    test("claims that are not a map of typed claims are refused") {
        val secret = CoseKey.of(crypto.keys.generateSecret())
        listOf(
            Cbor.encode(CborArray.of()),
            Cbor.encode(CborMap.of(CborInteger.of(1) to CborInteger.of(1))),
            Cbor.encode(CborMap.of(CborSimple.True to CborInteger.of(1))),
            Cbor.encode(CborMap.of(CborInteger.of(CwtClaims.EXPIRATION) to CborFloat(Double.NaN))),
            Cbor.encode(CborMap.of(CborInteger.of(CwtClaims.AUDIENCE) to CborArray.of())),
            Cbor.encode(CborMap.of(CborInteger.of(CwtClaims.CWT_ID) to CborText("id"))),
            utf8("not cbor"),
        ).forEach { payload ->
            val encoded = cose.mac0(payload = payload, key = secret, algorithm = CoseAlgorithm.Hmac256).encode()
            val outcome12 = cwt.validate(
                encoded = encoded,
                keys = listOf(secret),
                validation = everything(),
            )
            outcome12.failure() shouldBe CwtFailure.Malformed
        }
        val outcome13 = cwt.validate(
            encoded = utf8("not cbor"),
            keys = listOf(secret),
            validation = everything(),
        )
        outcome13.failure() shouldBe CwtFailure.Malformed
        val detached = cose.mac0(
            payload = utf8("x"),
            key = secret,
            algorithm = CoseAlgorithm.Hmac256,
            isDetached = true,
        )
        val outcome14 = cwt.validate(
            encoded = detached.encode(),
            keys = listOf(secret),
            validation = everything(),
        )
        outcome14.failure() shouldBe CwtFailure.Malformed
    }

    test("claims and validations are values") {
        claims shouldBe CwtClaims.of(claims.claims)
        claims shouldNotBe CwtClaims.of()
        claims.equals(ISSUER) shouldBe false
        claims.hashCode() shouldBe claims.claims.hashCode()
        claims.toString() shouldContain "CwtClaims"
        claims[CwtClaims.ISSUER] shouldBe CborText(ISSUER)
        claims[CborInteger.of(CwtClaims.SUBJECT)] shouldBe CborText(SUBJECT_NAME)
        CwtClaims.of(audience = listOf("a", "b")).audience shouldBe listOf("a", "b")
        CwtClaims.of().audience shouldBe emptyList()
        CwtClaims.of(others = CborMap.of(CborText("private") to CborBytes(ByteString()))).claims.size shouldBe 1
        shouldThrow<IllegalArgumentException> { CwtClaims.of(CborMap.of(CborInteger.of(1) to CborInteger.of(1))) }
        shouldThrow<IllegalArgumentException> {
            CwtClaims.of(issuer = ISSUER, others = CborMap.of(CborInteger.of(1) to CborText(ISSUER)))
        }
        validation shouldBe cwtValidation {
            algorithms(CoseAlgorithm.Es256, CoseAlgorithm.Hmac256Truncated64)
            issuer = ISSUER
            audience = AUDIENCE
            at = EXAMPLE_TIME
            require(CwtClaims.EXPIRATION, CwtClaims.CWT_ID)
        }
        validation shouldNotBe everything()
        validation.equals(ISSUER) shouldBe false
        validation.hashCode() shouldNotBe everything().hashCode()
        validation.toString() shouldContain "issuer=\"coap://as.example.com\""
        everything().toString() shouldContain "issuer=none"
        everything().toString() shouldContain "at=clock"
        everything { untaggedType = CoseMessageType.Sign1 }.untaggedType shouldBe CoseMessageType.Sign1
        everything { skew = 1.minutes }.skew shouldBe 1.minutes
        shouldThrow<ValidationException> { cwtValidation {} }
        shouldThrow<ValidationException> { everything { skew = -1.minutes } }
        shouldThrow<ValidationException> { everything { skew = 2.hours } }
    }

    test("registered claims are typed and times keep their fraction") {
        CwtClaims.of().issuer shouldBe null
        CwtClaims.of().subject shouldBe null
        CwtClaims.of(CborMap.of(CborInteger.of(value = 8) to CborSimple.True)).claims.size shouldBe 1
        val fraction = CwtClaims.of(issuedAt = NOW + HALF_SECOND.milliseconds)
        fraction.issuedAt shouldBe NOW + HALF_SECOND.milliseconds
        (fraction[CwtClaims.ISSUED_AT] is CborFloat) shouldBe true
        listOf(
            CwtClaims.SUBJECT to CborInteger.of(1),
            CwtClaims.NOT_BEFORE to CborText("now"),
            CwtClaims.ISSUED_AT to CborText("now"),
            CwtClaims.EXPIRATION to CborFloat(value = 1.0e300),
            CwtClaims.EXPIRATION to CborFloat(value = -1.0e300),
            CwtClaims.EXPIRATION to CborFloat(Double.POSITIVE_INFINITY),
            CwtClaims.AUDIENCE to CborArray.of(CborInteger.of(1)),
        ).forEach { (key, value) ->
            shouldThrow<IllegalArgumentException> { CwtClaims.of(CborMap.of(CborInteger.of(key) to value)) }
        }
        val untagged = everything { untaggedType = CoseMessageType.Encrypt0 }
        untagged.toString() shouldContain "untaggedType=Encrypt0"
        val pair = crypto.keys.generate(KeyType.Ed25519)
        val secret = CoseKey.of(crypto.keys.generateSecret())
        val inner = cwt.sign(
            claims = claims,
            signer = CoseSigner(key = CoseKey.of(pair.privateKey), algorithm = CoseAlgorithm.Ed25519),
        )
        val outer = cose.encrypt0(plaintext = inner, key = secret, algorithm = CoseAlgorithm.A256Gcm)
        val outcome15 = cwt.validate(
            outer.encode(),
            listOf(secret, CoseKey.of(pair.publicKey)),
            everything { untaggedType = CoseMessageType.Sign1 },
        )
        outcome15.value() shouldBe claims
        val outcome16 = cwt.validate(
            encoded = outer.encode(isTagged = false),
            keys = listOf(secret, CoseKey.of(pair.publicKey)),
            validation = untagged,
        )
        outcome16.value() shouldBe
            claims
    }
})
