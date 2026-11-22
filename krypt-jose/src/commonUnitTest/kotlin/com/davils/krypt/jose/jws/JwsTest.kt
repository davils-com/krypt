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

import com.davils.krypt.core.SecretText
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.CryptoPolicy
import com.davils.krypt.jose.JoseFailure
import com.davils.krypt.jose.JoseKey
import com.davils.krypt.jose.JoseLimits
import com.davils.krypt.jose.JsonValue
import com.davils.krypt.jose.fixture.base64
import com.davils.krypt.jose.fixture.compatible
import com.davils.krypt.jose.fixture.crypto
import com.davils.krypt.jose.fixture.failure
import com.davils.krypt.jose.fixture.utf8
import com.davils.krypt.jose.fixture.value
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.PolicyViolationException
import com.davils.krypt.primitive.key.KeyPair
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import kotlinx.io.bytestring.ByteString

private const val KEY_ID = "signer"
private const val SHA256_BYTES = 32
private const val SHA384_BYTES = 48
private const val SHA512_BYTES = 64
private const val TOO_LONG = 17
private val NULL_X: JsonValue.Object = JsonValue.Object.of("x" to JsonValue.Null)
private const val ALG = "alg"
private const val HEADER = """{"alg":"HS256"}"""
private val modern = Jws(crypto)
private val jws = Jws(compatible)
private val content = utf8("The payload of a test")

private fun header(json: String): String = base64(json)

private fun token(protected: String, payload: String = "e30", signature: String = "AAAA"): String =
    "${header(protected)}.$payload.$signature"

private suspend fun pairOf(type: KeyType, engine: Crypto = compatible): KeyPair = engine.keys.generate(type)

private suspend fun roundTrip(algorithm: JwsAlgorithm, signing: JoseKey, verifying: JoseKey) {
    val signer = JwsSigner(key = signing, algorithm = algorithm)
    val compact = jws.sign(payload = content, signer = signer)
    jws.verify(text = compact, keys = listOf(verifying), algorithms = setOf(algorithm)).value().payload shouldBe content
    val parts = compact.split('.')
    val forged = "${parts[0]}.${base64("forged")}.${parts[2]}"
    val outcome1 = jws.verify(
        text = forged,
        keys = listOf(verifying),
        algorithms = setOf(algorithm),
    )
    outcome1.failure() shouldBe JoseFailure.BadSignature
}

class JwsTest : FunSpec({
    test("signs and verifies every algorithm with a fitting key") {
        val hmacs = listOf(JwsAlgorithm.HS256 to SHA256_BYTES, JwsAlgorithm.HS384 to SHA384_BYTES)
        (hmacs + (JwsAlgorithm.HS512 to SHA512_BYTES)).forEach { (alg, size) ->
            val key = JoseKey.Secret(compatible.keys.generateSecret(size))
            roundTrip(algorithm = alg, signing = key, verifying = key)
        }
        val rsa = pairOf(KeyType.Rsa2048)
        val outcome2 = listOf(
            JwsAlgorithm.RS256,
            JwsAlgorithm.RS384,
            JwsAlgorithm.RS512,
            JwsAlgorithm.PS256,
            JwsAlgorithm.PS384,
            JwsAlgorithm.PS512,
        )
        outcome2.forEach { alg ->
            roundTrip(
                algorithm = alg,
                signing = JoseKey.Private(rsa.privateKey),
                verifying = JoseKey.Public(rsa.publicKey),
            )
        }
        val outcome3 = listOf(
            JwsAlgorithm.ES256 to KeyType.P256,
            JwsAlgorithm.ES384 to KeyType.P384,
            JwsAlgorithm.ES512 to KeyType.P521,
            JwsAlgorithm.EdDSA to KeyType.Ed25519,
            JwsAlgorithm.EdDSA to KeyType.Ed448,
            JwsAlgorithm.Ed25519 to KeyType.Ed25519,
            JwsAlgorithm.Ed448 to KeyType.Ed448,
        )
        outcome3.forEach { (alg, type) ->
            val pair = pairOf(type)
            roundTrip(
                algorithm = alg,
                signing = JoseKey.Private(pair.privateKey),
                verifying = JoseKey.Public(pair.publicKey),
            )
        }
        JwsAlgorithm.entries.forEach { alg -> JwsAlgorithm.of(alg.algorithmName) shouldBe alg }
        JwsAlgorithm.of("none") shouldBe null
    }

    test("tries only keys that fit the algorithm and the key id") {
        val pair = pairOf(KeyType.P256)
        val signer = JwsSigner(key = JoseKey.Private(pair.privateKey, KEY_ID), algorithm = JwsAlgorithm.ES256)
        val compact = jws.sign(payload = content, signer = signer)
        val decodedCompact = jws.decode(compact).value()
        val signature = decodedCompact.signatures.single()
        signature.header.keyId shouldBe KEY_ID
        val es256 = setOf(JwsAlgorithm.ES256)
        jws.verify(text = compact, keys = listOf(JoseKey.Public(pair.publicKey, KEY_ID)), algorithms = es256).value()
        val outcome4 = jws.verify(
            text = compact,
            keys = listOf(JoseKey.Public(pair.publicKey, "other")),
            algorithms = es256,
        )
        outcome4.failure() shouldBe
            JoseFailure.KeyNotFound
        val p384 = pairOf(KeyType.P384)
        val ed = pairOf(KeyType.Ed25519)
        val unfit = listOf(
            JoseKey.Public(p384.publicKey),
            JoseKey.Public(ed.publicKey),
            JoseKey.Private(pair.privateKey),
            JoseKey.Password(SecretText.of("password")),
            JoseKey.Secret(compatible.keys.generateSecret()),
        )
        jws.verify(text = compact, keys = unfit, algorithms = es256).failure() shouldBe JoseFailure.KeyNotFound
        val outcome5 = jws.verify(
            text = compact,
            keys = unfit + JoseKey.Public(pairOf(KeyType.P256).publicKey),
            algorithms = es256,
        )
        outcome5.failure() shouldBe
            JoseFailure.BadSignature
        val short = JoseKey.Secret(compatible.keys.generateSecret(16))
        val hmac = jws.sign(
            payload = content,
            signer = JwsSigner(JoseKey.Secret(compatible.keys.generateSecret(32)), JwsAlgorithm.HS256),
        )
        val outcome6 = jws.verify(
            text = hmac,
            keys = listOf(short),
            algorithms = setOf(JwsAlgorithm.HS256),
        )
        outcome6.failure() shouldBe JoseFailure.KeyNotFound
        val truncated = compact.substringBeforeLast('.') + "." + base64(ByteString(ByteArray(63)))
        val outcome7 = jws.verify(
            text = truncated,
            keys = listOf(JoseKey.Public(pair.publicKey)),
            algorithms = es256,
        )
        outcome7.failure() shouldBe
            JoseFailure.BadSignature
    }

    test("refuses keys and headers that do not fit when signing") {
        val pair = pairOf(KeyType.P256)
        val ec = JoseKey.Private(pair.privateKey)
        val short = JoseKey.Secret(compatible.keys.generateSecret(16))
        val outcome8 = listOf(
            JwsSigner(JoseKey.Public(pair.publicKey), JwsAlgorithm.ES256),
            JwsSigner(JoseKey.Password(SecretText.of("password")), JwsAlgorithm.HS256),
            JwsSigner(ec, JwsAlgorithm.RS256),
            JwsSigner(ec, JwsAlgorithm.ES384),
            JwsSigner(short, JwsAlgorithm.HS256),
            JwsSigner(short, JwsAlgorithm.RS256),
            JwsSigner(ec, JwsAlgorithm.ES256, JsonValue.Object.of(ALG to JsonValue.Text("none"))),
            JwsSigner(ec, JwsAlgorithm.ES256, JsonValue.Object.of("b64" to JsonValue.Bool(true))),
            JwsSigner(ec, JwsAlgorithm.ES256, JsonValue.Object.of("kid" to JsonValue.Null)),
        )
        outcome8.forEach { signer ->
            shouldThrow<IllegalArgumentException> { jws.sign(payload = content, signer = signer) }
        }
        val unprotected = JwsSigner(ec, JwsAlgorithm.ES256, unprotectedHeader = NULL_X)
        shouldThrow<IllegalArgumentException> { jws.sign(payload = content, signer = unprotected) }
        val critical = JwsSigner(ec, JwsAlgorithm.ES256, JsonValue.Object.of("crit" to JsonValue.Array(emptyList())))
        shouldThrow<IllegalArgumentException> {
            jws.sign(payload = content, signer = critical, isPayloadEncoded = false)
        }
        val signer = JwsSigner(ec, JwsAlgorithm.ES256)
        shouldThrow<IllegalArgumentException> {
            jws.sign(payload = utf8("a.b"), signer = signer, isPayloadEncoded = false)
        }
        shouldThrow<IllegalArgumentException> {
            jws.sign(payload = ByteString(byteArrayOf(-1)), signer = signer, isPayloadEncoded = false)
        }
        shouldThrow<IllegalArgumentException> { jws.signJson(payload = content, signers = emptyList()) }
        shouldThrow<IllegalArgumentException> {
            jws.signJson(payload = content, signers = listOf(signer, signer), isFlattened = true)
        }
        val nullCritical = JsonValue.Object.of("crit" to JsonValue.Null)
        val reserved = JwsSigner(ec, JwsAlgorithm.ES256, unprotectedHeader = nullCritical)
        shouldThrow<IllegalArgumentException> { jws.signJson(payload = content, signers = listOf(reserved)) }
        val keyed = JwsSigner(
            key = JoseKey.Private(pair.privateKey, KEY_ID),
            algorithm = JwsAlgorithm.ES256,
            header = JsonValue.Object.of("x" to JsonValue.Null),
            unprotectedHeader = JsonValue.Object.of("x" to JsonValue.Null),
        )
        shouldThrow<IllegalArgumentException> { jws.signJson(payload = content, signers = listOf(keyed)) }
        shouldThrow<PolicyViolationException> {
            modern.sign(content, JwsSigner(JoseKey.Private(pairOf(KeyType.Rsa2048).privateKey), JwsAlgorithm.RS256))
        }
    }

    test("writes and reads the JSON serializations with several signatures") {
        val ec = pairOf(KeyType.P256)
        val secret = JoseKey.Secret(compatible.keys.generateSecret(), KEY_ID)
        val signers = listOf(
            JwsSigner(
                key = JoseKey.Private(ec.privateKey),
                algorithm = JwsAlgorithm.ES256,
                unprotectedHeader = JsonValue.Object.of("kid" to JsonValue.Text("ec")),
            ),
            JwsSigner(
                key = secret,
                algorithm = JwsAlgorithm.HS256,
                header = JsonValue.Object.of("typ" to JsonValue.Text("x")),
            ),
        )
        val general = jws.signJson(payload = content, signers = signers)
        val message = jws.decode(general).value()
        message.isCompact shouldBe false
        message.signatures.size shouldBe 2
        message.signatures[0].unprotectedHeader shouldBe JsonValue.Object.of("kid" to JsonValue.Text("ec"))
        val both = setOf(JwsAlgorithm.ES256, JwsAlgorithm.HS256)
        val typed = jws.verify(message = message, keys = listOf(secret), algorithms = both).value()
        typed.header.type shouldBe "x"
        val outcome9 = jws.verify(
            message = message,
            keys = listOf(JoseKey.Public(ec.publicKey, "ec")),
            algorithms = both,
        )
        outcome9.value().algorithm shouldBe
            JwsAlgorithm.ES256
        val outcome10 = jws.verify(
            message = message,
            keys = listOf(secret),
            algorithms = setOf(JwsAlgorithm.ES256),
        )
        outcome10.failure() shouldBe JoseFailure.KeyNotFound
        val flattened = jws.signJson(
            payload = content,
            signers = listOf(signers[1]),
            isFlattened = true,
            isDetached = true,
        )
        val outcome11 = jws.verify(
            text = flattened,
            keys = listOf(secret),
            algorithms = both,
            detachedPayload = content,
        )
        outcome11.value().payload shouldBe content
        jws.decode(flattened).value().payload shouldBe null
        val unencoded = jws.signJson(payload = content, signers = signers, isPayloadEncoded = false)
        jws.decode(unencoded).value().isPayloadEncoded shouldBe false
        jws.verify(text = unencoded, keys = listOf(secret), algorithms = both).value().payload shouldBe content
        val compact = jws.sign(payload = content, signer = signers[1], isPayloadEncoded = false)
        jws.verify(text = compact, keys = listOf(secret), algorithms = both).value().payload shouldBe content
        val detached = jws.sign(payload = content, signer = signers[1], isDetached = true, isPayloadEncoded = false)
        jws.verify(text = detached, keys = listOf(secret), algorithms = both, detachedPayload = content).value()
        val outcome12 = jws.verify(
            text = general,
            keys = listOf(secret),
            algorithms = both,
            detachedPayload = content,
        )
        outcome12.failure() shouldBe JoseFailure.Malformed
        message shouldBe jws.decode(general).value()
        val again = jws.decode(general).value()
        message.hashCode() shouldBe again.hashCode()
        message shouldNotBe jws.decode(flattened).value()
        message shouldNotBe KEY_ID
        message.toString() shouldContain "signatures"
        val detachedMessage = jws.decode(flattened).value()
        detachedMessage.toString() shouldContain "detached"
        message.signatures[0] shouldNotBe message.signatures[1]
        message.signatures[0] shouldNotBe KEY_ID
        message.signatures[0].hashCode() shouldBe message.signatures[0].signature.hashCode()
        message.signatures[0].toString() shouldContain ALG
    }

    test("refuses critical extensions it does not understand and accepts those of the caller") {
        val secret = JoseKey.Secret(compatible.keys.generateSecret())
        val hs256 = setOf(JwsAlgorithm.HS256)
        val withCritical = JsonValue.Object.of(
            "crit" to JsonValue.Array(listOf(JsonValue.Text("exp"))),
            "exp" to JsonValue.Integer(1),
        )
        val compact = jws.sign(payload = content, signer = JwsSigner(secret, JwsAlgorithm.HS256, withCritical))
        val outcome13 = jws.verify(
            text = compact,
            keys = listOf(secret),
            algorithms = hs256,
        )
        outcome13.failure() shouldBe JoseFailure.UnknownCritical
        jws.verify(text = compact, keys = listOf(secret), algorithms = hs256, critical = setOf("exp")).value()
        val outcome14 = listOf(
            JsonValue.Object.of("crit" to JsonValue.Array(listOf(JsonValue.Text(ALG)))),
            JsonValue.Object.of("crit" to JsonValue.Array(listOf(JsonValue.Text("exp")))),
            JsonValue.Object.of(
                "crit" to JsonValue.Array(listOf(JsonValue.Text("exp"), JsonValue.Text("exp"))),
                "exp" to JsonValue.Integer(1),
            ),
        )
        outcome14.forEach { header ->
            val signed = jws.sign(payload = content, signer = JwsSigner(secret, JwsAlgorithm.HS256, header))
            val outcome15 = jws.verify(
                text = signed,
                keys = listOf(secret),
                algorithms = hs256,
                critical = setOf("exp", ALG),
            )
            outcome15.failure() shouldBe
                JoseFailure.UnknownCritical
        }
        val withX = JwsSigner(key = secret, algorithm = JwsAlgorithm.HS256, unprotectedHeader = NULL_X)
        val serialized = jws.signJson(payload = content, signers = listOf(withX))
        val unprotected = serialized.replace(
            oldValue = """"header":{"x":null}""",
            newValue = """"header":{"crit":["x"],"x":null}""",
        )
        val outcome16 = jws.verify(
            text = unprotected,
            keys = listOf(secret),
            algorithms = hs256,
            critical = setOf("x"),
        )
        outcome16.failure() shouldBe
            JoseFailure.UnknownCritical
        jws.verify(text = token("""{"alg":"none"}"""), keys = listOf(secret), algorithms = hs256).failure() shouldBe
            JoseFailure.UnsupportedAlgorithm
        val outcome17 = jws.verify(
            text = token(HEADER),
            keys = listOf(secret),
            algorithms = hs256,
            critical = emptySet(),
        )
        outcome17.failure() shouldBe
            JoseFailure.BadSignature
    }

    test("answers a refusal of the crypto policy with a failure") {
        val pair = pairOf(KeyType.P256)
        val compact = jws.sign(
            payload = content,
            signer = JwsSigner(JoseKey.Private(pair.privateKey), JwsAlgorithm.ES256),
        )
        val cnsa = Jws(Crypto(environment { policy = CryptoPolicy.Cnsa2 }))
        cnsa.verify(compact, listOf(JoseKey.Public(pair.publicKey)), setOf(JwsAlgorithm.ES256)).failure() shouldBe
            JoseFailure.AlgorithmNotAllowed
    }

    test("refuses hostile serializations") {
        val small = Jws(crypto, JoseLimits(maximumBytes = 16, maximumRecipients = 1))
        small.decode("a".repeat(n = TOO_LONG)).failure() shouldBe JoseFailure.LimitExceeded
        val unencoded = header("""{"alg":"HS256","b64":false,"crit":["b64"]}""")
        val outcome18 = listOf(
            "a.b",
            "a.b.c.d",
            "!!.e30.AAAA",
            "${header("[]")}.e30.AAAA",
            "${header("{")}.e30.AAAA",
            "${header("{}")}.e30.AAAA",
            token("""{"alg":1}"""),
            token("""{"alg":"HS256","crit":[]}"""),
            token("""{"alg":"HS256","crit":"b64"}"""),
            token("""{"alg":"HS256","crit":[1]}"""),
            token("""{"alg":"HS256","x5c":[]}"""),
            token("""{"alg":"HS256","b64":"no"}"""),
            token("""{"alg":"HS256","b64":false}"""),
            token("""{"alg":"HS256","b64":false,"crit":["exp"],"exp":1}"""),
            token("""{"alg":"HS256","p2c":"1"}"""),
            token("""{"alg":"HS256","epk":1}"""),
            token("""{"alg":"HS256","jwk":[]}"""),
            token("""{"alg":"HS256","kid":1}"""),
            token(HEADER, payload = "!!"),
            token(HEADER, signature = "!!"),
            """{"payload":"e30"}""",
            """{"payload":"e30","signatures":{}}""",
            """{"payload":"e30","signatures":[]}""",
            """{"payload":"e30","signatures":[1]}""",
            """{"payload":"e30","signatures":[{"protected":"${header(HEADER)}"}]}""",
            """{"payload":"e30","signatures":[],"signature":"AAAA"}""",
            """{"payload":"e30","protected":"${header("""{}""")}","signature":"AAAA"}""",
            """{"payload":"e30","header":{"alg":"HS256"},"protected":"${header(HEADER)}","signature":""}""",
            """{"payload":"e30","header":{"alg":"HS256","b64":true},"signature":""}""",
            """{"payload":"e30","header":1,"signature":""}""",
            """{"payload":1,"header":{"alg":"HS256"},"signature":""}""",
            """{"payload":"!","header":{"alg":"HS256"},"signature":""}""",
            """{"payload":"e30","signatures":[{"header":{"alg":"HS256"},"signature":""},""" +
                """{"protected":"$unencoded","signature":""}]}""",
            """{"payload":"e30"""",
            "\uD800.e30.AAAA",
            "{\uD800}",
        )
        outcome18.forEach { text -> jws.decode(text).failure() shouldBe JoseFailure.Malformed }
        val two = """{"payload":"e30","signatures":[{"header":{"alg":"HS256"},"signature":""},""" +
            """{"header":{"alg":"HS256"},"signature":""}]}"""
        val single = Jws(crypto, JoseLimits(maximumRecipients = 1))
        single.decode(two).failure() shouldBe JoseFailure.LimitExceeded
        val decodedTwo = jws.decode(two).value()
        decodedTwo.signatures.size shouldBe 2
        val anySecret = JoseKey.Secret(compatible.keys.generateSecret())
        val refused = jws.verify(text = two, keys = listOf(anySecret), algorithms = setOf(JwsAlgorithm.ES256))
        refused.failure() shouldBe JoseFailure.AlgorithmNotAllowed
        jws.decode(token(HEADER, payload = "")).value().payload shouldBe null
        jws.toString() shouldContain "Jws"
    }

    test("values compare and show themselves") {
        val key = JoseKey.Secret(compatible.keys.generateSecret())
        val signer = JwsSigner(key, JwsAlgorithm.HS256)
        signer shouldBe JwsSigner(key, JwsAlgorithm.HS256)
        signer.hashCode() shouldBe JwsSigner(key, JwsAlgorithm.HS256).hashCode()
        signer shouldNotBe JwsSigner(key, JwsAlgorithm.HS384)
        signer shouldNotBe KEY_ID
        signer.toString() shouldContain "HS256"
        val outcome19 = jws.verify(
            text = jws.sign(payload = content, signer = signer),
            keys = listOf(key),
            algorithms = setOf(JwsAlgorithm.HS256),
        )
        val verified = outcome19.value()
        val outcome20 = jws.verify(
            text = jws.sign(payload = content, signer = signer),
            keys = listOf(key),
            algorithms = setOf(JwsAlgorithm.HS256),
        )
        val again = outcome20.value()
        verified shouldBe again
        verified.hashCode() shouldBe again.hashCode()
        verified shouldNotBe KEY_ID
        verified.toString() shouldContain "HS256"
    }
})
