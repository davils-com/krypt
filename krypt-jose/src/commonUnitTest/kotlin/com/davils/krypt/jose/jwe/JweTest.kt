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
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.CryptoPolicy
import com.davils.krypt.core.policy.CryptoProfile
import com.davils.krypt.core.policy.cryptoPolicy
import com.davils.krypt.jose.JoseFailure
import com.davils.krypt.jose.JoseKey
import com.davils.krypt.jose.JoseLimits
import com.davils.krypt.jose.JsonValue
import com.davils.krypt.jose.fixture.FixedClock
import com.davils.krypt.jose.fixture.base64
import com.davils.krypt.jose.fixture.failure
import com.davils.krypt.jose.fixture.unbase64
import com.davils.krypt.jose.fixture.utf8
import com.davils.krypt.jose.fixture.value
import com.davils.krypt.jose.jwk.JsonWebKeys
import com.davils.krypt.primitive.Crypto
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import kotlinx.io.bytestring.ByteString

private const val ITERATIONS = 1_000
private const val KEY_ID = "recipient"
private val engine = Crypto(
    environment {
        clock = FixedClock
        policy = cryptoPolicy(CryptoProfile.Compatible) { minimumIterations = ITERATIONS }
    },
)
private val jwe = Jwe(engine, isPasswordAllowed = true)
private val strict = Jwe(engine)
private val algorithms = JweAlgorithm.entries.toSet()
private val encryptions = JweEncryption.entries.toSet()
private val plaintext = utf8("A secret message for the recipient")

private const val AES_128 = 16
private const val AES_256 = 32
private const val FIXTURE_PASSWORD: String = "fixture"
private const val RECIPIENT_COUNT = 3
private const val TAG_PART = 4
private const val CIPHERTEXT_PART = 3
private const val IV_PART = 2
private const val SHORT = 8
private const val KEY_SIZE = 24
private const val TOO_LONG = 17

private fun secret(bytes: Int, keyId: String? = null): JoseKey =
    JoseKey.Secret(key = engine.keys.generateSecret(bytes), keyId = keyId)

private suspend fun pair(type: KeyType): Pair<JoseKey, JoseKey> {
    val generated = engine.keys.generate(type)
    return JoseKey.Public(generated.publicKey) to JoseKey.Private(generated.privateKey)
}

private suspend fun decrypt(text: String, vararg keys: JoseKey, with: Jwe = jwe) =
    with.decrypt(text = text, keys = keys.toList(), algorithms = algorithms, encryptions = encryptions)

private suspend fun roundTrip(algorithm: JweAlgorithm, encrypting: JoseKey, decrypting: JoseKey, wrong: JoseKey) {
    JweEncryption.entries.forEach { encryption ->
        val recipient = JweRecipient(key = encrypting, algorithm = algorithm)
        val token = jwe.encrypt(plaintext = plaintext, recipient = recipient, encryption = encryption)
        decrypt(token, decrypting).value().plaintext shouldBe plaintext
        decrypt(token, wrong).failure() shouldBe JoseFailure.DecryptionFailed
    }
}

private fun withPart(token: String, index: Int, part: String): String {
    val parts = token.split('.').toMutableList()
    parts[index] = part
    return parts.joinToString(".")
}

private fun header(json: String): String = base64(json)

class JweTest : FunSpec({
    test("encrypts and decrypts with every key management algorithm and content encryption") {
        JweEncryption.entries.forEach { encryption ->
            val key = secret(encryption.keyBytes)
            val token = jwe.encrypt(
                plaintext = plaintext,
                recipient = JweRecipient(key, JweAlgorithm.Dir),
                encryption = encryption,
            )
            decrypt(token, key).value().encryption shouldBe encryption
            decrypt(token, secret(encryption.keyBytes)).failure() shouldBe JoseFailure.DecryptionFailed
        }
        val kw128 = secret(AES_128)
        roundTrip(algorithm = JweAlgorithm.A128KW, encrypting = kw128, decrypting = kw128, wrong = secret(AES_128))
        val kek = secret(AES_256)
        roundTrip(algorithm = JweAlgorithm.A256KW, encrypting = kek, decrypting = kek, wrong = secret(AES_256))
        val gcm128 = secret(AES_128)
        roundTrip(algorithm = JweAlgorithm.A128GCMKW, encrypting = gcm128, decrypting = gcm128, wrong = secret(AES_128))
        val gcm256 = secret(AES_256)
        roundTrip(algorithm = JweAlgorithm.A256GCMKW, encrypting = gcm256, decrypting = gcm256, wrong = secret(AES_256))
        listOf(KeyType.P256, KeyType.P384, KeyType.P521, KeyType.X25519, KeyType.X448).forEach { type ->
            val (public, private) = pair(type)
            val (_, other) = pair(type)
            roundTrip(algorithm = JweAlgorithm.EcdhEs, encrypting = public, decrypting = private, wrong = other)
            roundTrip(algorithm = JweAlgorithm.EcdhEsA128KW, encrypting = public, decrypting = private, wrong = other)
            roundTrip(algorithm = JweAlgorithm.EcdhEsA256KW, encrypting = public, decrypting = private, wrong = other)
        }
        val (rsaPublic, rsaPrivate) = pair(KeyType.Rsa2048)
        roundTrip(
            algorithm = JweAlgorithm.RsaOaep256,
            encrypting = rsaPublic,
            decrypting = rsaPrivate,
            wrong = pair(KeyType.Rsa2048).second,
        )
        val password = JoseKey.Password(SecretText.of("correct horse battery staple"))
        val wrongPassword = JoseKey.Password(SecretText.of("incorrect horse"))
        roundTrip(
            algorithm = JweAlgorithm.Pbes2Hs256A128KW,
            encrypting = password,
            decrypting = password,
            wrong = wrongPassword,
        )
        roundTrip(
            algorithm = JweAlgorithm.Pbes2Hs512A256KW,
            encrypting = password,
            decrypting = password,
            wrong = wrongPassword,
        )
        JweAlgorithm.entries.forEach { algorithm -> JweAlgorithm.of(algorithm.algorithmName) shouldBe algorithm }
        JweEncryption.entries.forEach { encryption -> JweEncryption.of(encryption.algorithmName) shouldBe encryption }
        JweAlgorithm.of("RSA1_5") shouldBe null
        JweEncryption.of("A192GCM") shouldBe null
    }

    test("writes and reads the JSON serializations with several recipients") {
        val kek = secret(AES_128, KEY_ID)
        val (ecPublic, ecPrivate) = pair(KeyType.P256)
        val (rsaPublic, rsaPrivate) = pair(KeyType.Rsa2048)
        val recipients = listOf(
            JweRecipient(kek, JweAlgorithm.A128KW),
            JweRecipient(ecPublic, JweAlgorithm.EcdhEsA256KW, JsonValue.Object.of("apu" to JsonValue.Text("QWxpY2U"))),
            JweRecipient(rsaPublic, JweAlgorithm.RsaOaep256),
        )
        val general = jwe.encryptJson(
            plaintext = plaintext,
            recipients = recipients,
            encryption = JweEncryption.A256GCM,
            protectedHeader = JsonValue.Object.of("cty" to JsonValue.Text("text/plain")),
            sharedHeader = JsonValue.Object.of("x-shared" to JsonValue.Bool(true)),
            additionalData = utf8("context"),
        )
        val message = jwe.decode(general).value()
        message.isCompact shouldBe false
        message.recipients.size shouldBe RECIPIENT_COUNT
        message.additionalData shouldBe utf8("context")
        message.sharedHeader["x-shared"] shouldBe JsonValue.Bool(true)
        decrypt(general, kek).value().header.contentType shouldBe "text/plain"
        decrypt(general, ecPrivate).value().algorithm shouldBe JweAlgorithm.EcdhEsA256KW
        decrypt(general, rsaPrivate).value().key shouldBe rsaPrivate
        decrypt(general, secret(AES_128)).failure() shouldBe JoseFailure.DecryptionFailed
        decrypt(general, secret(AES_128, "other")).failure() shouldBe JoseFailure.KeyNotFound
        val flattened = jwe.encryptJson(
            plaintext = plaintext,
            recipients = listOf(recipients[0]),
            encryption = JweEncryption.A128GCM,
            isFlattened = true,
        )
        decrypt(flattened, kek).value().plaintext shouldBe plaintext
        val ecdh = listOf(JweRecipient(ecPublic, JweAlgorithm.EcdhEs))
        val direct = jwe.encryptJson(plaintext = plaintext, recipients = ecdh, encryption = JweEncryption.A128GCM)
        decrypt(direct, ecPrivate).value().plaintext shouldBe plaintext
        message shouldBe jwe.decode(general).value()
        val again = jwe.decode(general).value()
        message.hashCode() shouldBe again.hashCode()
        message shouldNotBe jwe.decode(flattened).value()
        message shouldNotBe KEY_ID
        message.toString() shouldContain "recipients"
        message.recipients[0] shouldNotBe message.recipients[1]
        message.recipients[0] shouldBe message.recipients[0]
        message.recipients[0] shouldNotBe KEY_ID
        message.recipients[0].hashCode() shouldBe message.recipients[0].encryptedKey.hashCode()
        message.recipients[0].toString() shouldContain "bytes"
        val decrypted = decrypt(general, kek).value()
        decrypted shouldBe decrypt(general, kek).value()
        val repeated = decrypt(general, kek).value()
        decrypted.hashCode() shouldBe repeated.hashCode()
        decrypted shouldNotBe KEY_ID
        decrypted.toString() shouldContain "A256GCM"
        recipients[0] shouldBe JweRecipient(kek, JweAlgorithm.A128KW)
        recipients[0].hashCode() shouldBe JweRecipient(kek, JweAlgorithm.A128KW).hashCode()
        recipients[0] shouldNotBe recipients[1]
        recipients[0] shouldNotBe KEY_ID
        recipients[0].toString() shouldContain "A128KW"
        jwe.toString() shouldContain "passwordAllowed=true"
    }

    test("refuses keys and headers that do not fit when encrypting") {
        val (ecPublic, ecPrivate) = pair(KeyType.P256)
        val (edPublic, _) = pair(KeyType.Ed25519)
        val password = JoseKey.Password(SecretText.of(FIXTURE_PASSWORD))
        val outcome1 = listOf(
            JweRecipient(secret(AES_128), JweAlgorithm.Dir),
            JweRecipient(ecPublic, JweAlgorithm.A128KW),
            JweRecipient(secret(AES_256), JweAlgorithm.A128GCMKW),
            JweRecipient(ecPrivate, JweAlgorithm.EcdhEs),
            JweRecipient(edPublic, JweAlgorithm.EcdhEs),
            JweRecipient(ecPublic, JweAlgorithm.RsaOaep256),
            JweRecipient(secret(AES_128), JweAlgorithm.Pbes2Hs256A128KW),
            JweRecipient(secret(AES_128), JweAlgorithm.A128KW, JsonValue.Object.of("epk" to JsonValue.Null)),
            JweRecipient(secret(AES_128), JweAlgorithm.A128KW, JsonValue.Object.of("crit" to JsonValue.Null)),
        )
        outcome1.forEach { recipient ->
            shouldThrow<IllegalArgumentException> {
                jwe.encrypt(plaintext = plaintext, recipient = recipient, encryption = JweEncryption.A256GCM)
            }
        }
        shouldThrow<IllegalArgumentException> {
            strict.encrypt(plaintext, JweRecipient(password, JweAlgorithm.Pbes2Hs256A128KW), JweEncryption.A128GCM)
        }
        val kw = JweRecipient(secret(AES_128), JweAlgorithm.A128KW)
        listOf("alg", "enc", "zip", "iv", "tag", "p2s", "p2c").forEach { name ->
            val header = JsonValue.Object.of(name to JsonValue.Text("x"))
            shouldThrow<IllegalArgumentException> {
                jwe.encrypt(plaintext = plaintext, recipient = kw, encryption = JweEncryption.A128GCM, header = header)
            }
        }
        shouldThrow<IllegalArgumentException> {
            jwe.encryptJson(plaintext = plaintext, recipients = emptyList(), encryption = JweEncryption.A128GCM)
        }
        shouldThrow<IllegalArgumentException> {
            jwe.encryptJson(
                plaintext = plaintext,
                recipients = listOf(kw, kw),
                encryption = JweEncryption.A128GCM,
                isFlattened = true,
            )
        }
        shouldThrow<IllegalArgumentException> {
            jwe.encryptJson(
                plaintext = plaintext,
                recipients = listOf(kw, JweRecipient(ecPublic, JweAlgorithm.EcdhEs)),
                encryption = JweEncryption.A128GCM,
            )
        }
        shouldThrow<IllegalArgumentException> {
            Jwe(engine, JoseLimits(maximumRecipients = 1)).encryptJson(plaintext, listOf(kw, kw), JweEncryption.A128GCM)
        }
        shouldThrow<IllegalArgumentException> {
            val shared = JsonValue.Object.of("crit" to JsonValue.Null)
            jwe.encryptJson(
                plaintext = plaintext,
                recipients = listOf(kw),
                encryption = JweEncryption.A128GCM,
                sharedHeader = shared,
            )
        }
        shouldThrow<IllegalArgumentException> {
            val shared = JsonValue.Object.of("cty" to JsonValue.Null)
            val keyed = JweRecipient(secret(AES_128), JweAlgorithm.A128KW, JsonValue.Object.of("cty" to JsonValue.Null))
            jwe.encryptJson(
                plaintext = plaintext,
                recipients = listOf(keyed),
                encryption = JweEncryption.A128GCM,
                sharedHeader = shared,
            )
        }
    }

    test("gives one failure for every wrong key, tag or ciphertext") {
        val kek = secret(AES_128)
        listOf(JweEncryption.A128GCM, JweEncryption.A128CBC_HS256).forEach { encryption ->
            val token = jwe.encrypt(
                plaintext = plaintext,
                recipient = JweRecipient(kek, JweAlgorithm.A128KW),
                encryption = encryption,
            )
            val parts = token.split('.')
            val tag = unbase64(parts[4]).toByteArray()
            tag[0] = (tag[0] + 1).toByte()
            val ciphertext = unbase64(parts[3]).toByteArray()
            ciphertext[0] = (ciphertext[0] + 1).toByte()
            val outcome2 = listOf(
                withPart(token, index = TAG_PART, part = base64(ByteString(tag))),
                withPart(token, index = TAG_PART, part = base64(ByteString(tag.copyOf(newSize = SHORT)))),
                withPart(token, index = CIPHERTEXT_PART, part = base64(ByteString(ciphertext))),
                withPart(token, index = IV_PART, part = base64(ByteString(ByteArray(size = SHORT)))),
                withPart(token, index = 1, part = base64(ByteString(ByteArray(size = KEY_SIZE)))),
                withPart(token, 0, header("""{"alg":"A128KW","enc":"${encryption.algorithmName}","x":1}""")),
            )
            outcome2.forEach { forged -> decrypt(forged, kek).failure() shouldBe JoseFailure.DecryptionFailed }
        }
        val token = jwe.encrypt(
            plaintext = plaintext,
            recipient = JweRecipient(kek, JweAlgorithm.A128KW),
            encryption = JweEncryption.A128GCM,
        )
        val swapped = withPart(token, 0, header("""{"alg":"A128KW","enc":"A256GCM"}"""))
        decrypt(swapped, kek).failure() shouldBe JoseFailure.DecryptionFailed
    }

    test("refuses algorithms the caller, the opt-in or the policy does not allow") {
        val kek = secret(AES_128)
        val token = jwe.encrypt(
            plaintext = plaintext,
            recipient = JweRecipient(kek, JweAlgorithm.A128KW),
            encryption = JweEncryption.A128GCM,
        )
        val outcome3 = jwe.decrypt(
            text = token,
            keys = listOf(kek),
            algorithms = setOf(JweAlgorithm.A256KW),
            encryptions = encryptions,
        )
        outcome3.failure() shouldBe
            JoseFailure.AlgorithmNotAllowed
        val outcome4 = jwe.decrypt(
            text = token,
            keys = listOf(kek),
            algorithms = algorithms,
            encryptions = setOf(JweEncryption.A256GCM),
        )
        outcome4.failure() shouldBe
            JoseFailure.AlgorithmNotAllowed
        val password = JoseKey.Password(SecretText.of(FIXTURE_PASSWORD))
        val pbes2 = jwe.encrypt(
            plaintext = plaintext,
            recipient = JweRecipient(password, JweAlgorithm.Pbes2Hs256A128KW),
            encryption = JweEncryption.A128GCM,
        )
        decrypt(pbes2, password, with = strict).failure() shouldBe JoseFailure.AlgorithmNotAllowed
        val cnsa = Jwe(Crypto(environment { policy = CryptoPolicy.Cnsa2 }))
        val outcome5 = cnsa.decrypt(
            text = token,
            keys = listOf(kek),
            algorithms = algorithms,
            encryptions = encryptions,
        )
        outcome5.failure() shouldBe JoseFailure.AlgorithmNotAllowed
        val criticalHeader = JsonValue.Object.of(
            "crit" to JsonValue.Array(listOf(JsonValue.Text("x"))),
            "x" to JsonValue.Integer(1),
        )
        val critical = jwe.encrypt(
            plaintext = plaintext,
            recipient = JweRecipient(kek, JweAlgorithm.A128KW),
            encryption = JweEncryption.A128GCM,
            header = criticalHeader,
        )
        decrypt(critical, kek).failure() shouldBe JoseFailure.UnknownCritical
        val outcome6 = jwe.decrypt(
            text = critical,
            keys = listOf(kek),
            algorithms = algorithms,
            encryptions = encryptions,
            critical = setOf("x"),
        )
        outcome6.value()
        val outcome7 = listOf(
            """{"alg":"A128KW","enc":"A128GCM","zip":"DEF"}""",
            """{"alg":"RSA1_5","enc":"A128GCM"}""",
            """{"alg":"A128KW","enc":"A192GCM"}""",
        )
        outcome7.forEach { json ->
            decrypt(withPart(token, 0, header(json)), kek).failure() shouldBe JoseFailure.UnsupportedAlgorithm
        }
    }

    test("checks the members of the key management before any work") {
        val kek = secret(AES_128)
        val (ecPublic, ecPrivate) = pair(KeyType.P256)
        val (_, p384) = pair(KeyType.P384)
        val kw = jwe.encrypt(
            plaintext = plaintext,
            recipient = JweRecipient(kek, JweAlgorithm.A128KW),
            encryption = JweEncryption.A128GCM,
        )
        val dir = jwe.encrypt(
            plaintext = plaintext,
            recipient = JweRecipient(secret(AES_128), JweAlgorithm.Dir),
            encryption = JweEncryption.A128GCM,
        )
        val ecdh = jwe.encrypt(
            plaintext = plaintext,
            recipient = JweRecipient(ecPublic, JweAlgorithm.EcdhEs),
            encryption = JweEncryption.A128GCM,
        )
        val ecdhHeader = jwe.decode(ecdh).value().protectedHeader
        val epk = checkNotNull(ecdhHeader["epk"] as? JsonValue.Object)
        decrypt(ecdh, p384).failure() shouldBe JoseFailure.KeyNotFound
        decrypt(ecdh, ecPublic).failure() shouldBe JoseFailure.KeyNotFound
        val password = JoseKey.Password(SecretText.of(FIXTURE_PASSWORD))
        val outcome8 = listOf(
            withPart(dir, 1, "AAAA"),
            withPart(kw, 1, ""),
            withPart(kw, 0, header("""{"alg":"A128GCMKW","enc":"A128GCM"}""")),
            withPart(kw, 0, header("""{"alg":"A128GCMKW","enc":"A128GCM","iv":"AAAA","tag":"AAAA"}""")),
            withPart(dir, 0, header("""{"alg":"ECDH-ES","enc":"A128GCM"}""")),
            withPart(dir, 0, header("""{"alg":"ECDH-ES","enc":"A128GCM","epk":{"kty":"EC"}}""")),
            withPart(dir, 0, header("""{"alg":"ECDH-ES","enc":"A128GCM","apu":"!","epk":${epk.encode()}}""")),
            withPart(kw, 0, header("""{"alg":"PBES2-HS256+A128KW","enc":"A128GCM","p2s":"AAAA","p2c":1000}""")),
            withPart(kw, 0, header("""{"alg":"PBES2-HS256+A128KW","enc":"A128GCM","p2s":"AAAAAAAAAAA"}""")),
            withPart(kw, 0, header("""{"alg":"PBES2-HS256+A128KW","enc":"A128GCM","p2s":"AAAAAAAAAAA","p2c":0}""")),
        )
        outcome8.forEach { forged ->
            decrypt(forged, kek, ecPrivate, password).failure() shouldBe JoseFailure.Malformed
        }
        val tooMany = header("""{"alg":"PBES2-HS256+A128KW","enc":"A128GCM","p2s":"AAAAAAAAAAA","p2c":2000000}""")
        decrypt(withPart(kw, 0, tooMany), password).failure() shouldBe JoseFailure.LimitExceeded
        val tooFew = header("""{"alg":"PBES2-HS256+A128KW","enc":"A128GCM","p2s":"AAAAAAAAAAA","p2c":999}""")
        decrypt(withPart(kw, 0, tooFew), password).failure() shouldBe JoseFailure.AlgorithmNotAllowed
        val privateEpk = engine.keys.generate(KeyType.P256)
        val jwks = JsonWebKeys(engine)
        val withPrivate = jwks.of(key = privateEpk.privateKey).encode()
        val edKey = engine.keys.generate(KeyType.Ed25519)
        val ed = jwks.of(key = edKey.publicKey).encode()
        listOf(withPrivate, ed).forEach { key ->
            val forged = withPart(dir, 0, header("""{"alg":"ECDH-ES","enc":"A128GCM","epk":$key}"""))
            decrypt(forged, ecPrivate).failure() shouldBe JoseFailure.Malformed
        }
    }

    test("refuses hostile serializations") {
        val small = Jwe(engine, JoseLimits(maximumBytes = 16, maximumRecipients = 1))
        small.decode("a".repeat(n = TOO_LONG)).failure() shouldBe JoseFailure.LimitExceeded
        val protected = header("""{"enc":"A128GCM"}""")
        val content = """"iv":"AAAA","ciphertext":"","tag":"AAAA""""
        val dirOnly = header("""{"alg":"dir"}""")
        val encOnly = header("""{"enc":"A128GCM"}""")
        val dirAndEnc = header("""{"alg":"dir","enc":"A128GCM"}""")
        val empty = header("{}")
        val outcome9 = listOf(
            "a.b.c.d",
            "!!.a.b.c.d",
            "${header("[]")}.AAAA.AAAA.AAAA.AAAA",
            "$dirOnly..AAAA.AAAA.AAAA",
            "$encOnly..AAAA.AAAA.AAAA",
            "$dirAndEnc..!!.AAAA.AAAA",
            """{"protected":"$protected","recipients":{},$content}""",
            """{"protected":"$protected","recipients":[],$content}""",
            """{"protected":"$protected","recipients":[1],$content}""",
            """{"protected":"$protected","recipients":[{}],"header":{},$content}""",
            """{"protected":"$protected","header":{"alg":"dir"}}""",
            """{"protected":"$protected","header":{"alg":"dir","enc":"A128GCM"},$content}""",
            """{"protected":"$protected","unprotected":{"enc":"A128GCM"},"header":{"alg":"dir"},$content}""",
            """{"protected":"$empty","header":{"alg":"dir","enc":"A128GCM"},$content}""",
            """{"protected":"$protected","unprotected":1,"header":{"alg":"dir"},$content}""",
            """{"protected":"$protected","header":{"alg":"dir","kid":1},$content}""",
            """{"protected":"$protected","header":{"alg":"dir"},"aad":"!",$content}""",
            "{\uD800}",
        )
        outcome9.forEach { text -> jwe.decode(text).failure() shouldBe JoseFailure.Malformed }
        val two = """{"protected":"$protected","recipients":[{"header":{"alg":"dir"}},""" +
            """{"header":{"alg":"dir"}}],$content}"""
        small.decode(two).failure() shouldBe JoseFailure.LimitExceeded
        val decodedTwo = jwe.decode(two).value()
        decodedTwo.recipients.size shouldBe 2
        decrypt(two, secret(AES_128)).failure() shouldBe JoseFailure.DecryptionFailed
        decrypt(two, secret(AES_256)).failure() shouldBe JoseFailure.KeyNotFound
    }
})
