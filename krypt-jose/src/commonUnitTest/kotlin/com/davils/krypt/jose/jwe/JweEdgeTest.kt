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
import com.davils.krypt.core.policy.CryptoProfile
import com.davils.krypt.core.policy.cryptoPolicy
import com.davils.krypt.jose.JoseFailure
import com.davils.krypt.jose.JoseKey
import com.davils.krypt.jose.JsonValue
import com.davils.krypt.jose.fixture.base64
import com.davils.krypt.jose.fixture.failure
import com.davils.krypt.jose.fixture.utf8
import com.davils.krypt.jose.fixture.value
import com.davils.krypt.jose.jwk.JsonWebKeys
import com.davils.krypt.primitive.Crypto
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString

private const val SMALL_ITERATIONS = 1_000
private const val CHOSEN_ITERATIONS = 2_000
private const val AES_128 = 16
private const val GCM_NONCE = 12
private const val KID = "kid"
private const val RECIPIENTS = """"recipients""""
private val edgeEngine = Crypto(
    environment {
        policy = cryptoPolicy(CryptoProfile.Compatible) { minimumIterations = SMALL_ITERATIONS }
    },
)
private val edge = Jwe(edgeEngine, isPasswordAllowed = true)
private val allAlgorithms = JweAlgorithm.entries.toSet()
private val allEncryptions = JweEncryption.entries.toSet()
private val message = utf8("edge cases")

private fun kek(keyId: String? = null): JoseKey = JoseKey.Secret(
    key = edgeEngine.keys.generateSecret(AES_128),
    keyId = keyId,
)

private suspend fun open(token: String, keys: List<JoseKey>) =
    edge.decrypt(text = token, keys = keys, algorithms = allAlgorithms, encryptions = allEncryptions)

private suspend fun token(recipient: JweRecipient, header: JsonValue.Object = JsonValue.Object.Empty): String =
    edge.encrypt(plaintext = message, recipient = recipient, encryption = JweEncryption.A128GCM, header = header)

private fun replaced(token: String, header: String): String {
    val parts = token.split('.').toMutableList()
    parts[0] = base64(header)
    return parts.joinToString(".")
}

class JweEdgeTest : FunSpec({
    test("tries every fitting key in order and stops at the first that decrypts") {
        val right = kek()
        val wrong = kek()
        val compact = token(JweRecipient(right, JweAlgorithm.A128KW))
        open(compact, listOf(wrong, right)).value().key shouldBe right
        open(compact, listOf(right, wrong)).value().key shouldBe right
        val decoded = edge.decode(compact).value()
        val fromMessage = edge.decrypt(
            message = decoded,
            keys = listOf(right),
            algorithms = allAlgorithms,
            encryptions = allEncryptions,
        )
        fromMessage.value().key shouldBe right
    }

    test("keeps a key id the header already names") {
        val keyed = kek(KID)
        val header = JsonValue.Object.of("kid" to JsonValue.Text("named"))
        val compact = token(JweRecipient(keyed, JweAlgorithm.A128KW), header)
        edge.decode(compact).value().protectedHeader["kid"] shouldBe JsonValue.Text("named")
        open(compact, listOf(kek())).failure() shouldBe JoseFailure.DecryptionFailed
    }

    test("refuses missing and wrong members of the key management") {
        val kw = token(JweRecipient(kek(), JweAlgorithm.A128KW))
        val iv = base64(ByteString(ByteArray(GCM_NONCE)))
        val outcome1 = listOf(
            """{"alg":"A128GCMKW","enc":"A128GCM","iv":"$iv","tag":"AAAA"}""",
            """{"alg":"A128GCMKW","enc":"A128GCM","tag":"AAAAAAAAAAAAAAAAAAAAAA"}""",
            """{"alg":"PBES2-HS256+A128KW","enc":"A128GCM","p2c":1000}""",
        )
        outcome1.forEach { header ->
            open(replaced(token = kw, header = header), listOf(kek())).failure() shouldBe JoseFailure.Malformed
        }
        val rsaKey = edgeEngine.keys.generate(KeyType.Rsa2048).publicKey
        val jwks = JsonWebKeys(edgeEngine)
        val rsa = jwks.of(rsaKey).encode()
        val dir = edge.encrypt(message, JweRecipient(kek(), JweAlgorithm.Dir), JweEncryption.A128GCM)
        val rsaEpk = replaced(token = dir, header = """{"alg":"ECDH-ES","enc":"A128GCM","epk":$rsa}""")
        open(rsaEpk, listOf(kek())).failure() shouldBe JoseFailure.Malformed
    }

    test("tells keys that do not fit from keys that are wrong") {
        val gcm = token(JweRecipient(kek(), JweAlgorithm.A128GCMKW))
        val long = JoseKey.Secret(edgeEngine.keys.generateSecret())
        open(gcm, listOf(long)).failure() shouldBe JoseFailure.KeyNotFound
        val password = JoseKey.Password(SecretText.of("edge"))
        val pbes2 = token(JweRecipient(password, JweAlgorithm.Pbes2Hs256A128KW, iterations = CHOSEN_ITERATIONS))
        edge.decode(pbes2).value().protectedHeader["p2c"] shouldBe JsonValue.Integer(CHOSEN_ITERATIONS.toLong())
        open(pbes2, listOf(kek())).failure() shouldBe JoseFailure.KeyNotFound
        open(pbes2, listOf(password)).value().plaintext shouldBe message
        val rsa = edgeEngine.keys.generate(KeyType.Rsa2048)
        val oaep = token(JweRecipient(JoseKey.Public(rsa.publicKey), JweAlgorithm.RsaOaep256))
        val ec = edgeEngine.keys.generate(KeyType.P256)
        open(oaep, listOf(kek(), JoseKey.Private(ec.privateKey))).failure() shouldBe JoseFailure.KeyNotFound
        shouldThrow<IllegalArgumentException> { token(JweRecipient(kek(), JweAlgorithm.RsaOaep256)) }
        val agreement = edgeEngine.keys.generate(KeyType.X25519)
        val partyInfo = JsonValue.Object.of("apu" to JsonValue.Text("QQ"), "apv" to JsonValue.Text("Qg"))
        val ecdh = token(JweRecipient(JoseKey.Public(agreement.publicKey), JweAlgorithm.EcdhEs), partyInfo)
        open(ecdh, listOf(JoseKey.Private(agreement.privateKey))).value().plaintext shouldBe message
        open(ecdh, listOf(kek())).failure() shouldBe JoseFailure.KeyNotFound
    }

    test("reads JSON serializations without a protected header and refuses missing parts") {
        val general = edge.encryptJson(message, listOf(JweRecipient(kek(), JweAlgorithm.A128KW)), JweEncryption.A128GCM)
        val rest = general.substring(general.indexOf(RECIPIENTS))
        val withoutProtected = """{"unprotected":{"enc":"A128GCM"},""" + rest
        edge.decode(withoutProtected).value().protectedHeader shouldBe JsonValue.Object.Empty
        listOf("ciphertext", "tag").forEach { member ->
            val start = general.indexOf(""""$member":""")
            val renamed = general.replaceRange(startIndex = start + 1, endIndex = start + 2, replacement = "x")
            edge.decode(renamed).failure() shouldBe JoseFailure.Malformed
        }
    }
})
