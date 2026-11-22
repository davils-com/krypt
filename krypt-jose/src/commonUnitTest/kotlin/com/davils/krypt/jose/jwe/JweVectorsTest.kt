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

import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.SecretText
import com.davils.krypt.core.environment
import com.davils.krypt.jose.JoseFailure
import com.davils.krypt.jose.JoseKey
import com.davils.krypt.jose.fixture.Rfc7520
import com.davils.krypt.jose.fixture.Vectors
import com.davils.krypt.jose.fixture.compatible
import com.davils.krypt.jose.fixture.compatibleKeys
import com.davils.krypt.jose.fixture.failure
import com.davils.krypt.jose.fixture.hex
import com.davils.krypt.jose.fixture.keyOf
import com.davils.krypt.jose.fixture.replayed
import com.davils.krypt.jose.fixture.unbase64
import com.davils.krypt.jose.fixture.utf8
import com.davils.krypt.jose.fixture.value
import com.davils.krypt.jose.internal.ConcatKdf
import com.davils.krypt.primitive.Crypto
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldEndWith
import io.kotest.matchers.string.shouldStartWith

private val jwe = Jwe(compatible)
private val passwords = Jwe(compatible, isPasswordAllowed = true)
private val algorithms = JweAlgorithm.entries.toSet()
private val encryptions = JweEncryption.entries.toSet()
private const val KEY_COUNT = 3
private const val OPENING = "You can trust us to stick with you"
private const val CLOSING = "We are your friends, Frodo."

private suspend fun plaintextOf(text: String, key: JoseKey, engine: Jwe = jwe): String {
    val decrypted = engine.decrypt(text = text, keys = listOf(key), algorithms = algorithms, encryptions = encryptions)
    val bytes = decrypted.value().plaintext
    return bytes.toByteArray().decodeToString()
}

private suspend fun checkFrodo(text: String, key: JoseKey) {
    val plaintext = plaintextOf(text, key)
    plaintext shouldStartWith OPENING
    plaintext shouldEndWith CLOSING
}

class JweVectorsTest : FunSpec({
    test("RFC 7520 5.4 and 5.5 decrypt ECDH-ES with and without key wrapping") {
        checkFrodo(Rfc7520.JWE_ECDH_KW_COMPACT, keyOf(Rfc7520.EC_P384_PRIVATE))
        checkFrodo(Rfc7520.JWE_ECDH_KW_GENERAL, keyOf(Rfc7520.EC_P384_PRIVATE))
        checkFrodo(Rfc7520.JWE_ECDH_COMPACT, keyOf(Rfc7520.EC_P256_PRIVATE))
        checkFrodo(Rfc7520.JWE_ECDH_GENERAL, keyOf(Rfc7520.EC_P256_PRIVATE))
    }

    test("RFC 7520 5.6 to 5.8 decrypt dir, AES-GCM key wrapping and AES key wrap") {
        checkFrodo(Rfc7520.JWE_DIR_COMPACT, keyOf(Rfc7520.AES128_DIR_KEY))
        checkFrodo(Rfc7520.JWE_GCMKW_COMPACT, keyOf(Rfc7520.AES256_GCMKW_KEY))
        checkFrodo(Rfc7520.JWE_GCMKW_FLATTENED, keyOf(Rfc7520.AES256_GCMKW_KEY))
        checkFrodo(Rfc7520.JWE_KW_COMPACT, keyOf(Rfc7520.AES128_KW_KEY))
        checkFrodo(Rfc7520.JWE_KW_GENERAL, keyOf(Rfc7520.AES128_KW_KEY))
    }

    test("RFC 7520 5.10 to 5.12 decrypt with additional data and unprotected headers") {
        val key = keyOf(Rfc7520.AES128_KW_KEY)
        checkFrodo(Rfc7520.JWE_AAD_GENERAL, key)
        checkFrodo(Rfc7520.JWE_PROTECTED_FIELDS_GENERAL, key)
        checkFrodo(Rfc7520.JWE_CONTENT_ONLY_GENERAL, key)
    }

    test("RFC 7520 5.13 decrypts the recipients krypt supports and skips RSA1_5") {
        checkFrodo(Rfc7520.JWE_MULTIPLE_GENERAL, keyOf(Rfc7520.EC_P384_PRIVATE))
        checkFrodo(Rfc7520.JWE_MULTIPLE_GENERAL, keyOf(Rfc7520.AES256_GCMKW_KEY))
        val decrypted = jwe.decrypt(
            text = Rfc7520.JWE_MULTIPLE_GENERAL,
            keys = listOf(keyOf(Rfc7520.AES128_KW_KEY)),
            algorithms = algorithms,
            encryptions = encryptions,
        )
        decrypted.failure() shouldBe JoseFailure.UnsupportedAlgorithm
    }

    test("RFC 7520 5.1 and 5.9 are refused for RSA1_5 and zip") {
        val key = keyOf(Rfc7520.AES128_KW_KEY)
        val outcome1 = jwe.decrypt(
            text = Rfc7520.JWE_RSA15_COMPACT,
            keys = listOf(key),
            algorithms = algorithms,
            encryptions = encryptions,
        )
        outcome1.failure() shouldBe
            JoseFailure.UnsupportedAlgorithm
        val outcome2 = jwe.decrypt(
            text = Rfc7520.JWE_ZIP_COMPACT,
            keys = listOf(key),
            algorithms = algorithms,
            encryptions = encryptions,
        )
        outcome2.failure() shouldBe
            JoseFailure.UnsupportedAlgorithm
    }

    test("RFC 7520 5.3 decrypts PBES2 only with the opt-in") {
        val password = JoseKey.Password(SecretText.of("entrap_o–peter_long–credit_tun"))
        val plaintext = plaintextOf(Rfc7520.JWE_PBES2_COMPACT, password, passwords)
        val set = compatibleKeys.decodeSet(plaintext).value()
        set.keys.size shouldBe KEY_COUNT
        plaintextOf(Rfc7520.JWE_PBES2_GENERAL, password, passwords) shouldBe plaintext
        val outcome3 = jwe.decrypt(
            text = Rfc7520.JWE_PBES2_COMPACT,
            keys = listOf(password),
            algorithms = algorithms,
            encryptions = encryptions,
        )
        outcome3.failure() shouldBe
            JoseFailure.AlgorithmNotAllowed
    }

    test("RFC 7517 C decrypts an RSA private key encrypted with PBES2") {
        val password = JoseKey.Password(SecretText.of(Vectors.RFC7517_PASSWORD))
        val decrypted = passwords.decrypt(
            text = Vectors.RFC7517_ENCRYPTED_KEY,
            keys = listOf(password),
            algorithms = algorithms,
            encryptions = encryptions,
        )
        decrypted.value().header.contentType shouldBe "jwk+json"
        val bytes = decrypted.value().plaintext
        val jwk = compatibleKeys.decode(bytes.toByteArray().decodeToString()).value()
        jwk.isPrivate shouldBe true
    }

    test("RFC 7516 A.3 encrypts with A128KW and A128CBC-HS256 deterministically and decrypts") {
        val random = replayed(hex(Vectors.RFC7516_CEK), unbase64(Vectors.RFC7516_IV))
        val replaying = Jwe(Crypto(environment(compatible.environment) { this.random = random }))
        val key = keyOf(Vectors.RFC7516_KEY)
        val recipient = JweRecipient(key = key, algorithm = JweAlgorithm.A128KW)
        val token = replaying.encrypt(utf8(Vectors.RFC7516_PLAINTEXT), recipient, JweEncryption.A128CBC_HS256)
        token shouldBe Vectors.RFC7516_JWE
        plaintextOf(Vectors.RFC7516_JWE, key) shouldBe Vectors.RFC7516_PLAINTEXT
    }

    test("RFC 7518 C derives the key of ECDH-ES with the Concat KDF") {
        val alice = compatibleKeys.decode(Vectors.RFC7518_ALICE).value()
        val bob = compatibleKeys.privateKey(compatibleKeys.decode(Vectors.RFC7518_BOB).value()).value()
        val shared = compatible.agreements.agree(privateKey = bob, publicKey = compatibleKeys.publicKey(alice).value())
        shared shouldBe SecretBytes.copyOf(hex(Vectors.RFC7518_SHARED))
        val derived = ConcatKdf.derive(
            crypto = compatible,
            secret = shared,
            algorithmId = "A128GCM",
            partyU = utf8("Alice"),
            partyV = utf8("Bob"),
            bits = 128,
        )
        derived shouldBe SecretBytes.copyOf(unbase64(Vectors.RFC7518_DERIVED))
    }

    test("RFC 8037 A.6 agrees on the X25519 secret of a JWK") {
        val bob = compatibleKeys.privateKey(compatibleKeys.decode(Vectors.RFC8037_X25519_PRIVATE).value()).value()
        val ephemeral = compatibleKeys.publicKey(compatibleKeys.decode(Vectors.RFC8037_X25519_EPHEMERAL).value())
        val shared = compatible.agreements.agree(privateKey = bob, publicKey = ephemeral.value())
        shared shouldBe SecretBytes.copyOf(hex(Vectors.RFC8037_X25519_SHARED))
    }
})
