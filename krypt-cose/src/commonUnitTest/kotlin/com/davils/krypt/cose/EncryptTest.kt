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

package com.davils.krypt.cose

import com.davils.krypt.core.algorithm.AeadAlgorithm
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.algorithm.KeyWrapAlgorithm
import com.davils.krypt.cose.cbor.CborBytes
import com.davils.krypt.cose.cbor.CborInteger
import com.davils.krypt.cose.cbor.CborMap
import com.davils.krypt.cose.fixture.AES_GCM_01
import com.davils.krypt.cose.fixture.AES_GCM_01_KEY_0
import com.davils.krypt.cose.fixture.AES_GCM_01_RNG
import com.davils.krypt.cose.fixture.AES_GCM_02
import com.davils.krypt.cose.fixture.AES_GCM_02_KEY_0
import com.davils.krypt.cose.fixture.AES_GCM_03
import com.davils.krypt.cose.fixture.AES_GCM_03_KEY_0
import com.davils.krypt.cose.fixture.AES_GCM_04
import com.davils.krypt.cose.fixture.AES_GCM_ENC_01
import com.davils.krypt.cose.fixture.AES_GCM_ENC_01_RNG
import com.davils.krypt.cose.fixture.AES_GCM_ENC_02
import com.davils.krypt.cose.fixture.AES_GCM_ENC_03
import com.davils.krypt.cose.fixture.AES_WRAP_128_04
import com.davils.krypt.cose.fixture.AES_WRAP_128_04_KEY_0
import com.davils.krypt.cose.fixture.CHACHA_01
import com.davils.krypt.cose.fixture.CHACHA_01_KEY_0
import com.davils.krypt.cose.fixture.CHACHA_ENC_01
import com.davils.krypt.cose.fixture.CONTENT
import com.davils.krypt.cose.fixture.ENC_PASS_02
import com.davils.krypt.cose.fixture.ENC_PASS_02_AAD
import com.davils.krypt.cose.fixture.P256_HKDF_256_01
import com.davils.krypt.cose.fixture.P256_HKDF_256_01_KEY_0
import com.davils.krypt.cose.fixture.P256_HKDF_256_02
import com.davils.krypt.cose.fixture.P256_HKDF_512_01
import com.davils.krypt.cose.fixture.P256_WRAP_128_01
import com.davils.krypt.cose.fixture.P256_WRAP_192_01
import com.davils.krypt.cose.fixture.P256_WRAP_256_01
import com.davils.krypt.cose.fixture.P521_HKDF_256_01
import com.davils.krypt.cose.fixture.P521_HKDF_256_01_KEY_0
import com.davils.krypt.cose.fixture.X25519_DIRECT
import com.davils.krypt.cose.fixture.X25519_DIRECT_KEY_0
import com.davils.krypt.cose.fixture.cose
import com.davils.krypt.cose.fixture.crypto
import com.davils.krypt.cose.fixture.failure
import com.davils.krypt.cose.fixture.hex
import com.davils.krypt.cose.fixture.hexOf
import com.davils.krypt.cose.fixture.key
import com.davils.krypt.cose.fixture.relaxed
import com.davils.krypt.cose.fixture.replaying
import com.davils.krypt.cose.fixture.utf8
import com.davils.krypt.cose.fixture.value
import com.davils.krypt.cose.fixture.withoutKeyId
import com.davils.krypt.cose.key.CoseKey
import com.davils.krypt.cose.key.CoseKeyOperation
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

private val CONTENTS: Set<CoseAlgorithm> =
    CoseAlgorithm.entries.filter { algorithm -> algorithm.kind == CoseAlgorithmKind.ContentEncryption }.toSet()
private val DISTRIBUTIONS: Set<CoseAlgorithm> =
    CoseAlgorithm.entries.filter { algorithm -> algorithm.kind == CoseAlgorithmKind.KeyDistribution }.toSet()
private val EVERYTHING: Set<CoseAlgorithm> = CONTENTS + DISTRIBUTIONS
private const val SECRET: String = "our-secret"

private fun anonymous(encoded: String): CoseKey = CoseKey.of(secretKey = checkNotNull(key(encoded).secretKey))

private suspend fun decrypts(encoded: String, keyHex: String) {
    decrypts(encoded = encoded, key = key(keyHex))
}

private suspend fun decrypts(encoded: String, key: CoseKey) {
    val message = relaxed.decodeEncrypt(hex(encoded)).value()
    relaxed.decrypt(message = message, keys = listOf(key), algorithms = EVERYTHING).value() shouldBe utf8(CONTENT)
}

private suspend fun decrypts0(encoded: String, keyHex: String) {
    val message = relaxed.decodeEncrypt0(hex(encoded)).value()
    relaxed.decrypt(message = message, keys = listOf(key(keyHex)), algorithms = EVERYTHING).value() shouldBe
        utf8(CONTENT)
}

private suspend fun isSupported(algorithm: CoseAlgorithm): Boolean {
    val aead = algorithm.aead ?: return true
    return crypto.capabilities.supports(aead)
}

class EncryptTest : FunSpec({
    test("the AES-GCM examples of the COSE working group decrypt") {
        decrypts(encoded = AES_GCM_01, keyHex = AES_GCM_01_KEY_0)
        decrypts(encoded = AES_GCM_03, key = anonymous(AES_GCM_03_KEY_0))
        decrypts0(encoded = AES_GCM_ENC_01, keyHex = AES_GCM_01_KEY_0)
        decrypts0(encoded = AES_GCM_ENC_03, keyHex = AES_GCM_03_KEY_0)
        val external = relaxed.decodeEncrypt0(hex(ENC_PASS_02)).value()
        val outcome1 = relaxed.decrypt(
            message = external,
            keys = listOf(key(AES_GCM_01_KEY_0)),
            algorithms = EVERYTHING,
            externalAad = hex(ENC_PASS_02_AAD),
        )
        outcome1.value() shouldBe utf8(CONTENT)
        if (crypto.capabilities.supports(AeadAlgorithm.Aes192Gcm)) {
            decrypts(encoded = AES_GCM_02, key = anonymous(AES_GCM_02_KEY_0))
            decrypts0(encoded = AES_GCM_ENC_02, keyHex = AES_GCM_02_KEY_0)
        }
        if (crypto.capabilities.supports(AeadAlgorithm.ChaCha20Poly1305)) {
            decrypts(encoded = CHACHA_01, keyHex = CHACHA_01_KEY_0)
            decrypts0(encoded = CHACHA_ENC_01, keyHex = CHACHA_01_KEY_0)
        }
    }

    test("the key wrap and ECDH examples of the COSE working group decrypt") {
        decrypts(encoded = AES_WRAP_128_04, keyHex = AES_WRAP_128_04_KEY_0)
        decrypts(encoded = P256_HKDF_256_01, keyHex = P256_HKDF_256_01_KEY_0)
        decrypts(encoded = P256_HKDF_256_02, keyHex = P256_HKDF_256_01_KEY_0)
        decrypts(encoded = P256_HKDF_512_01, keyHex = P256_HKDF_256_01_KEY_0)
        decrypts(encoded = P521_HKDF_256_01, key = withoutKeyId(key(P521_HKDF_256_01_KEY_0)))
        decrypts(encoded = P256_WRAP_128_01, keyHex = P256_HKDF_256_01_KEY_0)
        decrypts(encoded = P256_WRAP_256_01, keyHex = P256_HKDF_256_01_KEY_0)
        decrypts(encoded = X25519_DIRECT, keyHex = X25519_DIRECT_KEY_0)
        if (crypto.capabilities.supports(KeyWrapAlgorithm.Aes192Kw)) {
            decrypts(encoded = P256_WRAP_192_01, keyHex = P256_HKDF_256_01_KEY_0)
        }
    }

    test("a changed tag fails with the one failure of decryption") {
        val message = relaxed.decodeEncrypt(hex(AES_GCM_04)).value()
        val outcome2 = relaxed.decrypt(
            message = message,
            keys = listOf(key(AES_GCM_01_KEY_0)),
            algorithms = EVERYTHING,
        )
        outcome2.failure() shouldBe
            CoseFailure.DecryptionFailed
    }

    test("AES-GCM with direct keys is created exactly as the known answers") {
        val replayed = Cose(replaying(AES_GCM_01_RNG))
        val recipient = CoseRecipientSpec(key = key(AES_GCM_01_KEY_0), algorithm = CoseAlgorithm.Direct)
        val message = replayed.encrypt(
            plaintext = utf8(CONTENT),
            algorithm = CoseAlgorithm.A128Gcm,
            recipients = listOf(recipient),
        )
        hexOf(message.encode()) shouldBe AES_GCM_01
        val single = Cose(replaying(AES_GCM_ENC_01_RNG))
        val encrypted = single.encrypt0(
            plaintext = utf8(CONTENT),
            key = anonymous(AES_GCM_01_KEY_0),
            algorithm = CoseAlgorithm.A128Gcm,
        )
        hexOf(encrypted.encode()) shouldBe AES_GCM_ENC_01
    }

    test("every content algorithm round-trips with every kind of recipient") {
        val wraps = listOf(CoseAlgorithm.A128Kw, CoseAlgorithm.A192Kw, CoseAlgorithm.A256Kw)
        val agreements = listOf(
            CoseAlgorithm.EcdhEsA128Kw to KeyType.P256,
            CoseAlgorithm.EcdhEsA192Kw to KeyType.P521,
            CoseAlgorithm.EcdhEsA256Kw to KeyType.X25519,
        )
        val wrapKeys = wraps.map { algorithm ->
            val size = checkNotNull(algorithm.keyWrap).keyBytes
            CoseKey.of(crypto.keys.generateSecret(size), keyId = utf8(algorithm.algorithmName))
        }
        val agreementKeys = agreements.map { (algorithm, type) ->
            algorithm to crypto.keys.generate(type)
        }
        val outcome3 = wraps.zip(
            wrapKeys,
        )
        val specs = outcome3.map { (algorithm, wrapKey) -> CoseRecipientSpec(key = wrapKey, algorithm = algorithm) } +
            agreementKeys.map { (algorithm, pair) ->
                CoseRecipientSpec(
                    key = CoseKey.of(pair.publicKey, keyId = utf8(algorithm.algorithmName)),
                    algorithm = algorithm,
                )
            }
        val receivers = wrapKeys +
            agreementKeys.map { (algorithm, pair) ->
                CoseKey.of(pair.privateKey, keyId = utf8(algorithm.algorithmName))
            }
        val usable = specs.filter { spec -> crypto.capabilities.supports(checkNotNull(spec.algorithm.keyWrap)) }
        CONTENTS.filter { algorithm -> isSupported(algorithm) }.forEach { algorithm ->
            val message = cose.encrypt(
                plaintext = utf8(CONTENT),
                algorithm = algorithm,
                recipients = usable,
                externalAad = utf8("aad"),
            )
            val decoded = cose.decodeEncrypt(message.encode(isTagged = false)).value()
            val matching = receivers.filter { receiver -> usable.any { spec -> spec.key.keyId == receiver.keyId } }
            matching.forEach { receiver ->
                val outcome4 = cose.decrypt(
                    message = decoded,
                    keys = listOf(receiver),
                    algorithms = EVERYTHING,
                    externalAad = utf8("aad"),
                )
                outcome4.value() shouldBe
                    utf8(CONTENT)
            }
            val outcome5 = cose.decrypt(
                message = decoded,
                keys = receivers,
                algorithms = EVERYTHING,
            )
            outcome5.failure() shouldBe CoseFailure.DecryptionFailed
            val outcome6 = cose.decrypt(
                message = decoded,
                keys = receivers,
                algorithms = CONTENTS,
                externalAad = utf8("aad"),
            )
            outcome6.failure() shouldBe
                CoseFailure.AlgorithmNotPermitted
        }
    }

    test("direct key agreement derives the content key for one recipient") {
        val pair = crypto.keys.generate(KeyType.P384)
        val spec = CoseRecipientSpec(
            key = CoseKey.of(pair.publicKey),
            algorithm = CoseAlgorithm.EcdhEsHkdf512,
            unprotectedHeaders = CoseHeaders.of(
                parameters = CborMap.of(
                    CborInteger
                        .of(-20L) to CborBytes(utf8("salt")),
                    CborInteger
                        .of(-21L) to CborBytes(utf8("alice")),
                ),
            ),
        )
        val message = cose.encrypt(
            plaintext = utf8(CONTENT),
            algorithm = CoseAlgorithm.A256Gcm,
            recipients = listOf(spec),
            isDetached = true,
        )
        val receiver = CoseKey.of(pair.privateKey, operations = setOf(CoseKeyOperation.DeriveKey))
        val outcome7 = cose.decrypt(
            message = message,
            keys = listOf(receiver),
            algorithms = EVERYTHING,
            detachedCiphertext = message.ciphertext,
        )
        outcome7.failure() shouldBe
            CoseFailure.Malformed
        val encryptedAgain = cose.encrypt(
            plaintext = utf8(CONTENT),
            algorithm = CoseAlgorithm.A256Gcm,
            recipients = listOf(spec),
        )
        val ciphertext = checkNotNull(encryptedAgain.ciphertext)
        val attached = cose.encrypt(
            plaintext = utf8(CONTENT),
            algorithm = CoseAlgorithm.A256Gcm,
            recipients = listOf(spec),
        )
        val outcome9 = cose.decrypt(
            message = attached,
            keys = listOf(receiver),
            algorithms = EVERYTHING,
        )
        outcome9.value() shouldBe utf8(CONTENT)
        ciphertext.size shouldBe CONTENT.length + AeadAlgorithm.Aes256Gcm.tagBytes
        val other = crypto.keys.generate(KeyType.P384)
        val outcome10 = cose.decrypt(
            message = attached,
            keys = listOf(CoseKey.of(other.privateKey)),
            algorithms = EVERYTHING,
        )
        outcome10.failure() shouldBe
            CoseFailure.DecryptionFailed
        shouldThrow<IllegalArgumentException> {
            cose.encrypt(plaintext = utf8(CONTENT), algorithm = CoseAlgorithm.A256Gcm, recipients = listOf(spec, spec))
        }
    }

    test("Encrypt0 completes a Partial IV with the base IV of the key") {
        val baseIv = hex("000102030405060708090A0B")
        val secret = CoseKey.of(crypto.keys.generateSecret(16), keyId = utf8(SECRET), baseIv = baseIv)
        val headers = CoseHeaders.of(
            parameters = CborMap.of(
                CborInteger
                    .of(6L) to CborBytes(hex("61")),
            ),
        )
        val message = cose.encrypt0(
            plaintext = utf8(CONTENT),
            key = secret,
            algorithm = CoseAlgorithm.A128Gcm,
            unprotectedHeaders = headers,
        )
        cose.decrypt(message = message, keys = listOf(secret), algorithms = CONTENTS).value() shouldBe utf8(CONTENT)
        val withoutBase = CoseKey.of(checkNotNull(secret.secretKey), keyId = utf8(SECRET))
        val outcome11 = cose.decrypt(
            message = message,
            keys = listOf(withoutBase),
            algorithms = CONTENTS,
        )
        outcome11.failure() shouldBe CoseFailure.DecryptionFailed
        shouldThrow<IllegalArgumentException> {
            cose.encrypt0(
                plaintext = utf8(CONTENT),
                key = withoutBase,
                algorithm = CoseAlgorithm.A128Gcm,
                unprotectedHeaders = headers,
            )
        }
        shouldThrow<IllegalArgumentException> {
            cose.encrypt(
                plaintext = utf8(CONTENT),
                algorithm = CoseAlgorithm.A128Gcm,
                recipients = listOf(CoseRecipientSpec(key = withoutBase, algorithm = CoseAlgorithm.Direct)),
                unprotectedHeaders = headers,
            )
        }
        shouldThrow<IllegalArgumentException> {
            cose.encrypt0(
                plaintext = utf8(CONTENT),
                key = secret,
                algorithm = CoseAlgorithm.A256Gcm,
            )
        }
        shouldThrow<IllegalArgumentException> {
            cose.encrypt0(
                plaintext = utf8(CONTENT),
                key = secret,
                algorithm = CoseAlgorithm.Hmac256,
            )
        }
    }
})
