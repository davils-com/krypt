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

package com.davils.krypt.primitive.cipher

import com.davils.krypt.core.algorithm.AeadAlgorithm
import com.davils.krypt.core.algorithm.AsymmetricEncryptionAlgorithm
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.algorithm.KeyWrapAlgorithm
import com.davils.krypt.primitive.fixture.crypto
import com.davils.krypt.primitive.fixture.hex
import com.davils.krypt.primitive.fixture.hexOf
import com.davils.krypt.primitive.fixture.secret
import com.davils.krypt.primitive.fixture.utf8
import com.davils.krypt.primitive.key.SecretKey
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.io.bytestring.ByteString

private const val GCM_KEY: String = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"
private const val GCM_NONCE: String = "cafebabefacedbaddecaf888"
private const val GCM_PLAINTEXT: String =
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e24" +
        "49a6b525b16aedf5aa0de657ba637b39"
private const val GCM_AAD: String = "feedfacedeadbeeffeedfacedeadbeefabaddad2"
private const val GCM_SEALED: String =
    "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b10" +
        "56828838c5f61e6393ba7a0abcc9f66276fc6ece0f4e1768cddf8853bb2d551b"
private const val KEK: String = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
private const val WRAPPED_DATA: String = "00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f"
private const val WRAPPED: String = "28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21"
private const val KEK_192: String = "000102030405060708090a0b0c0d0e0f1011121314151617"
private const val WRAPPED_128: String = "00112233445566778899aabbccddeeff"
private const val WRAPPED_BY_192: String = "96778b25ae6ca435f92b5b97c050aed2468ab8a17ad84e5d"
private const val CHACHA_KEY: String = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
private const val CHACHA_NONCE: String = "070000004041424344454647"
private const val CHACHA_AAD: String = "50515253c0c1c2c3c4c5c6c7"
private const val CHACHA_TAG: String = "1ae10b594f09e26a7e902ecbd0600691"
private const val SUNSCREEN: String =
    "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, " +
        "sunscreen would be it."
private const val MESSAGE: String = "the message"
private const val CONTEXT: String = "record:1"

class CipherTest : FunSpec({
    test("AES-256-GCM matches NIST test case 16") {
        val key = SecretKey.adopt(secret(GCM_KEY))
        val sealed = crypto.aead.encrypt(
            key = key,
            nonce = hex(GCM_NONCE),
            plaintext = hex(GCM_PLAINTEXT),
            associatedData = hex(GCM_AAD),
            algorithm = AeadAlgorithm.Aes256Gcm,
        )
        hexOf(sealed) shouldBe GCM_SEALED
        val opened = crypto.aead.decrypt(
            key = key,
            nonce = hex(GCM_NONCE),
            ciphertext = sealed,
            associatedData = hex(GCM_AAD),
            algorithm = AeadAlgorithm.Aes256Gcm,
        )
        opened shouldBe hex(GCM_PLAINTEXT)
    }

    test("ChaCha20-Poly1305 matches RFC 8439 section 2.8.2 where the platform has it") {
        val isSupported = crypto.capabilities.supports(AeadAlgorithm.ChaCha20Poly1305)
        val sealed = crypto.aead.takeIf { isSupported }?.encrypt(
            key = SecretKey.adopt(secret(CHACHA_KEY)),
            nonce = hex(CHACHA_NONCE),
            plaintext = utf8(SUNSCREEN),
            associatedData = hex(CHACHA_AAD),
            algorithm = AeadAlgorithm.ChaCha20Poly1305,
        )
        sealed?.let { bytes -> hexOf(bytes).takeLast(CHACHA_TAG.length) shouldBe CHACHA_TAG }
    }

    test("a sealed box opens with the same key and context only") {
        val key = crypto.keys.generateSecret()
        val box = crypto.aead.seal(key = key, plaintext = utf8(MESSAGE), associatedData = utf8(CONTEXT))
        crypto.aead.open(key = key, box = box, associatedData = utf8(CONTEXT)) shouldBe utf8(MESSAGE)
        crypto.aead.open(key = key, box = box, associatedData = utf8("record:2")) shouldBe null
        crypto.aead.open(key = crypto.keys.generateSecret(), box = box, associatedData = utf8(CONTEXT)) shouldBe null
        val flipped = box.ciphertext.toByteArray().also { bytes -> bytes[0] = (bytes[0].toInt() xor 1).toByte() }
        crypto.aead.open(
            key = key,
            box = SealedBox(nonce = box.nonce, ciphertext = ByteString(flipped)),
            associatedData = utf8(CONTEXT),
        ) shouldBe
            null
        val decoded = checkNotNull(SealedBox.decodeOrNull(encoded = box.encoded, algorithm = AeadAlgorithm.Aes256Gcm))
        decoded shouldBe box
        decoded.hashCode() shouldBe box.hashCode()
        decoded.toString() shouldBe "SealedBox(nonce=12, ciphertext=27)"
        SealedBox.decodeOrNull(encoded = ByteString(ByteArray(1)), algorithm = AeadAlgorithm.Aes256Gcm) shouldBe null
        crypto.aead.decrypt(
            key = key,
            nonce = box.nonce,
            ciphertext = ByteString(ByteArray(1)),
            associatedData = ByteString(),
            algorithm = AeadAlgorithm.Aes256Gcm,
        ) shouldBe null
        box shouldNotBe crypto.aead.seal(key = key, plaintext = utf8(MESSAGE), associatedData = utf8(CONTEXT))
    }

    test("keys and nonces of the wrong length are refused") {
        val short = SecretKey.adopt(secret("00".repeat(SecretKey.MINIMUM_BYTES)))
        shouldThrow<IllegalArgumentException> { crypto.aead.seal(key = short, plaintext = utf8(MESSAGE)) }
        shouldThrow<IllegalArgumentException> {
            crypto.aead.encrypt(
                key = crypto.keys.generateSecret(),
                nonce = ByteString(),
                plaintext = utf8(MESSAGE),
                associatedData = ByteString(),
                algorithm = AeadAlgorithm.Aes256Gcm,
            )
        }
        val box = crypto.aead.seal(key = short, plaintext = utf8(MESSAGE), algorithm = AeadAlgorithm.Aes128Gcm)
        box.nonce.size shouldBe AeadAlgorithm.Aes128Gcm.nonceBytes
    }

    test("the AES key wrap matches RFC 3394 section 4.6") {
        val kek = SecretKey.adopt(secret(KEK))
        val wrapped = crypto.keyWraps.wrap(kek = kek, key = secret(WRAPPED_DATA))
        hexOf(wrapped) shouldBe WRAPPED
        crypto.keyWraps.unwrap(kek = kek, wrapped = wrapped)?.let { key -> hexOf(key) } shouldBe WRAPPED_DATA
        val tampered = hex("00" + WRAPPED.drop(2))
        crypto.keyWraps.unwrap(kek = kek, wrapped = tampered) shouldBe null
        crypto.keyWraps.unwrap(kek = kek, wrapped = ByteString(ByteArray(SecretKey.MINIMUM_BYTES))) shouldBe null
        shouldThrow<IllegalArgumentException> { crypto.keyWraps.wrap(kek = kek, key = secret("0011")) }
        shouldThrow<IllegalArgumentException> {
            crypto.keyWraps.wrap(
                kek = SecretKey.adopt(secret("00".repeat(SecretKey.MINIMUM_BYTES))),
                key = secret(WRAPPED_DATA),
            )
        }
        shouldThrow<IllegalArgumentException> {
            crypto.keyWraps.unwrap(
                kek = SecretKey.adopt(secret("00".repeat(SecretKey.MINIMUM_BYTES))),
                wrapped = hex(WRAPPED),
            )
        }
    }

    test("AES-192 wraps by RFC 3394 section 4.2 and seals with GCM where the platform has it") {
        val kek = SecretKey.adopt(secret(KEK_192))
        val isWrapping = crypto.capabilities.supports(KeyWrapAlgorithm.Aes192Kw)
        val wrapped = kek.takeIf { isWrapping }?.let { found ->
            crypto.keyWraps.wrap(kek = found, key = secret(WRAPPED_128), algorithm = KeyWrapAlgorithm.Aes192Kw)
        }
        wrapped?.let { found -> hexOf(found) shouldBe WRAPPED_BY_192 }
        val isSealing = crypto.capabilities.supports(AeadAlgorithm.Aes192Gcm)
        val box = kek.takeIf { isSealing }?.let { found ->
            crypto.aead.seal(key = found, plaintext = utf8(MESSAGE), algorithm = AeadAlgorithm.Aes192Gcm)
        }
        val opened = box?.let { found ->
            crypto.aead.open(key = kek, box = found, algorithm = AeadAlgorithm.Aes192Gcm)
        }
        opened?.let { plain -> hexOf(plain) } shouldBe box?.let { hexOf(utf8(MESSAGE)) }
    }

    test("RSA-OAEP encrypts a key for the holder of the private key") {
        val pair = crypto.keys.generate(KeyType.Rsa3072)
        val ciphertext = crypto.encryptions.encrypt(publicKey = pair.publicKey, plaintext = utf8(MESSAGE))
        val decrypted = crypto.encryptions.decrypt(privateKey = pair.privateKey, ciphertext = ciphertext)
        decrypted?.let { plain -> hexOf(plain) } shouldBe hexOf(utf8(MESSAGE))
        crypto.encryptions.decrypt(
            privateKey = pair.privateKey,
            ciphertext = ciphertext,
            algorithm = AsymmetricEncryptionAlgorithm.RsaOaepSha384,
        ) shouldBe null
        val ed = crypto.keys.generate(KeyType.Ed25519)
        shouldThrow<IllegalArgumentException> {
            crypto.encryptions.encrypt(
                publicKey = ed.publicKey,
                plaintext = utf8(MESSAGE),
            )
        }
        shouldThrow<IllegalArgumentException> {
            crypto.encryptions.decrypt(
                privateKey = ed.privateKey,
                ciphertext = ciphertext,
            )
        }
    }
})
