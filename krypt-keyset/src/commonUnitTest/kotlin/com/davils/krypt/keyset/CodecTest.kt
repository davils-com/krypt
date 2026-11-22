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

package com.davils.krypt.keyset

import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.algorithm.AeadAlgorithm
import com.davils.krypt.core.algorithm.KdfAlgorithm
import com.davils.krypt.core.algorithm.KemAlgorithm
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.CryptoPolicy
import com.davils.krypt.keyset.fixture.ID
import com.davils.krypt.keyset.fixture.OTHER_ID
import com.davils.krypt.keyset.fixture.RawEntry
import com.davils.krypt.keyset.fixture.crypto
import com.davils.krypt.keyset.fixture.encryptedOf
import com.davils.krypt.keyset.fixture.flipped
import com.davils.krypt.keyset.fixture.keysetOf
import com.davils.krypt.keyset.fixture.keysets
import com.davils.krypt.keyset.fixture.utf8
import com.davils.krypt.keyset.kms.LocalKms
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.exchange.HpkeSuite
import com.davils.krypt.primitive.key.PrivateKey
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString

private const val NAME: String = "payments"
private const val AEAD: String = "aead"
private const val AES: String = "Aes256Gcm"
private const val SIGNING: String = "signing"
private const val HYBRID: String = "hybrid"
private const val ED25519: String = "Ed25519"
private const val UNKNOWN: String = "Nope"
private const val HKDF: String = "HkdfSha256"
private const val DHKEM: String = "DhkemX25519"
private const val KEY_BYTES: Int = 32
private const val DESTROYED: Long = 2L
private const val UNKNOWN_STATUS: Long = 7L

private val secret: ByteString = ByteString(ByteArray(KEY_BYTES) { index -> index.toByte() })

private suspend fun decodeSecret(encoded: ByteString): KeysetFailure? {
    val kms = LocalKms(crypto, crypto.keys.generateSecret())
    val encrypted = kms.encrypt(plaintext = SecretBytes.copyOf(encoded), associatedData = utf8("krypt keyset v1 "))
    return keysets.decrypt(encryptedOf(kms.keyUri, encrypted), kms).failureOrNull()
}

private suspend fun publicOf(type: KeyType): ByteString? {
    val keyset = keysets.generate(KeyPurpose.Signing(type))
    return keyset.primary.publicKey?.encoded
}

private fun privateOf(key: PrivateKey): ByteString {
    val encoded = crypto.keys.encodePrivate(key)
    return encoded.reveal { bytes -> ByteString(bytes) }
}

class CodecTest : FunSpec({
    val kms = LocalKms(crypto, crypto.keys.generateSecret())

    test("every purpose survives encryption and decryption") {
        val purposes = listOf(KeyPurpose.Aead(), KeyPurpose.Mac(), KeyPurpose.Signing(), KeyPurpose.Hybrid())
        purposes.forEach { purpose ->
            val keyset = keysets.rotate(keysets.generate(purpose))
            val disabled = keysets.disable(keyset, keyset.keys.first().id)
            val encrypted = keysets.encrypt(disabled, kms, utf8(NAME))
            keysets.decrypt(encrypted, kms, utf8(NAME)).getOrNull() shouldBe disabled
        }
    }

    test("a destroyed key keeps its id only") {
        val keyset = keysets.rotate(keysets.generate(KeyPurpose.Signing()))
        val destroyed = keysets.destroy(keyset, keyset.keys.first().id)
        val decrypted = keysets.decrypt(keysets.encrypt(destroyed, kms), kms).getOrNull()
        decrypted shouldBe destroyed
    }

    test("an encrypted key set is bound to its name, its key and its bytes") {
        val keyset = keysets.generate(KeyPurpose.Aead())
        val encrypted = keysets.encrypt(keyset, kms, utf8(NAME))
        keysets.decrypt(encrypted, kms, utf8("other")).failureOrNull() shouldBe KeysetFailure.DecryptionFailed
        val other = LocalKms(crypto = crypto, key = crypto.keys.generateSecret(), keyUri = "other")
        keysets.decrypt(encrypted, other, utf8(NAME)).failureOrNull() shouldBe KeysetFailure.WrongKeyManagementService
        val tampered = flipped(encrypted, encrypted.size - 1)
        keysets.decrypt(tampered, kms, utf8(NAME)).failureOrNull() shouldBe KeysetFailure.DecryptionFailed
        keysets.decrypt(utf8("garbage"), kms).failureOrNull() shouldBe KeysetFailure.Malformed
        val small = Keysets(crypto = crypto, limits = KeysetLimits(maximumEncodedBytes = 1))
        small.decrypt(encrypted, kms, utf8(NAME)).failureOrNull() shouldBe KeysetFailure.Malformed
    }

    test("a public key set is encoded in the clear and read back") {
        val p256 = HpkeSuite(
            kem = KemAlgorithm.DhkemP256,
            kdf = KdfAlgorithm.HkdfSha256,
            aead = AeadAlgorithm.Aes128Gcm,
        )
        val keyset = keysets.publicKeyset(keysets.rotate(keysets.generate(KeyPurpose.Hybrid(p256))))
        val encoded = keysets.encodePublic(keyset)
        keysets.decodePublic(encoded).getOrNull() shouldBe keyset
        shouldThrow<IllegalArgumentException> { keysets.encodePublic(keysets.generate(KeyPurpose.Signing())) }
        val cnsa = Keysets(Crypto(environment { policy = CryptoPolicy.Cnsa2 }))
        cnsa.decodePublic(encoded) shouldBe Outcome.Failure(KeysetFailure.Refused)
    }

    test("hostile public key sets are refused") {
        val public = publicOf(KeyType.Ed25519)
        val p256 = publicOf(KeyType.P256)
        val cases = mapOf(
            keysetOf(listOf(SIGNING, ED25519), listOf(RawEntry(publicKey = public)), version = 2L) to
                KeysetFailure.Unsupported,
            keysetOf(listOf(SIGNING, "Ed99"), listOf(RawEntry(publicKey = public))) to KeysetFailure.Unsupported,
            keysetOf(listOf("none", ED25519), listOf(RawEntry(publicKey = public))) to KeysetFailure.Unsupported,
            keysetOf(listOf(SIGNING, "X25519"), listOf(RawEntry(publicKey = public))) to KeysetFailure.Unsupported,
            keysetOf(listOf(SIGNING), listOf(RawEntry(publicKey = public))) to KeysetFailure.Unsupported,
            keysetOf(listOf(HYBRID, DHKEM, HKDF), listOf(RawEntry(publicKey = public))) to
                KeysetFailure.Unsupported,
            keysetOf(listOf(HYBRID, DHKEM, HKDF, UNKNOWN), listOf(RawEntry(publicKey = public))) to
                KeysetFailure.Unsupported,
            keysetOf(listOf(SIGNING, ED25519), emptyList()) to KeysetFailure.Malformed,
            keysetOf(listOf(SIGNING, ED25519), listOf(RawEntry(publicKey = public)), primary = ByteString(1)) to
                KeysetFailure.Malformed,
            keysetOf(listOf(SIGNING, ED25519), listOf(RawEntry(publicKey = public)), primary = OTHER_ID) to
                KeysetFailure.Malformed,
            keysetOf(listOf(SIGNING, ED25519), listOf(RawEntry(publicKey = public), RawEntry(publicKey = public))) to
                KeysetFailure.Malformed,
            keysetOf(listOf(SIGNING, ED25519), listOf(RawEntry(status = 1L, publicKey = public))) to
                KeysetFailure.Malformed,
            keysetOf(listOf(SIGNING, ED25519), listOf(RawEntry(status = UNKNOWN_STATUS, publicKey = public))) to
                KeysetFailure.Malformed,
            keysetOf(listOf(SIGNING, ED25519), listOf(RawEntry(id = ByteString(1), publicKey = public))) to
                KeysetFailure.Malformed,
            keysetOf(listOf(SIGNING, ED25519), listOf(RawEntry())) to KeysetFailure.Malformed,
            keysetOf(listOf(SIGNING, ED25519), listOf(RawEntry(publicKey = p256))) to KeysetFailure.Malformed,
            keysetOf(listOf(SIGNING, ED25519), listOf(RawEntry(publicKey = utf8("junk")))) to KeysetFailure.Malformed,
            keysetOf(listOf(SIGNING, ED25519), listOf(RawEntry(publicKey = public, secret = secret))) to
                KeysetFailure.Malformed,
            keysetOf(listOf(SIGNING, ED25519), listOf(RawEntry(publicKey = public, privateKey = secret))) to
                KeysetFailure.Malformed,
            keysetOf(listOf(AEAD, AES), listOf(RawEntry(secret = secret))) to KeysetFailure.Malformed,
            keysetOf(listOf(AEAD, UNKNOWN), listOf(RawEntry(secret = secret))) to KeysetFailure.Unsupported,
            keysetOf(listOf("mac", UNKNOWN), listOf(RawEntry(secret = secret))) to KeysetFailure.Unsupported,
            keysetOf(listOf(HYBRID, UNKNOWN, HKDF, AES), listOf(RawEntry(publicKey = public))) to
                KeysetFailure.Unsupported,
            keysetOf(listOf(HYBRID, DHKEM, UNKNOWN, AES), listOf(RawEntry(publicKey = public))) to
                KeysetFailure.Unsupported,
            keysetOf(
                listOf(SIGNING, ED25519),
                listOf(RawEntry(publicKey = public), RawEntry(id = OTHER_ID, status = DESTROYED, publicKey = public)),
            ) to KeysetFailure.Malformed,
            utf8("garbage") to KeysetFailure.Malformed,
        )
        cases.forEach { (encoded, failure) -> keysets.decodePublic(encoded).failureOrNull() shouldBe failure }
        val single = keysetOf(listOf(SIGNING, ED25519), listOf(RawEntry(publicKey = public)))
        keysets.decodePublic(single).getOrNull()?.primaryId shouldBe KeyId.of(ID)
        val many = keysetOf(listOf(SIGNING, ED25519), listOf(RawEntry(publicKey = public), RawEntry(id = OTHER_ID)))
        val small = Keysets(crypto = crypto, limits = KeysetLimits(maximumKeys = 1))
        small.decodePublic(many).failureOrNull() shouldBe KeysetFailure.Malformed
    }

    test("hostile secret key sets are refused") {
        val pair = keysets.generate(KeyPurpose.Signing())
        val public = pair.primary.publicKey?.encoded
        val private = privateOf(checkNotNull(pair.primary.privateKey))
        val otherPrivate = keysets.generate(KeyPurpose.Signing()).primary.privateKey
        val foreign = privateOf(checkNotNull(otherPrivate))
        val p256 = keysets.generate(KeyPurpose.Signing(KeyType.P256)).primary.privateKey
        val wrongType = privateOf(checkNotNull(p256))
        decodeSecret(keysetOf(listOf(AEAD, AES), listOf(RawEntry()))) shouldBe KeysetFailure.Malformed
        decodeSecret(keysetOf(listOf(AEAD, AES), listOf(RawEntry(secret = ByteString(1))))) shouldBe
            KeysetFailure.Malformed
        decodeSecret(keysetOf(listOf(AEAD, AES), listOf(RawEntry(secret = secret, publicKey = public)))) shouldBe
            KeysetFailure.Malformed
        decodeSecret(keysetOf(listOf(AEAD, AES), listOf(RawEntry(secret = secret, privateKey = private)))) shouldBe
            KeysetFailure.Malformed
        decodeSecret(keysetOf(listOf(SIGNING, ED25519), listOf(RawEntry(publicKey = public)))) shouldBe
            KeysetFailure.Malformed
        decodeSecret(
            keysetOf(listOf(SIGNING, ED25519), listOf(RawEntry(publicKey = public, privateKey = foreign))),
        ) shouldBe KeysetFailure.Malformed
        decodeSecret(
            keysetOf(listOf(SIGNING, ED25519), listOf(RawEntry(publicKey = public, privateKey = wrongType))),
        ) shouldBe KeysetFailure.Malformed
        decodeSecret(
            keysetOf(listOf(SIGNING, ED25519), listOf(RawEntry(publicKey = public, privateKey = utf8("junk")))),
        ) shouldBe KeysetFailure.Malformed
        decodeSecret(
            keysetOf(listOf(SIGNING, ED25519), listOf(RawEntry(publicKey = public, privateKey = private))),
        ) shouldBe
            null
        decodeSecret(keysetOf(listOf(AEAD, AES), listOf(RawEntry(secret = secret)))) shouldBe null
    }
})
