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

package com.davils.krypt.primitive

import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.asn1.BitString
import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.asn1.DerWriter
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.Tag
import com.davils.krypt.asn1.pem.Pem
import com.davils.krypt.asn1.readRemaining
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.SecretText
import com.davils.krypt.core.algorithm.AeadAlgorithm
import com.davils.krypt.core.algorithm.KdfAlgorithm
import com.davils.krypt.core.algorithm.KemAlgorithm
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.primitive.exchange.HpkeSuite
import com.davils.krypt.primitive.fixture.RfcKeys
import com.davils.krypt.primitive.fixture.crypto
import com.davils.krypt.primitive.fixture.fastCrypto
import com.davils.krypt.primitive.fixture.hex
import com.davils.krypt.primitive.fixture.utf8
import com.davils.krypt.primitive.key.KeyFailure
import com.davils.krypt.primitive.password.PasswordVerification
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.io.bytestring.ByteString

private const val PBES2: String = "1.2.840.113549.1.5.13"
private const val ED25519_OID: String = "1.3.101.112"
private const val EC_OID: String = "1.2.840.10045.2.1"
private const val PBKDF2: String = "1.2.840.113549.1.5.12"
private const val HMAC_SHA256: String = "1.2.840.113549.2.9"
private const val AES_256_CBC: String = "2.16.840.1.101.3.4.1.42"
private const val SALT: Int = 16
private const val IV: Int = 16
private const val SHORT: Int = 4
private const val AES_128_KEY: Long = 16
private const val ITERATIONS: Long = 1_000
private const val MESSAGE: String = "edge"
private const val PASSWORD: String = "password"
private const val SALT_B64: String = "AAAAAAAAAAAAAAAAAAAAAA"
private const val HASH_B64: String = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

private fun DerWriter.algorithm(oid: String, parameters: DerWriter.() -> Unit = {}) {
    sequence {
        objectIdentifier(ObjectIdentifier.of(oid))
        parameters()
    }
}

private fun encryptedKey(
    scheme: String = PBES2,
    kdf: String = PBKDF2,
    salt: Int = SALT,
    keyLength: Long? = null,
    prf: String? = HMAC_SHA256,
    cipher: String = AES_256_CBC,
    iv: Int = IV,
): ByteString = Der.encode {
    sequence {
        algorithm(scheme) {
            sequence {
                algorithm(kdf) {
                    sequence {
                        octetString(ByteString(ByteArray(salt)))
                        integer(ITERATIONS)
                        keyLength?.let { length -> integer(length) }
                        prf?.let { oid -> algorithm(oid) { nullValue() } }
                    }
                }
                algorithm(cipher) { octetString(ByteString(ByteArray(iv))) }
            }
        }
        octetString(ByteString(ByteArray(SALT)))
    }
}

private fun withUnusedOctet(bits: BitString): ByteString = ByteString(byteArrayOf(0) + bits.bytes.toByteArray())

private fun compressedOf(point: BitString): BitString {
    val bytes = point.bytes.toByteArray()
    bytes[0] = 2
    return BitString(ByteString(bytes))
}

class EdgeCasesTest : FunSpec({
    context("encrypted keys with a scheme krypt does not read are refused") {
        withData(
            nameFn = { (name, _) -> name },
            listOf(
                "not PBES2" to encryptedKey(scheme = PBKDF2),
                "not PBKDF2" to encryptedKey(kdf = PBES2),
                "a short salt" to encryptedKey(salt = SHORT),
                "the SHA-1 default" to encryptedKey(prf = null),
                "an unknown PRF" to encryptedKey(prf = PBES2),
                "an unknown cipher" to encryptedKey(cipher = PBES2),
                "a short IV" to encryptedKey(iv = SHORT),
                "a mismatched key length" to encryptedKey(keyLength = AES_128_KEY),
            ),
        ) { (_, encoded) ->
            val decrypted = fastCrypto.keys.decrypt(encoded, SecretText.of(PASSWORD))
            decrypted.failureOrNull() shouldBe KeyFailure.UnsupportedEncryption
        }
        val wellFormed = fastCrypto.keys.decrypt(encryptedKey(keyLength = SALT.toLong() * 2), SecretText.of(PASSWORD))
        wellFormed.failureOrNull() shouldBe KeyFailure.WrongPassword
    }

    test("ECDSA signatures with negative or oversized integers are invalid") {
        val pair = crypto.keys.generate(KeyType.P256)
        val negative = Der.encode {
            sequence {
                integer(-1L)
                integer(1L)
            }
        }
        val oversized = Der.encode {
            sequence {
                integer(DerInteger.ofMagnitude(ByteString(ByteArray(SALT * 3) { 1 })))
                integer(1L)
            }
        }
        listOf(negative, oversized, utf8(MESSAGE)).forEach { signature ->
            crypto.signatures.verify(
                key = pair.publicKey,
                data = utf8(MESSAGE),
                signature = signature,
            ) shouldBe Verification.Invalid
        }
    }

    test("public keys with a malformed point or parameters are refused") {
        val pair = crypto.keys.generate(KeyType.P256)
        val point = Der.decodeOrNull(pair.publicKey.encoded) {
            readSequence {
                readElement()
                readBitString()
            }
        }
        val compressed = Der.encode {
            sequence {
                algorithm(EC_OID) { objectIdentifier(ObjectIdentifier.of("1.2.840.10045.3.1.7")) }
                bitString(compressedOf(checkNotNull(point)))
            }
        }
        crypto.keys.decodePublic(compressed).failureOrNull() shouldBe KeyFailure.Malformed
        val withParameters = Der.encode {
            sequence {
                algorithm(ED25519_OID) { nullValue() }
                bitString(BitString(ByteString(ByteArray(SALT * 2))))
            }
        }
        crypto.keys.decodePublic(withParameters).failureOrNull() shouldBe KeyFailure.UnsupportedAlgorithm
        val twoParameters = Der.encode {
            sequence {
                algorithm(ED25519_OID) {
                    nullValue()
                    nullValue()
                }
                bitString(BitString(ByteString(ByteArray(SALT * 2))))
            }
        }
        crypto.keys.decodePublic(twoParameters).failureOrNull() shouldBe KeyFailure.Malformed
        val ecWithNull = Der.encode {
            sequence {
                algorithm(EC_OID) { nullValue() }
                bitString(checkNotNull(point))
            }
        }
        crypto.keys.decodePublic(ecWithNull).failureOrNull() shouldBe KeyFailure.UnsupportedAlgorithm
    }

    test("a PKCS #8 version 2 key carries its public key") {
        val pair = crypto.keys.generate(KeyType.Ed25519)
        val seed = Der.decodeOrNull(crypto.keys.encodePrivate(pair.privateKey).reveal { bytes -> ByteString(bytes) }) {
            readSequence {
                readInteger()
                readElement()
                readOctetString().also { readRemaining() }
            }
        }
        val publicBits = Der.decodeOrNull(pair.publicKey.encoded) {
            readSequence {
                readElement()
                readBitString()
            }
        }
        val v2 = Der.encode {
            sequence {
                integer(1L)
                algorithm(ED25519_OID)
                octetString(checkNotNull(seed))
                element(
                    tag = Tag.context(number = 1, isConstructed = false),
                    content = withUnusedOctet(checkNotNull(publicBits)),
                )
            }
        }
        crypto.keys
            .decodePrivate(SecretBytes.copyOf(v2))
            .getOrNull()
            ?.publicKey shouldBe pair.publicKey
    }

    test("HPKE covers its remaining suites and refuses an authenticated ML-KEM") {
        val p521 = HpkeSuite(KemAlgorithm.DhkemP521, KdfAlgorithm.HkdfSha512, AeadAlgorithm.Aes256Gcm)
        val recipient = crypto.keys.generate(KeyType.P521)
        val sealed = crypto.hpke.seal(suite = p521, recipient = recipient.publicKey, plaintext = utf8(MESSAGE))
        crypto.hpke.open(suite = p521, recipient = recipient.privateKey, sealed = sealed) shouldBe utf8(MESSAGE)
        val p384 = crypto.keys.generate(KeyType.P384).privateKey
        shouldThrow<IllegalArgumentException> { crypto.hpke.open(suite = p521, recipient = p384, sealed = sealed) }
        val isChaCha = crypto.capabilities.supports(AeadAlgorithm.ChaCha20Poly1305)
        val chacha = HpkeSuite(
            KemAlgorithm.DhkemX25519,
            KdfAlgorithm.HkdfSha256,
            AeadAlgorithm.ChaCha20Poly1305,
        ).takeIf { isChaCha }
        val x25519 = crypto.keys.generate(KeyType.X25519)
        chacha?.let { suite ->
            val box = crypto.hpke.seal(suite = suite, recipient = x25519.publicKey, plaintext = utf8(MESSAGE))
            crypto.hpke.open(suite = suite, recipient = x25519.privateKey, sealed = box) shouldBe utf8(MESSAGE)
        }
        shouldThrow<IllegalArgumentException> {
            crypto.hpke.sender(
                suite = HpkeSuite.MlKem768Aes256Gcm,
                recipient = x25519.publicKey,
                sender = x25519.privateKey,
            )
        }
        HpkeSuite.MlKem768Aes256Gcm shouldNotBe HpkeSuite(KemAlgorithm.MlKem768, KdfAlgorithm.HkdfSha256, aead = null)
        HpkeSuite.X25519Aes256Gcm shouldNotBe HpkeSuite(
            KemAlgorithm.DhkemX25519,
            KdfAlgorithm.HkdfSha384,
            AeadAlgorithm.Aes256Gcm,
        )
        HpkeSuite.X25519Aes256Gcm.equals(MESSAGE) shouldBe false
    }

    context("stored password hashes with missing or inconsistent fields are malformed") {
        withData(
            listOf(
                "\$pbkdf2-sha256\$l=32\$$SALT_B64\$$HASH_B64",
                "\$pbkdf2-sha256\$i=1000\$$SALT_B64\$$HASH_B64",
                "\$pbkdf2-sha256\$i=1000,l=8\$$SALT_B64\$AAAAAAAAAAA",
                "\$pbkdf2-sha256\$i=1000,l=32\$$SALT_B64\$!!",
                "x\$pbkdf2-sha256\$i=1000,l=32\$$SALT_B64\$$HASH_B64",
            ),
        ) { encoded ->
            fastCrypto.passwords.verify(
                SecretText.of(PASSWORD),
                encoded,
            ) shouldBe PasswordVerification.Malformed
        }
    }

    test("a signer needs a known public key and digesters finish once") {
        val encoding = SecretBytes.copyOf(hex(RfcKeys.ED25519_PKCS8_PREFIX + RfcKeys.ED25519_SECRET))
        val ed25519 = crypto.keys.decodePrivate(encoding).getOrNull()
        shouldThrow<IllegalArgumentException> { crypto.signatures.signer(checkNotNull(ed25519)) }
        val digester = crypto.digests.digester()
        digester?.finish()
        digester?.let { finished -> shouldThrow<IllegalStateException> { finished.finish() } }
        digester?.let { finished -> shouldThrow<IllegalStateException> { finished.update(utf8(MESSAGE)) } }
        digester?.let { finished -> finished.toString() shouldBe "Digester(SHA-256, finished=true)" }
    }

    test("keys of different curves do not pair and a public PEM of another label is skipped") {
        val p256 = crypto.keys.generate(KeyType.P256)
        val p384 = crypto.keys.generate(KeyType.P384)
        shouldThrow<IllegalArgumentException> { crypto.keys.pair(p256.privateKey, p384.publicKey) }
        val text = Pem.encode(label = "CERTIFICATE", bytes = p256.publicKey.encoded)
        crypto.keys.decodePublicPem(text).failureOrNull() shouldBe KeyFailure.Malformed
        crypto.keys.decodePrivatePem(text).failureOrNull() shouldBe KeyFailure.Malformed
    }
})
