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
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.Tag
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.SecretText
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.primitive.exchange.HpkeSuite
import com.davils.krypt.primitive.fixture.RfcKeys
import com.davils.krypt.primitive.fixture.crypto
import com.davils.krypt.primitive.fixture.fastCrypto
import com.davils.krypt.primitive.fixture.hex
import com.davils.krypt.primitive.password.PasswordVerification
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.io.bytestring.ByteString

private const val RSA_OID: String = "1.2.840.113549.1.1.1"
private const val ED25519_OID: String = "1.3.101.112"
private const val SALT: String = "000102030405060708090a0b0c0d0e0f"
private const val FAST_ITERATIONS: Int = 1_000
private const val DERIVED_BYTES: Int = 32
private const val X25519_ENC: Int = 32
private const val P256_FIELD: Int = 32

private fun rsaPublicKey(modulus: DerInteger, exponent: DerInteger): ByteString = Der.encode {
    sequence {
        integer(modulus)
        integer(exponent)
    }
}

private fun rsaSpki(modulus: DerInteger, exponent: DerInteger): ByteString = Der.encode {
    sequence {
        sequence {
            objectIdentifier(ObjectIdentifier.of(RSA_OID))
            nullValue()
        }
        bitString(BitString(rsaPublicKey(modulus = modulus, exponent = exponent)))
    }
}

private fun rsaPkcs8(modulus: DerInteger): ByteString = Der.encode {
    sequence {
        integer(0L)
        sequence {
            objectIdentifier(ObjectIdentifier.of(RSA_OID))
            nullValue()
        }
        octetStringOf {
            sequence {
                integer(0L)
                integer(modulus)
                integer(DerInteger.of(65_537L))
                repeat(6) { integer(DerInteger.of(1L)) }
            }
        }
    }
}

private suspend fun derived(text: String): SecretBytes = fastCrypto.derivations.pbkdf2(
    password = SecretText.of(text),
    salt = hex(SALT),
    iterations = FAST_ITERATIONS,
    length = DERIVED_BYTES,
)

class AuditPrimitiveTest : FunSpec({
    test("A-3: an RSA public key with a negative modulus is a typed refusal, not an exception") {
        val spki = rsaSpki(modulus = DerInteger.of(-1L), exponent = DerInteger.of(65_537L))
        val outcome = shouldNotThrowAny { crypto.keys.decodePublic(spki) }
        outcome.failureOrNull() shouldNotBe null
    }

    test("A-3: an RSA private key with a negative modulus is a typed refusal, not an exception") {
        val encoding = SecretBytes.copyOf(rsaPkcs8(DerInteger.of(-1L)))
        val outcome = shouldNotThrowAny { crypto.keys.decodePrivate(encoding) }
        outcome.failureOrNull() shouldNotBe null
    }

    test("A-1: HPKE open with a small-order X25519 encapsulation returns null instead of throwing") {
        val recipient = crypto.keys.generate(KeyType.X25519)
        val sealed = ByteString(ByteArray(X25519_ENC) + ByteArray(X25519_ENC))
        val opened = shouldNotThrowAny {
            crypto.hpke.open(suite = HpkeSuite.X25519Aes256Gcm, recipient = recipient.privateKey, sealed = sealed)
        }
        opened shouldBe null
    }

    test("A-1: HPKE open with a P-256 encapsulation off the curve returns null instead of throwing") {
        val recipient = crypto.keys.generate(KeyType.P256)
        val coordinate = ByteArray(P256_FIELD).also { bytes -> bytes[P256_FIELD - 1] = 1 }
        val enc = byteArrayOf(4) + coordinate + coordinate
        val sealed = ByteString(enc + ByteArray(X25519_ENC))
        val suite = HpkeSuite(
            kem = com.davils.krypt.core.algorithm.KemAlgorithm.DhkemP256,
            kdf = com.davils.krypt.core.algorithm.KdfAlgorithm.HkdfSha256,
            aead = com.davils.krypt.core.algorithm.AeadAlgorithm.Aes128Gcm,
        )
        val opened = shouldNotThrowAny {
            crypto.hpke.open(suite = suite, recipient = recipient.privateKey, sealed = sealed)
        }
        opened shouldBe null
    }

    test("A-1: an X25519 agreement with a small-order peer key fails with a krypt failure, not a platform one") {
        val own = crypto.keys.generate(KeyType.X25519)
        val zero = crypto.keys.decodePublic(hex(RfcKeys.X25519_SPKI_PREFIX + "00".repeat(X25519_ENC))).getOrNull()
        val thrown = runCatching { crypto.agreements.agree(own.privateKey, checkNotNull(zero)) }.exceptionOrNull()
        (thrown == null || thrown is CryptoException) shouldBe true
    }

    test("A-6: a PKCS #8 key whose embedded public key does not belong to it is refused") {
        val wrongPublic = ByteArray(X25519_ENC) { index -> index.toByte() }
        val pkcs8 = Der.encode {
            sequence {
                integer(1L)
                sequence { objectIdentifier(ObjectIdentifier.of(ED25519_OID)) }
                octetString(hex("0420" + RfcKeys.ED25519_SECRET))
                element(tag = Tag.context(number = 1, isConstructed = false), content = ByteString(byteArrayOf(0) + wrongPublic))
            }
        }
        val key = crypto.keys.decodePrivate(SecretBytes.copyOf(pkcs8)).getOrNull()
        val genuine = hex(RfcKeys.ED25519_SPKI_PREFIX + RfcKeys.ED25519_PUBLIC)
        (key == null || key.publicKey?.encoded == genuine) shouldBe true
    }

    test("A-9: a stored password hash with a non-canonical iteration count is malformed") {
        val password = SecretText.of("correct horse")
        val stored = fastCrypto.passwords.hash(password)
        val padded = stored.replace("i=$FAST_ITERATIONS,", "i=0$FAST_ITERATIONS,")
        val signed = stored.replace("i=$FAST_ITERATIONS,", "i=+$FAST_ITERATIONS,")
        padded shouldNotBe stored
        fastCrypto.passwords.verify(password, padded) shouldBe PasswordVerification.Malformed
        fastCrypto.passwords.verify(password, signed) shouldBe PasswordVerification.Malformed
    }

    test("A-10: a password with a lone surrogate does not derive the key of a different password") {
        val lone = derived("pass\uD800word")
        lone shouldNotBe derived("pass?word")
        lone shouldNotBe derived("pass�word")
    }
})
