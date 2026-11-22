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

package com.davils.krypt.primitive.key

import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.asn1.BitString
import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerElement
import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.Tag
import com.davils.krypt.asn1.readRemaining
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.algorithm.EllipticCurve
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.primitive.exchange.HpkeSuite
import com.davils.krypt.primitive.fixture.OpenSslKeys
import com.davils.krypt.primitive.fixture.RfcKeys
import com.davils.krypt.primitive.fixture.crypto
import com.davils.krypt.primitive.fixture.hex
import com.davils.krypt.primitive.internal.KeyCodec
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString

private const val RAW_BYTES: Int = 32
private const val SHORT_BYTES: Int = 3
private const val X25519_OID: String = "1.3.101.110"
private const val SMALL_EXPONENT: Long = 3

private val malformed: Outcome<PrivateKey, KeyFailure> = Outcome.Failure(KeyFailure.Malformed)

private fun publicElement(bits: BitString): ByteString =
    Der.encode { element(tag = Tag.context(number = 1, isConstructed = false), content = bitStringContent(bits)) }

private fun bitStringContent(bits: BitString): ByteString {
    val encoded = Der.encode { bitString(bits) }
    return checkNotNull(Der.decodeOrNull(encoded) { readElement(Tag.BitString).content })
}

private fun withPublic(pkcs8: ByteString, publicBits: BitString): SecretBytes {
    val parts = checkNotNull(
        Der.decodeOrNull(pkcs8) {
            readSequence {
                readInteger()
                val algorithm = readElement(Tag.Sequence)
                val privateKey = readOctetString()
                readRemaining()
                algorithm to privateKey
            }
        },
    )
    val encoded = Der.encode {
        sequence {
            integer(1L)
            raw(parts.first.encoded)
            octetString(parts.second)
            raw(publicElement(publicBits))
        }
    }
    return SecretBytes.copyOf(encoded)
}

private fun sec1Of(pkcs8: ByteString): DerElement = checkNotNull(
    Der.decodeOrNull(pkcs8) {
        readSequence {
            readInteger()
            readElement(Tag.Sequence)
            val inner = readOctetString()
            checkNotNull(Der.decodeOrNull(inner) { readElement() })
        }
    },
)

private fun scalarOf(sec1: DerElement): ByteString = checkNotNull(
    Der.decodeOrNull(sec1.encoded) {
        readSequence {
            readInteger()
            val scalar = readOctetString()
            readRemaining()
            scalar
        }
    },
)

private fun ecPkcs8(curve: EllipticCurve, scalar: ByteString, publicBits: BitString?): SecretBytes {
    val sec1 = Der.encode {
        sequence {
            integer(1L)
            octetString(scalar)
        }
    }
    val encoded = Der.encode {
        sequence {
            integer(1L.takeIf { publicBits != null } ?: 0L)
            raw(KeyCodec.ecAlgorithm(curve))
            octetString(sec1)
            publicBits?.let { bits -> raw(publicElement(bits)) }
        }
    }
    return SecretBytes.copyOf(encoded)
}

private fun bitsOf(spki: ByteString): BitString = checkNotNull(
    Der.decodeOrNull(spki) {
        readSequence {
            readElement(Tag.Sequence)
            readBitString()
        }
    },
)

class EmbeddedPublicKeyTest : FunSpec({
    test("an Ed25519 key whose embedded public key belongs to another key is malformed") {
        val pkcs8 = hex(RfcKeys.ED25519_PKCS8_PREFIX + RfcKeys.ED25519_SECRET)
        val foreign = BitString(ByteString(ByteArray(RAW_BYTES) { index -> index.toByte() }))
        crypto.keys.decodePrivate(withPublic(pkcs8 = pkcs8, publicBits = foreign)) shouldBe malformed
        val genuine = BitString(hex(RfcKeys.ED25519_PUBLIC))
        val paired = crypto.keys.decodePrivate(withPublic(pkcs8 = pkcs8, publicBits = genuine)).getOrNull()
        paired?.publicKey?.encoded shouldBe hex(RfcKeys.ED25519_SPKI_PREFIX + RfcKeys.ED25519_PUBLIC)
    }

    test("an X25519 key without a public key derives it and can receive HPKE") {
        val pkcs8 = SecretBytes.copyOf(hex(RfcKeys.X25519_PKCS8_PREFIX + RfcKeys.X25519_ALICE_SECRET))
        val alice = checkNotNull(crypto.keys.decodePrivate(pkcs8).getOrNull())
        val expected = hex(RfcKeys.X25519_SPKI_PREFIX + RfcKeys.X25519_ALICE_PUBLIC)
        alice.publicKey?.encoded shouldBe expected
        val recipient = checkNotNull(crypto.keys.decodePublic(expected).getOrNull())
        val message = "for alice".encodeToByteString()
        val sealed = crypto.hpke.seal(suite = HpkeSuite.X25519Aes256Gcm, recipient = recipient, plaintext = message)
        crypto.hpke.open(suite = HpkeSuite.X25519Aes256Gcm, recipient = alice, sealed = sealed) shouldBe message
        val bob = BitString(hex(RfcKeys.X25519_BOB_PUBLIC))
        val raw = hex(RfcKeys.X25519_PKCS8_PREFIX + RfcKeys.X25519_ALICE_SECRET)
        crypto.keys.decodePrivate(withPublic(pkcs8 = raw, publicBits = bob)) shouldBe malformed
        val own = BitString(hex(RfcKeys.X25519_ALICE_PUBLIC))
        val paired = crypto.keys.decodePrivate(withPublic(pkcs8 = raw, publicBits = own))
        paired.getOrNull()?.publicKey shouldBe recipient
    }

    test("an X25519 key whose public key the platform cannot derive is malformed") {
        val short = Der.encode {
            sequence {
                integer(0L)
                sequence { objectIdentifier(ObjectIdentifier.of(X25519_OID)) }
                octetStringOf { octetString(ByteString(ByteArray(SHORT_BYTES))) }
            }
        }
        crypto.keys.decodePrivate(SecretBytes.copyOf(short)) shouldBe malformed
    }

    test("an EC key whose embedded public keys disagree or belong to another key is malformed") {
        val pkcs8 = hex(OpenSslKeys.EC_PKCS8)
        val stranger = crypto.keys.generate(KeyType.P256)
        val other = bitsOf(stranger.publicKey.encoded)
        crypto.keys.decodePrivate(withPublic(pkcs8 = pkcs8, publicBits = other)) shouldBe malformed
        val scalar = scalarOf(sec1Of(pkcs8))
        val bare = ecPkcs8(curve = EllipticCurve.P256, scalar = scalar, publicBits = null)
        val anonymous = crypto.keys.decodePrivate(bare)
        anonymous.getOrNull()?.publicKey shouldBe null
        val foreign = ecPkcs8(curve = EllipticCurve.P256, scalar = scalar, publicBits = other)
        crypto.keys.decodePrivate(foreign) shouldBe malformed
        val own = checkNotNull(crypto.keys.decodePublic(hex(OpenSslKeys.EC_SPKI)).getOrNull())
        val paired = ecPkcs8(curve = EllipticCurve.P256, scalar = scalar, publicBits = bitsOf(own.encoded))
        val decoded = crypto.keys.decodePrivate(paired)
        decoded.getOrNull()?.publicKey shouldBe own
    }

    test("an RSA key whose embedded public key differs from its modulus and exponent is malformed") {
        val pkcs8 = KeyCodec.pkcs8Of(algorithm = KeyCodec.rsaAlgorithm(), privateKey = hex(OpenSslKeys.RSA_PKCS1))
        val modulus = checkNotNull(
            Der.decodeOrNull(hex(OpenSslKeys.RSA_PKCS1)) {
                readSequence {
                    readInteger()
                    val found = readInteger()
                    readRemaining()
                    found
                }
            },
        )
        val small = KeyCodec.rsaPublicBits(modulus = modulus, exponent = DerInteger.of(SMALL_EXPONENT))
        crypto.keys.decodePrivate(withPublic(pkcs8 = pkcs8, publicBits = small)) shouldBe malformed
        val garbage = BitString(ByteString(ByteArray(RAW_BYTES)))
        crypto.keys.decodePrivate(withPublic(pkcs8 = pkcs8, publicBits = garbage)) shouldBe malformed
    }
})
