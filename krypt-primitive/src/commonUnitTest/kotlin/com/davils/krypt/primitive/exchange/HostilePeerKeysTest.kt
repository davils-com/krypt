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

package com.davils.krypt.primitive.exchange

import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.asn1.BitString
import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.core.algorithm.AeadAlgorithm
import com.davils.krypt.core.algorithm.KdfAlgorithm
import com.davils.krypt.core.algorithm.KemAlgorithm
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.primitive.CryptoException
import com.davils.krypt.primitive.Verification
import com.davils.krypt.primitive.fixture.RfcKeys
import com.davils.krypt.primitive.fixture.crypto
import com.davils.krypt.primitive.fixture.hex
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString

private const val X25519_BYTES: Int = 32
private const val P256_FIELD: Int = 32
private const val MODULUS_BYTES: Int = 512
private const val EXPONENT_BYTES: Int = 11

private val smallOrder: ByteString = ByteString(ByteArray(X25519_BYTES))

private val offCurve: ByteString = run {
    val coordinate = ByteArray(P256_FIELD).also { bytes -> bytes[P256_FIELD - 1] = 1 }
    ByteString(byteArrayOf(4) + coordinate + coordinate)
}

private val p256Suite: HpkeSuite = HpkeSuite(
    kem = KemAlgorithm.DhkemP256,
    kdf = KdfAlgorithm.HkdfSha256,
    aead = AeadAlgorithm.Aes128Gcm,
)

private fun largeExponentSpki(): ByteString {
    val modulus = ByteArray(MODULUS_BYTES) { 0x5A }.also { bytes ->
        bytes[0] = 0xC0.toByte()
        bytes[MODULUS_BYTES - 1] = 0x01
    }
    val exponent = ByteArray(EXPONENT_BYTES).also { bytes ->
        bytes[0] = 0x01
        bytes[EXPONENT_BYTES - 1] = 0x01
    }
    val publicKey = Der.encode {
        sequence {
            integer(DerInteger.ofMagnitude(ByteString(modulus)))
            integer(DerInteger.ofMagnitude(ByteString(exponent)))
        }
    }
    return Der.encode {
        sequence {
            sequence {
                objectIdentifier(ObjectIdentifier.of("1.2.840.113549.1.1.1"))
                nullValue()
            }
            bitString(BitString(publicKey))
        }
    }
}

class HostilePeerKeysTest : FunSpec({
    test("HPKE opens nothing from an X25519 encapsulation of small order, without an exception") {
        val recipient = crypto.keys.generate(KeyType.X25519)
        val sealed = ByteString(smallOrder.toByteArray() + ByteArray(X25519_BYTES))
        val suite = HpkeSuite.X25519Aes256Gcm
        crypto.hpke.open(suite = suite, recipient = recipient.privateKey, sealed = sealed).shouldBeNull()
        val context = crypto.hpke.recipient(
            suite = HpkeSuite.X25519Aes256Gcm,
            recipient = recipient.privateKey,
            encapsulated = smallOrder,
        )
        context.shouldBeNull()
        val secret = crypto.kems.decapsulate(
            recipient = recipient.privateKey,
            encapsulated = smallOrder,
            algorithm = KemAlgorithm.DhkemX25519,
        )
        secret.shouldBeNull()
    }

    test("HPKE opens nothing from a P-256 encapsulation off the curve, without an exception") {
        val recipient = crypto.keys.generate(KeyType.P256)
        val sealed = ByteString(offCurve.toByteArray() + ByteArray(X25519_BYTES))
        crypto.hpke.open(suite = p256Suite, recipient = recipient.privateKey, sealed = sealed).shouldBeNull()
    }

    test("an authenticated recipient opens nothing when the sender key is of small order") {
        val recipient = crypto.keys.generate(KeyType.X25519)
        val sender = crypto.keys.decodePublic(hex(RfcKeys.X25519_SPKI_PREFIX + "00".repeat(X25519_BYTES)))
        val setup = crypto.hpke.sender(suite = HpkeSuite.X25519Aes256Gcm, recipient = recipient.publicKey)
        val context = crypto.hpke.recipient(
            suite = HpkeSuite.X25519Aes256Gcm,
            recipient = recipient.privateKey,
            encapsulated = setup.encapsulated,
            sender = checkNotNull(sender.getOrNull()),
        )
        context.shouldBeNull()
    }

    test("an agreement with a peer key of small order fails as a krypt failure that hides the platform") {
        val own = crypto.keys.generate(KeyType.X25519)
        val zero = crypto.keys.decodePublic(hex(RfcKeys.X25519_SPKI_PREFIX + "00".repeat(X25519_BYTES)))
        val peer = checkNotNull(zero.getOrNull())
        val refused = shouldThrow<CryptoException> { crypto.agreements.agree(own.privateKey, peer) }
        refused.cause.shouldBeNull()
        refused.message shouldBe "The platform refused the key or the input"
        val stranger = crypto.keys.generate(KeyType.X25519)
        crypto.keys.pair(privateKey = own.privateKey, publicKey = peer).shouldBeNull()
        crypto.keys.pair(privateKey = own.privateKey, publicKey = stranger.publicKey).shouldBeNull()
    }

    test("a key that was read but that the platform refuses verifies nothing, without an exception") {
        val key = crypto.keys.decodePublic(largeExponentSpki()).getOrNull()
        key shouldNotBe null
        val verification = crypto.signatures.verify(
            key = checkNotNull(key),
            data = "message".encodeToByteString(),
            signature = ByteString(ByteArray(MODULUS_BYTES)),
            algorithm = SignatureAlgorithm.RsaPssSha256,
        )
        verification shouldBe Verification.Invalid
    }
})
