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
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.algorithm.AeadAlgorithm
import com.davils.krypt.core.algorithm.KdfAlgorithm
import com.davils.krypt.core.algorithm.KemAlgorithm
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.primitive.fixture.RfcKeys
import com.davils.krypt.primitive.fixture.crypto
import com.davils.krypt.primitive.fixture.hex
import com.davils.krypt.primitive.fixture.hexOf
import com.davils.krypt.primitive.fixture.utf8
import com.davils.krypt.primitive.internal.Dhkem
import com.davils.krypt.primitive.key.KeyPair
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import kotlinx.io.bytestring.ByteString

private const val MESSAGE: String = "a hybrid message"
private const val EXPORT_LENGTH: Int = 32
private const val PSK: String = "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82"

private suspend fun x25519(secret: String, public: String): KeyPair {
    val encoding = SecretBytes.copyOf(hex(RfcKeys.X25519_PKCS8_PREFIX + secret))
    val privateKey = crypto.keys.decodePrivate(encoding).getOrNull()
    val publicKey = crypto.keys.decodePublic(hex(RfcKeys.X25519_SPKI_PREFIX + public)).getOrNull()
    return checkNotNull(crypto.keys.pair(privateKey = checkNotNull(privateKey), publicKey = checkNotNull(publicKey)))
}

class ExchangeTest : FunSpec({
    test("X25519 matches RFC 7748 section 6.1") {
        val alice = x25519(secret = RfcKeys.X25519_ALICE_SECRET, public = RfcKeys.X25519_ALICE_PUBLIC)
        val bob = x25519(secret = RfcKeys.X25519_BOB_SECRET, public = RfcKeys.X25519_BOB_PUBLIC)
        hexOf(crypto.agreements.agree(alice.privateKey, bob.publicKey)) shouldBe RfcKeys.X25519_SHARED
        hexOf(crypto.agreements.agree(bob.privateKey, alice.publicKey)) shouldBe RfcKeys.X25519_SHARED
    }

    test("ECDH agrees on the curves and refuses mixed keys") {
        val first = crypto.keys.generate(KeyType.P384)
        val second = crypto.keys.generate(KeyType.P384)
        crypto.agreements.agree(
            first.privateKey,
            second.publicKey,
        ) shouldBe crypto.agreements.agree(second.privateKey, first.publicKey)
        val other = crypto.keys.generate(KeyType.P256)
        shouldThrow<IllegalArgumentException> { crypto.agreements.agree(first.privateKey, other.publicKey) }
        val signing = crypto.keys.generate(KeyType.Ed25519)
        shouldThrow<IllegalArgumentException> { crypto.agreements.agree(signing.privateKey, signing.publicKey) }
    }

    test("HPKE matches RFC 9180 appendix A.1.1") {
        val suite = HpkeSuite(KemAlgorithm.DhkemX25519, KdfAlgorithm.HkdfSha256, AeadAlgorithm.Aes128Gcm)
        val ephemeral = x25519(secret = RfcKeys.HPKE_EPHEMERAL_SECRET, public = RfcKeys.HPKE_EPHEMERAL_PUBLIC)
        val recipient = x25519(secret = RfcKeys.HPKE_RECIPIENT_SECRET, public = RfcKeys.HPKE_RECIPIENT_PUBLIC)
        val sender = crypto.hpke.senderWith(
            suite = suite,
            recipient = recipient.publicKey,
            info = hex(RfcKeys.HPKE_INFO),
            sender = null,
            psk = null,
            pskId = ByteString(),
            ephemeral = ephemeral,
        )
        hexOf(sender.encapsulated) shouldBe RfcKeys.HPKE_EPHEMERAL_PUBLIC
        val ciphertext = sender.context.seal(
            plaintext = hex(RfcKeys.HPKE_PLAINTEXT),
            associatedData = hex(RfcKeys.HPKE_AAD),
        )
        hexOf(ciphertext) shouldBe RfcKeys.HPKE_CIPHERTEXT
        hexOf(
            sender.context.export(exporterContext = ByteString(), length = EXPORT_LENGTH),
        ) shouldBe RfcKeys.HPKE_EXPORTED
        val receiver = checkNotNull(
            crypto.hpke.recipient(
                suite = suite,
                recipient = recipient.privateKey,
                encapsulated = sender.encapsulated,
                info = hex(RfcKeys.HPKE_INFO),
            ),
        )
        receiver.open(
            ciphertext = ciphertext,
            associatedData = hex(RfcKeys.HPKE_AAD),
        ) shouldBe hex(RfcKeys.HPKE_PLAINTEXT)
        receiver.open(ciphertext = ciphertext, associatedData = hex(RfcKeys.HPKE_AAD)) shouldBe null
        receiver.toString() shouldContain "sequence=1"
    }

    context("every HPKE mode and suite round-trips") {
        withData(listOf(HpkeSuite.X25519Aes256Gcm, HpkeSuite.P384Aes256Gcm)) { suite ->
            val recipient = crypto.keys.generate(Dhkem.keyTypeOf(suite.kem))
            val sender = crypto.keys.generate(Dhkem.keyTypeOf(suite.kem))
            val psk = SecretBytes.copyOf(hex(PSK))
            val setup = crypto.hpke.sender(
                suite = suite,
                recipient = recipient.publicKey,
                sender = sender.privateKey,
                psk = psk,
                pskId = utf8("id"),
            )
            val ciphertext = setup.context.seal(utf8(MESSAGE))
            val receiver = crypto.hpke.recipient(
                suite = suite,
                recipient = recipient.privateKey,
                encapsulated = setup.encapsulated,
                sender = sender.publicKey,
                psk = psk,
                pskId = utf8("id"),
            )
            receiver?.open(ciphertext) shouldBe utf8(MESSAGE)
            val sealed = crypto.hpke.seal(suite = suite, recipient = recipient.publicKey, plaintext = utf8(MESSAGE))
            crypto.hpke.open(suite = suite, recipient = recipient.privateKey, sealed = sealed) shouldBe utf8(MESSAGE)
            crypto.hpke.open(
                suite = suite,
                recipient = recipient.privateKey,
                sealed = ByteString(ByteArray(1)),
            ) shouldBe null
        }
    }

    test("an export-only suite exports and refuses to seal") {
        val suite = HpkeSuite(KemAlgorithm.DhkemX25519, KdfAlgorithm.HkdfSha256, aead = null)
        val recipient = crypto.keys.generate(KeyType.X25519)
        val setup = crypto.hpke.sender(suite = suite, recipient = recipient.publicKey)
        val receiver = checkNotNull(
            crypto.hpke.recipient(suite = suite, recipient = recipient.privateKey, encapsulated = setup.encapsulated),
        )
        setup.context.export(utf8("ctx"), EXPORT_LENGTH) shouldBe receiver.export(utf8("ctx"), EXPORT_LENGTH)
        shouldThrow<IllegalStateException> { setup.context.seal(utf8(MESSAGE)) }
        shouldThrow<IllegalStateException> { receiver.open(utf8(MESSAGE)) }
        shouldThrow<IllegalArgumentException> {
            crypto.hpke.seal(
                suite = suite,
                recipient = recipient.publicKey,
                plaintext = utf8(MESSAGE),
            )
        }
        shouldThrow<IllegalArgumentException> {
            crypto.hpke.open(
                suite = suite,
                recipient = recipient.privateKey,
                sealed = utf8(MESSAGE),
            )
        }
        suite.toString() shouldContain "export only"
        setup.toString() shouldContain "encapsulated=32"
        setup.context.destroy()
    }

    test("HPKE refuses a short or unpaired pre-shared key and a malformed encapsulation") {
        val recipient = crypto.keys.generate(KeyType.X25519)
        shouldThrow<IllegalArgumentException> {
            crypto.hpke.sender(
                suite = HpkeSuite.X25519Aes256Gcm,
                recipient = recipient.publicKey,
                psk = SecretBytes.copyOf(hex("00")),
                pskId = utf8("id"),
            )
        }
        shouldThrow<IllegalArgumentException> {
            crypto.hpke.sender(suite = HpkeSuite.X25519Aes256Gcm, recipient = recipient.publicKey, pskId = utf8("id"))
        }
        crypto.hpke.recipient(
            suite = HpkeSuite.X25519Aes256Gcm,
            recipient = recipient.privateKey,
            encapsulated = utf8("short"),
        ) shouldBe null
        shouldThrow<IllegalArgumentException> {
            HpkeSuite(
                KemAlgorithm.DhkemX25519,
                KdfAlgorithm.Pbkdf2Sha256,
                AeadAlgorithm.Aes256Gcm,
            )
        }
        HpkeSuite.X25519Aes256Gcm shouldNotBe HpkeSuite.P384Aes256Gcm
        HpkeSuite.X25519Aes256Gcm.hashCode() shouldBe HpkeSuite(
            KemAlgorithm.DhkemX25519,
            KdfAlgorithm.HkdfSha256,
            AeadAlgorithm.Aes256Gcm,
        ).hashCode()
    }

    test("a KEM encapsulates a secret only the recipient decapsulates") {
        val recipient = crypto.keys.generate(KeyType.P256)
        val encapsulation = crypto.kems.encapsulate(recipient.publicKey)
        crypto.kems.decapsulate(
            recipient.privateKey,
            encapsulation.encapsulated,
            KemAlgorithm.DhkemP256,
        ) shouldBe encapsulation.sharedSecret
        encapsulation.toString() shouldContain "secret=32"
        shouldThrow<IllegalArgumentException> { crypto.kems.encapsulate(recipient.publicKey, KemAlgorithm.DhkemX25519) }
        shouldThrow<IllegalArgumentException> {
            crypto.kems.decapsulate(
                recipient.privateKey,
                encapsulation.encapsulated,
                KemAlgorithm.DhkemX25519,
            )
        }
        shouldThrow<IllegalArgumentException> {
            crypto.kems.defaultFor(
                crypto.keys.generate(KeyType.Ed25519).publicKey,
            )
        }
    }

    test("ML-KEM works where the platform has it") {
        val types = listOf(KeyType.MlKem768, KeyType.MlKem1024)
        types.filter { type -> crypto.capabilities.supports(type) }.forEach { type ->
            val recipient = crypto.keys.generate(type)
            val algorithm = crypto.kems.defaultFor(recipient.publicKey)
            val encapsulation = crypto.kems.encapsulate(recipient.publicKey)
            crypto.kems.decapsulate(
                recipient.privateKey,
                encapsulation.encapsulated,
                algorithm,
            ) shouldBe encapsulation.sharedSecret
            val suite = HpkeSuite(algorithm, KdfAlgorithm.HkdfSha256, AeadAlgorithm.Aes256Gcm)
            val sealed = crypto.hpke.seal(suite = suite, recipient = recipient.publicKey, plaintext = utf8(MESSAGE))
            crypto.hpke.open(suite = suite, recipient = recipient.privateKey, sealed = sealed) shouldBe utf8(MESSAGE)
        }
    }
})
