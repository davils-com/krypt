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

import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.cose.cbor.Cbor
import com.davils.krypt.cose.cbor.CborArray
import com.davils.krypt.cose.cbor.CborBytes
import com.davils.krypt.cose.cbor.CborItem
import com.davils.krypt.cose.cbor.CborMap
import com.davils.krypt.cose.cbor.CborSimple
import com.davils.krypt.cose.cbor.CborTag
import com.davils.krypt.cose.cbor.CborText
import com.davils.krypt.cose.fixture.CONTENT
import com.davils.krypt.cose.fixture.cose
import com.davils.krypt.cose.fixture.crypto
import com.davils.krypt.cose.fixture.failure
import com.davils.krypt.cose.fixture.headers
import com.davils.krypt.cose.fixture.label
import com.davils.krypt.cose.fixture.protectedOf
import com.davils.krypt.cose.fixture.recipientItem
import com.davils.krypt.cose.fixture.tagged
import com.davils.krypt.cose.fixture.utf8
import com.davils.krypt.cose.fixture.value
import com.davils.krypt.cose.key.CoseKey
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString

private val EVERYTHING: Set<CoseAlgorithm> = CoseAlgorithm.entries.toSet()
private val A128GCM: CborMap = headers(1L to label(value = 1))
private val IV: CborMap = headers(5L to CborBytes(ByteString(ByteArray(12))))
private val EMPTY: CborBytes = CborBytes(ByteString())
private val PAYLOAD: CborBytes = CborBytes(utf8(CONTENT))
private val ONE: ByteString = ByteString(ByteArray(32) { index -> (index / 31).toByte() })

private fun encrypt(vararg recipients: CborItem, body: CborMap = A128GCM): ByteString =
    tagged(CoseMessageType.Encrypt, protectedOf(body), IV, PAYLOAD, CborArray(recipients.toList()))

class MessageHostileTest : FunSpec({
    test("structures of the wrong shape are refused") {
        val malformed = listOf(
            Cbor.encode(CborArray.of()),
            Cbor.encode(CborTag(number = 999UL, content = CborArray.of())),
            Cbor.encode(CborMap.Empty),
            tagged(CoseMessageType.Sign1, EMPTY, CborMap.Empty, PAYLOAD),
            tagged(CoseMessageType.Sign1, CborText("p"), CborMap.Empty, PAYLOAD, EMPTY),
            tagged(CoseMessageType.Sign1, EMPTY, CborArray.of(), PAYLOAD, EMPTY),
            tagged(CoseMessageType.Sign1, EMPTY, CborMap.Empty, CborSimple.True, EMPTY),
            tagged(CoseMessageType.Sign1, CborBytes(utf8("x")), CborMap.Empty, PAYLOAD, EMPTY),
            tagged(CoseMessageType.Sign1, CborBytes(Cbor.encode(CborArray.of())), CborMap.Empty, PAYLOAD, EMPTY),
            tagged(CoseMessageType.Sign, EMPTY, CborMap.Empty, PAYLOAD, CborArray.of()),
            tagged(CoseMessageType.Sign, EMPTY, CborMap.Empty, PAYLOAD, CborSimple.True),
            tagged(CoseMessageType.Sign, EMPTY, CborMap.Empty, PAYLOAD, CborArray.of(CborArray.of(EMPTY))),
            tagged(CoseMessageType.Sign, EMPTY, CborMap.Empty, PAYLOAD, CborArray.of(CborSimple.True)),
            tagged(CoseMessageType.Encrypt, EMPTY, IV, PAYLOAD, CborArray.of()),
            tagged(CoseMessageType.Encrypt, EMPTY, IV, PAYLOAD, CborArray.of(CborArray.of(EMPTY))),
            tagged(CoseMessageType.Encrypt, EMPTY, IV, PAYLOAD, CborArray.of(CborSimple.True)),
            tagged(CoseMessageType.Encrypt, EMPTY, IV, PAYLOAD, CborSimple.True),
            tagged(CoseMessageType.Mac, EMPTY, CborMap.Empty, PAYLOAD, EMPTY, CborArray.of()),
        )
        malformed.forEach { encoded -> cose.decode(encoded).failure() shouldBe CoseFailure.Malformed }
        cose.decodeSign1(tagged(CoseMessageType.Mac0, EMPTY, CborMap.Empty, PAYLOAD, EMPTY)).failure() shouldBe
            CoseFailure.Malformed
        cose.decodeSign1(Cbor.encode(CborSimple.True)).failure() shouldBe CoseFailure.Malformed
    }

    test("every type decodes tagged and untagged") {
        val secret = CoseKey.of(crypto.keys.generateSecret(16))
        val pair = crypto.keys.generate(KeyType.P256)
        val signer = CoseSigner(key = CoseKey.of(pair.privateKey), algorithm = CoseAlgorithm.Esp256)
        val direct = listOf(CoseRecipientSpec(key = secret, algorithm = CoseAlgorithm.Direct))
        val sign1 = cose.sign1(payload = utf8(CONTENT), signer = signer)
        val sign = cose.sign(payload = utf8(CONTENT), signers = listOf(signer))
        val mac0 = cose.mac0(
            payload = utf8(CONTENT),
            key = CoseKey.of(crypto.keys.generateSecret()),
            algorithm = CoseAlgorithm.Hmac256,
        )
        val mac = cose.mac(
            payload = utf8(CONTENT),
            algorithm = CoseAlgorithm.Hmac256,
            recipients = listOf(
                CoseRecipientSpec(key = CoseKey.of(crypto.keys.generateSecret()), algorithm = CoseAlgorithm.Direct),
            ),
        )
        val encrypt0 = cose.encrypt0(plaintext = utf8(CONTENT), key = secret, algorithm = CoseAlgorithm.A128Gcm)
        val encrypt = cose.encrypt(plaintext = utf8(CONTENT), algorithm = CoseAlgorithm.A128Gcm, recipients = direct)
        val messages = listOf(sign1, sign, mac0, mac, encrypt0, encrypt)
        messages.forEach { message ->
            cose.decode(message.encode()).value() shouldBe message
            cose.decode(message.encode(isTagged = false)).failure() shouldBe CoseFailure.Malformed
        }
        cose.decodeSign1(sign1.encode(isTagged = false)).value() shouldBe sign1
        cose.decodeSign(sign.encode(isTagged = false)).value() shouldBe sign
        cose.decodeMac0(mac0.encode(isTagged = false)).value() shouldBe mac0
        cose.decodeMac(mac.encode(isTagged = false)).value() shouldBe mac
        cose.decodeEncrypt0(encrypt0.encode(isTagged = false)).value() shouldBe encrypt0
        cose.decodeEncrypt(encrypt.encode(isTagged = false)).value() shouldBe encrypt
    }

    test("nested recipients are read within the limit") {
        val nested = recipientItem(
            protectedMap = CborMap.Empty,
            unprotectedMap = headers(1L to label(value = -6)),
            ciphertext = ByteString(),
        )
        val outer = CborArray.of(EMPTY, headers(1L to label(value = -3)), EMPTY, CborArray.of(nested))
        val message = cose.decodeEncrypt(encrypt(outer)).value()
        val layer = message.recipients.single()
        layer.recipients.size shouldBe 1
        val bounded = Cose(crypto = crypto, limits = CoseLimits(maximumRecipients = 1))
        bounded.decodeEncrypt(encrypt(outer)).failure() shouldBe CoseFailure.Malformed
        cose.decodeEncrypt(encrypt(CborArray.of(EMPTY, CborMap.Empty, EMPTY, CborArray.of()))).failure() shouldBe
            CoseFailure.Malformed
        cose.decodeEncrypt(encrypt(CborArray.of(EMPTY, CborMap.Empty, EMPTY, EMPTY, EMPTY))).failure() shouldBe
            CoseFailure.Malformed
        val signatures = Cose(crypto = crypto, limits = CoseLimits(maximumSignatures = 1))
        val signature = CborArray.of(EMPTY, CborMap.Empty, EMPTY)
        val twice = tagged(CoseMessageType.Sign, EMPTY, CborMap.Empty, PAYLOAD, CborArray.of(signature, signature))
        signatures.decodeSign(twice).failure() shouldBe CoseFailure.Malformed
        val decodedTwice = cose.decodeSign(twice).value()
        decodedTwice.signatures.size shouldBe 2
    }

    test("recipients that break the rules give no key") {
        val secret = CoseKey.of(crypto.keys.generateSecret(16), keyId = utf8("k"))
        val wrap = CoseKey.of(crypto.keys.generateSecret(16))
        val directProtected = recipientItem(
            protectedMap = headers(1L to label(value = -6)),
            unprotectedMap = CborMap.Empty,
            ciphertext = ByteString(),
        )
        val nilWrap = recipientItem(
            protectedMap = CborMap.Empty,
            unprotectedMap = headers(1L to label(value = -3)),
            ciphertext = null,
        )
        listOf(directProtected, nilWrap).forEach { recipient ->
            val message = cose.decodeEncrypt(encrypt(recipient)).value()
            val outcome1 = cose.decrypt(
                message = message,
                keys = listOf(secret, wrap),
                algorithms = EVERYTHING,
            )
            outcome1.failure() shouldBe CoseFailure.DecryptionFailed
        }
        val wide = cose.encrypt(
            plaintext = utf8(CONTENT),
            algorithm = CoseAlgorithm.A256Gcm,
            recipients = listOf(CoseRecipientSpec(key = wrap, algorithm = CoseAlgorithm.A128Kw)),
        )
        val reused = cose.decodeEncrypt(encrypt(recipientItem(recipient = wide.recipients.single()))).value()
        val outcome2 = cose.decrypt(
            message = reused,
            keys = listOf(wrap),
            algorithms = EVERYTHING,
        )
        outcome2.failure() shouldBe CoseFailure.DecryptionFailed
        val partial = tagged(
            CoseMessageType.Encrypt,
            protectedOf(A128GCM),
            headers(6L to CborBytes(utf8("p"))),
            PAYLOAD,
            CborArray.of(
                recipientItem(
                    protectedMap = CborMap.Empty,
                    unprotectedMap = headers(1L to label(value = -6)),
                    ciphertext = ByteString(),
                ),
            ),
        )
        val outcome3 = cose.decrypt(
            message = cose.decodeEncrypt(partial).value(),
            keys = listOf(secret),
            algorithms = EVERYTHING,
        )
        outcome3.failure() shouldBe
            CoseFailure.DecryptionFailed
    }

    test("agreement recipients need a fitting public ephemeral key") {
        val pair = crypto.keys.generate(KeyType.P256)
        val receiver = CoseKey.of(pair.privateKey)
        val spec = CoseRecipientSpec(key = CoseKey.of(pair.publicKey), algorithm = CoseAlgorithm.EcdhEsHkdf256)
        val created = cose.encrypt(
            plaintext = utf8(CONTENT),
            algorithm = CoseAlgorithm.A128Gcm,
            recipients = listOf(spec),
        )
        val recipient = created.recipients.single()
        val ephemeral = checkNotNull(recipient.unprotectedHeaders[-1L])
        val protectedAlgorithm = headers(1L to label(value = -25))
        val variants = listOf(
            CborMap.Empty,
            headers(-1L to headers(1L to label(value = 2))),
            headers(
                -1L to CborMap(checkNotNull(ephemeral.mapOrNull()).entries + (label(value = -4) to CborBytes(ONE))),
            ),
            headers(-1L to headers(1L to label(value = 2), -1L to label(value = 1), -4L to CborBytes(ONE))),
        )
        variants.forEach { unprotected ->
            val item = recipientItem(
                protectedMap = protectedAlgorithm,
                unprotectedMap = unprotected,
                ciphertext = ByteString(),
            )
            val message = cose.decodeEncrypt(encrypt(item, body = created.protectedHeaders.parameters)).value()
            val outcome4 = cose.decrypt(
                message = message,
                keys = listOf(receiver),
                algorithms = EVERYTHING,
            )
            outcome4.failure() shouldBe CoseFailure.DecryptionFailed
        }
        val moved = recipientItem(
            protectedMap = CborMap(protectedAlgorithm.entries + (label(value = -1) to ephemeral)),
            unprotectedMap = CborMap.Empty,
            ciphertext = ByteString(),
        )
        val movedMessage = cose.decodeEncrypt(encrypt(moved, body = created.protectedHeaders.parameters)).value()
        val outcome5 = cose.decrypt(
            message = movedMessage,
            keys = listOf(receiver),
            algorithms = EVERYTHING,
        )
        outcome5.failure() shouldBe CoseFailure.DecryptionFailed
        cose.decrypt(message = created, keys = listOf(receiver), algorithms = EVERYTHING).value() shouldBe utf8(CONTENT)
        val other = CoseKey.of(crypto.keys.generate(KeyType.P384).privateKey)
        val outcome6 = cose.decrypt(
            message = created,
            keys = listOf(other),
            algorithms = EVERYTHING,
        )
        outcome6.failure() shouldBe CoseFailure.DecryptionFailed
    }

    test("a recipient with a crit nobody understands is skipped") {
        val pair = crypto.keys.generate(KeyType.X25519)
        val critical = CoseHeaders.of(
            critical = listOf(label(value = -65_537)),
            parameters = CborMap.of(label(value = -65_537) to CborSimple.True),
        )
        val spec = CoseRecipientSpec(
            key = CoseKey.of(pair.publicKey, keyId = utf8("x")),
            algorithm = CoseAlgorithm.EcdhEsA128Kw,
            protectedHeaders = critical,
        )
        val message = cose.encrypt(
            plaintext = utf8(CONTENT),
            algorithm = CoseAlgorithm.A128Gcm,
            recipients = listOf(spec),
        )
        val receiver = CoseKey.of(pair.privateKey, keyId = utf8("x"))
        val outcome7 = cose.decrypt(
            message = message,
            keys = listOf(receiver),
            algorithms = EVERYTHING,
        )
        outcome7.failure() shouldBe CoseFailure.DecryptionFailed
        val understanding = Cose(crypto = crypto, criticalLabels = setOf(label(value = -65_537)))
        val outcome8 = understanding.decrypt(
            message = message,
            keys = listOf(receiver),
            algorithms = EVERYTHING,
        )
        outcome8.value() shouldBe utf8(CONTENT)
        val absent = CoseRecipientSpec(
            key = CoseKey.of(pair.publicKey, keyId = utf8("x")),
            algorithm = CoseAlgorithm.EcdhEsA128Kw,
            protectedHeaders = CoseHeaders.of(critical = listOf(label(value = 4))),
        )
        val absentMessage = cose.encrypt(
            plaintext = utf8(CONTENT),
            algorithm = CoseAlgorithm.A128Gcm,
            recipients = listOf(absent),
        )
        val outcome9 = cose.decrypt(
            message = absentMessage,
            keys = listOf(receiver),
            algorithms = EVERYTHING,
        )
        outcome9.failure() shouldBe CoseFailure.DecryptionFailed
    }

    test("payloads are either attached or detached") {
        val secret = CoseKey.of(crypto.keys.generateSecret())
        val message = cose.mac0(payload = utf8(CONTENT), key = secret, algorithm = CoseAlgorithm.Hmac256)
        val outcome10 = cose.verify(
            message = message,
            keys = listOf(secret),
            algorithms = EVERYTHING,
            detachedPayload = utf8(CONTENT),
        )
        outcome10.failure() shouldBe
            CoseFailure.Malformed
    }
})
