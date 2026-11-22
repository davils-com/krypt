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
import com.davils.krypt.cose.cbor.CborArray
import com.davils.krypt.cose.cbor.CborBytes
import com.davils.krypt.cose.cbor.CborMap
import com.davils.krypt.cose.cbor.CborSimple
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
import com.davils.krypt.cose.internal.sure
import com.davils.krypt.cose.key.CoseKey
import com.davils.krypt.cose.key.CoseKeyOperation
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString

private const val IV: Long = 5
private const val PARTIAL_IV: Long = 6
private const val NONCE: Long = -25
private val EVERYTHING: Set<CoseAlgorithm> = CoseAlgorithm.entries.toSet()
private val TWELVE: ByteString = ByteString(ByteArray(12))
private val A128GCM: CborMap = headers(1L to label(value = 1))

private fun ivHeaders(vararg entries: Pair<Long, ByteString>): CoseHeaders =
    CoseHeaders.of(CborMap(entries.map { (key, value) -> label(key) to CborBytes(value) }))

class EdgeCasesTest : FunSpec({
    test("IVs and Partial IVs are read from either bucket and checked") {
        val base = TWELVE
        val secret = CoseKey.of(crypto.keys.generateSecret(16), baseIv = base)
        val plain = CoseKey.of(secret.secretKey.sure())
        listOf(
            ivHeaders(IV to TWELVE) to CoseHeaders.Empty,
            CoseHeaders.Empty to ivHeaders(IV to TWELVE),
            ivHeaders(PARTIAL_IV to utf8("p")) to CoseHeaders.Empty,
        ).forEach { (protectedHeaders, unprotectedHeaders) ->
            val message = cose.encrypt0(
                plaintext = utf8(CONTENT),
                key = secret,
                algorithm = CoseAlgorithm.A128Gcm,
                protectedHeaders = protectedHeaders,
                unprotectedHeaders = unprotectedHeaders,
            )
            val outcome1 = cose.decrypt(
                message = message,
                keys = listOf(secret),
                algorithms = EVERYTHING,
            )
            outcome1.value() shouldBe utf8(CONTENT)
        }
        val withIv = cose.encrypt0(plaintext = utf8(CONTENT), key = plain, algorithm = CoseAlgorithm.A128Gcm)
        cose.decrypt(message = withIv, keys = listOf(secret), algorithms = EVERYTHING).value() shouldBe utf8(CONTENT)
        val shortBase = CoseKey.of(secret.secretKey.sure(), baseIv = utf8("short"))
        val partial = cose.encrypt0(
            plaintext = utf8(CONTENT),
            key = secret,
            algorithm = CoseAlgorithm.A128Gcm,
            unprotectedHeaders = ivHeaders(PARTIAL_IV to utf8("p")),
        )
        val outcome2 = cose.decrypt(
            message = partial,
            keys = listOf(shortBase, plain),
            algorithms = EVERYTHING,
        )
        outcome2.failure() shouldBe CoseFailure.DecryptionFailed
        val asymmetric = CoseKey.of(crypto.keys.generate(KeyType.P256).publicKey)
        val outcome3 = cose.decrypt(
            message = withIv,
            keys = listOf(asymmetric),
            algorithms = EVERYTHING,
        )
        outcome3.failure() shouldBe CoseFailure.DecryptionFailed
        val wrong = listOf(
            headers(IV to CborBytes(utf8("short"))) to CborMap.Empty,
            CborMap.Empty to CborMap.Empty,
            headers(IV to CborBytes(TWELVE)) to headers(PARTIAL_IV to CborBytes(utf8("p"))),
            CborMap.Empty to headers(PARTIAL_IV to CborBytes(ByteString(ByteArray(13)))),
        )
        wrong.forEach { (protectedMap, unprotectedMap) ->
            val body = CborMap(A128GCM.entries + protectedMap.entries)
            val encoded = tagged(CoseMessageType.Encrypt0, protectedOf(body), unprotectedMap, CborBytes(utf8(CONTENT)))
            val outcome4 = cose.decrypt(
                message = cose.decodeEncrypt0(encoded).value(),
                keys = listOf(secret),
                algorithms = EVERYTHING,
            )
            outcome4.failure() shouldBe
                CoseFailure.Malformed
        }
        shouldThrow<IllegalArgumentException> {
            cose.encrypt0(
                plaintext = utf8(CONTENT),
                key = shortBase,
                algorithm = CoseAlgorithm.A128Gcm,
                unprotectedHeaders = ivHeaders(PARTIAL_IV to utf8("p")),
            )
        }
    }

    test("headers refuse IVs and nonces of the wrong type") {
        listOf(
            headers(IV to CborText("iv")),
            headers(PARTIAL_IV to CborText("iv")),
            headers(NONCE to CborText("nonce")),
        ).forEach { parameters -> shouldThrow<IllegalArgumentException> { CoseHeaders.of(parameters) } }
        CoseHeaders.of(headers(NONCE to CborBytes(utf8("nonce")))).isEmpty shouldBe false
    }

    test("algorithms in headers must agree with the signer and fit the layer") {
        val pair = crypto.keys.generate(KeyType.P256)
        val key = CoseKey.of(pair.privateKey, keyId = utf8("kid"))
        shouldThrow<IllegalArgumentException> {
            cose.sign1(
                payload = utf8(CONTENT),
                signer = CoseSigner(
                    key = key,
                    algorithm = CoseAlgorithm.Esp256,
                    protectedHeaders = CoseHeaders.of(headers(1L to CborText("x"))),
                ),
            )
        }
        val given = cose.sign1(
            payload = utf8(CONTENT),
            signer = CoseSigner(
                key = key,
                algorithm = CoseAlgorithm.Esp256,
                unprotectedHeaders = CoseHeaders.of(keyId = utf8("given")),
            ),
        )
        given.unprotectedHeaders.keyId shouldBe utf8("given")
        val content = tagged(
            CoseMessageType.Sign1,
            protectedOf(A128GCM),
            CborMap.Empty,
            CborBytes(utf8(CONTENT)),
            CborBytes(ByteString()),
        )
        val verifier = CoseKey.of(pair.publicKey)
        val outcome5 = cose.verify(
            message = cose.decodeSign1(content).value(),
            keys = listOf(verifier),
            algorithms = EVERYTHING,
        )
        outcome5.failure() shouldBe
            CoseFailure.AlgorithmNotPermitted
        val text = tagged(
            CoseMessageType.Sign1,
            protectedOf(headers(1L to CborText("ES256"))),
            CborMap.Empty,
            CborBytes(utf8(CONTENT)),
            CborBytes(ByteString()),
        )
        val outcome6 = cose.verify(
            message = cose.decodeSign1(text).value(),
            keys = listOf(verifier),
            algorithms = EVERYTHING,
        )
        outcome6.failure() shouldBe
            CoseFailure.AlgorithmNotPermitted
    }

    test("keys are chosen only for what they may do") {
        val pair = crypto.keys.generate(KeyType.P256)
        val message = cose.sign1(
            payload = utf8(CONTENT),
            signer = CoseSigner(key = CoseKey.of(pair.privateKey), algorithm = CoseAlgorithm.Esp256),
        )
        val privateOnly = CoseKey.of(pair.privateKey, publicKey = null)
        val restricted = CoseKey.of(pair.publicKey, algorithm = CoseAlgorithm.Es256)
        val signOnly = CoseKey.of(pair.publicKey, operations = setOf(CoseKeyOperation.Sign))
        val secret = CoseKey.of(crypto.keys.generateSecret())
        listOf(privateOnly, restricted, signOnly, secret).forEach { key ->
            val outcome7 = cose.verify(
                message = message,
                keys = listOf(key),
                algorithms = EVERYTHING,
            )
            outcome7.failure() shouldBe CoseFailure.KeyNotFound
        }
        val verifyOnly = CoseKey.of(pair.publicKey, operations = setOf(CoseKeyOperation.Verify, CoseKeyOperation.Sign))
        val outcome8 = cose.verify(
            message = message,
            keys = listOf(verifyOnly),
            algorithms = EVERYTHING,
        )
        outcome8.value() shouldBe utf8(CONTENT)
        shouldThrow<IllegalArgumentException> { CoseKey.of(pair.publicKey, algorithm = CoseAlgorithm.Ps256) }
        val mac = cose.mac0(payload = utf8(CONTENT), key = secret, algorithm = CoseAlgorithm.Hmac256)
        val outcome9 = cose.verify(
            message = mac,
            keys = listOf(CoseKey.of(pair.publicKey)),
            algorithms = EVERYTHING,
        )
        outcome9.failure() shouldBe CoseFailure.KeyNotFound
        val otherAlgorithm = CoseKey.of(secret.secretKey.sure(), algorithm = CoseAlgorithm.Hmac512)
        val outcome10 = cose.verify(
            message = mac,
            keys = listOf(otherAlgorithm),
            algorithms = EVERYTHING,
        )
        outcome10.failure() shouldBe CoseFailure.KeyNotFound
        shouldThrow<IllegalArgumentException> {
            CoseRecipientSpec(
                key = CoseKey.of(pair.publicKey, algorithm = CoseAlgorithm.EcdhEsHkdf512),
                algorithm = CoseAlgorithm.EcdhEsHkdf256,
            )
        }
    }

    test("recipients without a fitting key or algorithm give none") {
        val small = CoseKey.of(crypto.keys.generateSecret(16), keyId = utf8("w"))
        val large = CoseKey.of(crypto.keys.generateSecret(32), keyId = utf8("w"))
        val wrapped = cose.encrypt(
            plaintext = utf8(CONTENT),
            algorithm = CoseAlgorithm.A128Gcm,
            recipients = listOf(CoseRecipientSpec(key = small, algorithm = CoseAlgorithm.A128Kw)),
        )
        val outcome11 = cose.decrypt(
            message = wrapped,
            keys = listOf(large),
            algorithms = EVERYTHING,
        )
        outcome11.failure() shouldBe CoseFailure.DecryptionFailed
        val direct = cose.encrypt(
            plaintext = utf8(CONTENT),
            algorithm = CoseAlgorithm.A128Gcm,
            recipients = listOf(CoseRecipientSpec(key = small, algorithm = CoseAlgorithm.Direct)),
        )
        val outcome12 = cose.decrypt(
            message = direct,
            keys = listOf(large),
            algorithms = EVERYTHING,
        )
        outcome12.failure() shouldBe CoseFailure.DecryptionFailed
        val contentKey = CoseKey.of(checkNotNull(small.secretKey), keyId = utf8("w"), algorithm = CoseAlgorithm.A128Gcm)
        val outcome13 = cose.decrypt(
            message = direct,
            keys = listOf(contentKey),
            algorithms = EVERYTHING,
        )
        outcome13.value() shouldBe utf8(CONTENT)
        val pair = crypto.keys.generate(KeyType.P256)
        val agreed = cose.encrypt(
            plaintext = utf8(CONTENT),
            algorithm = CoseAlgorithm.A128Gcm,
            recipients = listOf(
                CoseRecipientSpec(key = CoseKey.of(pair.publicKey), algorithm = CoseAlgorithm.EcdhEsA128Kw),
            ),
        )
        val outcome14 = cose.decrypt(
            message = agreed,
            keys = listOf(small, CoseKey.of(pair.publicKey)),
            algorithms = EVERYTHING,
        )
        outcome14.failure() shouldBe
            CoseFailure.DecryptionFailed
        val recipient = agreed.recipients.single()
        val nil = recipientItem(
            protectedMap = recipient.protectedHeaders.parameters,
            unprotectedMap = recipient.unprotectedHeaders.parameters,
            ciphertext = null,
        )
        val body = protectedOf(agreed.protectedHeaders.parameters)
        val encoded = tagged(
            CoseMessageType.Encrypt,
            body,
            agreed.unprotectedHeaders.parameters,
            CborBytes(agreed.ciphertext.sure()),
            CborArray.of(nil),
        )
        val outcome15 = cose.decrypt(
            message = cose.decodeEncrypt(encoded).value(),
            keys = listOf(CoseKey.of(pair.privateKey)),
            algorithms = EVERYTHING,
        )
        outcome15.failure() shouldBe CoseFailure.DecryptionFailed
        listOf(CborMap.Empty, headers(1L to CborText("x")), headers(1L to label(value = 1))).forEach { unprotected ->
            val item = recipientItem(
                protectedMap = CborMap.Empty,
                unprotectedMap = unprotected,
                ciphertext = ByteString(),
            )
            val message = tagged(
                CoseMessageType.Encrypt,
                body,
                agreed.unprotectedHeaders.parameters,
                CborBytes(agreed.ciphertext.sure()),
                CborArray.of(item),
            )
            val outcome16 = cose.decrypt(
                message = cose.decodeEncrypt(message).value(),
                keys = listOf(small),
                algorithms = EVERYTHING,
            )
            outcome16.failure() shouldBe
                CoseFailure.AlgorithmNotPermitted
        }
    }

    test("MACs and encryptions may leave the content out") {
        val secret = CoseKey.of(crypto.keys.generateSecret())
        val recipients = listOf(CoseRecipientSpec(key = secret, algorithm = CoseAlgorithm.Direct))
        val mac = cose.mac(
            payload = utf8(CONTENT),
            algorithm = CoseAlgorithm.Hmac256,
            recipients = recipients,
            isDetached = true,
        )
        mac.payload shouldBe null
        val outcome17 = cose.verify(
            message = mac,
            keys = listOf(secret),
            algorithms = EVERYTHING,
            detachedPayload = utf8(CONTENT),
        )
        outcome17.value() shouldBe utf8(CONTENT)
        val encrypted = cose.encrypt(
            plaintext = utf8(CONTENT),
            algorithm = CoseAlgorithm.A256Gcm,
            recipients = recipients,
            isDetached = true,
        )
        encrypted.ciphertext shouldBe null
        val nested = CoseRecipient(
            protectedHeaders = CoseHeaders.Empty,
            unprotectedHeaders = CoseHeaders.of(headers(1L to label(value = -6))),
            ciphertext = ByteString(),
            recipients = mac.recipients,
            protectedEncoding = ByteString(),
        )
        val outer = CoseMac(
            protectedHeaders = mac.protectedHeaders,
            unprotectedHeaders = mac.unprotectedHeaders,
            payload = utf8(CONTENT),
            tag = mac.tag,
            recipients = listOf(nested),
            protectedEncoding = mac.protectedEncoding,
        )
        cose.decodeMac(outer.encode()).value() shouldBe outer
        CborSimple(value = 255).toString() shouldBe "simple(255)"
    }
})
