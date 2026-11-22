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
import com.davils.krypt.core.algorithm.MacAlgorithm
import com.davils.krypt.cose.cbor.Cbor
import com.davils.krypt.cose.cbor.CborArray
import com.davils.krypt.cose.cbor.CborBytes
import com.davils.krypt.cose.cbor.CborInteger
import com.davils.krypt.cose.cbor.CborMap
import com.davils.krypt.cose.cbor.CborText
import com.davils.krypt.cose.fixture.HMAC_01_KEY_0
import com.davils.krypt.cose.fixture.MAC0_PASS_02
import com.davils.krypt.cose.fixture.MAC0_PASS_02_AAD
import com.davils.krypt.cose.fixture.MAC0_PASS_03
import com.davils.krypt.cose.fixture.SIGN1_PASS_01
import com.davils.krypt.cose.fixture.SIGN1_PASS_01_KEY_0
import com.davils.krypt.cose.fixture.cose
import com.davils.krypt.cose.fixture.crypto
import com.davils.krypt.cose.fixture.failure
import com.davils.krypt.cose.fixture.hex
import com.davils.krypt.cose.fixture.key
import com.davils.krypt.cose.fixture.recipientItem
import com.davils.krypt.cose.fixture.relaxed
import com.davils.krypt.cose.fixture.tagged
import com.davils.krypt.cose.fixture.utf8
import com.davils.krypt.cose.fixture.value
import com.davils.krypt.cose.key.CoseKey
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString

private const val TRUNCATED: Int = 8

private val algorithmLabel: CborInteger = CborInteger.of(1)

private fun unprotectedAlgorithm(algorithm: CoseAlgorithm): CborMap =
    CborMap.of(algorithmLabel to CborInteger.of(algorithm.id))

private suspend fun encrypted(recipient: CoseRecipientSpec): CoseEncrypt =
    cose.encrypt(plaintext = utf8("x"), algorithm = CoseAlgorithm.A256Gcm, recipients = listOf(recipient))

class ProtectedAlgorithmTest : FunSpec({
    test("an unprotected alg cannot downgrade HMAC 256/256 to HMAC 256/64") {
        val secret = CoseKey.of(crypto.keys.generateSecret())
        val payload = utf8("pay 10 EUR to alice")
        val empty = CborBytes(ByteString())
        val structure = CborArray.of(CborText("MAC0"), empty, empty, CborBytes(payload))
        val secretKey = checkNotNull(secret.secretKey)
        val tag = crypto.macs.mac(key = secretKey, data = Cbor.encode(structure), algorithm = MacAlgorithm.HmacSha256)
        val allowed = setOf(CoseAlgorithm.Hmac256, CoseAlgorithm.Hmac256Truncated64)
        listOf(
            CoseAlgorithm.Hmac256 to tag,
            CoseAlgorithm.Hmac256Truncated64 to tag.substring(startIndex = 0, endIndex = TRUNCATED),
        ).forEach { (algorithm, bytes) ->
            val encoded = tagged(
                CoseMessageType.Mac0,
                CborBytes(ByteString()),
                unprotectedAlgorithm(algorithm),
                CborBytes(payload),
                CborBytes(bytes),
            )
            val message = cose.decodeMac0(encoded).value()
            cose.verify(message = message, keys = listOf(secret), algorithms = allowed).failure() shouldBe
                CoseFailure.Malformed
        }
        val genuine = cose.mac0(payload = payload, key = secret, algorithm = CoseAlgorithm.Hmac256)
        genuine.protectedHeaders.algorithm shouldBe CoseAlgorithm.Hmac256
        cose.verify(message = genuine, keys = listOf(secret), algorithms = allowed).value() shouldBe payload
    }

    test("the examples of the COSE working group with an unprotected alg are refused") {
        val sign1 = relaxed.decodeSign1(hex(SIGN1_PASS_01)).value()
        val signatures = CoseAlgorithm.entries.filter { algorithm -> algorithm.kind == CoseAlgorithmKind.Signature }
        relaxed.verify(sign1, listOf(key(SIGN1_PASS_01_KEY_0)), signatures.toSet()).failure() shouldBe
            CoseFailure.Malformed
        val macs = setOf(CoseAlgorithm.Hmac256)
        val mac0 = relaxed.decodeMac0(hex(MAC0_PASS_03)).value()
        relaxed.verify(message = mac0, keys = listOf(key(HMAC_01_KEY_0)), algorithms = macs).failure() shouldBe
            CoseFailure.Malformed
        val external = relaxed.decodeMac0(hex(MAC0_PASS_02)).value()
        val outcome = relaxed.verify(
            message = external,
            keys = listOf(key(HMAC_01_KEY_0)),
            algorithms = macs,
            externalAad = hex(MAC0_PASS_02_AAD),
        )
        outcome.failure() shouldBe CoseFailure.Malformed
    }

    test("creating a message or a signature with an unprotected alg is refused") {
        val secret = CoseKey.of(crypto.keys.generateSecret())
        val pair = crypto.keys.generate(KeyType.P256)
        val unprotected = CoseHeaders.of(unprotectedAlgorithm(CoseAlgorithm.Hmac256))
        shouldThrow<IllegalArgumentException> {
            cose.mac0(
                payload = utf8("x"),
                key = secret,
                algorithm = CoseAlgorithm.Hmac256,
                unprotectedHeaders = unprotected,
            )
        }
        val signer = CoseSigner(
            key = CoseKey.of(pair.privateKey),
            algorithm = CoseAlgorithm.Esp256,
            unprotectedHeaders = CoseHeaders.of(unprotectedAlgorithm(CoseAlgorithm.Esp256)),
        )
        shouldThrow<IllegalArgumentException> { cose.sign1(payload = utf8("x"), signer = signer) }
        val recipient = CoseRecipientSpec(
            key = CoseKey.of(pair.publicKey),
            algorithm = CoseAlgorithm.EcdhEsHkdf256,
            unprotectedHeaders = CoseHeaders.of(unprotectedAlgorithm(CoseAlgorithm.EcdhEsHkdf256)),
        )
        shouldThrow<IllegalArgumentException> {
            cose.encrypt(plaintext = utf8("x"), algorithm = CoseAlgorithm.A256Gcm, recipients = listOf(recipient))
        }
    }

    test("an ECDH-ES recipient names its alg protected, a direct or key wrap recipient unprotected") {
        val pair = crypto.keys.generate(KeyType.P256)
        val algorithms = setOf(CoseAlgorithm.A256Gcm, CoseAlgorithm.EcdhEsHkdf256, CoseAlgorithm.A256Kw)
        val agreement = CoseRecipientSpec(key = CoseKey.of(pair.publicKey), algorithm = CoseAlgorithm.EcdhEsHkdf256)
        val message = encrypted(agreement)
        val recipient = message.recipients.single()
        recipient.protectedHeaders.algorithm shouldBe CoseAlgorithm.EcdhEsHkdf256
        val unprotectedEntries = recipient.unprotectedHeaders.parameters.entries
        val moved = CborMap(unprotectedEntries + recipient.protectedHeaders.parameters.entries)
        val encoded = tagged(
            CoseMessageType.Encrypt,
            CborBytes(message.protectedEncoding),
            message.unprotectedHeaders.parameters,
            CborBytes(checkNotNull(message.ciphertext)),
            CborArray.of(recipientItem(protectedMap = CborMap.of(), unprotectedMap = moved, ciphertext = ByteString())),
        )
        val keys = listOf(CoseKey.of(pair.privateKey))
        val forged = cose.decodeEncrypt(encoded).value()
        cose.decrypt(message = forged, keys = keys, algorithms = algorithms).failure() shouldBe CoseFailure.Malformed
        cose.decrypt(message = message, keys = keys, algorithms = algorithms).value() shouldBe utf8("x")
        val secret = CoseKey.of(crypto.keys.generateSecret())
        val wrapping = CoseRecipientSpec(key = secret, algorithm = CoseAlgorithm.A256Kw)
        val wrapped = encrypted(wrapping)
        val wrappedRecipient = wrapped.recipients.single()
        wrappedRecipient.unprotectedHeaders.algorithm shouldBe CoseAlgorithm.A256Kw
        cose.decrypt(message = wrapped, keys = listOf(secret), algorithms = algorithms).value() shouldBe utf8("x")
    }
})
