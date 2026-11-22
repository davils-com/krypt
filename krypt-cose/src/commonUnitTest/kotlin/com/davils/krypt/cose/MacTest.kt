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

import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.cose.fixture.CONTENT
import com.davils.krypt.cose.fixture.HMAC_01
import com.davils.krypt.cose.fixture.HMAC_01_KEY_0
import com.davils.krypt.cose.fixture.HMAC_02
import com.davils.krypt.cose.fixture.HMAC_02_KEY_0
import com.davils.krypt.cose.fixture.HMAC_03
import com.davils.krypt.cose.fixture.HMAC_03_KEY_0
import com.davils.krypt.cose.fixture.HMAC_04
import com.davils.krypt.cose.fixture.HMAC_05
import com.davils.krypt.cose.fixture.HMAC_05_KEY_0
import com.davils.krypt.cose.fixture.HMAC_ENC_01
import com.davils.krypt.cose.fixture.HMAC_ENC_02
import com.davils.krypt.cose.fixture.HMAC_ENC_03
import com.davils.krypt.cose.fixture.HMAC_ENC_04
import com.davils.krypt.cose.fixture.P256_HKDF_256_03
import com.davils.krypt.cose.fixture.P256_HKDF_256_03_KEY_0
import com.davils.krypt.cose.fixture.cose
import com.davils.krypt.cose.fixture.crypto
import com.davils.krypt.cose.fixture.failure
import com.davils.krypt.cose.fixture.hex
import com.davils.krypt.cose.fixture.hexOf
import com.davils.krypt.cose.fixture.key
import com.davils.krypt.cose.fixture.relaxed
import com.davils.krypt.cose.fixture.utf8
import com.davils.krypt.cose.fixture.value
import com.davils.krypt.cose.internal.sure
import com.davils.krypt.cose.key.CoseKey
import com.davils.krypt.cose.key.CoseKeyOperation
import com.davils.krypt.primitive.key.SecretKey
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

private val MACS: Set<CoseAlgorithm> = setOf(
    CoseAlgorithm.Hmac256Truncated64,
    CoseAlgorithm.Hmac256,
    CoseAlgorithm.Hmac384,
    CoseAlgorithm.Hmac512,
    CoseAlgorithm.Direct,
    CoseAlgorithm.EcdhEsHkdf256,
)
private const val OUR_SECRET: String = "our-secret"

private suspend fun anonymous(encoded: String): CoseKey {
    val found = key(encoded)
    return CoseKey.of(secretKey = checkNotNull(found.secretKey))
}

private suspend fun verifiesMac(encoded: String, keyHex: String) {
    val message = relaxed.decodeMac(hex(encoded)).value()
    relaxed.verify(message = message, keys = listOf(key(keyHex)), algorithms = MACS).value() shouldBe utf8(CONTENT)
}

private suspend fun verifiesMac0(encoded: String, keyHex: String) {
    val message = relaxed.decodeMac0(hex(encoded)).value()
    relaxed.verify(message = message, keys = listOf(key(keyHex)), algorithms = MACS).value() shouldBe utf8(CONTENT)
}

private const val HMAC_512_KEY_BYTES: Int = 64

class MacTest : FunSpec({
    test("the MAC examples of the COSE working group verify") {
        verifiesMac(encoded = HMAC_01, keyHex = HMAC_01_KEY_0)
        verifiesMac(encoded = HMAC_02, keyHex = HMAC_02_KEY_0)
        verifiesMac(encoded = HMAC_03, keyHex = HMAC_03_KEY_0)
        verifiesMac(encoded = HMAC_05, keyHex = HMAC_05_KEY_0)
        verifiesMac0(encoded = HMAC_ENC_01, keyHex = HMAC_01_KEY_0)
        verifiesMac0(encoded = HMAC_ENC_02, keyHex = HMAC_02_KEY_0)
        verifiesMac0(encoded = HMAC_ENC_03, keyHex = HMAC_03_KEY_0)
    }

    test("a MAC derived by ECDH-ES verifies") {
        verifiesMac(encoded = P256_HKDF_256_03, keyHex = P256_HKDF_256_03_KEY_0)
    }

    test("wrong tags are refused") {
        val mac = relaxed.decodeMac(hex(HMAC_04)).value()
        val outcome2 = relaxed.verify(
            message = mac,
            keys = listOf(key(HMAC_01_KEY_0)),
            algorithms = MACS,
        )
        outcome2.failure() shouldBe CoseFailure.InvalidTag
        val mac0 = relaxed.decodeMac0(hex(HMAC_ENC_04)).value()
        val outcome3 = relaxed.verify(
            message = mac0,
            keys = listOf(key(HMAC_01_KEY_0)),
            algorithms = MACS,
        )
        outcome3.failure() shouldBe CoseFailure.InvalidTag
    }

    test("HMAC with direct keys is created exactly as the known answers") {
        val recipient = CoseRecipientSpec(key = key(HMAC_01_KEY_0), algorithm = CoseAlgorithm.Direct)
        val mac = cose.mac(payload = utf8(CONTENT), algorithm = CoseAlgorithm.Hmac256, recipients = listOf(recipient))
        hexOf(mac.encode()) shouldBe HMAC_01
        val mac0 = cose.mac0(payload = utf8(CONTENT), key = anonymous(HMAC_01_KEY_0), algorithm = CoseAlgorithm.Hmac256)
        hexOf(mac0.encode()) shouldBe HMAC_ENC_01
        val short = cose.mac0(
            payload = utf8(CONTENT),
            key = anonymous(HMAC_05_KEY_0),
            algorithm = CoseAlgorithm.Hmac256Truncated64,
        )
        short.tag.size shouldBe CoseAlgorithm.Hmac256Truncated64.tagBytes
    }

    test("every MAC round-trips with every kind of recipient") {
        val macs = listOf(CoseAlgorithm.Hmac256Truncated64, CoseAlgorithm.Hmac256, CoseAlgorithm.Hmac384)
        val wrapKey = CoseKey.of(crypto.keys.generateSecret(16), keyId = utf8("wrap"))
        val agreement = crypto.keys.generate(KeyType.P384)
        val recipients = listOf(
            CoseRecipientSpec(key = wrapKey, algorithm = CoseAlgorithm.A128Kw),
            CoseRecipientSpec(
                key = CoseKey.of(agreement.publicKey, keyId = utf8("ecdh")),
                algorithm = CoseAlgorithm.EcdhEsA256Kw,
            ),
        )
        val receivers = listOf(wrapKey, CoseKey.of(agreement.privateKey, keyId = utf8("ecdh")))
        val allowed = macs.toSet() + setOf(CoseAlgorithm.A128Kw, CoseAlgorithm.EcdhEsA256Kw)
        macs.forEach { algorithm ->
            val mac = cose.mac(payload = utf8(CONTENT), algorithm = algorithm, recipients = recipients)
            val decoded = cose.decodeMac(mac.encode()).value()
            receivers.forEach { receiver ->
                val outcome4 = cose.verify(
                    message = decoded,
                    keys = listOf(receiver),
                    algorithms = allowed,
                )
                outcome4.value() shouldBe utf8(CONTENT)
            }
            val outcome5 = cose.verify(
                message = decoded,
                keys = listOf(receiver(OUR_SECRET)),
                algorithms = allowed,
            )
            outcome5.failure() shouldBe CoseFailure.KeyNotFound
            val outcome6 = cose.verify(
                message = decoded,
                keys = receivers,
                algorithms = macs.toSet(),
            )
            outcome6.failure() shouldBe CoseFailure.AlgorithmNotPermitted
        }
    }

    test("MAC0 refuses keys that do not fit and payloads that are missing") {
        val secret = CoseKey.of(crypto.keys.generateSecret(HMAC_512_KEY_BYTES), keyId = utf8(OUR_SECRET))
        val message = cose.mac0(
            payload = utf8(CONTENT),
            key = secret,
            algorithm = CoseAlgorithm.Hmac512,
            isDetached = true,
        )
        val outcome7 = cose.verify(
            message = message,
            keys = listOf(secret),
            algorithms = MACS,
            detachedPayload = utf8(CONTENT),
        )
        outcome7.value() shouldBe utf8(CONTENT)
        val outcome8 = cose.verify(
            message = message,
            keys = listOf(secret),
            algorithms = MACS,
        )
        outcome8.failure() shouldBe CoseFailure.Malformed
        val outcome9 = cose.verify(
            message = message,
            keys = listOf(receiver("other")),
            algorithms = MACS,
            detachedPayload = utf8(CONTENT),
        )
        outcome9.failure() shouldBe
            CoseFailure.KeyNotFound
        val limited = CoseKey.of(
            secretKey = secret.secretKey.sure(),
            keyId = utf8(OUR_SECRET),
            operations = setOf(CoseKeyOperation.MacCreate),
        )
        val outcome10 = cose.verify(
            message = message,
            keys = listOf(limited),
            algorithms = MACS,
            detachedPayload = utf8(CONTENT),
        )
        outcome10.failure() shouldBe
            CoseFailure.KeyNotFound
        val other = CoseKey.of(crypto.keys.generateSecret(HMAC_512_KEY_BYTES), keyId = utf8(OUR_SECRET))
        val outcome11 = cose.verify(
            message = message,
            keys = listOf(other),
            algorithms = MACS,
            detachedPayload = utf8(CONTENT),
        )
        outcome11.failure() shouldBe
            CoseFailure.InvalidTag
        val outcome12 = cose.verify(
            message = message,
            keys = listOf(secret),
            algorithms = setOf(CoseAlgorithm.Hmac256),
            detachedPayload = utf8(CONTENT),
        )
        outcome12.failure() shouldBe CoseFailure.AlgorithmNotPermitted
        shouldThrow<IllegalArgumentException> {
            cose.mac0(payload = utf8(CONTENT), key = secret, algorithm = CoseAlgorithm.A128Gcm)
        }
        val verifyOnly = CoseKey.of(
            secretKey = secret.secretKey.sure(),
            operations = setOf(CoseKeyOperation.MacVerify),
        )
        shouldThrow<IllegalArgumentException> {
            cose.mac0(payload = utf8(CONTENT), key = verifyOnly, algorithm = CoseAlgorithm.Hmac256)
        }
        shouldThrow<IllegalArgumentException> {
            cose.mac(payload = utf8(CONTENT), algorithm = CoseAlgorithm.Ed25519, recipients = emptyList())
        }
    }

    test("an HMAC key shorter than the output of its hash is refused") {
        val short = CoseKey.of(crypto.keys.generateSecret(), keyId = utf8(OUR_SECRET))
        shouldThrow<IllegalArgumentException> {
            cose.mac0(payload = utf8(CONTENT), key = short, algorithm = CoseAlgorithm.Hmac384)
        }
        val long = CoseKey.of(crypto.keys.generateSecret(HMAC_512_KEY_BYTES), keyId = utf8(OUR_SECRET))
        val message = cose.mac0(payload = utf8(CONTENT), key = long, algorithm = CoseAlgorithm.Hmac512)
        cose.verify(message = message, keys = listOf(long), algorithms = MACS).value() shouldBe utf8(CONTENT)
        cose.verify(message = message, keys = listOf(short), algorithms = MACS).failure() shouldBe
            CoseFailure.KeyNotFound
    }
})

private fun receiver(keyId: String): CoseKey =
    CoseKey.of(SecretKey.of(SecretBytes.copyOf(ByteArray(size = 32))), keyId = utf8(keyId))
