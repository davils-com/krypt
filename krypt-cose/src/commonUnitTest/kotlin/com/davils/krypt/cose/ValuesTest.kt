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

import com.davils.kore.core.validation.report.ValidationException
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.cose.cbor.CborLimits
import com.davils.krypt.cose.fixture.CONTENT
import com.davils.krypt.cose.fixture.cose
import com.davils.krypt.cose.fixture.crypto
import com.davils.krypt.cose.fixture.utf8
import com.davils.krypt.cose.fixture.value
import com.davils.krypt.cose.key.CoseKey
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain

private const val OTHER: String = "other"

private fun <T : Any> comparesByValue(value: T, same: T, different: T) {
    value shouldBe same
    value.hashCode() shouldBe same.hashCode()
    value shouldNotBe different
    value.equals(OTHER) shouldBe false
}

class ValuesTest : FunSpec({
    test("messages compare by every field and show sizes only") {
        val secret = CoseKey.of(crypto.keys.generateSecret(16), keyId = utf8("kid"))
        val pair = crypto.keys.generate(KeyType.Ed25519)
        val signer = CoseSigner(key = CoseKey.of(pair.privateKey), algorithm = CoseAlgorithm.Ed25519)
        val direct = listOf(CoseRecipientSpec(key = secret, algorithm = CoseAlgorithm.Direct))
        val sign1 = cose.sign1(payload = utf8(CONTENT), signer = signer)
        comparesByValue(
            value = sign1,
            same = cose.decodeSign1(sign1.encode()).value(),
            different = cose.sign1(payload = utf8(OTHER), signer = signer),
        )
        val sign = cose.sign(payload = utf8(CONTENT), signers = listOf(signer), isDetached = true)
        comparesByValue(
            value = sign,
            same = cose.decodeSign(sign.encode()).value(),
            different = cose.sign(payload = utf8(OTHER), signers = listOf(signer)),
        )
        comparesByValue(
            value = sign.signatures[0],
            same = sign.signatures[0],
            different = cose.sign(payload = utf8(OTHER), signers = listOf(signer)).signatures[0],
        )
        val mac0 = cose.mac0(payload = utf8(CONTENT), key = secret, algorithm = CoseAlgorithm.Hmac256)
        comparesByValue(
            value = mac0,
            same = cose.decodeMac0(mac0.encode()).value(),
            different = cose.mac0(payload = utf8(OTHER), key = secret, algorithm = CoseAlgorithm.Hmac256),
        )
        val mac = cose.mac(
            payload = utf8(CONTENT),
            algorithm = CoseAlgorithm.Hmac256,
            recipients = listOf(
                CoseRecipientSpec(key = CoseKey.of(crypto.keys.generateSecret()), algorithm = CoseAlgorithm.Direct),
            ),
        )
        comparesByValue(
            value = mac,
            same = cose.decodeMac(mac.encode()).value(),
            different = cose.mac0(payload = utf8(CONTENT), key = secret, algorithm = CoseAlgorithm.Hmac256),
        )
        val encrypt0 = cose.encrypt0(
            plaintext = utf8(CONTENT),
            key = secret,
            algorithm = CoseAlgorithm.A128Gcm,
            isDetached = true,
        )
        comparesByValue(
            value = encrypt0,
            same = cose.decodeEncrypt0(encrypt0.encode()).value(),
            different = cose.encrypt0(plaintext = utf8(CONTENT), key = secret, algorithm = CoseAlgorithm.A128Gcm),
        )
        val encrypt = cose.encrypt(plaintext = utf8(CONTENT), algorithm = CoseAlgorithm.A128Gcm, recipients = direct)
        comparesByValue(
            value = encrypt,
            same = cose.decodeEncrypt(encrypt.encode()).value(),
            different = cose.encrypt(plaintext = utf8(CONTENT), algorithm = CoseAlgorithm.A128Gcm, recipients = direct),
        )
        comparesByValue(value = encrypt.recipients[0], same = encrypt.recipients[0], different = mac.recipients[0])
        sign1.toString() shouldContain "CoseSign1(protected={1: -19}"
        sign.toString() shouldContain "payload=detached"
        sign.signatures[0].toString() shouldContain "signature=64 bytes"
        mac0.toString() shouldContain "tag=32 bytes"
        mac.toString() shouldContain "recipients=["
        encrypt0.toString() shouldContain "ciphertext=detached"
        encrypt.toString() shouldContain "ciphertext=36 bytes"
        encrypt.recipients[0].toString() shouldContain "CoseRecipient("
        listOf(sign1, sign, mac0, mac, encrypt0, encrypt).map { message -> message.type } shouldBe
            CoseMessageType.entries.toList()
    }

    test("signers and recipients check their keys") {
        val pair = crypto.keys.generate(KeyType.P256)
        val signer = CoseSigner(key = CoseKey.of(pair.privateKey), algorithm = CoseAlgorithm.Esp256)
        comparesByValue(
            value = signer,
            same = CoseSigner(CoseKey.of(pair.privateKey), CoseAlgorithm.Esp256),
            different = CoseSigner(CoseKey.of(pair.privateKey), CoseAlgorithm.Es256),
        )
        signer.toString() shouldContain "ESP256"
        shouldThrow<IllegalArgumentException> {
            CoseSigner(
                key = CoseKey.of(pair.privateKey),
                algorithm = CoseAlgorithm.A128Gcm,
            )
        }
        shouldThrow<IllegalArgumentException> {
            CoseSigner(
                key = CoseKey.of(pair.publicKey),
                algorithm = CoseAlgorithm.Esp256,
            )
        }
        shouldThrow<IllegalArgumentException> {
            CoseSigner(
                key = CoseKey.of(pair.privateKey),
                algorithm = CoseAlgorithm.Esp384,
            )
        }
        val secret = CoseKey.of(crypto.keys.generateSecret(16))
        val spec = CoseRecipientSpec(key = secret, algorithm = CoseAlgorithm.A128Kw)
        comparesByValue(
            value = spec,
            same = CoseRecipientSpec(secret, CoseAlgorithm.A128Kw),
            different = CoseRecipientSpec(secret, CoseAlgorithm.Direct),
        )
        spec.toString() shouldContain "A128KW"
        shouldThrow<IllegalArgumentException> { CoseRecipientSpec(key = secret, algorithm = CoseAlgorithm.A128Gcm) }
        shouldThrow<IllegalArgumentException> {
            CoseRecipientSpec(
                key = CoseKey.of(pair.publicKey),
                algorithm = CoseAlgorithm.A128Kw,
            )
        }
        shouldThrow<IllegalArgumentException> {
            CoseRecipientSpec(
                key = secret,
                algorithm = CoseAlgorithm.EcdhEsHkdf256,
            )
        }
        shouldThrow<IllegalArgumentException> {
            CoseRecipientSpec(
                key = CoseKey.of(pair.privateKey, publicKey = null),
                algorithm = CoseAlgorithm.EcdhEsHkdf256,
            )
        }
        shouldThrow<IllegalArgumentException> {
            CoseRecipientSpec(
                key = secret,
                algorithm = CoseAlgorithm.A128Kw,
                protectedHeaders = CoseHeaders.of(keyId = utf8("kid")),
            )
        }
        CoseRecipientSpec(
            key = CoseKey.of(pair.publicKey),
            algorithm = CoseAlgorithm.EcdhEsHkdf256,
            protectedHeaders = CoseHeaders.of(keyId = utf8("kid")),
        ).algorithm shouldBe
            CoseAlgorithm.EcdhEsHkdf256
        shouldThrow<IllegalArgumentException> {
            cose.encrypt(
                plaintext = utf8(CONTENT),
                algorithm = CoseAlgorithm.A256Gcm,
                recipients = listOf(CoseRecipientSpec(key = secret, algorithm = CoseAlgorithm.Direct)),
            )
        }
        shouldThrow<IllegalArgumentException> {
            cose.encrypt(
                plaintext = utf8(CONTENT),
                algorithm = CoseAlgorithm.A256Gcm,
                recipients = emptyList(),
            )
        }
    }

    test("limits, algorithms and types describe themselves") {
        comparesByValue(value = CoseLimits.Default, same = CoseLimits(), different = CoseLimits(maximumKeys = 1))
        CoseLimits(cbor = CborLimits(maximumDepth = 2)) shouldNotBe CoseLimits.Default
        CoseLimits.Default.toString() shouldContain "maximumSignatures=8"
        shouldThrow<ValidationException> { CoseLimits(maximumSignatures = 0) }
        shouldThrow<ValidationException> { CoseLimits(maximumRecipients = CoseLimits.HARD_MAXIMUM_RECIPIENTS + 1) }
        shouldThrow<ValidationException> { CoseLimits(maximumCertificates = 0) }
        shouldThrow<ValidationException> { CoseLimits(maximumKeys = 0) }
        CoseAlgorithm.entries.forEach { algorithm -> CoseAlgorithm.of(algorithm.id) shouldBe algorithm }
        CoseAlgorithm.of(id = 0) shouldBe null
        CoseAlgorithmKind.entries.map { kind -> kind.name } shouldBe
            listOf("Signature", "Mac", "ContentEncryption", "KeyDistribution")
        cose.toString() shouldContain "Cose("
    }
})
