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

@file:OptIn(LegacyCryptography::class)

package com.davils.krypt.cms.enveloped

import com.davils.krypt.cms.fixture.AUTH_ENVELOPED_RSA
import com.davils.krypt.cms.fixture.EC_RECIPIENT_CERTIFICATE
import com.davils.krypt.cms.fixture.ENCRYPTED
import com.davils.krypt.cms.fixture.ENVELOPED_EC
import com.davils.krypt.cms.fixture.ENVELOPED_KEK
import com.davils.krypt.cms.fixture.ENVELOPED_RSA
import com.davils.krypt.cms.fixture.KEM_RECIPIENT_CERTIFICATE
import com.davils.krypt.cms.fixture.RSA_RECIPIENT_CERTIFICATE
import com.davils.krypt.cms.fixture.certificate
import com.davils.krypt.cms.fixture.checkValue
import com.davils.krypt.cms.fixture.cms
import com.davils.krypt.cms.fixture.crypto
import com.davils.krypt.cms.fixture.enveloped
import com.davils.krypt.cms.fixture.value
import com.davils.krypt.core.LegacyCryptography
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.SecretText
import com.davils.krypt.core.algorithm.AsymmetricEncryptionAlgorithm
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.KdfAlgorithm
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.algorithm.KeyWrapAlgorithm
import com.davils.krypt.primitive.key.SecretKey
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import kotlinx.io.bytestring.ByteString

private const val ITERATIONS: Int = 1_000
private const val KEY_BYTES: Int = 32
private const val SECRET: String = "secret"

private fun key(fill: Int): SecretKey = SecretKey.of(SecretBytes.copyOf(ByteArray(KEY_BYTES) { fill.toByte() }))

class EnvelopedValuesTest : FunSpec({
    test("recipients compare every property and show no secret") {
        val rsa = certificate(RSA_RECIPIENT_CERTIFICATE)
        val ec = certificate(EC_RECIPIENT_CERTIFICATE)
        val kem = certificate(KEM_RECIPIENT_CERTIFICATE)
        checkValue(
            value = Recipient.KeyTransport(rsa),
            same = Recipient.KeyTransport(rsa),
            different = listOf(
                Recipient.KeyTransport(ec),
                Recipient.KeyTransport(rsa, AsymmetricEncryptionAlgorithm.RsaOaepSha512),
                Recipient.KeyTransport(rsa, isKeyIdentifierUsed = true),
            ),
        ) shouldContain "RSAES-OAEP-SHA-256"
        shouldThrow<IllegalArgumentException> { Recipient.KeyTransport(rsa, AsymmetricEncryptionAlgorithm.RsaPkcs1) }
        checkValue(
            value = Recipient.KeyAgreement(ec),
            same = Recipient.KeyAgreement(ec),
            different = listOf(
                Recipient.KeyAgreement(rsa),
                Recipient.KeyAgreement(ec, digest = DigestAlgorithm.Sha384),
                Recipient.KeyAgreement(ec, wrap = KeyWrapAlgorithm.Aes128Kw),
                Recipient.KeyAgreement(ec, isKeyIdentifierUsed = true),
                Recipient.KeyAgreement(ec, userKeyingMaterial = ByteString(1)),
            ),
        ) shouldContain "AES-256-KW"
        checkValue(
            value = Recipient.Kek(ByteString(1), key(1)),
            same = Recipient.Kek(ByteString(1), key(1)),
            different = listOf(Recipient.Kek(ByteString(2), key(1)), Recipient.Kek(ByteString(1), key(2))),
        ) shouldBe "Kek(01)"
        checkValue(
            value = Recipient.Password(SecretText.of(SECRET), ITERATIONS),
            same = Recipient.Password(SecretText.of(SECRET), ITERATIONS),
            different = listOf(
                Recipient.Password(SecretText.of("other"), ITERATIONS),
                Recipient.Password(SecretText.of(SECRET), ITERATIONS + 1),
                Recipient.Password(SecretText.of(SECRET), ITERATIONS, KdfAlgorithm.Pbkdf2Sha512),
            ),
        ) shouldNotContain SECRET
        checkValue(
            value = Recipient.Kem(kem),
            same = Recipient.Kem(kem),
            different = listOf(
                Recipient.Kem(ec),
                Recipient.Kem(kem, kdf = KdfAlgorithm.HkdfSha512),
                Recipient.Kem(kem, wrap = KeyWrapAlgorithm.Aes128Kw),
                Recipient.Kem(kem, isKeyIdentifierUsed = true),
                Recipient.Kem(kem, userKeyingMaterial = ByteString(1)),
            ),
        ) shouldContain "HKDF-SHA-256"
    }

    test("credentials compare every property and show no secret") {
        val rsa = certificate(RSA_RECIPIENT_CERTIFICATE)
        val ec = certificate(EC_RECIPIENT_CERTIFICATE)
        val first = crypto.keys.generate(KeyType.P256).privateKey
        val second = crypto.keys.generate(KeyType.P256).privateKey
        checkValue(
            value = Credential.Certified(rsa, first),
            same = Credential.Certified(rsa, first),
            different = listOf(Credential.Certified(ec, first), Credential.Certified(rsa, second)),
        ) shouldContain "Certified("
        checkValue(
            value = Credential.Kek(ByteString(1), key(1)),
            same = Credential.Kek(ByteString(1), key(1)),
            different = listOf(Credential.Kek(ByteString(2), key(1)), Credential.Kek(ByteString(1), key(2))),
        ) shouldBe "Kek(01)"
        checkValue(
            value = Credential.Password(SecretText.of(SECRET)),
            same = Credential.Password(SecretText.of(SECRET)),
            different = listOf(Credential.Password(SecretText.of("other"))),
        ) shouldBe "Password(redacted)"
    }

    test("decoded messages compare their encodings") {
        val enveloped = cms.decodeEnveloped(ENVELOPED_RSA).value()
        val other = cms.decodeEnveloped(ENVELOPED_EC).value()
        checkValue(
            value = enveloped,
            same = cms.decodeEnveloped(ENVELOPED_RSA).value(),
            different = listOf(other),
        ) shouldBe
            "EnvelopedData(authenticated=false, Aes256Cbc, 1 recipients)"
        val recipient = enveloped.recipients.single()
        checkValue(value = recipient, same = enveloped.recipients.single(), different = other.recipients) shouldContain
            "KeyTransport"
        recipient.isSupported shouldBe true
        recipient.keyIdentifier shouldBe null
        cms
            .enveloped(ENVELOPED_KEK)
            .recipients
            .single()
            .references shouldBe emptyList()
        cms.decodeEnveloped(AUTH_ENVELOPED_RSA).value().unprotectedAttributes shouldBe emptyList()
        val encrypted = cms.decodeEncrypted(ENCRYPTED).value()
        val own = cms.encrypt(ByteString(1), key(1))
        checkValue(value = encrypted, same = cms.decodeEncrypted(ENCRYPTED).value(), different = listOf(own)) shouldBe
            "EncryptedData(Aes128Cbc)"
        ContentEncryption.Aes128Gcm.isAuthenticated shouldBe true
    }
})
