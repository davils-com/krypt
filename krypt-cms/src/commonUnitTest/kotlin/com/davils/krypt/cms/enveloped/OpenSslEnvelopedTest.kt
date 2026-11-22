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

import com.davils.kore.core.outcome.failureOrNull
import com.davils.krypt.cms.Cms
import com.davils.krypt.cms.CmsFailure
import com.davils.krypt.cms.fixture.AUTH_ENVELOPED_RSA
import com.davils.krypt.cms.fixture.CONTENT
import com.davils.krypt.cms.fixture.EC_RECIPIENT_CERTIFICATE
import com.davils.krypt.cms.fixture.EC_RECIPIENT_KEY
import com.davils.krypt.cms.fixture.ENCRYPTED
import com.davils.krypt.cms.fixture.ENVELOPED_EC
import com.davils.krypt.cms.fixture.ENVELOPED_KEK
import com.davils.krypt.cms.fixture.ENVELOPED_KEM
import com.davils.krypt.cms.fixture.ENVELOPED_PASSWORD
import com.davils.krypt.cms.fixture.ENVELOPED_RSA
import com.davils.krypt.cms.fixture.FixedClock
import com.davils.krypt.cms.fixture.KEM_RECIPIENT_CERTIFICATE
import com.davils.krypt.cms.fixture.KEM_RECIPIENT_KEY
import com.davils.krypt.cms.fixture.RSA_RECIPIENT_CERTIFICATE
import com.davils.krypt.cms.fixture.RSA_RECIPIENT_KEY
import com.davils.krypt.cms.fixture.certificate
import com.davils.krypt.cms.fixture.cms
import com.davils.krypt.cms.fixture.crypto
import com.davils.krypt.cms.fixture.hex
import com.davils.krypt.cms.fixture.privateKey
import com.davils.krypt.cms.fixture.value
import com.davils.krypt.core.LegacyCryptography
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.SecretText
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.KemAlgorithm
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.cryptoPolicy
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.key.SecretKey
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.encodeToByteString

private const val PASSWORD: String = "fixture-password"
private const val KEK: String = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
private const val ENCRYPTION_KEY: String = "0f0e0d0c0b0a09080706050403020100"

class OpenSslEnvelopedTest : FunSpec({
    test("krypt decrypts what OpenSSL envelops for RSA-OAEP and ECDH recipients") {
        val rsa = Credential.Certified(certificate(RSA_RECIPIENT_CERTIFICATE), privateKey(RSA_RECIPIENT_KEY))
        val enveloped = cms.decodeEnveloped(ENVELOPED_RSA).value()
        enveloped.isAuthenticated shouldBe false
        enveloped.encryption shouldBe ContentEncryption.Aes256Cbc
        enveloped.recipients.single().type shouldBe RecipientType.KeyTransport
        cms.decrypt(enveloped, rsa).value() shouldBe CONTENT
        val authenticated = cms.decodeEnveloped(AUTH_ENVELOPED_RSA).value()
        authenticated.isAuthenticated shouldBe true
        authenticated.encryption shouldBe ContentEncryption.Aes256Gcm
        cms.decrypt(authenticated, rsa).value() shouldBe CONTENT
        val ec = Credential.Certified(certificate(EC_RECIPIENT_CERTIFICATE), privateKey(EC_RECIPIENT_KEY))
        val agreed = cms.decodeEnveloped(ENVELOPED_EC).value()
        agreed.recipients.single().type shouldBe RecipientType.KeyAgreement
        cms.decrypt(agreed, ec).value() shouldBe CONTENT
        cms.decrypt(agreed, rsa).failureOrNull() shouldBe CmsFailure.RecipientNotFound
    }

    test("krypt decrypts what OpenSSL envelops for a key-encryption key and a password") {
        val kek = Credential.Kek("kek-1".encodeToByteString(), SecretKey.of(SecretBytes.copyOf(hex(KEK))))
        cms.decrypt(cms.decodeEnveloped(ENVELOPED_KEK).value(), kek).value() shouldBe CONTENT
        val password = Credential.Password(SecretText.of(PASSWORD))
        val enveloped = cms.decodeEnveloped(ENVELOPED_PASSWORD).value()
        cms.decrypt(enveloped, password).failureOrNull() shouldBe CmsFailure.AlgorithmNotPermitted
        val legacy = Cms(
            Crypto(
                environment {
                    clock = FixedClock
                    policy = cryptoPolicy { acceptLegacy(DigestAlgorithm.Sha1) }
                },
            ),
        )
        legacy.decrypt(enveloped, password).value() shouldBe CONTENT
        val wrong = Credential.Password(SecretText.of("wrong"))
        legacy.decrypt(enveloped, wrong).failureOrNull() shouldBe CmsFailure.DecryptionFailed
    }

    test("krypt decrypts what OpenSSL encrypts with a caller key") {
        val encrypted = cms.decodeEncrypted(ENCRYPTED).value()
        encrypted.encryption shouldBe ContentEncryption.Aes128Cbc
        val key = SecretKey.of(SecretBytes.copyOf(hex(ENCRYPTION_KEY)))
        cms.decrypt(encrypted, key).value() shouldBe CONTENT
    }

    test("krypt decrypts what OpenSSL envelops for an ML-KEM recipient where the platform has ML-KEM") {
        val enveloped = cms.decodeEnveloped(ENVELOPED_KEM).value()
        enveloped.recipients.single().type shouldBe RecipientType.Kem
        if (crypto.capabilities.supports(KemAlgorithm.MlKem768)) {
            val kem = Credential.Certified(certificate(KEM_RECIPIENT_CERTIFICATE), privateKey(KEM_RECIPIENT_KEY))
            cms.decrypt(enveloped, kem).value() shouldBe CONTENT
        }
    }
})
