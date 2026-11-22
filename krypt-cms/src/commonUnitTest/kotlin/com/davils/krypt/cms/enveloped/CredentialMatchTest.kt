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

package com.davils.krypt.cms.enveloped

import com.davils.kore.core.outcome.failureOrNull
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.cms.CmsFailure
import com.davils.krypt.cms.fixture.CONTENT
import com.davils.krypt.cms.fixture.EC_RECIPIENT_CERTIFICATE
import com.davils.krypt.cms.fixture.EC_RECIPIENT_KEY
import com.davils.krypt.cms.fixture.ENVELOPED_EC
import com.davils.krypt.cms.fixture.ENVELOPED_KEM
import com.davils.krypt.cms.fixture.ENVELOPED_RSA
import com.davils.krypt.cms.fixture.EnvelopedBase
import com.davils.krypt.cms.fixture.KEM_RECIPIENT_CERTIFICATE
import com.davils.krypt.cms.fixture.KEM_RECIPIENT_KEY
import com.davils.krypt.cms.fixture.RSA_RECIPIENT_CERTIFICATE
import com.davils.krypt.cms.fixture.certificate
import com.davils.krypt.cms.fixture.cms
import com.davils.krypt.cms.fixture.constructed
import com.davils.krypt.cms.fixture.crypto
import com.davils.krypt.cms.fixture.decryptCbc
import com.davils.krypt.cms.fixture.der
import com.davils.krypt.cms.fixture.enveloped
import com.davils.krypt.cms.fixture.privateKey
import com.davils.krypt.cms.fixture.refusal
import com.davils.krypt.cms.fixture.sequenceOf
import com.davils.krypt.cms.fixture.tagged
import com.davils.krypt.cms.fixture.value
import com.davils.krypt.cms.fixture.with
import com.davils.krypt.cms.internal.CmsOids
import com.davils.krypt.cms.internal.KeyProtection
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.SecretText
import com.davils.krypt.core.algorithm.KemAlgorithm
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.primitive.key.SecretKey
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString

private const val KEY_BYTES: Int = 32
private const val OTHER_TAG: Int = 4
private const val ODD_KEY_BYTES: Int = 24
private const val KEM: Int = 2
private const val KDF: Int = 4
private const val WRAP: Int = 6
private val UNKNOWN: ObjectIdentifier = ObjectIdentifier.of("1.2.3.4")

private fun kek(): SecretKey = SecretKey.of(SecretBytes.copyOf(ByteArray(KEY_BYTES) { 1 }))

class CredentialMatchTest : FunSpec({
    test("credentials of the wrong kind or family do not open a recipient") {
        val rsaBase = EnvelopedBase(cms.decodeEnveloped(ENVELOPED_RSA).value())
        val unsupported = rsaBase.recipient.with(
            2,
            der {
                sequence {
                    objectIdentifier(CmsOids.RSA_ENCRYPTION)
                    nullValue()
                }
            },
        )
        val decoded = cms.decodeEnveloped(rsaBase.withRecipients(listOf(sequenceOf(unsupported)))).value()
        cms.refusal(decoded, Credential.Password(SecretText.of("x"))) shouldBe CmsFailure.RecipientNotFound
        val ecKey = privateKey(EC_RECIPIENT_KEY)
        val wrongFamily = Credential.Certified(certificate(RSA_RECIPIENT_CERTIFICATE), ecKey)
        cms.decryptCbc(rsaBase.enveloped, wrongFamily).failureOrNull() shouldBe CmsFailure.DecryptionFailed
        if (crypto.capabilities.supports(KeyType.X25519)) {
            val x25519 = crypto.keys.generate(KeyType.X25519).privateKey
            val wrongScheme = Credential.Certified(certificate(EC_RECIPIENT_CERTIFICATE), x25519)
            cms.decryptCbc(cms.decodeEnveloped(ENVELOPED_EC).value(), wrongScheme).failureOrNull() shouldBe
                CmsFailure.DecryptionFailed
        }
        if (crypto.capabilities.supports(KemAlgorithm.MlKem768)) {
            val notKem = Credential.Certified(certificate(KEM_RECIPIENT_CERTIFICATE), ecKey)
            cms.decryptCbc(cms.decodeEnveloped(ENVELOPED_KEM).value(), notKem).failureOrNull() shouldBe
                CmsFailure.DecryptionFailed
        }
    }

    test("KEM recipients with unusual algorithm parameters are unusable") {
        val base = EnvelopedBase(cms.decodeEnveloped(ENVELOPED_KEM).value())
        val fields = base.recipient
        val kem = EnvelopedBase.childrenOf(fields[1])

        fun withParameters(oid: ObjectIdentifier) = der {
            sequence {
                objectIdentifier(oid)
                nullValue()
            }
        }
        listOf(
            kem.with(KEM, withParameters(CmsOids.ML_KEM_768)),
            kem.with(KDF, withParameters(CmsOids.HKDF_SHA256)),
            kem.with(WRAP, der { sequence { objectIdentifier(UNKNOWN) } }),
        ).forEach { children ->
            val encoded = base.withRecipients(
                listOf(tagged(constructed(OTHER_TAG), listOf(fields[0], sequenceOf(children)))),
            )
            cms
                .enveloped(encoded)
                .recipients
                .single()
                .isSupported shouldBe false
        }
        if (crypto.capabilities.supports(KemAlgorithm.MlKem768)) {
            val credential = Credential.Certified(certificate(KEM_RECIPIENT_CERTIFICATE), privateKey(KEM_RECIPIENT_KEY))
            cms.decryptCbc(base.enveloped, credential).value() shouldBe CONTENT
        }
    }

    test("a recovered key of the wrong size fails like a wrong key") {
        val base = EnvelopedBase(cms.envelop(CONTENT, listOf(Recipient.Kek(ByteString(1), kek()))))
        val odd = SecretBytes.copyOf(ByteArray(ODD_KEY_BYTES) { 2 })
        val recipient = KeyProtection(crypto).protect(Recipient.Kek(ByteString(1), kek()), odd)
        val decoded = cms.decodeEnveloped(base.withRecipients(listOf(recipient))).value()
        cms.decryptCbc(decoded, Credential.Kek(ByteString(1), kek())).failureOrNull() shouldBe
            CmsFailure.DecryptionFailed
    }
})
