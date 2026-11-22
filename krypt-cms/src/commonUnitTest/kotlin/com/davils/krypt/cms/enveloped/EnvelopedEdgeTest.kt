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
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.cms.Cms
import com.davils.krypt.cms.CmsFailure
import com.davils.krypt.cms.fixture.CONTENT
import com.davils.krypt.cms.fixture.EnvelopedBase
import com.davils.krypt.cms.fixture.Pki
import com.davils.krypt.cms.fixture.certificates
import com.davils.krypt.cms.fixture.cms
import com.davils.krypt.cms.fixture.constructed
import com.davils.krypt.cms.fixture.crypto
import com.davils.krypt.cms.fixture.decryptCbc
import com.davils.krypt.cms.fixture.der
import com.davils.krypt.cms.fixture.hex
import com.davils.krypt.cms.fixture.refusal
import com.davils.krypt.cms.fixture.replaced
import com.davils.krypt.cms.fixture.tagged
import com.davils.krypt.cms.fixture.value
import com.davils.krypt.cms.fixture.with
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.SecretText
import com.davils.krypt.core.algorithm.AeadAlgorithm
import com.davils.krypt.core.algorithm.KemAlgorithm
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.cryptoPolicy
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.key.SecretKey
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString

private const val NAME: String = "recipient"
private const val KEY_BYTES: Int = 32
private const val BLOCK: Int = 16
private const val ITERATIONS: Int = 1_000
private const val ENCRYPTED_KEY: Int = 3
private const val EC_PUBLIC_KEY: String = "06072a8648ce3d0201"
private const val OTHER_KEY: String = "06072a8648ce3d0209"

private fun kek(): SecretKey = SecretKey.of(SecretBytes.copyOf(ByteArray(KEY_BYTES) { 1 }))

class EnvelopedEdgeTest : FunSpec({
    test("montgomery agreement with keying material and KEM without it") {
        val pki = Pki.create()
        val ukm = "ukm".encodeToByteString()
        if (crypto.capabilities.supports(KeyType.X25519)) {
            val x25519 = pki.issue(KeyType.X25519, NAME)
            val enveloped = cms.envelop(
                CONTENT,
                listOf(Recipient.KeyAgreement(x25519.certificate, userKeyingMaterial = ukm)),
            )
            cms.decryptCbc(enveloped, x25519.credential).value() shouldBe CONTENT
        }
        if (crypto.capabilities.supports(KemAlgorithm.MlKem1024)) {
            val small = pki.issue(KeyType.MlKem768, NAME)
            val large = pki.issue(KeyType.MlKem1024, NAME)
            val enveloped = cms.envelop(CONTENT, listOf(Recipient.Kem(small.certificate)))
            cms.decryptCbc(enveloped, small.credential).value() shouldBe CONTENT
            val mismatched = Credential.Certified(small.certificate, large.pair.privateKey)
            cms.decryptCbc(enveloped, mismatched).failureOrNull() shouldBe CmsFailure.DecryptionFailed
            val large1024 = cms.envelop(CONTENT, listOf(Recipient.Kem(large.certificate)))
            large1024.recipients.single().type shouldBe RecipientType.Kem
        }
    }

    test("a recipient's certificate needs a usable key and the policy may forbid the AEAD") {
        val pki = Pki.create()
        val ec = pki.issue(KeyType.P256, NAME)
        val changed = replaced(encoded = ec.certificate.encoded, old = hex(EC_PUBLIC_KEY), new = hex(OTHER_KEY))
        val unknownKey = checkNotNull(certificates.decode(changed).getOrNull())
        shouldThrow<IllegalArgumentException> { cms.envelop(CONTENT, listOf(Recipient.KeyAgreement(unknownKey))) }
        val enveloped = cms.envelop(CONTENT, listOf(Recipient.Kek(ByteString(1), kek())))
        val strict = Cms(Crypto(environment { policy = cryptoPolicy { forbid(AeadAlgorithm.Aes256Gcm) } }))
        strict.refusal(enveloped, Credential.Kek(ByteString(1), kek())) shouldBe CmsFailure.AlgorithmNotPermitted
    }

    test("password recipients with a broken wrap fail like a wrong password") {
        val fast = Cms(
            Crypto(
                environment {
                    policy = cryptoPolicy {
                        minimumIterations = ITERATIONS
                        minimumVerifiedIterations = ITERATIONS
                    }
                },
            ),
        )
        val base = EnvelopedBase(fast.envelop(CONTENT, listOf(Recipient.Password(SecretText.of("secret"), ITERATIONS))))
        val credential = Credential.Password(SecretText.of("secret"))
        listOf(ByteString(ByteArray(BLOCK)), ByteString(ByteArray(2 * BLOCK + 1))).forEach { wrapped ->
            val fields = base.recipient.with(ENCRYPTED_KEY, der { octetString(wrapped) })
            val decoded = fast.decodeEnveloped(base.withRecipients(listOf(tagged(constructed(3), fields)))).value()
            fast.decryptCbc(decoded, credential).failureOrNull() shouldBe CmsFailure.DecryptionFailed
        }
    }
})
