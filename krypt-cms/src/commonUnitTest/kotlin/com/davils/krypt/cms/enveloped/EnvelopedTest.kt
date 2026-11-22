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
import com.davils.krypt.cms.Cms
import com.davils.krypt.cms.CmsFailure
import com.davils.krypt.cms.CmsLimits
import com.davils.krypt.cms.ContentTypes
import com.davils.krypt.cms.fixture.CONTENT
import com.davils.krypt.cms.fixture.Pki
import com.davils.krypt.cms.fixture.cms
import com.davils.krypt.cms.fixture.crypto
import com.davils.krypt.cms.fixture.decryptCbc
import com.davils.krypt.cms.fixture.encryptCbc
import com.davils.krypt.cms.fixture.envelopCbc
import com.davils.krypt.cms.fixture.flipped
import com.davils.krypt.cms.fixture.replaced
import com.davils.krypt.cms.fixture.value
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.SecretText
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.KdfAlgorithm
import com.davils.krypt.core.algorithm.KemAlgorithm
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.algorithm.KeyWrapAlgorithm
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.cryptoPolicy
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.PolicyViolationException
import com.davils.krypt.primitive.key.SecretKey
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString

private const val NAME: String = "recipient"
private const val SECRET: String = "secret"
private const val PASSWORD_VERSION: Int = 3
private const val ITERATIONS: Int = 1_000
private const val STRICT_ITERATIONS: Int = 2_000
private const val KEK_BYTES: Int = 32
private const val SHORT_KEK_BYTES: Int = 16

private val fast: Crypto = Crypto(
    environment {
        policy = cryptoPolicy {
            minimumIterations = ITERATIONS
            minimumVerifiedIterations = ITERATIONS
        }
    },
)

private fun kek(size: Int, fill: Int = 1): SecretKey = SecretKey.of(
    SecretBytes.copyOf(ByteArray(size) { fill.toByte() }),
)

class EnvelopedTest : FunSpec({
    val quick = Cms(fast)

    test("every kind of recipient opens what krypt envelops, with AES-CBC and AES-GCM") {
        val pki = Pki.create()
        val rsa = pki.issue(KeyType.Rsa3072, NAME)
        val p256 = pki.issue(KeyType.P256, NAME)
        val p384 = pki.issue(KeyType.P384, NAME)
        val supported = listOf(KeyType.X25519, KeyType.X448).filter { type -> crypto.capabilities.supports(type) }
        val montgomery = supported.map { type -> pki.issue(type, NAME) }
        val kem = pki.takeIf { crypto.capabilities.supports(KemAlgorithm.MlKem768) }?.issue(KeyType.MlKem768, NAME)
        val ukm = "ukm".encodeToByteString()
        val recipients = listOfNotNull(
            Recipient.KeyTransport(rsa.certificate),
            Recipient.KeyAgreement(p256.certificate, isKeyIdentifierUsed = true, userKeyingMaterial = ukm),
            Recipient.KeyAgreement(p384.certificate, digest = DigestAlgorithm.Sha384, wrap = KeyWrapAlgorithm.Aes128Kw),
            Recipient.Kek(ByteString(1), kek(KEK_BYTES)),
            Recipient.Kek(ByteString(2), kek(SHORT_KEK_BYTES)),
            Recipient.Password(SecretText.of(SECRET), ITERATIONS),
            kem?.let { found ->
                Recipient.Kem(
                    found.certificate,
                    isKeyIdentifierUsed = true,
                    userKeyingMaterial = ukm,
                )
            },
        ) +
            montgomery.map { found -> Recipient.KeyAgreement(found.certificate, digest = DigestAlgorithm.Sha512) }
        val credentials = listOfNotNull(
            rsa.credential,
            p256.credential,
            p384.credential,
            Credential.Kek(ByteString(1), kek(KEK_BYTES)),
            Credential.Kek(ByteString(2), kek(SHORT_KEK_BYTES)),
            Credential.Password(SecretText.of(SECRET)),
            kem?.credential,
        ) +
            montgomery.map { found -> found.credential }
        ContentEncryption.entries.forEach { encryption ->
            val enveloped = quick.envelopCbc(CONTENT, recipients, encryption)
            enveloped.isAuthenticated shouldBe encryption.isAuthenticated
            enveloped.recipients.size shouldBe recipients.size
            credentials.forEach { credential -> quick.decryptCbc(enveloped, credential).value() shouldBe CONTENT }
        }
    }

    test("versions follow RFC 5652") {
        val pki = Pki.create()
        val rsa = pki.issue(KeyType.Rsa3072, NAME)
        val transport = cms.envelopCbc(
            CONTENT,
            listOf(Recipient.KeyTransport(rsa.certificate)),
            ContentEncryption.Aes128Cbc,
        )
        transport.version shouldBe 0
        val keyed = Recipient.KeyTransport(rsa.certificate, isKeyIdentifierUsed = true)
        cms.envelopCbc(CONTENT, listOf(keyed), ContentEncryption.Aes128Cbc).version shouldBe 2
        val password = Recipient.Password(SecretText.of(SECRET), ITERATIONS)
        quick.envelopCbc(CONTENT, listOf(password), ContentEncryption.Aes128Cbc).version shouldBe PASSWORD_VERSION
        cms.envelop(CONTENT, listOf(keyed)).version shouldBe 0
        val typed = cms.envelop(CONTENT, listOf(keyed), contentType = ContentTypes.SignedData)
        typed.contentType shouldBe ContentTypes.SignedData
        typed.authenticatedAttributes?.size shouldBe 1
        cms.decryptCbc(typed, rsa.credential).value() shouldBe CONTENT
    }

    test("wrong keys, passwords and tags fail alike") {
        val pki = Pki.create()
        val rsa = pki.issue(KeyType.Rsa3072, NAME)
        val ec = pki.issue(KeyType.P256, NAME)
        val recipients = listOf(
            Recipient.KeyTransport(rsa.certificate),
            Recipient.KeyAgreement(ec.certificate),
            Recipient.Kek(ByteString(1), kek(KEK_BYTES)),
            Recipient.Password(SecretText.of(SECRET), ITERATIONS),
        )
        val enveloped = quick.envelop(CONTENT, recipients)
        val other = pki.issue(KeyType.Rsa3072, NAME)
        val impostor = Credential.Certified(rsa.certificate, other.pair.privateKey)
        val wrongCurve = Credential.Certified(ec.certificate, other.pair.privateKey)
        quick.decryptCbc(enveloped, impostor).failureOrNull() shouldBe CmsFailure.DecryptionFailed
        quick.decryptCbc(enveloped, wrongCurve).failureOrNull() shouldBe CmsFailure.DecryptionFailed
        quick.decryptCbc(enveloped, Credential.Kek(ByteString(1), kek(KEK_BYTES, fill = 2))).failureOrNull() shouldBe
            CmsFailure.DecryptionFailed
        quick.decryptCbc(enveloped, Credential.Kek(ByteString(1), kek(SHORT_KEK_BYTES))).failureOrNull() shouldBe
            CmsFailure.DecryptionFailed
        quick.decryptCbc(enveloped, Credential.Password(SecretText.of("wrong"))).failureOrNull() shouldBe
            CmsFailure.DecryptionFailed
        quick.decryptCbc(enveloped, Credential.Kek(ByteString(2), kek(KEK_BYTES))).failureOrNull() shouldBe
            CmsFailure.RecipientNotFound
        val mac = enveloped.parts.mac
        val forged = cms.decodeEnveloped(replaced(encoded = enveloped.encoded, old = mac, new = flipped(mac))).value()
        quick.decryptCbc(forged, rsa.credential).failureOrNull() shouldBe CmsFailure.DecryptionFailed
        val ciphertext = checkNotNull(enveloped.encryptedContent)
        val tampered = replaced(encoded = enveloped.encoded, old = ciphertext, new = flipped(ciphertext))
        val changed = cms.decodeEnveloped(tampered).value()
        quick.decryptCbc(changed, rsa.credential).failureOrNull() shouldBe CmsFailure.DecryptionFailed
    }

    test("the policy bounds passwords and algorithms") {
        val password = Recipient.Password(SecretText.of(SECRET), ITERATIONS)
        shouldThrow<PolicyViolationException> { cms.envelop(CONTENT, listOf(password)) }
        val enveloped = quick.envelop(CONTENT, listOf(password, Recipient.Kek(ByteString(1), kek(KEK_BYTES))))
        val strict = Cms(
            Crypto(environment { policy = cryptoPolicy { minimumVerifiedIterations = STRICT_ITERATIONS } }),
        )
        strict.decryptCbc(enveloped, Credential.Password(SecretText.of(SECRET))).failureOrNull() shouldBe
            CmsFailure.AlgorithmNotPermitted
        shouldThrow<IllegalArgumentException> {
            Recipient.Password(
                SecretText.of("x"),
                ITERATIONS,
                KdfAlgorithm.HkdfSha256,
            )
        }
        shouldThrow<IllegalArgumentException> {
            Recipient.Kem(
                Pki.create().certificate,
                kdf = KdfAlgorithm.Pbkdf2Sha256,
            )
        }
        shouldThrow<IllegalArgumentException> { Recipient.Kek(ByteString(1), kek(KEK_BYTES - 1)) }
    }

    test("recipients refuse keys of another kind and the limits hold") {
        val pki = Pki.create()
        val ec = pki.issue(KeyType.P256, NAME)
        val ed = pki.issue(KeyType.Ed25519, NAME)
        shouldThrow<IllegalArgumentException> { cms.envelop(CONTENT, listOf(Recipient.KeyTransport(ec.certificate))) }
        shouldThrow<IllegalArgumentException> { cms.envelop(CONTENT, listOf(Recipient.KeyAgreement(ed.certificate))) }
        shouldThrow<IllegalArgumentException> { cms.envelop(CONTENT, listOf(Recipient.Kem(ec.certificate))) }
        shouldThrow<IllegalArgumentException> {
            cms.envelop(CONTENT, listOf(Recipient.KeyAgreement(ec.certificate, digest = DigestAlgorithm.Sha3256)))
        }
        shouldThrow<IllegalArgumentException> { cms.envelop(CONTENT, emptyList()) }
        val small = Cms(crypto, CmsLimits(maximumContentBytes = 1, maximumRecipients = 1))
        val kekRecipient = Recipient.Kek(ByteString(1), kek(KEK_BYTES))
        shouldThrow<IllegalArgumentException> { small.envelop(CONTENT, listOf(kekRecipient)) }
        shouldThrow<IllegalArgumentException> { small.envelop(ByteString(1), listOf(kekRecipient, kekRecipient)) }
        small
            .envelop(ByteString(1), listOf(kekRecipient))
            .recipients
            .single()
            .keyIdentifier shouldBe ByteString(1)
    }

    test("encrypted data with a caller key") {
        val key = kek(KEK_BYTES)
        val encrypted = cms.encryptCbc(CONTENT, key)
        encrypted.version shouldBe 0
        encrypted.contentType shouldBe ContentTypes.Data
        encrypted.unprotectedAttributes shouldBe emptyList()
        cms.decryptCbc(cms.decodeEncrypted(encrypted.encoded).value(), key).value() shouldBe CONTENT
        cms.decryptCbc(encrypted, kek(KEK_BYTES, fill = 2)).failureOrNull() shouldBe CmsFailure.DecryptionFailed
        cms.decryptCbc(encrypted, kek(SHORT_KEK_BYTES)).failureOrNull() shouldBe CmsFailure.DecryptionFailed
        shouldThrow<IllegalArgumentException> { cms.encryptCbc(CONTENT, key, ContentEncryption.Aes256Gcm) }
        shouldThrow<IllegalArgumentException> { cms.encryptCbc(CONTENT, key, ContentEncryption.Aes128Cbc) }
        val small = Cms(crypto, CmsLimits(maximumContentBytes = 1))
        shouldThrow<IllegalArgumentException> { small.encryptCbc(CONTENT, key) }
    }
})
