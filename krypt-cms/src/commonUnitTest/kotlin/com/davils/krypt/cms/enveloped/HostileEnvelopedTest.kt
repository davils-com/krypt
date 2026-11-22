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
import com.davils.krypt.asn1.BitString
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.Tag
import com.davils.krypt.cms.Attribute
import com.davils.krypt.cms.Cms
import com.davils.krypt.cms.CmsFailure
import com.davils.krypt.cms.CmsLimits
import com.davils.krypt.cms.ContentTypes
import com.davils.krypt.cms.fixture.CONTENT
import com.davils.krypt.cms.fixture.EC_RECIPIENT_CERTIFICATE
import com.davils.krypt.cms.fixture.EC_RECIPIENT_KEY
import com.davils.krypt.cms.fixture.ENVELOPED_EC
import com.davils.krypt.cms.fixture.ENVELOPED_KEM
import com.davils.krypt.cms.fixture.ENVELOPED_RSA
import com.davils.krypt.cms.fixture.EnvelopedBase
import com.davils.krypt.cms.fixture.KEM_RECIPIENT_CERTIFICATE
import com.davils.krypt.cms.fixture.NOW
import com.davils.krypt.cms.fixture.RSA_RECIPIENT_CERTIFICATE
import com.davils.krypt.cms.fixture.RSA_RECIPIENT_KEY
import com.davils.krypt.cms.fixture.certificate
import com.davils.krypt.cms.fixture.cms
import com.davils.krypt.cms.fixture.constructed
import com.davils.krypt.cms.fixture.contentInfo
import com.davils.krypt.cms.fixture.crypto
import com.davils.krypt.cms.fixture.decryptCbc
import com.davils.krypt.cms.fixture.der
import com.davils.krypt.cms.fixture.encryptCbc
import com.davils.krypt.cms.fixture.envelopCbc
import com.davils.krypt.cms.fixture.enveloped
import com.davils.krypt.cms.fixture.indefinite
import com.davils.krypt.cms.fixture.innerParts
import com.davils.krypt.cms.fixture.opened
import com.davils.krypt.cms.fixture.privateKey
import com.davils.krypt.cms.fixture.refusal
import com.davils.krypt.cms.fixture.sequenceOf
import com.davils.krypt.cms.fixture.tagged
import com.davils.krypt.cms.fixture.trailing
import com.davils.krypt.cms.fixture.truncated
import com.davils.krypt.cms.fixture.value
import com.davils.krypt.cms.fixture.with
import com.davils.krypt.cms.internal.AttributeCodec
import com.davils.krypt.cms.internal.CmsOids
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.SecretText
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.cryptoPolicy
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.key.SecretKey
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString

private const val KEY_BYTES: Int = 32
private const val IV_BYTES: Int = 16
private const val NONCE_BYTES: Int = 12
private const val TAG_BYTES: Long = 16
private const val SHORT_TAG_BYTES: Long = 12
private const val ITERATIONS: Int = 1_000
private const val CONTENT_INFO: Int = 2
private const val ALGORITHM: Int = 2
private const val ORIGINATOR: Int = 1
private const val DERIVATION: Int = 1
private const val KEY_ENCRYPTION: Int = 2
private const val KEM: Int = 2
private const val KDF: Int = 4
private const val KEK_LENGTH: Int = 5
private const val AGREEMENT_TAG: Int = 1
private const val KEK_TAG: Int = 2
private const val PASSWORD_TAG: Int = 3
private const val OTHER_TAG: Int = 4
private const val UNKNOWN_TAG: Int = 5
private const val WRONG_VERSION: Long = 3
private const val POINT_BYTES: Int = 4
private const val SECRET: String = "secret"
private val UNKNOWN: ObjectIdentifier = ObjectIdentifier.of("1.2.3.4")
private val KEK_ID: ByteString = ByteString(1)
private val ATTRIBUTE: Attribute = Attribute(CmsOids.CONTENT_TYPE, listOf(der { objectIdentifier(ContentTypes.Data) }))

private val fast: Cms = Cms(
    Crypto(
        environment {
            policy = cryptoPolicy {
                minimumIterations = ITERATIONS
                minimumVerifiedIterations = ITERATIONS
            }
        },
    ),
)

private fun kek(): SecretKey = SecretKey.of(SecretBytes.copyOf(ByteArray(KEY_BYTES) { 1 }))

private fun failureOf(encoded: ByteString, engine: Cms = cms): CmsFailure? {
    val decoded = engine.decodeEnveloped(encoded)
    return decoded.failureOrNull()
}

private fun oid(value: ObjectIdentifier): ByteString = der { sequence { objectIdentifier(value) } }

private fun contentInfoOf(type: ObjectIdentifier, algorithm: ByteString, content: ByteString?): ByteString = der {
    sequence {
        objectIdentifier(type)
        raw(algorithm)
        content?.let { found -> octetString(found, Tag.context(number = 0, isConstructed = false)) }
    }
}

private fun cbc(iv: ByteString): ByteString = der {
    sequence {
        objectIdentifier(CmsOids.AES256_CBC)
        octetString(iv)
    }
}

private fun gcm(nonce: ByteString, tag: Long?): ByteString = der {
    sequence {
        objectIdentifier(CmsOids.AES256_GCM)
        sequence {
            octetString(nonce)
            tag?.let { found -> integer(found) }
        }
    }
}

private fun attributes(number: Int): ByteString = tagged(constructed(number), listOf(AttributeCodec.encode(ATTRIBUTE)))

private fun withParameters(oid: ObjectIdentifier): ByteString = der {
    sequence {
        objectIdentifier(oid)
        nullValue()
    }
}

private fun originator(algorithm: ObjectIdentifier, bits: BitString): ByteString = tagged(
    constructed(0),
    listOf(tagged(constructed(1), listOf(oid(algorithm), der { bitString(bits) }))),
)

class HostileEnvelopedTest : FunSpec({
    test("broken envelopes are refused") {
        val envelope = cms.envelopCbc(CONTENT, listOf(Recipient.Kek(KEK_ID, kek())), ContentEncryption.Aes256Cbc)
        val base = EnvelopedBase(envelope)
        val encoded = envelope.encoded
        failureOf(truncated(encoded)) shouldBe CmsFailure.Malformed
        failureOf(trailing(encoded)) shouldBe CmsFailure.Malformed
        failureOf(indefinite(encoded)) shouldBe CmsFailure.Malformed
        failureOf(contentInfo(ContentTypes.SignedData, base.parts)) shouldBe CmsFailure.Malformed
        failureOf(base.withRecipients(emptyList())) shouldBe CmsFailure.Malformed
        val unknownChoice = tagged(constructed(UNKNOWN_TAG), listOf(der { nullValue() }))
        failureOf(base.withRecipients(listOf(unknownChoice))) shouldBe CmsFailure.Malformed
        val shortIv = cbc(ByteString(ByteArray(IV_BYTES - 1)))
        val withShortIv = contentInfoOf(type = ContentTypes.Data, algorithm = shortIv, content = CONTENT)
        failureOf(base.withPart(CONTENT_INFO, withShortIv)) shouldBe CmsFailure.Malformed
        cms.decodeEncrypted(encoded).failureOrNull() shouldBe CmsFailure.Malformed
        val recipient = envelope.recipients.single().encoded
        val two = base.withRecipients(listOf(recipient, recipient))
        failureOf(two, Cms(crypto, CmsLimits(maximumRecipients = 2))) shouldBe null
        failureOf(two, Cms(crypto, CmsLimits(maximumRecipients = 1))) shouldBe CmsFailure.Malformed
        failureOf(encoded, Cms(crypto, CmsLimits(maximumContentBytes = CONTENT.size))) shouldBe null
        failureOf(encoded, Cms(crypto, CmsLimits(maximumContentBytes = 1))) shouldBe CmsFailure.Malformed
    }

    test("optional parts are read and missing content is reported") {
        val envelope = cms.envelopCbc(CONTENT, listOf(Recipient.Kek(KEK_ID, kek())), ContentEncryption.Aes256Cbc)
        val base = EnvelopedBase(envelope)
        val credential = Credential.Kek(KEK_ID, kek())
        val originatorInfo = tagged(constructed(0), emptyList())
        val extended = base.withParts(listOf(base.parts[0], originatorInfo) + base.parts.drop(1) + attributes(1))
        val decoded = cms.enveloped(extended)
        decoded.unprotectedAttributes shouldBe listOf(ATTRIBUTE)
        cms.opened(decoded, credential) shouldBe CONTENT
        val algorithm = EnvelopedBase.childrenOf(base.parts[CONTENT_INFO])[1]
        val detached = contentInfoOf(type = ContentTypes.Data, algorithm = algorithm, content = null)
        cms.refusal(cms.enveloped(base.withPart(CONTENT_INFO, detached)), credential) shouldBe CmsFailure.ContentMissing
        val unknown = contentInfoOf(type = ContentTypes.Data, algorithm = oid(UNKNOWN), content = CONTENT)
        val strange = cms.enveloped(base.withPart(CONTENT_INFO, unknown))
        strange.encryption shouldBe null
        strange.toString().contains("unknown") shouldBe true
        cms.refusal(strange, credential) shouldBe CmsFailure.AlgorithmNotPermitted
        val nonce = ByteString(ByteArray(NONCE_BYTES))
        val misplaced = contentInfoOf(type = ContentTypes.Data, algorithm = gcm(nonce, TAG_BYTES), content = CONTENT)
        cms.enveloped(base.withPart(CONTENT_INFO, misplaced)).encryption shouldBe null
        val authenticated = EnvelopedBase(cms.envelop(CONTENT, listOf(Recipient.Kek(KEK_ID, kek()))))
        val gcmChildren = EnvelopedBase.childrenOf(authenticated.parts[CONTENT_INFO])
        val variants = listOf(
            gcmChildren.with(1, gcm(nonce, null)),
            gcmChildren.with(1, gcm(nonce, SHORT_TAG_BYTES)),
            gcmChildren.with(1, gcm(ByteString(ByteArray(IV_BYTES)), TAG_BYTES)),
        )
        variants.forEach { children ->
            cms.enveloped(authenticated.withPart(CONTENT_INFO, sequenceOf(children))).encryption shouldBe null
        }
        val opened = cms.enveloped(authenticated.withParts(authenticated.parts + attributes(2)))
        opened.unprotectedAttributes shouldBe listOf(ATTRIBUTE)
        opened.authenticatedAttributes shouldBe null
        cms.opened(opened, credential) shouldBe CONTENT
    }

    test("encrypted data is read strictly") {
        val encrypted = cms.encryptCbc(CONTENT, kek())
        val parts = innerParts(encrypted.encoded)
        val withAttributes = contentInfo(ContentTypes.EncryptedData, parts.with(0, der { integer(2) }) + attributes(1))
        cms.decodeEncrypted(withAttributes).value().unprotectedAttributes shouldBe listOf(ATTRIBUTE)
        val algorithm = EnvelopedBase.childrenOf(parts[1])[1]
        val detachedInfo = contentInfoOf(type = ContentTypes.Data, algorithm = algorithm, content = null)
        val detached = cms.decodeEncrypted(contentInfo(ContentTypes.EncryptedData, parts.with(1, detachedInfo))).value()
        cms.decryptCbc(detached, kek()).failureOrNull() shouldBe CmsFailure.ContentMissing
        val unknownInfo = contentInfoOf(type = ContentTypes.Data, algorithm = oid(UNKNOWN), content = CONTENT)
        val strange = cms.decodeEncrypted(contentInfo(ContentTypes.EncryptedData, parts.with(1, unknownInfo))).value()
        strange.toString().contains("unknown") shouldBe true
        cms.decryptCbc(strange, kek()).failureOrNull() shouldBe CmsFailure.AlgorithmNotPermitted
        cms.decodeEncrypted(truncated(encrypted.encoded)).failureOrNull() shouldBe CmsFailure.Malformed
    }

    test("key transport recipients are strict about versions and parameters") {
        val base = EnvelopedBase(cms.enveloped(ENVELOPED_RSA))
        val credential = Credential.Certified(certificate(RSA_RECIPIENT_CERTIFICATE), privateKey(RSA_RECIPIENT_KEY))
        val recipient = base.recipient
        failureOf(base.withRecipients(listOf(sequenceOf(recipient.with(0, der { integer(2) }))))) shouldBe
            CmsFailure.Malformed
        val sha256 = oid(CmsOids.SHA256)
        val hash = tagged(constructed(0), listOf(sha256))

        fun oaep(vararg fields: ByteString): ByteString = der {
            sequence {
                objectIdentifier(CmsOids.RSAES_OAEP)
                raw(sequenceOf(fields.toList()))
            }
        }

        fun mask(algorithm: ObjectIdentifier, digest: ByteString): ByteString =
            tagged(constructed(1), listOf(sequenceOf(listOf(der { objectIdentifier(algorithm) }, digest))))

        fun label(source: ObjectIdentifier, value: ByteString): ByteString = tagged(
            constructed(2),
            listOf(sequenceOf(listOf(der { objectIdentifier(source) }, der { octetString(value) }))),
        )
        val mgf1 = mask(CmsOids.MGF1, sha256)
        val unsupported = listOf(
            withParameters(CmsOids.RSA_ENCRYPTION),
            oaep(),
            oaep(hash, mask(CmsOids.MGF1, oid(CmsOids.SHA384))),
            oaep(hash, mask(UNKNOWN, sha256)),
            oaep(hash, mgf1, label(CmsOids.P_SPECIFIED, ByteString(1))),
            oaep(hash, mgf1, label(UNKNOWN, ByteString())),
        )
        unsupported.forEach { algorithm ->
            val changed = cms.enveloped(base.withRecipients(listOf(sequenceOf(recipient.with(ALGORITHM, algorithm)))))
            changed.recipients.single().isSupported shouldBe false
            cms.refusal(changed, credential) shouldBe CmsFailure.AlgorithmNotPermitted
            cms.refusal(changed, Credential.Password(SecretText.of(SECRET))) shouldBe CmsFailure.RecipientNotFound
        }
        val withLabel = oaep(hash, mgf1, label(CmsOids.P_SPECIFIED, ByteString()))
        val labelled = cms.enveloped(base.withRecipients(listOf(sequenceOf(recipient.with(ALGORITHM, withLabel)))))
        cms.opened(labelled, credential) shouldBe CONTENT
    }

    test("key agreement recipients are strict about their originator and algorithms") {
        val base = EnvelopedBase(cms.enveloped(ENVELOPED_EC))
        val credential = Credential.Certified(certificate(EC_RECIPIENT_CERTIFICATE), privateKey(EC_RECIPIENT_KEY))
        val recipient = base.recipient

        fun rebuilt(children: List<ByteString>): ByteString =
            base.withRecipients(listOf(tagged(constructed(AGREEMENT_TAG), children)))
        val keys = EnvelopedBase.childrenOf(recipient.last())
        val issuerSerial = tagged(constructed(0), listOf(EnvelopedBase.childrenOf(keys.first()).first()))
        val keyEncryption = EnvelopedBase.childrenOf(recipient[KEY_ENCRYPTION])
        val unsupported = listOf(
            recipient.with(ORIGINATOR, issuerSerial),
            recipient.with(KEY_ENCRYPTION, sequenceOf(keyEncryption.with(0, der { objectIdentifier(UNKNOWN) }))),
            recipient.with(KEY_ENCRYPTION, sequenceOf(keyEncryption.with(1, oid(UNKNOWN)))),
            recipient.with(KEY_ENCRYPTION, sequenceOf(listOf(keyEncryption[0]))),
        )
        unsupported.forEach { children ->
            val changed = cms.enveloped(rebuilt(children))
            changed.recipients.single().isSupported shouldBe false
            cms.refusal(changed, credential) shouldBe CmsFailure.AlgorithmNotPermitted
        }
        failureOf(rebuilt(recipient.with(0, der { integer(2) }))) shouldBe CmsFailure.Malformed
        failureOf(rebuilt(recipient.with(recipient.size - 1, sequenceOf(emptyList())))) shouldBe CmsFailure.Malformed
        val twice = sequenceOf(keys + keys)
        val many = rebuilt(recipient.with(recipient.size - 1, twice))
        failureOf(many, Cms(crypto, CmsLimits(maximumRecipients = 1))) shouldBe CmsFailure.Malformed
        val unusedBits = originator(CmsOids.EC_PUBLIC_KEY, BitString(ByteString(0), 1))
        failureOf(rebuilt(recipient.with(ORIGINATOR, unusedBits))) shouldBe CmsFailure.Malformed
        val point = BitString(ByteString(ByteArray(POINT_BYTES)))
        val garbage = cms.enveloped(rebuilt(recipient.with(ORIGINATOR, originator(CmsOids.EC_PUBLIC_KEY, point))))
        cms.refusal(garbage, credential) shouldBe CmsFailure.DecryptionFailed
        val montgomery = cms.enveloped(rebuilt(recipient.with(ORIGINATOR, originator(CmsOids.X25519, point))))
        cms.refusal(montgomery, credential) shouldBe CmsFailure.DecryptionFailed
        val ukm = tagged(constructed(1), listOf(der { octetString(ByteString(1)) }))
        val withUkm = listOf(recipient[0], recipient[1], ukm) + recipient.drop(2)
        cms.refusal(cms.enveloped(rebuilt(withUkm)), credential) shouldBe CmsFailure.DecryptionFailed
        val rsa = Credential.Certified(certificate(EC_RECIPIENT_CERTIFICATE), privateKey(RSA_RECIPIENT_KEY))
        cms.refusal(base.enveloped, rsa) shouldBe CmsFailure.DecryptionFailed
    }

    test("key-encryption-key recipients are strict") {
        val base = EnvelopedBase(cms.envelop(CONTENT, listOf(Recipient.Kek(KEK_ID, kek()))))
        val credential = Credential.Kek(KEK_ID, kek())
        val recipient = base.recipient

        fun rebuilt(children: List<ByteString>): ByteString =
            base.withRecipients(listOf(tagged(constructed(KEK_TAG), children)))
        val unknownWrap = cms.enveloped(rebuilt(recipient.with(KEY_ENCRYPTION, oid(UNKNOWN))))
        unknownWrap.recipients.single().keyIdentifier shouldBe KEK_ID
        cms.refusal(unknownWrap, credential) shouldBe CmsFailure.AlgorithmNotPermitted
        cms.refusal(unknownWrap, Credential.Kek(ByteString(2), kek())) shouldBe CmsFailure.RecipientNotFound
        val withNull = cms.enveloped(rebuilt(recipient.with(KEY_ENCRYPTION, withParameters(CmsOids.AES256_WRAP))))
        withNull.recipients.single().isSupported shouldBe false
        val dated = sequenceOf(listOf(der { octetString(KEK_ID) }, der { generalizedTime(NOW) }))
        cms.opened(cms.enveloped(rebuilt(recipient.with(1, dated))), credential) shouldBe CONTENT
        failureOf(rebuilt(recipient.with(0, der { integer(WRONG_VERSION) }))) shouldBe CmsFailure.Malformed
    }

    test("password recipients are strict") {
        val recipients = listOf(Recipient.Password(SecretText.of(SECRET), ITERATIONS))
        val password = EnvelopedBase(fast.envelop(CONTENT, recipients))
        val secret = Credential.Password(SecretText.of(SECRET))
        val fields = password.recipient

        fun rebuilt(children: List<ByteString>): ByteString =
            password.withRecipients(listOf(tagged(constructed(PASSWORD_TAG), children)))
        val derivation = EnvelopedBase.childrenOf(fields[DERIVATION])
        val parameters = EnvelopedBase.childrenOf(derivation[1])

        fun pbkdf2(vararg values: ByteString): ByteString =
            tagged(constructed(0), listOf(derivation[0], sequenceOf(values.toList())))
        val salt = parameters[0]
        val iterations = parameters[1]
        val prf = parameters[2]
        val keyLength = der { integer(IV_BYTES.toLong()) }
        val unknownKek = sequenceOf(listOf(der { objectIdentifier(UNKNOWN) }, cbc(ByteString(ByteArray(IV_BYTES)))))
        val gcmKek = sequenceOf(
            listOf(der { objectIdentifier(CmsOids.PWRI_KEK) }, gcm(ByteString(ByteArray(NONCE_BYTES)), TAG_BYTES)),
        )
        val unsupported = listOf(
            fields.filterIndexed { index, _ -> index != DERIVATION },
            fields.with(DERIVATION, tagged(constructed(0), listOf(der { objectIdentifier(UNKNOWN) }, derivation[1]))),
            fields.with(DERIVATION, pbkdf2(salt, iterations, oid(UNKNOWN))),
            fields.with(DERIVATION, pbkdf2(der { octetString(ByteString(1)) }, iterations, prf)),
            fields.with(DERIVATION, pbkdf2(salt, iterations, keyLength, prf)),
            fields.with(KEY_ENCRYPTION, unknownKek),
            fields.with(KEY_ENCRYPTION, gcmKek),
        )
        unsupported.forEach { changed ->
            val decoded = fast.enveloped(rebuilt(changed))
            decoded.recipients.single().isSupported shouldBe false
            fast.refusal(decoded, secret) shouldBe CmsFailure.AlgorithmNotPermitted
        }
        val sized = fields.with(DERIVATION, pbkdf2(salt, iterations, der { integer(KEY_BYTES.toLong()) }, prf))
        fast.opened(fast.enveloped(rebuilt(sized)), secret) shouldBe CONTENT
        val legacy = fields.with(DERIVATION, pbkdf2(salt, iterations))
        fast.refusal(fast.enveloped(rebuilt(legacy)), secret) shouldBe CmsFailure.AlgorithmNotPermitted
        failureOf(rebuilt(fields.with(0, der { integer(1) }))) shouldBe CmsFailure.Malformed
        val certified = Credential.Certified(certificate(RSA_RECIPIENT_CERTIFICATE), privateKey(RSA_RECIPIENT_KEY))
        fast.refusal(password.enveloped, certified) shouldBe CmsFailure.RecipientNotFound
    }

    test("other recipients are kept and KEM recipients are strict") {
        val base = EnvelopedBase(cms.enveloped(ENVELOPED_KEM))
        val fields = base.recipient
        val kemFields = EnvelopedBase.childrenOf(fields[1])
        val otherType = tagged(constructed(OTHER_TAG), listOf(der { objectIdentifier(UNKNOWN) }, der { nullValue() }))
        val other = cms.enveloped(base.withRecipients(listOf(otherType))).recipients.single()
        other.type shouldBe RecipientType.Other
        other.references shouldBe emptyList()

        fun kem(children: List<ByteString>): ByteString =
            base.withRecipients(listOf(tagged(constructed(OTHER_TAG), listOf(fields[0], sequenceOf(children)))))
        val credential = Credential.Kek(KEK_ID, kek())
        listOf(
            kemFields.with(KEM, oid(UNKNOWN)),
            kemFields.with(KDF, oid(UNKNOWN)),
            kemFields.with(KEK_LENGTH, der { integer(TAG_BYTES) }),
        ).forEach { children ->
            val decoded = cms.enveloped(kem(children))
            val recipient = decoded.recipients.single()
            recipient.type shouldBe RecipientType.Kem
            recipient.isSupported shouldBe false
            cms.refusal(decoded, credential) shouldBe CmsFailure.RecipientNotFound
        }
        failureOf(kem(kemFields.with(0, der { integer(1) }))) shouldBe CmsFailure.Malformed
        val ec = Credential.Certified(certificate(EC_RECIPIENT_CERTIFICATE), privateKey(EC_RECIPIENT_KEY))
        cms.refusal(base.enveloped, ec) shouldBe CmsFailure.RecipientNotFound
        val unusable = cms.enveloped(kem(kemFields.with(KEM, oid(UNKNOWN))))
        val named = Credential.Certified(certificate(KEM_RECIPIENT_CERTIFICATE), privateKey(EC_RECIPIENT_KEY))
        cms.refusal(unusable, named) shouldBe CmsFailure.AlgorithmNotPermitted
    }
})
