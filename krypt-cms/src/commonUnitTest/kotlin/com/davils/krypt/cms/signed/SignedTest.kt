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

package com.davils.krypt.cms.signed

import com.davils.kore.core.outcome.failureOrNull
import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.cms.Attribute
import com.davils.krypt.cms.CertificateReference
import com.davils.krypt.cms.Cms
import com.davils.krypt.cms.CmsFailure
import com.davils.krypt.cms.CmsLimits
import com.davils.krypt.cms.ContentTypes
import com.davils.krypt.cms.fixture.CONTENT
import com.davils.krypt.cms.fixture.FixedClock
import com.davils.krypt.cms.fixture.NOW
import com.davils.krypt.cms.fixture.Pki
import com.davils.krypt.cms.fixture.cms
import com.davils.krypt.cms.fixture.crypto
import com.davils.krypt.cms.fixture.der
import com.davils.krypt.cms.fixture.flipped
import com.davils.krypt.cms.fixture.replaced
import com.davils.krypt.cms.fixture.value
import com.davils.krypt.cms.fixture.verified
import com.davils.krypt.cms.internal.CmsOids
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.CryptoProfile
import com.davils.krypt.core.policy.cryptoPolicy
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.PolicyViolationException
import com.davils.krypt.x509.crl.RevocationLists
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString
import kotlin.time.Duration.Companion.days

private const val NAME: String = "signer"
private const val KEY_IDENTIFIER_VERSION: Int = 3
private const val CERTIFICATES: Int = 3
private const val SMALL_ATTRIBUTES: Int = 3
private const val SIGNED_ATTRIBUTES: Int = 4

class SignedTest : FunSpec({
    test("every algorithm krypt and the platform offer signs and verifies") {
        val pki = Pki.create()
        val types = listOf(KeyType.P256, KeyType.P384, KeyType.Ed25519, KeyType.Ed448, KeyType.MlDsa44)
        types.forEach { type ->
            val isSupported = crypto.capabilities.supports(type)
            val identity = pki.takeIf { isSupported }?.issue(type, NAME)
            identity?.let { found ->
                val isEd448 = type == KeyType.Ed448
                val signed = cms.sign(CONTENT) {
                    signer(found.signer, found.certificate) { isSignedAttributesUsed = !isEd448 }
                }
                val verified = cms.verified(signed, parameters = pki.parameters).single()
                verified.certificate shouldBe found.certificate
                val attributes = signed.signers.single().signedAttributes
                attributes?.size shouldBe listOf(SIGNED_ATTRIBUTES, null)[isEd448.compareTo(false)]
            }
        }
    }

    test("RSA-PSS and, where the policy permits it, RSA PKCS #1 v1.5") {
        val pki = Pki.create()
        val rsa = pki.issue(KeyType.Rsa3072, NAME)
        val pss = crypto.signatures.signer(rsa.pair.privateKey, SignatureAlgorithm.RsaPssSha512)
        val signed = cms.sign(CONTENT) { signer(pss, rsa.certificate) }
        signed.signers.single().digestAlgorithm shouldBe DigestAlgorithm.Sha512
        cms.verify(signed, parameters = pki.parameters).value().size shouldBe 1
        val compatible = Crypto(
            environment {
                clock = FixedClock
                policy = cryptoPolicy(CryptoProfile.Compatible) { }
            },
        )
        val pkcs1 = compatible.signatures.signer(rsa.pair.privateKey, SignatureAlgorithm.RsaPkcs1Sha256)
        val legacy = Cms(compatible).sign(CONTENT) { signer(pkcs1, rsa.certificate) }
        cms.verify(legacy, parameters = pki.parameters).value().size shouldBe 1
        shouldThrow<PolicyViolationException> { cms.sign(CONTENT) { signer(pkcs1, rsa.certificate) } }
    }

    test("detached content, key identifiers, several signers, carried certificates and revocation lists") {
        val pki = Pki.create()
        val first = pki.issue(KeyType.P256, NAME)
        val second = pki.issue(KeyType.Ed25519, NAME)
        val list = RevocationLists(crypto).issue(crypto.signatures.signer(first.pair.privateKey)) {
            issuer = first.certificate.subject
            thisUpdate = NOW
            nextUpdate = NOW + 1.days
            number = DerInteger.of(1)
        }
        val signed = cms.sign(CONTENT) {
            isDetached = true
            contentType = ContentTypes.TstInfo
            signer(first.signer, first.certificate) { isKeyIdentifierUsed = true }
            signer(second.signer, second.certificate) {
                isCertificateIncluded = false
                isSigningTimeIncluded = false
                isSigningCertificateIncluded = false
                signedAttribute(Attribute(CmsOids.SIGNING_CERTIFICATE, listOf(der { sequence { sequence { } } })))
                unsignedAttribute(Attribute(CmsOids.TIME_STAMP_TOKEN, listOf(der { nullValue() })))
            }
            certificates(listOf(pki.certificate, second.certificate))
            revocationLists(listOf(list))
        }
        signed.version shouldBe KEY_IDENTIFIER_VERSION
        signed.isDetached shouldBe true
        signed.revocationLists shouldBe listOf(list)
        signed.certificates.size shouldBe CERTIFICATES
        val keyed = signed.signers.first { signer -> signer.version == KEY_IDENTIFIER_VERSION }
        keyed.identifier shouldBe CertificateReference.KeyIdentifier.of(first.certificate)
        keyed.signingTime shouldBe NOW
        val plain = signed.signers.first { signer -> signer.version == 1 }
        plain.signingTime shouldBe null
        plain.timeStampTokens shouldBe listOf(der { nullValue() })
        val keyedOutcome = cms.verifySigner(
            signedData = signed,
            signer = keyed,
            content = CONTENT,
            parameters = pki.parameters,
        )
        keyedOutcome.value().signer shouldBe keyed
        val plainOutcome = cms.verifySigner(
            signedData = signed,
            signer = plain,
            content = CONTENT,
            parameters = pki.parameters,
        )
        plainOutcome.failureOrNull() shouldBe CmsFailure.AttributeMismatch
    }

    test("tampering is caught") {
        val pki = Pki.create()
        val identity = pki.issue(KeyType.P256, NAME)
        val signed = cms.sign(CONTENT) { signer(identity.signer, identity.certificate) }
        val signer = signed.signers.single()
        cms.verify(signed, "other".encodeToByteString()).failureOrNull() shouldBe CmsFailure.DigestMismatch
        val forged = replaced(encoded = signed.encoded, old = signer.signature, new = flipped(signer.signature))
        cms.verify(cms.decodeSigned(forged).value()).failureOrNull() shouldBe CmsFailure.BadSignature
        val stranger = Pki.create()
        cms.verify(signed, parameters = stranger.parameters).failureOrNull() shouldBe CmsFailure.UntrustedSigner
        val typed = cms.sign(CONTENT) {
            contentType = ContentTypes.EncryptedData
            signer(identity.signer, identity.certificate)
        }
        val retyped = replaced(
            encoded = typed.encoded,
            old = ContentTypes.EncryptedData.content,
            new = ContentTypes.Data.content,
        )
        cms.verify(cms.decodeSigned(retyped).value()).failureOrNull() shouldBe CmsFailure.AttributeMismatch
        val other = pki.issue(KeyType.P256, NAME)
        val misbound = cms.sign(CONTENT) {
            signer(identity.signer, identity.certificate)
            certificates(listOf(other.certificate))
        }
        val bound = replaced(
            encoded = misbound.encoded,
            old = crypto.digests.digest(identity.certificate.encoded),
            new = crypto.digests.digest(other.certificate.encoded),
        )
        cms.verify(cms.decodeSigned(bound).value()).failureOrNull() shouldBe CmsFailure.AttributeMismatch
    }

    test("a missing certificate, a forbidden algorithm and no signer at all") {
        val pki = Pki.create()
        val identity = pki.issue(KeyType.P256, NAME)
        val signed = cms.sign(CONTENT) {
            signer(identity.signer, identity.certificate) { isCertificateIncluded = false }
        }
        cms.verify(signed).failureOrNull() shouldBe CmsFailure.SignerNotFound
        val supplied = SignatureParameters(certificates = listOf(identity.certificate))
        cms.verified(signed, parameters = supplied).single().path shouldBe null
        val strict = Cms(Crypto(environment { policy = cryptoPolicy { forbid(SignatureAlgorithm.EcdsaSha256) } }))
        strict.verify(signed, parameters = supplied).failureOrNull() shouldBe CmsFailure.AlgorithmNotPermitted
        val digestless = Cms(Crypto(environment { policy = cryptoPolicy { forbid(DigestAlgorithm.Sha256) } }))
        digestless.verify(signed, parameters = supplied).failureOrNull() shouldBe CmsFailure.AlgorithmNotPermitted
    }

    test("countersignatures and unsigned attributes") {
        val pki = Pki.create()
        val identity = pki.issue(KeyType.P256, NAME)
        val counter = pki.issue(KeyType.Ed25519, NAME)
        val signed = cms.sign(CONTENT) { signer(identity.signer, identity.certificate) }
        val target = signed.signers.single()
        val countersigned = cms.countersign(
            signedData = signed,
            target = target,
            signer = counter.signer,
            certificate = counter.certificate,
        )
        val twice = cms.countersign(
            signedData = countersigned,
            target = countersigned.signers.single(),
            signer = counter.signer,
            certificate = counter.certificate,
        ) {
            isCertificateIncluded = false
        }
        val countered = twice.signers.single()
        countered.countersignatures.size shouldBe 2
        cms.verified(twice, parameters = pki.parameters).size shouldBe 1
        countered.countersignatures.forEach { countersignature ->
            countersignature.contentType shouldBe null
            val outcome = cms.verifyCountersignature(
                signedData = twice,
                target = countered,
                countersignature = countersignature,
                parameters = pki.parameters,
            )
            outcome.value().signer shouldBe countersignature
        }
        val wrongTarget = countered.countersignatures.first()
        val wrong = cms.verifyCountersignature(
            signedData = twice,
            target = wrongTarget,
            countersignature = wrongTarget,
            parameters = pki.parameters,
        )
        wrong.failureOrNull() shouldBe CmsFailure.DigestMismatch
        val annotated = cms.addUnsignedAttribute(
            twice,
            countered,
            Attribute(CmsOids.TIME_STAMP_TOKEN, listOf(CONTENT_VALUE)),
        )
        annotated.signers.single().timeStampTokens shouldBe listOf(CONTENT_VALUE)
        shouldThrow<IllegalArgumentException> { cms.addUnsignedAttribute(signed, countered, ATTRIBUTE) }
    }

    test("signing refuses what it cannot write") {
        val pki = Pki.create()
        val identity = pki.issue(KeyType.P256, NAME)
        val other = pki.issue(KeyType.P256, NAME)
        shouldThrow<IllegalArgumentException> { cms.sign(CONTENT) { } }
        shouldThrow<IllegalArgumentException> { cms.sign(CONTENT) { signer(identity.signer, other.certificate) } }
        shouldThrow<IllegalArgumentException> {
            cms.sign(CONTENT) { signer(identity.signer, identity.certificate) { signedAttribute(SIGNING_TIME) } }
        }
        shouldThrow<IllegalArgumentException> {
            cms.sign(CONTENT) { signer(identity.signer, pki.certificate) { isKeyIdentifierUsed = true } }
        }
        val small = Cms(
            crypto,
            CmsLimits(maximumContentBytes = 1, maximumAttributes = SMALL_ATTRIBUTES),
        )
        shouldThrow<IllegalArgumentException> { small.sign(CONTENT) { signer(identity.signer, identity.certificate) } }
        shouldThrow<IllegalArgumentException> {
            small.sign(ByteString(1)) { signer(identity.signer, identity.certificate) }
        }
        shouldThrow<IllegalArgumentException> {
            small.sign(ByteString(1)) {
                signer(identity.signer, identity.certificate) {
                    isSigningTimeIncluded = false
                    repeat(
                        times = 4,
                    ) { index ->
                        unsignedAttribute(
                            Attribute(CmsOids.TIME_STAMP_TOKEN, listOf(der { integer(index.toLong()) })),
                        )
                    }
                }
            }
        }
        if (crypto.capabilities.supports(KeyType.Ed448)) {
            val ed448 = pki.issue(KeyType.Ed448, NAME)
            shouldThrow<IllegalArgumentException> { cms.sign(CONTENT) { signer(ed448.signer, ed448.certificate) } }
        }
    }
})

private val CONTENT_VALUE: ByteString = der { octetString(CONTENT) }

private val ATTRIBUTE: Attribute = Attribute(CmsOids.TIME_STAMP_TOKEN, listOf(CONTENT_VALUE))

private val SIGNING_TIME: Attribute = Attribute(CmsOids.SIGNING_TIME, listOf(der { time(NOW) }))
