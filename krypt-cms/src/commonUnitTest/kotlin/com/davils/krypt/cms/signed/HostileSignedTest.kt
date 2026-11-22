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

package com.davils.krypt.cms.signed

import com.davils.kore.core.outcome.failureOrNull
import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.Tag
import com.davils.krypt.asn1.TagClass
import com.davils.krypt.cms.Attribute
import com.davils.krypt.cms.Cms
import com.davils.krypt.cms.CmsFailure
import com.davils.krypt.cms.CmsLimits
import com.davils.krypt.cms.ContentTypes
import com.davils.krypt.cms.fixture.CONTENT
import com.davils.krypt.cms.fixture.FixedClock
import com.davils.krypt.cms.fixture.NOW
import com.davils.krypt.cms.fixture.SignedBase
import com.davils.krypt.cms.fixture.cms
import com.davils.krypt.cms.fixture.constructed
import com.davils.krypt.cms.fixture.contentInfo
import com.davils.krypt.cms.fixture.crypto
import com.davils.krypt.cms.fixture.der
import com.davils.krypt.cms.fixture.indefinite
import com.davils.krypt.cms.fixture.refusal
import com.davils.krypt.cms.fixture.tagged
import com.davils.krypt.cms.fixture.trailing
import com.davils.krypt.cms.fixture.truncated
import com.davils.krypt.cms.fixture.value
import com.davils.krypt.cms.fixture.verified
import com.davils.krypt.cms.fixture.with
import com.davils.krypt.cms.internal.AttributeCodec
import com.davils.krypt.cms.internal.CmsOids
import com.davils.krypt.cms.internal.ENCODING_ORDER
import com.davils.krypt.cms.internal.concat
import com.davils.krypt.core.LegacyCryptography
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.AlgorithmUse
import com.davils.krypt.core.policy.cryptoPolicy
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.signature.Signer
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.crl.RevocationList
import com.davils.krypt.x509.crl.RevocationLists
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString
import kotlin.time.Duration.Companion.days

private const val NAME: String = "signer"
private const val KEY_IDENTIFIER_VERSION: Long = 3
private const val VERSION: Int = 0
private const val DIGEST: Int = 2
private const val SIGNED_ATTRIBUTES: Int = 3
private const val ALGORITHM: Int = 4
private const val SIGNATURE: Int = 5
private const val ENCAPSULATED: Int = 2
private const val CERTIFICATES: Int = 3
private const val DIRECTORY: Int = 4
private const val OCTET_STRING: Int = 4
private const val ATTRIBUTES: Int = 4
private val UNKNOWN: ObjectIdentifier = ObjectIdentifier.of("1.2.3.4")

private fun failureOf(encoded: ByteString, engine: Cms = cms): CmsFailure? {
    val decoded = engine.decodeSigned(encoded)
    return decoded.failureOrNull()
}

private fun attribute(type: ObjectIdentifier, vararg values: ByteString): ByteString =
    AttributeCodec.encode(Attribute(type, values.toList()))

private fun signedSet(attributes: List<ByteString>): ByteString = tagged(constructed(0), attributes)

private fun limited(limits: CmsLimits): Cms = Cms(crypto, limits)

private suspend fun revocationList(signer: Signer, certificate: Certificate): RevocationList =
    RevocationLists(crypto).issue(signer) {
        issuer = certificate.subject
        thisUpdate = NOW
        nextUpdate = NOW + 1.days
        number = DerInteger.of(1)
    }

private fun essVersion1(certificate: Certificate, hash: ByteString, serial: DerInteger): Attribute = Attribute(
    CmsOids.SIGNING_CERTIFICATE,
    listOf(
        der {
            sequence {
                sequence {
                    sequence {
                        octetString(hash)
                        sequence {
                            sequence { explicit(DIRECTORY) { raw(certificate.issuer.encoded) } }
                            integer(serial)
                        }
                    }
                }
            }
        },
    ),
)

class HostileSignedTest : FunSpec({
    test("broken encodings are refused") {
        val base = SignedBase.create()
        val encoded = base.signed.encoded
        failureOf(truncated(encoded)) shouldBe CmsFailure.Malformed
        failureOf(trailing(encoded)) shouldBe CmsFailure.Malformed
        failureOf(indefinite(encoded)) shouldBe CmsFailure.Malformed
        failureOf(ByteString()) shouldBe CmsFailure.Malformed
        failureOf(contentInfo(ContentTypes.EnvelopedData, base.parts)) shouldBe CmsFailure.Malformed
        failureOf(base.withPart(VERSION, der { integer(2) })) shouldBe CmsFailure.Malformed
        failureOf(base.withPart(VERSION, der { integer(ATTRIBUTES.toLong()) })) shouldBe CmsFailure.Malformed
        val constructedContent = der {
            sequence {
                objectIdentifier(ContentTypes.Data)
                explicit(0) {
                    constructed(Tag(TagClass.Universal, isConstructed = true, number = OCTET_STRING)) {
                        octetString(CONTENT)
                    }
                }
            }
        }
        failureOf(base.withPart(ENCAPSULATED, constructedContent)) shouldBe CmsFailure.Malformed
    }

    test("certificates and revocation lists must be what they claim") {
        val base = SignedBase.create()
        val other = tagged(constructed(1), listOf(der { nullValue() }))
        failureOf(base.withPart(CERTIFICATES, tagged(constructed(0), listOf(other)))) shouldBe CmsFailure.Malformed
        val empty = der { sequence { } }
        failureOf(base.withPart(CERTIFICATES, tagged(constructed(0), listOf(empty)))) shouldBe CmsFailure.Malformed
        failureOf(base.withExtra(tagged(constructed(1), listOf(other)))) shouldBe CmsFailure.Malformed
        failureOf(base.withExtra(tagged(constructed(1), listOf(empty)))) shouldBe CmsFailure.Malformed
    }

    test("signer infos are strict") {
        val base = SignedBase.create()
        val signer = base.signer
        failureOf(
            base.withSigner(signer.with(VERSION, der { integer(KEY_IDENTIFIER_VERSION) })),
        ) shouldBe CmsFailure.Malformed
        val digest = attribute(CmsOids.MESSAGE_DIGEST, der { octetString(ByteString(1)) })
        val contentType = attribute(CmsOids.CONTENT_TYPE, der { objectIdentifier(ContentTypes.Data) })
        val sorted = listOf(digest, contentType).sortedWith(ENCODING_ORDER)
        val unsorted = signedSet(sorted.reversed())
        failureOf(base.withSigner(signer.with(SIGNED_ATTRIBUTES, unsorted))) shouldBe CmsFailure.Malformed
        val duplicated = signedSet((sorted + contentType).sortedWith(ENCODING_ORDER))
        failureOf(base.withSigner(signer.with(SIGNED_ATTRIBUTES, duplicated))) shouldBe CmsFailure.Malformed
        failureOf(base.withSigner(signer.with(SIGNED_ATTRIBUTES, signedSet(listOf(contentType))))) shouldBe
            CmsFailure.Malformed
        val sortedValues = listOf(der { objectIdentifier(ContentTypes.Data) }, der { objectIdentifier(UNKNOWN) })
            .sortedWith(ENCODING_ORDER)
        val twoValues = AttributeCodec.encode(Attribute(CmsOids.CONTENT_TYPE, sortedValues))
        val withTwo = signedSet(listOf(twoValues, digest).sortedWith(ENCODING_ORDER))
        failureOf(base.withSigner(signer.with(SIGNED_ATTRIBUTES, withTwo))) shouldBe CmsFailure.Malformed
        failureOf(base.withSigner(signer.with(SIGNED_ATTRIBUTES, signedSet(emptyList())))) shouldBe CmsFailure.Malformed
        val valueless = der {
            sequence {
                objectIdentifier(CmsOids.SIGNING_TIME)
                setOf { }
            }
        }
        val withValueless = signedSet(listOf(valueless, digest).sortedWith(ENCODING_ORDER))
        failureOf(base.withSigner(signer.with(SIGNED_ATTRIBUTES, withValueless))) shouldBe CmsFailure.Malformed
        val badTime = attribute(CmsOids.SIGNING_TIME, der { nullValue() })
        val withBadTime = signedSet(listOf(badTime, digest).sortedWith(ENCODING_ORDER))
        failureOf(base.withSigner(signer.with(SIGNED_ATTRIBUTES, withBadTime))) shouldBe CmsFailure.Malformed
        val counter = tagged(constructed(1), listOf(attribute(CmsOids.COUNTERSIGNATURE, der { nullValue() })))
        failureOf(base.withSigner(signer + counter)) shouldBe CmsFailure.Malformed
    }

    test("unknown algorithms are kept and refused at verification") {
        val base = SignedBase.create()
        val signer = base.signer
        val unknown = der { sequence { objectIdentifier(UNKNOWN) } }
        val strange = cms.decodeSigned(base.withSigner(signer.with(ALGORITHM, unknown))).value()
        strange.signers.single().signatureAlgorithm shouldBe null
        strange.signers.single().toString() shouldBe "SignerInfo(${strange.signers.single().identifier}, , 0 counter)"
        cms.verify(strange).failureOrNull() shouldBe CmsFailure.AlgorithmNotPermitted
        val digestless = cms.decodeSigned(base.withSigner(signer.with(DIGEST, unknown))).value()
        digestless.signers.single().digestAlgorithm shouldBe null
        cms.verify(digestless).failureOrNull() shouldBe CmsFailure.AlgorithmNotPermitted
        val rsaEncryption = der {
            sequence {
                objectIdentifier(CmsOids.RSA_ENCRYPTION)
                nullValue()
            }
        }
        val pkcs1 = cms.decodeSigned(base.withSigner(signer.with(ALGORITHM, rsaEncryption))).value()
        pkcs1.signers.single().signatureAlgorithm shouldBe SignatureAlgorithm.RsaPkcs1Sha256
        cms.verify(pkcs1).failureOrNull() shouldBe CmsFailure.AlgorithmNotPermitted
        val noSignature = base.withSigner(signer.with(SIGNATURE, der { octetString(ByteString(1)) }))
        cms.verify(cms.decodeSigned(noSignature).value()).failureOrNull() shouldBe CmsFailure.BadSignature
    }

    test("signing-certificate attributes of version 1 need SHA-1 and must match") {
        val base = SignedBase.create()
        val legacy = Crypto(
            environment {
                clock = FixedClock
                policy = cryptoPolicy { acceptLegacy(DigestAlgorithm.Sha1) }
            },
        )
        val identity = base.identity
        val certificate = identity.certificate
        val hash = legacy.digests.digest(certificate.encoded, DigestAlgorithm.Sha1, AlgorithmUse.Verify)
        val good = cms.sign(CONTENT) {
            signer(identity.signer, certificate) {
                isSigningCertificateIncluded = false
                signedAttribute(essVersion1(certificate, hash, certificate.serialNumber))
            }
        }
        cms.verify(good).failureOrNull() shouldBe CmsFailure.AlgorithmNotPermitted
        Cms(legacy).verified(good).size shouldBe 1
        val wrongSerial = cms.sign(CONTENT) {
            signer(identity.signer, certificate) {
                isSigningCertificateIncluded = false
                signedAttribute(essVersion1(certificate, hash, DerInteger.of(1)))
            }
        }
        Cms(legacy).refusal(wrongSerial) shouldBe CmsFailure.AttributeMismatch
        val unknownHash = Attribute(
            CmsOids.SIGNING_CERTIFICATE_V2,
            listOf(
                der {
                    sequence {
                        sequence {
                            sequence {
                                sequence { objectIdentifier(UNKNOWN) }
                                octetString(hash)
                            }
                        }
                    }
                },
            ),
        )
        val unknown = cms.sign(CONTENT) {
            signer(identity.signer, certificate) {
                isSigningCertificateIncluded = false
                signedAttribute(unknownHash)
            }
        }
        cms.verify(unknown).failureOrNull() shouldBe CmsFailure.AlgorithmNotPermitted
    }

    test("every limit holds at its value and refuses one past it") {
        val base = SignedBase.create()
        val identity = base.identity
        val second = base.pki.issue(KeyType.P256, NAME)
        val first = revocationList(identity.signer, identity.certificate)
        val other = revocationList(second.signer, second.certificate)
        val two = cms.sign(CONTENT) {
            signer(identity.signer, identity.certificate)
            signer(second.signer, second.certificate)
            revocationLists(listOf(first, other))
        }
        val encoded = two.encoded
        failureOf(encoded, limited(CmsLimits(maximumSigners = 2))) shouldBe null
        failureOf(encoded, limited(CmsLimits(maximumSigners = 1))) shouldBe CmsFailure.Malformed
        failureOf(encoded, limited(CmsLimits(maximumCertificates = 2))) shouldBe null
        failureOf(encoded, limited(CmsLimits(maximumCertificates = 1))) shouldBe CmsFailure.Malformed
        failureOf(encoded, limited(CmsLimits(maximumRevocationLists = 2))) shouldBe null
        failureOf(encoded, limited(CmsLimits(maximumRevocationLists = 1))) shouldBe CmsFailure.Malformed
        failureOf(encoded, limited(CmsLimits(maximumAttributes = ATTRIBUTES))) shouldBe null
        failureOf(encoded, limited(CmsLimits(maximumAttributes = ATTRIBUTES - 1))) shouldBe CmsFailure.Malformed
        failureOf(encoded, limited(CmsLimits(maximumContentBytes = CONTENT.size))) shouldBe null
        failureOf(encoded, limited(CmsLimits(maximumContentBytes = CONTENT.size - 1))) shouldBe CmsFailure.Malformed
        failureOf(encoded, limited(CmsLimits(maximumBytes = encoded.size))) shouldBe null
        failureOf(encoded, limited(CmsLimits(maximumBytes = encoded.size - 1))) shouldBe CmsFailure.Malformed
        val signed = base.signed
        val target = signed.signers.single()
        val once = cms.countersign(
            signedData = signed,
            target = target,
            signer = second.signer,
            certificate = second.certificate,
        )
        val counter = once.signers
            .single()
            .countersignatures
            .single()
        val nestedAttributes = der {
            with(AttributeCodec) {
                writeAttributes(constructed(1), listOf(Attribute(CmsOids.COUNTERSIGNATURE, listOf(counter.encoded))))
            }
        }
        val nested = der { element(Tag.Sequence, concat(listOf(counter.parts.fields, nestedAttributes))) }
        val deep = cms.signedWriter.withUnsigned(
            data = signed,
            target = target,
            attribute = Attribute(CmsOids.COUNTERSIGNATURE, listOf(nested)),
        )
        failureOf(deep, limited(CmsLimits(maximumNesting = 2))) shouldBe null
        failureOf(deep, limited(CmsLimits(maximumNesting = 1))) shouldBe CmsFailure.Malformed
        val twice = cms.countersign(
            signedData = once,
            target = once.signers.single(),
            signer = second.signer,
            certificate = second.certificate,
        )
        failureOf(twice.encoded, limited(CmsLimits(maximumSigners = 1))) shouldBe CmsFailure.Malformed
    }
})
