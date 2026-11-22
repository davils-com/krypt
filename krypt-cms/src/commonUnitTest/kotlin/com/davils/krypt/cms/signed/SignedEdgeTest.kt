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
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.Tag
import com.davils.krypt.cms.Attribute
import com.davils.krypt.cms.Cms
import com.davils.krypt.cms.CmsFailure
import com.davils.krypt.cms.CmsLimits
import com.davils.krypt.cms.fixture.CONTENT
import com.davils.krypt.cms.fixture.SignedBase
import com.davils.krypt.cms.fixture.certificates
import com.davils.krypt.cms.fixture.cms
import com.davils.krypt.cms.fixture.crypto
import com.davils.krypt.cms.fixture.der
import com.davils.krypt.cms.fixture.hex
import com.davils.krypt.cms.fixture.refusal
import com.davils.krypt.cms.fixture.replaced
import com.davils.krypt.cms.fixture.tagged
import com.davils.krypt.cms.fixture.value
import com.davils.krypt.cms.fixture.verified
import com.davils.krypt.cms.fixture.with
import com.davils.krypt.cms.internal.CmsOids
import com.davils.krypt.core.algorithm.EllipticCurve
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.CryptoPolicyBuilder
import com.davils.krypt.core.policy.CryptoProfile
import com.davils.krypt.core.policy.cryptoPolicy
import com.davils.krypt.primitive.Crypto
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString

private const val NAME: String = "signer"
private const val STRICT_RSA_BITS: Int = 3_072
private const val SIGNERS: Int = 4
private const val DIGEST: Int = 2
private const val ALGORITHM: Int = 4
private const val ATTRIBUTES: Int = 4
private const val DIRECTORY: Int = 4
private const val EC_PUBLIC_KEY: String = "06072a8648ce3d0201"
private const val OTHER_KEY: String = "06072a8648ce3d0209"

private fun policy(configure: CryptoPolicyBuilder.() -> Unit): Cms =
    Cms(Crypto(environment { policy = cryptoPolicy(configure = configure) }))

class SignedEdgeTest : FunSpec({
    test("signed data without signers and signers beyond the limits") {
        val base = SignedBase.create()
        val empty = cms.decodeSigned(base.withPart(SIGNERS, tagged(Tag.Set, emptyList()))).value()
        cms.verify(empty).failureOrNull() shouldBe CmsFailure.SignerNotFound
        val identity = base.identity
        val small = Cms(crypto, CmsLimits(maximumSigners = 1, maximumAttributes = ATTRIBUTES))
        shouldThrow<IllegalArgumentException> {
            small.sign(CONTENT) {
                signer(identity.signer, identity.certificate)
                signer(identity.signer, identity.certificate)
            }
        }
        var signed = small.sign(CONTENT) { signer(identity.signer, identity.certificate) }
        repeat(ATTRIBUTES) { index ->
            val type = ObjectIdentifier.of("1.2.3.${index + 1}")
            signed = small.addUnsignedAttribute(
                signed,
                signed.signers.single(),
                Attribute(type, listOf(der { nullValue() })),
            )
        }
        shouldThrow<IllegalArgumentException> {
            small.addUnsignedAttribute(
                signed,
                signed.signers.single(),
                Attribute(ObjectIdentifier.of("1.2.4"), listOf(der { nullValue() })),
            )
        }
    }

    test("keys and algorithms the policy or krypt cannot use") {
        val base = SignedBase.create()
        val identity = base.identity
        val certificate = identity.certificate
        val changed = replaced(encoded = certificate.encoded, old = hex(EC_PUBLIC_KEY), new = hex(OTHER_KEY))
        val unknownKey = checkNotNull(certificates.decode(changed).getOrNull())
        unknownKey.publicKey shouldBe null
        val withoutCertificate = cms.sign(CONTENT) {
            signer(identity.signer, certificate) { isCertificateIncluded = false }
        }
        val unusable = SignatureParameters(certificates = listOf(unknownKey))
        cms.refusal(withoutCertificate, parameters = unusable) shouldBe CmsFailure.AlgorithmNotPermitted
        val curves = policy { curves(EllipticCurve.P384) }
        curves.refusal(base.signed) shouldBe CmsFailure.AlgorithmNotPermitted
        val compatible = Crypto(environment { policy = cryptoPolicy(CryptoProfile.Compatible) { } })
        val rsa = base.pki.issue(KeyType.Rsa2048, NAME, generator = compatible)
        val rsaSigner = compatible.signatures.signer(rsa.pair.privateKey)
        val rsaSigned = Cms(compatible).sign(CONTENT) { signer(rsaSigner, rsa.certificate) }
        cms.verified(rsaSigned).size shouldBe 1
        val strict = policy { minimumVerifiedRsaBits = STRICT_RSA_BITS }
        strict.verify(rsaSigned).failureOrNull() shouldBe CmsFailure.AlgorithmNotPermitted
        val sha384 = der { sequence { objectIdentifier(CmsOids.SHA384) } }
        val inconsistent = cms.decodeSigned(base.withSigner(base.signer.with(DIGEST, sha384))).value()
        cms.verify(inconsistent).failureOrNull() shouldBe CmsFailure.AlgorithmNotPermitted
        val ed25519 = der { sequence { objectIdentifier(ObjectIdentifier.of("1.3.101.112")) } }
        val mismatched = cms.decodeSigned(base.withSigner(base.signer.with(ALGORITHM, ed25519))).value()
        cms.verify(mismatched).failureOrNull() shouldBe CmsFailure.AlgorithmNotPermitted
        val digestWithParameters = der {
            sequence {
                objectIdentifier(CmsOids.SHA256)
                integer(1)
            }
        }
        val withParameters = cms.decodeSigned(base.withSigner(base.signer.with(DIGEST, digestWithParameters))).value()
        withParameters.signers.single().digestAlgorithm shouldBe null
    }

    test("an EdDSA signer with signed attributes needs a digest krypt knows") {
        val base = SignedBase.create()
        val ed25519 = base.pki.issue(KeyType.Ed25519, NAME)
        val signed = cms.sign(CONTENT) { signer(ed25519.signer, ed25519.certificate) }
        val signer = signed.signers.single()
        cms.verifySigner(signed, signer).value().certificate shouldBe ed25519.certificate
        val fields = SignedBase.elementsOf(signer.encoded)
        val unknown = der { sequence { objectIdentifier(ObjectIdentifier.of("1.2.3.4")) } }
        val other = SignedBase(base.pki, ed25519, signed)
        val changed = cms.decodeSigned(other.withSigner(fields.with(DIGEST, unknown))).value()
        cms.verify(changed).failureOrNull() shouldBe CmsFailure.AlgorithmNotPermitted
        val countersigned = cms.countersign(
            signedData = signed,
            target = signer,
            signer = base.identity.signer,
            certificate = base.identity.certificate,
        )
        val target = countersigned.signers.single()
        cms.verifyCountersignature(countersigned, target, target.countersignatures.single()).value().signer shouldBe
            target.countersignatures.single()
    }

    test("signing-certificate attributes with and without issuer and serial") {
        val base = SignedBase.create()
        val identity = base.identity
        val certificate = identity.certificate
        val hash = crypto.digests.digest(certificate.encoded)

        fun ess(vararg names: ByteString, withSerial: Boolean = true) = Attribute(
            CmsOids.SIGNING_CERTIFICATE_V2,
            listOf(
                der {
                    sequence {
                        sequence {
                            sequence {
                                octetString(hash)
                                if (withSerial) {
                                    sequence {
                                        sequence { names.forEach { name -> explicit(DIRECTORY) { raw(name) } } }
                                        integer(certificate.serialNumber)
                                    }
                                }
                            }
                        }
                    }
                },
            ),
        )

        suspend fun signedWith(attribute: Attribute) = cms.sign(CONTENT) {
            signer(identity.signer, certificate) {
                isSigningCertificateIncluded = false
                signedAttribute(attribute)
            }
        }
        cms.verify(signedWith(ess(withSerial = false))).value().size shouldBe 1
        val otherIssuer = certificate.subject.encoded
        cms.verify(signedWith(ess(otherIssuer))).failureOrNull() shouldBe CmsFailure.AttributeMismatch
        val both = signedWith(ess(otherIssuer, certificate.issuer.encoded))
        cms.verify(both).value().size shouldBe 1
        val few = Cms(crypto, CmsLimits(maximumCertificates = 1))
        few.refusal(both) shouldBe CmsFailure.AttributeMismatch
        val empty = Attribute(CmsOids.SIGNING_CERTIFICATE_V2, listOf(der { sequence { sequence { } } }))
        cms.verify(signedWith(empty)).failureOrNull() shouldBe CmsFailure.AttributeMismatch
    }
})
