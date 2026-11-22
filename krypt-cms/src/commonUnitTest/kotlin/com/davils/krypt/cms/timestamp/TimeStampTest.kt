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

package com.davils.krypt.cms.timestamp

import com.davils.kore.core.outcome.failureOrNull
import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.Tag
import com.davils.krypt.cms.Attribute
import com.davils.krypt.cms.CmsFailure
import com.davils.krypt.cms.ContentTypes
import com.davils.krypt.cms.fixture.CONTENT
import com.davils.krypt.cms.fixture.Identity
import com.davils.krypt.cms.fixture.NOW
import com.davils.krypt.cms.fixture.Pki
import com.davils.krypt.cms.fixture.cms
import com.davils.krypt.cms.fixture.crypto
import com.davils.krypt.cms.fixture.der
import com.davils.krypt.cms.fixture.value
import com.davils.krypt.cms.internal.CmsOids
import com.davils.krypt.cms.internal.TimeStampCodec
import com.davils.krypt.cms.internal.TstParts
import com.davils.krypt.cms.signed.SignatureParameters
import com.davils.krypt.cms.signed.SignedData
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.x509.extension.KeyPurposes
import com.davils.krypt.x509.extension.KeyUsage
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString

private val POLICY: ObjectIdentifier = ObjectIdentifier.of("1.3.6.1.4.1.99999.10")
private val OTHER_POLICY: ObjectIdentifier = ObjectIdentifier.of("1.3.6.1.4.1.99999.11")
private val UNKNOWN_POLICY: ObjectIdentifier = ObjectIdentifier.of("1.3.6.1.4.1.99999.12")
private const val BAD_ALGORITHM: Int = 0
private const val BAD_DATA_FORMAT: Int = 5
private const val UNACCEPTED_POLICY: Int = 15
private const val UNACCEPTED_EXTENSION: Int = 16
private const val NAME: String = "signer"

private val timeStamps: TimeStamps = TimeStamps(crypto)

private fun authority(pki: Pki, tsa: Identity): TimeStampAuthority = TimeStampAuthority(
    crypto = crypto,
    signer = tsa.signer,
    certificate = tsa.certificate,
    policy = POLICY,
    policies = setOf(OTHER_POLICY),
    accuracy = Accuracy(seconds = 1),
    chain = listOf(pki.certificate),
    digests = setOf(DigestAlgorithm.Sha256, DigestAlgorithm.Sha512),
)

private suspend fun manualToken(identity: Identity, isBound: Boolean): SignedData {
    val parts = TstParts(
        policy = POLICY,
        digest = DigestAlgorithm.Sha256,
        hashedMessage = crypto.digests.digest(CONTENT),
        serialNumber = DerInteger.of(1),
        genTime = NOW,
        accuracy = null,
        isOrdered = true,
        nonce = null,
        encoded = ByteString(),
    )
    val info = TimeStampCodec(cms.signedCodec, cms.limits).encodeTstInfo(parts, DigestAlgorithm.Sha256)
    return cms.sign(info) {
        contentType = ContentTypes.TstInfo
        signer(identity.signer, identity.certificate) { isSigningCertificateIncluded = isBound }
    }
}

class TimeStampTest : FunSpec({
    test("an authority grants tokens that verify") {
        val pki = Pki.create()
        val tsa = pki.authority()
        val authority = authority(pki, tsa)
        val request = timeStamps.request(CONTENT, digest = DigestAlgorithm.Sha512)
        val response = timeStamps.decodeResponse(authority.respond(request.encoded)).value()
        val token = timeStamps.verify(response, request, pki.parameters).value()
        token.info.genTime shouldBe NOW
        token.info.policy shouldBe POLICY
        token.info.accuracy shouldBe Accuracy(seconds = 1)
        token.info.nonce shouldBe request.nonce
        token.info.isOrdered shouldBe false
        token.signedData.certificates.toSet() shouldBe setOf(tsa.certificate, pki.certificate)
        val quiet = timeStamps.request(
            data = CONTENT,
            policy = OTHER_POLICY,
            isCertificateRequested = false,
            nonceBytes = null,
        )
        val answered = timeStamps.decodeResponse(authority.respond(quiet)).value()
        timeStamps.verify(answered, quiet, pki.parameters).failureOrNull() shouldBe CmsFailure.SignerNotFound
        val supplied = SignatureParameters(
            certificates = listOf(tsa.certificate),
            validator = pki.parameters.validator,
            validation = pki.parameters.validation,
        )
        val quietToken = timeStamps.verify(answered, quiet, supplied).value()
        quietToken.info.policy shouldBe OTHER_POLICY
        quietToken.signedData.certificates shouldBe emptyList()
    }

    test("the authority rejects what it does not accept") {
        val pki = Pki.create()
        val authority = authority(pki, pki.authority())
        val unknown = timeStamps.request(CONTENT, policy = UNKNOWN_POLICY)
        val rejected = timeStamps.decodeResponse(authority.respond(unknown)).value()
        rejected.status shouldBe TimeStampStatus.Rejection
        rejected.failures shouldBe setOf(UNACCEPTED_POLICY)
        rejected.token shouldBe null
        timeStamps.verify(rejected, unknown).failureOrNull() shouldBe CmsFailure.TimeStampRejected
        val sha384 = timeStamps.request(CONTENT, digest = DigestAlgorithm.Sha384)
        timeStamps.decodeResponse(authority.respond(sha384)).value().failures shouldBe setOf(BAD_ALGORITHM)
        timeStamps.decodeResponse(authority.respond(ByteString(1))).value().failures shouldBe setOf(BAD_DATA_FORMAT)
        val hashed = crypto.digests.digest(CONTENT)
        val imprint = der {
            sequence {
                sequence { objectIdentifier(CmsOids.SHA256) }
                octetString(hashed)
            }
        }
        val extended = der {
            sequence {
                integer(1)
                raw(imprint)
                constructed(Tag.context(number = 0, isConstructed = true)) { sequence { objectIdentifier(POLICY) } }
            }
        }
        val request = timeStamps.decodeRequest(extended).value()
        request.hasExtensions shouldBe true
        timeStamps.decodeResponse(authority.respond(request)).value().failures shouldBe setOf(UNACCEPTED_EXTENSION)
        val unknownDigest = der {
            sequence {
                integer(1)
                sequence {
                    sequence { objectIdentifier(POLICY) }
                    octetString(CONTENT)
                }
            }
        }
        val strange = timeStamps.decodeRequest(unknownDigest).value()
        strange.digest shouldBe null
        timeStamps.decodeResponse(authority.respond(strange)).value().failures shouldBe setOf(BAD_ALGORITHM)
        val granted = timeStamps.decodeResponse(authority.respond(timeStamps.request(CONTENT))).value()
        timeStamps.verify(granted, strange).failureOrNull() shouldBe CmsFailure.AlgorithmNotPermitted
    }

    test("tokens are checked against the data, the nonce, the policy and the certificate") {
        val pki = Pki.create()
        val authority = authority(pki, pki.authority())
        val request = timeStamps.request(CONTENT, isCertificateRequested = false)
        val token = checkNotNull(timeStamps.decodeResponse(authority.respond(request)).value().token)
        val parameters = TimeStampParameters(
            signature = SignatureParameters(certificates = listOf(authority.certificate)),
        )
        timeStamps.verifyToken(token, CONTENT, parameters).value() shouldBe token
        timeStamps.verifyToken(token, ByteString(1), parameters).failureOrNull() shouldBe CmsFailure.TimeStampMismatch
        val mismatches = listOf(
            TimeStampParameters(parameters.signature, nonce = DerInteger.of(1)),
            TimeStampParameters(parameters.signature, policy = OTHER_POLICY),
            TimeStampParameters(parameters.signature, isCertificateRequired = true),
        )
        mismatches.forEach { expectations ->
            timeStamps.verifyToken(token, CONTENT, expectations).failureOrNull() shouldBe CmsFailure.TimeStampMismatch
        }
        val matching = TimeStampParameters(parameters.signature, nonce = request.nonce, policy = POLICY)
        timeStamps.verifyToken(token, CONTENT, matching).value() shouldBe token
    }

    test("only a time-stamping certificate bound by ESS vouches for a time") {
        val pki = Pki.create()
        val plain = pki.issue(KeyType.P256, NAME)
        val unbound = timeStamps.decodeToken(manualToken(plain, isBound = false).encoded).value()
        timeStamps.verifyToken(unbound, CONTENT).failureOrNull() shouldBe CmsFailure.AttributeMismatch
        val bound = timeStamps.decodeToken(manualToken(plain, isBound = true).encoded).value()
        bound.info.isOrdered shouldBe true
        timeStamps.verifyToken(bound, CONTENT).failureOrNull() shouldBe CmsFailure.UnauthorizedTimeStampAuthority
        val loose = pki.issue(KeyType.P256, NAME) {
            keyUsage(setOf(KeyUsage.DigitalSignature))
            extendedKeyUsage(listOf(KeyPurposes.TimeStamping))
        }
        shouldThrow<IllegalArgumentException> { authority(pki, loose) }
        val tsa = pki.authority()
        shouldThrow<IllegalArgumentException> {
            TimeStampAuthority(crypto = crypto, signer = plain.signer, certificate = tsa.certificate, policy = POLICY)
        }
    }

    test("a signature time stamp travels as an unsigned attribute") {
        val pki = Pki.create()
        val authority = authority(pki, pki.authority())
        val identity = pki.issue(KeyType.P256, NAME)
        val signed = cms.sign(CONTENT) { signer(identity.signer, identity.certificate) }
        val signer = signed.signers.single()
        val request = timeStamps.request(signer.signature)
        val token = checkNotNull(timeStamps.decodeResponse(authority.respond(request)).value().token)
        val stamped = cms.addUnsignedAttribute(signed, signer, timeStamps.signatureTimeStamp(token))
        val stampedSigner = stamped.signers.single()
        stampedSigner.timeStampTokens shouldBe listOf(token.encoded)
        val parameters = TimeStampParameters(pki.parameters)
        timeStamps.verifySignatureTimeStamps(stampedSigner, parameters).value() shouldBe listOf(token)
        timeStamps.verifySignatureTimeStamps(signer, parameters).value() shouldBe emptyList()
        timeStamps.verifySignatureTimeStamps(stampedSigner).value() shouldBe listOf(token)
        cms.verify(stamped, parameters = pki.parameters).value().size shouldBe 1
        val foreignResponse = authority.respond(timeStamps.request("other".encodeToByteString()))
        val foreign = checkNotNull(timeStamps.decodeResponse(foreignResponse).value().token)
        val wrong = cms.addUnsignedAttribute(signed, signer, timeStamps.signatureTimeStamp(foreign))
        timeStamps.verifySignatureTimeStamps(wrong.signers.single(), parameters).failureOrNull() shouldBe
            CmsFailure.TimeStampMismatch
        val garbage = cms.addUnsignedAttribute(
            signed,
            signer,
            Attribute(CmsOids.TIME_STAMP_TOKEN, listOf(der { nullValue() })),
        )
        timeStamps.verifySignatureTimeStamps(garbage.signers.single(), parameters).failureOrNull() shouldBe
            CmsFailure.Malformed
    }

    test("requests check their nonce size") {
        shouldThrow<IllegalArgumentException> {
            timeStamps.request(
                CONTENT,
                nonceBytes = TimeStamps.MINIMUM_NONCE_SIZE - 1,
            )
        }
        shouldThrow<IllegalArgumentException> {
            timeStamps.request(
                CONTENT,
                nonceBytes = TimeStamps.MAXIMUM_NONCE_SIZE + 1,
            )
        }
        timeStamps.request(CONTENT, nonceBytes = TimeStamps.MAXIMUM_NONCE_SIZE).nonce?.isNegative shouldBe false
    }
})
