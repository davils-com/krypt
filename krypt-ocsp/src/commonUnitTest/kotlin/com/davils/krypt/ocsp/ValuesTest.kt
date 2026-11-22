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

package com.davils.krypt.ocsp

import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.EllipticCurve
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.cryptoPolicy
import com.davils.krypt.ocsp.fixture.Authority
import com.davils.krypt.ocsp.fixture.NOW
import com.davils.krypt.ocsp.fixture.SHA256_BYTES
import com.davils.krypt.ocsp.fixture.Scenario
import com.davils.krypt.ocsp.fixture.filled
import com.davils.krypt.ocsp.fixture.ocsp
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.x509.Certificates
import com.davils.krypt.x509.RevocationReason
import com.davils.krypt.x509.extension.Extension
import com.davils.krypt.x509.extension.ExtensionIds
import com.davils.krypt.x509.path.TrustAnchor
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import kotlinx.io.bytestring.ByteString
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes

private fun idOf(
    serial: Long = 1L,
    nameHash: ByteString = filled(SHA256_BYTES),
    algorithm: DigestAlgorithm = DigestAlgorithm.Sha256,
): CertId = CertId(
    hashAlgorithm = algorithm,
    issuerNameHash = nameHash,
    issuerKeyHash = filled(algorithm.outputBytes),
    serialNumber = DerInteger.of(serial),
)

private const val SHA384_BYTES: Int = 48

class ValuesTest : FunSpec({
    test("identifiers and answers compare every field") {
        val id = idOf()
        id shouldBe idOf()
        id.hashCode() shouldBe idOf().hashCode()
        id shouldNotBe idOf(serial = 2L)
        id shouldNotBe idOf(nameHash = ByteString(ByteArray(SHA256_BYTES) { 1 }))
        id shouldNotBe idOf(nameHash = filled(SHA384_BYTES), algorithm = DigestAlgorithm.Sha384)
        id shouldNotBe "id"
        id.toString() shouldContain "SHA-256"
        shouldThrow<IllegalArgumentException> { idOf(nameHash = filled(1)) }
        shouldThrow<IllegalArgumentException> {
            CertId(
                hashAlgorithm = DigestAlgorithm.Sha256,
                issuerNameHash = filled(SHA256_BYTES),
                issuerKeyHash = filled(1),
                serialNumber = DerInteger.of(1L),
            )
        }
        shouldThrow<IllegalArgumentException> {
            CertId(
                hashAlgorithm = DigestAlgorithm.Sha3256,
                issuerNameHash = filled(SHA256_BYTES),
                issuerKeyHash = filled(SHA256_BYTES),
                serialNumber = DerInteger.of(1L),
            )
        }
        val answer = SingleResponse(certId = id, status = CertificateStatus.Good, thisUpdate = NOW)
        answer shouldBe SingleResponse(certId = id, status = CertificateStatus.Good, thisUpdate = NOW)
        answer.hashCode() shouldBe id.hashCode()
        answer shouldNotBe SingleResponse(certId = id, status = CertificateStatus.Unknown, thisUpdate = NOW)
        answer shouldNotBe SingleResponse(
            certId = id,
            status = CertificateStatus.Good,
            thisUpdate = NOW,
            nextUpdate = NOW,
        )
        answer shouldNotBe "answer"
        answer.toString() shouldContain "nextUpdate=none"
        SingleResponse(
            certId = id,
            status = CertificateStatus.Good,
            thisUpdate = NOW,
            nextUpdate = NOW,
        ).toString() shouldContain
            "nextUpdate=20"
        val extension = Extension(ExtensionIds.OcspNoCheck, false, ByteString())
        answer shouldNotBe SingleResponse(
            certId = id,
            status = CertificateStatus.Good,
            thisUpdate = NOW,
            extensions = listOf(extension),
        )
    }

    test("statuses and responder names show what they are") {
        val revoked = CertificateStatus.Revoked(NOW, RevocationReason.KeyCompromise)
        revoked shouldBe CertificateStatus.Revoked(NOW, RevocationReason.KeyCompromise)
        revoked shouldNotBe CertificateStatus.Revoked(NOW)
        revoked shouldNotBe CertificateStatus.Revoked(NOW + 1.days, RevocationReason.KeyCompromise)
        revoked shouldNotBe CertificateStatus.Good
        revoked.hashCode() shouldBe NOW.hashCode()
        revoked.toString() shouldContain "reason=KeyCompromise"
        CertificateStatus.Revoked(NOW).toString() shouldContain "reason=none"
        CertificateStatus.Good.toString() shouldBe "Good"
        CertificateStatus.Unknown.toString() shouldBe "Unknown"
        val byName = ResponderId.ByName(ByteString(1))
        byName shouldBe ResponderId.ByName(ByteString(1))
        byName shouldNotBe ResponderId.ByName(ByteString(2))
        byName shouldNotBe ResponderId.ByKey(ByteString(1))
        byName.hashCode() shouldBe ByteString(1).hashCode()
        byName.toString() shouldBe "ResponderId.ByName(01)"
        val byKey = ResponderId.ByKey(ByteString(1))
        byKey shouldBe ResponderId.ByKey(ByteString(1))
        byKey shouldNotBe ResponderId.ByKey(ByteString(2))
        byKey shouldNotBe byName
        byKey.hashCode() shouldBe ByteString(1).hashCode()
        byKey.toString() shouldBe "ResponderId.ByKey(01)"
        OcspResponseStatus.SignatureRequired.code shouldBe OcspResponseStatus.Unauthorized.code - 1
    }

    test("messages, issuers and settings compare and show themselves") {
        val scenario = Scenario.create()
        val request = scenario.request(nonceBytes = Ocsp.DEFAULT_NONCE_SIZE)
        request shouldNotBe "request"
        request.hashCode() shouldBe request.encoded.hashCode()
        request.toString() shouldContain "nonce="
        scenario.request().toString() shouldContain "nonce=none"
        val encoded = scenario.authority.responder().respond(scenario.request())
        val response = scenario.decoded(encoded)
        response shouldBe scenario.decoded(encoded)
        response shouldNotBe "response"
        response.hashCode() shouldBe encoded.hashCode()
        response.toString() shouldContain "Successful"
        val basic = checkNotNull(response.basic)
        basic shouldBe scenario.decoded(encoded).basic
        basic shouldNotBe "basic"
        basic.hashCode() shouldBe basic.tbs.hashCode()
        basic.toString() shouldContain "responses=1"
        val later = scenario.decoded(scenario.authority.responder().errorResponse(OcspResponseStatus.InternalError))
        later.toString() shouldContain "unsigned"
        val other = scenario.authority.responder().sign(
            listOf(SingleResponse(scenario.certId(), CertificateStatus.Unknown, NOW)),
        )
        basic shouldNotBe scenario.decoded(other).basic
        val issuer = scenario.issuer
        issuer shouldBe OcspIssuer.of(TrustAnchor.of(scenario.authority.certificate))
        issuer shouldNotBe OcspIssuer(issuer.name, Authority.root().issuer.publicKey)
        issuer shouldNotBe OcspIssuer(Authority.root("Other").issuer.name, issuer.publicKey)
        issuer shouldNotBe "issuer"
        issuer.hashCode() shouldBe issuer.name.hashCode()
        issuer.toString() shouldContain "OcspIssuer"
        val noP256 = Crypto(environment { policy = cryptoPolicy { curves(EllipticCurve.P384) } })
        val decoded = Certificates(noP256).decode(scenario.leaf.encoded)
        val unreadable = checkNotNull(decoded.getOrNull())
        shouldThrow<IllegalArgumentException> { OcspIssuer.of(unreadable) }
        ocsp.toString() shouldContain "OcspLimits"
    }

    test("limits and parameters have bounds") {
        OcspLimits() shouldBe OcspLimits.Default
        OcspLimits().hashCode() shouldBe OcspLimits.Default.hashCode()
        OcspLimits() shouldNotBe OcspLimits(maximumEntries = 1)
        OcspLimits() shouldNotBe "limits"
        OcspLimits().toString() shouldContain "maximumBytes=65536"
        shouldThrow<IllegalArgumentException> { OcspLimits(maximumBytes = OcspLimits.HARD_MAXIMUM_BYTES + 1) }
        shouldThrow<IllegalArgumentException> { OcspLimits(maximumBytes = 0) }
        shouldThrow<IllegalArgumentException> { OcspLimits(maximumEntries = 0) }
        shouldThrow<IllegalArgumentException> { OcspLimits(maximumCertificates = 0) }
        shouldThrow<IllegalArgumentException> { OcspLimits(maximumExtensions = 0) }
        shouldThrow<IllegalArgumentException> { OcspLimits(maximumEntries = OcspLimits.HARD_MAXIMUM_ENTRIES + 1) }
        shouldThrow<IllegalArgumentException> {
            OcspLimits(maximumCertificates = OcspLimits.HARD_MAXIMUM_CERTIFICATES + 1)
        }
        shouldThrow<IllegalArgumentException> {
            OcspLimits(maximumExtensions = OcspLimits.HARD_MAXIMUM_EXTENSIONS + 1)
        }
        OcspLimits(
            maximumBytes = OcspLimits.HARD_MAXIMUM_BYTES,
            maximumEntries = OcspLimits.HARD_MAXIMUM_ENTRIES,
            maximumCertificates = OcspLimits.HARD_MAXIMUM_CERTIFICATES,
            maximumExtensions = OcspLimits.HARD_MAXIMUM_EXTENSIONS,
        ).maximumBytes shouldBe OcspLimits.HARD_MAXIMUM_BYTES
        OcspParameters() shouldBe OcspParameters()
        OcspParameters().hashCode() shouldBe OcspParameters().hashCode()
        OcspParameters() shouldNotBe OcspParameters(at = NOW)
        OcspParameters() shouldNotBe "parameters"
        OcspParameters().toString() shouldContain "at=clock"
        OcspParameters(at = NOW).toString() shouldContain "at=20"
        shouldThrow<IllegalArgumentException> { OcspParameters(skew = (-1).minutes) }
        shouldThrow<IllegalArgumentException> { OcspParameters(maximumAge = (-1).days) }
        Ocsp.MINIMUM_NONCE_SIZE shouldBe Ocsp.DEFAULT_NONCE_SIZE
    }
})
