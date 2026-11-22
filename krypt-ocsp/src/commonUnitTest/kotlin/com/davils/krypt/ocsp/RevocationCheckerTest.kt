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
import com.davils.krypt.core.algorithm.EllipticCurve
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.cryptoPolicy
import com.davils.krypt.ocsp.fixture.Authority
import com.davils.krypt.ocsp.fixture.FixedClock
import com.davils.krypt.ocsp.fixture.LEAF
import com.davils.krypt.ocsp.fixture.NOW
import com.davils.krypt.ocsp.fixture.crypto
import com.davils.krypt.ocsp.fixture.ocsp
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.Certificates
import com.davils.krypt.x509.path.PathFailure
import com.davils.krypt.x509.path.PathValidation
import com.davils.krypt.x509.path.PathValidator
import com.davils.krypt.x509.path.RevocationChecker
import com.davils.krypt.x509.path.RevocationStatus
import com.davils.krypt.x509.path.TrustAnchor
import com.davils.krypt.x509.path.ValidationParameters
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.io.bytestring.ByteString
import kotlin.time.Duration.Companion.days

private val AT: ValidationParameters = ValidationParameters(at = NOW)

private suspend fun RevocationChecker.statusOf(
    certificate: Certificate,
    issuer: Certificate?,
    anchor: TrustAnchor,
): RevocationStatus = check(certificate = certificate, issuer = issuer, anchor = anchor, at = NOW)

class RevocationCheckerTest : FunSpec({
    test("path validation asks OCSP about every certificate of the path") {
        val root = Authority.root()
        val ca = root.issue("ca", isCa = true)
        val leaf = ca.issue(LEAF).certificate
        var revoked: CertificateStatus? = null
        val leafSource = OcspStatusSource { serial ->
            revoked.takeIf { serial == leaf.serialNumber }
                ?: CertificateStatus.Good
        }
        val responders = listOf(root.responder(), ca.responder(source = leafSource))
        val source = OcspResponseSource { request, _, issuer ->
            responders[(issuer.name == ca.certificate.subject).compareTo(false)].respond(request)
        }
        val checker = OcspRevocationChecker(ocsp, source)
        val validator = PathValidator(crypto, listOf(TrustAnchor.of(root.certificate)), checker)
        validator.validate(leaf, listOf(ca.certificate), AT).isValid shouldBe true
        revoked = CertificateStatus.Revoked(NOW - 1.days)
        val result = validator.validate(leaf, listOf(ca.certificate), AT)
        result.shouldBeInstanceOf<PathValidation.Invalid>().failure shouldBe PathFailure.Revoked
        val silent = PathValidator(
            crypto,
            listOf(TrustAnchor.of(root.certificate)),
            OcspRevocationChecker(ocsp, OcspResponseSource { _, _, _ -> null }),
        )
        val unknown = silent.validate(leaf, listOf(ca.certificate), AT)
        unknown.shouldBeInstanceOf<PathValidation.Invalid>().failure shouldBe PathFailure.RevocationUnknown
        checker.toString() shouldContain "OcspRevocationChecker"
    }

    test("stapled and broken responses") {
        val root = Authority.root()
        val ca = root.issue("ca", isCa = true)
        val leaf = ca.issue(LEAF).certificate
        val anchor = TrustAnchor.of(root.certificate)
        val stapled = ca.responder().respond(ocsp.request(listOf(ocsp.certId(leaf, ca.issuer)), nonceBytes = null))
        val checker = OcspRevocationChecker(ocsp, OcspResponseSource.stapled(leaf, stapled))
        checker.statusOf(certificate = leaf, issuer = ca.certificate, anchor = anchor) shouldBe RevocationStatus.Good
        checker.statusOf(certificate = ca.certificate, issuer = null, anchor = anchor) shouldBe RevocationStatus.Unknown
        val nonced = OcspRevocationChecker(
            ocsp = ocsp,
            source = OcspResponseSource.stapled(leaf, stapled),
            parameters = OcspParameters(isNonceRequired = true),
            nonceBytes = Ocsp.DEFAULT_NONCE_SIZE,
        )
        nonced.statusOf(certificate = leaf, issuer = ca.certificate, anchor = anchor) shouldBe RevocationStatus.Unknown
        val late = checker.check(certificate = leaf, issuer = ca.certificate, anchor = anchor, at = NOW + 2.days)
        late shouldBe RevocationStatus.Unknown
        val unknown = ca.responder(source = { _ -> CertificateStatus.Unknown })
        val answering = OcspRevocationChecker(ocsp, OcspResponseSource { request, _, _ -> unknown.respond(request) })
        answering.statusOf(
            certificate = leaf,
            issuer = ca.certificate,
            anchor = anchor,
        ) shouldBe RevocationStatus.Unknown
        val garbage = OcspRevocationChecker(ocsp, OcspResponseSource { _, _, _ -> ByteString(1) })
        garbage.statusOf(certificate = leaf, issuer = ca.certificate, anchor = anchor) shouldBe RevocationStatus.Unknown
        val noP256 = Crypto(
            environment {
                clock = FixedClock
                policy = cryptoPolicy { curves(EllipticCurve.P384) }
            },
        )
        val decoded = Certificates(noP256).decode(ca.certificate.encoded)
        val hidden = checkNotNull(decoded.getOrNull())
        checker.statusOf(certificate = leaf, issuer = hidden, anchor = anchor) shouldBe RevocationStatus.Unknown
    }
})
