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

package com.davils.krypt.ocsp

import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.LegacyCryptography
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.cryptoPolicy
import com.davils.krypt.ocsp.fixture.Authority
import com.davils.krypt.ocsp.fixture.FixedClock
import com.davils.krypt.ocsp.fixture.NOW
import com.davils.krypt.ocsp.fixture.Scenario
import com.davils.krypt.ocsp.fixture.der
import com.davils.krypt.ocsp.fixture.ocsp
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.PolicyViolationException
import com.davils.krypt.x509.extension.Extension
import com.davils.krypt.x509.extension.ExtensionIds
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days

private val legacy: Ocsp = Ocsp(
    Crypto(
        environment {
            clock = FixedClock
            policy = cryptoPolicy { acceptLegacy(DigestAlgorithm.Sha1) }
        },
    ),
)

class ResponderTest : FunSpec({
    test("several certificates are answered one by one") {
        val scenario = Scenario.create()
        val sibling = scenario.authority.issue("sibling").certificate
        val stranger = Scenario.create()
        val certIds = listOf(scenario.certId(), ocsp.certId(sibling, scenario.issuer), stranger.certId())
        val revoked = CertificateStatus.Revoked(NOW - 1.days)
        val source = OcspStatusSource { serial -> revoked.takeIf { serial == sibling.serialNumber } }
        val responder = scenario.authority.responder(source = source)
        val request = ocsp.request(certIds)
        val basic = checkNotNull(scenario.decoded(responder.respond(request)).basic)
        basic.responses.map { response -> response.status } shouldBe listOf(
            CertificateStatus.Unknown,
            revoked,
            CertificateStatus.Unknown,
        )
        basic.nonce shouldBe request.nonce
    }

    test("SHA-1 identifiers work only where the policy accepts them") {
        val scenario = Scenario.create(legacy)
        val request = scenario.request(algorithm = DigestAlgorithm.Sha1)
        val sha1 = request.certIds.single()
        sha1.issuerKeyHash.size shouldBe DigestAlgorithm.Sha1.outputBytes
        val decoded = checkNotNull(ocsp.decodeRequest(request.encoded).getOrNull())
        decoded.certIds shouldBe request.certIds
        val encoded = scenario.authority.responder(engine = legacy).respond(request)
        scenario.failureOf(encoded) shouldBe null
        Scenario(scenario.authority, scenario.leaf).failureOf(encoded) shouldBe OcspFailure.NotFound
        val modern = scenario.authority.responder().respond(request)
        scenario.decoded(modern).status shouldBe OcspResponseStatus.Unauthorized
        shouldThrow<PolicyViolationException> { ocsp.certId(scenario.leaf, scenario.issuer, DigestAlgorithm.Sha1) }
        shouldThrow<IllegalArgumentException> { ocsp.certId(scenario.leaf, scenario.issuer, DigestAlgorithm.Sha3256) }
    }

    test("answers without a nonce are cached and pre-signed") {
        val scenario = Scenario.create()
        val cache = OcspResponseCache()
        var status: CertificateStatus = CertificateStatus.Good
        val responder = scenario.authority.responder(source = { _ -> status }, cache = cache)
        val first = responder.respond(scenario.request())
        status = CertificateStatus.Unknown
        responder.respond(scenario.request()) shouldBe first
        cache.size() shouldBe 1
        val fresh = responder.respond(scenario.request(nonceBytes = Ocsp.DEFAULT_NONCE_SIZE))
        scenario.verify(fresh).getOrNull()?.status shouldBe CertificateStatus.Unknown
        val presigned = responder.presign(scenario.leaf.serialNumber)
        presigned shouldNotBe first
        responder.respond(scenario.request()) shouldBe presigned
        scenario.verify(presigned).getOrNull()?.status shouldBe CertificateStatus.Unknown
    }

    test("answers carry the extensions they are given") {
        val scenario = Scenario.create()
        val extension = Extension(
            ExtensionIds.OcspNoCheck,
            false,
            com.davils.krypt.ocsp.fixture
                .der { nullValue() },
        )
        val answer = SingleResponse(
            certId = scenario.certId(),
            status = CertificateStatus.Good,
            thisUpdate = NOW,
            nextUpdate = NOW + 1.days,
            extensions = listOf(extension),
        )
        val encoded = scenario.authority.responder().sign(listOf(answer))
        scenario.verify(encoded).getOrNull() shouldBe answer
    }

    test("critical extensions of answers and requests without a nonce") {
        val scenario = Scenario.create()
        val critical = Extension(ExtensionIds.OcspNoCheck, true, der { nullValue() })
        val answer = SingleResponse(
            certId = scenario.certId(),
            status = CertificateStatus.Good,
            thisUpdate = NOW,
            extensions = listOf(critical),
        )
        val encoded = scenario.authority.responder().sign(listOf(answer))
        ocsp.decodeResponse(encoded).failureOrNull() shouldBe OcspFailure.Malformed
        val sibling = scenario.authority.issue("sibling").certificate
        val both = ocsp.request(listOf(scenario.certId(), ocsp.certId(sibling, scenario.issuer)), nonceBytes = null)
        val cache = OcspResponseCache()
        val answered = scenario.authority.responder(cache = cache).respond(both)
        scenario.verify(answered).getOrNull()?.status shouldBe CertificateStatus.Good
        cache.size() shouldBe 0
    }

    test("responders refuse what they cannot do") {
        val scenario = Scenario.create()
        val authority = scenario.authority
        val responder = authority.responder()
        shouldThrow<IllegalArgumentException> { responder.errorResponse(OcspResponseStatus.Successful) }
        shouldThrow<IllegalArgumentException> { responder.sign(emptyList()) }
        val stranger = Authority.root("Stranger")
        shouldThrow<IllegalArgumentException> {
            authority.responder(signer = stranger.signer, certificate = authority.delegate().certificate)
        }
        shouldThrow<IllegalArgumentException> {
            OcspResponder(
                ocsp = ocsp,
                issuer = scenario.issuer,
                signer = authority.signer,
                source = Authority.GOOD,
                validity = Duration.ZERO,
            )
        }
        responder.toString() shouldContain "OcspResponder"
    }
})
