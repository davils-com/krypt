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

import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.EllipticCurve
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.CryptoPolicy
import com.davils.krypt.core.policy.cryptoPolicy
import com.davils.krypt.ocsp.fixture.Authority
import com.davils.krypt.ocsp.fixture.FixedClock
import com.davils.krypt.ocsp.fixture.LEAF
import com.davils.krypt.ocsp.fixture.NOW
import com.davils.krypt.ocsp.fixture.ROOT
import com.davils.krypt.ocsp.fixture.Scenario
import com.davils.krypt.ocsp.fixture.ocsp
import com.davils.krypt.ocsp.internal.ResponseCodec
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.x509.RevocationReason
import com.davils.krypt.x509.extension.KeyPurposes
import com.davils.krypt.x509.extension.KeyUsage
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.io.bytestring.ByteString
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes

private const val STRICT_RSA_BITS: Int = 4_096
private const val AGE_DAYS: Int = 7

private fun flipped(bytes: ByteString): ByteString {
    val array = bytes.toByteArray()
    array[0] = (array[0].toInt() xor 1).toByte()
    return ByteString(array)
}

private fun ocspWith(policy: CryptoPolicy): Ocsp = Ocsp(
    Crypto(
        environment {
            clock = FixedClock
            this.policy = policy
        },
    ),
)

class VerificationTest : FunSpec({
    test("a good answer signed by the issuer verifies and echoes the nonce") {
        val scenario = Scenario.create()
        val request = scenario.request(nonceBytes = Ocsp.DEFAULT_NONCE_SIZE)
        val encoded = scenario.authority.responder().respond(request.encoded)
        val answer = checkNotNull(scenario.verify(encoded, request).getOrNull())
        answer.status shouldBe CertificateStatus.Good
        answer.thisUpdate shouldBe NOW
        answer.nextUpdate shouldBe NOW + 1.days
        val basic = checkNotNull(scenario.decoded(encoded).basic)
        basic.nonce shouldBe request.nonce
        basic.responderId shouldBe ResponderId.ByName(scenario.authority.certificate.subject.encoded)
        basic.producedAt shouldBe NOW
        basic.certificates shouldBe emptyList()
        basic.responses.single().certId shouldBe request.certIds.single()
    }

    test("revoked and unknown answers are reported") {
        val scenario = Scenario.create()
        val revokedAt = NOW - 2.days
        val statuses = listOf(
            CertificateStatus.Revoked(revokedAt, RevocationReason.KeyCompromise),
            CertificateStatus.Revoked(revokedAt),
            CertificateStatus.Unknown,
        )
        statuses.forEach { status ->
            val responder = scenario.authority.responder(source = { _ -> status })
            val encoded = responder.respond(scenario.request().encoded)
            scenario.verify(encoded).getOrNull()?.status shouldBe status
        }
        val silent = scenario.authority.responder(source = { _ -> null })
        val encoded = silent.respond(scenario.request().encoded)
        scenario.verify(encoded).getOrNull()?.status shouldBe CertificateStatus.Unknown
    }

    test("a delegated responder the issuer authorized verifies") {
        val scenario = Scenario.create()
        val delegate = scenario.authority.delegate()
        val responder = scenario.authority.responder(signer = delegate.signer, certificate = delegate.certificate)
        val encoded = responder.respond(scenario.request().encoded)
        scenario.verify(encoded).getOrNull()?.status shouldBe CertificateStatus.Good
        val strict = OcspParameters(isNoCheckRequired = true)
        scenario.verify(encoded = encoded, parameters = strict).getOrNull() shouldNotBe null
        val basic = checkNotNull(scenario.decoded(encoded).basic)
        basic.certificates shouldBe listOf(delegate.certificate)
        basic.responderId shouldBe ResponderId.ByName(delegate.certificate.subject.encoded)
    }

    test("responders the issuer did not authorize are refused") {
        val scenario = Scenario.create()
        val authority = scenario.authority
        val responders = listOf(
            authority.issue("plain"),
            authority.delegate {
                keyUsage(setOf(KeyUsage.KeyEncipherment))
                extendedKeyUsage(listOf(KeyPurposes.OcspSigning))
            },
            authority.issue(
                name = "expired",
                notBefore = NOW - 2.days,
                notAfter = NOW - 1.days,
                extensions = Authority.DELEGATED,
            ),
            Authority.root("Other").delegate(),
            Authority.root(ROOT).delegate(),
        )
        responders.forEach { delegate ->
            val responder = authority.responder(signer = delegate.signer, certificate = delegate.certificate)
            val encoded = responder.respond(scenario.request().encoded)
            scenario.failureOf(encoded) shouldBe OcspFailure.UnauthorizedResponder
        }
        val unchecked = authority.delegate { extendedKeyUsage(listOf(KeyPurposes.OcspSigning)) }
        val responder = authority.responder(signer = unchecked.signer, certificate = unchecked.certificate)
        val encoded = responder.respond(scenario.request().encoded)
        scenario.failureOf(encoded) shouldBe null
        val strict = OcspParameters(isNoCheckRequired = true)
        scenario.failureOf(encoded, strict) shouldBe OcspFailure.UnauthorizedResponder
    }

    test("signatures of nobody authorized are bad") {
        val scenario = Scenario.create()
        val stranger = Authority.root("Stranger")
        val forged = scenario.authority.responder(signer = stranger.signer).respond(scenario.request().encoded)
        scenario.failureOf(forged) shouldBe OcspFailure.BadSignature
        val delegate = scenario.authority.delegate()
        val basic = checkNotNull(scenario.decoded(forged).basic)
        val tampered = ResponseCodec.encodeResponse(
            tbs = basic.tbs,
            algorithm = checkNotNull(basic.signatureAlgorithm),
            signature = flipped(basic.signature),
            certificates = listOf(delegate.certificate),
        )
        scenario.failureOf(tampered) shouldBe OcspFailure.BadSignature
    }

    test("algorithms and keys the policy forbids are refused") {
        val scenario = Scenario.create()
        val encoded = scenario.authority.responder().respond(scenario.request().encoded)
        val cnsa = Scenario(scenario.authority, scenario.leaf, ocspWith(CryptoPolicy.Cnsa2))
        cnsa.failureOf(encoded) shouldBe OcspFailure.AlgorithmNotPermitted
        val noP256 = Scenario(scenario.authority, scenario.leaf, ocspWith(cryptoPolicy { curves(EllipticCurve.P384) }))
        noP256.failureOf(encoded) shouldBe OcspFailure.BadSignature
        val rsa = Authority.root(type = KeyType.Rsa3072)
        val rsaScenario = Scenario(rsa, rsa.issue(LEAF).certificate)
        val rsaEncoded = rsa.responder().respond(rsaScenario.request().encoded)
        rsaScenario.failureOf(rsaEncoded) shouldBe null
        val strictRsa = ocspWith(
            cryptoPolicy {
                minimumRsaBits = STRICT_RSA_BITS
                minimumVerifiedRsaBits = STRICT_RSA_BITS
            },
        )
        Scenario(rsa, rsaScenario.leaf, strictRsa).failureOf(rsaEncoded) shouldBe OcspFailure.BadSignature
    }

    test("keys of another family or unreadable keys do not sign") {
        val scenario = Scenario.create()
        val encoded = scenario.authority.responder().respond(scenario.request())
        val rsa = Authority.root(type = KeyType.Rsa3072)
        val mismatched = OcspIssuer(scenario.issuer.name, rsa.issuer.publicKey)
        val outcome = ocsp.verify(scenario.decoded(encoded), scenario.leaf, mismatched)
        outcome.failureOrNull() shouldBe OcspFailure.BadSignature
        val rsaScenario = Scenario(
            rsa,
            rsa.issue(LEAF).certificate,
            ocspWith(cryptoPolicy { curves(EllipticCurve.P384) }),
        )
        val delegate = rsa.delegate()
        val responder = rsa.responder(signer = delegate.signer, certificate = delegate.certificate)
        val delegated = responder.respond(rsaScenario.request())
        rsaScenario.failureOf(delegated) shouldBe OcspFailure.BadSignature
    }

    test("nonces bind the answer to the request") {
        val scenario = Scenario.create()
        val responder = scenario.authority.responder()
        val sent = scenario.request(nonceBytes = Ocsp.DEFAULT_NONCE_SIZE)
        val other = scenario.request(nonceBytes = Ocsp.DEFAULT_NONCE_SIZE)
        val answered = responder.respond(other.encoded)
        scenario.verify(answered, sent).getOrNull() shouldBe null
        scenario.verify(answered, other).getOrNull() shouldNotBe null
        scenario.verify(answered, scenario.request()).getOrNull() shouldNotBe null
        val cached = responder.respond(scenario.request().encoded)
        scenario.verify(cached, sent).getOrNull() shouldNotBe null
        val required = OcspParameters(isNonceRequired = true)
        scenario.verify(encoded = cached, request = sent, parameters = required).getOrNull() shouldBe null
        scenario.verify(encoded = answered, parameters = required).getOrNull() shouldBe null
        scenario.verify(encoded = answered, request = other, parameters = required).getOrNull() shouldNotBe null
    }

    test("answers are found by their identifier") {
        val scenario = Scenario.create()
        val responder = scenario.authority.responder()
        val sibling = Scenario(scenario.authority, scenario.authority.issue("sibling").certificate)
        val encoded = responder.respond(scenario.request().encoded)
        sibling.failureOf(encoded) shouldBe OcspFailure.NotFound
        val foreign = Authority.root("Foreign")
        val foreignId = ocsp.certId(issuer = foreign.issuer, serialNumber = scenario.leaf.serialNumber)
        val misnamed = responder.sign(listOf(SingleResponse(foreignId, CertificateStatus.Good, NOW)))
        scenario.failureOf(misnamed) shouldBe OcspFailure.NotFound
        listOf(
            DigestAlgorithm.Sha384,
            DigestAlgorithm.Sha512,
        ).forEach { algorithm ->
            val answered = responder.respond(scenario.request(algorithm = algorithm).encoded)
            scenario.failureOf(answered) shouldBe null
        }
    }

    test("stale answers are refused") {
        val scenario = Scenario.create()
        val responder = scenario.authority.responder()
        val encoded = responder.respond(scenario.request().encoded)
        val late = OcspParameters(at = NOW + 2.days)
        scenario.failureOf(encoded, late) shouldBe OcspFailure.Stale
        scenario.failureOf(encoded, OcspParameters(at = NOW - 1.hours)) shouldBe OcspFailure.Stale
        scenario.failureOf(encoded, OcspParameters(at = NOW - 1.minutes)) shouldBe null
        scenario.failureOf(encoded, OcspParameters(at = NOW + 1.days + 1.minutes)) shouldBe null
        val open = responder.sign(listOf(SingleResponse(scenario.certId(), CertificateStatus.Good, NOW)))
        scenario.failureOf(open, OcspParameters(at = NOW + (AGE_DAYS - 1).days)) shouldBe null
        scenario.failureOf(open, OcspParameters(at = NOW + (AGE_DAYS + 1).days)) shouldBe OcspFailure.Stale
    }

    test("error responses carry no answer") {
        val scenario = Scenario.create()
        val responder = scenario.authority.responder()
        val later = responder.errorResponse(OcspResponseStatus.TryLater)
        scenario.decoded(later).status shouldBe OcspResponseStatus.TryLater
        scenario.decoded(later).basic shouldBe null
        scenario.failureOf(later) shouldBe OcspFailure.ResponderError
        val malformed = responder.respond(ByteString(1, 2))
        scenario.decoded(malformed).status shouldBe OcspResponseStatus.MalformedRequest
        val foreign = Scenario.create()
        val unauthorized = responder.respond(foreign.request().encoded)
        scenario.decoded(unauthorized).status shouldBe OcspResponseStatus.Unauthorized
    }
})
