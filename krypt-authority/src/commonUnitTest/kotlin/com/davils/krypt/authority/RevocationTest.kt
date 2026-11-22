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

package com.davils.krypt.authority

import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.authority.fixture.MemoryRepository
import com.davils.krypt.authority.fixture.MovableClock
import com.davils.krypt.authority.fixture.NOW
import com.davils.krypt.authority.fixture.issued
import com.davils.krypt.authority.fixture.rootAuthority
import com.davils.krypt.authority.fixture.serverRequest
import com.davils.krypt.authority.fixture.testEnvironment
import com.davils.krypt.ocsp.CertificateStatus
import com.davils.krypt.ocsp.Ocsp
import com.davils.krypt.ocsp.OcspIssuer
import com.davils.krypt.ocsp.OcspParameters
import com.davils.krypt.ocsp.OcspResponder
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.x509.RevocationReason
import com.davils.krypt.x509.crl.RevocationLists
import com.davils.krypt.x509.path.CrlRevocationChecker
import com.davils.krypt.x509.path.PathFailure
import com.davils.krypt.x509.path.PathValidation
import com.davils.krypt.x509.path.PathValidator
import com.davils.krypt.x509.path.TrustAnchor
import com.davils.krypt.x509.path.ValidationParameters
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours

class RevocationTest : FunSpec({
    test("only certificates of the authority are revoked, once and for good") {
        val repository = MemoryRepository()
        val root = rootAuthority(repository = repository).authority
        val other = rootAuthority(repository = repository).authority
        val leaf = root.issued(serverRequest())
        val foreign = other.issued(serverRequest())
        root.revoke(DerInteger.of(1L)).failureOrNull() shouldBe RevocationFailure.UnknownCertificate
        root.revoke(foreign.serialNumber).failureOrNull() shouldBe RevocationFailure.UnknownCertificate
        root.revoke(leaf.serialNumber, RevocationReason.CertificateHold).failureOrNull() shouldBe
            RevocationFailure.ReasonNotPermitted
        root.revoke(leaf.serialNumber, RevocationReason.RemoveFromCrl).failureOrNull() shouldBe
            RevocationFailure.ReasonNotPermitted
        val revocation = checkNotNull(root.revoke(leaf.serialNumber, RevocationReason.KeyCompromise, NOW).getOrNull())
        revocation.reason shouldBe RevocationReason.KeyCompromise
        revocation.invalidAt shouldBe NOW
        root.revoke(leaf.serialNumber).failureOrNull() shouldBe RevocationFailure.AlreadyRevoked
        val second = root.issued(serverRequest())
        checkNotNull(root.revoke(second.serialNumber, RevocationReason.Unspecified).getOrNull()).reason shouldBe null
    }

    test("full and delta lists carry the revocations and validation sees them") {
        val clock = MovableClock()
        val crypto = Crypto(testEnvironment(clock))
        val root = rootAuthority(on = crypto).authority
        val first = root.issued(serverRequest())
        val second = root.issued(serverRequest())
        root.revoke(first.serialNumber, RevocationReason.Superseded)
        clock.at = NOW + 1.hours
        val full = root.revocationList()
        full.number shouldBe DerInteger.of(1L)
        full.entries.single().serialNumber shouldBe first.serialNumber
        full.issuer shouldBe root.certificate.subject
        clock.at = NOW + 2.hours
        root.revoke(second.serialNumber)
        val delta = root.deltaRevocationList(full)
        delta.deltaOf shouldBe DerInteger.of(1L)
        delta.number shouldBe DerInteger.of(2L)
        delta.entries.single().serialNumber shouldBe second.serialNumber
        shouldThrow<IllegalArgumentException> { root.deltaRevocationList(delta) }
        shouldThrow<IllegalArgumentException> { rootAuthority(on = crypto).authority.deltaRevocationList(full) }
        shouldThrow<IllegalArgumentException> { root.revocationList(Duration.ZERO) }
        val checker = CrlRevocationChecker(RevocationLists(crypto)) { _ -> listOf(full) }
        val validator = PathValidator(crypto, listOf(TrustAnchor.of(root.certificate)), checker)
        val result = validator.validate(first, parameters = ValidationParameters(at = clock.at))
        result.shouldBeInstanceOf<PathValidation.Invalid>().failure shouldBe PathFailure.Revoked
    }

    test("the status source answers an OCSP responder") {
        val root = rootAuthority()
        val authority = root.authority
        val crypto = authority.crypto
        val good = authority.issued(serverRequest())
        val revoked = authority.issued(serverRequest())
        authority.revoke(revoked.serialNumber, RevocationReason.KeyCompromise)
        authority.statusSource.status(good.serialNumber) shouldBe CertificateStatus.Good
        authority.statusSource.status(revoked.serialNumber).shouldBeInstanceOf<CertificateStatus.Revoked>()
        authority.statusSource.status(DerInteger.of(1L)) shouldBe null
        val ocsp = Ocsp(crypto)
        val issuer = OcspIssuer.of(authority.certificate)
        val responder = OcspResponder(
            ocsp = ocsp,
            issuer = issuer,
            signer = crypto.signatures.signer(root.pair.privateKey),
            source = authority.statusSource,
        )
        val request = ocsp.request(listOf(ocsp.certId(certificate = revoked, issuer = issuer)))
        val response = checkNotNull(ocsp.decodeResponse(responder.respond(request)).getOrNull())
        val single = ocsp.verify(
            response = response,
            certificate = revoked,
            issuer = issuer,
            request = request,
            parameters = OcspParameters(at = NOW),
        )
        checkNotNull(single.getOrNull()).status.shouldBeInstanceOf<CertificateStatus.Revoked>()
    }
})
