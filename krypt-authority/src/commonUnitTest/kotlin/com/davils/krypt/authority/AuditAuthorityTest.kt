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
import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.authority.fixture.MemoryRepository
import com.davils.krypt.authority.fixture.MovableClock
import com.davils.krypt.authority.fixture.NOW
import com.davils.krypt.authority.fixture.crypto
import com.davils.krypt.authority.fixture.issued
import com.davils.krypt.authority.fixture.rootAuthority
import com.davils.krypt.authority.fixture.serverRequest
import com.davils.krypt.authority.fixture.testEnvironment
import com.davils.krypt.authority.policy.issuancePolicy
import com.davils.krypt.authority.profile.CertificateProfile
import com.davils.krypt.authority.store.AuthorityRepository
import com.davils.krypt.authority.store.Revocation
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.name.AttributeTypes
import com.davils.krypt.x509.name.GeneralName
import com.davils.krypt.x509.request.CertificationRequests
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.launch
import kotlin.time.Duration.Companion.seconds

private class GatedRepository(private val inner: MemoryRepository) : AuthorityRepository {
    val gate: CompletableDeferred<Unit> = CompletableDeferred()

    override suspend fun record(certificate: Certificate): Boolean = inner.record(certificate)

    override suspend fun find(serialNumber: DerInteger): Certificate? = inner.find(serialNumber)

    override suspend fun revoke(revocation: Revocation): Boolean {
        gate.await()
        return inner.revoke(revocation)
    }

    override suspend fun revocation(serialNumber: DerInteger): Revocation? = inner.revocation(serialNumber)

    override suspend fun revocations(): List<Revocation> = inner.revocations()

    override suspend fun nextCrlNumber(): Long = inner.nextCrlNumber()
}

class AuditAuthorityTest : FunSpec({
    test("the subject of a request is held to the name policy like its alternative names") {
        val policy = issuancePolicy {
            dnsDomains("example.com")
            emailDomains("example.com")
        }
        val root = rootAuthority(policy = policy)
        val pair = crypto.keys.generate(KeyType.P256)
        val request = CertificationRequests(crypto).create(crypto.signatures.signer(pair.privateKey)) {
            subject {
                commonName("www.evil.com")
                attribute(AttributeTypes.EmailAddress, "ceo@evil.com")
            }
            extensions { subjectAlternativeNames(listOf(GeneralName.Dns("www.example.com"))) }
        }
        val enrolled = root.authority.enroll(request, CertificateProfile.TlsServer)
        enrolled.failureOrNull() shouldBe IssuanceFailure.NameNotPermitted
    }

    test("a partial wildcard is refused when wildcards are not allowed") {
        val policy = issuancePolicy { dnsDomains("example.com") }
        val root = rootAuthority(policy = policy)
        val partial = root.authority.issue(serverRequest(name = GeneralName.Dns("f*.example.com")))
        partial.failureOrNull() shouldBe IssuanceFailure.NameNotPermitted
    }

    test("a revocation recorded after the base list was cut is in the next delta") {
        val clock = MovableClock(NOW)
        val on = Crypto(testEnvironment(clock = clock))
        val memory = MemoryRepository()
        val gated = GatedRepository(memory)
        val root = rootAuthority(on = on, repository = memory)
        val authority = CertificateAuthority(
            crypto = on,
            certificate = root.authority.certificate,
            signer = root.authority.signer,
            repository = gated,
        )
        val leaf = authority.issued(serverRequest())
        val revoking = launch(start = CoroutineStart.UNDISPATCHED) { authority.revoke(leaf.serialNumber) }
        clock.at = NOW + 2.seconds
        val base = authority.revocationList()
        base.find(leaf.serialNumber) shouldBe null
        gated.gate.complete(Unit)
        revoking.join()
        clock.at = NOW + 4.seconds
        val delta = authority.deltaRevocationList(base)
        delta.find(leaf.serialNumber) shouldNotBe null
    }
})
