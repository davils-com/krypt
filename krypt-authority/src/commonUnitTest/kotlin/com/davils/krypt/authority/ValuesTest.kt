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

import com.davils.kore.core.validation.report.ValidationException
import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.authority.fixture.MemoryRepository
import com.davils.krypt.authority.fixture.NOW
import com.davils.krypt.authority.fixture.crypto
import com.davils.krypt.authority.fixture.issued
import com.davils.krypt.authority.fixture.rootAuthority
import com.davils.krypt.authority.fixture.serverRequest
import com.davils.krypt.authority.policy.IssuancePolicy
import com.davils.krypt.authority.policy.issuancePolicy
import com.davils.krypt.authority.profile.CertificateProfile
import com.davils.krypt.authority.store.Revocation
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.primitive.signature.Signer
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.RevocationReason
import com.davils.krypt.x509.extension.KeyUsage
import com.davils.krypt.x509.name.distinguishedName
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days

private const val NAME: String = "custom"
private val SIGNING: Set<KeyUsage> = setOf(KeyUsage.DigitalSignature)

private fun authority(certificate: Certificate, signer: Signer): CertificateAuthority = CertificateAuthority(
    crypto = crypto,
    certificate = certificate,
    signer = signer,
    repository = MemoryRepository(),
)

class ValuesTest : FunSpec({
    test("requests, profiles and revocations compare every field") {
        val request = serverRequest()
        val same = IssuanceRequest(
            subject = request.subject,
            publicKey = request.publicKey,
            profile = request.profile,
            names = request.names,
        )
        request shouldBe same
        request shouldNotBe IssuanceRequest(request.subject, request.publicKey, request.profile)
        request shouldNotBe NAME
        request.hashCode() shouldBe same.hashCode()
        request.toString() shouldContain "tls-server"
        val profile = CertificateProfile(NAME, SIGNING)
        profile shouldBe CertificateProfile(NAME, SIGNING)
        profile shouldNotBe CertificateProfile(NAME, SIGNING, isNameRequired = true)
        profile shouldNotBe NAME
        profile.hashCode() shouldBe CertificateProfile(NAME, SIGNING).hashCode()
        profile.toString() shouldBe "CertificateProfile($NAME)"
        val revocation = Revocation(DerInteger.of(1L), NOW, RevocationReason.Superseded)
        revocation shouldBe Revocation(DerInteger.of(1L), NOW, RevocationReason.Superseded)
        revocation shouldNotBe Revocation(DerInteger.of(1L), NOW)
        revocation shouldNotBe NAME
        revocation.hashCode() shouldBe DerInteger.of(1L).hashCode()
        revocation.toString() shouldContain "Superseded"
        Revocation(DerInteger.of(1L), NOW).toString() shouldContain "none"
    }

    test("profiles and policies refuse values out of range") {
        shouldThrow<IllegalArgumentException> { CertificateProfile(" ", SIGNING) }
        shouldThrow<IllegalArgumentException> { CertificateProfile(NAME, emptySet()) }
        shouldThrow<IllegalArgumentException> { CertificateProfile(NAME, SIGNING, maximumValidity = Duration.ZERO) }
        shouldThrow<IllegalArgumentException> { CertificateProfile(NAME, SIGNING, pathLength = 0) }
        shouldThrow<IllegalArgumentException> { CertificateProfile.intermediate(pathLength = -1) }
        shouldThrow<ValidationException> { issuancePolicy { backdate = 2.days } }
        shouldThrow<ValidationException> { issuancePolicy { maximumValidity = Duration.ZERO } }
        IssuancePolicy.Default.toString() shouldContain "397d"
    }

    test("an authority needs an authority certificate and its key") {
        val root = rootAuthority()
        val certificate = root.authority.certificate
        val signer = root.authority.signer
        val leaf = root.authority.issued(serverRequest())
        shouldThrow<IllegalArgumentException> { authority(leaf, signer) }
        val stranger = crypto.signatures.signer(crypto.keys.generate(KeyType.P256).privateKey)
        shouldThrow<IllegalArgumentException> { authority(certificate, stranger) }
        val listOnly = CertificateProfile(NAME, setOf(KeyUsage.CrlSign), isCa = true)
        val crlSigner = root.authority.issued(
            IssuanceRequest(distinguishedName { commonName(NAME) }, root.pair.publicKey, listOnly),
        )
        shouldThrow<IllegalArgumentException> { authority(crlSigner, signer) }
        val subject = certificate.subject
        shouldThrow<IllegalArgumentException> {
            CertificateAuthority.createRoot(
                crypto = crypto,
                signer = signer,
                subject = subject,
                validity = Duration.ZERO,
            )
        }
        shouldThrow<IllegalArgumentException> {
            CertificateAuthority.createRoot(
                crypto = crypto,
                signer = signer,
                subject = subject,
                validity = 1.days,
                pathLength = -1,
            )
        }
    }
})
