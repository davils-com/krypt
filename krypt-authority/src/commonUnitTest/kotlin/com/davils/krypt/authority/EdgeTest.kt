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
import com.davils.krypt.authority.fixture.NOW
import com.davils.krypt.authority.fixture.crypto
import com.davils.krypt.authority.fixture.issued
import com.davils.krypt.authority.fixture.rootAuthority
import com.davils.krypt.authority.fixture.serverRequest
import com.davils.krypt.authority.profile.CertificateProfile
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.primitive.signature.Signer
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.Certificates
import com.davils.krypt.x509.crl.RevocationLists
import com.davils.krypt.x509.extension.NameConstraints
import com.davils.krypt.x509.name.DistinguishedName
import com.davils.krypt.x509.name.GeneralName
import com.davils.krypt.x509.name.distinguishedName
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlin.time.Duration.Companion.days

private const val DAYS: Int = 3_650
private const val DOMAIN: String = "example.com"
private val OTHER: DistinguishedName = distinguishedName { commonName("Other") }

private suspend fun bare(issuer: DistinguishedName, isCa: Boolean): Pair<Certificate, Signer> {
    val pair = crypto.keys.generate(KeyType.P256)
    val signer = crypto.signatures.signer(pair.privateKey)
    val certificate = Certificates(crypto).issue(signer) {
        subject = issuer
        this.issuer = issuer
        publicKey = pair.publicKey
        notBefore = NOW
        notAfter = NOW + DAYS.days
        extensions { basicConstraints(isCa = isCa) }
    }
    return certificate to signer
}

class EdgeTest : FunSpec({
    test("an authority without key usage or key identifier still issues with RFC 7093 identifiers") {
        val (certificate, signer) = bare(issuer = OTHER, isCa = true)
        val authority = CertificateAuthority(
            crypto = crypto,
            certificate = certificate,
            signer = signer,
            repository = MemoryRepository(),
        )
        val leaf = authority.issued(serverRequest())
        val identifier = leaf.extensions.authorityKeyIdentifier?.keyIdentifier
        identifier shouldBe Certificates(crypto).keyIdentifier(signer.publicKey)
    }

    test("lists and certificates of other authorities are not taken for its own") {
        val root = rootAuthority()
        val authority = root.authority
        val signer = authority.signer
        val withoutKeyId = RevocationLists(crypto).issue(signer) {
            issuer = authority.certificate.subject
            thisUpdate = NOW
            number = DerInteger.of(1L)
        }
        shouldThrow<IllegalArgumentException> { authority.deltaRevocationList(withoutKeyId) }
        val (otherCertificate, otherSigner) = bare(issuer = OTHER, isCa = true)
        val other = CertificateAuthority(
            crypto = crypto,
            certificate = otherCertificate,
            signer = otherSigner,
            repository = MemoryRepository(),
        )
        shouldThrow<IllegalArgumentException> { authority.deltaRevocationList(other.revocationList()) }
        val (stray, _) = bare(issuer = authority.certificate.subject, isCa = false)
        root.repository.issued[stray.serialNumber] = stray
        authority.revoke(stray.serialNumber).failureOrNull() shouldBe RevocationFailure.UnknownCertificate
        val foreign = other.issued(serverRequest())
        root.repository.issued[foreign.serialNumber] = foreign
        authority.revoke(foreign.serialNumber).failureOrNull() shouldBe RevocationFailure.UnknownCertificate
    }

    test("an intermediate carries its name constraints") {
        val root = rootAuthority().authority
        val request = serverRequest(profile = CertificateProfile.intermediate())
        val constrained = IssuanceRequest(
            subject = request.subject,
            publicKey = request.publicKey,
            profile = request.profile,
            nameConstraints = NameConstraints(permitted = listOf(GeneralName.Dns(DOMAIN))),
        )
        val issued = checkNotNull(root.issue(constrained).getOrNull())
        val constraints = issued.extensions.nameConstraints
        constraints?.permitted shouldBe listOf(GeneralName.Dns(DOMAIN))
    }
})
