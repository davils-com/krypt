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

import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.authority.fixture.HOST
import com.davils.krypt.authority.fixture.MemoryRepository
import com.davils.krypt.authority.fixture.NOW
import com.davils.krypt.authority.fixture.crypto
import com.davils.krypt.authority.fixture.issued
import com.davils.krypt.authority.fixture.rootAuthority
import com.davils.krypt.authority.fixture.serverRequest
import com.davils.krypt.authority.policy.IssuancePolicy
import com.davils.krypt.authority.policy.issuancePolicy
import com.davils.krypt.authority.profile.CertificateProfile
import com.davils.krypt.authority.profile.ProfileRule
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.extension.ExtensionIds
import com.davils.krypt.x509.extension.KeyPurposes
import com.davils.krypt.x509.extension.KeyUsage
import com.davils.krypt.x509.name.DistinguishedName
import com.davils.krypt.x509.name.GeneralName
import com.davils.krypt.x509.path.PathValidation
import com.davils.krypt.x509.path.PathValidator
import com.davils.krypt.x509.path.TrustAnchor
import com.davils.krypt.x509.path.ValidationParameters
import com.davils.krypt.x509.request.CertificationRequests
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.time.Duration.Companion.days

private const val SERIAL_BYTES: Int = 20
private const val STATUS_REQUEST: Int = 5
private const val CRL_URL: String = "http://crl.example.com/root.crl"
private const val OCSP_URL: String = "http://ocsp.example.com"
private const val ISSUER_URL: String = "http://example.com/root.crt"
private const val SPIFFE_ID: String = "spiffe://example.org/web"

private fun Certificate.isCritical(id: ObjectIdentifier): Boolean {
    val all = extensions.all
    return all.single { extension -> extension.id == id }.isCritical
}

private suspend fun request(profile: CertificateProfile, names: List<GeneralName> = emptyList()): IssuanceRequest {
    val pair = crypto.keys.generate(KeyType.P256)
    return IssuanceRequest(
        subject = DistinguishedName.Empty,
        publicKey = pair.publicKey,
        profile = profile,
        names = names,
    )
}

class IssuanceTest : FunSpec({
    test("a root issues an intermediate by request, which issues a server certificate that validates") {
        val root = rootAuthority()
        val intermediatePair = crypto.keys.generate(KeyType.P256)
        val intermediateSigner = crypto.signatures.signer(intermediatePair.privateKey)
        val csr = CertificationRequests(crypto).create(intermediateSigner) { subject { commonName("Intermediate") } }
        val enrolled = root.authority.enroll(csr, CertificateProfile.intermediate(pathLength = 0))
        val intermediateCertificate = checkNotNull(enrolled.getOrNull())
        val constraints = intermediateCertificate.extensions.basicConstraints
        constraints?.pathLength shouldBe 0
        val policy = issuancePolicy {
            crlUrls(CRL_URL)
            ocspUrls(OCSP_URL)
            issuerUrls(ISSUER_URL)
            policies(KeyPurposes.AnyPolicy)
        }
        val intermediate = CertificateAuthority(
            crypto = crypto,
            certificate = intermediateCertificate,
            signer = intermediateSigner,
            repository = MemoryRepository(),
            policy = policy,
        )
        val leaf = intermediate.issued(serverRequest())
        val extensions = leaf.extensions
        val serial = leaf.serialNumber
        serial.bytes.size shouldBe SERIAL_BYTES
        extensions.keyUsage shouldBe setOf(KeyUsage.DigitalSignature)
        extensions.extendedKeyUsage shouldBe listOf(KeyPurposes.ServerAuth)
        extensions.subjectAlternativeNames shouldBe listOf(GeneralName.Dns(HOST))
        val intermediateId = intermediateCertificate.extensions.subjectKeyIdentifier
        extensions.authorityKeyIdentifier?.keyIdentifier shouldBe intermediateId
        val point = extensions.crlDistributionPoints.single()
        point.names shouldBe listOf(GeneralName.Uri(CRL_URL))
        extensions.authorityInformationAccess.size shouldBe 2
        extensions.certificatePolicies shouldBe listOf(KeyPurposes.AnyPolicy)
        leaf.notBefore shouldBe NOW - policy.backdate
        val validator = PathValidator(crypto, listOf(TrustAnchor.of(root.authority.certificate)))
        val parameters = ValidationParameters(at = NOW, purpose = KeyPurposes.ServerAuth, isRevocationRequired = false)
        val validation = validator.validate(leaf, listOf(intermediateCertificate), parameters)
        validation.shouldBeInstanceOf<PathValidation.Valid>()
        val rsa = intermediate.issued(serverRequest(type = KeyType.Rsa3072))
        rsa.extensions.keyUsage shouldBe setOf(KeyUsage.DigitalSignature, KeyUsage.KeyEncipherment)
        root.authority.toString() shouldBe "CertificateAuthority(CN=Root)"
    }

    test("every profile issues what it promises") {
        val root = rootAuthority()
        val mtls = root.authority.issued(serverRequest(profile = CertificateProfile.Mtls))
        mtls.extensions.extendedKeyUsage shouldBe listOf(KeyPurposes.ServerAuth, KeyPurposes.ClientAuth)
        val responder = root.authority.issued(request(CertificateProfile.OcspSigning))
        responder.extensions.isOcspNoCheck shouldBe true
        val stamping = root.authority.issued(request(CertificateProfile.TimeStamping))
        stamping.isCritical(ExtensionIds.ExtendedKeyUsage) shouldBe true
        val svidRequest = serverRequest(GeneralName.Uri(SPIFFE_ID), profile = CertificateProfile.SpiffeSvid)
        val svid = root.authority.issued(svidRequest)
        svid.notAfter - svid.notBefore shouldBe 1.days + IssuancePolicy.Default.backdate
        val email = listOf(GeneralName.Email("ops@example.com"))
        val anonymous = root.authority.issued(request(CertificateProfile.TlsClient, email))
        anonymous.isCritical(ExtensionIds.SubjectAlternativeName) shouldBe true
        val mail = root.authority.issued(request(CertificateProfile.Email, email))
        mail.extensions.keyUsage shouldBe setOf(KeyUsage.DigitalSignature)
        val staple = CertificateProfile(
            name = "staple",
            keyUsages = setOf(KeyUsage.DigitalSignature),
            rules = setOf(ProfileRule.MustStaple),
        )
        val stapled = root.authority.issued(request(staple))
        stapled.extensions.tlsFeatures shouldBe setOf(STATUS_REQUEST)
        val code = root.authority.issued(request(CertificateProfile.CodeSigning))
        code.extensions.extendedKeyUsage shouldBe listOf(KeyPurposes.CodeSigning)
    }
})
