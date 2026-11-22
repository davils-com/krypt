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
import com.davils.kore.core.validation.report.ValidationException
import com.davils.krypt.authority.fixture.crypto
import com.davils.krypt.authority.fixture.rootAuthority
import com.davils.krypt.authority.policy.IssuancePolicy
import com.davils.krypt.authority.policy.IssuancePolicyBuilder
import com.davils.krypt.authority.policy.issuancePolicy
import com.davils.krypt.authority.profile.CertificateProfile
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.x509.name.AttributeTypes
import com.davils.krypt.x509.name.DistinguishedName
import com.davils.krypt.x509.name.DistinguishedNameBuilder
import com.davils.krypt.x509.name.GeneralName
import com.davils.krypt.x509.name.distinguishedName
import com.davils.krypt.x509.request.CertificationRequests
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlin.time.Duration.Companion.days

private const val DOMAIN: String = "example.com"
private const val HOST: String = "www.example.com"
private const val EVIL: String = "www.evil.com"
private const val COMPANY: String = "Example Ltd"
private const val BACKDATE_DAYS: Int = 2
private val ADDRESS: GeneralName = checkNotNull(GeneralName.IpAddress.parseOrNull("10.0.0.1"))

private val STRICT: IssuancePolicy = issuancePolicy {
    dnsDomains(DOMAIN)
    emailDomains(DOMAIN)
    uriPrefixes("spiffe://example.org/")
    fixedAttribute(AttributeTypes.Organization, COMPANY)
}

private suspend fun failureOf(
    subject: DistinguishedNameBuilder.() -> Unit,
    names: List<GeneralName> = emptyList(),
    profile: CertificateProfile = CertificateProfile.TlsClient,
    policy: IssuancePolicy = STRICT,
): IssuanceFailure? {
    val authority = rootAuthority(policy = policy).authority
    val request = IssuanceRequest(
        subject = distinguishedName(subject),
        publicKey = crypto.keys.generate(KeyType.P256).publicKey,
        profile = profile,
        names = names,
    )
    return authority.issue(request).failureOrNull()
}

class SubjectPolicyTest : FunSpec({
    test("the subject of a request is held to the name policy like its alternative names") {
        val root = rootAuthority(policy = STRICT)
        val pair = crypto.keys.generate(KeyType.P256)
        val request = CertificationRequests(crypto).create(crypto.signatures.signer(pair.privateKey)) {
            subject {
                commonName(EVIL)
                attribute(AttributeTypes.EmailAddress, "ceo@evil.com")
            }
            extensions { subjectAlternativeNames(listOf(GeneralName.Dns(HOST))) }
        }
        val enrolled = root.authority.enroll(request, CertificateProfile.TlsServer)
        enrolled.failureOrNull() shouldBe IssuanceFailure.NameNotPermitted
    }

    test("a common name must be one of the alternative names") {
        val names = listOf(GeneralName.Dns(HOST))
        failureOf(subject = { commonName(HOST) }, names = names, profile = CertificateProfile.TlsServer) shouldBe null
        failureOf(subject = { commonName("WWW.Example.COM") }, names = names) shouldBe null
        failureOf(subject = { commonName(EVIL) }, names = names) shouldBe IssuanceFailure.NameNotPermitted
        failureOf(subject = { commonName("10.0.0.1") }, names = listOf(ADDRESS)) shouldBe null
        val directory = GeneralName.Directory(DistinguishedName.Empty)
        failureOf(subject = { commonName("x") }, names = listOf(directory)) shouldBe IssuanceFailure.NameNotPermitted
    }

    test("a common name without alternative names follows the rules of its kind") {
        failureOf(subject = { commonName("Ada Lovelace") }) shouldBe null
        failureOf(subject = { commonName(HOST) }) shouldBe null
        failureOf(subject = { commonName(EVIL) }) shouldBe IssuanceFailure.NameNotPermitted
        failureOf(subject = { commonName("ops@example.com") }) shouldBe null
        failureOf(subject = { commonName("ops@evil.com") }) shouldBe IssuanceFailure.NameNotPermitted
        failureOf(subject = { commonName("spiffe://example.org/web") }) shouldBe null
        failureOf(subject = { commonName("spiffe://evil.org/web") }) shouldBe IssuanceFailure.NameNotPermitted
        failureOf(subject = { commonName("www_evil.example.com") }) shouldBe IssuanceFailure.NameNotPermitted
    }

    test("only allowed attribute types with their fixed values make a subject") {
        failureOf(subject = { organization(COMPANY) }) shouldBe null
        failureOf(subject = { organization("Evil Ltd") }) shouldBe IssuanceFailure.NameNotPermitted
        failureOf(subject = { domainComponent("example") }) shouldBe IssuanceFailure.NameNotPermitted
        val email: DistinguishedNameBuilder.() -> Unit = { attribute(AttributeTypes.EmailAddress, "ops@example.com") }
        failureOf(subject = email) shouldBe IssuanceFailure.NameNotPermitted
        val open = issuancePolicy {
            subjectAttributes(AttributeTypes.DomainComponent, AttributeTypes.EmailAddress)
        }
        failureOf(subject = { domainComponent("example") }, policy = open) shouldBe null
        failureOf(subject = email, policy = open) shouldBe IssuanceFailure.NameNotPermitted
        failureOf(subject = { commonName(HOST) }, policy = open) shouldBe IssuanceFailure.NameNotPermitted
        open.subjectAttributes shouldBe setOf(AttributeTypes.DomainComponent, AttributeTypes.EmailAddress)
        STRICT.fixedAttributes shouldBe mapOf(AttributeTypes.Organization to COMPANY)
    }

    test("a policy built around its builder is still validated") {
        val builder = IssuancePolicyBuilder()
        builder.backdate = BACKDATE_DAYS.days
        shouldThrow<ValidationException> { IssuancePolicy(builder) }
    }
})
