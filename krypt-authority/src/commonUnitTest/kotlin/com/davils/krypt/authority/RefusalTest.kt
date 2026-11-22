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
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.authority.fixture.HOST
import com.davils.krypt.authority.fixture.MemoryRepository
import com.davils.krypt.authority.fixture.MovableClock
import com.davils.krypt.authority.fixture.NOW
import com.davils.krypt.authority.fixture.crypto
import com.davils.krypt.authority.fixture.rootAuthority
import com.davils.krypt.authority.fixture.serverRequest
import com.davils.krypt.authority.fixture.testEnvironment
import com.davils.krypt.authority.policy.issuancePolicy
import com.davils.krypt.authority.profile.CertificateProfile
import com.davils.krypt.core.algorithm.EllipticCurve
import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.cryptoPolicy
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.x509.extension.NameConstraints
import com.davils.krypt.x509.name.GeneralName
import com.davils.krypt.x509.name.distinguishedName
import com.davils.krypt.x509.request.CertificationRequests
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days

private const val DOMAIN: String = "example.com"
private const val SPIFFE: String = "spiffe://example.org/"
private const val LONG_DAYS: Int = 400
private const val SHORT_DAYS: Int = 30
private const val LONGER_DAYS: Int = 60
private const val LAST_DAY: Int = 3_649
private val ADDRESS: GeneralName = checkNotNull(GeneralName.IpAddress.parseOrNull("10.0.0.1"))

private suspend fun CertificateAuthority.failureOf(request: IssuanceRequest): IssuanceFailure? =
    issue(request).failureOrNull()

private suspend fun CertificateAuthority.failureOf(
    name: GeneralName,
    profile: CertificateProfile = CertificateProfile.TlsServer,
): IssuanceFailure? = failureOf(serverRequest(name = name, profile = profile))

private suspend fun withValidity(validity: Duration, profile: CertificateProfile = CertificateProfile.TlsServer) =
    IssuanceRequest(
        subject = distinguishedName { commonName(HOST) },
        publicKey = crypto.keys.generate(KeyType.P256).publicKey,
        profile = profile,
        names = listOf(GeneralName.Dns(HOST)),
        validity = validity,
    )

class RefusalTest : FunSpec({
    test("keys, constraints and profiles the authority may not issue are refused") {
        val ecOnly = rootAuthority(policy = issuancePolicy { keyFamilies(KeyFamily.Ec) })
        ecOnly.authority.failureOf(serverRequest(type = KeyType.Ed25519)) shouldBe IssuanceFailure.KeyNotPermitted
        val leaf = serverRequest()
        val constrained = IssuanceRequest(
            subject = leaf.subject,
            publicKey = leaf.publicKey,
            profile = leaf.profile,
            names = leaf.names,
            nameConstraints = NameConstraints(permitted = listOf(GeneralName.Dns(DOMAIN))),
        )
        ecOnly.authority.failureOf(constrained) shouldBe IssuanceFailure.InvalidRequest
        val lastCa = rootAuthority(pathLength = 0)
        val intermediate = serverRequest(profile = CertificateProfile.intermediate(pathLength = 0))
        val intermediateRequest = IssuanceRequest(
            subject = intermediate.subject,
            publicKey = intermediate.publicKey,
            profile = intermediate.profile,
        )
        lastCa.authority.failureOf(intermediateRequest) shouldBe IssuanceFailure.ProfileNotPermitted
        val limited = rootAuthority(pathLength = 1)
        val unlimited = IssuanceRequest(
            subject = intermediate.subject,
            publicKey = intermediate.publicKey,
            profile = CertificateProfile.intermediate(),
        )
        limited.authority.failureOf(unlimited) shouldBe IssuanceFailure.ProfileNotPermitted
        limited.authority.failureOf(intermediateRequest) shouldBe null
        val conflicting = rootAuthority(repository = MemoryRepository(isRecording = false))
        conflicting.authority.failureOf(serverRequest()) shouldBe IssuanceFailure.SerialConflict
    }

    test("names outside the profile or the policy are refused") {
        val open = rootAuthority().authority
        open.failureOf(serverRequest()) shouldBe null
        val nameless = serverRequest()
        val withoutNames = IssuanceRequest(nameless.subject, nameless.publicKey, CertificateProfile.TlsServer)
        open.failureOf(withoutNames) shouldBe IssuanceFailure.NameNotPermitted
        open.failureOf(GeneralName.Email("ops@$DOMAIN")) shouldBe IssuanceFailure.NameNotPermitted
        open.failureOf(GeneralName.RegisteredId(ObjectIdentifier.of("1.2.3")), CertificateProfile.TlsClient) shouldBe
            IssuanceFailure.NameNotPermitted
        val directory = GeneralName.Directory(distinguishedName { commonName(HOST) })
        open.failureOf(directory, CertificateProfile.TlsClient) shouldBe IssuanceFailure.NameNotPermitted
        val two = IssuanceRequest(
            subject = nameless.subject,
            publicKey = nameless.publicKey,
            profile = CertificateProfile.SpiffeSvid,
            names = listOf(GeneralName.Uri("${SPIFFE}a"), GeneralName.Uri("${SPIFFE}b")),
        )
        open.failureOf(two) shouldBe IssuanceFailure.NameNotPermitted
        val strict = rootAuthority(
            policy = issuancePolicy {
                dnsDomains(DOMAIN)
                emailDomains(DOMAIN)
                uriPrefixes(SPIFFE)
                isIpAddressAllowed = false
            },
        ).authority
        strict.failureOf(GeneralName.Dns(HOST)) shouldBe null
        strict.failureOf(GeneralName.Dns(DOMAIN)) shouldBe null
        strict.failureOf(GeneralName.Dns("evil.com")) shouldBe IssuanceFailure.NameNotPermitted
        strict.failureOf(GeneralName.Dns("*.$DOMAIN")) shouldBe IssuanceFailure.NameNotPermitted
        strict.failureOf(ADDRESS) shouldBe IssuanceFailure.NameNotPermitted
        strict.failureOf(GeneralName.Email("ops@$DOMAIN"), CertificateProfile.Email) shouldBe null
        val foreignMail = GeneralName.Email("ops@evil.com")
        strict.failureOf(foreignMail, CertificateProfile.Email) shouldBe IssuanceFailure.NameNotPermitted
        strict.failureOf(GeneralName.Uri("${SPIFFE}web"), CertificateProfile.SpiffeSvid) shouldBe null
        strict.failureOf(GeneralName.Uri("spiffe://evil.org/web"), CertificateProfile.SpiffeSvid) shouldBe
            IssuanceFailure.NameNotPermitted
        val wildcards = rootAuthority(policy = issuancePolicy { isWildcardAllowed = true }).authority
        wildcards.failureOf(GeneralName.Dns("*.$DOMAIN")) shouldBe null
        open.failureOf(ADDRESS) shouldBe null
    }

    test("validities beyond the profile, the policy or the authority are refused") {
        val root = rootAuthority().authority
        root.failureOf(withValidity(LONG_DAYS.days)) shouldBe IssuanceFailure.ValidityNotPermitted
        root.failureOf(withValidity(Duration.ZERO)) shouldBe IssuanceFailure.ValidityNotPermitted
        val short = rootAuthority(policy = issuancePolicy { maximumValidity = SHORT_DAYS.days }).authority
        short.failureOf(withValidity(LONGER_DAYS.days)) shouldBe IssuanceFailure.ValidityNotPermitted
        short.failureOf(serverRequest()) shouldBe null
        val clock = MovableClock()
        val moving = Crypto(testEnvironment(clock))
        val ending = rootAuthority(on = moving).authority
        clock.at = NOW + LAST_DAY.days
        ending.failureOf(serverRequest()) shouldBe IssuanceFailure.ValidityNotPermitted
        clock.at = NOW - 1.days
        ending.failureOf(serverRequest()) shouldBe IssuanceFailure.ValidityNotPermitted
    }

    test("certification requests prove the key and give the names") {
        val root = rootAuthority().authority
        val pair = crypto.keys.generate(KeyType.P256)
        val requests = CertificationRequests(crypto)
        val csr = requests.create(crypto.signatures.signer(pair.privateKey)) {
            subject { commonName(HOST) }
            extensions { subjectAlternativeNames(listOf(GeneralName.Dns(HOST))) }
        }
        val issued = checkNotNull(root.enroll(csr, CertificateProfile.TlsServer).getOrNull())
        issued.extensions.subjectAlternativeNames shouldBe listOf(GeneralName.Dns(HOST))
        val bytes = csr.encoded.toByteArray()
        bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 1).toByte()
        val tampered = checkNotNull(requests.decode(ByteString(bytes)).getOrNull())
        root.enroll(tampered, CertificateProfile.TlsServer).failureOrNull() shouldBe IssuanceFailure.InvalidRequest
        val noP256 = Crypto(environment { policy = cryptoPolicy { curves(EllipticCurve.P384) } })
        val decoded = CertificationRequests(noP256).decode(csr.encoded)
        val unreadable = checkNotNull(decoded.getOrNull())
        root.enroll(unreadable, CertificateProfile.TlsServer).failureOrNull() shouldBe IssuanceFailure.KeyNotPermitted
    }
})
