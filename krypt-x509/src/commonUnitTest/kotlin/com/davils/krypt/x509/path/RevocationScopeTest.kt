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

package com.davils.krypt.x509.path

import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.RevocationReason
import com.davils.krypt.x509.crl.IssuingDistributionPoint
import com.davils.krypt.x509.crl.RevocationList
import com.davils.krypt.x509.extension.DistributionPoint
import com.davils.krypt.x509.extension.Extension
import com.davils.krypt.x509.extension.KeyUsage
import com.davils.krypt.x509.fixture.Authority
import com.davils.krypt.x509.fixture.NOW
import com.davils.krypt.x509.fixture.crypto
import com.davils.krypt.x509.fixture.der
import com.davils.krypt.x509.fixture.revocationLists
import com.davils.krypt.x509.name.GeneralName
import com.davils.krypt.x509.name.distinguishedName
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours

private const val HOST: String = "api.example.com"
private const val ISSUER_HOURS: Int = 3
private val UNKNOWN: ObjectIdentifier = ObjectIdentifier.of("1.3.6.1.4.1.99999.9")
private val POINT_A: GeneralName = GeneralName.Uri("http://crl.example.com/a.crl")
private val POINT_B: GeneralName = GeneralName.Uri("http://crl.example.com/b.crl")

private suspend fun issuedList(
    root: Authority,
    number: Long,
    point: IssuingDistributionPoint? = null,
    revoked: Certificate? = null,
    isCritical: Boolean = false,
): RevocationList = revocationLists.issue(root.signer) {
    issuer = root.certificate.subject
    thisUpdate = NOW - number.hours
    nextUpdate = NOW + 1.days
    this.number = DerInteger.of(number)
    issuingDistributionPoint = point
    revoked?.let { certificate -> revoke(certificate.serialNumber, NOW - ISSUER_HOURS.hours) }
    if (isCritical) extensions { add(Extension(UNKNOWN, true, der { nullValue() })) }
}

private suspend fun statusOf(root: Authority, certificate: Certificate, lists: List<RevocationList>): RevocationStatus {
    val checker = CrlRevocationChecker(revocationLists) { _ -> lists }
    return checker.check(certificate = certificate, issuer = null, anchor = TrustAnchor.of(root.certificate), at = NOW)
}

private suspend fun pointed(root: Authority, point: DistributionPoint): Certificate = root
    .issue(HOST, extensions = {
        basicConstraints(isCa = false)
        keyUsage(setOf(KeyUsage.DigitalSignature))
        crlDistributionPoints(listOf(point))
    })
    .certificate

class RevocationScopeTest : FunSpec({
    test("a partition of a revocation list does not vouch for a certificate of another partition") {
        val root = Authority.root()
        val leaf = pointed(root, DistributionPoint(listOf(POINT_B)))
        val partitionB = issuedList(
            root = root,
            number = 2L,
            point = IssuingDistributionPoint(names = listOf(POINT_B)),
            revoked = leaf,
        )
        val partitionA = issuedList(root, number = 1L, point = IssuingDistributionPoint(names = listOf(POINT_A)))
        statusOf(root, leaf, listOf(partitionA)) shouldBe RevocationStatus.Unknown
        statusOf(root, leaf, listOf(partitionA, partitionB)) shouldBe RevocationStatus.Revoked
        val cleanB = issuedList(root, number = 1L, point = IssuingDistributionPoint(names = listOf(POINT_B)))
        statusOf(root, leaf, listOf(partitionA, cleanB)) shouldBe RevocationStatus.Good
        val validator = PathValidator(
            crypto = crypto,
            anchors = listOf(TrustAnchor.of(root.certificate)),
            revocation = CrlRevocationChecker(revocationLists) { _ -> listOf(partitionA, partitionB) },
        )
        validator.validate(leaf, parameters = ValidationParameters(at = NOW)).isValid shouldBe false
    }

    test("a partitioned list does not cover a certificate without distribution points") {
        val root = Authority.root()
        val leaf = root.issue(HOST).certificate
        val partition = issuedList(root, number = 1L, point = IssuingDistributionPoint(names = listOf(POINT_A)))
        statusOf(root, leaf, listOf(partition)) shouldBe RevocationStatus.Unknown
    }

    test("the list issuer of a distribution point names a partition") {
        val root = Authority.root()
        val issuerName = GeneralName.Directory(distinguishedName { commonName("CRL issuer") })
        val leaf = pointed(root, DistributionPoint(names = emptyList(), crlIssuer = listOf(issuerName)))
        val partition = issuedList(root, number = 1L, point = IssuingDistributionPoint(names = listOf(issuerName)))
        statusOf(root, leaf, listOf(partition)) shouldBe RevocationStatus.Good
    }

    test("a revocation in any applicable list wins over a newer list") {
        val root = Authority.root()
        val leaf = root.issue(HOST).certificate
        val older = issuedList(root, number = 2L, revoked = leaf)
        val newer = issuedList(root, number = 1L)
        statusOf(root, leaf, listOf(newer, older)) shouldBe RevocationStatus.Revoked
    }

    test("lists of some reasons are good only together") {
        val root = Authority.root()
        val leaf = root.issue(HOST).certificate
        val compromise = setOf(RevocationReason.KeyCompromise)
        val rest = RevocationReason.entries.filter { reason -> reason.bit != null && reason !in compromise }.toSet()
        val first = issuedList(root, number = 1L, point = IssuingDistributionPoint(onlySomeReasons = compromise))
        val second = issuedList(root, number = 2L, point = IssuingDistributionPoint(onlySomeReasons = rest))
        statusOf(root, leaf, listOf(first)) shouldBe RevocationStatus.Unknown
        statusOf(root, leaf, listOf(first, second)) shouldBe RevocationStatus.Good
    }

    test("lists of end entities, authorities or other issuers cover only their scope") {
        val root = Authority.root()
        val leaf = root.issue(HOST).certificate
        val authority = root.issue("intermediate", isCa = true).certificate
        val users = issuedList(root, number = 1L, point = IssuingDistributionPoint(isUserOnly = true))
        val authorities = issuedList(root, number = 1L, point = IssuingDistributionPoint(isCaOnly = true))
        val indirect = issuedList(root, number = 1L, point = IssuingDistributionPoint(isIndirect = true))
        statusOf(root, leaf, listOf(users)) shouldBe RevocationStatus.Good
        statusOf(root, authority, listOf(users)) shouldBe RevocationStatus.Unknown
        statusOf(root, authority, listOf(authorities)) shouldBe RevocationStatus.Good
        statusOf(root, leaf, listOf(authorities)) shouldBe RevocationStatus.Unknown
        statusOf(root, leaf, listOf(indirect)) shouldBe RevocationStatus.Unknown
    }

    test("a revocation list with an unknown critical extension is not used") {
        val root = Authority.root()
        val leaf = root.issue(HOST).certificate
        val list = issuedList(root, number = 1L, isCritical = true)
        list.unknownCritical shouldBe listOf(UNKNOWN)
        statusOf(root, leaf, listOf(list)) shouldBe RevocationStatus.Unknown
    }

    test("a failing source of revocation lists yields an unknown status") {
        val root = Authority.root()
        val leaf = root.issue(HOST).certificate
        val failing = CrlRevocationChecker(revocationLists) { _ -> error("unreachable") }
        val anchor = TrustAnchor.of(root.certificate)
        failing.check(certificate = leaf, issuer = null, anchor = anchor, at = NOW) shouldBe RevocationStatus.Unknown
    }
})
