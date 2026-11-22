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

import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.RevocationReason
import com.davils.krypt.x509.crl.IssuingDistributionPoint
import com.davils.krypt.x509.crl.RevocationList
import com.davils.krypt.x509.extension.KeyUsage
import com.davils.krypt.x509.fixture.Authority
import com.davils.krypt.x509.fixture.NOW
import com.davils.krypt.x509.fixture.crypto
import com.davils.krypt.x509.fixture.revocationLists
import com.davils.krypt.x509.name.GeneralName
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import kotlinx.io.bytestring.ByteString
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant

private const val HOST: String = "api.example.com"
private const val LONG_LABEL: Int = 64

private suspend fun Authority.list(
    revoked: List<Pair<DerInteger, RevocationReason?>> = emptyList(),
    next: Instant? = NOW + 1.days,
    point: IssuingDistributionPoint? = null,
    delta: Boolean = false,
): RevocationList = revocationLists.issue(signer) {
    issuer = certificate.subject
    thisUpdate = NOW - 1.days
    nextUpdate = next
    number = DerInteger.of(1L)
    issuingDistributionPoint = point
    deltaOf = DerInteger.of(1L).takeIf { delta }
    revoked.forEach { (serial, reason) -> revoke(serial, NOW - 1.days, reason) }
}

class IdentityTest : FunSpec({
    test("service identities match by RFC 9525") {
        val root = Authority.root()
        val names = listOf(
            GeneralName.Dns(HOST),
            GeneralName.Dns("*.apps.example.com"),
            GeneralName.Dns("*.com"),
            GeneralName.Dns("f*o.example.com"),
            checkNotNull(GeneralName.IpAddress.parseOrNull("192.0.2.1")),
            checkNotNull(GeneralName.IpAddress.parseOrNull("2001:db8::1")),
        )
        val certificate = root.issue(HOST, extensions = { subjectAlternativeNames(names) }).certificate
        listOf(
            HOST,
            "API.Example.COM.",
            "x.apps.example.com",
            "192.0.2.1",
            "[2001:db8::1]",
            "2001:DB8::1",
        ).forEach { host ->
            ServiceIdentity.matches(certificate, host) shouldBe true
        }
        listOf(
            "example.com",
            "a.b.apps.example.com",
            "apps.example.com",
            "x.com",
            "foo.example.com",
            "192.0.2.2",
            "",
            "a..b",
            "-a.example.com",
            "a_b.example.com",
            "x".repeat(LONG_LABEL) + ".com",
        ).forEach { host -> ServiceIdentity.matches(certificate, host) shouldBe false }
    }

    test("pins match a key of the path") {
        val root = Authority.root()
        val leaf = root.issue(HOST)
        val valid = PathValidator(
            crypto,
            listOf(TrustAnchor.of(root.certificate)),
        ).validate(leaf.certificate, parameters = ValidationParameters(at = NOW))
            as PathValidation.Valid
        PinSet.of(crypto, listOf(root.certificate)).matches(crypto, valid) shouldBe true
        PinSet.of(crypto, listOf(Authority.root().certificate)).matches(crypto, valid) shouldBe false
        val pins = PinSet.of(crypto, listOf(leaf.certificate))
        pins shouldBe PinSet(pins.pins)
        pins.hashCode() shouldBe pins.pins.hashCode()
        pins shouldNotBe Any()
        pins.toString() shouldContain "PinSet("
        shouldThrow<IllegalArgumentException> { PinSet(emptySet()) }
        shouldThrow<IllegalArgumentException> { PinSet(setOf(ByteString(1))) }
    }

    test("revocation lists decide only when they are authentic, fresh and in scope") {
        val root = Authority.root()
        val leaf = root.issue(HOST)
        val serial = leaf.certificate.serialNumber
        val anchor = TrustAnchor.of(root.certificate)

        suspend fun statusWith(lists: List<RevocationList>, issuer: Certificate? = null): RevocationStatus =
            CrlRevocationChecker(revocationLists) { _ -> lists }.check(
                certificate = leaf.certificate,
                issuer = issuer,
                anchor = anchor,
                at = NOW,
            )
        statusWith(listOf(root.list())) shouldBe RevocationStatus.Good
        statusWith(
            listOf(root.list(listOf(serial to RevocationReason.KeyCompromise))),
        ) shouldBe RevocationStatus.Revoked
        statusWith(listOf(root.list(listOf(serial to RevocationReason.RemoveFromCrl)))) shouldBe RevocationStatus.Good
        statusWith(listOf(root.list(next = null))) shouldBe RevocationStatus.Unknown
        statusWith(listOf(root.list(next = NOW - 1.days))) shouldBe RevocationStatus.Unknown
        statusWith(listOf(Authority.root().list())) shouldBe RevocationStatus.Unknown
        statusWith(listOf(root.list(delta = true))) shouldBe RevocationStatus.Unknown
        statusWith(
            listOf(root.list(point = IssuingDistributionPoint(isCaOnly = true))),
        ) shouldBe RevocationStatus.Unknown
        statusWith(
            listOf(root.list(point = IssuingDistributionPoint(isIndirect = true))),
        ) shouldBe RevocationStatus.Unknown
        statusWith(
            listOf(root.list(point = IssuingDistributionPoint(isUserOnly = true))),
        ) shouldBe RevocationStatus.Good
        statusWith(
            listOf(
                root.list(point = IssuingDistributionPoint(onlySomeReasons = setOf(RevocationReason.KeyCompromise))),
            ),
        ) shouldBe
            RevocationStatus.Unknown
        val impostor = Authority.root()
        val forged = revocationLists.issue(impostor.signer) {
            issuer = root.certificate.subject
            thisUpdate = NOW - 1.days
            nextUpdate = NOW + 1.days
            number = DerInteger.of(2L)
        }
        statusWith(listOf(forged)) shouldBe RevocationStatus.Unknown
        statusWith(listOf(root.list()), issuer = root.certificate) shouldBe RevocationStatus.Good
        val noCrlSign = Authority.root(
            extensions = {
                basicConstraints(isCa = true)
                keyUsage(setOf(KeyUsage.KeyCertSign))
            },
        )
        statusWith(listOf(root.list()), issuer = noCrlSign.certificate) shouldBe RevocationStatus.Unknown
        CrlRevocationChecker(revocationLists) { _ -> emptyList() }.toString() shouldContain "CrlRevocationChecker"
        val caLeaf = root.issue("ca", isCa = true).certificate
        CrlRevocationChecker(revocationLists) { _ ->
            listOf(
                root.list(point = IssuingDistributionPoint(isUserOnly = true)),
            )
        }.check(certificate = caLeaf, issuer = null, anchor = anchor, at = NOW) shouldBe RevocationStatus.Unknown
        revocationLists.decode(root.list().encoded).getOrNull() shouldNotBe null
    }
})
