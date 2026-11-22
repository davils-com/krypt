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

package com.davils.krypt.x509.crl

import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.primitive.Verification
import com.davils.krypt.x509.RevocationReason
import com.davils.krypt.x509.X509Failure
import com.davils.krypt.x509.X509Limits
import com.davils.krypt.x509.fixture.Authority
import com.davils.krypt.x509.fixture.NOW
import com.davils.krypt.x509.fixture.crypto
import com.davils.krypt.x509.fixture.revocationLists
import com.davils.krypt.x509.fixture.utf8
import com.davils.krypt.x509.name.GeneralName
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import kotlin.time.Duration.Companion.days

private const val URL: String = "http://crl.example.com/a.crl"
private const val FIRST: Long = 3L
private const val SECOND: Long = 1L
private const val THIRD: Long = 2L
private const val MISSING: Long = 9L

class RevocationListsTest : FunSpec({
    test("a list is issued, read back and searched by serial number") {
        val root = Authority.root()
        val identifier = utf8("issuer-key")
        val list = revocationLists.issue(root.signer) {
            issuer = root.certificate.subject
            thisUpdate = NOW
            nextUpdate = NOW + 7.days
            number = DerInteger.of(1L)
            issuingDistributionPoint = IssuingDistributionPoint(
                names = listOf(GeneralName.Uri(URL)),
                isUserOnly = true,
                onlySomeReasons = setOf(RevocationReason.KeyCompromise),
            )
            revoke(
                serialNumber = DerInteger.of(FIRST),
                revokedAt = NOW,
                reason = RevocationReason.KeyCompromise,
                invalidAt = NOW - 1.days,
            )
            revoke(DerInteger.of(SECOND), NOW)
            revoke(serialNumber = DerInteger.of(THIRD), revokedAt = NOW, reason = RevocationReason.CertificateHold)
            extensions { authorityKeyIdentifier(identifier) }
        }
        list.entries.map { entry -> entry.serialNumber } shouldBe listOf(
            DerInteger.of(SECOND),
            DerInteger.of(THIRD),
            DerInteger.of(FIRST),
        )
        list.find(DerInteger.of(FIRST))?.reason shouldBe RevocationReason.KeyCompromise
        list.find(DerInteger.of(FIRST))?.invalidAt shouldBe NOW - 1.days
        list.find(DerInteger.of(MISSING)) shouldBe null
        list.number shouldBe DerInteger.of(1L)
        list.isDelta shouldBe false
        list.issuingDistributionPoint?.onlySomeReasons shouldBe setOf(RevocationReason.KeyCompromise)
        list.issuingDistributionPoint?.names shouldBe listOf(GeneralName.Uri(URL))
        list.extensions.authorityKeyIdentifier?.keyIdentifier shouldBe identifier
        revocationLists.verifySignature(list, checkNotNull(root.certificate.publicKey)) shouldBe Verification.Valid
        revocationLists.decodePem(revocationLists.encodePem(list)).getOrNull() shouldBe list
        list shouldNotBe Any()
        list.hashCode() shouldBe list.encoded.hashCode()
        list.toString() shouldContain "entries=3"
        revocationLists.toString() shouldContain "RevocationLists"
    }

    test("a delta list without entries names its base") {
        val root = Authority.root()
        val delta = revocationLists.issue(root.signer) {
            issuer = root.certificate.subject
            thisUpdate = NOW
            number = DerInteger.of(2L)
            deltaOf = DerInteger.of(1L)
            issuingDistributionPoint = IssuingDistributionPoint(isCaOnly = true, isIndirect = true)
        }
        delta.isDelta shouldBe true
        delta.entries shouldBe emptyList()
        delta.nextUpdate shouldBe null
        delta.issuingDistributionPoint?.isIndirect shouldBe true
        shouldThrow<IllegalArgumentException> { revocationLists.issue(root.signer) { thisUpdate = NOW } }
        shouldThrow<IllegalArgumentException> {
            revocationLists.issue(
                root.signer,
            ) { issuer = root.certificate.subject }
        }
        shouldThrow<IllegalArgumentException> {
            revocationLists.issue(root.signer) {
                issuer = root.certificate.subject
                thisUpdate = NOW
            }
        }
        shouldThrow<IllegalArgumentException> {
            IssuingDistributionPoint(
                isUserOnly = true,
                isCaOnly = true,
            )
        }
    }

    test("hostile lists are refused") {
        val root = Authority.root()
        val list = revocationLists.issue(root.signer) {
            issuer = root.certificate.subject
            thisUpdate = NOW
            number = DerInteger.of(1L)
            repeat(3) { index -> revoke(DerInteger.of(index.toLong()), NOW) }
        }
        revocationLists.decode(utf8("junk")).failureOrNull() shouldBe X509Failure.Malformed
        revocationLists.decodePem("nothing").failureOrNull() shouldBe X509Failure.Malformed
        val small = RevocationLists(crypto, X509Limits(maximumRevokedEntries = 2))
        small.decode(list.encoded).failureOrNull() shouldBe X509Failure.Malformed
        val values: List<Any> = listOf(
            RevokedCertificate(DerInteger.of(1L), NOW),
            IssuingDistributionPoint(),
        )
        values.forEach { value ->
            value shouldNotBe Any()
            value.hashCode() shouldBe value.hashCode()
        }
        RevokedCertificate(DerInteger.of(1L), NOW).toString() shouldContain "reason=none"
        IssuingDistributionPoint().toString() shouldContain "reasons=all"
    }
})
