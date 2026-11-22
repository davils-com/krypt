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

package com.davils.krypt.x509

import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.x509.crl.IssuingDistributionPoint
import com.davils.krypt.x509.crl.RevokedCertificate
import com.davils.krypt.x509.extension.AccessDescription
import com.davils.krypt.x509.extension.AuthorityKeyIdentifier
import com.davils.krypt.x509.extension.BasicConstraints
import com.davils.krypt.x509.extension.Extension
import com.davils.krypt.x509.extension.KeyPurposes
import com.davils.krypt.x509.extension.NameConstraints
import com.davils.krypt.x509.extension.PolicyConstraints
import com.davils.krypt.x509.extension.PolicyMapping
import com.davils.krypt.x509.fixture.NOW
import com.davils.krypt.x509.fixture.utf8
import com.davils.krypt.x509.name.GeneralName
import com.davils.krypt.x509.name.distinguishedName
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain

private val FIRST: ObjectIdentifier = ObjectIdentifier.of("1.2.3.1")
private val SECOND: ObjectIdentifier = ObjectIdentifier.of("1.2.3.2")
private const val HOST: String = "example.com"
private const val LONG_VALUE: Int = 1_025
private const val INHIBITING: String = "PolicyConstraints(requireExplicitPolicy=none, inhibitPolicyMapping=2)"
private const val REQUIRING: String = "PolicyConstraints(requireExplicitPolicy=2, inhibitPolicyMapping=none)"

class ValuesTest : FunSpec({
    test("every field of a value takes part in its equality") {
        BasicConstraints(isCa = true) shouldNotBe BasicConstraints(isCa = false)
        BasicConstraints(isCa = true) shouldNotBe BasicConstraints(isCa = true, pathLength = 1)
        BasicConstraints(isCa = true, pathLength = 1).toString() shouldBe "BasicConstraints(ca=true, pathLength=1)"
        PolicyMapping(
            issuerPolicy = FIRST,
            subjectPolicy = SECOND,
        ) shouldNotBe PolicyMapping(issuerPolicy = SECOND, subjectPolicy = SECOND)
        PolicyMapping(
            issuerPolicy = FIRST,
            subjectPolicy = SECOND,
        ) shouldNotBe PolicyMapping(issuerPolicy = FIRST, subjectPolicy = FIRST)
        PolicyMapping(
            issuerPolicy = FIRST,
            subjectPolicy = SECOND,
        ) shouldBe PolicyMapping(issuerPolicy = FIRST, subjectPolicy = SECOND)
        val ocsp = AccessDescription(KeyPurposes.OcspAccess, GeneralName.Uri(HOST))
        ocsp shouldNotBe AccessDescription(KeyPurposes.CaIssuersAccess, GeneralName.Uri(HOST))
        ocsp shouldNotBe AccessDescription(KeyPurposes.OcspAccess, GeneralName.Dns(HOST))
        ocsp shouldBe AccessDescription(KeyPurposes.OcspAccess, GeneralName.Uri(HOST))
        PolicyConstraints(requireExplicitPolicy = 1) shouldNotBe PolicyConstraints(inhibitPolicyMapping = 1)
        PolicyConstraints(requireExplicitPolicy = 1) shouldNotBe PolicyConstraints(
            requireExplicitPolicy = 1,
            inhibitPolicyMapping = 1,
        )
        PolicyConstraints(requireExplicitPolicy = 1) shouldBe PolicyConstraints(requireExplicitPolicy = 1)
        PolicyConstraints(inhibitPolicyMapping = 2).toString() shouldBe INHIBITING
        PolicyConstraints(requireExplicitPolicy = 2).toString() shouldBe REQUIRING
        AuthorityKeyIdentifier(null).hashCode() shouldBe 0
        AuthorityKeyIdentifier(utf8("a")) shouldNotBe AuthorityKeyIdentifier(utf8("b"))
        val excluded = NameConstraints(excluded = listOf(GeneralName.Dns(HOST)))
        excluded shouldNotBe NameConstraints(permitted = listOf(GeneralName.Dns(HOST)))
        excluded shouldNotBe NameConstraints(
            permitted = listOf(GeneralName.Dns(HOST)),
            excluded = listOf(GeneralName.Dns(HOST)),
        )
        excluded shouldBe NameConstraints(excluded = listOf(GeneralName.Dns(HOST)))
        val extension = Extension(FIRST, false, utf8("x"))
        extension shouldNotBe Extension(SECOND, false, utf8("x"))
        extension shouldNotBe Extension(FIRST, true, utf8("x"))
        extension shouldNotBe Extension(FIRST, false, utf8("y"))
        extension shouldBe Extension(FIRST, false, utf8("x"))
        val revoked = RevokedCertificate(DerInteger.of(1L), NOW, RevocationReason.Superseded)
        revoked shouldBe RevokedCertificate(DerInteger.of(1L), NOW, RevocationReason.Superseded)
        revoked shouldNotBe RevokedCertificate(DerInteger.of(1L), NOW)
        revoked.toString() shouldContain "reason=Superseded"
        val point = IssuingDistributionPoint(onlySomeReasons = setOf(RevocationReason.KeyCompromise))
        point shouldBe IssuingDistributionPoint(onlySomeReasons = setOf(RevocationReason.KeyCompromise))
        point shouldNotBe IssuingDistributionPoint()
        point.toString() shouldContain "reasons=[KeyCompromise]"
    }

    test("limits refuse values past their ceilings") {
        shouldThrow<IllegalArgumentException> { X509Limits(maximumBytes = X509Limits.HARD_MAXIMUM_BYTES + 1) }
        shouldThrow<IllegalArgumentException> { X509Limits(maximumExtensions = X509Limits.HARD_MAXIMUM_EXTENSIONS + 1) }
        shouldThrow<IllegalArgumentException> { X509Limits(maximumNames = X509Limits.HARD_MAXIMUM_NAMES + 1) }
        shouldThrow<IllegalArgumentException> {
            X509Limits(
                maximumRevokedEntries = X509Limits.HARD_MAXIMUM_REVOKED_ENTRIES + 1,
            )
        }
        shouldThrow<IllegalArgumentException> {
            X509Limits(
                maximumPathLength = X509Limits.HARD_MAXIMUM_PATH_LENGTH + 1,
            )
        }
        shouldThrow<IllegalArgumentException> {
            X509Limits(
                maximumPathAttempts = X509Limits.HARD_MAXIMUM_PATH_ATTEMPTS + 1,
            )
        }
        shouldThrow<IllegalArgumentException> { distinguishedName { commonName("x".repeat(LONG_VALUE)) } }
        shouldThrow<IllegalArgumentException> { distinguishedName { country("de") } }
        shouldThrow<IllegalArgumentException> { distinguishedName { country("DEU") } }
    }
})
