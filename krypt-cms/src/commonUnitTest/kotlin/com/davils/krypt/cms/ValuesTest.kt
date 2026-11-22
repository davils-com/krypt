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

package com.davils.krypt.cms

import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.cms.fixture.CA_CERTIFICATE
import com.davils.krypt.cms.fixture.EC_CERTIFICATE
import com.davils.krypt.cms.fixture.Pki
import com.davils.krypt.cms.fixture.certificate
import com.davils.krypt.cms.fixture.checkValue
import com.davils.krypt.cms.fixture.cms
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlinx.io.bytestring.ByteString

private val TYPE: ObjectIdentifier = ObjectIdentifier.of("1.2.3")
private val OTHER_TYPE: ObjectIdentifier = ObjectIdentifier.of("1.2.4")

class ValuesTest : FunSpec({
    test("limits are checked against their ceilings") {
        val limits = CmsLimits()
        checkValue(
            value = limits,
            same = CmsLimits.Default,
            different = listOf(
                CmsLimits(maximumBytes = 1),
                CmsLimits(maximumContentBytes = 1),
                CmsLimits(maximumSigners = 1),
                CmsLimits(maximumAttributes = 1),
                CmsLimits(maximumCertificates = 1),
                CmsLimits(maximumRevocationLists = 1),
                CmsLimits(maximumRecipients = 1),
                CmsLimits(maximumNesting = 1),
            ),
        ) shouldContain "maximumNesting=${CmsLimits.DEFAULT_MAXIMUM_NESTING}"
        val invalid = listOf<() -> CmsLimits>(
            { CmsLimits(maximumBytes = 0) },
            { CmsLimits(maximumBytes = CmsLimits.HARD_MAXIMUM_BYTES + 1) },
            { CmsLimits(maximumContentBytes = 0) },
            { CmsLimits(maximumContentBytes = CmsLimits.HARD_MAXIMUM_BYTES + 1) },
            { CmsLimits(maximumSigners = 0) },
            { CmsLimits(maximumSigners = CmsLimits.HARD_MAXIMUM_SIGNERS + 1) },
            { CmsLimits(maximumAttributes = 0) },
            { CmsLimits(maximumAttributes = CmsLimits.HARD_MAXIMUM_ATTRIBUTES + 1) },
            { CmsLimits(maximumCertificates = 0) },
            { CmsLimits(maximumCertificates = CmsLimits.HARD_MAXIMUM_CERTIFICATES + 1) },
            { CmsLimits(maximumRevocationLists = 0) },
            { CmsLimits(maximumRevocationLists = CmsLimits.HARD_MAXIMUM_REVOCATION_LISTS + 1) },
            { CmsLimits(maximumRecipients = 0) },
            { CmsLimits(maximumRecipients = CmsLimits.HARD_MAXIMUM_RECIPIENTS + 1) },
            { CmsLimits(maximumNesting = 0) },
            { CmsLimits(maximumNesting = CmsLimits.HARD_MAXIMUM_NESTING + 1) },
        )
        invalid.forEach { create -> shouldThrow<IllegalArgumentException> { create() } }
        cms.toString() shouldContain "CmsLimits"
    }

    test("attributes compare their type and values") {
        val attribute = Attribute(TYPE, listOf(ByteString(1)))
        checkValue(
            value = attribute,
            same = Attribute(TYPE, listOf(ByteString(1))),
            different = listOf(Attribute(OTHER_TYPE, listOf(ByteString(1))), Attribute(TYPE, listOf(ByteString(2)))),
        ) shouldBe "Attribute(1.2.3, 1 values)"
        shouldThrow<IllegalArgumentException> { Attribute(TYPE, emptyList()) }
    }

    test("certificate references match their certificate") {
        val certificate = certificate(EC_CERTIFICATE)
        val root = certificate(CA_CERTIFICATE)
        val issuerSerial = CertificateReference.IssuerSerial.of(certificate)
        issuerSerial.matches(certificate) shouldBe true
        issuerSerial.matches(root) shouldBe false
        val bySubject = CertificateReference.IssuerSerial(certificate.subject.encoded, certificate.serialNumber)
        bySubject.matches(certificate) shouldBe false
        checkValue(
            value = issuerSerial,
            same = CertificateReference.IssuerSerial(certificate.issuer.encoded, certificate.serialNumber),
            different = listOf(
                CertificateReference.IssuerSerial(certificate.issuer.encoded, DerInteger.of(1)),
                CertificateReference.IssuerSerial(ByteString(1), certificate.serialNumber),
            ),
        ) shouldBe "IssuerSerial(10)"
        val keyIdentifier = CertificateReference.KeyIdentifier.of(certificate)
        keyIdentifier.matches(certificate) shouldBe true
        keyIdentifier.matches(root) shouldBe false
        checkValue(
            value = keyIdentifier,
            same = CertificateReference.KeyIdentifier(keyIdentifier.keyIdentifier),
            different = listOf(CertificateReference.KeyIdentifier(ByteString(1))),
        ) shouldContain "KeyIdentifier("
    }

    test("a reference by key identifier needs the extension") {
        val pki = Pki.create()
        shouldThrow<IllegalArgumentException> { CertificateReference.KeyIdentifier.of(pki.certificate) }
        ContentTypes.Data.dotted shouldBe "1.2.840.113549.1.7.1"
    }
})
