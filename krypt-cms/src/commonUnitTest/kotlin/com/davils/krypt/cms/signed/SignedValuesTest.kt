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

package com.davils.krypt.cms.signed

import com.davils.krypt.cms.fixture.CONTENT
import com.davils.krypt.cms.fixture.EC_CERTIFICATE
import com.davils.krypt.cms.fixture.Pki
import com.davils.krypt.cms.fixture.SIGNED_EC
import com.davils.krypt.cms.fixture.SIGNED_TWO
import com.davils.krypt.cms.fixture.certificate
import com.davils.krypt.cms.fixture.checkValue
import com.davils.krypt.cms.fixture.cms
import com.davils.krypt.cms.fixture.value
import com.davils.krypt.x509.path.ValidationParameters
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain

class SignedValuesTest : FunSpec({
    test("signed data and signers compare their encodings") {
        val signed = cms.decodeSigned(SIGNED_EC).value()
        val two = cms.decodeSigned(SIGNED_TWO).value()
        checkValue(value = signed, same = cms.decodeSigned(SIGNED_EC).value(), different = listOf(two)) shouldBe
            "SignedData(1.2.840.113549.1.7.1, 1 signers, detached=false)"
        val signer = signed.signers.single()
        checkValue(value = signer, same = signed.signers.single(), different = two.signers) shouldContain
            "ECDSA-SHA-256"
        signed.content shouldBe CONTENT
    }

    test("parameters and results compare every property") {
        val pki = Pki.create()
        val trusted = pki.parameters
        val certificate = certificate(EC_CERTIFICATE)
        val parameters = SignatureParameters(certificates = listOf(certificate))
        checkValue(
            value = parameters,
            same = SignatureParameters(certificates = listOf(certificate)),
            different = listOf(
                SignatureParameters(),
                SignatureParameters(certificates = listOf(certificate), validator = trusted.validator),
                SignatureParameters(
                    certificates = listOf(certificate),
                    validation = ValidationParameters(isRevocationRequired = false),
                ),
            ),
        ) shouldBe "SignatureParameters(1 certificates, path=false)"
        val signed = cms.decodeSigned(SIGNED_TWO).value()
        val verified = cms.verify(signed).value()
        val first = verified.first()
        val second = verified.last()
        val withPath = VerifiedSigner(signer = first.signer, certificate = first.certificate, path = null)
        checkValue(
            value = first,
            same = withPath,
            different = listOf(
                second,
                VerifiedSigner(signer = first.signer, certificate = second.certificate, path = null),
                VerifiedSigner(signer = second.signer, certificate = first.certificate, path = null),
            ),
        ) shouldContain "VerifiedSigner("
    }
})
