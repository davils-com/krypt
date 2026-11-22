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

import com.davils.kore.core.outcome.failureOrNull
import com.davils.krypt.cms.CertificateReference
import com.davils.krypt.cms.CmsFailure
import com.davils.krypt.cms.ContentTypes
import com.davils.krypt.cms.fixture.CA_CERTIFICATE
import com.davils.krypt.cms.fixture.CONTENT
import com.davils.krypt.cms.fixture.EC_CERTIFICATE
import com.davils.krypt.cms.fixture.ML_DSA_CERTIFICATE
import com.davils.krypt.cms.fixture.SIGNED_EC
import com.davils.krypt.cms.fixture.SIGNED_EC_DETACHED
import com.davils.krypt.cms.fixture.SIGNED_ED25519
import com.davils.krypt.cms.fixture.SIGNED_KEY_IDENTIFIER
import com.davils.krypt.cms.fixture.SIGNED_ML_DSA
import com.davils.krypt.cms.fixture.SIGNED_NO_ATTRIBUTES
import com.davils.krypt.cms.fixture.SIGNED_RSA_PKCS1
import com.davils.krypt.cms.fixture.SIGNED_RSA_PSS
import com.davils.krypt.cms.fixture.SIGNED_TWO
import com.davils.krypt.cms.fixture.certificate
import com.davils.krypt.cms.fixture.cms
import com.davils.krypt.cms.fixture.crypto
import com.davils.krypt.cms.fixture.value
import com.davils.krypt.cms.fixture.verified
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.x509.path.PathValidation
import com.davils.krypt.x509.path.PathValidator
import com.davils.krypt.x509.path.TrustAnchor
import com.davils.krypt.x509.path.ValidationParameters
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

private const val CERTIFICATES: Int = 3
private const val KEY_IDENTIFIER_VERSION: Int = 3

class OpenSslSignedTest : FunSpec({
    val anchor = TrustAnchor.of(certificate(CA_CERTIFICATE))
    val validator = PathValidator(crypto = crypto, anchors = listOf(anchor))
    val trusted = SignatureParameters(
        validator = validator,
        validation = ValidationParameters(isRevocationRequired = false),
    )

    test("krypt reads and verifies what OpenSSL signs with ECDSA, RSA-PSS, RSA PKCS #1 and Ed25519") {
        val expected = mapOf(
            SIGNED_EC to SignatureAlgorithm.EcdsaSha256,
            SIGNED_RSA_PSS to SignatureAlgorithm.RsaPssSha256,
            SIGNED_RSA_PKCS1 to SignatureAlgorithm.RsaPkcs1Sha384,
            SIGNED_ED25519 to SignatureAlgorithm.Ed25519,
            SIGNED_NO_ATTRIBUTES to SignatureAlgorithm.EcdsaSha256,
            SIGNED_KEY_IDENTIFIER to SignatureAlgorithm.EcdsaSha256,
        )
        expected.forEach { (encoded, algorithm) ->
            val signed = cms.decodeSigned(encoded).value()
            signed.contentType shouldBe ContentTypes.Data
            signed.signers.single().signatureAlgorithm shouldBe algorithm
            val content = CONTENT.takeIf { signed.isDetached }
            val verified = cms.verified(signed, content, trusted).single()
            verified.path.shouldBeInstanceOf<PathValidation.Valid>()
        }
    }

    test("a detached signature needs its content") {
        val signed = cms.decodeSigned(SIGNED_EC_DETACHED).value()
        signed.content shouldBe null
        cms.verify(signed).failureOrNull() shouldBe CmsFailure.ContentMissing
        cms.verify(signed, CONTENT).value().size shouldBe 1
    }

    test("several signers, a key identifier and ML-DSA") {
        val two = cms.decodeSigned(SIGNED_TWO).value()
        two.signers.size shouldBe 2
        two.certificates.size shouldBe CERTIFICATES
        cms.verify(two, parameters = trusted).value().size shouldBe 2
        val keyed = cms.decodeSigned(SIGNED_KEY_IDENTIFIER).value()
        keyed.version shouldBe KEY_IDENTIFIER_VERSION
        keyed.signers.single().identifier shouldBe CertificateReference.KeyIdentifier.of(certificate(EC_CERTIFICATE))
        val mlDsa = cms.decodeSigned(SIGNED_ML_DSA).value()
        mlDsa.signers.single().digestAlgorithm shouldBe DigestAlgorithm.Sha512
        val outcome = cms.verify(mlDsa, parameters = trusted)
        val isSupported = crypto.capabilities.supports(SignatureAlgorithm.MlDsa65)
        val expected = listOf(CmsFailure.AlgorithmNotPermitted, null)[isSupported.compareTo(false)]
        outcome.failureOrNull() shouldBe expected
        certificate(ML_DSA_CERTIFICATE).subject.commonName shouldBe "krypt CMS mldsa"
    }
})
