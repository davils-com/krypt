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

import com.davils.krypt.cms.fixture.CONTENT
import com.davils.krypt.cms.fixture.Pki
import com.davils.krypt.cms.fixture.SIGNED_EC
import com.davils.krypt.cms.fixture.SIGNED_ED25519
import com.davils.krypt.cms.fixture.SIGNED_ED448
import com.davils.krypt.cms.fixture.SIGNED_ML_DSA
import com.davils.krypt.cms.fixture.SIGNED_RSA_PKCS1
import com.davils.krypt.cms.fixture.SIGNED_RSA_PSS
import com.davils.krypt.cms.fixture.cms
import com.davils.krypt.cms.fixture.crypto
import com.davils.krypt.cms.fixture.value
import com.davils.krypt.cms.signed.SignedData
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec

private const val TRAILER: Int = 1

private fun jdkSignature(algorithm: SignatureAlgorithm): Signature {
    val names = mapOf(
        SignatureAlgorithm.EcdsaSha256 to "SHA256withECDSA",
        SignatureAlgorithm.EcdsaSha384 to "SHA384withECDSA",
        SignatureAlgorithm.RsaPkcs1Sha384 to "SHA384withRSA",
        SignatureAlgorithm.Ed25519 to "Ed25519",
        SignatureAlgorithm.Ed448 to "Ed448",
        SignatureAlgorithm.MlDsa65 to "ML-DSA-65",
        SignatureAlgorithm.MlDsa44 to "ML-DSA-44",
    )
    val digests = mapOf(
        SignatureAlgorithm.RsaPssSha256 to "SHA-256",
        SignatureAlgorithm.RsaPssSha384 to "SHA-384",
    )
    val digest = digests[algorithm] ?: return Signature.getInstance(names.getValue(algorithm))
    val size = MessageDigest.getInstance(digest).digestLength
    val pss = Signature.getInstance("RSASSA-PSS")
    pss.setParameter(
        PSSParameterSpec(digest, "MGF1", MGF1ParameterSpec(digest), size, TRAILER),
    )
    return pss
}

private fun jdkVerifies(signed: SignedData): Boolean = signed.signers.all { signer ->
    val certificate = CertificateFactory
        .getInstance("X.509")
        .generateCertificate(
            ByteArrayInputStream(
                signed.certificates
                    .first { signer.identifier.matches(it) }
                    .encoded
                    .toByteArray(),
            ),
        )
        as X509Certificate
    val signature = jdkSignature(checkNotNull(signer.signatureAlgorithm))
    signature.initVerify(certificate.publicKey)
    val input = signer.parts.signed?.encoded ?: checkNotNull(signed.content)
    signature.update(input.toByteArray())
    signature.verify(signer.signature.toByteArray())
}

class JdkInteropTest : FunSpec({
    test("java.security verifies the signatures OpenSSL wrote, which krypt verifies as well") {
        listOf(
            SIGNED_EC,
            SIGNED_RSA_PSS,
            SIGNED_RSA_PKCS1,
            SIGNED_ED25519,
            SIGNED_ML_DSA,
            SIGNED_ED448,
        ).forEach { encoded ->
            val signed = cms.decodeSigned(encoded).value()
            val content = CONTENT.takeIf { signed.isDetached }
            val withContent = SignedData(signed.parts.copy(content = CONTENT))
            jdkVerifies(withContent) shouldBe true
            cms.verify(signed, content).value().size shouldBe signed.signers.size
        }
    }

    test("java.security verifies the signatures krypt writes") {
        val pki = Pki.create()
        val types = listOf(KeyType.P384, KeyType.Ed25519, KeyType.Ed448, KeyType.MlDsa44)
        types.forEach { type ->
            val identity = pki.issue(type, "jdk")
            val isEd448 = type == KeyType.Ed448
            val signed = cms.sign(CONTENT) {
                signer(identity.signer, identity.certificate) { isSignedAttributesUsed = !isEd448 }
            }
            jdkVerifies(signed) shouldBe true
        }
        val rsa = pki.issue(KeyType.Rsa3072, "jdk")
        val pss = crypto.signatures.signer(rsa.pair.privateKey, SignatureAlgorithm.RsaPssSha384)
        jdkVerifies(cms.sign(CONTENT) { signer(pss, rsa.certificate) }) shouldBe true
    }
})
