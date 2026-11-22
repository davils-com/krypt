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

package com.davils.krypt.ocsp

import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.x509.Certificates
import com.davils.krypt.x509.extension.KeyUsage
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlin.time.Duration.Companion.days

private const val BASIC_FIELDS: Int = 8
private const val RESPONSE_FIELDS: Int = 3

class JavaReachTest : FunSpec({
    test("Java cannot pair the signature of a revoked answer with a good status") {
        val crypto = Crypto()
        val certificates = Certificates(crypto)
        val now = crypto.environment.clock.now()
        val rootPair = crypto.keys.generate(KeyType.P256)
        val rootSigner = crypto.signatures.signer(rootPair.privateKey)
        val root = certificates.issue(rootSigner) {
            subject { commonName("Root") }
            publicKey = rootPair.publicKey
            notBefore = now - 1.days
            notAfter = now + 1.days
            extensions {
                basicConstraints(isCa = true)
                keyUsage(setOf(KeyUsage.KeyCertSign, KeyUsage.CrlSign, KeyUsage.DigitalSignature))
            }
        }
        val leafPair = crypto.keys.generate(KeyType.P256)
        val leaf = certificates.issue(rootSigner) {
            subject { commonName("leaf") }
            issuer = root.subject
            publicKey = leafPair.publicKey
            notBefore = now - 1.days
            notAfter = now + 1.days
        }
        val ocsp = Ocsp(crypto)
        val issuer = OcspIssuer.of(root)
        val responder = OcspResponder(
            ocsp = ocsp,
            issuer = issuer,
            signer = rootSigner,
            source = { _ -> CertificateStatus.Revoked(now - 1.days) },
        )
        val certId = ocsp.certId(certificate = leaf, issuer = issuer)
        val revoked = checkNotNull(ocsp.decodeResponse(responder.presign(leaf.serialNumber)).getOrNull())
        val basic = checkNotNull(revoked.basic)
        val good = SingleResponse(certId = certId, status = CertificateStatus.Good, thisUpdate = now)
        val basicConstructor = BasicOcspResponse::class.java.constructors.firstOrNull { found ->
            found.parameterCount == BASIC_FIELDS
        }
        val responseConstructor = OcspResponse::class.java.constructors.firstOrNull { found ->
            found.parameterCount == RESPONSE_FIELDS
        }
        val forgedBasic = basicConstructor?.newInstance(
            basic.responderId,
            basic.producedAt,
            listOf(good),
            basic.nonce,
            basic.signatureAlgorithm,
            basic.signature,
            basic.certificates,
            basic.tbs,
        )
        val forged = forgedBasic?.let { found ->
            responseConstructor?.newInstance(revoked.status, found, revoked.encoded) as? OcspResponse
        }
        val status = forged?.let { response ->
            ocsp.verify(response = response, certificate = leaf, issuer = issuer).getOrNull()?.status
        }
        status shouldBe null
        val sealed = BasicOcspResponse::class.java.constructors.single()
        sealed.parameterTypes.single().name shouldBe "com.davils.krypt.ocsp.internal.BasicResponseParts"
    }
})
