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

import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.Verification
import com.davils.krypt.x509.extension.KeyPurposes
import com.davils.krypt.x509.extension.KeyUsage
import com.davils.krypt.x509.name.GeneralName
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant

private const val NOW: Long = 1_800_000_000L

class InteropTest : FunSpec({
    test("the JDK reads what krypt issues and krypt reads it back") {
        val crypto = Crypto()
        val certificates = Certificates(crypto)
        val types = listOf(KeyType.P256, KeyType.Ed25519, KeyType.Rsa3072)
        types.forEach { type ->
            val pair = crypto.keys.generate(type)
            val signer = crypto.signatures.signer(pair.privateKey)
            val now = Instant.fromEpochSeconds(NOW)
            val certificate = certificates.issue(signer) {
                subject {
                    country("DE")
                    organization("Davils")
                    commonName("krypt test $type")
                }
                publicKey = pair.publicKey
                notBefore = now
                notAfter = now + 30.days
                extensions {
                    basicConstraints(isCa = true, pathLength = 0)
                    keyUsage(setOf(KeyUsage.KeyCertSign, KeyUsage.CrlSign, KeyUsage.DigitalSignature))
                    extendedKeyUsage(listOf(KeyPurposes.ServerAuth, KeyPurposes.ClientAuth))
                    subjectAlternativeNames(
                        listOf(
                            GeneralName.Dns("example.com"),
                            checkNotNull(GeneralName.IpAddress.parseOrNull("2001:db8::1")),
                        ),
                    )
                }
            }
            val jdk = CertificateFactory
                .getInstance("X.509")
                .generateCertificate(ByteArrayInputStream(certificate.encoded.toByteArray())) as X509Certificate
            jdk.verify(jdk.publicKey)
            jdk.basicConstraints shouldBe 0
            jdk.subjectX500Principal.name shouldBe "CN=krypt test $type,O=Davils,C=DE"
            certificate.subject.rfc4514() shouldBe "CN=krypt test $type,O=Davils,C=DE"
            certificates.verifySignature(certificate, pair.publicKey) shouldBe Verification.Valid
            val decoded = checkNotNull(certificates.decode(certificate.encoded).getOrNull())
            decoded.extensions.subjectAlternativeNames.size shouldBe 2
            decoded.extensions.basicConstraints?.pathLength shouldBe 0
            decoded.extensions.keyUsage shouldBe setOf(
                KeyUsage.KeyCertSign,
                KeyUsage.CrlSign,
                KeyUsage.DigitalSignature,
            )
            checkNotNull(
                certificates.decodePem(certificates.encodePem(certificate)).getOrNull(),
            ).single() shouldBe certificate
        }
    }
})
