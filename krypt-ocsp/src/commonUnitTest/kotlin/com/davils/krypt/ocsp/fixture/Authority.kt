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

package com.davils.krypt.ocsp.fixture

import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.ocsp.CertificateStatus
import com.davils.krypt.ocsp.Ocsp
import com.davils.krypt.ocsp.OcspIssuer
import com.davils.krypt.ocsp.OcspResponder
import com.davils.krypt.ocsp.OcspResponseCache
import com.davils.krypt.ocsp.OcspStatusSource
import com.davils.krypt.primitive.signature.Signer
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.extension.ExtensionsBuilder
import com.davils.krypt.x509.extension.KeyPurposes
import com.davils.krypt.x509.extension.KeyUsage
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant

internal class Authority(val certificate: Certificate, val signer: Signer) {
    val issuer: OcspIssuer get() = OcspIssuer.of(certificate)

    suspend fun issue(
        name: String,
        isCa: Boolean = false,
        notBefore: Instant = NOW - DAYS.days,
        notAfter: Instant = NOW + DAYS.days,
        extensions: ExtensionsBuilder.() -> Unit = defaultsOf(isCa),
    ): Authority {
        val pair = crypto.keys.generate(KeyType.P256)
        val issued = certificates.issue(signer) {
            subject { commonName(name) }
            issuer = certificate.subject
            publicKey = pair.publicKey
            this.notBefore = notBefore
            this.notAfter = notAfter
            extensions(extensions)
        }
        return Authority(issued, crypto.signatures.signer(pair.privateKey))
    }

    suspend fun delegate(extensions: ExtensionsBuilder.() -> Unit = DELEGATED): Authority =
        issue(name = "responder", extensions = extensions)

    fun responder(
        source: OcspStatusSource = GOOD,
        signer: Signer = this.signer,
        certificate: Certificate? = null,
        cache: OcspResponseCache? = null,
        engine: Ocsp = ocsp,
    ): OcspResponder = OcspResponder(
        ocsp = engine,
        issuer = issuer,
        signer = signer,
        source = source,
        responderCertificate = certificate,
        cache = cache,
    )

    companion object {
        val GOOD: OcspStatusSource = OcspStatusSource { _ -> CertificateStatus.Good }

        val DELEGATED: ExtensionsBuilder.() -> Unit = {
            keyUsage(setOf(KeyUsage.DigitalSignature))
            extendedKeyUsage(listOf(KeyPurposes.OcspSigning))
            ocspNoCheck()
        }

        suspend fun root(name: String = ROOT, type: KeyType = KeyType.P256): Authority {
            val pair = crypto.keys.generate(type)
            val signer = crypto.signatures.signer(pair.privateKey)
            val certificate = certificates.issue(signer) {
                subject { commonName(name) }
                publicKey = pair.publicKey
                notBefore = NOW - DAYS.days
                notAfter = NOW + DAYS.days
                extensions(defaultsOf(true))
            }
            return Authority(certificate, signer)
        }

        fun defaultsOf(isCa: Boolean): ExtensionsBuilder.() -> Unit = {
            basicConstraints(isCa = isCa)
            val usages = listOf(setOf(KeyUsage.DigitalSignature), setOf(KeyUsage.KeyCertSign, KeyUsage.CrlSign))
            keyUsage(usages[isCa.compareTo(false)])
        }
    }
}
