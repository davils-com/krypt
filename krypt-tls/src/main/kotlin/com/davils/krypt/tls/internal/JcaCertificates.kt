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

package com.davils.krypt.tls.internal

import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.Certificates
import kotlinx.io.bytestring.ByteString
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

internal object JcaCertificates {
    private const val TYPE: String = "X.509"

    const val MAXIMUM_CHAIN: Int = 32

    fun toJca(certificate: Certificate): X509Certificate {
        val factory = CertificateFactory.getInstance(TYPE)
        val stream = ByteArrayInputStream(certificate.encoded.toByteArray())
        return factory.generateCertificate(stream) as X509Certificate
    }

    fun fromJca(codec: Certificates, chain: Array<out X509Certificate>?): List<Certificate>? {
        val presented = chain.orEmpty().toList()
        val isSized = presented.size in 1..MAXIMUM_CHAIN
        val bounded = presented.takeIf { isSized }.orEmpty()
        val decoded = bounded.mapNotNull { found -> codec.decode(ByteString(found.encoded)).getOrNull() }
        return decoded.takeIf { isSized && decoded.size == presented.size }
    }
}
