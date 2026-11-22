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

package com.davils.krypt.ct.internal

import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerReader
import com.davils.krypt.asn1.Tag
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.policy.AlgorithmUse
import com.davils.krypt.ct.SctOrigin
import com.davils.krypt.ct.SignedCertificateTimestamp
import com.davils.krypt.ct.internal.TlsWriter.Companion.tls
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.extension.ExtensionIds
import kotlinx.io.bytestring.ByteString

private const val V1: Int = 0
private const val CERTIFICATE_TIMESTAMP: Int = 0
private const val X509_ENTRY: Int = 0
private const val PRECERT_ENTRY: Int = 1
private const val EXTENSIONS: Int = 3

internal object SignedData {
    suspend fun of(
        crypto: Crypto,
        timestamp: SignedCertificateTimestamp,
        origin: SctOrigin,
        certificate: Certificate,
        issuer: Certificate,
    ): ByteString {
        val entry = when (origin) {
            SctOrigin.Embedded -> precertEntry(crypto = crypto, certificate = certificate, issuer = issuer)

            SctOrigin.Tls, SctOrigin.Ocsp -> tls {
                u16(X509_ENTRY)
                vector24(certificate.encoded)
            }
        }
        return tls {
            u8(V1)
            u8(CERTIFICATE_TIMESTAMP)
            u64(timestamp.timestamp.toEpochMilliseconds())
            bytes(entry)
            vector16(timestamp.extensions)
        }
    }

    fun precertificate(tbs: ByteString): ByteString =
        checkNotNull(Der.decodeOrNull(tbs) { readSequence { readPrecertificate() } }) { "A decoded certificate" }

    private suspend fun precertEntry(crypto: Crypto, certificate: Certificate, issuer: Certificate): ByteString {
        val issuerKeyHash = crypto.digests.digest(
            data = issuer.subjectPublicKeyInfo,
            algorithm = DigestAlgorithm.Sha256,
            use = AlgorithmUse.Verify,
        )
        val tbs = precertificate(certificate.tbs)
        return tls {
            u16(PRECERT_ENTRY)
            bytes(issuerKeyHash)
            vector24(tbs)
        }
    }

    private fun DerReader.readPrecertificate(): ByteString {
        val extensionsTag = Tag.context(number = EXTENSIONS, isConstructed = true)
        val fields = mutableListOf<ByteString>()
        while (!isExhausted && !isNext(extensionsTag)) fields += readElement().encoded
        val kept = readOptionalExplicit(EXTENSIONS) { readSequence { readKept() } }.orEmpty()
        return Der.encode {
            sequence {
                fields.forEach { field -> raw(field) }
                if (kept.isNotEmpty()) {
                    explicit(
                        EXTENSIONS,
                    ) { sequence { kept.forEach { extension -> raw(extension) } } }
                }
            }
        }
    }

    private fun DerReader.readKept(): List<ByteString> {
        val kept = mutableListOf<ByteString>()
        while (!isExhausted) {
            val extension = readElement(Tag.Sequence)
            val id = extension.reader().readObjectIdentifier()
            if (id != ExtensionIds.SignedCertificateTimestamps) kept += extension.encoded
        }
        return kept
    }
}
