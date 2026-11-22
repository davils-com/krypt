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

@file:OptIn(LegacyCryptography::class)

package com.davils.krypt.cms.internal

import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.asn1.DerReader
import com.davils.krypt.asn1.Tag
import com.davils.krypt.asn1.readRemaining
import com.davils.krypt.cms.internal.Algorithms.readDigestAlgorithm
import com.davils.krypt.core.LegacyCryptography
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.x509.Certificate
import kotlinx.io.bytestring.ByteString

private const val DIRECTORY_NAME: Int = 4

internal class EssCertId(
    val digest: DigestAlgorithm?,
    val hash: ByteString,
    val issuers: List<ByteString>?,
    val serialNumber: DerInteger?,
) {
    fun isIssuerSerialOf(certificate: Certificate): Boolean {
        val isIssuer = issuers?.contains(certificate.issuer.encoded) != false
        val isSerial = serialNumber?.let { serial -> serial == certificate.serialNumber } != false
        return isIssuer && isSerial
    }

    companion object {
        private val DIRECTORY: Tag = Tag.context(number = DIRECTORY_NAME, isConstructed = true)

        fun DerReader.readFirstCertId(isVersion2: Boolean, maximum: Int): EssCertId = readSequence {
            val first = readSequence {
                if (isExhausted) malformed("a certificate identifier")
                val id = readSequence { readCertId(isVersion2, maximum) }
                readRemaining()
                id
            }
            readRemaining()
            first
        }

        private fun DerReader.readCertId(isVersion2: Boolean, maximum: Int): EssCertId {
            val isAlgorithm = isVersion2 && isNext(Tag.Sequence)
            val digest = when (isAlgorithm) {
                true -> readDigestAlgorithm()
                false -> defaultDigest(isVersion2)
            }
            val hash = readOctetString()
            val issuerSerial = takeUnless { isExhausted }?.readSequence {
                val names = readSequence {
                    val all = readRemaining()
                    if (all.size > maximum) limited("at most $maximum general names")
                    all.filter { name -> name.tag == DIRECTORY }.map { name ->
                        name.parse(
                            DIRECTORY,
                        ) { readElement().encoded }
                    }
                }
                names to readInteger()
            }
            return EssCertId(
                digest = digest,
                hash = hash,
                issuers = issuerSerial?.first,
                serialNumber = issuerSerial?.second,
            )
        }

        private fun defaultDigest(isVersion2: Boolean): DigestAlgorithm =
            listOf(DigestAlgorithm.Sha1, DigestAlgorithm.Sha256)[isVersion2.compareTo(false)]
    }
}
