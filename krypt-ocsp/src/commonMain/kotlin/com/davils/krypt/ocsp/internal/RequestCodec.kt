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

package com.davils.krypt.ocsp.internal

import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerFailure
import com.davils.krypt.asn1.DerReader
import com.davils.krypt.asn1.Tag
import com.davils.krypt.asn1.readListOf
import com.davils.krypt.ocsp.CertId
import com.davils.krypt.ocsp.OcspLimits
import com.davils.krypt.ocsp.OcspRequest
import com.davils.krypt.ocsp.internal.CertIdCodec.readCertId
import com.davils.krypt.ocsp.internal.CertIdCodec.writeCertId
import com.davils.krypt.ocsp.internal.ExtensionLists.nonceExtension
import com.davils.krypt.ocsp.internal.ExtensionLists.nonceOf
import com.davils.krypt.ocsp.internal.ExtensionLists.readExtensions
import com.davils.krypt.ocsp.internal.ExtensionLists.writeExtensions
import kotlinx.io.bytestring.ByteString

private const val VERSION: Int = 0
private const val REQUESTOR_NAME: Int = 1
private const val REQUEST_EXTENSIONS: Int = 2
private const val SIGNATURE: Int = 0
private const val SINGLE_EXTENSIONS: Int = 0

internal object RequestCodec {
    fun encode(certIds: List<CertId>, nonce: ByteString?): ByteString = Der.encode {
        sequence {
            sequence {
                sequence { certIds.forEach { certId -> sequence { writeCertId(certId) } } }
                nonce?.let { value -> explicit(REQUEST_EXTENSIONS) { writeExtensions(listOf(nonceExtension(value))) } }
            }
        }
    }

    fun DerReader.readRequest(encoded: ByteString, limits: OcspLimits): OcspRequest = readSequence {
        val (certIds, nonce) = readSequence {
            if (isNext(Tag.context(number = VERSION, isConstructed = true))) {
                refuse(DerFailure.InvalidValue, "the default version left out")
            }
            readOptionalExplicit(REQUESTOR_NAME) { readElement() }
            val ids = readListOf(limits.maximumEntries) { readSingleRequest(limits) }
            val extensions = readOptionalExplicit(REQUEST_EXTENSIONS) {
                readExtensions(limits.maximumExtensions, ExtensionLists.NONCE_ONLY)
            }
            ids to nonceOf(extensions.orEmpty())
        }
        readOptionalExplicit(SIGNATURE) { readElement(Tag.Sequence) }
        if (certIds.isEmpty()) refuse(DerFailure.InvalidValue, "at least one certificate")
        OcspRequest(certIds = certIds, nonce = nonce, encoded = encoded)
    }

    private fun DerReader.readSingleRequest(limits: OcspLimits): CertId = readSequence {
        val certId = readCertId()
        readOptionalExplicit(SINGLE_EXTENSIONS) { readExtensions(limits.maximumExtensions, emptySet()) }
        certId
    }
}
