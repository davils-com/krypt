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

import com.davils.krypt.asn1.DerFailure
import com.davils.krypt.asn1.DerReader
import com.davils.krypt.asn1.DerWriter
import com.davils.krypt.asn1.Tag
import com.davils.krypt.ocsp.CertId

internal object CertIdCodec {
    fun DerWriter.writeCertId(certId: CertId) {
        sequence {
            sequence {
                objectIdentifier(OcspOids.DIGESTS.getValue(certId.hashAlgorithm))
                nullValue()
            }
            octetString(certId.issuerNameHash)
            octetString(certId.issuerKeyHash)
            integer(certId.serialNumber)
        }
    }

    fun DerReader.readCertId(): CertId = readSequence {
        val digest = readSequence {
            val oid = readObjectIdentifier()
            if (isNext(Tag.Null)) readNull()
            OcspOids.digestOf(oid)
        }
        val algorithm = digest ?: refuse(DerFailure.InvalidValue, "a known digest")
        val nameHash = readOctetString()
        val keyHash = readOctetString()
        val serial = readInteger()
        val size = algorithm.outputBytes
        if (nameHash.size != size || keyHash.size != size) refuse(DerFailure.InvalidValue, "digests of their size")
        CertId(hashAlgorithm = algorithm, issuerNameHash = nameHash, issuerKeyHash = keyHash, serialNumber = serial)
    }
}
