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

package com.davils.krypt.cms.internal

import com.davils.krypt.asn1.DerReader
import com.davils.krypt.asn1.DerWriter
import com.davils.krypt.asn1.Tag
import com.davils.krypt.asn1.readRemaining
import com.davils.krypt.cms.CertificateReference
import com.davils.krypt.x509.Certificate

private const val KEY_IDENTIFIER: Int = 0

internal object References {
    private val KEY_ID: Tag = Tag.context(number = KEY_IDENTIFIER, isConstructed = false)
    private val RECIPIENT_KEY_ID: Tag = Tag.context(number = KEY_IDENTIFIER, isConstructed = true)

    fun of(certificate: Certificate, isKeyIdentifier: Boolean): CertificateReference = when (isKeyIdentifier) {
        true -> CertificateReference.KeyIdentifier.of(certificate)
        false -> CertificateReference.IssuerSerial.of(certificate)
    }

    fun DerReader.readReference(): CertificateReference {
        val keyIdentifier = readOptional(KEY_ID)?.content
        return keyIdentifier?.let { found -> CertificateReference.KeyIdentifier(found) } ?: readIssuerSerial()
    }

    fun DerReader.readRecipientKeyReference(): CertificateReference {
        val keyIdentifier = readOptional(RECIPIENT_KEY_ID)?.parse(RECIPIENT_KEY_ID) {
            val identifier = readOctetString()
            readRemaining()
            identifier
        }
        return keyIdentifier?.let { found -> CertificateReference.KeyIdentifier(found) } ?: readIssuerSerial()
    }

    fun DerWriter.writeReference(reference: CertificateReference) {
        when (reference) {
            is CertificateReference.KeyIdentifier -> octetString(reference.keyIdentifier, KEY_ID)
            is CertificateReference.IssuerSerial -> writeIssuerSerial(reference)
        }
    }

    fun DerWriter.writeRecipientKeyReference(reference: CertificateReference) {
        when (reference) {
            is CertificateReference.KeyIdentifier -> constructed(RECIPIENT_KEY_ID) {
                octetString(reference.keyIdentifier)
            }

            is CertificateReference.IssuerSerial -> writeIssuerSerial(reference)
        }
    }

    private fun DerReader.readIssuerSerial(): CertificateReference = readSequence {
        val issuer = readElement(Tag.Sequence).encoded
        CertificateReference.IssuerSerial(issuer = issuer, serialNumber = readInteger())
    }

    private fun DerWriter.writeIssuerSerial(reference: CertificateReference.IssuerSerial) {
        sequence {
            raw(reference.issuer)
            integer(reference.serialNumber)
        }
    }
}
