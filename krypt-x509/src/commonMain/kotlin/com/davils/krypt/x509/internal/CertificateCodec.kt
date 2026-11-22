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

@file:OptIn(DavilsInternal::class)

package com.davils.krypt.x509.internal

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerFailure
import com.davils.krypt.asn1.DerLimits
import com.davils.krypt.asn1.DerReader
import com.davils.krypt.asn1.DerWriter
import com.davils.krypt.asn1.Tag
import com.davils.krypt.asn1.readInt
import com.davils.krypt.asn1.readTime
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.x509.AlgorithmIdentifiers.readSignatureAlgorithm
import com.davils.krypt.x509.AlgorithmIdentifiers.writeSignatureAlgorithm
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.X509Limits
import com.davils.krypt.x509.extension.Extension
import com.davils.krypt.x509.extension.Extensions
import com.davils.krypt.x509.internal.ExtensionWrites.writeExtensions
import com.davils.krypt.x509.internal.NameCodec.readName
import kotlinx.io.bytestring.ByteString

private const val VERSION: Int = 0
private const val ISSUER_UNIQUE_ID: Int = 1
private const val SUBJECT_UNIQUE_ID: Int = 2
private const val EXTENSIONS: Int = 3
private const val V3: Int = 2
private const val MAXIMUM_SERIAL_BYTES: Int = 21

internal object CertificateCodec {
    fun decodeOrNull(crypto: Crypto, encoded: ByteString, limits: X509Limits): Certificate? =
        Der.decodeOrNull(encoded, DerLimits(maximumBytes = limits.maximumBytes)) {
            readSequence {
                val tbs = readElement(Tag.Sequence)
                val outerAlgorithm = readElement(Tag.Sequence)
                val signature = readBitString()
                if (signature.unusedBits != 0) refuse(DerFailure.InvalidValue, "a signature of whole bytes")
                val parts = tbs.reader().readTbs(crypto = crypto, limits = limits, encoded = encoded, tbs = tbs.encoded)
                val isConsistent = parts.algorithmEncoding == outerAlgorithm.encoded
                if (!isConsistent) refuse(DerFailure.InvalidValue, "one signature algorithm")
                certificateOf(parts, signature.bytes)
            }
        }

    fun DerWriter.writeTbs(template: TbsTemplate) {
        sequence {
            explicit(VERSION) { integer(V3.toLong()) }
            integer(template.serialNumber)
            writeSignatureAlgorithm(template.algorithm)
            raw(template.issuer.encoded)
            sequence {
                time(template.notBefore)
                time(template.notAfter)
            }
            raw(template.subject.encoded)
            raw(template.subjectPublicKeyInfo)
            if (template.extensions.isNotEmpty()) explicit(EXTENSIONS) { writeExtensions(template.extensions) }
        }
    }

    fun DerReader.readExtensionList(maximum: Int): List<Extension> = readSequence {
        val extensions = mutableListOf<Extension>()
        while (!isExhausted) {
            if (extensions.size >= maximum) refuse(DerFailure.LimitExceeded, "at most $maximum extensions")
            extensions += readSequence {
                val id = readObjectIdentifier()
                val isCritical = Tag.Boolean.takeIf { tag -> isNext(tag) }?.let { readBoolean() } == true
                Extension(id = id, isCritical = isCritical, value = readOctetString())
            }
        }
        val ids = extensions.map { extension -> extension.id }
        if (extensions.isEmpty() || ids.toSet().size != ids.size) refuse(DerFailure.InvalidValue, "distinct extensions")
        extensions
    }

    private fun DerReader.readTbs(crypto: Crypto, limits: X509Limits, encoded: ByteString, tbs: ByteString): TbsParts {
        val version = readOptionalExplicit(VERSION) { readInt(VERSION..V3) } ?: VERSION
        val serial = readInteger()
        val algorithmElement = readElement(Tag.Sequence)
        val algorithm = Der.decodeOrNull(algorithmElement.encoded) { readSignatureAlgorithm() }
        val issuer = readName(limits.maximumNames)
        val (notBefore, notAfter) = readSequence { readTime() to readTime() }
        val subject = readName(limits.maximumNames)
        val spki = readElement(Tag.Sequence).encoded
        readOptional(Tag.context(number = ISSUER_UNIQUE_ID, isConstructed = false))
        readOptional(Tag.context(number = SUBJECT_UNIQUE_ID, isConstructed = false))
        val extensions = readOptionalExplicit(EXTENSIONS) { readExtensionList(limits.maximumExtensions) }
        val isConsistent = (version == V3 || extensions == null) && serial.magnitude().size <= MAXIMUM_SERIAL_BYTES
        if (!isConsistent) refuse(DerFailure.InvalidValue, "a consistent version and serial number")
        return TbsParts(
            encoded = encoded,
            version = version + 1,
            serial = serial,
            algorithm = algorithm,
            algorithmEncoding = algorithmElement.encoded,
            issuer = issuer,
            notBefore = notBefore,
            notAfter = notAfter,
            subject = subject,
            spki = spki,
            publicKey = crypto.keys.decodePublic(spki).getOrNull(),
            extensions = Extensions(extensions.orEmpty(), limits.maximumNames),
            tbs = tbs,
        )
    }

    private fun certificateOf(parts: TbsParts, signature: ByteString): Certificate = Certificate(parts, signature)
}
