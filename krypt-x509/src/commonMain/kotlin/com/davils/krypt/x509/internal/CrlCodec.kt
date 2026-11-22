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
import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerFailure
import com.davils.krypt.asn1.DerReader
import com.davils.krypt.asn1.DerWriter
import com.davils.krypt.asn1.Tag
import com.davils.krypt.asn1.readGeneralizedTime
import com.davils.krypt.asn1.readInt
import com.davils.krypt.asn1.readTime
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.x509.AlgorithmIdentifiers.readSignatureAlgorithm
import com.davils.krypt.x509.AlgorithmIdentifiers.writeSignatureAlgorithm
import com.davils.krypt.x509.RevocationReason
import com.davils.krypt.x509.X509Limits
import com.davils.krypt.x509.crl.IssuingDistributionPoint
import com.davils.krypt.x509.crl.RevocationList
import com.davils.krypt.x509.crl.RevocationListBuilder
import com.davils.krypt.x509.crl.RevokedCertificate
import com.davils.krypt.x509.extension.Extension
import com.davils.krypt.x509.extension.ExtensionIds
import com.davils.krypt.x509.extension.Extensions
import com.davils.krypt.x509.internal.CertificateCodec.readExtensionList
import com.davils.krypt.x509.internal.ExtensionReads.bitStringOf
import com.davils.krypt.x509.internal.ExtensionWrites.writeExtensions
import com.davils.krypt.x509.internal.NameCodec.readGeneralNames
import com.davils.krypt.x509.internal.NameCodec.readName
import com.davils.krypt.x509.name.GeneralName
import kotlinx.io.bytestring.ByteString

private const val V2: Int = 1
private const val CRL_EXTENSIONS: Int = 0
private const val POINT: Int = 0
private const val ONLY_USER: Int = 1
private const val ONLY_CA: Int = 2
private const val SOME_REASONS: Int = 3
private const val INDIRECT: Int = 4
private const val ONLY_ATTRIBUTE: Int = 5
private const val FULL_NAME: Int = 0
private const val MAXIMUM_REASON: Int = 10
private val TRUE: ByteString = ByteString(-1)
private val TIMES: Set<Tag> = setOf(Tag.UtcTime, Tag.GeneralizedTime)

internal object CrlCodec {
    fun DerReader.readRevocationList(encoded: ByteString, limits: X509Limits): RevocationList = readSequence {
        val tbs = readElement(Tag.Sequence)
        val outer = readElement(Tag.Sequence)
        val signature = readBitString()
        if (signature.unusedBits != 0) refuse(DerFailure.InvalidValue, "a signature of whole bytes")
        val inner = tbs.reader()
        inner.readInt(V2..V2)
        val algorithmElement = inner.readElement(Tag.Sequence)
        if (algorithmElement.encoded != outer.encoded) inner.refuse(DerFailure.InvalidValue, "one signature algorithm")
        val issuer = inner.readName(limits.maximumNames)
        val thisUpdate = inner.readTime()
        val isTime = inner.peekTag() in TIMES
        val nextUpdate = inner.takeIf { isTime }?.readTime()
        val entryList = inner.readOptional(Tag.Sequence)
        val entries = entryList?.let { element -> entriesOf(element.reader(), limits) }.orEmpty()
        val extensionList = inner.readOptionalExplicit(CRL_EXTENSIONS) { readExtensionList(limits.maximumExtensions) }
        val extensions = extensionList.orEmpty()
        if (!inner.isExhausted) inner.refuse(DerFailure.InvalidValue, "the end of the list")
        val reader = ExtensionReader(extensions)
        val parts = CrlParts(
            encoded = encoded,
            signatureAlgorithm = Der.decodeOrNull(algorithmElement.encoded) { readSignatureAlgorithm() },
            issuer = issuer,
            thisUpdate = thisUpdate,
            nextUpdate = nextUpdate,
            number = reader.read(ExtensionIds.CrlNumber) { readInteger() },
            deltaOf = reader.read(ExtensionIds.DeltaCrlIndicator) { readInteger() },
            issuingDistributionPoint = reader.read(
                ExtensionIds.IssuingDistributionPoint,
            ) { readIssuingPoint(limits.maximumNames) },
            extensions = Extensions(extensions, limits.maximumNames),
            entries = entries.sortedWith { first, second -> first.serialNumber.compareTo(second.serialNumber) },
            tbs = tbs.encoded,
        )
        RevocationList(parts, signature.bytes)
    }

    fun encodeTbs(builder: RevocationListBuilder, algorithm: SignatureAlgorithm): ByteString {
        val issuer = requireNotNull(builder.issuer) { "A revocation list needs its issuer" }
        val thisUpdate = requireNotNull(builder.thisUpdate) { "A revocation list needs the time it is issued" }
        val number = requireNotNull(builder.number) { "A revocation list needs its number" }
        val extensions = listOfNotNull(
            Extension(id = ExtensionIds.CrlNumber, isCritical = false, value = Der.encode { integer(number) }),
            builder.deltaOf?.let { base ->
                Extension(
                    ExtensionIds.DeltaCrlIndicator,
                    true,
                    Der.encode { integer(base) },
                )
            },
            builder.issuingDistributionPoint?.let { point ->
                Extension(
                    ExtensionIds.IssuingDistributionPoint,
                    true,
                    issuingPoint(point),
                )
            },
        ) +
            builder.extensions
        return Der.encode {
            sequence {
                integer(V2.toLong())
                writeSignatureAlgorithm(algorithm)
                raw(issuer.encoded)
                time(thisUpdate)
                builder.nextUpdate?.let { next -> time(next) }
                if (builder.revoked.isNotEmpty()) sequence { builder.revoked.forEach { entry -> writeEntry(entry) } }
                explicit(CRL_EXTENSIONS) { writeExtensions(extensions) }
            }
        }
    }

    private fun DerWriter.writeEntry(entry: RevokedCertificate) {
        sequence {
            integer(entry.serialNumber)
            time(entry.revokedAt)
            val extensions = listOfNotNull(
                entry.reason?.let { reason ->
                    Extension(
                        ExtensionIds.ReasonCode,
                        false,
                        Der.encode { integer(reason.code.toLong(), Tag.Enumerated) },
                    )
                },
                entry.invalidAt?.let { at ->
                    Extension(
                        ExtensionIds.InvalidityDate,
                        false,
                        Der.encode { generalizedTime(at) },
                    )
                },
            )
            if (extensions.isNotEmpty()) writeExtensions(extensions)
        }
    }

    private fun issuingPoint(point: IssuingDistributionPoint): ByteString = Der.encode {
        sequence {
            if (point.names.isNotEmpty()) {
                explicit(POINT) { ExtensionWrites.run { writeImplicitNames(FULL_NAME, point.names) } }
            }
            if (point.isUserOnly) boolean(true, Tag.context(number = ONLY_USER, isConstructed = false))
            if (point.isCaOnly) boolean(true, Tag.context(number = ONLY_CA, isConstructed = false))
            point.onlySomeReasons?.let { reasons ->
                bitString(
                    ExtensionWrites.reasonBits(reasons),
                    Tag.context(number = SOME_REASONS, isConstructed = false),
                )
            }
            if (point.isIndirect) boolean(true, Tag.context(number = INDIRECT, isConstructed = false))
        }
    }

    private fun entriesOf(reader: DerReader, limits: X509Limits): List<RevokedCertificate> {
        val entries = mutableListOf<RevokedCertificate>()
        while (!reader.isExhausted) {
            if (entries.size >= limits.maximumRevokedEntries) {
                reader.refuse(
                    DerFailure.LimitExceeded,
                    "at most ${limits.maximumRevokedEntries} entries",
                )
            }
            entries += reader.readSequence { readEntry(limits) }
        }
        if (entries.isEmpty()) reader.refuse(DerFailure.InvalidValue, "at least one entry")
        return entries
    }

    private fun DerReader.readEntry(limits: X509Limits): RevokedCertificate {
        val serial = readInteger()
        val revokedAt = readTime()
        val element = readOptional(Tag.Sequence)
        val extensions = element?.let { found -> entryExtensions(found.encoded, limits) }.orEmpty()
        val reader = ExtensionReader(extensions)
        val code = reader.read(ExtensionIds.ReasonCode) { readInt(0..MAXIMUM_REASON, Tag.Enumerated) }
        val reason = code?.let { found ->
            RevocationReason.ofCode(found) ?: refuse(
                DerFailure.InvalidValue,
                "a known reason",
            )
        }
        return RevokedCertificate(
            serialNumber = serial,
            revokedAt = revokedAt,
            reason = reason,
            invalidAt = reader.read(ExtensionIds.InvalidityDate) { readGeneralizedTime() },
            certificateIssuer = reader
                .read(
                    ExtensionIds.CertificateIssuer,
                ) { readGeneralNames(limits.maximumNames) }
                .orEmpty(),
        )
    }

    private fun DerReader.entryExtensions(encoded: ByteString, limits: X509Limits): List<Extension> {
        val extensions = Der.decodeOrNull(encoded) { readExtensionList(limits.maximumExtensions) }
        return extensions ?: refuse(DerFailure.InvalidValue, "entry extensions")
    }

    private fun DerReader.readIssuingPoint(maximum: Int): IssuingDistributionPoint = readSequence {
        val names = readOptionalExplicit(POINT) {
            val full = readOptional(Tag.context(number = FULL_NAME, isConstructed = true))
            val fullNames = full?.let { element -> ExtensionReads.namesOf(element.reader(), maximum) }
            fullNames ?: emptyList<GeneralName>().also { readElement() }
        }
        val isUserOnly = readFlag(ONLY_USER)
        val isCaOnly = readFlag(ONLY_CA)
        val reasons = readOptional(Tag.context(number = SOME_REASONS, isConstructed = false))?.let { element ->
            ExtensionReads.reasonsOf(bitStringOf(element.content))
        }
        val isIndirectList = readFlag(INDIRECT)
        if (readFlag(ONLY_ATTRIBUTE) || (isUserOnly && isCaOnly)) refuse(DerFailure.InvalidValue, "a supported scope")
        IssuingDistributionPoint(
            names = names.orEmpty(),
            isUserOnly = isUserOnly,
            isCaOnly = isCaOnly,
            onlySomeReasons = reasons,
            isIndirect = isIndirectList,
        )
    }

    private fun DerReader.readFlag(number: Int): Boolean {
        val element = readOptional(Tag.context(number = number, isConstructed = false)) ?: return false
        if (element.content != TRUE) refuse(DerFailure.InvalidValue, "a flag that is true")
        return true
    }
}
