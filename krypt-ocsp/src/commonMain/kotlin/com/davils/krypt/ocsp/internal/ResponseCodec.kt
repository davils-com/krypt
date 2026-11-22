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

package com.davils.krypt.ocsp.internal

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.asn1.BitString
import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerFailure
import com.davils.krypt.asn1.DerLimits
import com.davils.krypt.asn1.DerReader
import com.davils.krypt.asn1.DerWriter
import com.davils.krypt.asn1.Tag
import com.davils.krypt.asn1.readGeneralizedTime
import com.davils.krypt.asn1.readInt
import com.davils.krypt.asn1.readListOf
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.ocsp.BasicOcspResponse
import com.davils.krypt.ocsp.CertificateStatus
import com.davils.krypt.ocsp.OcspLimits
import com.davils.krypt.ocsp.OcspResponse
import com.davils.krypt.ocsp.OcspResponseStatus
import com.davils.krypt.ocsp.ResponderId
import com.davils.krypt.ocsp.SingleResponse
import com.davils.krypt.ocsp.internal.CertIdCodec.readCertId
import com.davils.krypt.ocsp.internal.CertIdCodec.writeCertId
import com.davils.krypt.ocsp.internal.ExtensionLists.nonceExtension
import com.davils.krypt.ocsp.internal.ExtensionLists.nonceOf
import com.davils.krypt.ocsp.internal.ExtensionLists.readExtensions
import com.davils.krypt.ocsp.internal.ExtensionLists.writeExtensions
import com.davils.krypt.x509.AlgorithmIdentifiers.readSignatureAlgorithm
import com.davils.krypt.x509.AlgorithmIdentifiers.writeSignatureAlgorithm
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.Certificates
import com.davils.krypt.x509.RevocationReason
import kotlinx.io.bytestring.ByteString
import kotlin.time.Instant

private const val RESPONSE_BYTES: Int = 0
private const val VERSION: Int = 0
private const val BY_NAME: Int = 1
private const val BY_KEY: Int = 2
private const val RESPONSE_EXTENSIONS: Int = 1
private const val CERTIFICATES: Int = 0
private const val GOOD: Int = 0
private const val REVOKED: Int = 1
private const val UNKNOWN: Int = 2
private const val NEXT_UPDATE: Int = 0
private const val SINGLE_EXTENSIONS: Int = 1
private const val REASON: Int = 0
private const val MAXIMUM_STATUS: Int = 6
private const val MAXIMUM_REASON: Int = 10
private const val KEY_HASH_BYTES: Int = 20

internal object ResponseCodec {
    private val GOOD_TAG: Tag = Tag.context(number = GOOD, isConstructed = false)
    private val UNKNOWN_TAG: Tag = Tag.context(number = UNKNOWN, isConstructed = false)
    private val REVOKED_TAG: Tag = Tag.context(number = REVOKED, isConstructed = true)

    fun DerReader.readResponse(encoded: ByteString, limits: OcspLimits, certificates: Certificates): OcspResponse =
        readSequence {
            val code = readInt(0..MAXIMUM_STATUS, Tag.Enumerated)
            val known = OcspResponseStatus.entries.firstOrNull { status -> status.code == code }
            val status = known ?: refuse(DerFailure.InvalidValue, "a known status")
            val basic = readOptionalExplicit(RESPONSE_BYTES) {
                readSequence {
                    if (readObjectIdentifier() != OcspOids.BASIC) refuse(DerFailure.InvalidValue, "a basic response")
                    val bytes = readOctetString()
                    val read = Der.decodeOrNull(bytes, DerLimits(maximumBytes = limits.maximumBytes)) {
                        readBasic(limits, certificates)
                    }
                    read ?: refuse(DerFailure.InvalidValue, "a valid basic response")
                }
            }
            val isSuccessful = status == OcspResponseStatus.Successful
            if (isSuccessful != (basic != null)) {
                refuse(DerFailure.InvalidValue, "a signed answer exactly when successful")
            }
            OcspResponse(ResponseParts(status = status, basic = basic, encoded = encoded))
        }

    fun encodeData(
        responderName: ByteString,
        producedAt: Instant,
        responses: List<SingleResponse>,
        nonce: ByteString?,
    ): ByteString = Der.encode {
        sequence {
            explicit(BY_NAME) { raw(responderName) }
            generalizedTime(producedAt)
            sequence { responses.forEach { response -> writeSingle(response) } }
            nonce?.let { value -> explicit(RESPONSE_EXTENSIONS) { writeExtensions(listOf(nonceExtension(value))) } }
        }
    }

    fun encodeResponse(
        tbs: ByteString,
        algorithm: SignatureAlgorithm,
        signature: ByteString,
        certificates: List<Certificate>,
    ): ByteString {
        val basic = Der.encode {
            sequence {
                raw(tbs)
                writeSignatureAlgorithm(algorithm)
                bitString(BitString(signature))
                if (certificates.isNotEmpty()) {
                    explicit(
                        CERTIFICATES,
                    ) { sequence { certificates.forEach { certificate -> raw(certificate.encoded) } } }
                }
            }
        }
        return Der.encode {
            sequence {
                integer(OcspResponseStatus.Successful.code.toLong(), Tag.Enumerated)
                explicit(RESPONSE_BYTES) {
                    sequence {
                        objectIdentifier(OcspOids.BASIC)
                        octetString(basic)
                    }
                }
            }
        }
    }

    fun encodeError(status: OcspResponseStatus): ByteString =
        Der.encode { sequence { integer(status.code.toLong(), Tag.Enumerated) } }

    private fun DerReader.readBasic(limits: OcspLimits, certificates: Certificates): BasicOcspResponse = readSequence {
        val tbs = readElement(Tag.Sequence)
        val algorithmElement = readElement(Tag.Sequence)
        val signature = readBitString()
        if (signature.unusedBits != 0) refuse(DerFailure.InvalidValue, "a signature of whole bytes")
        val chain = readOptionalExplicit(CERTIFICATES) {
            readListOf(limits.maximumCertificates) { certificateOf(readElement(Tag.Sequence).encoded, certificates) }
        }
        val data = tbs.reader().readData(limits)
        val parts = BasicResponseParts(
            responderId = data.responderId,
            producedAt = data.producedAt,
            responses = data.responses,
            nonce = data.nonce,
            signatureAlgorithm = Der.decodeOrNull(algorithmElement.encoded) { readSignatureAlgorithm() },
            signature = signature.bytes,
            certificates = chain.orEmpty(),
            tbs = tbs.encoded,
        )
        BasicOcspResponse(parts)
    }

    private fun DerReader.certificateOf(encoded: ByteString, certificates: Certificates): Certificate {
        val certificate = certificates.decode(encoded).getOrNull()
        return certificate ?: refuse(DerFailure.InvalidValue, "a valid certificate")
    }

    private fun DerReader.readData(limits: OcspLimits): ResponseData {
        if (isNext(Tag.context(number = VERSION, isConstructed = true))) {
            refuse(DerFailure.InvalidValue, "the default version left out")
        }
        val responderId = readResponderId()
        val producedAt = readGeneralizedTime()
        val responses = readListOf(limits.maximumEntries) { readSingle(limits) }
        val extensions = readOptionalExplicit(RESPONSE_EXTENSIONS) {
            readExtensions(limits.maximumExtensions, ExtensionLists.NONCE_ONLY)
        }
        val nonce = nonceOf(extensions.orEmpty())
        if (!isExhausted || responses.isEmpty()) refuse(DerFailure.InvalidValue, "at least one answer and nothing more")
        return ResponseData(responderId = responderId, producedAt = producedAt, responses = responses, nonce = nonce)
    }

    private fun DerReader.readResponderId(): ResponderId {
        val byName = readOptionalExplicit(BY_NAME) { ResponderId.ByName(readElement(Tag.Sequence).encoded) }
        return byName ?: readExplicit(BY_KEY) {
            val hash = readOctetString()
            if (hash.size != KEY_HASH_BYTES) refuse(DerFailure.InvalidValue, "a key hash of SHA-1")
            ResponderId.ByKey(hash)
        }
    }

    private fun DerReader.readSingle(limits: OcspLimits): SingleResponse = readSequence {
        val certId = readCertId()
        val status = readStatus()
        val thisUpdate = readGeneralizedTime()
        val nextUpdate = readOptionalExplicit(NEXT_UPDATE) { readGeneralizedTime() }
        val extensions = readOptionalExplicit(
            SINGLE_EXTENSIONS,
        ) { readExtensions(limits.maximumExtensions, emptySet()) }
        if (nextUpdate != null && nextUpdate < thisUpdate) refuse(DerFailure.InvalidValue, "an ordered validity")
        SingleResponse(
            certId = certId,
            status = status,
            thisUpdate = thisUpdate,
            nextUpdate = nextUpdate,
            extensions = extensions.orEmpty(),
        )
    }

    private fun DerReader.readStatus(): CertificateStatus {
        if (isNext(REVOKED_TAG)) return readConstructed(REVOKED_TAG) { readRevoked() }
        val element = readElement()
        val statuses = listOf(GOOD_TAG to CertificateStatus.Good, UNKNOWN_TAG to CertificateStatus.Unknown)
        val status = statuses.firstOrNull { (tag, _) -> tag == element.tag }?.second
        val valid = status?.takeIf { element.content.size == 0 }
        return valid ?: refuse(DerFailure.InvalidValue, "a known certificate status")
    }

    private fun DerReader.readRevoked(): CertificateStatus.Revoked {
        val revokedAt = readGeneralizedTime()
        val code = readOptionalExplicit(REASON) { readInt(0..MAXIMUM_REASON, Tag.Enumerated) }
        val reason = code?.let { found -> reasonOf(found) }
        return CertificateStatus.Revoked(revokedAt, reason)
    }

    private fun DerReader.reasonOf(code: Int): RevocationReason {
        val reason = RevocationReason.entries.firstOrNull { entry -> entry.code == code }
        return reason ?: refuse(DerFailure.InvalidValue, "a known reason")
    }

    private fun DerWriter.writeSingle(response: SingleResponse) {
        sequence {
            writeCertId(response.certId)
            when (val status = response.status) {
                CertificateStatus.Good -> element(GOOD_TAG, ByteString())

                CertificateStatus.Unknown -> element(UNKNOWN_TAG, ByteString())

                is CertificateStatus.Revoked -> constructed(REVOKED_TAG) {
                    generalizedTime(status.revokedAt)
                    status.reason?.let { reason -> explicit(REASON) { integer(reason.code.toLong(), Tag.Enumerated) } }
                }
            }
            generalizedTime(response.thisUpdate)
            response.nextUpdate?.let { next -> explicit(NEXT_UPDATE) { generalizedTime(next) } }
            if (response.extensions.isNotEmpty()) explicit(SINGLE_EXTENSIONS) { writeExtensions(response.extensions) }
        }
    }
}
