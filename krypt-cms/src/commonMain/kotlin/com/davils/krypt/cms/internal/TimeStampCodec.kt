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

import com.davils.krypt.asn1.BitString
import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.asn1.DerReader
import com.davils.krypt.asn1.DerWriter
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.Tag
import com.davils.krypt.asn1.readGeneralizedTime
import com.davils.krypt.asn1.readInt
import com.davils.krypt.asn1.readListOf
import com.davils.krypt.asn1.readText
import com.davils.krypt.cms.CmsLimits
import com.davils.krypt.cms.ContentTypes
import com.davils.krypt.cms.internal.Algorithms.readDigestAlgorithm
import com.davils.krypt.cms.internal.Algorithms.writeDigestAlgorithm
import com.davils.krypt.cms.signed.SignedData
import com.davils.krypt.cms.timestamp.Accuracy
import com.davils.krypt.cms.timestamp.TimeStampRequest
import com.davils.krypt.cms.timestamp.TimeStampResponse
import com.davils.krypt.cms.timestamp.TimeStampStatus
import com.davils.krypt.cms.timestamp.TimeStampToken
import com.davils.krypt.cms.timestamp.TstInfo
import com.davils.krypt.core.algorithm.DigestAlgorithm
import kotlinx.io.bytestring.ByteString

private const val VERSION: Long = 1
private const val MILLIS: Int = 0
private const val MICROS: Int = 1
private const val MAXIMUM_PART: Int = 999
private const val EXTENSIONS: Int = 0
private const val TSA_NAME: Int = 0
private const val TST_EXTENSIONS: Int = 1

internal class TimeStampCodec(private val signedCodec: SignedCodec, private val limits: CmsLimits) {
    fun encodeRequest(
        digest: DigestAlgorithm,
        hashedMessage: ByteString,
        policy: ObjectIdentifier?,
        nonce: DerInteger?,
        isCertificateRequested: Boolean,
    ): ByteString = Der.encode {
        sequence {
            integer(VERSION)
            writeImprint(digest, hashedMessage)
            policy?.let { found -> objectIdentifier(found) }
            nonce?.let { found -> integer(found) }
            if (isCertificateRequested) boolean(true)
        }
    }

    fun decodeRequest(encoded: ByteString): TimeStampRequest? = Der.decodeOrNull(encoded, signedCodec.derLimits) {
        readSequence {
            readVersion()
            val (digest, hash) = readImprint()
            val policy = takeIf { isNext(Tag.ObjectIdentifier) }?.readObjectIdentifier()
            val nonce = takeIf { isNext(Tag.Integer) }?.readInteger()
            val isRequested = takeIf { isNext(Tag.Boolean) }?.readBoolean()
            if (isRequested == false) malformed("certReq FALSE, which DER omits")
            val extensions = readOptional(Tag.context(number = EXTENSIONS, isConstructed = true))
            TimeStampRequest(
                digest = digest,
                hashedMessage = hash,
                policy = policy,
                nonce = nonce,
                isCertificateRequested = isRequested == true,
                hasExtensions = extensions != null,
                encoded = encoded,
            )
        }
    }

    fun decodeResponse(encoded: ByteString): TimeStampResponse? = Der.decodeOrNull(encoded, signedCodec.derLimits) {
        readSequence {
            val (status, text, failures) = readSequence {
                val code = readInt(0 until TimeStampStatus.entries.size)
                val text = takeIf { isNext(Tag.Sequence) }?.readListOf(limits.maximumAttributes) {
                    readText(Tag.Utf8String)
                }
                val bits = takeIf { isNext(Tag.BitString) }?.readBitString()
                Triple(TimeStampStatus.entries[code], text.orEmpty(), bits?.let { found -> setBits(found) }.orEmpty())
            }
            val token = takeUnless { isExhausted }?.let { tokenOf(readElement(Tag.Sequence).encoded) }
            TimeStampResponse(status = status, statusText = text, failures = failures, token = token, encoded = encoded)
        }
    }

    fun decodeToken(encoded: ByteString): TimeStampToken? = Der.decodeOrNull(encoded, signedCodec.derLimits) {
        readElement(Tag.Sequence)
        tokenOf(encoded)
    }

    fun encodeTstInfo(parts: TstParts, digest: DigestAlgorithm): ByteString = Der.encode {
        sequence {
            integer(VERSION)
            objectIdentifier(parts.policy)
            writeImprint(digest, parts.hashedMessage)
            integer(parts.serialNumber)
            generalizedTime(parts.genTime)
            parts.accuracy?.let { accuracy -> writeAccuracy(accuracy) }
            if (parts.isOrdered) boolean(true)
            parts.nonce?.let { nonce -> integer(nonce) }
        }
    }

    fun encodeResponse(status: TimeStampStatus, text: String?, failures: Set<Int>, token: ByteString?): ByteString =
        Der.encode {
            sequence {
                sequence {
                    integer(status.code.toLong())
                    text?.let { found -> sequence { utf8String(found) } }
                    if (failures.isNotEmpty()) bitString(BitString.ofNamedBits(failures))
                }
                token?.let { found -> raw(found) }
            }
        }

    private fun tokenOf(encoded: ByteString): TimeStampToken {
        val signedData = signedCodec.decode(encoded) ?: malformed("a time-stamp token")
        val info = infoOf(signedData)
        if (signedData.signers.size != 1) malformed("a time-stamp token of one signer")
        return TimeStampToken(signedData, info)
    }

    private fun infoOf(signedData: SignedData): TstInfo {
        val isTstInfo = signedData.contentType == ContentTypes.TstInfo
        val content = signedData.content?.takeIf { isTstInfo } ?: malformed("a TSTInfo")
        return signedCodec.value(content) { readTstInfo(content) }
    }

    private fun DerReader.readTstInfo(encoded: ByteString): TstInfo = readSequence {
        readVersion()
        val policy = readObjectIdentifier()
        val (digest, hash) = readImprint()
        val serial = readInteger()
        val genTime = readGeneralizedTime()
        val accuracy = takeIf { isNext(Tag.Sequence) }?.readAccuracy()
        val isOrdered = takeIf { isNext(Tag.Boolean) }?.readBoolean()
        if (isOrdered == false) malformed("ordering FALSE, which DER omits")
        val nonce = takeIf { isNext(Tag.Integer) }?.readInteger()
        readOptional(Tag.context(number = TSA_NAME, isConstructed = true))
        readOptional(Tag.context(number = TST_EXTENSIONS, isConstructed = true))
        val parts = TstParts(
            policy = policy,
            digest = digest,
            hashedMessage = hash,
            serialNumber = serial,
            genTime = genTime,
            accuracy = accuracy,
            isOrdered = isOrdered == true,
            nonce = nonce,
            encoded = encoded,
        )
        TstInfo(parts)
    }

    private fun DerReader.readVersion() {
        readInt(1..1)
    }

    private fun DerReader.readImprint(): Pair<DigestAlgorithm?, ByteString> = readSequence {
        val digest = readDigestAlgorithm()
        val hash = readOctetString()
        val isSized = digest?.let { found -> hash.size == found.outputBytes } != false
        if (!isSized) malformed("an imprint as long as its digest")
        digest to hash
    }

    private fun DerWriter.writeImprint(digest: DigestAlgorithm, hashedMessage: ByteString) {
        sequence {
            writeDigestAlgorithm(digest)
            octetString(hashedMessage)
        }
    }

    private fun DerReader.readAccuracy(): Accuracy = readSequence {
        val seconds = takeIf { isNext(Tag.Integer) }?.readInt(0..Int.MAX_VALUE) ?: 0
        val millis = readOptional(Tag.context(number = MILLIS, isConstructed = false))?.let { element ->
            partOf(element.content)
        } ?: 0
        val micros = readOptional(Tag.context(number = MICROS, isConstructed = false))?.let { element ->
            partOf(element.content)
        } ?: 0
        if (seconds.toLong() + millis + micros == 0L) malformed("an accuracy that is not zero")
        Accuracy(seconds = seconds, millis = millis, micros = micros)
    }

    private fun partOf(content: ByteString): Int {
        val number = DerInteger.decodeOrNull(content)?.toLongOrNull()
        val value = number?.takeIf { found -> found in 1..MAXIMUM_PART }
        return value?.toInt() ?: malformed("a part of an accuracy of 1 to 999")
    }

    private fun DerWriter.writeAccuracy(accuracy: Accuracy) {
        sequence {
            if (accuracy.seconds > 0) integer(accuracy.seconds.toLong())
            if (accuracy.millis > 0) {
                integer(
                    accuracy.millis.toLong(),
                    Tag.context(number = MILLIS, isConstructed = false),
                )
            }
            if (accuracy.micros > 0) {
                integer(
                    accuracy.micros.toLong(),
                    Tag.context(number = MICROS, isConstructed = false),
                )
            }
        }
    }

    private fun setBits(bits: BitString): Set<Int> = (0 until bits.size).filter { index -> bits[index] }.toSet()
}
