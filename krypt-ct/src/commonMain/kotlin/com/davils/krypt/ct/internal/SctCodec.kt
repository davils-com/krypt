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

import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.ct.CtFailure
import com.davils.krypt.ct.CtLimits
import com.davils.krypt.ct.SignedCertificateTimestamp
import com.davils.krypt.ct.internal.TlsWriter.Companion.tls
import kotlinx.io.bytestring.ByteString
import kotlin.time.Instant

private const val V1: Int = 0
private const val LIST_LENGTH_BYTES: Int = 2
private const val MAXIMUM_VECTOR: Int = 65_535

internal object SctCodec {
    fun encode(timestamp: SignedCertificateTimestamp): ByteString = tls {
        u8(V1)
        bytes(timestamp.logId)
        u64(timestamp.timestamp.toEpochMilliseconds())
        vector16(timestamp.extensions)
        u8(timestamp.hashAlgorithm)
        u8(timestamp.signatureAlgorithm)
        vector16(timestamp.signature)
    }

    fun encodeList(timestamps: List<SignedCertificateTimestamp>): ByteString {
        val isEachShort = timestamps.all { timestamp -> timestamp.encoded.size <= MAXIMUM_VECTOR }
        val entries = tls { timestamps.forEach { timestamp -> vector16(timestamp.encoded) } }
        require(isEachShort && entries.size <= MAXIMUM_VECTOR) { "A list has at most $MAXIMUM_VECTOR bytes" }
        return tls { vector16(entries) }
    }

    fun algorithmOf(hash: Int, signature: Int): SignatureAlgorithm? {
        val algorithms = mapOf(
            SignedCertificateTimestamp.RSA to SignatureAlgorithm.RsaPkcs1Sha256,
            SignedCertificateTimestamp.ECDSA to SignatureAlgorithm.EcdsaSha256,
        )
        return algorithms[signature]?.takeIf { hash == SignedCertificateTimestamp.SHA256 }
    }

    fun decodeList(encoded: ByteString, limits: CtLimits): Outcome<List<SignedCertificateTimestamp>, CtFailure> {
        if (encoded.size > limits.maximumListBytes) return Outcome.Failure(CtFailure.LimitExceeded)
        return try {
            Outcome.Success(readList(encoded, limits))
        } catch (refused: TlsRefusal) {
            Outcome.Failure(refused.failure)
        }
    }

    private fun readList(encoded: ByteString, limits: CtLimits): List<SignedCertificateTimestamp> {
        val outer = TlsReader(encoded)
        val entries = TlsReader(outer.vector16(limits.maximumListBytes))
        outer.finish()
        if (encoded.size == LIST_LENGTH_BYTES) throw TlsRefusal(CtFailure.Malformed)
        val timestamps = mutableListOf<SignedCertificateTimestamp>()
        var count = 0
        while (!entries.isExhausted) {
            count += 1
            if (count > limits.maximumTimestamps) throw TlsRefusal(CtFailure.LimitExceeded)
            readEntry(entries.vector16(limits.maximumListBytes), limits)?.let { timestamp -> timestamps += timestamp }
        }
        return timestamps
    }

    private fun readEntry(entry: ByteString, limits: CtLimits): SignedCertificateTimestamp? {
        val reader = TlsReader(entry)
        val version = reader.u8()
        return reader.takeIf { version == V1 }?.readVersion1(limits)
    }

    private fun TlsReader.readVersion1(limits: CtLimits): SignedCertificateTimestamp {
        val logId = bytes(SignedCertificateTimestamp.LOG_ID_BYTES)
        val milliseconds = u64()
        val extensions = vector16(limits.maximumExtensionBytes)
        val hash = u8()
        val signatureAlgorithm = u8()
        val signature = vector16(limits.maximumSignatureBytes)
        finish()
        if (milliseconds < 0 || signature.size == 0) throw TlsRefusal(CtFailure.Malformed)
        return SignedCertificateTimestamp(
            logId = logId,
            timestamp = Instant.fromEpochMilliseconds(milliseconds),
            extensions = extensions,
            hashAlgorithm = hash,
            signatureAlgorithm = signatureAlgorithm,
            signature = signature,
        )
    }
}
