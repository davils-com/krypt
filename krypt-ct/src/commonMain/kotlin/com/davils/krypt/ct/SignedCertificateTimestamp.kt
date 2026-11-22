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

package com.davils.krypt.ct

import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.core.encoding.Hex
import com.davils.krypt.ct.internal.SctCodec
import kotlinx.io.bytestring.ByteString
import kotlin.time.Instant

/**
 * A signed certificate timestamp of version 1 by RFC 6962: the promise of a log to publish a certificate.
 *
 * A timestamp says nothing until it is verified against a known log with [Transparency.verify].
 *
 * @property logId the id of the log, the SHA-256 digest of its public key.
 * @property timestamp when the log saw the certificate, in milliseconds.
 * @property extensions the extensions of the log, usually empty.
 * @property hashAlgorithm the hash of the signature as TLS 1.2 numbers it, 4 for SHA-256.
 * @property signatureAlgorithm the signature as TLS 1.2 numbers it, 1 for RSA and 3 for ECDSA.
 * @property signature the signature of the log.
 * @constructor Holds a timestamp.
 * @throws IllegalArgumentException if [logId] is not 32 bytes, [timestamp] lies before 1970, an algorithm is not one
 *   byte or a field is longer than 65535 bytes.
 * @since 1.0.0
 */
public class SignedCertificateTimestamp(
    public val logId: ByteString,
    public val timestamp: Instant,
    public val extensions: ByteString,
    public val hashAlgorithm: Int,
    public val signatureAlgorithm: Int,
    public val signature: ByteString,
) {
    init {
        require(logId.size == LOG_ID_BYTES) { "A log id has $LOG_ID_BYTES bytes" }
        require(timestamp.toEpochMilliseconds() >= 0) { "A timestamp lies after 1970" }
        require(
            hashAlgorithm in 0..MAXIMUM_CODE && signatureAlgorithm in 0..MAXIMUM_CODE,
        ) { "An algorithm is one byte" }
        require(
            extensions.size <= MAXIMUM_FIELD && signature.size <= MAXIMUM_FIELD,
        ) { "A field has at most 65535 bytes" }
    }

    /**
     * The TLS encoding.
     *
     * @since 1.0.0
     */
    public val encoded: ByteString = SctCodec.encode(this)

    /**
     * The signature algorithm, or null if it is not SHA-256 with ECDSA or RSA.
     *
     * @since 1.0.0
     */
    public val algorithm: SignatureAlgorithm? = SctCodec.algorithmOf(
        hash = hashAlgorithm,
        signature = signatureAlgorithm,
    )

    /**
     * Compares the encodings.
     *
     * @param other the other object.
     * @return true if [other] is the same timestamp.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is SignedCertificateTimestamp && encoded == other.encoded

    /**
     * Hashes the encoding.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = encoded.hashCode()

    /**
     * Shows the log and the time.
     *
     * @return the timestamp as text.
     * @since 1.0.0
     */
    override fun toString(): String = "SignedCertificateTimestamp(log=${Hex.encode(logId)}, at=$timestamp)"

    /**
     * The size of a log id and the algorithm numbers of TLS 1.2.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The size of a log id.
         *
         * @since 1.0.0
         */
        public const val LOG_ID_BYTES: Int = 32

        /**
         * The hash algorithm SHA-256.
         *
         * @since 1.0.0
         */
        public const val SHA256: Int = 4

        /**
         * The signature algorithm RSA with PKCS #1 v1.5.
         *
         * @since 1.0.0
         */
        public const val RSA: Int = 1

        /**
         * The signature algorithm ECDSA.
         *
         * @since 1.0.0
         */
        public const val ECDSA: Int = 3

        private const val MAXIMUM_CODE: Int = 255
        private const val MAXIMUM_FIELD: Int = 65_535
    }
}
