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

package com.davils.krypt.cose

import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.encoding.Hex
import com.davils.krypt.cose.cbor.CborArray
import com.davils.krypt.cose.cbor.CborBytes
import com.davils.krypt.cose.cbor.CborInteger
import com.davils.krypt.cose.cbor.CborItem
import com.davils.krypt.cose.internal.longOrNull
import kotlinx.io.bytestring.ByteString

/**
 * The hash of a certificate in the `x5t` header parameter of RFC 9360: a COSE_CertHash of the hash algorithm and the
 * hash of the DER encoding of the certificate.
 *
 * krypt computes and compares the hash algorithms SHA-256 (-16), SHA-384 (-43) and SHA-512 (-44); a hash of another
 * algorithm is kept but never matches.
 *
 * @property algorithm the hash algorithm as the COSE registry names it, an integer or a text.
 * @property value the hash.
 * @constructor Describes a hash.
 * @since 1.0.0
 */
public class CoseCertificateHash(public val algorithm: CborItem, public val value: ByteString) {
    /**
     * The digest of krypt the hash algorithm names, or null if krypt does not compute it.
     *
     * @since 1.0.0
     */
    public val digest: DigestAlgorithm?
        get() = algorithm.longOrNull()?.let { id -> DIGESTS[id] }

    internal fun toItem(): CborItem = CborArray.of(algorithm, CborBytes(value))

    /**
     * Compares the algorithm and the hash.
     *
     * @param other the other object.
     * @return true if [other] is the same hash.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean =
        other is CoseCertificateHash && algorithm == other.algorithm && value == other.value

    /**
     * Hashes the algorithm and the hash.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = listOf(algorithm, value).hashCode()

    /**
     * Shows the algorithm and the hash in hex.
     *
     * @return the hash as text.
     * @since 1.0.0
     */
    override fun toString(): String = "CoseCertificateHash($algorithm, ${Hex.encode(value)})"

    /**
     * The values of the hash algorithms.
     *
     * @since 1.0.0
     */
    public companion object {
        private val DIGESTS: Map<Long, DigestAlgorithm> = mapOf(
            -16L to DigestAlgorithm.Sha256,
            -43L to DigestAlgorithm.Sha384,
            -44L to DigestAlgorithm.Sha512,
        )

        /**
         * Returns the value of [digest] in the COSE registry.
         *
         * @param digest SHA-256, SHA-384 or SHA-512.
         * @return the value.
         * @throws IllegalArgumentException if COSE does not name [digest] for certificate hashes in krypt.
         * @since 1.0.0
         */
        public fun idOf(digest: DigestAlgorithm): CborInteger {
            val id = DIGESTS.entries.firstOrNull { entry -> entry.value == digest }?.key
            return CborInteger.of(requireNotNull(id) { "COSE hashes certificates with SHA-256, SHA-384 or SHA-512" })
        }
    }
}
