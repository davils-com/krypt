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

package com.davils.krypt.ocsp

import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.encoding.Hex
import com.davils.krypt.ocsp.internal.OcspOids
import kotlinx.io.bytestring.ByteString

/**
 * The identifier of a certificate in OCSP: digests of the name and the key of its issuer and its serial number.
 *
 * @property hashAlgorithm the digest of the name and the key.
 * @property issuerNameHash the digest of the DER encoding of the name of the issuer.
 * @property issuerKeyHash the digest of the public key of the issuer, without its algorithm.
 * @property serialNumber the serial number of the certificate.
 * @constructor Identifies a certificate.
 * @throws IllegalArgumentException if [hashAlgorithm] is neither SHA-1 nor SHA-2 or a digest does not have its size.
 * @since 1.0.0
 */
public class CertId(
    public val hashAlgorithm: DigestAlgorithm,
    public val issuerNameHash: ByteString,
    public val issuerKeyHash: ByteString,
    public val serialNumber: DerInteger,
) {
    private val values: List<Any> get() = listOf(hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber)

    init {
        require(hashAlgorithm in OcspOids.DIGESTS) { "OCSP identifies certificates with SHA-1 or SHA-2 only" }
        val size = hashAlgorithm.outputBytes
        require(issuerNameHash.size == size && issuerKeyHash.size == size) {
            "A digest of ${hashAlgorithm.algorithmName} has $size bytes"
        }
    }

    /**
     * Compares every property.
     *
     * @param other the other object.
     * @return true if [other] identifies the same certificate the same way.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is CertId && values == other.values

    /**
     * Hashes the serial number.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = serialNumber.hashCode()

    /**
     * Shows the algorithm, the key digest and the serial number.
     *
     * @return the identifier as text.
     * @since 1.0.0
     */
    override fun toString(): String =
        "CertId(${hashAlgorithm.algorithmName}, key=${Hex.encode(issuerKeyHash)}, serial=$serialNumber)"
}
