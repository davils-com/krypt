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

import com.davils.krypt.core.encoding.Hex
import kotlinx.io.bytestring.ByteString

/**
 * An OCSP request: the certificates it asks about and the nonce that binds the answer to it.
 *
 * @property certIds the certificates.
 * @property nonce the nonce of RFC 9654, or null.
 * @property encoded the DER encoding.
 * @since 1.0.0
 */
public class OcspRequest internal constructor(
    public val certIds: List<CertId>,
    public val nonce: ByteString?,
    public val encoded: ByteString,
) {
    /**
     * Compares the encodings.
     *
     * @param other the other object.
     * @return true if [other] is the same request.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is OcspRequest && encoded == other.encoded

    /**
     * Hashes the encoding.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = encoded.hashCode()

    /**
     * Shows the certificates and the nonce.
     *
     * @return the request as text.
     * @since 1.0.0
     */
    override fun toString(): String {
        val shown = nonce?.let { found -> Hex.encode(found) }
        return "OcspRequest($certIds, nonce=${shown ?: NONE})"
    }

    private companion object {
        const val NONE: String = "none"
    }
}
