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

import com.davils.krypt.ocsp.internal.ResponseParts
import kotlinx.io.bytestring.ByteString

/**
 * An OCSP response: its status and, when it is successful, its signed content.
 *
 * @property status the status.
 * @property basic the signed content, or null for an error status.
 * @property encoded the DER encoding.
 * @since 1.0.0
 */
public class OcspResponse private constructor(
    public val status: OcspResponseStatus,
    public val basic: BasicOcspResponse?,
    public val encoded: ByteString,
) {
    internal constructor(parts: ResponseParts) : this(parts.status, parts.basic, parts.encoded)

    /**
     * Compares the encodings.
     *
     * @param other the other object.
     * @return true if [other] is the same response.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is OcspResponse && encoded == other.encoded

    /**
     * Hashes the encoding.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = encoded.hashCode()

    /**
     * Shows the status and the content.
     *
     * @return the response as text.
     * @since 1.0.0
     */
    override fun toString(): String = "OcspResponse($status, ${basic ?: UNSIGNED})"

    private companion object {
        const val UNSIGNED: String = "unsigned"
    }
}
