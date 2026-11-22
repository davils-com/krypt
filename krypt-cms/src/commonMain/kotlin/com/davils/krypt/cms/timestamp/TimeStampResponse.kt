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

package com.davils.krypt.cms.timestamp

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.text.SafeText
import kotlinx.io.bytestring.ByteString

/**
 * A TimeStampResp of RFC 3161, as read and not yet verified.
 *
 * @property status the status.
 * @property statusText the free text of the authority, possibly from an attacker; show it only through an escape.
 * @property failures the bits of PKIFailureInfo that are set, such as 0 for badAlg or 15 for unacceptedPolicy.
 * @property token the token, or null if the status grants none.
 * @property encoded the DER encoding.
 * @since 1.0.0
 */
public class TimeStampResponse internal constructor(
    public val status: TimeStampStatus,
    public val statusText: List<String>,
    public val failures: Set<Int>,
    public val token: TimeStampToken?,
    public val encoded: ByteString,
) {
    /**
     * Compares the encodings.
     *
     * @param other the other object.
     * @return true if [other] has the same encoding.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is TimeStampResponse && encoded == other.encoded

    /**
     * Hashes the encoding.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = encoded.hashCode()

    /**
     * Shows the status, the escaped text and the failures.
     *
     * @return the response as text.
     * @since 1.0.0
     */
    @OptIn(DavilsInternal::class)
    override fun toString(): String =
        "TimeStampResponse($status, ${SafeText.text(statusText.joinToString(separator = "; "))}, failures=$failures)"
}
