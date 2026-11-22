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

import com.davils.krypt.cms.signed.SignedData
import kotlinx.io.bytestring.ByteString

/**
 * A time-stamp token of RFC 3161: signed data of one signer, the authority, over a [TstInfo], as read and not yet
 * verified.
 *
 * @property signedData the signed data.
 * @property info what the authority vouches for.
 * @since 1.0.0
 */
public class TimeStampToken internal constructor(public val signedData: SignedData, public val info: TstInfo) {
    /**
     * The DER encoding of the token's ContentInfo.
     *
     * @since 1.0.0
     */
    public val encoded: ByteString get() = signedData.encoded

    /**
     * Compares the encodings.
     *
     * @param other the other object.
     * @return true if [other] has the same encoding.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is TimeStampToken && encoded == other.encoded

    /**
     * Hashes the encoding.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = encoded.hashCode()

    /**
     * Shows what the token vouches for.
     *
     * @return the token as text.
     * @since 1.0.0
     */
    override fun toString(): String = "TimeStampToken($info)"
}
