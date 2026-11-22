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

import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.cms.internal.TstParts
import com.davils.krypt.core.algorithm.DigestAlgorithm
import kotlinx.io.bytestring.ByteString
import kotlin.time.Instant

/**
 * The TSTInfo of RFC 3161: what a time-stamp authority vouches for.
 *
 * @since 1.0.0
 */
public class TstInfo internal constructor(internal val parts: TstParts) {
    /**
     * The policy under which the token was issued.
     *
     * @since 1.0.0
     */
    public val policy: ObjectIdentifier = parts.policy

    /**
     * The digest of the message imprint, or null if krypt does not know it.
     *
     * @since 1.0.0
     */
    public val digest: DigestAlgorithm? = parts.digest

    /**
     * The digest of the time-stamped message.
     *
     * @since 1.0.0
     */
    public val hashedMessage: ByteString = parts.hashedMessage

    /**
     * The serial number, unique per authority.
     *
     * @since 1.0.0
     */
    public val serialNumber: DerInteger = parts.serialNumber

    /**
     * The time the authority vouches for.
     *
     * @since 1.0.0
     */
    public val genTime: Instant = parts.genTime

    /**
     * The accuracy of [genTime], or null if the authority states none.
     *
     * @since 1.0.0
     */
    public val accuracy: Accuracy? = parts.accuracy

    /**
     * True if tokens of this authority are ordered by [genTime] regardless of their accuracy.
     *
     * @since 1.0.0
     */
    public val isOrdered: Boolean = parts.isOrdered

    /**
     * The nonce of the request, or null.
     *
     * @since 1.0.0
     */
    public val nonce: DerInteger? = parts.nonce

    /**
     * The DER encoding.
     *
     * @since 1.0.0
     */
    public val encoded: ByteString = parts.encoded

    /**
     * Compares the encodings.
     *
     * @param other the other object.
     * @return true if [other] has the same encoding.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is TstInfo && encoded == other.encoded

    /**
     * Hashes the encoding.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = encoded.hashCode()

    /**
     * Shows the policy and the time.
     *
     * @return the info as text.
     * @since 1.0.0
     */
    override fun toString(): String = "TstInfo(${policy.dotted}, $genTime)"
}
