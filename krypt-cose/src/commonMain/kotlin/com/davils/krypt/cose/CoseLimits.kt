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

import com.davils.kore.core.validation.Validatable
import com.davils.kore.core.validation.ValidationScope
import com.davils.kore.core.validation.inRange
import com.davils.kore.core.validation.validateOrThrow
import com.davils.krypt.cose.cbor.CborLimits

private const val SUBJECT: String = "limits"
private const val DEFAULT_MAXIMUM_SIGNATURES: Int = 8
private const val DEFAULT_MAXIMUM_RECIPIENTS: Int = 16
private const val DEFAULT_MAXIMUM_CERTIFICATES: Int = 8
private const val DEFAULT_MAXIMUM_KEYS: Int = 64

/**
 * The bounds of reading COSE messages, COSE keys and CWTs, so that hostile input cannot demand unbounded memory or
 * work.
 *
 * @property cbor the bounds of every CBOR encoding read, the message itself and every protected header and key in it.
 * @property maximumSignatures the most signatures of a COSE_Sign, from 1 to [HARD_MAXIMUM_SIGNATURES]; 8 by default.
 * @property maximumRecipients the most recipients of a COSE_Encrypt or a COSE_Mac, counted over every layer, from 1 to
 *   [HARD_MAXIMUM_RECIPIENTS]; 16 by default.
 * @property maximumCertificates the most certificates of an `x5chain` header parameter, from 1 to
 *   [HARD_MAXIMUM_CERTIFICATES]; 8 by default.
 * @property maximumKeys the most keys of a COSE_KeySet, from 1 to [HARD_MAXIMUM_KEYS]; 64 by default.
 * @throws com.davils.kore.core.validation.report.ValidationException if a bound lies outside its hard ceiling.
 * @since 1.0.0
 */
public class CoseLimits(
    public val cbor: CborLimits = CborLimits.Default,
    public val maximumSignatures: Int = DEFAULT_MAXIMUM_SIGNATURES,
    public val maximumRecipients: Int = DEFAULT_MAXIMUM_RECIPIENTS,
    public val maximumCertificates: Int = DEFAULT_MAXIMUM_CERTIFICATES,
    public val maximumKeys: Int = DEFAULT_MAXIMUM_KEYS,
) : Validatable {
    private val values: List<Any>
        get() = listOf(cbor, maximumSignatures, maximumRecipients, maximumCertificates, maximumKeys)

    init {
        validateOrThrow(SUBJECT)
    }

    /**
     * Checks every bound against its hard ceiling.
     *
     * @receiver the validation that collects the violations.
     * @since 1.0.0
     */
    override fun ValidationScope.validate() {
        inRange(property = ::maximumSignatures, value = maximumSignatures, range = 1..HARD_MAXIMUM_SIGNATURES)
        inRange(property = ::maximumRecipients, value = maximumRecipients, range = 1..HARD_MAXIMUM_RECIPIENTS)
        inRange(property = ::maximumCertificates, value = maximumCertificates, range = 1..HARD_MAXIMUM_CERTIFICATES)
        inRange(property = ::maximumKeys, value = maximumKeys, range = 1..HARD_MAXIMUM_KEYS)
    }

    /**
     * Compares every bound.
     *
     * @param other the other object.
     * @return true if [other] has the same bounds.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is CoseLimits && values == other.values

    /**
     * Hashes every bound.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = values.hashCode()

    /**
     * Shows every bound.
     *
     * @return the limits as text.
     * @since 1.0.0
     */
    override fun toString(): String = "CoseLimits(cbor=$cbor, maximumSignatures=$maximumSignatures, " +
        "maximumRecipients=$maximumRecipients, maximumCertificates=$maximumCertificates, maximumKeys=$maximumKeys)"

    /**
     * The hard ceilings and the default limits.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The hard ceiling of [maximumSignatures]: 256.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_SIGNATURES: Int = 256

        /**
         * The hard ceiling of [maximumRecipients]: 1,024.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_RECIPIENTS: Int = 1_024

        /**
         * The hard ceiling of [maximumCertificates]: 64.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_CERTIFICATES: Int = 64

        /**
         * The hard ceiling of [maximumKeys]: 4,096.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_KEYS: Int = 4_096

        /**
         * The default limits.
         *
         * @since 1.0.0
         */
        public val Default: CoseLimits = CoseLimits()
    }
}
