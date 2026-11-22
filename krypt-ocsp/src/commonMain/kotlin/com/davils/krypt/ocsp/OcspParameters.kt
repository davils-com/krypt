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

import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/**
 * How an OCSP response is verified.
 *
 * @property at the time of verification, or null for the clock of the environment.
 * @property skew how far the clocks of the responder and the verifier may differ.
 * @property maximumAge how old an answer without a next update may be.
 * @property isNonceRequired whether the response must echo the nonce of the request; responders that answer from a
 *   cache, as RFC 9919 describes, do not.
 * @property isNoCheckRequired whether a delegated responder certificate must carry the ocsp-nocheck extension, so
 *   that its own revocation needs no check; krypt never checks the revocation of a delegated responder.
 * @constructor Describes the verification.
 * @throws IllegalArgumentException if [skew] or [maximumAge] is negative.
 * @since 1.0.0
 */
public class OcspParameters(
    public val at: Instant? = null,
    public val skew: Duration = DEFAULT_SKEW_MINUTES.minutes,
    public val maximumAge: Duration = DEFAULT_AGE_DAYS.days,
    public val isNonceRequired: Boolean = false,
    public val isNoCheckRequired: Boolean = false,
) {
    private val values: List<Any?> get() = listOf(at, skew, maximumAge, isNonceRequired, isNoCheckRequired)

    init {
        require(!skew.isNegative() && !maximumAge.isNegative()) { "A skew and an age are not negative" }
    }

    /**
     * Compares every property.
     *
     * @param other the other object.
     * @return true if [other] describes the same verification.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is OcspParameters && values == other.values

    /**
     * Hashes every property.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = values.hashCode()

    /**
     * Shows every property.
     *
     * @return the parameters as text.
     * @since 1.0.0
     */
    override fun toString(): String = "OcspParameters(at=${at ?: CLOCK}, skew=$skew, " +
        "maximumAge=$maximumAge, nonceRequired=$isNonceRequired, noCheckRequired=$isNoCheckRequired)"

    private companion object {
        const val DEFAULT_SKEW_MINUTES: Int = 5
        const val DEFAULT_AGE_DAYS: Int = 7
        const val CLOCK: String = "clock"
    }
}
