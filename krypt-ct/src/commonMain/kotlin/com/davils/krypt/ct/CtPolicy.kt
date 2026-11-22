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

import com.davils.kore.core.validation.Validatable
import com.davils.kore.core.validation.ValidationScope
import com.davils.kore.core.validation.inRange
import com.davils.kore.core.validation.validateOrThrow

private const val SUBJECT: String = "ctPolicy"

/**
 * How many valid signed certificate timestamps a certificate needs, like the policy of Chrome: two of distinct logs
 * for a certificate valid at most 180 days, three for a longer one, of at least two distinct operators.
 *
 * Build a policy of your own with [ctPolicy].
 *
 * @since 1.0.0
 */
public class CtPolicy internal constructor(builder: CtPolicyBuilder) : Validatable {
    /**
     * Up to how many days of validity a certificate counts as short-lived, 1 to [MAXIMUM_DAYS].
     *
     * @since 1.0.0
     */
    public val shortLifetimeDays: Int = builder.shortLifetimeDays

    /**
     * The timestamps of distinct logs a short-lived certificate needs, 1 to [MAXIMUM_COUNT].
     *
     * @since 1.0.0
     */
    public val minimumForShort: Int = builder.minimumForShort

    /**
     * The timestamps of distinct logs a longer-lived certificate needs, 1 to [MAXIMUM_COUNT].
     *
     * @since 1.0.0
     */
    public val minimumForLong: Int = builder.minimumForLong

    /**
     * The distinct operators of the logs that gave valid timestamps, 1 to [MAXIMUM_COUNT].
     *
     * @since 1.0.0
     */
    public val minimumOperators: Int = builder.minimumOperators

    private val values: List<Int> get() = listOf(shortLifetimeDays, minimumForShort, minimumForLong, minimumOperators)

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
        inRange(property = ::shortLifetimeDays, value = shortLifetimeDays, range = 1..MAXIMUM_DAYS)
        inRange(property = ::minimumForShort, value = minimumForShort, range = 1..MAXIMUM_COUNT)
        inRange(property = ::minimumForLong, value = minimumForLong, range = 1..MAXIMUM_COUNT)
        inRange(property = ::minimumOperators, value = minimumOperators, range = 1..MAXIMUM_COUNT)
    }

    /**
     * Compares every bound.
     *
     * @param other the other object.
     * @return true if [other] asks the same.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is CtPolicy && values == other.values

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
     * @return the policy as text.
     * @since 1.0.0
     */
    override fun toString(): String =
        "CtPolicy(shortLifetimeDays=$shortLifetimeDays, minimumForShort=$minimumForShort, " +
            "minimumForLong=$minimumForLong, minimumOperators=$minimumOperators)"

    /**
     * The hard ceilings and the default policy.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The hard ceiling of the lifetime in days.
         *
         * @since 1.0.0
         */
        public const val MAXIMUM_DAYS: Int = 3_650

        /**
         * The hard ceiling of every count.
         *
         * @since 1.0.0
         */
        public const val MAXIMUM_COUNT: Int = 16

        /**
         * The policy of Chrome.
         *
         * @since 1.0.0
         */
        public val Default: CtPolicy = ctPolicy {}
    }
}
