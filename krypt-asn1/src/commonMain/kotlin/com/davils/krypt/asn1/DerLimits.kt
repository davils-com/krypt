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

package com.davils.krypt.asn1

import com.davils.kore.core.validation.Validatable
import com.davils.kore.core.validation.ValidationScope
import com.davils.kore.core.validation.inRange
import com.davils.kore.core.validation.validateOrThrow

private const val SUBJECT: String = "limits"
private const val DEFAULT_MAXIMUM_BYTES: Int = 16 * 1_024 * 1_024
private const val DEFAULT_MAXIMUM_DEPTH: Int = 32
private const val DEFAULT_MAXIMUM_ELEMENTS: Int = 1_000_000

/**
 * The bounds a [DerReader] keeps, so that hostile input cannot demand unbounded memory, recursion or work.
 *
 * @property maximumBytes the largest input, from 1 to [HARD_MAXIMUM_BYTES]; 16 MiB by default.
 * @property maximumDepth the deepest nesting of constructed elements, from 1 to [HARD_MAXIMUM_DEPTH]; 32 by default.
 * @property maximumElements the most elements one input may hold, from 1 to [HARD_MAXIMUM_ELEMENTS]; 1,000,000 by
 *   default.
 * @throws com.davils.kore.core.validation.report.ValidationException if a bound lies outside its hard ceiling.
 * @since 1.0.0
 */
public class DerLimits(
    public val maximumBytes: Int = DEFAULT_MAXIMUM_BYTES,
    public val maximumDepth: Int = DEFAULT_MAXIMUM_DEPTH,
    public val maximumElements: Int = DEFAULT_MAXIMUM_ELEMENTS,
) : Validatable {
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
        inRange(property = ::maximumBytes, value = maximumBytes, range = 1..HARD_MAXIMUM_BYTES)
        inRange(property = ::maximumDepth, value = maximumDepth, range = 1..HARD_MAXIMUM_DEPTH)
        inRange(property = ::maximumElements, value = maximumElements, range = 1..HARD_MAXIMUM_ELEMENTS)
    }

    /**
     * Compares every bound.
     *
     * @param other the other object.
     * @return true if [other] has the same bounds.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is DerLimits &&
        maximumBytes == other.maximumBytes &&
        maximumDepth == other.maximumDepth &&
        maximumElements == other.maximumElements

    /**
     * Hashes every bound.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = listOf(maximumBytes, maximumDepth, maximumElements).hashCode()

    /**
     * Shows every bound.
     *
     * @return the limits as text.
     * @since 1.0.0
     */
    override fun toString(): String =
        "DerLimits(maximumBytes=$maximumBytes, maximumDepth=$maximumDepth, maximumElements=$maximumElements)"

    /**
     * The hard ceilings and the default limits.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The hard ceiling of [maximumBytes]: 256 MiB.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_BYTES: Int = 256 * 1_024 * 1_024

        /**
         * The hard ceiling of [maximumDepth]: 128.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_DEPTH: Int = 128

        /**
         * The hard ceiling of [maximumElements]: 16,000,000.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_ELEMENTS: Int = 16_000_000

        /**
         * The default limits.
         *
         * @since 1.0.0
         */
        public val Default: DerLimits = DerLimits()
    }
}
