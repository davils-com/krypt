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

package com.davils.krypt.cose.cbor

import com.davils.kore.core.validation.Validatable
import com.davils.kore.core.validation.ValidationScope
import com.davils.kore.core.validation.inRange
import com.davils.kore.core.validation.validateOrThrow

private const val SUBJECT: String = "limits"
private const val DEFAULT_MAXIMUM_BYTES: Int = 1_024 * 1_024
private const val DEFAULT_MAXIMUM_DEPTH: Int = 16
private const val DEFAULT_MAXIMUM_ITEMS: Int = 65_536
private const val DEFAULT_MAXIMUM_STRING_BYTES: Int = 1_024 * 1_024
private const val DEFAULT_MAXIMUM_MAP_ENTRIES: Int = 256

/**
 * The bounds a decoder of CBOR keeps, so that hostile input cannot demand unbounded memory, recursion or work. Every
 * bound is checked before the work it guards: a length before its bytes are copied, a count before its items are
 * read.
 *
 * @property maximumBytes the largest input, from 1 to [HARD_MAXIMUM_BYTES]; 1 MiB by default.
 * @property maximumDepth the deepest nesting of arrays, maps and tags, from 1 to [HARD_MAXIMUM_DEPTH]; 16 by default.
 * @property maximumItems the most data items one input may hold, from 1 to [HARD_MAXIMUM_ITEMS]; 65,536 by default.
 * @property maximumStringBytes the longest byte or text string, from 1 to [HARD_MAXIMUM_BYTES]; 1 MiB by default.
 * @property maximumMapEntries the most entries of one map, from 1 to [HARD_MAXIMUM_MAP_ENTRIES]; 256 by default.
 * @throws com.davils.kore.core.validation.report.ValidationException if a bound lies outside its hard ceiling.
 * @since 1.0.0
 */
public class CborLimits(
    public val maximumBytes: Int = DEFAULT_MAXIMUM_BYTES,
    public val maximumDepth: Int = DEFAULT_MAXIMUM_DEPTH,
    public val maximumItems: Int = DEFAULT_MAXIMUM_ITEMS,
    public val maximumStringBytes: Int = DEFAULT_MAXIMUM_STRING_BYTES,
    public val maximumMapEntries: Int = DEFAULT_MAXIMUM_MAP_ENTRIES,
) : Validatable {
    private val values: List<Int>
        get() = listOf(maximumBytes, maximumDepth, maximumItems, maximumStringBytes, maximumMapEntries)

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
        inRange(property = ::maximumItems, value = maximumItems, range = 1..HARD_MAXIMUM_ITEMS)
        inRange(property = ::maximumStringBytes, value = maximumStringBytes, range = 1..HARD_MAXIMUM_BYTES)
        inRange(property = ::maximumMapEntries, value = maximumMapEntries, range = 1..HARD_MAXIMUM_MAP_ENTRIES)
    }

    /**
     * Compares every bound.
     *
     * @param other the other object.
     * @return true if [other] has the same bounds.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is CborLimits && values == other.values

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
    override fun toString(): String = "CborLimits(maximumBytes=$maximumBytes, maximumDepth=$maximumDepth, " +
        "maximumItems=$maximumItems, maximumStringBytes=$maximumStringBytes, maximumMapEntries=$maximumMapEntries)"

    /**
     * The hard ceilings and the default limits.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The hard ceiling of [maximumBytes] and [maximumStringBytes]: 64 MiB.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_BYTES: Int = 64 * 1_024 * 1_024

        /**
         * The hard ceiling of [maximumDepth]: 64.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_DEPTH: Int = 64

        /**
         * The hard ceiling of [maximumItems]: 4,000,000.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_ITEMS: Int = 4_000_000

        /**
         * The hard ceiling of [maximumMapEntries]: 65,536.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_MAP_ENTRIES: Int = 65_536

        /**
         * The default limits.
         *
         * @since 1.0.0
         */
        public val Default: CborLimits = CborLimits()
    }
}
