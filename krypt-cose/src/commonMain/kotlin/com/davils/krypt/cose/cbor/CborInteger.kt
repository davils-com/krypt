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

import com.davils.krypt.cose.internal.CborWriter

/**
 * An integer of CBOR: an unsigned integer of major type 0 from 0 to 2^64 - 1, or a negative integer of major type 1
 * from -1 to -2^64.
 *
 * The full range of 64 bits is kept through [argument], the value CBOR encodes: the integer itself when it is not
 * negative, and -1 minus the integer when it is.
 *
 * @property isNegative whether the integer is negative, of major type 1.
 * @property argument the encoded argument: the value, or -1 minus the value of a negative integer.
 * @since 1.0.0
 */
public class CborInteger private constructor(public val isNegative: Boolean, public val argument: ULong) : CborItem() {
    /**
     * Returns the integer as a [Long].
     *
     * @return the value, or null if it lies outside the range of [Long].
     * @since 1.0.0
     */
    public fun toLongOrNull(): Long? {
        if (argument > Long.MAX_VALUE.toULong()) return null
        val magnitude = argument.toLong()
        return listOf(magnitude, -1L - magnitude)[isNegative.compareTo(false)]
    }

    override fun write(writer: CborWriter) {
        writer.head(major = majorType(), argument = argument)
    }

    override fun integerOrNull(): CborInteger = this

    private fun majorType(): Int = listOf(UNSIGNED, NEGATIVE)[isNegative.compareTo(false)]

    /**
     * Compares the sign and the argument.
     *
     * @param other the other object.
     * @return true if [other] is the same integer.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean =
        other is CborInteger && isNegative == other.isNegative && argument == other.argument

    /**
     * Hashes the sign and the argument.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = argument.hashCode() * HASH_FACTOR + isNegative.hashCode()

    /**
     * Shows the integer in decimal, as the diagnostic notation of CBOR does.
     *
     * @return the integer as text.
     * @since 1.0.0
     */
    override fun toString(): String {
        val isLowest = isNegative && argument == ULong.MAX_VALUE
        if (isLowest) return LOWEST
        val magnitude = listOf(argument, argument + 1UL)[isNegative.compareTo(false)]
        return listOf("", "-")[isNegative.compareTo(false)] + magnitude.toString()
    }

    /**
     * The factories of an integer.
     *
     * @since 1.0.0
     */
    public companion object {
        private const val UNSIGNED: Int = 0
        private const val NEGATIVE: Int = 1
        private const val HASH_FACTOR: Int = 31
        private const val LOWEST: String = "-18446744073709551616"

        /**
         * Returns the integer [value].
         *
         * @param value the value.
         * @return the integer.
         * @since 1.0.0
         */
        public fun of(value: Long): CborInteger {
            val isNegative = value < 0L
            val argument = listOf(value, -1L - value)[isNegative.compareTo(false)]
            return CborInteger(isNegative = isNegative, argument = argument.toULong())
        }

        /**
         * Returns the unsigned integer [value], of major type 0.
         *
         * @param value the value, up to 2^64 - 1.
         * @return the integer.
         * @since 1.0.0
         */
        public fun unsigned(value: ULong): CborInteger = CborInteger(isNegative = false, argument = value)

        /**
         * Returns the negative integer -1 - [argument], of major type 1.
         *
         * @param argument the argument, so that the value lies from -1 down to -2^64.
         * @return the integer.
         * @since 1.0.0
         */
        public fun negative(argument: ULong): CborInteger = CborInteger(isNegative = true, argument = argument)
    }
}
