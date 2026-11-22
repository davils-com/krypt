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
 * A simple value of CBOR, of major type 7: false, true, null, undefined, or an unassigned value from 0 to 19 or from
 * 32 to 255.
 *
 * @property value the number of the simple value.
 * @constructor Wraps [value].
 * @throws IllegalArgumentException if [value] is 24 to 31, which CBOR reserves, or outside 0 to 255.
 * @since 1.0.0
 */
public class CborSimple(public val value: Int) : CborItem() {
    /**
     * Tells whether the value is false or true.
     *
     * @since 1.0.0
     */
    public val isBoolean: Boolean get() = value == FALSE || value == TRUE

    init {
        require(value in 0..UNDEFINED || value in FIRST_EXTENDED..LAST) { "A simple value is 0 to 23 or 32 to 255" }
    }

    override fun write(writer: CborWriter) {
        writer.head(major = MAJOR, argument = value.toULong())
    }

    override fun simpleOrNull(): CborSimple = this

    /**
     * Compares the value.
     *
     * @param other the other object.
     * @return true if [other] is the same simple value.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is CborSimple && value == other.value

    /**
     * Hashes the value.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = value

    /**
     * Shows the value in the diagnostic notation of CBOR, such as `true` or `simple(16)`.
     *
     * @return the value as text.
     * @since 1.0.0
     */
    override fun toString(): String = NAMES.getOrNull(value - FALSE) ?: "simple($value)"

    /**
     * The named simple values.
     *
     * @since 1.0.0
     */
    public companion object {
        private const val MAJOR: Int = 7
        private const val FALSE: Int = 20
        private const val TRUE: Int = 21
        private const val NULL: Int = 22
        private const val UNDEFINED: Int = 23
        private const val FIRST_EXTENDED: Int = 32
        private const val LAST: Int = 255
        private val NAMES: List<String> = listOf("false", "true", "null", "undefined")

        /**
         * The value false.
         *
         * @since 1.0.0
         */
        public val False: CborSimple = CborSimple(FALSE)

        /**
         * The value true.
         *
         * @since 1.0.0
         */
        public val True: CborSimple = CborSimple(TRUE)

        /**
         * The value null.
         *
         * @since 1.0.0
         */
        public val Null: CborSimple = CborSimple(NULL)

        /**
         * The value undefined.
         *
         * @since 1.0.0
         */
        public val Undefined: CborSimple = CborSimple(UNDEFINED)

        /**
         * Returns false or true.
         *
         * @param value the Boolean.
         * @return [True] or [False].
         * @since 1.0.0
         */
        public fun of(value: Boolean): CborSimple = listOf(False, True)[value.compareTo(false)]
    }
}
