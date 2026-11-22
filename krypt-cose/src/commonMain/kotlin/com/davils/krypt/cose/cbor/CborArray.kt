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
 * An array of CBOR, of major type 4.
 *
 * @constructor Copies [items].
 * @param items the items in order.
 * @since 1.0.0
 */
public class CborArray(items: List<CborItem>) : CborItem() {
    /**
     * The items in order; the list cannot be changed.
     *
     * @since 1.0.0
     */
    public val items: List<CborItem> = items.toList()

    /**
     * The number of items.
     *
     * @since 1.0.0
     */
    public val size: Int get() = items.size

    /**
     * Returns the item at [index].
     *
     * @param index the index, from 0 to [size] - 1.
     * @return the item.
     * @throws IndexOutOfBoundsException if [index] is out of range.
     * @since 1.0.0
     */
    public operator fun get(index: Int): CborItem = items[index]

    override fun write(writer: CborWriter) {
        writer.head(major = MAJOR, argument = items.size.toULong())
        items.forEach { item -> item.write(writer) }
    }

    override fun itemsOrNull(): List<CborItem> = items

    /**
     * Compares the items in order.
     *
     * @param other the other object.
     * @return true if [other] is an array of equal items.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is CborArray && items == other.items

    /**
     * Hashes the items.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = items.hashCode()

    /**
     * Shows the items in the diagnostic notation of CBOR.
     *
     * @return the array as text.
     * @since 1.0.0
     */
    override fun toString(): String = items.joinToString(separator = ", ", prefix = "[", postfix = "]")

    /**
     * Builds arrays.
     *
     * @since 1.0.0
     */
    public companion object {
        private const val MAJOR: Int = 4

        /**
         * Returns an array of [items].
         *
         * @param items the items in order.
         * @return the array.
         * @since 1.0.0
         */
        public fun of(vararg items: CborItem): CborArray = CborArray(items.toList())
    }
}
