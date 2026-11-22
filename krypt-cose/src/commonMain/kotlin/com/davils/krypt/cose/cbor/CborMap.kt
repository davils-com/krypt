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

import com.davils.krypt.cose.internal.Bytes
import com.davils.krypt.cose.internal.CborWriter

/**
 * A map of CBOR, of major type 5, whose keys are distinct.
 *
 * The entries are kept in the order of RFC 8949 section 4.2.1: sorted by the bytes of the deterministic encoding of
 * their keys. A lookup compares the keys one by one, so it costs time in the number of entries, which every decoder
 * bounds with [CborLimits.maximumMapEntries].
 *
 * @constructor Sorts [entries] by their keys.
 * @param entries the entries, whose keys must be distinct.
 * @throws IllegalArgumentException if two keys are equal.
 * @since 1.0.0
 */
public class CborMap(entries: List<Pair<CborItem, CborItem>>) : CborItem() {
    /**
     * The entries, sorted by the deterministic encoding of their keys; the list cannot be changed.
     *
     * @since 1.0.0
     */
    public val entries: List<Pair<CborItem, CborItem>>

    /**
     * The number of entries.
     *
     * @since 1.0.0
     */
    public val size: Int get() = entries.size

    /**
     * The keys in the order of [entries].
     *
     * @since 1.0.0
     */
    public val keys: List<CborItem> get() = entries.map { entry -> entry.first }

    init {
        val keyed = entries.map { entry -> CborWriter.encode(entry.first) to entry }
        val sorted = keyed.sortedWith { first, second -> Bytes.compare(first = first.first, second = second.first) }
        val isDistinct = sorted.zipWithNext().none { (first, second) -> first.first == second.first }
        require(isDistinct) { "The keys of a CBOR map are distinct" }
        this.entries = sorted.map { entry -> entry.second }
    }

    /**
     * Returns the value of [key].
     *
     * @param key the key.
     * @return the value, or null if the map has no such key.
     * @since 1.0.0
     */
    public operator fun get(key: CborItem): CborItem? = entries.firstOrNull { entry -> entry.first == key }?.second

    /**
     * Returns the value of the integer key [label], as COSE names its parameters.
     *
     * @param label the key.
     * @return the value, or null if the map has no such key.
     * @since 1.0.0
     */
    public operator fun get(label: Long): CborItem? = get(CborInteger.of(label))

    /**
     * Tells whether the map has [key].
     *
     * @param key the key.
     * @return true if the map has the key.
     * @since 1.0.0
     */
    public operator fun contains(key: CborItem): Boolean = get(key) != null

    override fun write(writer: CborWriter) {
        writer.head(major = MAJOR, argument = entries.size.toULong())
        entries.forEach { (key, value) ->
            key.write(writer)
            value.write(writer)
        }
    }

    override fun mapOrNull(): CborMap = this

    /**
     * Compares the entries.
     *
     * @param other the other object.
     * @return true if [other] is a map of the same entries.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is CborMap && entries == other.entries

    /**
     * Hashes the entries.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = entries.hashCode()

    /**
     * Shows the entries in the diagnostic notation of CBOR.
     *
     * @return the map as text.
     * @since 1.0.0
     */
    override fun toString(): String = entries.joinToString(separator = ", ", prefix = "{", postfix = "}") { entry ->
        "${entry.first}: ${entry.second}"
    }

    /**
     * Builds maps.
     *
     * @since 1.0.0
     */
    public companion object {
        private const val MAJOR: Int = 5

        /**
         * The empty map.
         *
         * @since 1.0.0
         */
        public val Empty: CborMap = CborMap(emptyList())

        /**
         * Returns a map of [entries].
         *
         * @param entries the entries, whose keys must be distinct.
         * @return the map.
         * @throws IllegalArgumentException if two keys are equal.
         * @since 1.0.0
         */
        public fun of(vararg entries: Pair<CborItem, CborItem>): CborMap = CborMap(entries.toList())
    }
}
