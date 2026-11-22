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

@file:OptIn(DavilsInternal::class)

package com.davils.krypt.jose

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.collection.OrderedMap
import com.davils.kore.core.text.SafeText
import com.davils.krypt.jose.internal.JsonWriter
import com.davils.krypt.jose.internal.Unicode

private const val NULL_TEXT: String = "null"

/**
 * A JSON value of RFC 8259 as JOSE uses it: the I-JSON subset of RFC 7493, in which every text is valid Unicode
 * without noncharacters, every number is an integer that a double represents exactly and no object repeats a member
 * name.
 *
 * Values are immutable and safe to share between threads.
 *
 * @since 1.0.0
 */
public sealed interface JsonValue {
    /**
     * A JSON string.
     *
     * @property value the text.
     * @throws IllegalArgumentException if [value] holds a lone surrogate or a Unicode noncharacter.
     * @since 1.0.0
     */
    public class Text(public val value: String) : JsonValue {
        init {
            require(Unicode.isInterchangeable(value)) { "A JSON text holds no lone surrogate and no noncharacter" }
        }

        /**
         * Compares the texts.
         *
         * @param other the other object.
         * @return true if [other] is the same text.
         * @since 1.0.0
         */
        override fun equals(other: Any?): Boolean = other is Text && value == other.value

        /**
         * Hashes the text.
         *
         * @return the hash.
         * @since 1.0.0
         */
        override fun hashCode(): Int = value.hashCode()

        /**
         * Shows the text, escaped.
         *
         * @return the value as text.
         * @since 1.0.0
         */
        override fun toString(): String = SafeText.quoted(value)
    }

    /**
     * A JSON number, which JOSE needs only as an integer: a NumericDate or an iteration count.
     *
     * @property value the integer, at most [MAXIMUM] in magnitude.
     * @throws IllegalArgumentException if [value] exceeds [MAXIMUM] in magnitude.
     * @since 1.0.0
     */
    public class Integer(public val value: Long) : JsonValue {
        init {
            require(value in -MAXIMUM..MAXIMUM) { "A JSON integer of JOSE is at most $MAXIMUM in magnitude" }
        }

        /**
         * Compares the integers.
         *
         * @param other the other object.
         * @return true if [other] is the same integer.
         * @since 1.0.0
         */
        override fun equals(other: Any?): Boolean = other is Integer && value == other.value

        /**
         * Hashes the integer.
         *
         * @return the hash.
         * @since 1.0.0
         */
        override fun hashCode(): Int = value.hashCode()

        /**
         * Shows the integer.
         *
         * @return the value as text.
         * @since 1.0.0
         */
        override fun toString(): String = value.toString()

        /**
         * The bounds of an integer.
         *
         * @since 1.0.0
         */
        public companion object {
            /**
             * The largest magnitude, 2^53 - 1, the largest integer every JSON parser reads exactly.
             *
             * @since 1.0.0
             */
            public const val MAXIMUM: Long = 9_007_199_254_740_991L
        }
    }

    /**
     * A JSON `true` or `false`.
     *
     * @property isTrue the truth value.
     * @since 1.0.0
     */
    public class Bool(public val isTrue: Boolean) : JsonValue {
        /**
         * Compares the truth values.
         *
         * @param other the other object.
         * @return true if [other] is the same truth value.
         * @since 1.0.0
         */
        override fun equals(other: Any?): Boolean = other is Bool && isTrue == other.isTrue

        /**
         * Hashes the truth value.
         *
         * @return the hash.
         * @since 1.0.0
         */
        override fun hashCode(): Int = isTrue.hashCode()

        /**
         * Shows the truth value.
         *
         * @return the value as text.
         * @since 1.0.0
         */
        override fun toString(): String = isTrue.toString()
    }

    /**
     * The JSON `null`.
     *
     * @since 1.0.0
     */
    public object Null : JsonValue {
        /**
         * Shows `null`.
         *
         * @return the value as text.
         * @since 1.0.0
         */
        override fun toString(): String = NULL_TEXT
    }

    /**
     * A JSON array.
     *
     * @param items the elements, copied.
     * @since 1.0.0
     */
    public class Array(items: List<JsonValue>) : JsonValue {
        /**
         * The elements in order.
         *
         * @since 1.0.0
         */
        public val items: List<JsonValue> = items.toList()

        /**
         * Compares the elements in order.
         *
         * @param other the other object.
         * @return true if [other] holds equal elements in the same order.
         * @since 1.0.0
         */
        override fun equals(other: Any?): Boolean = other is Array && items == other.items

        /**
         * Hashes the elements.
         *
         * @return the hash.
         * @since 1.0.0
         */
        override fun hashCode(): Int = items.hashCode()

        /**
         * Shows the size.
         *
         * @return the value as text.
         * @since 1.0.0
         */
        override fun toString(): String = "Array(${items.size} items)"
    }

    /**
     * A JSON object, whose member names are unique.
     *
     * @param members the members in order, copied.
     * @throws IllegalArgumentException if a name occurs twice or is not interchangeable Unicode.
     * @since 1.0.0
     */
    public class Object(members: List<Pair<String, JsonValue>>) : JsonValue {
        private val index = OrderedMap<String, JsonValue>()

        /**
         * The members in order.
         *
         * @since 1.0.0
         */
        public val members: List<Pair<String, JsonValue>> = members.toList()

        /**
         * The member names in order.
         *
         * @since 1.0.0
         */
        public val names: List<String> get() = members.map { member -> member.first }

        init {
            for ((name, value) in this.members) {
                require(Unicode.isInterchangeable(name)) { "A member name holds no lone surrogate or noncharacter" }
                require(name !in index) { "The member ${SafeText.quoted(name)} occurs twice" }
                index[name] = value
            }
        }

        /**
         * Returns the value of the member [name].
         *
         * @param name the member name.
         * @return the value, or null if the object has no such member.
         * @since 1.0.0
         */
        public operator fun get(name: String): JsonValue? = index[name]

        /**
         * Tells whether the object has the member [name].
         *
         * @param name the member name.
         * @return true if the member is present.
         * @since 1.0.0
         */
        public operator fun contains(name: String): Boolean = name in index

        /**
         * Writes the object as compact JSON text, members in order and without whitespace.
         *
         * @return the JSON text.
         * @since 1.0.0
         */
        public fun encode(): String = JsonWriter.write(this)

        /**
         * Compares the members regardless of their order.
         *
         * @param other the other object.
         * @return true if [other] has the same names with equal values.
         * @since 1.0.0
         */
        override fun equals(other: Any?): Boolean = other is Object &&
            members.size == other.members.size &&
            members.all { (name, value) -> other[name] == value }

        /**
         * Hashes the members regardless of their order.
         *
         * @return the hash.
         * @since 1.0.0
         */
        override fun hashCode(): Int = members.sumOf { member -> member.hashCode() }

        /**
         * Shows the member names, never the values, which may be secret.
         *
         * @return the value as text.
         * @since 1.0.0
         */
        override fun toString(): String = "Object(${names.joinToString { name -> SafeText.text(name) }})"

        /**
         * The empty object.
         *
         * @since 1.0.0
         */
        public companion object {
            /**
             * The object without members.
             *
             * @since 1.0.0
             */
            public val Empty: Object = Object(emptyList())

            /**
             * Builds an object of [members].
             *
             * @param members the members in order.
             * @return the object.
             * @throws IllegalArgumentException if a name occurs twice.
             * @since 1.0.0
             */
            public fun of(vararg members: Pair<String, JsonValue>): Object = Object(members.toList())
        }
    }
}
