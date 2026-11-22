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

import kotlinx.io.bytestring.ByteString

private const val SEVEN_BITS: Int = 7
private const val LOW_SEVEN: Int = 0x7F
private const val CONTINUATION: Int = 0x80
private const val FIRST_ARC_FACTOR: Long = 40
private const val MAXIMUM_FIRST_ARC: Long = 2
private const val MAXIMUM_ARC_BYTES: Int = 9
private const val MAXIMUM_DIGITS: Int = 19

/**
 * An ASN.1 OBJECT IDENTIFIER, such as `1.2.840.113549.1.1.11` for sha256WithRSAEncryption.
 *
 * Every arc fits a non-negative `Long`; the first arc is 0, 1 or 2, and the second is below 40 unless the first is 2.
 * Identifiers are ordered by their arcs, so they can key an ordered map.
 *
 * @since 1.0.0
 */
public class ObjectIdentifier private constructor(private val arcList: List<Long>) : Comparable<ObjectIdentifier> {
    /**
     * The arcs.
     *
     * @since 1.0.0
     */
    public val arcs: List<Long> get() = arcList

    /**
     * The dotted form, such as `2.5.29.17`.
     *
     * @since 1.0.0
     */
    public val dotted: String = arcList.joinToString(separator = ".")

    /**
     * The content octets of the DER encoding.
     *
     * @since 1.0.0
     */
    public val content: ByteString = encode(arcList)

    /**
     * Orders identifiers by their arcs.
     *
     * @param other the other identifier.
     * @return the order.
     * @since 1.0.0
     */
    override fun compareTo(other: ObjectIdentifier): Int {
        val shared = minOf(a = arcList.size, b = other.arcList.size)
        val firstDifference = (0 until shared).firstOrNull { index -> arcList[index] != other.arcList[index] }
        val byArc = firstDifference?.let { index -> arcList[index].compareTo(other.arcList[index]) }
        return byArc ?: arcList.size.compareTo(other.arcList.size)
    }

    /**
     * Compares the arcs.
     *
     * @param other the other object.
     * @return true if [other] is the same identifier.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is ObjectIdentifier && arcList == other.arcList

    /**
     * Hashes the arcs.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = arcList.hashCode()

    /**
     * Returns the dotted form.
     *
     * @return the identifier as text.
     * @since 1.0.0
     */
    override fun toString(): String = dotted

    /**
     * The factories of an identifier.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The most arcs an identifier may have: 64.
         *
         * @since 1.0.0
         */
        public const val MAXIMUM_ARCS: Int = 64

        /**
         * Parses the dotted form, such as `1.3.6.1.5.5.7.3.1`.
         *
         * @param dotted the dotted form: decimal arcs without leading zeros, separated by single dots.
         * @return the identifier.
         * @throws IllegalArgumentException if [dotted] is not a valid identifier.
         * @since 1.0.0
         */
        public fun of(dotted: String): ObjectIdentifier =
            requireNotNull(parseOrNull(dotted)) { "This is not an object identifier in dotted form" }

        /**
         * Parses the dotted form, or returns null if it is not a valid identifier.
         *
         * @param dotted the dotted form.
         * @return the identifier or null.
         * @since 1.0.0
         */
        public fun parseOrNull(dotted: String): ObjectIdentifier? {
            val parts = dotted.split('.')
            val arcs = parts.mapNotNull { part -> arcOrNull(part) }
            val isComplete = arcs.size == parts.size && isValid(arcs)
            return arcs.takeIf { isComplete }?.let { valid -> ObjectIdentifier(valid) }
        }

        /**
         * Reads the content octets of an OBJECT IDENTIFIER.
         *
         * @param content the content octets.
         * @return the identifier, or null if the content is not a minimal encoding of a valid identifier.
         * @since 1.0.0
         */
        public fun decodeOrNull(content: ByteString): ObjectIdentifier? {
            val values = subidentifiersOrNull(content) ?: return null
            val first = minOf(a = values[0] / FIRST_ARC_FACTOR, b = MAXIMUM_FIRST_ARC)
            val arcs = listOf(first, values[0] - first * FIRST_ARC_FACTOR) + values.drop(1)
            return arcs.takeIf { isValid(arcs) }?.let { valid -> ObjectIdentifier(valid) }
        }

        private fun subidentifiersOrNull(content: ByteString): List<Long>? {
            val values = mutableListOf<Long>()
            var current = 0L
            var bytesInArc = 0
            var isValid = content.size > 0
            for (index in 0 until content.size) {
                val byte = content[index].toInt()
                isValid = isValid && !(bytesInArc == 0 && byte == CONTINUATION) && bytesInArc < MAXIMUM_ARC_BYTES
                current = (current shl SEVEN_BITS) or (byte and LOW_SEVEN).toLong()
                bytesInArc += 1
                if (byte and CONTINUATION == 0) {
                    values += current
                    current = 0L
                    bytesInArc = 0
                }
            }
            val isComplete = isValid && bytesInArc == 0 && values.all { value -> value >= 0 }
            return values.takeIf { isComplete && values.size < MAXIMUM_ARCS }
        }

        private fun arcOrNull(part: String): Long? {
            val isDecimal = part.isNotEmpty() && part.length <= MAXIMUM_DIGITS && part.all { char -> char in '0'..'9' }
            val hasLeadingZero = part.length > 1 && part.startsWith('0')
            return part.takeIf { isDecimal && !hasLeadingZero }?.toLongOrNull()
        }

        private fun isValid(arcs: List<Long>): Boolean {
            val isSized = arcs.size in 2..MAXIMUM_ARCS
            val first = arcs.getOrNull(0) ?: -1L
            val second = arcs.getOrNull(1) ?: -1L
            val isRooted = first in 0..MAXIMUM_FIRST_ARC && second >= 0
            val isSecondInRange = first == MAXIMUM_FIRST_ARC || second < FIRST_ARC_FACTOR
            val isFirstEncodable = second <= Long.MAX_VALUE - first * FIRST_ARC_FACTOR
            return isSized && isRooted && isSecondInRange && isFirstEncodable
        }

        private fun encode(arcs: List<Long>): ByteString {
            val values = listOf(arcs[0] * FIRST_ARC_FACTOR + arcs[1]) + arcs.drop(2)
            val bytes = values.flatMap { value -> base128(value) }
            return ByteString(bytes.toByteArray())
        }

        private fun base128(value: Long): List<Byte> {
            val groups = mutableListOf((value and LOW_SEVEN.toLong()).toByte())
            var rest = value ushr SEVEN_BITS
            while (rest > 0) {
                groups += ((rest and LOW_SEVEN.toLong()) or CONTINUATION.toLong()).toByte()
                rest = rest ushr SEVEN_BITS
            }
            return groups.asReversed()
        }
    }
}
