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

import com.davils.krypt.core.encoding.Hex
import kotlinx.io.bytestring.ByteString

private const val BYTE_BITS: Int = 8
private const val BYTE_MASK: Int = 0xFF
private const val SIGN_BIT: Int = 0x80
private const val LONG_BYTES: Int = 8

/**
 * An ASN.1 INTEGER of any size, held as its minimal two's complement bytes, such as the serial number of a
 * certificate or a field of an RSA key.
 *
 * krypt does no arithmetic on large integers in common code; an integer is a value to compare, encode and hand to the
 * platform. Two integers are equal when their bytes are.
 *
 * @since 1.0.0
 */
public class DerInteger private constructor(private val twosComplement: ByteString) : Comparable<DerInteger> {
    /**
     * The minimal two's complement bytes, big endian, as DER encodes them.
     *
     * @since 1.0.0
     */
    public val bytes: ByteString get() = twosComplement

    /**
     * Tells whether the integer is below zero.
     *
     * @since 1.0.0
     */
    public val isNegative: Boolean get() = twosComplement[0].toInt() and SIGN_BIT != 0

    /**
     * The magnitude of a non-negative integer as unsigned big endian bytes without leading zeros, empty for zero.
     *
     * @return the magnitude.
     * @throws IllegalStateException if the integer is negative.
     * @since 1.0.0
     */
    public fun magnitude(): ByteString {
        check(!isNegative) { "A negative integer has no unsigned magnitude" }
        val array = twosComplement.toByteArray()
        val start = array.indexOfFirst { byte -> byte.toInt() != 0 }.takeIf { index -> index >= 0 } ?: array.size
        return ByteString(data = array, startIndex = start, endIndex = array.size)
    }

    /**
     * Returns the value as a `Long`, or null if it does not fit.
     *
     * @return the value or null.
     * @since 1.0.0
     */
    public fun toLongOrNull(): Long? {
        if (twosComplement.size > LONG_BYTES) return null
        var value = -isNegative.compareTo(false).toLong()
        for (index in 0 until twosComplement.size) {
            value = (value shl BYTE_BITS) or (twosComplement[index].toLong() and BYTE_MASK.toLong())
        }
        return value
    }

    /**
     * Orders integers by value.
     *
     * @param other the other integer.
     * @return the order.
     * @since 1.0.0
     */
    override fun compareTo(other: DerInteger): Int {
        val bySign = other.isNegative.compareTo(isNegative)
        val bySize = (twosComplement.size - other.twosComplement.size) * (1 - 2 * isNegative.compareTo(false))
        return bySign.takeIf { order -> order != 0 } ?: bySize.takeIf { order -> order != 0 } ?: compareBytes(other)
    }

    private fun compareBytes(other: DerInteger): Int {
        for (index in 0 until twosComplement.size) {
            val order =
                (twosComplement[index].toInt() and BYTE_MASK) - (other.twosComplement[index].toInt() and BYTE_MASK)
            if (order != 0) return order
        }
        return 0
    }

    /**
     * Compares the bytes.
     *
     * @param other the other object.
     * @return true if [other] is the same integer.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is DerInteger && twosComplement == other.twosComplement

    /**
     * Hashes the bytes.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = twosComplement.hashCode()

    /**
     * Shows the value in decimal if it fits a `Long`, otherwise its bytes in hexadecimal.
     *
     * @return the integer as text.
     * @since 1.0.0
     */
    override fun toString(): String = toLongOrNull()?.toString() ?: "0x${Hex.encode(twosComplement)}"

    /**
     * The factories of an integer.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * Zero.
         *
         * @since 1.0.0
         */
        public val Zero: DerInteger = of(0L)

        /**
         * Returns [value] as an integer.
         *
         * @param value the value.
         * @return the integer.
         * @since 1.0.0
         */
        public fun of(value: Long): DerInteger {
            val array = ByteArray(LONG_BYTES) { index -> (value shr (LONG_BYTES - 1 - index) * BYTE_BITS).toByte() }
            return DerInteger(minimal(array))
        }

        /**
         * Returns the non-negative integer whose unsigned big endian bytes are [magnitude], such as a serial number
         * drawn from random bytes.
         *
         * @param magnitude the unsigned bytes; leading zeros are dropped and empty means zero.
         * @return the integer.
         * @since 1.0.0
         */
        public fun ofMagnitude(magnitude: ByteString): DerInteger {
            val array = ByteArray(magnitude.size + 1)
            magnitude.copyInto(destination = array, destinationOffset = 1)
            return DerInteger(minimal(array))
        }

        /**
         * Reads the content octets of an INTEGER, which DER requires in their minimal form.
         *
         * @param content the content octets.
         * @return the integer, or null if the content is empty or not minimal.
         * @since 1.0.0
         */
        public fun decodeOrNull(content: ByteString): DerInteger? {
            val isMinimal = content.size == 1 || (content.size > 1 && !hasRedundantLead(content))
            return DerInteger(content).takeIf { isMinimal }
        }

        private fun hasRedundantLead(content: ByteString): Boolean {
            val first = content[0].toInt() and BYTE_MASK
            val secondSign = content[1].toInt() and SIGN_BIT
            return (first == 0 && secondSign == 0) || (first == BYTE_MASK && secondSign != 0)
        }

        private fun minimal(array: ByteArray): ByteString {
            var start = 0
            while (start < array.size - 1 && isRedundantAt(array, start)) start += 1
            return ByteString(data = array, startIndex = start, endIndex = array.size)
        }

        private fun isRedundantAt(array: ByteArray, index: Int): Boolean {
            val lead = array[index].toInt() and BYTE_MASK
            val nextSign = array[index + 1].toInt() and SIGN_BIT
            return (lead == 0 && nextSign == 0) || (lead == BYTE_MASK && nextSign != 0)
        }
    }
}
