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

import com.davils.krypt.asn1.internal.unsignedAtOrNull
import com.davils.krypt.core.encoding.Hex
import kotlinx.io.bytestring.ByteString

private const val MAXIMUM_UNUSED: Int = 7
private const val BYTE_BITS: Int = 8
private const val HASH_FACTOR: Int = 31

/**
 * An ASN.1 BIT STRING: [bytes] whose last byte leaves [unusedBits] low bits unused, such as a public key or a
 * signature (whole bytes) or the key usage of a certificate (named bits).
 *
 * DER requires the unused bits to be zero; krypt refuses one that is not.
 *
 * @property bytes the bits, most significant bit first.
 * @property unusedBits the number of unused low bits of the last byte, from 0 to 7, and 0 if [bytes] is empty.
 * @since 1.0.0
 */
public class BitString(public val bytes: ByteString, public val unusedBits: Int = 0) {
    init {
        require(unusedBits in 0..MAXIMUM_UNUSED) { "A bit string leaves 0 to 7 bits unused, not $unusedBits" }
        require(bytes.size > 0 || unusedBits == 0) { "An empty bit string leaves no bits unused" }
        val lastByte = bytes.unsignedAtOrNull(bytes.size - 1) ?: 0
        require(lastByte and (1 shl unusedBits) - 1 == 0) { "The unused bits of a bit string must be zero" }
    }

    /**
     * The number of bits.
     *
     * @since 1.0.0
     */
    public val size: Int get() = bytes.size * BYTE_BITS - unusedBits

    /**
     * Tells whether the bit at [index] is set, counting from the most significant bit of the first byte, as the named
     * bits of a key usage count.
     *
     * @param index the bit, from 0 on; a bit past the end is unset.
     * @return true if the bit is set.
     * @since 1.0.0
     */
    public operator fun get(index: Int): Boolean {
        val isInside = index in 0 until size
        val byte = bytes.unsignedAtOrNull(index / BYTE_BITS) ?: 0
        return isInside && byte shr MAXIMUM_UNUSED - index % BYTE_BITS and 1 == 1
    }

    /**
     * Compares the bits.
     *
     * @param other the other object.
     * @return true if [other] holds the same bits.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean =
        other is BitString && bytes == other.bytes && unusedBits == other.unusedBits

    /**
     * Hashes the bits.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = bytes.hashCode() * HASH_FACTOR + unusedBits

    /**
     * Shows the bits in hexadecimal and the number of unused bits.
     *
     * @return the bit string as text.
     * @since 1.0.0
     */
    override fun toString(): String = "BitString(${Hex.encode(bytes)}, unusedBits=$unusedBits)"

    /**
     * The factory of named bits.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * Returns the minimal bit string with exactly the bits [set], as DER encodes named bits: trailing zero bits
         * are dropped.
         *
         * @param set the indices of the set bits, each at least 0.
         * @return the bit string.
         * @throws IllegalArgumentException if an index is negative.
         * @since 1.0.0
         */
        public fun ofNamedBits(set: Set<Int>): BitString {
            require(set.all { index -> index >= 0 }) { "A named bit has a non-negative index" }
            val highest = set.maxOrNull() ?: return BitString(ByteString())
            val array = ByteArray(highest / BYTE_BITS + 1)
            set.forEach { index ->
                val position = index / BYTE_BITS
                array[position] = (array[position].toInt() or (1 shl MAXIMUM_UNUSED - index % BYTE_BITS)).toByte()
            }
            return BitString(bytes = ByteString(array), unusedBits = MAXIMUM_UNUSED - highest % BYTE_BITS)
        }
    }
}
