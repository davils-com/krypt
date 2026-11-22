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

package com.davils.krypt.core

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.text.SafeText

private const val DESTROYED_MESSAGE: String = "The secret text was destroyed, so it cannot be read any more"
private const val ONE_BYTE_LIMIT: Int = 0x80
private const val TWO_BYTE_LIMIT: Int = 0x800
private const val THREE_BYTE_LIMIT: Int = 0x10000
private const val SIX_BITS: Int = 6
private const val CONTINUATION: Int = 0x80
private const val CONTINUATION_MASK: Int = 0x3F
private const val TWO_BYTE_LEAD: Int = 0xC0
private const val THREE_BYTE_LEAD: Int = 0xE0
private const val FOUR_BYTE_LEAD: Int = 0xF0
private const val UTF8_THREE: Int = 3
private const val HIGH_SURROGATE_START: Int = 0xD800
private const val LOW_SURROGATE_START: Int = 0xDC00
private const val SURROGATE_BITS: Int = 10
private const val REPLACEMENT: Int = 0xFFFD

/**
 * A secret text, such as a password or a passphrase, held as characters that krypt wipes on [destroy].
 *
 * A secret text behaves like [SecretBytes]: it copies what it is given, lends its characters only to a block, shows
 * nothing of itself, compares in constant time and hashes by length alone. [utf8] encodes it for a key derivation
 * without ever creating a `String`, which could not be wiped. A lone surrogate is encoded as U+FFFD.
 *
 * @since 1.0.0
 */
public class SecretText private constructor(initial: CharArray) {
    private var chars: CharArray? = initial

    /**
     * The number of UTF-16 code units, which stays readable after [destroy].
     *
     * @since 1.0.0
     */
    public val length: Int = initial.size

    /**
     * Tells whether [destroy] wiped the characters.
     *
     * @since 1.0.0
     */
    public val isDestroyed: Boolean get() = chars == null

    /**
     * Lends the characters to [block], which must neither change nor keep the array.
     *
     * @param R the result of [block].
     * @param block reads the characters.
     * @return what [block] returns.
     * @throws IllegalStateException if the text was destroyed.
     * @since 1.0.0
     */
    public inline fun <R> reveal(block: (CharArray) -> R): R = block(revealed())

    @PublishedApi
    internal fun revealed(): CharArray = checkNotNull(chars) { DESTROYED_MESSAGE }

    /**
     * Encodes the text in UTF-8 into new secret bytes.
     *
     * @return the UTF-8 bytes.
     * @throws IllegalStateException if the text was destroyed.
     * @since 1.0.0
     */
    public fun utf8(): SecretBytes {
        val source = checkNotNull(chars) { DESTROYED_MESSAGE }
        val buffer = ByteArray(source.size * UTF8_THREE + 1)
        var written = 0
        var index = 0
        while (index < source.size) {
            val codePoint = codePointAt(source, index)
            index += 1 + (codePoint >= THREE_BYTE_LIMIT).compareTo(false)
            written = encode(codePoint, buffer, written)
        }
        val result = SecretBytes.copyOf(buffer.copyOf(written))
        buffer.fill(0)
        return result
    }

    /**
     * Overwrites the characters with zeros and forgets them. Destroying twice does nothing.
     *
     * @since 1.0.0
     */
    public fun destroy() {
        chars?.fill(Char(0))
        chars = null
    }

    /**
     * Runs [block] with this text and destroys the text afterwards, also when [block] throws.
     *
     * @param R the result of [block].
     * @param block uses the text.
     * @return what [block] returns.
     * @since 1.0.0
     */
    public inline fun <R> use(block: (SecretText) -> R): R {
        try {
            return block(this)
        } finally {
            destroy()
        }
    }

    /**
     * Compares the characters with those of [other] in constant time. A destroyed text equals only itself.
     *
     * @param other the other object.
     * @return true if [other] is a secret text with the same characters.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        val mine = chars ?: return false
        return other is SecretText && other.chars?.let { theirs -> sameChars(first = mine, second = theirs) } == true
    }

    /**
     * Returns a hash of the length alone.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = length

    /**
     * Shows the length and whether the text was destroyed, never the characters.
     *
     * @return the secret text as text.
     * @since 1.0.0
     */
    override fun toString(): String = "SecretText(length=$length, text=${SafeText.REDACTED}, destroyed=$isDestroyed)"

    /**
     * The factories of a secret text.
     *
     * @since 1.0.0
     */
    public companion object {
        private val LEADS: IntArray = intArrayOf(0, TWO_BYTE_LEAD, THREE_BYTE_LEAD, FOUR_BYTE_LEAD)

        /**
         * Copies [chars] into a new secret text; the caller still owns [chars] and should wipe it.
         *
         * @param chars the characters.
         * @return the secret text.
         * @since 1.0.0
         */
        public fun copyOf(chars: CharArray): SecretText = SecretText(chars.copyOf())

        /**
         * Copies [text] into a new secret text. The `String` itself cannot be wiped, so prefer [copyOf] with a
         * `CharArray` for a password that comes from a user.
         *
         * @param text the text.
         * @return the secret text.
         * @since 1.0.0
         */
        public fun of(text: CharSequence): SecretText = SecretText(CharArray(text.length) { index -> text[index] })

        /**
         * Takes over [chars] without copying it; the caller never touches the array again.
         *
         * @param chars the characters.
         * @return the secret text.
         * @since 1.0.0
         */
        public fun adopt(chars: CharArray): SecretText = SecretText(chars)

        private fun sameChars(first: CharArray, second: CharArray): Boolean {
            var difference = first.size xor second.size
            val shared = minOf(a = first.size, b = second.size)
            for (index in 0 until shared) difference = difference or (first[index].code xor second[index].code)
            return difference == 0
        }

        private fun codePointAt(chars: CharArray, index: Int): Int {
            val high = chars[index]
            val low = chars.getOrNull(index + 1)
            val isPair = high.isHighSurrogate() && low != null && low.isLowSurrogate()
            if (isPair) return pairOf(high = high.code, low = low.code)
            return high.code + (REPLACEMENT - high.code) * high.isSurrogate().compareTo(false)
        }

        private fun pairOf(high: Int, low: Int): Int =
            (high - HIGH_SURROGATE_START shl SURROGATE_BITS) + (low - LOW_SURROGATE_START) + THREE_BYTE_LIMIT

        private fun encode(codePoint: Int, buffer: ByteArray, at: Int): Int {
            val extra = (codePoint >= ONE_BYTE_LIMIT).compareTo(false) +
                (codePoint >= TWO_BYTE_LIMIT).compareTo(false) +
                (codePoint >= THREE_BYTE_LIMIT).compareTo(false)
            if (extra == 0) {
                buffer[at] = codePoint.toByte()
                return at + 1
            }
            buffer[at] = (LEADS[extra] or (codePoint shr SIX_BITS * extra)).toByte()
            for (index in 1..extra) buffer[at + index] = continuation(codePoint shr SIX_BITS * (extra - index))
            return at + extra + 1
        }

        private fun continuation(bits: Int): Byte = (CONTINUATION or (bits and CONTINUATION_MASK)).toByte()
    }
}
