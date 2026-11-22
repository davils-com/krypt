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

package com.davils.krypt.core.encoding

import com.davils.kore.core.outcome.Outcome
import kotlinx.io.bytestring.ByteString

private const val NIBBLE_BITS: Int = 4
private const val NIBBLE_MASK: Int = 0x0F
private const val BYTE_MASK: Int = 0xFF
private const val DIGIT_LIMIT: Int = 10
private const val LOWER_OFFSET: Int = 'a'.code - DIGIT_LIMIT
private const val UPPER_OFFSET: Int = 'A'.code - DIGIT_LIMIT
private const val INVALID: Int = -1

/**
 * Base16 of RFC 4648, the hexadecimal text of bytes, strict in what it reads.
 *
 * The decoder accepts upper and lower case digits and, when asked, a separator between every pair, but nothing else:
 * no whitespace, no prefix such as `0x` and no odd length. The value of every digit is computed without a branch or a
 * table lookup on the digit, so decoding a secret takes the same time whatever its bytes.
 *
 * @since 1.0.0
 */
public object Hex {
    /**
     * The longest text the decoder reads, in characters: 16 MiB.
     *
     * @since 1.0.0
     */
    public const val MAXIMUM_TEXT_LENGTH: Int = 16 * 1_024 * 1_024

    /**
     * Encodes [bytes] in lower case hexadecimal, with [separator] between the pairs if one is given.
     *
     * @param bytes the bytes.
     * @param separator the character between two pairs, such as `:` for a fingerprint, or null for none.
     * @return the text.
     * @since 1.0.0
     */
    public fun encode(bytes: ByteArray, separator: Char? = null): String {
        val text = StringBuilder(bytes.size * (2 + (separator != null).compareTo(false)))
        bytes.forEachIndexed { index, byte ->
            if (separator != null && index > 0) text.append(separator)
            val value = byte.toInt() and BYTE_MASK
            text.append(digit(value shr NIBBLE_BITS))
            text.append(digit(value and NIBBLE_MASK))
        }
        return text.toString()
    }

    /**
     * Encodes [bytes] in lower case hexadecimal, with [separator] between the pairs if one is given.
     *
     * @param bytes the bytes.
     * @param separator the character between two pairs, or null for none.
     * @return the text.
     * @since 1.0.0
     */
    public fun encode(bytes: ByteString, separator: Char? = null): String =
        encode(bytes = bytes.toByteArray(), separator = separator)

    /**
     * Decodes [text], which holds pairs of hexadecimal digits, each pair after the first preceded by [separator] if
     * one is given.
     *
     * @param text the text, at most [MAXIMUM_TEXT_LENGTH] characters.
     * @param separator the character between two pairs, or null if there is none.
     * @return the bytes, or why [text] is not hexadecimal.
     * @since 1.0.0
     */
    public fun decode(text: CharSequence, separator: Char? = null): Outcome<ByteString, EncodingFailure> =
        when (val decoded = decodeToArray(text, separator)) {
            is Outcome.Success -> Outcome.Success(ByteString(decoded.value))
            is Outcome.Failure -> decoded
        }

    internal fun decodeToArray(text: CharSequence, separator: Char?): Outcome<ByteArray, EncodingFailure> {
        val failure = shapeFailureOf(text, separator) ?: return decodePairs(text, separator)
        return Outcome.Failure(failure)
    }

    private fun shapeFailureOf(text: CharSequence, separator: Char?): EncodingFailure? {
        if (text.length > MAXIMUM_TEXT_LENGTH) return EncodingFailure.TooLong
        val stride = strideOf(separator)
        val count = pairsIn(text, stride)
        val isShaped = text.isEmpty() || count * stride - (stride - 2) == text.length
        return EncodingFailure.InvalidLength.takeUnless { isShaped }
    }

    private fun decodePairs(text: CharSequence, separator: Char?): Outcome<ByteArray, EncodingFailure> {
        val stride = strideOf(separator)
        val bytes = ByteArray(pairsIn(text, stride))
        var invalid = 0
        for (index in bytes.indices) {
            val at = index * stride
            val high = valueOf(text[at])
            val low = valueOf(text[at + 1])
            invalid = invalid or high or low or separatorMismatch(
                text = text,
                at = at - 1,
                separator = separator,
                index = index,
            )
            bytes[index] = ((high shl NIBBLE_BITS) or low).toByte()
        }
        if (invalid < 0) return Outcome.Failure(EncodingFailure.InvalidCharacter)
        return Outcome.Success(bytes)
    }

    private fun strideOf(separator: Char?): Int = 2 + (separator != null).compareTo(false)

    private fun pairsIn(text: CharSequence, stride: Int): Int = (text.length + stride - 2) / stride

    private fun separatorMismatch(text: CharSequence, at: Int, separator: Char?, index: Int): Int {
        if (separator == null || index == 0) return 0
        return -(text[at] != separator).compareTo(false)
    }

    private fun digit(value: Int): Char {
        val letterMask = DIGIT_LIMIT - 1 - value shr Int.SIZE_BITS - 1
        return (value + '0'.code + (letterMask and LOWER_OFFSET - '0'.code)).toChar()
    }

    private fun valueOf(char: Char): Int {
        val code = char.code
        val digit = code - '0'.code
        val lower = code - LOWER_OFFSET
        val upper = code - UPPER_OFFSET
        val digitMask = inRange(value = digit, low = 0, high = DIGIT_LIMIT - 1)
        val lowerMask = inRange(value = lower, low = DIGIT_LIMIT, high = NIBBLE_MASK)
        val upperMask = inRange(value = upper, low = DIGIT_LIMIT, high = NIBBLE_MASK)
        val value = (digit and digitMask) or (lower and lowerMask) or (upper and upperMask)
        return value or (INVALID and (digitMask or lowerMask or upperMask).inv())
    }

    private fun inRange(value: Int, low: Int, high: Int): Int =
        (value - low or high - value).inv() shr Int.SIZE_BITS - 1
}
