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

private const val GROUP_BYTES: Int = 3
private const val GROUP_CHARS: Int = 4
private const val SIX_BITS: Int = 6
private const val SIX_MASK: Int = 0x3F
private const val BYTE_BITS: Int = 8
private const val BYTE_MASK: Int = 0xFF
private const val UPPER_COUNT: Int = 26
private const val DIGIT_START: Int = 52
private const val VALUE_62: Int = 62
private const val VALUE_63: Int = 63
private const val INVALID: Int = -1
private const val PAD: Char = '='
private const val TWO_PADS: Int = 2
private const val SHIFT_HIGH: Int = 18
private const val SHIFT_MIDDLE: Int = 12
private const val SHIFT_FIRST_BYTE: Int = 16

/**
 * Base64 of RFC 4648, strict in what it reads.
 *
 * The decoder accepts exactly one text for every byte sequence: no whitespace, no line breaks, padding exactly when
 * it is asked for and the unused bits of the last character zero. A caller that reads a format with line breaks, such
 * as PEM, removes them first and keeps every other check. The value of every character is computed without a branch
 * or a table lookup on the character, so decoding a secret takes the same time whatever its bytes.
 *
 * @since 1.0.0
 */
public object Base64 {
    /**
     * The longest text the decoder reads, in characters: 64 MiB.
     *
     * @since 1.0.0
     */
    public const val MAXIMUM_TEXT_LENGTH: Int = 64 * 1_024 * 1_024

    /**
     * Encodes [bytes].
     *
     * @param bytes the bytes.
     * @param alphabet the alphabet; [Base64Alphabet.Standard] by default.
     * @param padding whether the text ends with `=` up to a multiple of four characters; true by default.
     * @return the text.
     * @since 1.0.0
     */
    public fun encode(
        bytes: ByteArray,
        alphabet: Base64Alphabet = Base64Alphabet.Standard,
        padding: Boolean = true,
    ): String {
        val text = StringBuilder((bytes.size + 2) / GROUP_BYTES * GROUP_CHARS)
        var index = 0
        while (index + GROUP_BYTES <= bytes.size) {
            val first = byteAt(bytes, index) shl SHIFT_FIRST_BYTE
            val second = byteAt(bytes, index + 1) shl BYTE_BITS
            val group = first or second or byteAt(bytes, index + 2)
            appendChars(text = text, group = group, count = GROUP_CHARS, alphabet = alphabet)
            index += GROUP_BYTES
        }
        val rest = bytes.size - index
        if (rest > 0) appendTail(text = text, bytes = bytes, at = index, alphabet = alphabet, padding = padding)
        return text.toString()
    }

    /**
     * Encodes [bytes].
     *
     * @param bytes the bytes.
     * @param alphabet the alphabet; [Base64Alphabet.Standard] by default.
     * @param padding whether the text is padded with `=`; true by default.
     * @return the text.
     * @since 1.0.0
     */
    public fun encode(
        bytes: ByteString,
        alphabet: Base64Alphabet = Base64Alphabet.Standard,
        padding: Boolean = true,
    ): String = encode(bytes = bytes.toByteArray(), alphabet = alphabet, padding = padding)

    /**
     * Decodes [text].
     *
     * @param text the text, at most [MAXIMUM_TEXT_LENGTH] characters.
     * @param alphabet the alphabet; [Base64Alphabet.Standard] by default.
     * @param padding whether the text must be padded with `=` (true, the default) or must not be (false).
     * @return the bytes, or why [text] is not the canonical Base64 of any bytes.
     * @since 1.0.0
     */
    public fun decode(
        text: CharSequence,
        alphabet: Base64Alphabet = Base64Alphabet.Standard,
        padding: Boolean = true,
    ): Outcome<ByteString, EncodingFailure> = when (val decoded = decodeToArray(text, alphabet, padding)) {
        is Outcome.Success -> Outcome.Success(ByteString(decoded.value))
        is Outcome.Failure -> decoded
    }

    internal fun decodeToArray(
        text: CharSequence,
        alphabet: Base64Alphabet,
        padding: Boolean,
    ): Outcome<ByteArray, EncodingFailure> {
        val tooLong = EncodingFailure.TooLong.takeIf { text.length > MAXIMUM_TEXT_LENGTH }
        val body = bodyLength(text, padding)
        val badPadding = EncodingFailure.InvalidPadding.takeIf { body < 0 }
        val badLength = EncodingFailure.InvalidLength.takeIf { body % GROUP_CHARS == 1 }
        val failure = tooLong ?: badPadding ?: badLength ?: return decodeBody(
            text = text,
            body = body,
            alphabet = alphabet,
        )
        return Outcome.Failure(failure)
    }

    private fun decodeBody(
        text: CharSequence,
        body: Int,
        alphabet: Base64Alphabet,
    ): Outcome<ByteArray, EncodingFailure> {
        val bytes = ByteArray(body / GROUP_CHARS * GROUP_BYTES + body % GROUP_CHARS * GROUP_BYTES / GROUP_CHARS)
        val leftover = fill(text = text, body = body, alphabet = alphabet, target = bytes)
        val invalid = EncodingFailure.InvalidCharacter.takeIf { leftover < 0 }
        val failure = invalid ?: EncodingFailure.NonCanonical.takeIf { leftover > 0 }
        if (failure != null) return Outcome.Failure(failure)
        return Outcome.Success(bytes)
    }

    private fun bodyLength(text: CharSequence, padding: Boolean): Int {
        val pads = text.takeLastWhile { char -> char == PAD }.length
        val body = text.length - pads
        val expectedPads = (GROUP_CHARS - body % GROUP_CHARS) % GROUP_CHARS
        val isPaddingRight = (padding && pads == expectedPads) || (!padding && pads == 0)
        val hasInnerPad = text.subSequence(startIndex = 0, endIndex = body).contains(PAD)
        if (!isPaddingRight || hasInnerPad || pads > TWO_PADS) return -1
        return body
    }

    private fun fill(text: CharSequence, body: Int, alphabet: Base64Alphabet, target: ByteArray): Int {
        var invalid = 0
        var accumulator = 0
        var bits = 0
        var written = 0
        for (index in 0 until body) {
            val value = valueOf(text[index], alphabet)
            invalid = invalid or value
            accumulator = (accumulator shl SIX_BITS) or (value and SIX_MASK)
            bits += SIX_BITS
            if (bits >= BYTE_BITS) {
                bits -= BYTE_BITS
                target[written] = (accumulator shr bits).toByte()
                written += 1
                accumulator = accumulator and (1 shl bits) - 1
            }
        }
        if (invalid < 0) return INVALID
        return accumulator
    }

    private fun appendTail(text: StringBuilder, bytes: ByteArray, at: Int, alphabet: Base64Alphabet, padding: Boolean) {
        val rest = bytes.size - at
        val second = bytes.getOrNull(at + 1)?.let { byte -> byte.toInt() and BYTE_MASK } ?: 0
        val group = (byteAt(bytes, at) shl SHIFT_FIRST_BYTE) or (second shl BYTE_BITS)
        val chars = rest + 1
        appendChars(text = text, group = group, count = chars, alphabet = alphabet)
        if (padding) repeat(GROUP_CHARS - chars) { text.append(PAD) }
    }

    private fun appendChars(text: StringBuilder, group: Int, count: Int, alphabet: Base64Alphabet) {
        val shifts = intArrayOf(SHIFT_HIGH, SHIFT_MIDDLE, SIX_BITS, 0)
        for (position in 0 until count) text.append(charOf((group shr shifts[position]) and SIX_MASK, alphabet))
    }

    private fun byteAt(bytes: ByteArray, index: Int): Int = bytes[index].toInt() and BYTE_MASK

    private fun charOf(value: Int, alphabet: Base64Alphabet): Char {
        val upper = below(value = value, limit = UPPER_COUNT)
        val lower = below(value = value, limit = DIGIT_START) and upper.inv()
        val digit = below(value = value, limit = VALUE_62) and below(value = value, limit = DIGIT_START).inv()
        val mark62 = equal(first = value, second = VALUE_62)
        val mark63 = equal(first = value, second = VALUE_63)
        val code = ('A'.code + value and upper) or ('a'.code + value - UPPER_COUNT and lower) or
            ('0'.code + value - DIGIT_START and digit) or (symbol62(alphabet).code and mark62) or
            (symbol63(alphabet).code and mark63)
        return code.toChar()
    }

    private fun valueOf(char: Char, alphabet: Base64Alphabet): Int {
        val code = char.code
        val upper = within(value = code, low = 'A'.code, high = 'Z'.code)
        val lower = within(value = code, low = 'a'.code, high = 'z'.code)
        val digit = within(value = code, low = '0'.code, high = '9'.code)
        val mark62 = equal(first = code, second = symbol62(alphabet).code)
        val mark63 = equal(first = code, second = symbol63(alphabet).code)
        val value = (code - 'A'.code and upper) or (code - 'a'.code + UPPER_COUNT and lower) or
            (code - '0'.code + DIGIT_START and digit) or (VALUE_62 and mark62) or (VALUE_63 and mark63)
        return value or (INVALID and (upper or lower or digit or mark62 or mark63).inv())
    }

    private fun symbol62(alphabet: Base64Alphabet): Char = when (alphabet) {
        Base64Alphabet.Standard -> '+'
        Base64Alphabet.Url -> '-'
    }

    private fun symbol63(alphabet: Base64Alphabet): Char = when (alphabet) {
        Base64Alphabet.Standard -> '/'
        Base64Alphabet.Url -> '_'
    }

    private fun below(value: Int, limit: Int): Int = value - limit shr Int.SIZE_BITS - 1

    private fun within(value: Int, low: Int, high: Int): Int = (value - low or high - value).inv() shr Int.SIZE_BITS - 1

    private fun equal(first: Int, second: Int): Int = within(value = first, low = second, high = second)
}
