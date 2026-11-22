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

package com.davils.krypt.asn1.internal

import com.davils.krypt.asn1.Tag
import kotlinx.io.bytestring.ByteString

private const val BYTE_MASK: Int = 0xFF
private const val BYTE_BITS: Int = 8
private const val ASCII_LIMIT: Int = 0x7F
private const val VISIBLE_FIRST: Int = 0x20
private const val VISIBLE_LAST: Int = 0x7E
private const val UTF16_UNIT: Int = 2
private const val UTF32_UNIT: Int = 4
private const val MAXIMUM_CODE_POINT: Int = 0x10FFFF
private const val SURROGATE_FIRST: Int = 0xD800
private const val SURROGATE_LAST: Int = 0xDFFF
private const val SUPPLEMENTARY_BASE: Int = 0x10000
private const val SURROGATE_MASK: Int = 0x3FF
private const val SURROGATE_BITS: Int = 10
private const val LOW_SURROGATE_FIRST: Int = 0xDC00
private const val PRINTABLE_SYMBOLS: String = " '()+,-./:=?"

internal object DerStrings {
    private val PRINTABLE: BooleanArray = BooleanArray(ASCII_LIMIT + 1) { code ->
        val char = code.toChar()
        char.isLetterOrDigit() || char in PRINTABLE_SYMBOLS
    }
    private val DECODERS: Map<Tag, (ByteArray) -> String?> = mapOf(
        Tag.Utf8String to { bytes -> utf8OrNull(bytes) },
        Tag.PrintableString to { bytes ->
            asciiOrNull(
                bytes,
            )?.takeIf { text -> text.all { char -> isPrintable(char) } }
        },
        Tag.Ia5String to { bytes -> asciiOrNull(bytes) },
        Tag.NumericString to { bytes -> asciiOrNull(bytes)?.takeIf { text -> text.all { char -> isNumeric(char) } } },
        Tag.VisibleString to { bytes -> asciiOrNull(bytes)?.takeIf { text -> isVisible(text) } },
        Tag.TeletexString to { bytes -> latin1(bytes) },
        Tag.BmpString to { bytes -> utf16OrNull(bytes) },
        Tag.UniversalString to { bytes -> utf32OrNull(bytes) },
    )

    fun decodeOrNull(tag: Tag, content: ByteString): String? = DECODERS[tag]?.invoke(content.toByteArray())

    private fun isNumeric(char: Char): Boolean = char in '0'..'9' || char == ' '

    private fun latin1(bytes: ByteArray): String =
        CharArray(bytes.size) { index -> (bytes[index].toInt() and BYTE_MASK).toChar() }.concatToString()

    fun isPrintable(char: Char): Boolean = char.code < PRINTABLE.size && PRINTABLE[char.code]

    fun isAscii(text: String): Boolean = text.all { char -> char.code <= ASCII_LIMIT }

    fun isVisible(text: String): Boolean = text.all { char -> char.code in VISIBLE_FIRST..VISIBLE_LAST }

    private fun utf8OrNull(bytes: ByteArray): String? = try {
        bytes.decodeToString(throwOnInvalidSequence = true)
    } catch (_: CharacterCodingException) {
        null
    }

    private fun asciiOrNull(bytes: ByteArray): String? {
        val isAscii = bytes.all { byte -> byte >= 0 }
        return bytes.takeIf { isAscii }?.decodeToString()
    }

    private fun utf16OrNull(bytes: ByteArray): String? {
        val units = CharArray(bytes.size / UTF16_UNIT) { index ->
            val high = bytes[index * UTF16_UNIT].toInt() and BYTE_MASK
            (high shl BYTE_BITS or (bytes[index * UTF16_UNIT + 1].toInt() and BYTE_MASK)).toChar()
        }
        val text = units.concatToString()
        val isWellFormed = bytes.size % UTF16_UNIT == 0 && isPaired(text)
        return text.takeIf { isWellFormed }
    }

    private fun utf32OrNull(bytes: ByteArray): String? {
        val codePoints = (0 until bytes.size / UTF32_UNIT).map { index -> codePointAt(bytes, index * UTF32_UNIT) }
        val isValid = bytes.size % UTF32_UNIT == 0 && codePoints.all { point -> isScalar(point) }
        val text = StringBuilder()
        codePoints.filter { point -> isScalar(point) }.forEach { point -> appendCodePoint(text, point) }
        return text.toString().takeIf { isValid }
    }

    private fun codePointAt(bytes: ByteArray, at: Int): Int = (0 until UTF32_UNIT).fold(
        0,
    ) { value, offset -> value shl BYTE_BITS or (bytes[at + offset].toInt() and BYTE_MASK) }

    private fun isScalar(point: Int): Boolean =
        point in 0..MAXIMUM_CODE_POINT && point !in SURROGATE_FIRST..SURROGATE_LAST

    private fun appendCodePoint(text: StringBuilder, point: Int) {
        val isSupplementary = point > Char.MAX_VALUE.code
        val units = listOf((point and Char.MAX_VALUE.code).toChar().toString(), supplementary(point))
        text.append(units[isSupplementary.compareTo(false)])
    }

    private fun supplementary(point: Int): String {
        val offset = point - SUPPLEMENTARY_BASE
        val high = (SURROGATE_FIRST + (offset shr SURROGATE_BITS)).toChar()
        val low = (LOW_SURROGATE_FIRST + (offset and SURROGATE_MASK)).toChar()
        return charArrayOf(high, low).concatToString()
    }

    private fun isPaired(text: String): Boolean {
        var index = 0
        var isPaired = true
        while (index < text.length) {
            val char = text[index]
            val next = text.getOrNull(index + 1)
            val isPair = char.isHighSurrogate() && next != null && next.isLowSurrogate()
            isPaired = isPaired && (isPair || !char.isSurrogate())
            index += 1 + isPair.compareTo(false)
        }
        return isPaired
    }
}
