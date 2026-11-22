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

package com.davils.krypt.jose.internal

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.collection.OrderedMap
import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.jose.JoseFailure
import com.davils.krypt.jose.JoseLimits
import com.davils.krypt.jose.JsonValue

private const val END: Int = -1
private const val BYTE_MASK: Int = 0xFF
private const val SPACE: Int = 0x20
private const val TAB: Int = 0x09
private const val LINE_FEED: Int = 0x0A
private const val CARRIAGE_RETURN: Int = 0x0D
private const val QUOTE: Int = 0x22
private const val BACKSLASH: Int = 0x5C
private const val COMMA: Int = 0x2C
private const val COLON: Int = 0x3A
private const val MINUS: Int = 0x2D
private const val OPEN_BRACE: Int = 0x7B
private const val CLOSE_BRACE: Int = 0x7D
private const val OPEN_BRACKET: Int = 0x5B
private const val CLOSE_BRACKET: Int = 0x5D
private const val ZERO: Int = 0x30
private const val NINE: Int = 0x39
private const val LETTER_U: Int = 0x75
private const val ASCII_LIMIT: Int = 0x80
private const val CONTINUATION_MASK: Int = 0xC0
private const val CONTINUATION: Int = 0x80
private const val PAYLOAD_MASK: Int = 0x3F
private const val TWO_BYTE_LEAD: Int = 0xC2
private const val THREE_BYTE_LEAD: Int = 0xE0
private const val FOUR_BYTE_LEAD: Int = 0xF0
private const val LEAD_LIMIT: Int = 0xF5
private const val LEAD_BITS: Int = 0x7F
private const val SIX_BITS: Int = 6
private const val HEX_DIGITS: Int = 4
private const val HEX_BITS: Int = 4
private const val DECIMAL: Long = 10L
private const val MAXIMUM_DIGITS: Int = 16
private const val MAXIMUM_CODE_POINT: Int = 0x10FFFF
private const val SURROGATE_START: Int = 0xD800
private const val LOW_SURROGATE_START: Int = 0xDC00
private const val SURROGATE_END: Int = 0xDFFF
private const val SUPPLEMENTARY_START: Int = 0x10000

internal class JsonReader private constructor(private val bytes: ByteArray, private val limits: JoseLimits) {
    private var position: Int = 0
    private var isLimitHit: Boolean = false

    private fun document(): JsonValue {
        skipWhitespace()
        val value = value(depth = 1)
        skipWhitespace()
        require(position == bytes.size)
        return value
    }

    private fun value(depth: Int): JsonValue {
        val reader = READERS[peek()] ?: return number()
        return reader(this, depth)
    }

    private fun objectAt(depth: Int): JsonValue {
        within(depth <= limits.maximumDepth)
        position += 1
        skipWhitespace()
        val index = OrderedMap<String, JsonValue>()
        val members = ArrayList<Pair<String, JsonValue>>()
        val isEmpty = peek() == CLOSE_BRACE
        if (isEmpty) position += 1
        var isOpen = !isEmpty
        while (isOpen) {
            skipWhitespace()
            require(peek() == QUOTE)
            val name = string()
            require(name !in index)
            skipWhitespace()
            expect(COLON)
            skipWhitespace()
            val member = value(depth + 1)
            index[name] = member
            members += name to member
            within(members.size <= limits.maximumMembers)
            isOpen = separator(CLOSE_BRACE)
        }
        return JsonValue.Object(members)
    }

    private fun arrayAt(depth: Int): JsonValue {
        within(depth <= limits.maximumDepth)
        position += 1
        skipWhitespace()
        val items = ArrayList<JsonValue>()
        val isEmpty = peek() == CLOSE_BRACKET
        if (isEmpty) position += 1
        var isOpen = !isEmpty
        while (isOpen) {
            skipWhitespace()
            items += value(depth + 1)
            within(items.size <= limits.maximumMembers)
            isOpen = separator(CLOSE_BRACKET)
        }
        return JsonValue.Array(items)
    }

    private fun separator(close: Int): Boolean {
        skipWhitespace()
        val next = next()
        require(next == COMMA || next == close)
        return next == COMMA
    }

    private fun string(): String {
        expect(QUOTE)
        val text = StringBuilder()
        var byte = next()
        while (byte != QUOTE) {
            require(byte >= SPACE)
            val isEscape = byte == BACKSLASH
            if (isEscape) escape(text)
            if (!isEscape && byte < ASCII_LIMIT) text.append(byte.toChar())
            if (byte >= ASCII_LIMIT) multiByte(lead = byte, text = text)
            within(text.length <= limits.maximumStringLength)
            byte = next()
        }
        return text.toString()
    }

    private fun escape(text: StringBuilder) {
        val code = next()
        val simple = ESCAPES[code]
        if (simple != null) {
            text.append(simple)
            return
        }
        require(code == LETTER_U)
        val unit = hex()
        require(unit !in LOW_SURROGATE_START..SURROGATE_END)
        val isHigh = unit in SURROGATE_START until LOW_SURROGATE_START
        if (!isHigh) {
            require(Unicode.isCharacter(unit))
            text.append(unit.toChar())
            return
        }
        expect(BACKSLASH)
        expect(LETTER_U)
        val low = hex()
        require(low in LOW_SURROGATE_START..SURROGATE_END)
        require(Unicode.isCharacter(Unicode.pairOf(high = unit, low = low)))
        text.append(unit.toChar())
        text.append(low.toChar())
    }

    private fun hex(): Int {
        var unit = 0
        repeat(HEX_DIGITS) {
            val char = next().toChar()
            val digit = HEX.indexOf(char.lowercaseChar())
            require(digit >= 0)
            unit = unit shl HEX_BITS or digit
        }
        return unit
    }

    private fun multiByte(lead: Int, text: StringBuilder) {
        require(lead in TWO_BYTE_LEAD until LEAD_LIMIT)
        val extra = 1 + (lead >= THREE_BYTE_LEAD).compareTo(false) + (lead >= FOUR_BYTE_LEAD).compareTo(false)
        var codePoint = lead and (LEAD_BITS shr extra + 1)
        repeat(extra) {
            val continuation = next()
            require(continuation and CONTINUATION_MASK == CONTINUATION)
            codePoint = codePoint shl SIX_BITS or (continuation and PAYLOAD_MASK)
        }
        require(codePoint >= MINIMUMS[extra] && codePoint <= MAXIMUM_CODE_POINT)
        require(codePoint !in SURROGATE_START..SURROGATE_END && Unicode.isCharacter(codePoint))
        val isSupplementary = codePoint >= SUPPLEMENTARY_START
        if (isSupplementary) {
            val offset = codePoint - SUPPLEMENTARY_START
            text.append((SURROGATE_START + (offset shr SURROGATE_SHIFT)).toChar())
            text.append((LOW_SURROGATE_START + (offset and SURROGATE_MASK)).toChar())
        }
        if (!isSupplementary) text.append(codePoint.toChar())
    }

    private fun number(): JsonValue {
        val isNegative = peek() == MINUS
        if (isNegative) position += 1
        val first = next()
        require(first in ZERO..NINE)
        var magnitude = (first - ZERO).toLong()
        var digits = 1
        while (peek() in ZERO..NINE) {
            require(first != ZERO)
            magnitude = magnitude * DECIMAL + (next() - ZERO)
            digits += 1
            require(digits <= MAXIMUM_DIGITS)
        }
        require(magnitude <= JsonValue.Integer.MAXIMUM && !(isNegative && magnitude == 0L))
        val sign = 1L - 2L * isNegative.compareTo(false)
        return JsonValue.Integer(sign * magnitude)
    }

    private fun literal(word: String, value: JsonValue): JsonValue {
        for (char in word) expect(char.code)
        return value
    }

    private fun skipWhitespace() {
        while (peek() in WHITESPACE) position += 1
    }

    private fun expect(byte: Int) {
        require(next() == byte)
    }

    private fun peek(): Int = bytes.getOrNull(position)?.let { byte -> byte.toInt() and BYTE_MASK } ?: END

    private fun next(): Int {
        val byte = peek()
        position += 1
        return byte
    }

    private fun within(isWithin: Boolean) {
        isLimitHit = !isWithin
        require(isWithin)
    }

    companion object {
        private const val HEX: String = "0123456789abcdef"
        private const val SURROGATE_SHIFT: Int = 10
        private const val SURROGATE_MASK: Int = 0x3FF
        private val MINIMUMS: IntArray = intArrayOf(0, ASCII_LIMIT, 0x800, SUPPLEMENTARY_START)
        private val WHITESPACE: Set<Int> = setOf(SPACE, TAB, LINE_FEED, CARRIAGE_RETURN)
        private val ESCAPES: Map<Int, Char> = mapOf(
            QUOTE to '"',
            BACKSLASH to '\\',
            '/'.code to '/',
            'b'.code to '\b',
            'f'.code to '\u000C',
            'n'.code to '\n',
            'r'.code to '\r',
            't'.code to '\t',
        )
        private val READERS: Map<Int, JsonReader.(Int) -> JsonValue> = mapOf(
            OPEN_BRACE to { depth -> objectAt(depth) },
            OPEN_BRACKET to { depth -> arrayAt(depth) },
            QUOTE to { _ -> JsonValue.Text(string()) },
            't'.code to { _ -> literal(word = "true", value = JsonValue.Bool(true)) },
            'f'.code to { _ -> literal(word = "false", value = JsonValue.Bool(false)) },
            'n'.code to { _ -> literal(word = "null", value = JsonValue.Null) },
        )

        fun read(bytes: ByteArray, limits: JoseLimits): Outcome<JsonValue, JoseFailure> {
            if (bytes.size > limits.maximumBytes) return Outcome.Failure(JoseFailure.LimitExceeded)
            val reader = JsonReader(bytes, limits)
            return try {
                Outcome.Success(reader.document())
            } catch (ignored: IllegalArgumentException) {
                Outcome.Failure(failureOf(reader.isLimitHit))
            }
        }

        private fun failureOf(isLimitHit: Boolean): JoseFailure = when (isLimitHit) {
            true -> JoseFailure.LimitExceeded
            false -> JoseFailure.Malformed
        }

        fun readObject(bytes: ByteArray, limits: JoseLimits): Outcome<JsonValue.Object, JoseFailure> =
            when (val read = read(bytes, limits)) {
                is Outcome.Success -> objectOf(read.value)
                is Outcome.Failure -> read
            }

        private fun objectOf(value: JsonValue): Outcome<JsonValue.Object, JoseFailure> = when (value) {
            is JsonValue.Object -> Outcome.Success(value)
            is JsonValue.Array -> Outcome.Failure(JoseFailure.Malformed)
            is JsonValue.Text -> Outcome.Failure(JoseFailure.Malformed)
            is JsonValue.Integer -> Outcome.Failure(JoseFailure.Malformed)
            is JsonValue.Bool -> Outcome.Failure(JoseFailure.Malformed)
            JsonValue.Null -> Outcome.Failure(JoseFailure.Malformed)
        }
    }
}
