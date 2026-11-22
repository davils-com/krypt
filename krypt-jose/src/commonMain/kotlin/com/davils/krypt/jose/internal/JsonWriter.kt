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

package com.davils.krypt.jose.internal

import com.davils.krypt.jose.JsonValue

private const val HEX: String = "0123456789abcdef"
private const val CONTROL_LIMIT: Char = ' '
private const val NIBBLE_BITS: Int = 4
private const val NIBBLE_MASK: Int = 0xF
private const val NULL_TEXT: String = "null"

internal object JsonWriter {
    private val ESCAPES: Map<Char, String> = mapOf(
        '"' to "\\\"",
        '\\' to "\\\\",
        '\b' to "\\b",
        '\u000C' to "\\f",
        '\n' to "\\n",
        '\r' to "\\r",
        '\t' to "\\t",
    )

    fun write(value: JsonValue): String {
        val out = StringBuilder()
        append(out, value)
        return out.toString()
    }

    fun bytes(value: JsonValue): ByteArray = write(value).encodeToByteArray()

    private fun append(out: StringBuilder, value: JsonValue) {
        when (value) {
            is JsonValue.Text -> text(out, value.value)
            is JsonValue.Integer -> out.append(value.value)
            is JsonValue.Bool -> out.append(value.isTrue)
            JsonValue.Null -> out.append(NULL_TEXT)
            is JsonValue.Array -> array(out, value)
            is JsonValue.Object -> members(out, value)
        }
    }

    private fun array(out: StringBuilder, value: JsonValue.Array) {
        out.append('[')
        value.items.forEachIndexed { index, item ->
            if (index > 0) out.append(',')
            append(out, item)
        }
        out.append(']')
    }

    private fun members(out: StringBuilder, value: JsonValue.Object) {
        out.append('{')
        value.members.forEachIndexed { index, (name, member) ->
            if (index > 0) out.append(',')
            text(out, name)
            out.append(':')
            append(out, member)
        }
        out.append('}')
    }

    private fun text(out: StringBuilder, value: String) {
        out.append('"')
        for (char in value) out.append(ESCAPES[char] ?: plain(char))
        out.append('"')
    }

    private fun plain(char: Char): String {
        if (char >= CONTROL_LIMIT) return char.toString()
        val code = char.code
        return "\\u00" + HEX[code shr NIBBLE_BITS] + HEX[code and NIBBLE_MASK]
    }
}
