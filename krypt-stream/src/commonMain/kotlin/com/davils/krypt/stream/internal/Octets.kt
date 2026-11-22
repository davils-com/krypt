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

package com.davils.krypt.stream.internal

import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.buildByteString

private const val OCTET: Int = 0xFF
private const val BYTE_BITS: Int = 8
private const val U16_BYTES: Int = 2
private const val U32_BYTES: Int = 4

internal object Octets {
    fun concat(vararg parts: ByteString): ByteString = join(parts.asList())

    fun join(parts: List<ByteString>): ByteString = buildByteString {
        parts.forEach { part -> append(part.toByteArray()) }
    }

    fun utf8(text: String): ByteString = ByteString(text.encodeToByteArray())

    fun u16(value: Int): ByteString = unsigned(value.toLong(), U16_BYTES)

    fun u32(value: Long): ByteString = unsigned(value, U32_BYTES)

    fun unsigned(bytes: ByteArray, offset: Int, count: Int): Long {
        var value = 0L
        repeat(count) { index -> value = (value shl BYTE_BITS) or (bytes[offset + index].toLong() and OCTET.toLong()) }
        return value
    }

    private fun unsigned(value: Long, count: Int): ByteString {
        val bytes = ByteArray(count) { index -> (value shr BYTE_BITS * (count - 1 - index)).toByte() }
        return ByteString(bytes)
    }
}
