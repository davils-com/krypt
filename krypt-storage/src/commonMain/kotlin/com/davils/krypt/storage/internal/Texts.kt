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

package com.davils.krypt.storage.internal

import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.encoding.Base64
import com.davils.krypt.core.encoding.Base64Alphabet
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.buildByteString

private const val OCTET: Int = 0xFF
private const val BYTE_BITS: Int = 8
private const val U32_BYTES: Int = 4
private const val U64_BYTES: Int = 8

internal object Texts {
    fun utf8(text: String): ByteString = ByteString(text.encodeToByteArray())

    fun concat(vararg parts: ByteString): ByteString = buildByteString {
        parts.forEach { part -> append(part.toByteArray()) }
    }

    fun framed(parts: List<String>): ByteString = buildByteString {
        parts.forEach { part ->
            val bytes = part.encodeToByteArray()
            append(unsigned(value = bytes.size.toLong(), count = U32_BYTES).toByteArray())
            append(bytes)
        }
    }

    fun u32(value: Long): ByteString = unsigned(value = value, count = U32_BYTES)

    fun u64(value: Long): ByteString = unsigned(value = value, count = U64_BYTES)

    fun readU32(bytes: ByteString, offset: Int): Long {
        var value = 0L
        repeat(
            U32_BYTES,
        ) { index -> value = (value shl BYTE_BITS) or (bytes[offset + index].toLong() and OCTET.toLong()) }
        return value
    }

    fun base64Url(bytes: ByteString): String = Base64.encode(
        bytes = bytes,
        alphabet = Base64Alphabet.Url,
        padding = false,
    )

    fun fromBase64Url(text: String): ByteString? =
        Base64.decode(text = text, alphabet = Base64Alphabet.Url, padding = false).getOrNull()

    private fun unsigned(value: Long, count: Int): ByteString {
        val bytes = ByteArray(count) { index -> (value shr BYTE_BITS * (count - 1 - index)).toByte() }
        return ByteString(bytes)
    }
}
