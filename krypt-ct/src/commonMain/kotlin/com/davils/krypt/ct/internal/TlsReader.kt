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

package com.davils.krypt.ct.internal

import com.davils.krypt.ct.CtFailure
import kotlinx.io.bytestring.ByteString

private const val BYTE_MASK: Int = 0xFF
private const val BYTE_BITS: Int = 8
private const val U16_BYTES: Int = 2
private const val U64_BYTES: Int = 8

internal class TlsReader(private val input: ByteString) {
    private var position: Int = 0

    val isExhausted: Boolean get() = position == input.size

    fun u8(): Int = number(1).toInt()

    fun u16(): Int = number(U16_BYTES).toInt()

    fun u64(): Long = number(U64_BYTES)

    fun bytes(count: Int): ByteString {
        if (count > input.size - position) throw TlsRefusal(CtFailure.Malformed)
        val bytes = input.substring(startIndex = position, endIndex = position + count)
        position += count
        return bytes
    }

    fun vector16(maximum: Int): ByteString {
        val length = u16()
        if (length > maximum) throw TlsRefusal(CtFailure.LimitExceeded)
        return bytes(length)
    }

    fun finish() {
        if (!isExhausted) throw TlsRefusal(CtFailure.Malformed)
    }

    private fun number(count: Int): Long {
        val bytes = bytes(count)
        return (0 until count).fold(0L) { value, index ->
            (value shl BYTE_BITS) or (bytes[index].toLong() and BYTE_MASK.toLong())
        }
    }
}
