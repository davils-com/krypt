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

package com.davils.krypt.cose.internal

import com.davils.krypt.cose.cbor.CborItem
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.ByteStringBuilder
import kotlinx.io.bytestring.append

internal class CborWriter {
    private val builder = ByteStringBuilder()

    fun head(major: Int, argument: ULong) {
        val size = LIMITS.indexOfFirst { limit -> argument <= limit }
        val info = listOf(argument.toInt(), ONE_BYTE, TWO_BYTES, FOUR_BYTES, EIGHT_BYTES)[size]
        builder.append(((major shl MAJOR_SHIFT) or info).toByte())
        val length = WIDTHS[size]
        for (index in length - 1 downTo 0) {
            builder.append((argument shr index * Byte.SIZE_BITS).toByte())
        }
    }

    fun raw(bytes: ByteString) {
        builder.append(bytes)
    }

    fun raw(bytes: ByteArray) {
        builder.append(bytes)
    }

    fun toByteString(): ByteString = builder.toByteString()

    companion object {
        private const val MAJOR_SHIFT: Int = 5
        private const val ONE_BYTE: Int = 24
        private const val TWO_BYTES: Int = 25
        private const val FOUR_BYTES: Int = 26
        private const val EIGHT_BYTES: Int = 27
        private val LIMITS: List<ULong> = listOf(23UL, 0xFFUL, 0xFFFFUL, 0xFFFF_FFFFUL, ULong.MAX_VALUE)
        private val WIDTHS: List<Int> = listOf(0, 1, 2, 4, 8)

        fun encode(item: CborItem): ByteString {
            val writer = CborWriter()
            item.write(writer)
            return writer.toByteString()
        }
    }
}
