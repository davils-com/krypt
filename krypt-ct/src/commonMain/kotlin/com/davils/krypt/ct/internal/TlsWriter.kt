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

import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.ByteStringBuilder

private const val BYTE_BITS: Int = 8
private const val U16_BYTES: Int = 2
private const val U24_BYTES: Int = 3
private const val U64_BYTES: Int = 8

internal class TlsWriter {
    private val builder = ByteStringBuilder()

    fun u8(value: Int) {
        number(value = value.toLong(), count = 1)
    }

    fun u16(value: Int) {
        number(value = value.toLong(), count = U16_BYTES)
    }

    fun u24(value: Int) {
        number(value = value.toLong(), count = U24_BYTES)
    }

    fun u64(value: Long) {
        number(value = value, count = U64_BYTES)
    }

    fun bytes(value: ByteString) {
        builder.append(value.toByteArray())
    }

    fun vector16(value: ByteString) {
        u16(value.size)
        bytes(value)
    }

    fun vector24(value: ByteString) {
        u24(value.size)
        bytes(value)
    }

    fun toByteString(): ByteString = builder.toByteString()

    private fun number(value: Long, count: Int) {
        for (index in count - 1 downTo 0) builder.append((value shr index * BYTE_BITS).toByte())
    }

    companion object {
        fun tls(block: TlsWriter.() -> Unit): ByteString {
            val writer = TlsWriter()
            writer.block()
            return writer.toByteString()
        }
    }
}
