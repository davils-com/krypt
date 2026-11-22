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

import kotlinx.io.bytestring.ByteString

internal object Bytes {
    private const val UNSIGNED: Int = 0xff

    val Empty: ByteString = ByteString()

    fun compare(first: ByteString, second: ByteString): Int {
        val length = minOf(a = first.size, b = second.size)
        val index = (0 until length).firstOrNull { position -> first[position] != second[position] }
        val difference = index?.let { position ->
            (first[position].toInt() and UNSIGNED) - (second[position].toInt() and UNSIGNED)
        }
        return difference ?: (first.size - second.size)
    }

    fun concat(vararg parts: ByteString): ByteString {
        val total = parts.sumOf { part -> part.size }
        val bytes = ByteArray(total)
        var offset = 0
        parts.forEach { part ->
            part.copyInto(destination = bytes, destinationOffset = offset)
            offset += part.size
        }
        return ByteString(bytes)
    }

    fun leftPadded(bytes: ByteString, size: Int): ByteString = concat(ByteString(ByteArray(size - bytes.size)), bytes)

    fun xor(first: ByteString, second: ByteString): ByteString =
        ByteString(ByteArray(first.size) { index -> (first[index].toInt() xor second[index].toInt()).toByte() })
}
