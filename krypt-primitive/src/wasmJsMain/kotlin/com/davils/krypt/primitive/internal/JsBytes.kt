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

@file:OptIn(ExperimentalWasmJsInterop::class)

package com.davils.krypt.primitive.internal

private const val INT_BYTES: Int = 4
private const val BYTE_BITS: Int = 8
private const val BYTE_MASK: Int = 0xFF

internal object JsBytes {
    fun toJs(bytes: ByteArray): JsAny {
        val target = newBytes(bytes.size)
        var index = 0
        while (index < bytes.size) {
            val count = minOf(a = INT_BYTES, b = bytes.size - index)
            var value = 0
            for (offset in 0 until count) {
                value =
                    value or ((bytes[index + offset].toInt() and BYTE_MASK) shl offset * BYTE_BITS)
            }
            putInt(b = target, at = index, v = value, n = count)
            index += count
        }
        return target
    }

    fun fromJs(buffer: JsAny): ByteArray {
        val view = viewOf(buffer)
        val size = byteLength(buffer)
        val bytes = ByteArray(size)
        var index = 0
        while (index < size) {
            val value = intAt(b = view, i = index)
            val count = minOf(a = INT_BYTES, b = size - index)
            for (offset in 0 until count) bytes[index + offset] = (value shr offset * BYTE_BITS).toByte()
            index += count
        }
        wipe(view)
        return bytes
    }

    inline fun <R> withJs(bytes: ByteArray, block: (JsAny) -> R): R {
        val js = toJs(bytes)
        try {
            return block(js)
        } finally {
            wipe(js)
        }
    }
}
