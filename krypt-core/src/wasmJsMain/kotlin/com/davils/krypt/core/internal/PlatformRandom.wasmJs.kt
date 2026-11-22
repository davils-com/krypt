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

package com.davils.krypt.core.internal

private const val INT_BYTES: Int = 4
private const val BYTE_BITS: Int = 8

internal actual fun fillSecurely(target: ByteArray) {
    var index = 0
    while (index < target.size) {
        var value = randomInt()
        val end = minOf(index + INT_BYTES, target.size)
        while (index < end) {
            target[index] = value.toByte()
            value = value ushr BYTE_BITS
            index += 1
        }
    }
}

private fun randomInt(): Int = js("globalThis.crypto.getRandomValues(new Int32Array(1))[0]")
