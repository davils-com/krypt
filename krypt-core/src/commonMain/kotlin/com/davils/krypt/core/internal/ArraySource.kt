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

package com.davils.krypt.core.internal

import com.davils.krypt.core.io.ByteSource

internal class ArraySource(private val bytes: ByteArray) : ByteSource {
    private var position = 0

    override suspend fun read(target: ByteArray, offset: Int, length: Int): Int {
        val count = minOf(a = length, b = bytes.size - position)
        if (count <= 0) return -1
        bytes.copyInto(
            destination = target,
            destinationOffset = offset,
            startIndex = position,
            endIndex = position + count,
        )
        position += count
        return count
    }
}
