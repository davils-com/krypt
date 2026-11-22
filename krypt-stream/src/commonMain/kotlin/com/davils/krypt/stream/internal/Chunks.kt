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

import com.davils.krypt.core.io.ByteSource
import com.davils.krypt.core.io.readFully
import kotlinx.io.bytestring.ByteString

internal class Chunks(private val source: ByteSource, private val size: Int) {
    private var pending: ByteString? = null
    private var isDone: Boolean = false

    suspend fun nextOrNull(): Pair<ByteString, Boolean>? {
        if (isDone) return null
        val current = pending ?: read()
        val following = read()
        pending = following
        isDone = following.size == 0
        return current to isDone
    }

    private suspend fun read(): ByteString {
        val buffer = ByteArray(size)
        val count = source.readFully(buffer)
        return ByteString(data = buffer, startIndex = 0, endIndex = count)
    }
}
