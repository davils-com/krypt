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

package com.davils.krypt.stream

import kotlinx.io.bytestring.ByteString

/**
 * Returns these bytes as a [RandomAccessSource].
 *
 * @receiver the bytes.
 * @return the source.
 * @since 1.0.0
 */
public fun ByteString.asRandomAccessSource(): RandomAccessSource {
    val bytes = this
    return object : RandomAccessSource {
        override val size: Long get() = bytes.size.toLong()

        override suspend fun read(offset: Long, length: Int): ByteString {
            val start = offset.coerceIn(minimumValue = 0L, maximumValue = size).toInt()
            val end = (offset + length).coerceIn(minimumValue = start.toLong(), maximumValue = size).toInt()
            return bytes.substring(startIndex = start, endIndex = end)
        }
    }
}
