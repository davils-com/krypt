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

import com.davils.krypt.stream.RandomAccessSource
import kotlinx.io.bytestring.ByteString

internal class OffsetSource(private val source: RandomAccessSource, private val start: Long) : RandomAccessSource {
    override val size: Long get() = source.size - start

    override suspend fun read(offset: Long, length: Int): ByteString =
        source.read(offset = start + offset, length = length)
}
