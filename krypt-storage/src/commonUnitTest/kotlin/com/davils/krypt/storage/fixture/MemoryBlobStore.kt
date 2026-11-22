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

package com.davils.krypt.storage.fixture

import com.davils.krypt.core.io.BufferSink
import com.davils.krypt.core.io.ByteSink
import com.davils.krypt.storage.blob.BlobStore
import com.davils.krypt.stream.RandomAccessSource
import com.davils.krypt.stream.asRandomAccessSource
import kotlinx.io.bytestring.ByteString

internal class MemoryBlobStore : BlobStore {
    val objects: MutableMap<String, ByteString> = mutableMapOf()

    override suspend fun write(key: String, content: suspend (ByteSink) -> Unit) {
        val sink = BufferSink(Int.MAX_VALUE)
        content(sink)
        objects[key] = sink.toByteString()
    }

    override suspend fun open(key: String): RandomAccessSource? = objects[key]?.asRandomAccessSource()

    override suspend fun delete(key: String): Boolean = objects.remove(key) != null
}
