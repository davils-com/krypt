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

package com.davils.krypt.core.io

import com.davils.krypt.core.internal.ArraySource
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.io.bytestring.ByteString

/**
 * Reads [bytes] as a source.
 *
 * @receiver the bytes, which the source reads without copying; they must not change while it is read.
 * @return the source.
 * @since 1.0.0
 */
public fun ByteArray.asByteSource(): ByteSource = ArraySource(this)

/**
 * Reads [bytes] as a source.
 *
 * @receiver the bytes.
 * @return the source.
 * @since 1.0.0
 */
public fun ByteString.asByteSource(): ByteSource = toByteArray().asByteSource()

/**
 * Reads until [length] bytes are in [target] or the source ends.
 *
 * @receiver the source.
 * @param target the array to read into.
 * @param offset where the bytes go.
 * @param length the number of bytes wanted.
 * @return the number of bytes read, less than [length] only at the end of the source.
 * @since 1.0.0
 */
public suspend fun ByteSource.readFully(target: ByteArray, offset: Int = 0, length: Int = target.size - offset): Int {
    var filled = 0
    var last = 0
    while (filled < length && last >= 0) {
        last = read(target = target, offset = offset + filled, length = length - filled)
        if (last > 0) filled += last
    }
    return filled
}

/**
 * Reads the whole source into memory.
 *
 * @receiver the source.
 * @param maximum the most bytes to read, at least 0.
 * @return the bytes.
 * @throws ByteLimitException if the source holds more than [maximum] bytes.
 * @since 1.0.0
 */
public suspend fun ByteSource.readAll(maximum: Int): ByteString {
    val sink = BufferSink(maximum)
    val chunk = ByteArray(minOf(a = maximum, b = DEFAULT_CHUNK - 1) + 1)
    var count = read(target = chunk, offset = 0, length = chunk.size)
    while (count >= 0) {
        sink.append(source = chunk, offset = 0, length = count)
        count = read(target = chunk, offset = 0, length = chunk.size)
    }
    return sink.toByteString()
}

/**
 * Turns the source into a cold flow of chunks of at most [chunkSize] bytes.
 *
 * @receiver the source, which the flow reads once.
 * @param chunkSize the largest chunk, at least 1.
 * @return the flow.
 * @since 1.0.0
 */
public fun ByteSource.asFlow(chunkSize: Int = DEFAULT_CHUNK): Flow<ByteString> {
    require(chunkSize >= 1) { "A chunk needs at least one byte, not $chunkSize" }
    val source = this
    return flow {
        val chunk = ByteArray(chunkSize)
        var count = source.read(target = chunk, offset = 0, length = chunkSize)
        while (count >= 0) {
            emit(ByteString(data = chunk, startIndex = 0, endIndex = count))
            count = source.read(target = chunk, offset = 0, length = chunkSize)
        }
    }
}

/**
 * The default size of a chunk krypt reads at once: 64 KiB.
 *
 * @since 1.0.0
 */
public const val DEFAULT_CHUNK: Int = 64 * 1_024
