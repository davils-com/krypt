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

import kotlinx.io.bytestring.ByteString

private const val INITIAL_CAPACITY: Int = 256

/**
 * A sink that collects what is written into memory, up to [maximum] bytes.
 *
 * A buffer sink is not thread safe.
 *
 * @property maximum the most bytes the sink takes, at least 0.
 * @since 1.0.0
 */
public class BufferSink(public val maximum: Int) : ByteSink {
    init {
        require(maximum >= 0) { "The limit of a buffer sink cannot be negative: $maximum" }
    }

    private var buffer = ByteArray(minOf(a = maximum, b = INITIAL_CAPACITY))

    /**
     * The number of bytes written.
     *
     * @since 1.0.0
     */
    public var size: Int = 0
        private set

    /**
     * Appends [length] bytes of [source].
     *
     * @param source the bytes.
     * @param offset where the bytes start.
     * @param length the number of bytes.
     * @throws ByteLimitException if the sink would hold more than [maximum] bytes; nothing is appended then.
     * @since 1.0.0
     */
    override suspend fun write(source: ByteArray, offset: Int, length: Int) {
        append(source = source, offset = offset, length = length)
    }

    /**
     * Appends [length] bytes of [source] without suspending.
     *
     * @param source the bytes.
     * @param offset where the bytes start.
     * @param length the number of bytes.
     * @throws ByteLimitException if the sink would hold more than [maximum] bytes; nothing is appended then.
     * @since 1.0.0
     */
    public fun append(source: ByteArray, offset: Int = 0, length: Int = source.size) {
        if (length > maximum - size) throw ByteLimitException(maximum.toLong())
        if (size + length > buffer.size) {
            buffer = buffer.copyOf(
                minOf(a = maximum, b = maxOf(a = size + length, b = buffer.size * 2)),
            )
        }
        source.copyInto(destination = buffer, destinationOffset = size, startIndex = offset, endIndex = offset + length)
        size += length
    }

    /**
     * Returns what was written so far.
     *
     * @return the bytes.
     * @since 1.0.0
     */
    public fun toByteString(): ByteString = ByteString(data = buffer, startIndex = 0, endIndex = size)

    /**
     * Overwrites the collected bytes with zeros and empties the sink, for a sink that collected a secret.
     *
     * @since 1.0.0
     */
    public fun wipe() {
        buffer.fill(0)
        size = 0
    }

    /**
     * Shows the size and the limit, never the bytes.
     *
     * @return the sink as text.
     * @since 1.0.0
     */
    override fun toString(): String = "BufferSink(size=$size, maximum=$maximum)"
}
