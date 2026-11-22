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

import com.davils.krypt.stream.internal.Octets
import com.davils.krypt.stream.internal.Unlocked
import kotlinx.io.bytestring.ByteString

/**
 * Reads the plaintext of a container at any offset, decrypting only the segments it needs.
 *
 * Every segment is authenticated on its own and bound to its position and to whether it is the last one, so a
 * segment moved, swapped or cut off is refused. The reader holds the keys of the container until it is [close]d; it
 * is not safe to use from several coroutines at once.
 *
 * @property segmentSize the size of a segment of plaintext.
 * @property segments the number of segments.
 * @property plaintextBytes the size of the plaintext.
 * @since 1.0.0
 */
public class ContainerReader internal constructor(
    private val source: RandomAccessSource,
    private val unlocked: Unlocked,
    private val dataStart: Long,
    public val segmentSize: Int,
    public val segments: Long,
    public val plaintextBytes: Long,
) {
    private val chunkSize: Long = segmentSize.toLong() + unlocked.cipher.tagBytes

    /**
     * Decrypts the segment [index].
     *
     * @param index the segment, from 0.
     * @return the plaintext of the segment, or null if the segment was changed.
     * @throws IllegalArgumentException if [index] is out of range.
     * @throws IllegalStateException if the reader is closed.
     * @since 1.0.0
     */
    public suspend fun segment(index: Long): ByteString? {
        require(index in 0 until segments) { "The container has segments 0 to ${segments - 1}, not $index" }
        check(!unlocked.schedule.payload.isDestroyed) { "The reader is closed" }
        val offset = dataStart + index * chunkSize
        val length = (source.size - offset).coerceAtMost(chunkSize).toInt()
        val ciphertext = source.read(offset = offset, length = length)
        return unlocked.cipher.open(index = index, isLast = index == segments - 1, ciphertext = ciphertext)
    }

    /**
     * Decrypts [length] bytes of plaintext at [offset].
     *
     * @param offset where to start in the plaintext.
     * @param length how many bytes.
     * @return the plaintext, or null if a segment it touches was changed.
     * @throws IllegalArgumentException if the range is not within the plaintext.
     * @throws IllegalStateException if the reader is closed.
     * @since 1.0.0
     */
    public suspend fun read(offset: Long, length: Int): ByteString? {
        require(offset >= 0 && length >= 0 && offset + length <= plaintextBytes) {
            "The range $offset+$length is not within the $plaintextBytes bytes of plaintext"
        }
        val first = offset / segmentSize
        val last = ((offset + length - 1) / segmentSize).coerceAtLeast(first)
        val parts = mutableListOf<ByteString>()
        var index = first
        while (index <= last && length > 0) {
            parts += segment(index) ?: return null
            index++
        }
        val joined = Octets.join(parts)
        val start = (offset - first * segmentSize).toInt()
        return joined.substring(
            startIndex = start.coerceAtMost(joined.size),
            endIndex = (start + length).coerceAtMost(joined.size),
        )
    }

    /**
     * Wipes the keys of the container; the reader reads nothing afterwards.
     *
     * @since 1.0.0
     */
    public fun close() {
        unlocked.destroy()
    }

    /**
     * Shows the sizes.
     *
     * @return the reader as text.
     * @since 1.0.0
     */
    override fun toString(): String = "ContainerReader(segments=$segments, plaintextBytes=$plaintextBytes)"
}
