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

package com.davils.krypt.storage.record

import com.davils.krypt.keyset.KeysetMac
import com.davils.krypt.storage.internal.Texts
import kotlinx.io.bytestring.ByteString

private const val LABEL: String = "krypt blind index v1"
private const val PREFIX_BYTES: Int = 9
private const val MINIMUM_BYTES: Int = 8
private const val MAXIMUM_BYTES: Int = 32
private const val DEFAULT_BYTES: Int = 16

/**
 * A blind index for searching encrypted fields for equal values: a MAC of the normalised value, truncated to [size]
 * bytes and prefixed with the id of its key.
 *
 * A blind index leaks which records hold equal values and how often a value occurs; a short [size] makes values
 * collide on purpose and so hides more but returns false matches, which the application filters out after
 * decrypting. Use it only for columns where this leakage is acceptable, and keep one index per [column], so that
 * values of two columns cannot be matched. During a rotation of the key set, search with every one of [candidates].
 *
 * The object is safe to share between threads.
 *
 * @property mac the key set of the index.
 * @property column the column the index is for.
 * @property size the bytes of the MAC that are kept, 8 to 32; 16 by default.
 * @param normalize maps a value to the form that is compared, such as lower case for e-mail addresses.
 * @constructor Indexes [column] with [mac].
 * @throws IllegalArgumentException if [size] is out of range or [column] is empty.
 * @since 1.0.0
 */
public class BlindIndex(
    public val mac: KeysetMac,
    public val column: String,
    public val size: Int = DEFAULT_BYTES,
    private val normalize: (String) -> String = { value -> value },
) {
    init {
        require(size in MINIMUM_BYTES..MAXIMUM_BYTES) { "A blind index keeps $MINIMUM_BYTES to $MAXIMUM_BYTES bytes" }
        require(column.isNotEmpty()) { "A blind index names its column" }
    }

    /**
     * Returns the index of [value] under the primary key, to store with the record.
     *
     * @param value the value.
     * @return the index in base64url without padding.
     * @since 1.0.0
     */
    public suspend fun of(value: String): String = textOf(mac.compute(dataOf(value)))

    /**
     * Returns the indexes of [value] under every enabled key, primary first, to search with during a rotation.
     *
     * @param value the value.
     * @return the indexes in base64url without padding.
     * @since 1.0.0
     */
    public suspend fun candidates(value: String): List<String> =
        mac.computeAll(dataOf(value)).map { tag -> textOf(tag) }

    /**
     * Shows the column and the size.
     *
     * @return the index as text.
     * @since 1.0.0
     */
    override fun toString(): String = "BlindIndex(column=${column.length} characters, size=$size)"

    private fun dataOf(value: String): ByteString = Texts.framed(listOf(LABEL, column, normalize(value)))

    private fun textOf(tag: ByteString): String = Texts.base64Url(
        tag.substring(startIndex = 0, endIndex = PREFIX_BYTES + size),
    )
}
