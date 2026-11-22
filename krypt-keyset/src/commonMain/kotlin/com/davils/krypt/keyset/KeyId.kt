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

package com.davils.krypt.keyset

import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.RandomSource
import com.davils.krypt.core.encoding.Hex
import kotlinx.io.bytestring.ByteString

/**
 * The id of a key in a [Keyset]: eight random bytes that every ciphertext, tag and signature of the key starts with,
 * so the key set finds the key again without trying every key.
 *
 * An id is not secret and says nothing about the key.
 *
 * @property bytes the eight bytes of the id.
 * @since 1.0.0
 */
public class KeyId private constructor(public val bytes: ByteString) : Comparable<KeyId> {
    /**
     * The id as sixteen lower case hex digits.
     *
     * @since 1.0.0
     */
    public val hex: String get() = Hex.encode(bytes)

    /**
     * Orders ids by their bytes.
     *
     * @param other the other id.
     * @return the order.
     * @since 1.0.0
     */
    override fun compareTo(other: KeyId): Int = hex.compareTo(other.hex)

    /**
     * Compares the bytes.
     *
     * @param other the other object.
     * @return true if [other] is the same id.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is KeyId && bytes == other.bytes

    /**
     * Hashes the bytes.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = bytes.hashCode()

    /**
     * Shows the id in hex.
     *
     * @return the id as text.
     * @since 1.0.0
     */
    override fun toString(): String = hex

    /**
     * Creating and reading ids.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The number of bytes of an id.
         *
         * @since 1.0.0
         */
        public const val SIZE: Int = 8

        /**
         * Returns the id of [bytes].
         *
         * @param bytes the eight bytes.
         * @return the id.
         * @throws IllegalArgumentException if [bytes] are not eight bytes.
         * @since 1.0.0
         */
        public fun of(bytes: ByteString): KeyId {
            require(bytes.size == SIZE) { "A key id has $SIZE bytes, not ${bytes.size}" }
            return KeyId(bytes)
        }

        /**
         * Reads an id from sixteen hex digits.
         *
         * @param hex the id in hex.
         * @return the id, or null if [hex] is not sixteen hex digits.
         * @since 1.0.0
         */
        public fun parseOrNull(hex: String): KeyId? {
            val bytes = Hex.decode(hex).getOrNull()
            return bytes?.takeIf { decoded -> decoded.size == SIZE }?.let { decoded -> KeyId(decoded) }
        }

        internal fun random(random: RandomSource): KeyId = KeyId(ByteString(random.bytes(SIZE)))
    }
}
