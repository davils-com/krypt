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

/**
 * The limits of key sets.
 *
 * @property maximumKeys how many keys a key set holds at most, destroyed keys included.
 * @property maximumEncodedBytes how large an encoded or encrypted key set may be.
 * @constructor Checks the limits against their hard ceilings.
 * @throws IllegalArgumentException if a limit is not positive or exceeds its hard ceiling.
 * @since 1.0.0
 */
public class KeysetLimits(
    public val maximumKeys: Int = DEFAULT_MAXIMUM_KEYS,
    public val maximumEncodedBytes: Int = DEFAULT_MAXIMUM_ENCODED_BYTES,
) {
    init {
        require(maximumKeys in 1..HARD_MAXIMUM_KEYS) { "A key set holds 1 to $HARD_MAXIMUM_KEYS keys" }
        require(maximumEncodedBytes in 1..HARD_MAXIMUM_ENCODED_BYTES) {
            "An encoded key set has 1 to $HARD_MAXIMUM_ENCODED_BYTES bytes"
        }
    }

    /**
     * Compares every limit.
     *
     * @param other the other object.
     * @return true if [other] has the same limits.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is KeysetLimits &&
        maximumKeys == other.maximumKeys &&
        maximumEncodedBytes == other.maximumEncodedBytes

    /**
     * Hashes every limit.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = maximumKeys * HASH_FACTOR + maximumEncodedBytes

    /**
     * Shows every limit.
     *
     * @return the limits as text.
     * @since 1.0.0
     */
    override fun toString(): String = "KeysetLimits(maximumKeys=$maximumKeys, maximumEncodedBytes=$maximumEncodedBytes)"

    /**
     * The defaults and the hard ceilings.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The default number of keys.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_KEYS: Int = 256

        /**
         * The hard ceiling of the number of keys.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_KEYS: Int = 4_096

        /**
         * The default size of an encoded key set.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_ENCODED_BYTES: Int = 1_048_576

        /**
         * The hard ceiling of the size of an encoded key set.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_ENCODED_BYTES: Int = 16_777_216

        private const val HASH_FACTOR: Int = 31

        /**
         * The default limits.
         *
         * @since 1.0.0
         */
        public val Default: KeysetLimits = KeysetLimits()
    }
}
