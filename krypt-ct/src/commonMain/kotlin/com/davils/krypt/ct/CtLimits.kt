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

package com.davils.krypt.ct

/**
 * The limits of reading signed certificate timestamps.
 *
 * @property maximumListBytes the size of one encoded list.
 * @property maximumTimestamps how many timestamps one list holds at most.
 * @property maximumSignatureBytes the size of one signature.
 * @property maximumExtensionBytes the size of the extensions of one timestamp.
 * @constructor Checks the limits against their hard ceilings.
 * @throws IllegalArgumentException if a limit is not positive or exceeds its hard ceiling.
 * @since 1.0.0
 */
public class CtLimits(
    public val maximumListBytes: Int = DEFAULT_MAXIMUM_LIST_BYTES,
    public val maximumTimestamps: Int = DEFAULT_MAXIMUM_TIMESTAMPS,
    public val maximumSignatureBytes: Int = DEFAULT_MAXIMUM_SIGNATURE_BYTES,
    public val maximumExtensionBytes: Int = DEFAULT_MAXIMUM_EXTENSION_BYTES,
) {
    private val values: List<Int>
        get() = listOf(maximumListBytes, maximumTimestamps, maximumSignatureBytes, maximumExtensionBytes)

    init {
        require(maximumListBytes in 1..HARD_MAXIMUM_LIST_BYTES) { "A list has 1 to $HARD_MAXIMUM_LIST_BYTES bytes" }
        require(maximumTimestamps in 1..HARD_MAXIMUM_TIMESTAMPS) {
            "A list holds 1 to $HARD_MAXIMUM_TIMESTAMPS timestamps"
        }
        require(maximumSignatureBytes in 1..HARD_MAXIMUM_FIELD_BYTES) {
            "A signature has 1 to $HARD_MAXIMUM_FIELD_BYTES bytes"
        }
        require(maximumExtensionBytes in 0..HARD_MAXIMUM_FIELD_BYTES) {
            "Extensions have 0 to $HARD_MAXIMUM_FIELD_BYTES bytes"
        }
    }

    /**
     * Compares every limit.
     *
     * @param other the other object.
     * @return true if [other] has the same limits.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is CtLimits && values == other.values

    /**
     * Hashes every limit.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = values.hashCode()

    /**
     * Shows every limit.
     *
     * @return the limits as text.
     * @since 1.0.0
     */
    override fun toString(): String = "CtLimits(maximumListBytes=$maximumListBytes, " +
        "maximumTimestamps=$maximumTimestamps, maximumSignatureBytes=$maximumSignatureBytes, " +
        "maximumExtensionBytes=$maximumExtensionBytes)"

    /**
     * The defaults and the hard ceilings.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The default size of a list.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_LIST_BYTES: Int = 16_384

        /**
         * The hard ceiling of the size of a list, the most a length of two bytes can say.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_LIST_BYTES: Int = 65_535

        /**
         * The default number of timestamps of a list.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_TIMESTAMPS: Int = 16

        /**
         * The hard ceiling of the number of timestamps of a list.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_TIMESTAMPS: Int = 256

        /**
         * The default size of a signature.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_SIGNATURE_BYTES: Int = 1_024

        /**
         * The default size of the extensions of a timestamp.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_EXTENSION_BYTES: Int = 1_024

        /**
         * The hard ceiling of the size of a signature or of extensions.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_FIELD_BYTES: Int = 65_535

        /**
         * The default limits.
         *
         * @since 1.0.0
         */
        public val Default: CtLimits = CtLimits()
    }
}
