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

package com.davils.krypt.ocsp

/**
 * The limits of reading OCSP requests and responses.
 *
 * @property maximumBytes the size of one request or response.
 * @property maximumEntries how many certificates one request or response names.
 * @property maximumCertificates how many certificates a response carries.
 * @property maximumExtensions how many extensions a request, a response or one of their entries carries.
 * @constructor Checks the limits against their hard ceilings.
 * @throws IllegalArgumentException if a limit is not positive or exceeds its hard ceiling.
 * @since 1.0.0
 */
public class OcspLimits(
    public val maximumBytes: Int = DEFAULT_MAXIMUM_BYTES,
    public val maximumEntries: Int = DEFAULT_MAXIMUM_ENTRIES,
    public val maximumCertificates: Int = DEFAULT_MAXIMUM_CERTIFICATES,
    public val maximumExtensions: Int = DEFAULT_MAXIMUM_EXTENSIONS,
) {
    private val values: List<Int>
        get() = listOf(maximumBytes, maximumEntries, maximumCertificates, maximumExtensions)

    init {
        require(maximumBytes in 1..HARD_MAXIMUM_BYTES) { "An OCSP message has 1 to $HARD_MAXIMUM_BYTES bytes" }
        require(maximumEntries in 1..HARD_MAXIMUM_ENTRIES) {
            "An OCSP message names 1 to $HARD_MAXIMUM_ENTRIES certificates"
        }
        require(maximumCertificates in 1..HARD_MAXIMUM_CERTIFICATES) {
            "A response carries 1 to $HARD_MAXIMUM_CERTIFICATES certificates"
        }
        require(maximumExtensions in 1..HARD_MAXIMUM_EXTENSIONS) {
            "An OCSP message carries 1 to $HARD_MAXIMUM_EXTENSIONS extensions"
        }
    }

    /**
     * Compares every limit.
     *
     * @param other the other object.
     * @return true if [other] has the same limits.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is OcspLimits && values == other.values

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
    override fun toString(): String = "OcspLimits(maximumBytes=$maximumBytes, maximumEntries=$maximumEntries, " +
        "maximumCertificates=$maximumCertificates, maximumExtensions=$maximumExtensions)"

    /**
     * The defaults and the hard ceilings.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The default size of a message.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_BYTES: Int = 65_536

        /**
         * The hard ceiling of the size of a message.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_BYTES: Int = 16_777_216

        /**
         * The default number of certificates a message names.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_ENTRIES: Int = 64

        /**
         * The hard ceiling of the number of certificates a message names.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_ENTRIES: Int = 4_096

        /**
         * The default number of certificates in a response.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_CERTIFICATES: Int = 8

        /**
         * The hard ceiling of the number of certificates in a response.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_CERTIFICATES: Int = 64

        /**
         * The default number of extensions.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_EXTENSIONS: Int = 16

        /**
         * The hard ceiling of the number of extensions.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_EXTENSIONS: Int = 256

        /**
         * The default limits.
         *
         * @since 1.0.0
         */
        public val Default: OcspLimits = OcspLimits()
    }
}
