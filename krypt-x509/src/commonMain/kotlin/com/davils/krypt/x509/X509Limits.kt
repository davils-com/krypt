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

package com.davils.krypt.x509

/**
 * The limits of reading X.509 structures and of building paths.
 *
 * @property maximumBytes the size of one certificate, request or revocation list.
 * @property maximumExtensions how many extensions a structure has at most.
 * @property maximumNames how many names a name or an extension holds at most.
 * @property maximumRevokedEntries how many entries a revocation list holds at most.
 * @property maximumPathLength how many certificates a path has at most, the anchor not counted.
 * @property maximumPathAttempts how many candidate issuers path building tries at most.
 * @constructor Checks the limits against their hard ceilings.
 * @throws IllegalArgumentException if a limit is not positive or exceeds its hard ceiling.
 * @since 1.0.0
 */
public class X509Limits(
    public val maximumBytes: Int = DEFAULT_MAXIMUM_BYTES,
    public val maximumExtensions: Int = DEFAULT_MAXIMUM_EXTENSIONS,
    public val maximumNames: Int = DEFAULT_MAXIMUM_NAMES,
    public val maximumRevokedEntries: Int = DEFAULT_MAXIMUM_REVOKED_ENTRIES,
    public val maximumPathLength: Int = DEFAULT_MAXIMUM_PATH_LENGTH,
    public val maximumPathAttempts: Int = DEFAULT_MAXIMUM_PATH_ATTEMPTS,
) {
    private val values: List<Int>
        get() = listOf(
            maximumBytes,
            maximumExtensions,
            maximumNames,
            maximumRevokedEntries,
            maximumPathLength,
            maximumPathAttempts,
        )

    init {
        require(maximumBytes in 1..HARD_MAXIMUM_BYTES) { "A structure has 1 to $HARD_MAXIMUM_BYTES bytes" }
        require(maximumExtensions in 1..HARD_MAXIMUM_EXTENSIONS) {
            "A structure has 1 to $HARD_MAXIMUM_EXTENSIONS extensions"
        }
        require(maximumNames in 1..HARD_MAXIMUM_NAMES) { "A name has 1 to $HARD_MAXIMUM_NAMES parts" }
        require(maximumRevokedEntries in 1..HARD_MAXIMUM_REVOKED_ENTRIES) {
            "A revocation list has 1 to $HARD_MAXIMUM_REVOKED_ENTRIES entries"
        }
        require(maximumPathLength in 1..HARD_MAXIMUM_PATH_LENGTH) {
            "A path has 1 to $HARD_MAXIMUM_PATH_LENGTH certificates"
        }
        require(maximumPathAttempts in 1..HARD_MAXIMUM_PATH_ATTEMPTS) {
            "Path building tries 1 to $HARD_MAXIMUM_PATH_ATTEMPTS issuers"
        }
    }

    /**
     * Compares every limit.
     *
     * @param other the other object.
     * @return true if [other] has the same limits.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is X509Limits && values == other.values

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
    override fun toString(): String = "X509Limits(maximumBytes=$maximumBytes, maximumExtensions=$maximumExtensions, " +
        "maximumNames=$maximumNames, maximumRevokedEntries=$maximumRevokedEntries, " +
        "maximumPathLength=$maximumPathLength, maximumPathAttempts=$maximumPathAttempts)"

    /**
     * The defaults and the hard ceilings.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The default size of a structure.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_BYTES: Int = 65_536

        /**
         * The hard ceiling of the size of a structure; revocation lists can be large.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_BYTES: Int = 268_435_456

        /**
         * The default number of extensions.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_EXTENSIONS: Int = 64

        /**
         * The hard ceiling of the number of extensions.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_EXTENSIONS: Int = 1_024

        /**
         * The default number of parts of a name.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_NAMES: Int = 1_024

        /**
         * The hard ceiling of the number of parts of a name.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_NAMES: Int = 65_536

        /**
         * The default number of entries of a revocation list.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_REVOKED_ENTRIES: Int = 1_000_000

        /**
         * The hard ceiling of the number of entries of a revocation list.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_REVOKED_ENTRIES: Int = 16_000_000

        /**
         * The default length of a path.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_PATH_LENGTH: Int = 10

        /**
         * The hard ceiling of the length of a path.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_PATH_LENGTH: Int = 64

        /**
         * The default number of issuers path building tries.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_PATH_ATTEMPTS: Int = 256

        /**
         * The hard ceiling of the number of issuers path building tries.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_PATH_ATTEMPTS: Int = 65_536

        /**
         * The default limits.
         *
         * @since 1.0.0
         */
        public val Default: X509Limits = X509Limits()
    }
}
