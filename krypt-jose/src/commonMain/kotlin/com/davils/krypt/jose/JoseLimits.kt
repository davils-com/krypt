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

package com.davils.krypt.jose

/**
 * The limits every JOSE decoder checks before it does any work, each under a hard ceiling.
 *
 * @property maximumBytes the size of a serialization, a JSON document or a decoded part in bytes.
 * @property maximumDepth the nesting of JSON arrays and objects.
 * @property maximumMembers the members of one JSON object and the elements of one JSON array.
 * @property maximumStringLength the length of one JSON string in UTF-16 code units.
 * @property maximumRecipients the signatures of a JWS and the recipients of a JWE.
 * @property maximumCertificates the certificates of an `x5c` chain.
 * @property maximumKeys the keys of a JWK set.
 * @property maximumIterations the PBKDF2 iterations of PBES2 that decryption accepts, below the ceiling of the
 *   crypto policy as well.
 * @throws IllegalArgumentException if a limit is below 1 or above its hard ceiling.
 * @since 1.0.0
 */
public class JoseLimits(
    public val maximumBytes: Int = DEFAULT_MAXIMUM_BYTES,
    public val maximumDepth: Int = DEFAULT_MAXIMUM_DEPTH,
    public val maximumMembers: Int = DEFAULT_MAXIMUM_MEMBERS,
    public val maximumStringLength: Int = DEFAULT_MAXIMUM_STRING_LENGTH,
    public val maximumRecipients: Int = DEFAULT_MAXIMUM_RECIPIENTS,
    public val maximumCertificates: Int = DEFAULT_MAXIMUM_CERTIFICATES,
    public val maximumKeys: Int = DEFAULT_MAXIMUM_KEYS,
    public val maximumIterations: Int = DEFAULT_MAXIMUM_ITERATIONS,
) {
    private val values: List<Int>
        get() = listOf(
            maximumBytes,
            maximumDepth,
            maximumMembers,
            maximumStringLength,
            maximumRecipients,
            maximumCertificates,
            maximumKeys,
            maximumIterations,
        )

    init {
        require(maximumBytes in 1..HARD_MAXIMUM_BYTES) { "A serialization has 1 to $HARD_MAXIMUM_BYTES bytes" }
        require(maximumDepth in 1..HARD_MAXIMUM_DEPTH) { "JSON nests 1 to $HARD_MAXIMUM_DEPTH levels" }
        require(maximumMembers in 1..HARD_MAXIMUM_MEMBERS) { "A JSON object has 1 to $HARD_MAXIMUM_MEMBERS members" }
        require(maximumStringLength in 1..HARD_MAXIMUM_STRING_LENGTH) {
            "A JSON string has 1 to $HARD_MAXIMUM_STRING_LENGTH characters"
        }
        require(maximumRecipients in 1..HARD_MAXIMUM_RECIPIENTS) {
            "A message has 1 to $HARD_MAXIMUM_RECIPIENTS signatures or recipients"
        }
        require(maximumCertificates in 1..HARD_MAXIMUM_CERTIFICATES) {
            "A chain has 1 to $HARD_MAXIMUM_CERTIFICATES certificates"
        }
        require(maximumKeys in 1..HARD_MAXIMUM_KEYS) { "A key set has 1 to $HARD_MAXIMUM_KEYS keys" }
        require(maximumIterations in 1..HARD_MAXIMUM_ITERATIONS) {
            "PBES2 takes 1 to $HARD_MAXIMUM_ITERATIONS iterations"
        }
    }

    /**
     * Compares every limit.
     *
     * @param other the other object.
     * @return true if [other] has the same limits.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is JoseLimits && values == other.values

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
    override fun toString(): String = "JoseLimits(maximumBytes=$maximumBytes, maximumDepth=$maximumDepth, " +
        "maximumMembers=$maximumMembers, maximumStringLength=$maximumStringLength, " +
        "maximumRecipients=$maximumRecipients, maximumCertificates=$maximumCertificates, " +
        "maximumKeys=$maximumKeys, maximumIterations=$maximumIterations)"

    /**
     * The defaults and the hard ceilings.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The default size of a serialization: 256 KiB.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_BYTES: Int = 262_144

        /**
         * The hard ceiling of the size of a serialization: 64 MiB.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_BYTES: Int = 67_108_864

        /**
         * The default nesting of JSON.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_DEPTH: Int = 16

        /**
         * The hard ceiling of the nesting of JSON.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_DEPTH: Int = 64

        /**
         * The default number of members of a JSON object or elements of an array.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_MEMBERS: Int = 256

        /**
         * The hard ceiling of the number of members of a JSON object or elements of an array.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_MEMBERS: Int = 65_536

        /**
         * The default length of a JSON string, as long as the default serialization.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_STRING_LENGTH: Int = DEFAULT_MAXIMUM_BYTES

        /**
         * The hard ceiling of the length of a JSON string.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_STRING_LENGTH: Int = HARD_MAXIMUM_BYTES

        /**
         * The default number of signatures or recipients.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_RECIPIENTS: Int = 16

        /**
         * The hard ceiling of the number of signatures or recipients.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_RECIPIENTS: Int = 1_024

        /**
         * The default length of an `x5c` chain.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_CERTIFICATES: Int = 8

        /**
         * The hard ceiling of the length of an `x5c` chain.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_CERTIFICATES: Int = 64

        /**
         * The default number of keys of a JWK set.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_KEYS: Int = 64

        /**
         * The hard ceiling of the number of keys of a JWK set.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_KEYS: Int = 4_096

        /**
         * The default PBES2 iterations decryption accepts: 1,200,000, twice the minimum of the modern policy.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_ITERATIONS: Int = 1_200_000

        /**
         * The hard ceiling of the PBES2 iterations: 10,000,000, the ceiling of every crypto policy.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_ITERATIONS: Int = 10_000_000

        /**
         * The default limits.
         *
         * @since 1.0.0
         */
        public val Default: JoseLimits = JoseLimits()
    }
}
