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

package com.davils.krypt.spiffe

/**
 * The limits of reading SPIFFE material, checked before any work is done.
 *
 * @property maximumBytes the size of a SPIFFE bundle or bundle map as JSON text.
 * @property maximumAuthorities how many keys a bundle holds.
 * @property maximumTrustDomains how many trust domains a bundle map or a source holds.
 * @property maximumChainLength how many certificates an X.509-SVID chain holds, the leaf included.
 * @property maximumTokenBytes the size of a JWT-SVID.
 * @property maximumSvids how many X.509-SVIDs a source holds at once.
 * @constructor Checks the limits against their hard ceilings.
 * @throws IllegalArgumentException if a limit is not positive or exceeds its hard ceiling.
 * @since 1.0.0
 */
public class SpiffeLimits(
    public val maximumBytes: Int = DEFAULT_MAXIMUM_BYTES,
    public val maximumAuthorities: Int = DEFAULT_MAXIMUM_AUTHORITIES,
    public val maximumTrustDomains: Int = DEFAULT_MAXIMUM_TRUST_DOMAINS,
    public val maximumChainLength: Int = DEFAULT_MAXIMUM_CHAIN_LENGTH,
    public val maximumTokenBytes: Int = DEFAULT_MAXIMUM_TOKEN_BYTES,
    public val maximumSvids: Int = DEFAULT_MAXIMUM_SVIDS,
) {
    private val values: List<Int>
        get() = listOf(
            maximumBytes,
            maximumAuthorities,
            maximumTrustDomains,
            maximumChainLength,
            maximumTokenBytes,
            maximumSvids,
        )

    init {
        require(maximumBytes in 1..HARD_MAXIMUM_BYTES) { "A bundle has 1 to $HARD_MAXIMUM_BYTES bytes" }
        require(maximumAuthorities in 1..HARD_MAXIMUM_AUTHORITIES) {
            "A bundle holds 1 to $HARD_MAXIMUM_AUTHORITIES keys"
        }
        require(maximumTrustDomains in 1..HARD_MAXIMUM_TRUST_DOMAINS) {
            "A bundle map holds 1 to $HARD_MAXIMUM_TRUST_DOMAINS trust domains"
        }
        require(maximumChainLength in 1..HARD_MAXIMUM_CHAIN_LENGTH) {
            "An X.509-SVID chain holds 1 to $HARD_MAXIMUM_CHAIN_LENGTH certificates"
        }
        require(maximumTokenBytes in 1..HARD_MAXIMUM_TOKEN_BYTES) {
            "A JWT-SVID has 1 to $HARD_MAXIMUM_TOKEN_BYTES bytes"
        }
        require(maximumSvids in 1..HARD_MAXIMUM_SVIDS) { "A source holds 1 to $HARD_MAXIMUM_SVIDS X.509-SVIDs" }
    }

    /**
     * Compares every limit.
     *
     * @param other the other object.
     * @return true if [other] has the same limits.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is SpiffeLimits && values == other.values

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
    override fun toString(): String = "SpiffeLimits(maximumBytes=$maximumBytes, " +
        "maximumAuthorities=$maximumAuthorities, maximumTrustDomains=$maximumTrustDomains, " +
        "maximumChainLength=$maximumChainLength, maximumTokenBytes=$maximumTokenBytes, maximumSvids=$maximumSvids)"

    /**
     * The defaults and the hard ceilings.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The default size of a bundle or bundle map.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_BYTES: Int = 262_144

        /**
         * The hard ceiling of the size of a bundle or bundle map.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_BYTES: Int = 16_777_216

        /**
         * The default number of keys in a bundle.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_AUTHORITIES: Int = 64

        /**
         * The hard ceiling of the number of keys in a bundle.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_AUTHORITIES: Int = 4_096

        /**
         * The default number of trust domains of a bundle map or a source.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_TRUST_DOMAINS: Int = 256

        /**
         * The hard ceiling of the number of trust domains of a bundle map or a source.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_TRUST_DOMAINS: Int = 4_096

        /**
         * The default length of an X.509-SVID chain.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_CHAIN_LENGTH: Int = 8

        /**
         * The hard ceiling of the length of an X.509-SVID chain.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_CHAIN_LENGTH: Int = 64

        /**
         * The default size of a JWT-SVID.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_TOKEN_BYTES: Int = 16_384

        /**
         * The hard ceiling of the size of a JWT-SVID.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_TOKEN_BYTES: Int = 1_048_576

        /**
         * The default number of X.509-SVIDs of a source.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_SVIDS: Int = 16

        /**
         * The hard ceiling of the number of X.509-SVIDs of a source.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_SVIDS: Int = 1_024

        /**
         * The default limits.
         *
         * @since 1.0.0
         */
        public val Default: SpiffeLimits = SpiffeLimits()
    }
}
