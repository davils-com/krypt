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

/**
 * The limits of containers and manifests.
 *
 * @property maximumRecipients how many recipients a container has at most.
 * @property maximumSegments how many segments a container or a manifest covers at most.
 * @property maximumSignatures how many signatures a signed manifest holds at most.
 * @property maximumIterations the most PBKDF2 iterations a password recipient may ask for, on top of the policy.
 * @constructor Checks the limits against their hard ceilings.
 * @throws IllegalArgumentException if a limit is not positive or exceeds its hard ceiling.
 * @since 1.0.0
 */
public class StreamLimits(
    public val maximumRecipients: Int = DEFAULT_MAXIMUM_RECIPIENTS,
    public val maximumSegments: Long = HARD_MAXIMUM_SEGMENTS,
    public val maximumSignatures: Int = DEFAULT_MAXIMUM_SIGNATURES,
    public val maximumIterations: Int = DEFAULT_MAXIMUM_ITERATIONS,
) {
    init {
        require(maximumRecipients in 1..HARD_MAXIMUM_RECIPIENTS) {
            "A container has 1 to $HARD_MAXIMUM_RECIPIENTS recipients"
        }
        require(maximumSegments in 1L..HARD_MAXIMUM_SEGMENTS) { "A container has 1 to $HARD_MAXIMUM_SEGMENTS segments" }
        require(maximumSignatures in 1..HARD_MAXIMUM_SIGNATURES) {
            "A manifest holds 1 to $HARD_MAXIMUM_SIGNATURES signatures"
        }
        require(maximumIterations >= 1) { "A password needs at least one iteration" }
    }

    /**
     * Compares every limit.
     *
     * @param other the other object.
     * @return true if [other] has the same limits.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is StreamLimits &&
        maximumRecipients == other.maximumRecipients &&
        maximumSegments == other.maximumSegments &&
        maximumSignatures == other.maximumSignatures &&
        maximumIterations == other.maximumIterations

    /**
     * Hashes every limit.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int =
        listOf(maximumRecipients, maximumSegments, maximumSignatures, maximumIterations).hashCode()

    /**
     * Shows every limit.
     *
     * @return the limits as text.
     * @since 1.0.0
     */
    override fun toString(): String = "StreamLimits(maximumRecipients=$maximumRecipients, " +
        "maximumSegments=$maximumSegments, maximumSignatures=$maximumSignatures, " +
        "maximumIterations=$maximumIterations)"

    /**
     * The defaults and the hard ceilings.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The default number of recipients.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_RECIPIENTS: Int = 16

        /**
         * The hard ceiling of the number of recipients.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_RECIPIENTS: Int = 255

        /**
         * The hard ceiling of the number of segments: the nonce counter has 32 bits.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_SEGMENTS: Long = 4_294_967_295L

        /**
         * The default number of signatures.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_SIGNATURES: Int = 32

        /**
         * The hard ceiling of the number of signatures.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_SIGNATURES: Int = 1_024

        /**
         * The default ceiling of the iterations of a password recipient.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_ITERATIONS: Int = 10_000_000

        /**
         * The default limits.
         *
         * @since 1.0.0
         */
        public val Default: StreamLimits = StreamLimits()
    }
}
