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

package com.davils.krypt.keystore

/**
 * The limits of reading key stores.
 *
 * @property maximumBytes the size of a key store or a PEM text.
 * @property maximumEntries how many bags and contents a key store holds at most.
 * @property maximumMacIterations the most iterations the classic MAC of a PKCS #12 file may ask for; the iterations
 *   of PBKDF2 are bounded by the crypto policy.
 * @property maximumPasswordIterations the most iterations all password derivations of one PKCS #12 file may ask for
 *   together: the MAC, every encrypted content and every shrouded key.
 * @constructor Checks the limits against their hard ceilings.
 * @throws IllegalArgumentException if a limit is not positive or exceeds its hard ceiling.
 * @since 1.0.0
 */
public class KeystoreLimits(
    public val maximumBytes: Int = DEFAULT_MAXIMUM_BYTES,
    public val maximumEntries: Int = DEFAULT_MAXIMUM_ENTRIES,
    public val maximumMacIterations: Int = DEFAULT_MAXIMUM_MAC_ITERATIONS,
    public val maximumPasswordIterations: Int = DEFAULT_MAXIMUM_PASSWORD_ITERATIONS,
) {
    init {
        require(maximumBytes in 1..HARD_MAXIMUM_BYTES) { "A key store has 1 to $HARD_MAXIMUM_BYTES bytes" }
        require(maximumEntries in 1..HARD_MAXIMUM_ENTRIES) { "A key store has 1 to $HARD_MAXIMUM_ENTRIES entries" }
        require(maximumMacIterations in 1..HARD_MAXIMUM_MAC_ITERATIONS) {
            "A MAC asks for 1 to $HARD_MAXIMUM_MAC_ITERATIONS iterations"
        }
        require(maximumPasswordIterations in 1..HARD_MAXIMUM_PASSWORD_ITERATIONS) {
            "A key store asks for 1 to $HARD_MAXIMUM_PASSWORD_ITERATIONS iterations"
        }
    }

    /**
     * Compares every limit.
     *
     * @param other the other object.
     * @return true if [other] has the same limits.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is KeystoreLimits && values() == other.values()

    /**
     * Hashes every limit.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = values().hashCode()

    /**
     * Shows every limit.
     *
     * @return the limits as text.
     * @since 1.0.0
     */
    override fun toString(): String = "KeystoreLimits(maximumBytes=$maximumBytes, maximumEntries=$maximumEntries, " +
        "maximumMacIterations=$maximumMacIterations, maximumPasswordIterations=$maximumPasswordIterations)"

    private fun values(): List<Int> =
        listOf(maximumBytes, maximumEntries, maximumMacIterations, maximumPasswordIterations)

    /**
     * The defaults and the hard ceilings.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The default size of a key store: 1 MiB.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_BYTES: Int = 1_048_576

        /**
         * The hard ceiling of the size of a key store: 64 MiB.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_BYTES: Int = 67_108_864

        /**
         * The default number of entries.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_ENTRIES: Int = 256

        /**
         * The hard ceiling of the number of entries.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_ENTRIES: Int = 65_536

        /**
         * The default ceiling of the iterations of a classic MAC.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_MAC_ITERATIONS: Int = 100_000

        /**
         * The hard ceiling of the iterations of a classic MAC.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_MAC_ITERATIONS: Int = 10_000_000

        /**
         * The default iterations of all password derivations of one file: about 33 derivations at the minimum of the
         * modern policy.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_PASSWORD_ITERATIONS: Int = 20_000_000

        /**
         * The hard ceiling of the iterations of all password derivations of one file.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_PASSWORD_ITERATIONS: Int = 1_000_000_000

        /**
         * The default limits.
         *
         * @since 1.0.0
         */
        public val Default: KeystoreLimits = KeystoreLimits()
    }
}
