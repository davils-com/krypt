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

@file:OptIn(DavilsInternal::class)

package com.davils.krypt.core.policy

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.collection.immutableSet
import com.davils.kore.core.validation.Validatable
import com.davils.kore.core.validation.ValidationScope
import com.davils.kore.core.validation.inRange
import com.davils.kore.core.validation.validateOrThrow
import com.davils.krypt.core.algorithm.Algorithm
import com.davils.krypt.core.algorithm.EllipticCurve

private const val SUBJECT: String = "policy"

/**
 * Which algorithms, key sizes, curves and work factors krypt may use, decided once for an application.
 *
 * Every operation of krypt asks the policy of its environment before it does any work, for what it creates
 * ([AlgorithmUse.Protect]) as well as for what it reads ([AlgorithmUse.Verify]): a refused algorithm is a typed refusal
 * of the operation, never a silent downgrade. A policy only narrows what krypt can do; an algorithm the platform lacks
 * stays unavailable whatever the policy permits.
 *
 * A policy is immutable and thread safe. Build one with [cryptoPolicy] or take one of the profiles, such as [Modern].
 *
 * @since 1.0.0
 */
public class CryptoPolicy internal constructor(builder: CryptoPolicyBuilder) : Validatable {
    /**
     * The profile the policy started from.
     *
     * @since 1.0.0
     */
    public val profile: CryptoProfile = builder.profile

    /**
     * The algorithms permitted for something new.
     *
     * @since 1.0.0
     */
    public val protecting: Set<Algorithm> = builder.protecting.immutableSet()

    /**
     * The algorithms permitted for checking and opening, a superset of [protecting].
     *
     * @since 1.0.0
     */
    public val verifying: Set<Algorithm> = (builder.verifying + builder.protecting).immutableSet()

    /**
     * The curves an elliptic curve key may lie on.
     *
     * @since 1.0.0
     */
    public val curves: Set<EllipticCurve> = builder.curves.immutableSet()

    /**
     * The smallest RSA modulus in bits for a new key or a new signature or encryption, from
     * [HARD_MINIMUM_RSA_BITS] to [HARD_MAXIMUM_RSA_BITS].
     *
     * @since 1.0.0
     */
    public val minimumRsaBits: Int = builder.minimumRsaBits

    /**
     * The smallest RSA modulus in bits that may still be verified or decrypted, from [HARD_MINIMUM_RSA_BITS] to
     * [minimumRsaBits].
     *
     * @since 1.0.0
     */
    public val minimumVerifiedRsaBits: Int = builder.minimumVerifiedRsaBits

    /**
     * The largest RSA modulus in bits krypt accepts at all, which bounds the work of a hostile key; at most
     * [HARD_MAXIMUM_RSA_BITS].
     *
     * @since 1.0.0
     */
    public val maximumRsaBits: Int = builder.maximumRsaBits

    /**
     * The fewest PBKDF2 iterations of a new password derivation.
     *
     * @since 1.0.0
     */
    public val minimumIterations: Int = builder.minimumIterations

    /**
     * The fewest PBKDF2 iterations a stored derivation, such as an encrypted private key, may have been made with.
     *
     * @since 1.0.0
     */
    public val minimumVerifiedIterations: Int = builder.minimumVerifiedIterations

    /**
     * The most PBKDF2 iterations krypt runs, which bounds the work an attacker can demand with a crafted file; at most
     * [HARD_MAXIMUM_ITERATIONS].
     *
     * @since 1.0.0
     */
    public val maximumIterations: Int = builder.maximumIterations

    /**
     * Tells whether the policy demands a FIPS validated provider, which the [CryptoProfile.Fips] profile does.
     *
     * @since 1.0.0
     */
    public val isFipsProviderRequired: Boolean = builder.isFipsProviderRequired

    init {
        validateOrThrow(SUBJECT)
    }

    /**
     * Tells whether [algorithm] may be used for [use].
     *
     * @param algorithm the algorithm.
     * @param use what the operation does with it.
     * @return true if the policy permits it.
     * @since 1.0.0
     */
    public fun permits(algorithm: Algorithm, use: AlgorithmUse): Boolean = when (use) {
        AlgorithmUse.Protect -> algorithm in protecting
        AlgorithmUse.Verify -> algorithm in verifying
    }

    /**
     * Tells whether an RSA key of [bits] may be used for [use].
     *
     * @param bits the size of the modulus.
     * @param use what the operation does with the key.
     * @return true if the size is within the bounds of the policy.
     * @since 1.0.0
     */
    public fun permitsRsa(bits: Int, use: AlgorithmUse): Boolean {
        val minimum = when (use) {
            AlgorithmUse.Protect -> minimumRsaBits
            AlgorithmUse.Verify -> minimumVerifiedRsaBits
        }
        return bits in minimum..maximumRsaBits
    }

    /**
     * Tells whether a key on [curve] may be used.
     *
     * @param curve the curve.
     * @return true if the policy permits the curve.
     * @since 1.0.0
     */
    public fun permitsCurve(curve: EllipticCurve): Boolean = curve in curves

    /**
     * Tells whether a password derivation with [count] iterations may be used for [use].
     *
     * @param count the number of iterations.
     * @param use whether a new derivation is made or a stored one is checked.
     * @return true if the count is within the bounds of the policy.
     * @since 1.0.0
     */
    public fun permitsIterations(count: Int, use: AlgorithmUse): Boolean {
        val minimum = when (use) {
            AlgorithmUse.Protect -> minimumIterations
            AlgorithmUse.Verify -> minimumVerifiedIterations
        }
        return count in minimum..maximumIterations
    }

    /**
     * Checks that every bound lies within its hard ceiling and that the bounds are ordered.
     *
     * @receiver the validation that collects the violations.
     * @since 1.0.0
     */
    override fun ValidationScope.validate() {
        inRange(
            property = ::maximumRsaBits,
            value = maximumRsaBits,
            range = HARD_MINIMUM_RSA_BITS..HARD_MAXIMUM_RSA_BITS,
        )
        inRange(property = ::minimumRsaBits, value = minimumRsaBits, range = HARD_MINIMUM_RSA_BITS..maximumRsaBits)
        inRange(
            property = ::minimumVerifiedRsaBits,
            value = minimumVerifiedRsaBits,
            range = HARD_MINIMUM_RSA_BITS..minimumRsaBits,
        )
        inRange(property = ::maximumIterations, value = maximumIterations, range = 1..HARD_MAXIMUM_ITERATIONS)
        inRange(property = ::minimumIterations, value = minimumIterations, range = 1..maximumIterations)
        inRange(
            property = ::minimumVerifiedIterations,
            value = minimumVerifiedIterations,
            range = 1..minimumIterations,
        )
    }

    /**
     * Shows the profile and the bounds of the policy.
     *
     * @return the policy as text.
     * @since 1.0.0
     */
    override fun toString(): String =
        "CryptoPolicy(profile=$profile, protecting=${protecting.size}, verifying=${verifying.size}, " +
            "curves=$curves, rsa=$minimumVerifiedRsaBits/$minimumRsaBits..$maximumRsaBits, " +
            "iterations=$minimumVerifiedIterations/$minimumIterations..$maximumIterations, " +
            "fipsProvider=$isFipsProviderRequired)"

    /**
     * The hard ceilings and the policies of the profiles.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The smallest RSA modulus any policy permits: 2,048 bits.
         *
         * @since 1.0.0
         */
        public const val HARD_MINIMUM_RSA_BITS: Int = 2_048

        /**
         * The largest RSA modulus any policy permits: 16,384 bits.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_RSA_BITS: Int = 16_384

        /**
         * The most PBKDF2 iterations any policy permits: 10,000,000.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_ITERATIONS: Int = 10_000_000

        /**
         * The policy of [CryptoProfile.Modern], the default.
         *
         * @since 1.0.0
         */
        public val Modern: CryptoPolicy = cryptoPolicy(CryptoProfile.Modern) {}

        /**
         * The policy of [CryptoProfile.Compatible].
         *
         * @since 1.0.0
         */
        public val Compatible: CryptoPolicy = cryptoPolicy(CryptoProfile.Compatible) {}

        /**
         * The policy of [CryptoProfile.Cnsa2].
         *
         * @since 1.0.0
         */
        public val Cnsa2: CryptoPolicy = cryptoPolicy(CryptoProfile.Cnsa2) {}

        /**
         * The policy of [CryptoProfile.Fips].
         *
         * @since 1.0.0
         */
        public val Fips: CryptoPolicy = cryptoPolicy(CryptoProfile.Fips) {}
    }
}
