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

package com.davils.krypt.core.policy

import com.davils.kore.core.annotation.DavilsDsl
import com.davils.kore.core.dsl.ValidatingBuilder
import com.davils.krypt.core.LegacyCryptography
import com.davils.krypt.core.algorithm.AeadAlgorithm
import com.davils.krypt.core.algorithm.Algorithm
import com.davils.krypt.core.algorithm.AsymmetricEncryptionAlgorithm
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.EllipticCurve
import com.davils.krypt.core.algorithm.KdfAlgorithm
import com.davils.krypt.core.algorithm.KemAlgorithm
import com.davils.krypt.core.algorithm.KeyAgreementAlgorithm
import com.davils.krypt.core.algorithm.KeyWrapAlgorithm
import com.davils.krypt.core.algorithm.MacAlgorithm
import com.davils.krypt.core.algorithm.SignatureAlgorithm

private const val MODERN_RSA_BITS: Int = 3_072
private const val COMPATIBLE_RSA_BITS: Int = 2_048
private const val MODERN_ITERATIONS: Int = 600_000
private const val VERIFIED_ITERATIONS: Int = 1_000
private const val DEFAULT_MAXIMUM_ITERATIONS: Int = 5_000_000
private const val DEFAULT_MAXIMUM_RSA_BITS: Int = 8_192
private const val CNSA_SECURITY_BITS: Int = 192

/**
 * Builds a [CryptoPolicy] from the settings of a [CryptoProfile]; see [cryptoPolicy].
 *
 * @since 1.0.0
 */
@DavilsDsl
public class CryptoPolicyBuilder internal constructor(
    /**
     * The profile the settings start from.
     *
     * @since 1.0.0
     */
    public val profile: CryptoProfile,
) : ValidatingBuilder<CryptoPolicy>() {
    override val subject: String get() = "policy"

    internal val protecting: MutableSet<Algorithm> = protectingOf(profile).toMutableSet()

    internal val verifying: MutableSet<Algorithm> = verifyingOf(profile).toMutableSet()

    internal val curves: MutableSet<EllipticCurve> = curvesOf(profile).toMutableSet()

    /**
     * See [CryptoPolicy.minimumRsaBits].
     *
     * @since 1.0.0
     */
    public var minimumRsaBits: Int = rsaBitsOf(profile)
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [CryptoPolicy.minimumVerifiedRsaBits].
     *
     * @since 1.0.0
     */
    public var minimumVerifiedRsaBits: Int = verifiedRsaBitsOf(profile)
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [CryptoPolicy.maximumRsaBits].
     *
     * @since 1.0.0
     */
    public var maximumRsaBits: Int = DEFAULT_MAXIMUM_RSA_BITS
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [CryptoPolicy.minimumIterations].
     *
     * @since 1.0.0
     */
    public var minimumIterations: Int = MODERN_ITERATIONS
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [CryptoPolicy.minimumVerifiedIterations].
     *
     * @since 1.0.0
     */
    public var minimumVerifiedIterations: Int = VERIFIED_ITERATIONS
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [CryptoPolicy.maximumIterations].
     *
     * @since 1.0.0
     */
    public var maximumIterations: Int = DEFAULT_MAXIMUM_ITERATIONS
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [CryptoPolicy.isFipsProviderRequired].
     *
     * @since 1.0.0
     */
    public var isFipsProviderRequired: Boolean = profile == CryptoProfile.Fips
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * Permits [algorithms] for something new and for verification.
     *
     * @param algorithms the algorithms, none of them legacy.
     * @throws IllegalArgumentException if one of them is legacy; see [acceptLegacy].
     * @throws IllegalStateException if this builder was evaluated already.
     * @since 1.0.0
     */
    public fun permit(vararg algorithms: Algorithm) {
        checkOpen()
        val legacy = algorithms.filter { algorithm -> algorithm.isLegacy }
        require(legacy.isEmpty()) { "Legacy algorithms are never permitted for new protection: $legacy" }
        protecting += algorithms
        verifying += algorithms
    }

    /**
     * Permits [algorithms] for verification only, so that old data stays readable.
     *
     * @param algorithms the algorithms, none of them legacy.
     * @throws IllegalArgumentException if one of them is legacy; see [acceptLegacy].
     * @throws IllegalStateException if this builder was evaluated already.
     * @since 1.0.0
     */
    public fun accept(vararg algorithms: Algorithm) {
        checkOpen()
        val legacy = algorithms.filter { algorithm -> algorithm.isLegacy }
        require(legacy.isEmpty()) { "Legacy algorithms are accepted only through acceptLegacy: $legacy" }
        verifying += algorithms
    }

    /**
     * Accepts the legacy [algorithms] for verification only, such as SHA-1 to verify an old certificate.
     *
     * @param algorithms the legacy algorithms.
     * @throws IllegalStateException if this builder was evaluated already.
     * @since 1.0.0
     */
    @LegacyCryptography
    public fun acceptLegacy(vararg algorithms: Algorithm) {
        checkOpen()
        verifying += algorithms
    }

    /**
     * Forbids [algorithms] for every use.
     *
     * @param algorithms the algorithms.
     * @throws IllegalStateException if this builder was evaluated already.
     * @since 1.0.0
     */
    public fun forbid(vararg algorithms: Algorithm) {
        checkOpen()
        protecting -= algorithms.toSet()
        verifying -= algorithms.toSet()
    }

    /**
     * Restricts elliptic curve keys to [permitted].
     *
     * @param permitted the curves.
     * @throws IllegalStateException if this builder was evaluated already.
     * @since 1.0.0
     */
    public fun curves(vararg permitted: EllipticCurve) {
        checkOpen()
        curves.clear()
        curves += permitted
    }

    override fun assemble(): CryptoPolicy = CryptoPolicy(this)

    private companion object {
        val ALL: List<Algorithm> = DigestAlgorithm.entries +
            MacAlgorithm.entries +
            AeadAlgorithm.entries +
            KeyWrapAlgorithm.entries +
            KdfAlgorithm.entries +
            SignatureAlgorithm.entries +
            KeyAgreementAlgorithm.entries +
            AsymmetricEncryptionAlgorithm.entries +
            KemAlgorithm.entries

        val CURRENT: List<Algorithm> = ALL.filterNot { algorithm -> algorithm.isLegacy }

        val PKCS1_SIGNATURES: Set<Algorithm> = setOf(
            SignatureAlgorithm.RsaPkcs1Sha256,
            SignatureAlgorithm.RsaPkcs1Sha384,
            SignatureAlgorithm.RsaPkcs1Sha512,
        )

        val CNSA: Set<Algorithm> = setOf(
            AeadAlgorithm.Aes256Gcm,
            KeyWrapAlgorithm.Aes256Kw,
            KemAlgorithm.MlKem1024,
            KemAlgorithm.DhkemP384,
            SignatureAlgorithm.MlDsa87,
            KeyAgreementAlgorithm.EcdhP384,
        )

        fun protectingOf(profile: CryptoProfile): Set<Algorithm> = when (profile) {
            CryptoProfile.Modern -> CURRENT.toSet() - PKCS1_SIGNATURES
            CryptoProfile.Compatible -> CURRENT.toSet()
            CryptoProfile.Cnsa2 -> CURRENT.filter { algorithm -> isCnsa(algorithm) }.toSet()
            CryptoProfile.Fips -> CURRENT.filter { algorithm -> algorithm.isFipsApproved }.toSet()
        }

        fun verifyingOf(profile: CryptoProfile): Set<Algorithm> = when (profile) {
            CryptoProfile.Modern -> CURRENT.toSet()
            CryptoProfile.Compatible -> CURRENT.toSet()
            CryptoProfile.Cnsa2 -> protectingOf(profile)
            CryptoProfile.Fips -> protectingOf(profile)
        }

        fun curvesOf(profile: CryptoProfile): Set<EllipticCurve> = when (profile) {
            CryptoProfile.Cnsa2 -> setOf(EllipticCurve.P384)
            CryptoProfile.Modern -> EllipticCurve.entries.toSet()
            CryptoProfile.Compatible -> EllipticCurve.entries.toSet()
            CryptoProfile.Fips -> EllipticCurve.entries.toSet()
        }

        fun rsaBitsOf(profile: CryptoProfile): Int = when (profile) {
            CryptoProfile.Compatible -> COMPATIBLE_RSA_BITS
            CryptoProfile.Modern -> MODERN_RSA_BITS
            CryptoProfile.Cnsa2 -> MODERN_RSA_BITS
            CryptoProfile.Fips -> MODERN_RSA_BITS
        }

        fun verifiedRsaBitsOf(profile: CryptoProfile): Int = when (profile) {
            CryptoProfile.Cnsa2 -> MODERN_RSA_BITS
            CryptoProfile.Modern -> COMPATIBLE_RSA_BITS
            CryptoProfile.Compatible -> COMPATIBLE_RSA_BITS
            CryptoProfile.Fips -> COMPATIBLE_RSA_BITS
        }

        fun isCnsa(algorithm: Algorithm): Boolean {
            val isStrong = algorithm.securityBits >= CNSA_SECURITY_BITS
            val isHashedSignature = algorithm is SignatureAlgorithm && algorithm.digest != null
            val isClassical = isHashedSignature || isHashBased(algorithm)
            val isPermitted = isStrong && isClassical && algorithm.isFipsApproved
            return algorithm in CNSA || isPermitted
        }

        fun isHashBased(algorithm: Algorithm): Boolean = when (algorithm) {
            is DigestAlgorithm -> true
            is MacAlgorithm -> true
            is KdfAlgorithm -> true
            is AsymmetricEncryptionAlgorithm -> true
            is AeadAlgorithm -> false
            is KeyWrapAlgorithm -> false
            is SignatureAlgorithm -> false
            is KeyAgreementAlgorithm -> false
            is KemAlgorithm -> false
        }
    }
}
