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

package com.davils.krypt.core.algorithm

/**
 * A key derivation function.
 *
 * @property algorithmName the canonical name of the algorithm.
 * @property securityBits the security strength in bits.
 * @property digest the digest the function is built on.
 * @property isPasswordBased tells whether the function stretches a password.
 * @property isLegacy whether the algorithm is broken or weak and exists only to read old data.
 * @property isFipsApproved whether FIPS 140-3 approves the algorithm.
 * @property isPostQuantum whether the algorithm resists a quantum computer.
 * @since 1.0.0
 */
public enum class KdfAlgorithm(
    override val algorithmName: String,
    override val securityBits: Int,
    public val digest: DigestAlgorithm,
    public val isPasswordBased: Boolean,
    override val isLegacy: Boolean = false,
    override val isFipsApproved: Boolean = true,
    override val isPostQuantum: Boolean = false,
) : Algorithm {
    /**
     * HKDF with SHA-256 of RFC 5869, the default key derivation.
     *
     * @since 1.0.0
     */
    HkdfSha256(
        algorithmName = "HKDF-SHA-256",
        securityBits = 256,
        digest = DigestAlgorithm.Sha256,
        isPasswordBased = false,
    ),

    /**
     * HKDF with SHA-384.
     *
     * @since 1.0.0
     */
    HkdfSha384(
        algorithmName = "HKDF-SHA-384",
        securityBits = 384,
        digest = DigestAlgorithm.Sha384,
        isPasswordBased = false,
    ),

    /**
     * HKDF with SHA-512.
     *
     * @since 1.0.0
     */
    HkdfSha512(
        algorithmName = "HKDF-SHA-512",
        securityBits = 512,
        digest = DigestAlgorithm.Sha512,
        isPasswordBased = false,
    ),

    /**
     * PBKDF2 with HMAC-SHA-256 of RFC 8018, the default password derivation.
     *
     * @since 1.0.0
     */
    Pbkdf2Sha256(
        algorithmName = "PBKDF2-HMAC-SHA-256",
        securityBits = 256,
        digest = DigestAlgorithm.Sha256,
        isPasswordBased = true,
    ),

    /**
     * PBKDF2 with HMAC-SHA-512.
     *
     * @since 1.0.0
     */
    Pbkdf2Sha512(
        algorithmName = "PBKDF2-HMAC-SHA-512",
        securityBits = 512,
        digest = DigestAlgorithm.Sha512,
        isPasswordBased = true,
    ),
}
