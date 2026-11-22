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

import com.davils.krypt.core.LegacyCryptography

/**
 * A message digest.
 *
 * @property algorithmName the canonical name of the algorithm.
 * @property securityBits the security strength in bits.
 * @property outputBytes the length of a digest in bytes.
 * @property blockBytes the block length in bytes, which HMAC needs.
 * @property isLegacy whether the algorithm is broken or weak and exists only to read old data.
 * @property isFipsApproved whether FIPS 140-3 approves the algorithm.
 * @property isPostQuantum whether the algorithm resists a quantum computer.
 * @since 1.0.0
 */
public enum class DigestAlgorithm(
    override val algorithmName: String,
    override val securityBits: Int,
    public val outputBytes: Int,
    public val blockBytes: Int,
    override val isLegacy: Boolean = false,
    override val isFipsApproved: Boolean = true,
    override val isPostQuantum: Boolean = false,
) : Algorithm {
    /**
     * SHA-256 of FIPS 180-4, the default digest.
     *
     * @since 1.0.0
     */
    Sha256(
        algorithmName = "SHA-256",
        securityBits = 128,
        outputBytes = 32,
        blockBytes = 64,
    ),

    /**
     * SHA-384 of FIPS 180-4.
     *
     * @since 1.0.0
     */
    Sha384(
        algorithmName = "SHA-384",
        securityBits = 192,
        outputBytes = 48,
        blockBytes = 128,
    ),

    /**
     * SHA-512 of FIPS 180-4.
     *
     * @since 1.0.0
     */
    Sha512(
        algorithmName = "SHA-512",
        securityBits = 256,
        outputBytes = 64,
        blockBytes = 128,
    ),

    /**
     * SHA3-256 of FIPS 202, on the JVM only.
     *
     * @since 1.0.0
     */
    Sha3256(
        algorithmName = "SHA3-256",
        securityBits = 128,
        outputBytes = 32,
        blockBytes = 136,
    ),

    /**
     * SHA3-384 of FIPS 202, on the JVM only.
     *
     * @since 1.0.0
     */
    Sha3384(
        algorithmName = "SHA3-384",
        securityBits = 192,
        outputBytes = 48,
        blockBytes = 104,
    ),

    /**
     * SHA3-512 of FIPS 202, on the JVM only.
     *
     * @since 1.0.0
     */
    Sha3512(
        algorithmName = "SHA3-512",
        securityBits = 256,
        outputBytes = 64,
        blockBytes = 72,
    ),

    /**
     * SHA-1, broken against collisions; only to verify old signatures and to read old formats.
     *
     * @since 1.0.0
     */
    @LegacyCryptography
    Sha1(
        algorithmName = "SHA-1",
        securityBits = 0,
        outputBytes = 20,
        blockBytes = 64,
        isLegacy = true,
        isFipsApproved = false,
    ),

    /**
     * MD5, broken; only to read old formats.
     *
     * @since 1.0.0
     */
    @LegacyCryptography
    Md5(
        algorithmName = "MD5",
        securityBits = 0,
        outputBytes = 16,
        blockBytes = 64,
        isLegacy = true,
        isFipsApproved = false,
    ),
}
