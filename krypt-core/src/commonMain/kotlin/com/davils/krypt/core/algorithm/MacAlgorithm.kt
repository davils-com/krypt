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
 * A message authentication code.
 *
 * @property algorithmName the canonical name of the algorithm.
 * @property securityBits the security strength in bits.
 * @property digest the digest of the HMAC.
 * @property tagBytes the length of a tag in bytes.
 * @property isLegacy whether the algorithm is broken or weak and exists only to read old data.
 * @property isFipsApproved whether FIPS 140-3 approves the algorithm.
 * @property isPostQuantum whether the algorithm resists a quantum computer.
 * @since 1.0.0
 */
public enum class MacAlgorithm(
    override val algorithmName: String,
    override val securityBits: Int,
    public val digest: DigestAlgorithm,
    public val tagBytes: Int,
    override val isLegacy: Boolean = false,
    override val isFipsApproved: Boolean = true,
    override val isPostQuantum: Boolean = false,
) : Algorithm {
    /**
     * HMAC with SHA-256 of RFC 2104, the default MAC.
     *
     * @since 1.0.0
     */
    HmacSha256(
        algorithmName = "HMAC-SHA-256",
        securityBits = 256,
        digest = DigestAlgorithm.Sha256,
        tagBytes = 32,
    ),

    /**
     * HMAC with SHA-384.
     *
     * @since 1.0.0
     */
    HmacSha384(
        algorithmName = "HMAC-SHA-384",
        securityBits = 384,
        digest = DigestAlgorithm.Sha384,
        tagBytes = 48,
    ),

    /**
     * HMAC with SHA-512.
     *
     * @since 1.0.0
     */
    HmacSha512(
        algorithmName = "HMAC-SHA-512",
        securityBits = 512,
        digest = DigestAlgorithm.Sha512,
        tagBytes = 64,
    ),
}
