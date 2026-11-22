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
 * An encryption with a public key of RSA.
 *
 * @property algorithmName the canonical name of the algorithm.
 * @property securityBits the security strength in bits.
 * @property digest the digest of OAEP and of its MGF1, or null for PKCS #1 v1.5.
 * @property isLegacy whether the algorithm is broken or weak and exists only to read old data.
 * @property isFipsApproved whether FIPS 140-3 approves the algorithm.
 * @property isPostQuantum whether the algorithm resists a quantum computer.
 * @since 1.0.0
 */
public enum class AsymmetricEncryptionAlgorithm(
    override val algorithmName: String,
    override val securityBits: Int,
    public val digest: DigestAlgorithm?,
    override val isLegacy: Boolean = false,
    override val isFipsApproved: Boolean = true,
    override val isPostQuantum: Boolean = false,
) : Algorithm {
    /**
     * RSAES-OAEP of RFC 8017 with SHA-256 and MGF1 with SHA-256, the default.
     *
     * @since 1.0.0
     */
    RsaOaepSha256(
        algorithmName = "RSAES-OAEP-SHA-256",
        securityBits = 128,
        digest = DigestAlgorithm.Sha256,
    ),

    /**
     * RSAES-OAEP with SHA-384.
     *
     * @since 1.0.0
     */
    RsaOaepSha384(
        algorithmName = "RSAES-OAEP-SHA-384",
        securityBits = 192,
        digest = DigestAlgorithm.Sha384,
    ),

    /**
     * RSAES-OAEP with SHA-512.
     *
     * @since 1.0.0
     */
    RsaOaepSha512(
        algorithmName = "RSAES-OAEP-SHA-512",
        securityBits = 256,
        digest = DigestAlgorithm.Sha512,
    ),

    /**
     * RSAES-PKCS1-v1_5, open to padding oracles; only to read old data.
     *
     * @since 1.0.0
     */
    @LegacyCryptography
    RsaPkcs1(
        algorithmName = "RSAES-PKCS1-v1_5",
        securityBits = 0,
        digest = null,
        isLegacy = true,
        isFipsApproved = false,
    ),
}
