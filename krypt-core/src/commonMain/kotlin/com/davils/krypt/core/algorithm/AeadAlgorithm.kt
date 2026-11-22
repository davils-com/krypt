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
 * An authenticated encryption with associated data.
 *
 * @property algorithmName the canonical name of the algorithm.
 * @property securityBits the security strength in bits.
 * @property keyBytes the length of a key in bytes.
 * @property nonceBytes the length of a nonce in bytes.
 * @property tagBytes the length of the authentication tag in bytes.
 * @property isLegacy whether the algorithm is broken or weak and exists only to read old data.
 * @property isFipsApproved whether FIPS 140-3 approves the algorithm.
 * @property isPostQuantum whether the algorithm resists a quantum computer.
 * @since 1.0.0
 */
public enum class AeadAlgorithm(
    override val algorithmName: String,
    override val securityBits: Int,
    public val keyBytes: Int,
    public val nonceBytes: Int,
    public val tagBytes: Int,
    override val isLegacy: Boolean = false,
    override val isFipsApproved: Boolean = true,
    override val isPostQuantum: Boolean = false,
) : Algorithm {
    /**
     * AES-128 in GCM of NIST SP 800-38D.
     *
     * @since 1.0.0
     */
    Aes128Gcm(
        algorithmName = "AES-128-GCM",
        securityBits = 128,
        keyBytes = 16,
        nonceBytes = 12,
        tagBytes = 16,
    ),

    /**
     * AES-256 in GCM of NIST SP 800-38D, the default AEAD.
     *
     * @since 1.0.0
     */
    Aes256Gcm(
        algorithmName = "AES-256-GCM",
        securityBits = 256,
        keyBytes = 32,
        nonceBytes = 12,
        tagBytes = 16,
    ),

    /**
     * ChaCha20-Poly1305 of RFC 8439, on the JVM only.
     *
     * @since 1.0.0
     */
    ChaCha20Poly1305(
        algorithmName = "ChaCha20-Poly1305",
        securityBits = 256,
        keyBytes = 32,
        nonceBytes = 12,
        tagBytes = 16,
        isFipsApproved = false,
    ),
}
