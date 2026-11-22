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
 * A key encapsulation mechanism, which wraps a fresh shared secret for the holder of a public key.
 *
 * @property algorithmName the canonical name of the algorithm.
 * @property securityBits the security strength in bits.
 * @property family the family of the recipient key.
 * @property secretBytes the length of the shared secret in bytes.
 * @property isLegacy whether the algorithm is broken or weak and exists only to read old data.
 * @property isFipsApproved whether FIPS 140-3 approves the algorithm.
 * @property isPostQuantum whether the algorithm resists a quantum computer.
 * @since 1.0.0
 */
public enum class KemAlgorithm(
    override val algorithmName: String,
    override val securityBits: Int,
    public val family: KeyFamily,
    public val secretBytes: Int,
    override val isLegacy: Boolean = false,
    override val isFipsApproved: Boolean = true,
    override val isPostQuantum: Boolean = false,
) : Algorithm {
    /**
     * DHKEM over X25519 with HKDF-SHA-256 of RFC 9180, the default KEM.
     *
     * @since 1.0.0
     */
    DhkemX25519(
        algorithmName = "DHKEM(X25519, HKDF-SHA256)",
        securityBits = 128,
        family = KeyFamily.X25519,
        secretBytes = 32,
        isFipsApproved = false,
    ),

    /**
     * DHKEM over P-256 with HKDF-SHA-256 of RFC 9180.
     *
     * @since 1.0.0
     */
    DhkemP256(
        algorithmName = "DHKEM(P-256, HKDF-SHA256)",
        securityBits = 128,
        family = KeyFamily.Ec,
        secretBytes = 32,
    ),

    /**
     * DHKEM over P-384 with HKDF-SHA-384 of RFC 9180.
     *
     * @since 1.0.0
     */
    DhkemP384(
        algorithmName = "DHKEM(P-384, HKDF-SHA384)",
        securityBits = 192,
        family = KeyFamily.Ec,
        secretBytes = 48,
    ),

    /**
     * DHKEM over P-521 with HKDF-SHA-512 of RFC 9180.
     *
     * @since 1.0.0
     */
    DhkemP521(
        algorithmName = "DHKEM(P-521, HKDF-SHA512)",
        securityBits = 256,
        family = KeyFamily.Ec,
        secretBytes = 64,
    ),

    /**
     * ML-KEM-768 of FIPS 203, on the JVM only.
     *
     * @since 1.0.0
     */
    MlKem768(
        algorithmName = "ML-KEM-768",
        securityBits = 192,
        family = KeyFamily.MlKem,
        secretBytes = 32,
        isPostQuantum = true,
    ),

    /**
     * ML-KEM-1024 of FIPS 203, on the JVM only.
     *
     * @since 1.0.0
     */
    MlKem1024(
        algorithmName = "ML-KEM-1024",
        securityBits = 256,
        family = KeyFamily.MlKem,
        secretBytes = 32,
        isPostQuantum = true,
    ),
}
