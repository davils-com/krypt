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
 * A key agreement, which derives a shared secret from a private and a public key.
 *
 * @property algorithmName the canonical name of the algorithm.
 * @property securityBits the security strength in bits.
 * @property family the family of both keys.
 * @property curve the curve of ECDH, or null for X25519 and X448.
 * @property secretBytes the length of the shared secret in bytes.
 * @property isLegacy whether the algorithm is broken or weak and exists only to read old data.
 * @property isFipsApproved whether FIPS 140-3 approves the algorithm.
 * @property isPostQuantum whether the algorithm resists a quantum computer.
 * @since 1.0.0
 */
public enum class KeyAgreementAlgorithm(
    override val algorithmName: String,
    override val securityBits: Int,
    public val family: KeyFamily,
    public val curve: EllipticCurve?,
    public val secretBytes: Int,
    override val isLegacy: Boolean = false,
    override val isFipsApproved: Boolean = true,
    override val isPostQuantum: Boolean = false,
) : Algorithm {
    /**
     * X25519 of RFC 7748, the default key agreement.
     *
     * @since 1.0.0
     */
    X25519(
        algorithmName = "X25519",
        securityBits = 128,
        family = KeyFamily.X25519,
        curve = null,
        secretBytes = 32,
        isFipsApproved = false,
    ),

    /**
     * X448 of RFC 7748, on the JVM only.
     *
     * @since 1.0.0
     */
    X448(
        algorithmName = "X448",
        securityBits = 224,
        family = KeyFamily.X448,
        curve = null,
        secretBytes = 56,
        isFipsApproved = false,
    ),

    /**
     * ECDH on P-256 of NIST SP 800-56A.
     *
     * @since 1.0.0
     */
    EcdhP256(
        algorithmName = "ECDH-P-256",
        securityBits = 128,
        family = KeyFamily.Ec,
        curve = EllipticCurve.P256,
        secretBytes = 32,
    ),

    /**
     * ECDH on P-384.
     *
     * @since 1.0.0
     */
    EcdhP384(
        algorithmName = "ECDH-P-384",
        securityBits = 192,
        family = KeyFamily.Ec,
        curve = EllipticCurve.P384,
        secretBytes = 48,
    ),

    /**
     * ECDH on P-521.
     *
     * @since 1.0.0
     */
    EcdhP521(
        algorithmName = "ECDH-P-521",
        securityBits = 256,
        family = KeyFamily.Ec,
        curve = EllipticCurve.P521,
        secretBytes = 66,
    ),
}
