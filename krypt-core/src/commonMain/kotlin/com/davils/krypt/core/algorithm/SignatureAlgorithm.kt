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
 * A digital signature scheme.
 *
 * @property algorithmName the canonical name of the algorithm.
 * @property securityBits the security strength in bits.
 * @property family the family of the keys that sign and verify.
 * @property digest the digest the message is hashed with first, or null for a scheme that hashes on its own, such as
 *   EdDSA and ML-DSA.
 * @property isLegacy whether the algorithm is broken or weak and exists only to read old data.
 * @property isFipsApproved whether FIPS 140-3 approves the algorithm.
 * @property isPostQuantum whether the algorithm resists a quantum computer.
 * @since 1.0.0
 */
public enum class SignatureAlgorithm(
    override val algorithmName: String,
    override val securityBits: Int,
    public val family: KeyFamily,
    public val digest: DigestAlgorithm?,
    override val isLegacy: Boolean = false,
    override val isFipsApproved: Boolean = true,
    override val isPostQuantum: Boolean = false,
) : Algorithm {
    /**
     * Ed25519 of RFC 8032, the default signature.
     *
     * @since 1.0.0
     */
    Ed25519(
        algorithmName = "Ed25519",
        securityBits = 128,
        family = KeyFamily.Ed25519,
        digest = null,
    ),

    /**
     * Ed448 of RFC 8032, on the JVM only.
     *
     * @since 1.0.0
     */
    Ed448(
        algorithmName = "Ed448",
        securityBits = 224,
        family = KeyFamily.Ed448,
        digest = null,
    ),

    /**
     * ECDSA with SHA-256 of FIPS 186-5; the curve is the curve of the key.
     *
     * @since 1.0.0
     */
    EcdsaSha256(
        algorithmName = "ECDSA-SHA-256",
        securityBits = 128,
        family = KeyFamily.Ec,
        digest = DigestAlgorithm.Sha256,
    ),

    /**
     * ECDSA with SHA-384.
     *
     * @since 1.0.0
     */
    EcdsaSha384(
        algorithmName = "ECDSA-SHA-384",
        securityBits = 192,
        family = KeyFamily.Ec,
        digest = DigestAlgorithm.Sha384,
    ),

    /**
     * ECDSA with SHA-512.
     *
     * @since 1.0.0
     */
    EcdsaSha512(
        algorithmName = "ECDSA-SHA-512",
        securityBits = 256,
        family = KeyFamily.Ec,
        digest = DigestAlgorithm.Sha512,
    ),

    /**
     * RSASSA-PSS of RFC 8017 with SHA-256, MGF1 with SHA-256 and a salt of 32 bytes.
     *
     * @since 1.0.0
     */
    RsaPssSha256(
        algorithmName = "RSASSA-PSS-SHA-256",
        securityBits = 128,
        family = KeyFamily.Rsa,
        digest = DigestAlgorithm.Sha256,
    ),

    /**
     * RSASSA-PSS with SHA-384, MGF1 with SHA-384 and a salt of 48 bytes.
     *
     * @since 1.0.0
     */
    RsaPssSha384(
        algorithmName = "RSASSA-PSS-SHA-384",
        securityBits = 192,
        family = KeyFamily.Rsa,
        digest = DigestAlgorithm.Sha384,
    ),

    /**
     * RSASSA-PSS with SHA-512, MGF1 with SHA-512 and a salt of 64 bytes.
     *
     * @since 1.0.0
     */
    RsaPssSha512(
        algorithmName = "RSASSA-PSS-SHA-512",
        securityBits = 256,
        family = KeyFamily.Rsa,
        digest = DigestAlgorithm.Sha512,
    ),

    /**
     * RSASSA-PKCS1-v1_5 of RFC 8017 with SHA-256, the signature of most certificates.
     *
     * @since 1.0.0
     */
    RsaPkcs1Sha256(
        algorithmName = "RSASSA-PKCS1-v1_5-SHA-256",
        securityBits = 128,
        family = KeyFamily.Rsa,
        digest = DigestAlgorithm.Sha256,
    ),

    /**
     * RSASSA-PKCS1-v1_5 with SHA-384.
     *
     * @since 1.0.0
     */
    RsaPkcs1Sha384(
        algorithmName = "RSASSA-PKCS1-v1_5-SHA-384",
        securityBits = 192,
        family = KeyFamily.Rsa,
        digest = DigestAlgorithm.Sha384,
    ),

    /**
     * RSASSA-PKCS1-v1_5 with SHA-512.
     *
     * @since 1.0.0
     */
    RsaPkcs1Sha512(
        algorithmName = "RSASSA-PKCS1-v1_5-SHA-512",
        securityBits = 256,
        family = KeyFamily.Rsa,
        digest = DigestAlgorithm.Sha512,
    ),

    /**
     * ML-DSA-44 of FIPS 204, on the JVM only.
     *
     * @since 1.0.0
     */
    MlDsa44(
        algorithmName = "ML-DSA-44",
        securityBits = 128,
        family = KeyFamily.MlDsa,
        digest = null,
        isPostQuantum = true,
    ),

    /**
     * ML-DSA-65 of FIPS 204, on the JVM only.
     *
     * @since 1.0.0
     */
    MlDsa65(
        algorithmName = "ML-DSA-65",
        securityBits = 192,
        family = KeyFamily.MlDsa,
        digest = null,
        isPostQuantum = true,
    ),

    /**
     * ML-DSA-87 of FIPS 204, on the JVM only.
     *
     * @since 1.0.0
     */
    MlDsa87(
        algorithmName = "ML-DSA-87",
        securityBits = 256,
        family = KeyFamily.MlDsa,
        digest = null,
        isPostQuantum = true,
    ),

    /**
     * RSASSA-PKCS1-v1_5 with SHA-1, only to verify old signatures.
     *
     * @since 1.0.0
     */
    @LegacyCryptography
    RsaPkcs1Sha1(
        algorithmName = "RSASSA-PKCS1-v1_5-SHA-1",
        securityBits = 0,
        family = KeyFamily.Rsa,
        digest = DigestAlgorithm.Sha1,
        isLegacy = true,
        isFipsApproved = false,
    ),

    /**
     * ECDSA with SHA-1, only to verify old signatures.
     *
     * @since 1.0.0
     */
    @LegacyCryptography
    EcdsaSha1(
        algorithmName = "ECDSA-SHA-1",
        securityBits = 0,
        family = KeyFamily.Ec,
        digest = DigestAlgorithm.Sha1,
        isLegacy = true,
        isFipsApproved = false,
    ),
}
