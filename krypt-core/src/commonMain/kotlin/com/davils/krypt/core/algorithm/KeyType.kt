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
 * What to generate for a new asymmetric key pair.
 *
 * @property family the family of the key.
 * @property bits the size of the key in bits: the modulus of RSA, the order of a curve or the security category of
 *   ML-DSA and ML-KEM.
 * @property curve the curve of an elliptic curve key, or null.
 * @since 1.0.0
 */
public enum class KeyType(
    public val family: KeyFamily,
    public val bits: Int,
    public val curve: EllipticCurve?,
) {
    /**
     * An Ed25519 signing key, the default.
     *
     * @since 1.0.0
     */
    Ed25519(
        family = KeyFamily.Ed25519,
        bits = 256,
        curve = null,
    ),

    /**
     * An Ed448 signing key, on the JVM only.
     *
     * @since 1.0.0
     */
    Ed448(
        family = KeyFamily.Ed448,
        bits = 456,
        curve = null,
    ),

    /**
     * A P-256 key for ECDSA and ECDH.
     *
     * @since 1.0.0
     */
    P256(
        family = KeyFamily.Ec,
        bits = 256,
        curve = EllipticCurve.P256,
    ),

    /**
     * A P-384 key for ECDSA and ECDH.
     *
     * @since 1.0.0
     */
    P384(
        family = KeyFamily.Ec,
        bits = 384,
        curve = EllipticCurve.P384,
    ),

    /**
     * A P-521 key for ECDSA and ECDH.
     *
     * @since 1.0.0
     */
    P521(
        family = KeyFamily.Ec,
        bits = 521,
        curve = EllipticCurve.P521,
    ),

    /**
     * A 2048-bit RSA key, the smallest any profile permits.
     *
     * @since 1.0.0
     */
    Rsa2048(
        family = KeyFamily.Rsa,
        bits = 2048,
        curve = null,
    ),

    /**
     * A 3072-bit RSA key.
     *
     * @since 1.0.0
     */
    Rsa3072(
        family = KeyFamily.Rsa,
        bits = 3072,
        curve = null,
    ),

    /**
     * A 4096-bit RSA key.
     *
     * @since 1.0.0
     */
    Rsa4096(
        family = KeyFamily.Rsa,
        bits = 4096,
        curve = null,
    ),

    /**
     * An X25519 key agreement key.
     *
     * @since 1.0.0
     */
    X25519(
        family = KeyFamily.X25519,
        bits = 256,
        curve = null,
    ),

    /**
     * An X448 key agreement key, on the JVM only.
     *
     * @since 1.0.0
     */
    X448(
        family = KeyFamily.X448,
        bits = 448,
        curve = null,
    ),

    /**
     * An ML-DSA-44 signing key, on the JVM only.
     *
     * @since 1.0.0
     */
    MlDsa44(
        family = KeyFamily.MlDsa,
        bits = 44,
        curve = null,
    ),

    /**
     * An ML-DSA-65 signing key, on the JVM only.
     *
     * @since 1.0.0
     */
    MlDsa65(
        family = KeyFamily.MlDsa,
        bits = 65,
        curve = null,
    ),

    /**
     * An ML-DSA-87 signing key, on the JVM only.
     *
     * @since 1.0.0
     */
    MlDsa87(
        family = KeyFamily.MlDsa,
        bits = 87,
        curve = null,
    ),

    /**
     * An ML-KEM-768 decapsulation key, on the JVM only.
     *
     * @since 1.0.0
     */
    MlKem768(
        family = KeyFamily.MlKem,
        bits = 768,
        curve = null,
    ),

    /**
     * An ML-KEM-1024 decapsulation key, on the JVM only.
     *
     * @since 1.0.0
     */
    MlKem1024(
        family = KeyFamily.MlKem,
        bits = 1024,
        curve = null,
    ),
}
