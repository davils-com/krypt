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
 * A NIST prime curve of FIPS 186-5 for ECDSA and ECDH.
 *
 * @property curveName the name of the curve, such as `P-256`.
 * @property objectIdentifier the dotted object identifier of the named curve.
 * @property fieldBytes the length of a field element and of a scalar in bytes.
 * @property bits the size of the order of the curve in bits.
 * @property securityBits the security strength in bits.
 * @since 1.0.0
 */
public enum class EllipticCurve(
    public val curveName: String,
    public val objectIdentifier: String,
    public val fieldBytes: Int,
    public val bits: Int,
    public val securityBits: Int,
) {
    /**
     * P-256, also known as secp256r1 or prime256v1.
     *
     * @since 1.0.0
     */
    P256(
        curveName = "P-256",
        objectIdentifier = "1.2.840.10045.3.1.7",
        fieldBytes = 32,
        bits = 256,
        securityBits = 128,
    ),

    /**
     * P-384, also known as secp384r1.
     *
     * @since 1.0.0
     */
    P384(curveName = "P-384", objectIdentifier = "1.3.132.0.34", fieldBytes = 48, bits = 384, securityBits = 192),

    /**
     * P-521, also known as secp521r1.
     *
     * @since 1.0.0
     */
    P521(curveName = "P-521", objectIdentifier = "1.3.132.0.35", fieldBytes = 66, bits = 521, securityBits = 256),
}
