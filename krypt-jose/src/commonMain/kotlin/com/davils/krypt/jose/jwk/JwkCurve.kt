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

package com.davils.krypt.jose.jwk

import com.davils.krypt.core.algorithm.EllipticCurve
import com.davils.krypt.core.algorithm.KeyFamily

/**
 * The curves of a JWK, the `crv` member of RFC 7518 and RFC 8037.
 *
 * @property curveName the name in a JWK.
 * @property type the key type the curve belongs to.
 * @property family the key family of krypt.
 * @property publicBytes the size of a coordinate of an EC key or of the public key of an OKP key.
 * @property privateBytes the size of the private key.
 * @since 1.0.0
 */
public enum class JwkCurve(
    public val curveName: String,
    public val type: JwkType,
    public val family: KeyFamily,
    public val publicBytes: Int,
    public val privateBytes: Int,
) {
    /**
     * NIST P-256.
     *
     * @since 1.0.0
     */
    P256(curveName = "P-256", type = JwkType.Ec, family = KeyFamily.Ec, publicBytes = 32, privateBytes = 32),

    /**
     * NIST P-384.
     *
     * @since 1.0.0
     */
    P384(curveName = "P-384", type = JwkType.Ec, family = KeyFamily.Ec, publicBytes = 48, privateBytes = 48),

    /**
     * NIST P-521.
     *
     * @since 1.0.0
     */
    P521(curveName = "P-521", type = JwkType.Ec, family = KeyFamily.Ec, publicBytes = 66, privateBytes = 66),

    /**
     * Ed25519 of RFC 8032.
     *
     * @since 1.0.0
     */
    Ed25519(
        curveName = "Ed25519",
        type = JwkType.Okp,
        family = KeyFamily.Ed25519,
        publicBytes = 32,
        privateBytes = 32,
    ),

    /**
     * Ed448 of RFC 8032.
     *
     * @since 1.0.0
     */
    Ed448(curveName = "Ed448", type = JwkType.Okp, family = KeyFamily.Ed448, publicBytes = 57, privateBytes = 57),

    /**
     * X25519 of RFC 7748.
     *
     * @since 1.0.0
     */
    X25519(curveName = "X25519", type = JwkType.Okp, family = KeyFamily.X25519, publicBytes = 32, privateBytes = 32),

    /**
     * X448 of RFC 7748.
     *
     * @since 1.0.0
     */
    X448(curveName = "X448", type = JwkType.Okp, family = KeyFamily.X448, publicBytes = 56, privateBytes = 56),
    ;

    /**
     * The elliptic curve of krypt for an EC curve, null for an OKP curve.
     *
     * @since 1.0.0
     */
    public val ellipticCurve: EllipticCurve?
        get() = EllipticCurve.entries.firstOrNull { curve -> curve.curveName == curveName }

    /**
     * The lookup by name and by key.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * Returns the curve named [name], case-sensitively.
         *
         * @param name the name in a JWK.
         * @return the curve, or null if krypt does not know it.
         * @since 1.0.0
         */
        public fun of(name: String): JwkCurve? = entries.firstOrNull { curve -> curve.curveName == name }

        /**
         * Returns the curve of a key of [family] on [curve].
         *
         * @param family the key family.
         * @param curve the elliptic curve of an EC key, or null.
         * @return the curve, or null for RSA and the families JOSE has no curve for.
         * @since 1.0.0
         */
        public fun of(family: KeyFamily, curve: EllipticCurve?): JwkCurve? =
            entries.firstOrNull { candidate -> candidate.family == family && candidate.ellipticCurve == curve }
    }
}
