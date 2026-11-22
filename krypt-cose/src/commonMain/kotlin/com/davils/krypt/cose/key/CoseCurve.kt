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

package com.davils.krypt.cose.key

import com.davils.krypt.core.algorithm.EllipticCurve
import com.davils.krypt.core.algorithm.KeyFamily

/**
 * An elliptic curve of the COSE registry, the `crv` of a COSE_Key.
 *
 * @property id the value of the curve in the COSE registry.
 * @property keyType the key type the curve belongs to.
 * @property family the family of the keys of krypt on this curve.
 * @property curve the Weierstrass curve of krypt, or null for an Edwards or Montgomery curve.
 * @property size the length of a coordinate or of an encoded key in bytes.
 * @since 1.0.0
 */
public enum class CoseCurve(
    public val id: Long,
    public val keyType: CoseKeyType,
    public val family: KeyFamily,
    public val curve: EllipticCurve?,
    public val size: Int,
) {
    /**
     * NIST P-256.
     *
     * @since 1.0.0
     */
    P256(id = 1, keyType = CoseKeyType.Ec2, family = KeyFamily.Ec, curve = EllipticCurve.P256, size = 32),

    /**
     * NIST P-384.
     *
     * @since 1.0.0
     */
    P384(id = 2, keyType = CoseKeyType.Ec2, family = KeyFamily.Ec, curve = EllipticCurve.P384, size = 48),

    /**
     * NIST P-521.
     *
     * @since 1.0.0
     */
    P521(id = 3, keyType = CoseKeyType.Ec2, family = KeyFamily.Ec, curve = EllipticCurve.P521, size = 66),

    /**
     * X25519 of RFC 7748, for key agreement.
     *
     * @since 1.0.0
     */
    X25519(id = 4, keyType = CoseKeyType.Okp, family = KeyFamily.X25519, curve = null, size = 32),

    /**
     * X448 of RFC 7748, for key agreement.
     *
     * @since 1.0.0
     */
    X448(id = 5, keyType = CoseKeyType.Okp, family = KeyFamily.X448, curve = null, size = 56),

    /**
     * Ed25519 of RFC 8032, for signatures.
     *
     * @since 1.0.0
     */
    Ed25519(id = 6, keyType = CoseKeyType.Okp, family = KeyFamily.Ed25519, curve = null, size = 32),

    /**
     * Ed448 of RFC 8032, for signatures.
     *
     * @since 1.0.0
     */
    Ed448(id = 7, keyType = CoseKeyType.Okp, family = KeyFamily.Ed448, curve = null, size = 57),
}
