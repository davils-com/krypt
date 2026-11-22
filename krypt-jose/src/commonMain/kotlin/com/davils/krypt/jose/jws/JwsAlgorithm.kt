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

package com.davils.krypt.jose.jws

import com.davils.krypt.core.algorithm.EllipticCurve
import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.core.algorithm.MacAlgorithm
import com.davils.krypt.core.algorithm.SignatureAlgorithm

/**
 * The signature and MAC algorithms of a JWS, from RFC 7518, RFC 8037 and RFC 9864.
 *
 * `none` is not among them: krypt never accepts an unsecured JWS.
 *
 * @property algorithmName the name in the `alg` header.
 * @property mac the HMAC of the algorithm, or null.
 * @property signatures the signature algorithm for each key family that fits.
 * @property curve the curve an ECDSA key must be on, or null.
 * @since 1.0.0
 */
public enum class JwsAlgorithm(
    public val algorithmName: String,
    internal val mac: MacAlgorithm? = null,
    internal val signatures: Map<KeyFamily, SignatureAlgorithm> = emptyMap(),
    internal val curve: EllipticCurve? = null,
) {
    /**
     * HMAC with SHA-256, with a key of at least 32 bytes.
     *
     * @since 1.0.0
     */
    HS256("HS256", mac = MacAlgorithm.HmacSha256),

    /**
     * HMAC with SHA-384, with a key of at least 48 bytes.
     *
     * @since 1.0.0
     */
    HS384("HS384", mac = MacAlgorithm.HmacSha384),

    /**
     * HMAC with SHA-512, with a key of at least 64 bytes.
     *
     * @since 1.0.0
     */
    HS512("HS512", mac = MacAlgorithm.HmacSha512),

    /**
     * RSASSA-PKCS1-v1_5 with SHA-256.
     *
     * @since 1.0.0
     */
    RS256("RS256", signatures = mapOf(KeyFamily.Rsa to SignatureAlgorithm.RsaPkcs1Sha256)),

    /**
     * RSASSA-PKCS1-v1_5 with SHA-384.
     *
     * @since 1.0.0
     */
    RS384("RS384", signatures = mapOf(KeyFamily.Rsa to SignatureAlgorithm.RsaPkcs1Sha384)),

    /**
     * RSASSA-PKCS1-v1_5 with SHA-512.
     *
     * @since 1.0.0
     */
    RS512("RS512", signatures = mapOf(KeyFamily.Rsa to SignatureAlgorithm.RsaPkcs1Sha512)),

    /**
     * RSASSA-PSS with SHA-256 and MGF1 with SHA-256.
     *
     * @since 1.0.0
     */
    PS256("PS256", signatures = mapOf(KeyFamily.Rsa to SignatureAlgorithm.RsaPssSha256)),

    /**
     * RSASSA-PSS with SHA-384 and MGF1 with SHA-384.
     *
     * @since 1.0.0
     */
    PS384("PS384", signatures = mapOf(KeyFamily.Rsa to SignatureAlgorithm.RsaPssSha384)),

    /**
     * RSASSA-PSS with SHA-512 and MGF1 with SHA-512.
     *
     * @since 1.0.0
     */
    PS512("PS512", signatures = mapOf(KeyFamily.Rsa to SignatureAlgorithm.RsaPssSha512)),

    /**
     * ECDSA on P-256 with SHA-256.
     *
     * @since 1.0.0
     */
    ES256("ES256", signatures = mapOf(KeyFamily.Ec to SignatureAlgorithm.EcdsaSha256), curve = EllipticCurve.P256),

    /**
     * ECDSA on P-384 with SHA-384.
     *
     * @since 1.0.0
     */
    ES384("ES384", signatures = mapOf(KeyFamily.Ec to SignatureAlgorithm.EcdsaSha384), curve = EllipticCurve.P384),

    /**
     * ECDSA on P-521 with SHA-512.
     *
     * @since 1.0.0
     */
    ES512("ES512", signatures = mapOf(KeyFamily.Ec to SignatureAlgorithm.EcdsaSha512), curve = EllipticCurve.P521),

    /**
     * EdDSA of RFC 8037 with an Ed25519 or an Ed448 key; RFC 9864 deprecates it in favour of [Ed25519] and
     * [Ed448], which name the curve.
     *
     * @since 1.0.0
     */
    EdDSA(
        "EdDSA",
        signatures = mapOf(
            KeyFamily.Ed25519 to SignatureAlgorithm.Ed25519,
            KeyFamily.Ed448 to SignatureAlgorithm.Ed448,
        ),
    ),

    /**
     * EdDSA with Ed25519, fully specified by RFC 9864.
     *
     * @since 1.0.0
     */
    Ed25519("Ed25519", signatures = mapOf(KeyFamily.Ed25519 to SignatureAlgorithm.Ed25519)),

    /**
     * EdDSA with Ed448, fully specified by RFC 9864.
     *
     * @since 1.0.0
     */
    Ed448("Ed448", signatures = mapOf(KeyFamily.Ed448 to SignatureAlgorithm.Ed448)),
    ;

    /**
     * The lookup by name.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * Returns the algorithm named [name], case-sensitively.
         *
         * @param name the name in the `alg` header.
         * @return the algorithm, or null if krypt does not know it, as for `none`.
         * @since 1.0.0
         */
        public fun of(name: String): JwsAlgorithm? =
            entries.firstOrNull { algorithm -> algorithm.algorithmName == name }
    }
}
