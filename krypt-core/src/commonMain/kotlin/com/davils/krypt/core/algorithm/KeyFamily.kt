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
 * The family of an asymmetric key, which decides the algorithms the key can be used with.
 *
 * @since 1.0.0
 */
public enum class KeyFamily {
    /**
     * An Ed25519 signing key of RFC 8032.
     *
     * @since 1.0.0
     */
    Ed25519,

    /**
     * An Ed448 signing key of RFC 8032.
     *
     * @since 1.0.0
     */
    Ed448,

    /**
     * An elliptic curve key on a NIST curve, for ECDSA or ECDH.
     *
     * @since 1.0.0
     */
    Ec,

    /**
     * An RSA key, for RSA-PSS, RSA PKCS #1 signatures or RSA-OAEP.
     *
     * @since 1.0.0
     */
    Rsa,

    /**
     * An X25519 key agreement key of RFC 7748.
     *
     * @since 1.0.0
     */
    X25519,

    /**
     * An X448 key agreement key of RFC 7748.
     *
     * @since 1.0.0
     */
    X448,

    /**
     * An ML-DSA signing key of FIPS 204.
     *
     * @since 1.0.0
     */
    MlDsa,

    /**
     * An ML-KEM decapsulation key of FIPS 203.
     *
     * @since 1.0.0
     */
    MlKem,
}
