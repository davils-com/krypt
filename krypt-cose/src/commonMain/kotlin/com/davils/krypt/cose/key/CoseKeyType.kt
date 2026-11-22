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

/**
 * A key type of the COSE registry, the `kty` of a COSE_Key.
 *
 * @property id the value of the key type in the COSE registry.
 * @since 1.0.0
 */
public enum class CoseKeyType(public val id: Long) {
    /**
     * An octet key pair of RFC 9053: Ed25519, Ed448, X25519 or X448.
     *
     * @since 1.0.0
     */
    Okp(id = 1),

    /**
     * An elliptic curve key with x- and y-coordinates of RFC 9053: P-256, P-384 or P-521.
     *
     * @since 1.0.0
     */
    Ec2(id = 2),

    /**
     * An RSA key of RFC 8230.
     *
     * @since 1.0.0
     */
    Rsa(id = 3),

    /**
     * A symmetric key of RFC 9053.
     *
     * @since 1.0.0
     */
    Symmetric(id = 4),
}
