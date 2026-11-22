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

/**
 * The key types of RFC 7518 and RFC 8037, the `kty` member of a JWK.
 *
 * @property typeName the name in a JWK.
 * @since 1.0.0
 */
public enum class JwkType(public val typeName: String) {
    /**
     * An elliptic curve key on P-256, P-384 or P-521.
     *
     * @since 1.0.0
     */
    Ec("EC"),

    /**
     * An octet key pair of RFC 8037: Ed25519, Ed448, X25519 or X448.
     *
     * @since 1.0.0
     */
    Okp("OKP"),

    /**
     * An RSA key.
     *
     * @since 1.0.0
     */
    Rsa("RSA"),

    /**
     * A symmetric key, an octet sequence.
     *
     * @since 1.0.0
     */
    Oct("oct"),
    ;

    /**
     * The lookup by name.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * Returns the key type named [name], case-sensitively.
         *
         * @param name the name in a JWK.
         * @return the type, or null if krypt does not know it.
         * @since 1.0.0
         */
        public fun of(name: String): JwkType? = entries.firstOrNull { type -> type.typeName == name }
    }
}
