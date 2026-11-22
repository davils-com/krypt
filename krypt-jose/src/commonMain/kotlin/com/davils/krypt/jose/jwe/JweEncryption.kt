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

package com.davils.krypt.jose.jwe

import com.davils.krypt.core.algorithm.AeadAlgorithm
import com.davils.krypt.core.algorithm.MacAlgorithm

/**
 * The content encryption algorithms of a JWE, the `enc` header of RFC 7518.
 *
 * @property algorithmName the name in the `enc` header.
 * @property keyBytes the size of the content encryption key.
 * @property ivBytes the size of the initialization vector.
 * @property tagBytes the size of the authentication tag.
 * @property aead the AES-GCM of the algorithm, or null.
 * @property mac the HMAC of the algorithm, or null.
 * @since 1.0.0
 */
public enum class JweEncryption(
    public val algorithmName: String,
    public val keyBytes: Int,
    public val ivBytes: Int,
    public val tagBytes: Int,
    internal val aead: AeadAlgorithm? = null,
    internal val mac: MacAlgorithm? = null,
) {
    /**
     * AES-GCM with a key of 128 bits.
     *
     * @since 1.0.0
     */
    A128GCM("A128GCM", keyBytes = 16, ivBytes = 12, tagBytes = 16, aead = AeadAlgorithm.Aes128Gcm),

    /**
     * AES-GCM with a key of 256 bits.
     *
     * @since 1.0.0
     */
    A256GCM("A256GCM", keyBytes = 32, ivBytes = 12, tagBytes = 16, aead = AeadAlgorithm.Aes256Gcm),

    /**
     * AES-128-CBC with HMAC-SHA-256 truncated to 128 bits, encrypt-then-MAC.
     *
     * @since 1.0.0
     */
    A128CBC_HS256("A128CBC-HS256", keyBytes = 32, ivBytes = 16, tagBytes = 16, mac = MacAlgorithm.HmacSha256),

    /**
     * AES-256-CBC with HMAC-SHA-512 truncated to 256 bits, encrypt-then-MAC.
     *
     * @since 1.0.0
     */
    A256CBC_HS512("A256CBC-HS512", keyBytes = 64, ivBytes = 16, tagBytes = 32, mac = MacAlgorithm.HmacSha512),
    ;

    /**
     * The lookup by name.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * Returns the content encryption named [name], case-sensitively.
         *
         * @param name the name in the `enc` header.
         * @return the algorithm, or null if krypt does not offer it.
         * @since 1.0.0
         */
        public fun of(name: String): JweEncryption? =
            entries.firstOrNull { encryption -> encryption.algorithmName == name }
    }
}
