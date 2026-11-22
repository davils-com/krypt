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
import com.davils.krypt.core.algorithm.KdfAlgorithm
import com.davils.krypt.core.algorithm.KeyWrapAlgorithm

/**
 * The key management algorithms of a JWE, the `alg` header of RFC 7518.
 *
 * RSA1_5 and RSA-OAEP with SHA-1 are not offered.
 *
 * @property algorithmName the name in the `alg` header.
 * @property wrap the AES key wrap of the algorithm, or null.
 * @property gcm the AES-GCM of the GCM key wrapping, or null.
 * @property kdf the PBKDF2 of PBES2, or null.
 * @property isAgreement whether the algorithm is ECDH-ES.
 * @since 1.0.0
 */
public enum class JweAlgorithm(
    public val algorithmName: String,
    internal val wrap: KeyWrapAlgorithm? = null,
    internal val gcm: AeadAlgorithm? = null,
    internal val kdf: KdfAlgorithm? = null,
    internal val isAgreement: Boolean = false,
) {
    /**
     * The shared symmetric key is the content encryption key.
     *
     * @since 1.0.0
     */
    Dir("dir"),

    /**
     * AES key wrap with a key of 128 bits.
     *
     * @since 1.0.0
     */
    A128KW("A128KW", wrap = KeyWrapAlgorithm.Aes128Kw),

    /**
     * AES key wrap with a key of 256 bits.
     *
     * @since 1.0.0
     */
    A256KW("A256KW", wrap = KeyWrapAlgorithm.Aes256Kw),

    /**
     * AES-GCM key wrapping with a key of 128 bits; the IV and the tag go into the header.
     *
     * @since 1.0.0
     */
    A128GCMKW("A128GCMKW", gcm = AeadAlgorithm.Aes128Gcm),

    /**
     * AES-GCM key wrapping with a key of 256 bits; the IV and the tag go into the header.
     *
     * @since 1.0.0
     */
    A256GCMKW("A256GCMKW", gcm = AeadAlgorithm.Aes256Gcm),

    /**
     * Ephemeral-static ECDH with the Concat KDF, whose output is the content encryption key.
     *
     * @since 1.0.0
     */
    EcdhEs("ECDH-ES", isAgreement = true),

    /**
     * Ephemeral-static ECDH with the Concat KDF, whose output wraps the key with AES key wrap of 128 bits.
     *
     * @since 1.0.0
     */
    EcdhEsA128KW("ECDH-ES+A128KW", wrap = KeyWrapAlgorithm.Aes128Kw, isAgreement = true),

    /**
     * Ephemeral-static ECDH with the Concat KDF, whose output wraps the key with AES key wrap of 256 bits.
     *
     * @since 1.0.0
     */
    EcdhEsA256KW("ECDH-ES+A256KW", wrap = KeyWrapAlgorithm.Aes256Kw, isAgreement = true),

    /**
     * RSAES-OAEP with SHA-256 and MGF1 with SHA-256.
     *
     * @since 1.0.0
     */
    RsaOaep256("RSA-OAEP-256"),

    /**
     * PBES2 with HMAC-SHA-256 and AES key wrap of 128 bits; needs the opt-in of
     * [Jwe.isPasswordAllowed].
     *
     * @since 1.0.0
     */
    Pbes2Hs256A128KW("PBES2-HS256+A128KW", wrap = KeyWrapAlgorithm.Aes128Kw, kdf = KdfAlgorithm.Pbkdf2Sha256),

    /**
     * PBES2 with HMAC-SHA-512 and AES key wrap of 256 bits; needs the opt-in of
     * [Jwe.isPasswordAllowed].
     *
     * @since 1.0.0
     */
    Pbes2Hs512A256KW("PBES2-HS512+A256KW", wrap = KeyWrapAlgorithm.Aes256Kw, kdf = KdfAlgorithm.Pbkdf2Sha512),
    ;

    /**
     * Tells whether the algorithm determines the content encryption key itself, so that a message has only this
     * recipient: `dir` and `ECDH-ES`.
     *
     * @since 1.0.0
     */
    public val isDirect: Boolean get() = this == Dir || this == EcdhEs

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
         * @return the algorithm, or null if krypt does not offer it.
         * @since 1.0.0
         */
        public fun of(name: String): JweAlgorithm? =
            entries.firstOrNull { algorithm -> algorithm.algorithmName == name }
    }
}
