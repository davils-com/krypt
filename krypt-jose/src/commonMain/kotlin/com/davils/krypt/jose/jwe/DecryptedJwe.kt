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

import com.davils.krypt.jose.JoseHeader
import com.davils.krypt.jose.JoseKey
import kotlinx.io.bytestring.ByteString

/**
 * A JWE that decrypted.
 *
 * @property plaintext the plaintext, now authentic as far as the key management authenticates its sender: anyone may
 *   encrypt to a public key.
 * @property header the JOSE header of the recipient that decrypted.
 * @property algorithm the key management algorithm.
 * @property encryption the content encryption.
 * @property key the key that decrypted.
 * @since 1.0.0
 */
public class DecryptedJwe internal constructor(
    public val plaintext: ByteString,
    public val header: JoseHeader,
    public val algorithm: JweAlgorithm,
    public val encryption: JweEncryption,
    public val key: JoseKey,
) {
    private val values: List<Any> get() = listOf(plaintext, header, algorithm, encryption, key)

    /**
     * Compares every property.
     *
     * @param other the other object.
     * @return true if [other] is the same result.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is DecryptedJwe && values == other.values

    /**
     * Hashes every property.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = values.hashCode()

    /**
     * Shows the algorithms, the key and the size of the plaintext, never the plaintext.
     *
     * @return the result as text.
     * @since 1.0.0
     */
    override fun toString(): String = "DecryptedJwe(${algorithm.algorithmName}, ${encryption.algorithmName}, $key, " +
        "plaintext=${plaintext.size})"
}
