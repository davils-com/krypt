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

import com.davils.krypt.jose.JoseKey
import com.davils.krypt.jose.JsonValue

/**
 * One recipient to encrypt to: the key, the key management algorithm and the header members to add.
 *
 * The key fits the algorithm: a symmetric key of the size of the content key for `dir`, of the size of the wrapping
 * key for the AES algorithms, an EC P-256, P-384, P-521, X25519 or X448 public key for ECDH-ES, an RSA public key for
 * RSA-OAEP-256 and a password for PBES2. [header] may carry `apu` and `apv` for ECDH-ES but must not set `alg`,
 * `enc` or a member krypt generates (`epk`, `iv`, `tag`, `p2s`, `p2c`).
 *
 * @property key the key of the recipient.
 * @property algorithm the key management algorithm.
 * @property header the header members of this recipient.
 * @property iterations the PBKDF2 iterations of PBES2, or null for the minimum of the crypto policy.
 * @since 1.0.0
 */
public class JweRecipient(
    public val key: JoseKey,
    public val algorithm: JweAlgorithm,
    public val header: JsonValue.Object = JsonValue.Object.Empty,
    public val iterations: Int? = null,
) {
    private val values: List<Any?> get() = listOf(key, algorithm, header, iterations)

    /**
     * Compares every property.
     *
     * @param other the other object.
     * @return true if [other] describes the same recipient.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is JweRecipient && values == other.values

    /**
     * Hashes every property.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = values.hashCode()

    /**
     * Shows the algorithm and the key, never secret material.
     *
     * @return the recipient as text.
     * @since 1.0.0
     */
    override fun toString(): String = "JweRecipient(${algorithm.algorithmName}, $key)"
}
