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

import com.davils.krypt.jose.JoseKey
import com.davils.krypt.jose.JsonValue

/**
 * One signature to make: the key, the algorithm and the header members to add.
 *
 * The protected header starts with `alg`, followed by the members of [header] and, unless a header already names
 * one, the `kid` of [key]. [header] must not set `alg` or `b64`, which [Jws] writes itself.
 *
 * @property key the private key, or the symmetric key of an HMAC.
 * @property algorithm the algorithm.
 * @property header the members of the protected header.
 * @property unprotectedHeader the members of the unprotected header, which only the JSON serialization carries.
 * @since 1.0.0
 */
public class JwsSigner(
    public val key: JoseKey,
    public val algorithm: JwsAlgorithm,
    public val header: JsonValue.Object = JsonValue.Object.Empty,
    public val unprotectedHeader: JsonValue.Object = JsonValue.Object.Empty,
) {
    private val values: List<Any> get() = listOf(key, algorithm, header, unprotectedHeader)

    /**
     * Compares every property.
     *
     * @param other the other object.
     * @return true if [other] makes the same signature.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is JwsSigner && values == other.values

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
     * @return the signer as text.
     * @since 1.0.0
     */
    override fun toString(): String = "JwsSigner(${algorithm.algorithmName}, $key)"
}
