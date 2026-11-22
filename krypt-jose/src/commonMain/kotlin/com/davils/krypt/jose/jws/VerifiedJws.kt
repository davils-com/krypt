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

import com.davils.krypt.jose.JoseHeader
import com.davils.krypt.jose.JoseKey
import kotlinx.io.bytestring.ByteString

/**
 * A JWS whose signature verified.
 *
 * @property payload the payload, now authentic.
 * @property header the JOSE header of the signature that verified; only its protected members are authentic.
 * @property algorithm the algorithm of the signature.
 * @property key the key that verified it.
 * @since 1.0.0
 */
public class VerifiedJws internal constructor(
    public val payload: ByteString,
    public val header: JoseHeader,
    public val algorithm: JwsAlgorithm,
    public val key: JoseKey,
) {
    private val values: List<Any> get() = listOf(payload, header, algorithm, key)

    /**
     * Compares every property.
     *
     * @param other the other object.
     * @return true if [other] is the same result.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is VerifiedJws && values == other.values

    /**
     * Hashes every property.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = values.hashCode()

    /**
     * Shows the algorithm, the key and the size of the payload.
     *
     * @return the result as text.
     * @since 1.0.0
     */
    override fun toString(): String = "VerifiedJws(${algorithm.algorithmName}, $key, payload=${payload.size})"
}
