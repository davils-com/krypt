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

package com.davils.krypt.jose.jwt

import com.davils.krypt.jose.JoseHeader
import com.davils.krypt.jose.JoseKey
import com.davils.krypt.jose.jws.JwsAlgorithm

/**
 * A token that passed every check of its [JwtValidator].
 *
 * @property claims the claims.
 * @property header the header of the signed token, or of the encrypted one if it is not signed.
 * @property algorithm the signature algorithm, or null for a token that is only encrypted.
 * @property key the key that verified the signature, or that decrypted a token that is only encrypted.
 * @property isEncrypted whether the token was encrypted.
 * @since 1.0.0
 */
public class ValidatedJwt internal constructor(
    public val claims: JwtClaims,
    public val header: JoseHeader,
    public val algorithm: JwsAlgorithm?,
    public val key: JoseKey,
    public val isEncrypted: Boolean,
) {
    private val values: List<Any?> get() = listOf(claims, header, algorithm, key, isEncrypted)

    /**
     * Compares every property.
     *
     * @param other the other object.
     * @return true if [other] is the same result.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is ValidatedJwt && values == other.values

    /**
     * Hashes every property.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = values.hashCode()

    /**
     * Shows the claim names, the algorithm and the key.
     *
     * @return the result as text.
     * @since 1.0.0
     */
    override fun toString(): String =
        "ValidatedJwt($claims, ${algorithm?.algorithmName ?: UNSIGNED}, $key, encrypted=$isEncrypted)"

    private companion object {
        const val UNSIGNED: String = "unsigned"
    }
}
