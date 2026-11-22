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

package com.davils.krypt.cose

import com.davils.krypt.cose.internal.KeyFit
import com.davils.krypt.cose.key.CoseKey

/**
 * A signer of a COSE_Sign1 or a COSE_Sign: its key, its algorithm and the header parameters of its layer.
 *
 * [Cose] adds the algorithm to the protected header parameters and the key id of [key] to the unprotected ones unless
 * they are given already.
 *
 * @property key the key, with a private key that fits [algorithm].
 * @property algorithm the signature algorithm.
 * @property protectedHeaders the protected header parameters of the signer.
 * @property unprotectedHeaders the unprotected header parameters of the signer.
 * @constructor Describes a signer.
 * @throws IllegalArgumentException if [algorithm] is not a signature algorithm or [key] cannot sign with it.
 * @since 1.0.0
 */
public class CoseSigner(
    public val key: CoseKey,
    public val algorithm: CoseAlgorithm,
    public val protectedHeaders: CoseHeaders = CoseHeaders.Empty,
    public val unprotectedHeaders: CoseHeaders = CoseHeaders.Empty,
) {
    private val values: List<Any> get() = listOf(key, algorithm, protectedHeaders, unprotectedHeaders)

    init {
        require(algorithm.kind == CoseAlgorithmKind.Signature) { "${algorithm.algorithmName} does not sign" }
        require(KeyFit.canSign(key, algorithm)) { "The key cannot sign with ${algorithm.algorithmName}" }
    }

    /**
     * Compares the key, the algorithm and the headers.
     *
     * @param other the other object.
     * @return true if [other] is the same signer.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is CoseSigner && values == other.values

    /**
     * Hashes the key, the algorithm and the headers.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = values.hashCode()

    /**
     * Shows the key, never its private part, the algorithm and the headers.
     *
     * @return the signer as text.
     * @since 1.0.0
     */
    override fun toString(): String =
        "CoseSigner($key, ${algorithm.algorithmName}, protected=$protectedHeaders, unprotected=$unprotectedHeaders)"
}
