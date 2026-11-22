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
import com.davils.krypt.cose.key.CoseKeyType

/**
 * A recipient to create for a COSE_Encrypt or a COSE_Mac: its key, how it receives the content key and the header
 * parameters of its layer.
 *
 * With [CoseAlgorithm.Direct] the symmetric [key] is the content key; with the AES key wraps the symmetric [key]
 * wraps a fresh content key; with ECDH-ES the public [key] of the recipient and a fresh ephemeral key derive the
 * content key or the key that wraps it, with the `salt` and the PartyU and PartyV parameters of [unprotectedHeaders]
 * or [protectedHeaders] in the context of RFC 9053 section 5.2. Direct and direct key agreement allow only one
 * recipient. The protected bucket of direct and key wrap recipients stays empty, as RFC 9053 demands.
 *
 * @property key the key of the recipient.
 * @property algorithm the key distribution algorithm.
 * @property protectedHeaders the protected header parameters of the recipient.
 * @property unprotectedHeaders the unprotected header parameters of the recipient.
 * @constructor Describes a recipient.
 * @throws IllegalArgumentException if [algorithm] does not distribute keys, [key] does not fit it, or a direct or key
 *   wrap recipient has protected header parameters.
 * @since 1.0.0
 */
public class CoseRecipientSpec(
    public val key: CoseKey,
    public val algorithm: CoseAlgorithm,
    public val protectedHeaders: CoseHeaders = CoseHeaders.Empty,
    public val unprotectedHeaders: CoseHeaders = CoseHeaders.Empty,
) {
    private val values: List<Any> get() = listOf(key, algorithm, protectedHeaders, unprotectedHeaders)

    init {
        require(algorithm.kind == CoseAlgorithmKind.KeyDistribution) { "${algorithm.algorithmName} gives no key" }
        val isAgreement = algorithm.kdf != null
        val isFit = KeyFit.canAgree(key, algorithm).takeIf { isAgreement } ?: (key.type == CoseKeyType.Symmetric)
        require(isFit && KeyFit.isTypeFit(key, algorithm)) { "The key does not fit ${algorithm.algorithmName}" }
        require(isAgreement || protectedHeaders.isEmpty) { "A direct or key wrap recipient has no protected header" }
    }

    /**
     * Compares the key, the algorithm and the headers.
     *
     * @param other the other object.
     * @return true if [other] is the same recipient.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is CoseRecipientSpec && values == other.values

    /**
     * Hashes the key, the algorithm and the headers.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = values.hashCode()

    /**
     * Shows the key, never its secret part, the algorithm and the headers.
     *
     * @return the recipient as text.
     * @since 1.0.0
     */
    override fun toString(): String =
        "CoseRecipientSpec($key, ${algorithm.algorithmName}, protected=$protectedHeaders, " +
            "unprotected=$unprotectedHeaders)"
}
