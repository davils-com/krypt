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

@file:OptIn(DavilsInternal::class)

package com.davils.krypt.acme.account

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.text.SafeText
import com.davils.krypt.jose.jws.JwsAlgorithm
import com.davils.krypt.primitive.key.SecretKey

/**
 * The binding of a new ACME account to an account the CA keeps elsewhere, by RFC 8555 section 7.3.4: the CA hands
 * out a key id and a MAC key, and the client signs its account key with them.
 *
 * The MAC key stays with the caller, who destroys it. Values are immutable and safe to share between threads.
 *
 * @property keyId the key id the CA handed out.
 * @property key the MAC key the CA handed out.
 * @property algorithm the MAC algorithm; `HS256` by default.
 * @constructor Checks the key id and the algorithm.
 * @throws IllegalArgumentException if [keyId] is empty or [algorithm] is no MAC algorithm.
 * @since 1.0.0
 */
public class ExternalAccountBinding(
    public val keyId: String,
    public val key: SecretKey,
    public val algorithm: JwsAlgorithm = JwsAlgorithm.HS256,
) {
    init {
        require(keyId.isNotEmpty()) { "An external account binding has a key id" }
        require(algorithm in MAC_ALGORITHMS) { "An external account binding uses HS256, HS384 or HS512" }
    }

    /**
     * Compares the key id, the key and the algorithm.
     *
     * @param other the other object.
     * @return true if [other] is the same binding.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean =
        other is ExternalAccountBinding && keyId == other.keyId && key == other.key && algorithm == other.algorithm

    /**
     * Hashes the key id and the algorithm, never the key.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = listOf(keyId, algorithm).hashCode()

    /**
     * Shows the key id and the algorithm, never the key.
     *
     * @return the binding as text.
     * @since 1.0.0
     */
    override fun toString(): String =
        "ExternalAccountBinding(${SafeText.text(keyId)}, ${algorithm.algorithmName}, ${SafeText.REDACTED})"

    private companion object {
        val MAC_ALGORITHMS: Set<JwsAlgorithm> = setOf(JwsAlgorithm.HS256, JwsAlgorithm.HS384, JwsAlgorithm.HS512)
    }
}
