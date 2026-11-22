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

package com.davils.krypt.spiffe.x509

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.flatMap
import com.davils.kore.core.text.SafeText
import com.davils.krypt.primitive.key.PrivateKey
import com.davils.krypt.spiffe.SpiffeId
import com.davils.krypt.spiffe.SpiffeLimits
import com.davils.krypt.x509.Certificate

private const val NO_HINT: String = "none"

/**
 * An X.509-SVID of the workload itself: its SPIFFE id, its chain and its private key, as the SPIFFE Workload API
 * delivers it.
 *
 * [of] checks the chain by [X509SvidRules] but does not validate its path, which is the business of the peers. The
 * private key stays with the caller: the SVID never destroys or copies it, and its [toString] never shows it. The
 * object is immutable and safe to share between threads.
 *
 * @property id the SPIFFE id of the leaf.
 * @property privateKey the private key of the leaf.
 * @property hint the hint of the Workload API that tells several SVIDs apart, or null.
 * @since 1.0.0
 */
public class X509Svid private constructor(
    public val id: SpiffeId,
    chain: List<Certificate>,
    public val privateKey: PrivateKey,
    public val hint: String?,
) {
    /**
     * The chain, the leaf first, then the intermediates, without the root.
     *
     * @since 1.0.0
     */
    public val chain: List<Certificate> = chain.toList()

    /**
     * The leaf.
     *
     * @since 1.0.0
     */
    public val certificate: Certificate get() = chain.first()

    /**
     * Compares the chain, the key and the hint.
     *
     * @param other the other object.
     * @return true if [other] is the same SVID with the same private key object.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean =
        other is X509Svid && chain == other.chain && privateKey == other.privateKey && hint == other.hint

    /**
     * Hashes the chain and the hint.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = listOf(chain, hint).hashCode()

    /**
     * Shows the id, the length of the chain and the hint, never the key.
     *
     * @return the SVID as text.
     * @since 1.0.0
     */
    override fun toString(): String =
        "X509Svid($id, ${chain.size} certificates, hint=${SafeText.text(hint ?: NO_HINT)}, key=${SafeText.REDACTED})"

    /**
     * Building SVIDs.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The longest hint, the length section 5 of the Workload API specification advises against exceeding.
         *
         * @since 1.0.0
         */
        public const val MAXIMUM_HINT_LENGTH: Int = 1_024

        /**
         * Checks [chain] and [privateKey] and builds the SVID.
         *
         * @param chain the leaf first, then the intermediates, possibly from the Workload API.
         * @param privateKey the private key of the leaf.
         * @param hint the hint of the Workload API, or null.
         * @param limits the length of the chain.
         * @return the SVID, or the rule the chain breaks: a leaf or signing certificate against [X509SvidRules],
         *   [X509SvidFailure.KeyMismatch] if the public key the private key carries is not the one of the leaf, and
         *   [X509SvidFailure.LimitExceeded] for a long chain or a hint longer than [MAXIMUM_HINT_LENGTH].
         * @since 1.0.0
         */
        public fun of(
            chain: List<Certificate>,
            privateKey: PrivateKey,
            hint: String? = null,
            limits: SpiffeLimits = SpiffeLimits.Default,
        ): Outcome<X509Svid, X509SvidFailure> {
            val isLong = chain.size > limits.maximumChainLength || (hint?.length ?: 0) > MAXIMUM_HINT_LENGTH
            if (isLong) return Outcome.Failure(X509SvidFailure.LimitExceeded)
            return X509SvidRules.path(chain).flatMap { id ->
                val publicKey = privateKey.publicKey
                val isPaired = publicKey == null || publicKey == chain.first().publicKey
                when (isPaired) {
                    true -> Outcome.Success(X509Svid(id = id, chain = chain, privateKey = privateKey, hint = hint))
                    false -> Outcome.Failure(X509SvidFailure.KeyMismatch)
                }
            }
        }
    }
}
