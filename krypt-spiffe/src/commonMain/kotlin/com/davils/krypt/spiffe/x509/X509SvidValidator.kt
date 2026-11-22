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

package com.davils.krypt.spiffe.x509

import com.davils.kore.core.failure.attempted
import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.flatMap
import com.davils.kore.core.outcome.map
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.spiffe.SpiffeId
import com.davils.krypt.spiffe.SpiffeLimits
import com.davils.krypt.spiffe.source.BundleSource
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.X509Limits
import com.davils.krypt.x509.path.PathFailure
import com.davils.krypt.x509.path.PathValidation
import com.davils.krypt.x509.path.PathValidator
import com.davils.krypt.x509.path.RevocationChecker
import com.davils.krypt.x509.path.ValidationParameters

/**
 * Validates X.509-SVIDs by section 5 of the X509-SVID specification.
 *
 * The leaf must pass [X509SvidRules.leaf]. Its path is then validated by RFC 5280 with the [PathValidator] of
 * krypt-x509 against the X.509 authorities of the bundle of the trust domain of its SPIFFE id, and of no other trust
 * domain, at the time of the clock of [crypto] or of the parameters, under the crypto policy of [crypto] and with the
 * revocation checker, if any. Every signing certificate of the path, the certificate of the anchor included, must
 * then pass the rules of [X509SvidRules.path].
 *
 * The bundle source is foreign code: a failure of it is contained and counts as a missing bundle. The validator holds
 * no state of its own and is safe to share between threads.
 *
 * @property crypto the crypto of path validation.
 * @param bundles the bundles of the trust domains.
 * @param revocation the revocation checker of path validation, or null for none.
 * @property limits the length of the chain.
 * @param x509Limits the limits of the path search of krypt-x509.
 * @since 1.0.0
 */
public class X509SvidValidator(
    public val crypto: Crypto,
    private val bundles: BundleSource,
    private val revocation: RevocationChecker? = null,
    public val limits: SpiffeLimits = SpiffeLimits.Default,
    private val x509Limits: X509Limits = X509Limits.Default,
) {
    /**
     * Validates [chain] as an X.509-SVID.
     *
     * @param chain the leaf first, then the intermediates the peer sent, possibly from an attacker.
     * @param parameters the parameters of path validation, such as the time or a required purpose.
     * @return the validated SVID, or the rule it breaks.
     * @since 1.0.0
     */
    public suspend fun validate(
        chain: List<Certificate>,
        parameters: ValidationParameters = ValidationParameters(),
    ): Outcome<ValidatedX509Svid, X509SvidFailure> {
        val failure = X509SvidFailure.EmptyChain.takeIf { chain.isEmpty() }
            ?: X509SvidFailure.LimitExceeded.takeIf { chain.size > limits.maximumChainLength }
        if (failure != null) return Outcome.Failure(failure)
        return X509SvidRules.leaf(chain.first()).flatMap { id ->
            validated(id = id, chain = chain, parameters = parameters)
        }
    }

    /**
     * Shows the limits.
     *
     * @return the validator as text.
     * @since 1.0.0
     */
    override fun toString(): String = "X509SvidValidator($limits)"

    private suspend fun validated(
        id: SpiffeId,
        chain: List<Certificate>,
        parameters: ValidationParameters,
    ): Outcome<ValidatedX509Svid, X509SvidFailure> {
        val bundle = attempted { bundles.bundle(id.trustDomain) }.getOrNull()
        val anchors = bundle?.trustAnchors().orEmpty()
        if (anchors.isEmpty()) return Outcome.Failure(X509SvidFailure.NoBundle)
        val validator = PathValidator(crypto = crypto, anchors = anchors, revocation = revocation, limits = x509Limits)
        val leaf = chain.first()
        val validation = validator.validate(leaf = leaf, intermediates = chain.drop(1), parameters = parameters)
        return when (validation) {
            is PathValidation.Valid -> accepted(id = id, validation = validation)
            is PathValidation.Invalid -> Outcome.Failure(FAILURES[validation.failure] ?: X509SvidFailure.Untrusted)
        }
    }

    private fun accepted(id: SpiffeId, validation: PathValidation.Valid): Outcome<ValidatedX509Svid, X509SvidFailure> {
        val path = validation.path + listOfNotNull(validation.anchor.certificate)
        return X509SvidRules.path(path).map { _ ->
            ValidatedX509Svid(id = id, path = validation.path, anchor = validation.anchor)
        }
    }

    private companion object {
        val FAILURES: Map<PathFailure, X509SvidFailure> = mapOf(
            PathFailure.Expired to X509SvidFailure.Expired,
            PathFailure.Revoked to X509SvidFailure.Revoked,
        )
    }
}
