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

package com.davils.krypt.tls.peer

import com.davils.kore.core.failure.attempted
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.spiffe.SpiffeId
import com.davils.krypt.spiffe.TrustDomain
import com.davils.krypt.spiffe.source.BundleSource
import com.davils.krypt.spiffe.x509.X509SvidRules
import com.davils.krypt.x509.path.TrustAnchor

/**
 * A [PeerAuthorizer] for SPIFFE: grants a peer whose certificate is an X.509-SVID with an allowed SPIFFE id.
 *
 * The validated path of the peer, with the certificate of its anchor, must pass [X509SvidRules.path]: the leaf names
 * exactly one URI, a SPIFFE id with a path, is no authority and has a critical key usage with `digitalSignature` and
 * without `keyCertSign` and `cRLSign`; every signing certificate is an authority with `keyCertSign` and names at most
 * the id of the trust domain of the leaf. The id must then be one of [ids], reside in one of [trustDomains], or be
 * accepted by the predicate. With a bundle source, the anchor the trust manager validated the path to must also be an
 * X.509 authority of the bundle of the trust domain of the id, so that a trust domain whose authorities the trust
 * manager trusts can never vouch for the ids of another, as SPIFFE federation demands.
 *
 * The predicate and the bundle source are foreign code: a failure of either is contained and denies the peer. Safe to
 * share between threads.
 *
 * @property ids the SPIFFE ids allowed exactly.
 * @property trustDomains the trust domains whose every id is allowed.
 * @since 1.0.0
 */
public class SpiffeAuthorizer private constructor(
    public val ids: Set<SpiffeId>,
    public val trustDomains: Set<TrustDomain>,
    private val predicate: (suspend (SpiffeId) -> Boolean)?,
    private val bundles: BundleSource?,
) : PeerAuthorizer {
    init {
        val count = ids.size + trustDomains.size
        require(count <= PeerPolicy.HARD_MAXIMUM_RULES) {
            "A SPIFFE authorizer has at most ${PeerPolicy.HARD_MAXIMUM_RULES} rules"
        }
    }

    /**
     * Decides about [peer] by its SPIFFE id.
     *
     * @param peer the validated identity.
     * @return [Authorization.Granted] if the peer presents an X.509-SVID with an allowed id, anchored in the bundle of
     *   its trust domain when a bundle source is set.
     * @since 1.0.0
     */
    override suspend fun authorize(peer: PeerIdentity): Authorization {
        val path = peer.path + listOfNotNull(peer.anchor.certificate)
        val id = X509SvidRules.path(path).getOrNull()
        val isGranted = id != null && isAllowed(id) && isAnchored(id = id, anchor = peer.anchor)
        return DECISIONS[isGranted.compareTo(false)]
    }

    /**
     * Shows the number of ids and trust domains and whether a predicate and a bundle source are set.
     *
     * @return the authorizer as text.
     * @since 1.0.0
     */
    override fun toString(): String = "SpiffeAuthorizer(ids=${ids.size}, trustDomains=${trustDomains.size}, " +
        "predicate=${predicate != null}, bundles=${bundles != null})"

    private suspend fun isAllowed(id: SpiffeId): Boolean {
        val isListed = id in ids || id.trustDomain in trustDomains
        return isListed || isAccepted(id)
    }

    private suspend fun isAccepted(id: SpiffeId): Boolean {
        val accepts = predicate ?: return false
        return attempted { accepts(id) }.getOrDefault(false)
    }

    private suspend fun isAnchored(id: SpiffeId, anchor: TrustAnchor): Boolean {
        val source = bundles ?: return true
        val bundle = attempted { source.bundle(id.trustDomain) }.getOrNull()
        val anchors = bundle?.trustAnchors().orEmpty()
        return anchor in anchors
    }

    /**
     * Building SPIFFE authorizers.
     *
     * @since 1.0.0
     */
    public companion object {
        private val DECISIONS: List<Authorization> = listOf(Authorization.Denied, Authorization.Granted)

        /**
         * Allows exactly [ids].
         *
         * @param ids the SPIFFE ids, such as `spiffe://example.org/ns/prod/sa/api`.
         * @param bundles the bundles the anchor of a peer must belong to, or null to trust the trust manager alone.
         * @return the authorizer.
         * @throws IllegalArgumentException if [ids] is empty or holds more than [PeerPolicy.HARD_MAXIMUM_RULES] ids.
         * @since 1.0.0
         */
        public fun ids(vararg ids: SpiffeId, bundles: BundleSource? = null): SpiffeAuthorizer {
            require(ids.isNotEmpty()) { "A SPIFFE authorizer allows at least one id" }
            return SpiffeAuthorizer(ids = ids.toSet(), trustDomains = emptySet(), predicate = null, bundles = bundles)
        }

        /**
         * Allows every id of [trustDomains].
         *
         * @param trustDomains the trust domains, such as `example.org`.
         * @param bundles the bundles the anchor of a peer must belong to, or null to trust the trust manager alone.
         * @return the authorizer.
         * @throws IllegalArgumentException if [trustDomains] is empty or holds more than
         *   [PeerPolicy.HARD_MAXIMUM_RULES] trust domains.
         * @since 1.0.0
         */
        public fun trustDomains(vararg trustDomains: TrustDomain, bundles: BundleSource? = null): SpiffeAuthorizer {
            require(trustDomains.isNotEmpty()) { "A SPIFFE authorizer allows at least one trust domain" }
            return SpiffeAuthorizer(
                ids = emptySet(),
                trustDomains = trustDomains.toSet(),
                predicate = null,
                bundles = bundles,
            )
        }

        /**
         * Allows every id [predicate] accepts.
         *
         * @param bundles the bundles the anchor of a peer must belong to, or null to trust the trust manager alone.
         * @param predicate decides about the SPIFFE id of a peer; a failure denies the peer.
         * @return the authorizer.
         * @since 1.0.0
         */
        public fun matching(
            bundles: BundleSource? = null,
            predicate: suspend (SpiffeId) -> Boolean,
        ): SpiffeAuthorizer =
            SpiffeAuthorizer(ids = emptySet(), trustDomains = emptySet(), predicate = predicate, bundles = bundles)
    }
}
