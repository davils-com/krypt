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

package com.davils.krypt.spiffe.bundle

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.collection.OrderedMap
import com.davils.krypt.spiffe.SpiffeLimits
import com.davils.krypt.spiffe.TrustDomain
import com.davils.krypt.spiffe.source.BundleSource

/**
 * The bundles of several trust domains, at most one per trust domain, as SPIFFE federation keeps them: the bundle of
 * the own trust domain and those of federated ones, each kept apart and looked up by the trust domain of the SPIFFE
 * id being validated.
 *
 * The set is ordered by trust domain, bounded by [SpiffeLimits.HARD_MAXIMUM_TRUST_DOMAINS], immutable and safe to
 * share between threads.
 *
 * @constructor Checks and indexes the bundles.
 * @param bundles the bundles, each of another trust domain.
 * @throws IllegalArgumentException if two bundles belong to the same trust domain or there are more than
 *   [SpiffeLimits.HARD_MAXIMUM_TRUST_DOMAINS].
 * @since 1.0.0
 */
public class BundleSet(bundles: List<TrustBundle> = emptyList()) : BundleSource {
    private val index = OrderedMap<TrustDomain, TrustBundle>()

    /**
     * The bundles, ordered by trust domain.
     *
     * @since 1.0.0
     */
    public val bundles: List<TrustBundle> get() = index.entries.map { (_, bundle) -> bundle }

    /**
     * The trust domains, in order.
     *
     * @since 1.0.0
     */
    public val trustDomains: List<TrustDomain> get() = index.keys

    /**
     * How many trust domains the set holds.
     *
     * @since 1.0.0
     */
    public val size: Int get() = index.keys.size

    init {
        require(bundles.size <= SpiffeLimits.HARD_MAXIMUM_TRUST_DOMAINS) {
            "A bundle set holds at most ${SpiffeLimits.HARD_MAXIMUM_TRUST_DOMAINS} trust domains"
        }
        bundles.sortedBy { bundle -> bundle.trustDomain }.forEach { bundle ->
            require(bundle.trustDomain !in index) { "Each trust domain has one bundle" }
            index[bundle.trustDomain] = bundle
        }
    }

    /**
     * Returns the bundle of [trustDomain].
     *
     * @param trustDomain the trust domain.
     * @return the bundle, or null if the set has none for it.
     * @since 1.0.0
     */
    public operator fun get(trustDomain: TrustDomain): TrustBundle? = index[trustDomain]

    /**
     * Returns whether the set holds a bundle of [trustDomain].
     *
     * @param trustDomain the trust domain.
     * @return true if it does.
     * @since 1.0.0
     */
    public operator fun contains(trustDomain: TrustDomain): Boolean = trustDomain in index

    /**
     * Returns the bundle of [trustDomain].
     *
     * @param trustDomain the trust domain.
     * @return the bundle, or null if the set has none for it.
     * @since 1.0.0
     */
    override suspend fun bundle(trustDomain: TrustDomain): TrustBundle? = get(trustDomain)

    /**
     * Returns a set in which [bundle] replaces the bundle of its trust domain or joins the others.
     *
     * @param bundle the bundle.
     * @return the new set.
     * @throws IllegalArgumentException if the new set would hold more than [SpiffeLimits.HARD_MAXIMUM_TRUST_DOMAINS].
     * @since 1.0.0
     */
    public fun with(bundle: TrustBundle): BundleSet = BundleSet(without(bundle.trustDomain).bundles + bundle)

    /**
     * Returns a set without the bundle of [trustDomain], as when a federation relationship ends.
     *
     * @param trustDomain the trust domain.
     * @return the new set.
     * @since 1.0.0
     */
    public fun without(trustDomain: TrustDomain): BundleSet =
        BundleSet(bundles.filter { bundle -> bundle.trustDomain != trustDomain })

    /**
     * Compares the bundles.
     *
     * @param other the other object.
     * @return true if [other] holds the same bundles.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is BundleSet && bundles == other.bundles

    /**
     * Hashes the bundles.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = bundles.hashCode()

    /**
     * Shows the trust domains.
     *
     * @return the set as text.
     * @since 1.0.0
     */
    override fun toString(): String = "BundleSet($trustDomains)"

    /**
     * The empty set.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The set without any bundle.
         *
         * @since 1.0.0
         */
        public val Empty: BundleSet = BundleSet()
    }
}
