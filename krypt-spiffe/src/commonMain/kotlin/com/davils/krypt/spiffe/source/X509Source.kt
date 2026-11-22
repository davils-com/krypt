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

@file:OptIn(ExperimentalAtomicApi::class)

package com.davils.krypt.spiffe.source

import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.spiffe.SpiffeLimits
import com.davils.krypt.spiffe.TrustDomain
import com.davils.krypt.spiffe.bundle.BundleSet
import com.davils.krypt.spiffe.bundle.TrustBundle
import com.davils.krypt.spiffe.internal.SourceState
import com.davils.krypt.spiffe.x509.X509Svid
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.update

/**
 * Holds the current X.509-SVIDs of the workload and the bundles of its trust domain and the federated ones, which the
 * application pushes as it receives them, such as from every response of the stream of the Workload API.
 *
 * Every update is complete, as section 4.4 of the Workload API specification demands: what it lacks is dropped. An
 * update replaces the SVIDs and the bundles together in one atomic swap, so a reader sees either the old or the new
 * material and never a mix. An update is refused, and the current material kept, if it holds no SVID, exceeds the
 * [limits], lacks the bundle of the trust domain of an SVID, or carries a bundle whose `spiffe_sequence` is lower than
 * the one held for its trust domain. The source neither validates the SVIDs against the bundles, which the Workload
 * API vouches for, nor destroys the private keys of replaced SVIDs, which readers may still use.
 *
 * Safe to share between threads; no update blocks a reader.
 *
 * @property limits the number of SVIDs and trust domains.
 * @since 1.0.0
 */
public class X509Source(public val limits: SpiffeLimits = SpiffeLimits.Default) : SvidSource, BundleSource {
    private val state = AtomicReference(SourceState(svids = emptyList(), bundles = BundleSet.Empty))

    /**
     * The current SVIDs, the default one first, empty before the first update.
     *
     * @since 1.0.0
     */
    public val svids: List<X509Svid> get() = state.load().svids

    /**
     * The current bundles.
     *
     * @since 1.0.0
     */
    public val bundles: BundleSet get() = state.load().bundles

    /**
     * Returns the default SVID, the first one of the last update.
     *
     * @return the SVID, or null before the first update.
     * @since 1.0.0
     */
    override suspend fun svid(): X509Svid? = svids.firstOrNull()

    /**
     * Returns the first SVID with [hint], as section 5 of the Workload API specification selects one.
     *
     * @param hint the hint, such as `internal`.
     * @return the SVID, or null if none has this hint.
     * @since 1.0.0
     */
    public fun svid(hint: String): X509Svid? = svids.firstOrNull { svid -> svid.hint == hint }

    /**
     * Returns the current bundle of [trustDomain].
     *
     * @param trustDomain the trust domain.
     * @return the bundle, or null if the source holds none for it.
     * @since 1.0.0
     */
    override suspend fun bundle(trustDomain: TrustDomain): TrustBundle? = bundles[trustDomain]

    /**
     * Replaces the SVIDs and the bundles.
     *
     * @param svids the SVIDs, the default one first.
     * @param bundles the bundles of the own and of every federated trust domain.
     * @return success, or why the update was refused and the current material kept.
     * @since 1.0.0
     */
    public fun update(svids: List<X509Svid>, bundles: BundleSet): Outcome<Unit, SourceFailure> {
        val next = SourceState(svids = svids.toList(), bundles = bundles)
        return swap(isSvidRequired = true) { _ -> next }
    }

    /**
     * Replaces the bundles and keeps the SVIDs, as for a workload that only validates its peers or for a response of
     * the bundle stream of the Workload API.
     *
     * @param bundles the bundles of the own and of every federated trust domain.
     * @return success, or why the update was refused and the current material kept.
     * @since 1.0.0
     */
    public fun updateBundles(bundles: BundleSet): Outcome<Unit, SourceFailure> =
        swap(isSvidRequired = false) { current -> SourceState(svids = current.svids, bundles = bundles) }

    /**
     * Shows the number of SVIDs and the trust domains.
     *
     * @return the source as text.
     * @since 1.0.0
     */
    override fun toString(): String = "X509Source(svids=${svids.size}, ${bundles.trustDomains})"

    private fun swap(isSvidRequired: Boolean, next: (SourceState) -> SourceState): Outcome<Unit, SourceFailure> {
        var failure: SourceFailure? = null
        state.update { current ->
            val candidate = next(current)
            val found = failureOf(current = current, next = candidate, isSvidRequired = isSvidRequired)
            failure = found
            candidate.takeIf { found == null } ?: current
        }
        val refused = failure
        if (refused != null) return Outcome.Failure(refused)
        return Outcome.Success(Unit)
    }

    private fun failureOf(current: SourceState, next: SourceState, isSvidRequired: Boolean): SourceFailure? {
        val svids = next.svids
        val bundles = next.bundles
        val isBounded = svids.size <= limits.maximumSvids && bundles.size <= limits.maximumTrustDomains
        val isCovered = svids.all { svid -> svid.id.trustDomain in bundles }
        return SourceFailure.NoSvid.takeIf { isSvidRequired && svids.isEmpty() }
            ?: SourceFailure.LimitExceeded.takeUnless { isBounded }
            ?: SourceFailure.MissingBundle.takeUnless { isCovered }
            ?: SourceFailure.Rollback.takeIf { bundles.bundles.any { bundle -> isRollback(bundle, current.bundles) } }
    }

    private fun isRollback(bundle: TrustBundle, held: BundleSet): Boolean {
        val sequence = bundle.sequence
        val heldSequence = held[bundle.trustDomain]?.sequence
        return sequence != null && heldSequence != null && sequence < heldSequence
    }
}
