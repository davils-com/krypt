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

package com.davils.krypt.spiffe.internal

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.collection.OrderedMap
import com.davils.krypt.spiffe.SpiffeLimits
import com.davils.krypt.spiffe.TrustDomain
import com.davils.krypt.spiffe.bundle.BundleSet
import com.davils.krypt.spiffe.bundle.TrustBundle

internal object SequenceMarks {
    const val CAPACITY: Int = SpiffeLimits.HARD_MAXIMUM_TRUST_DOMAINS

    fun isRollback(bundles: BundleSet, marks: List<SequenceMark>): Boolean {
        val index = OrderedMap<TrustDomain, Long>()
        marks.forEach { mark -> index[mark.trustDomain] = mark.sequence }
        return bundles.bundles.any { bundle -> isBelow(bundle = bundle, mark = index[bundle.trustDomain]) }
    }

    fun advanced(marks: List<SequenceMark>, bundles: BundleSet): List<SequenceMark> {
        val absent = marks.filter { mark -> mark.trustDomain !in bundles }
        val present = bundles.bundles.mapNotNull { bundle -> markOf(bundle) }
        return (absent + present).takeLast(CAPACITY)
    }

    private fun isBelow(bundle: TrustBundle, mark: Long?): Boolean {
        val sequence = bundle.sequence
        return mark != null && (sequence == null || sequence < mark)
    }

    private fun markOf(bundle: TrustBundle): SequenceMark? {
        val sequence = bundle.sequence ?: return null
        return SequenceMark(trustDomain = bundle.trustDomain, sequence = sequence)
    }
}
