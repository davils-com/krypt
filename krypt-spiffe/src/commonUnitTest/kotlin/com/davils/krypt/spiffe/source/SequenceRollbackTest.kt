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

package com.davils.krypt.spiffe.source

import com.davils.krypt.spiffe.SpiffeLimits
import com.davils.krypt.spiffe.TrustDomain
import com.davils.krypt.spiffe.bundle.BundleSet
import com.davils.krypt.spiffe.bundle.TrustBundle
import com.davils.krypt.spiffe.fixture.domain
import com.davils.krypt.spiffe.fixture.failure
import com.davils.krypt.spiffe.fixture.foreign
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

private const val HIGH: Long = 5L

private const val LOW: Long = 1L

private fun setOf(sequence: Long?): BundleSet = BundleSet(listOf(TrustBundle(domain, sequence = sequence)))

private fun domainNumber(number: Int): TrustDomain = TrustDomain.of("d$number.example.org")

class SequenceRollbackTest : FunSpec({
    test("a bundle without a sequence after one with a sequence is refused as a rollback") {
        val source = X509Source()
        source.updateBundles(setOf(HIGH)).failure() shouldBe null
        source.updateBundles(setOf(LOW)).failure() shouldBe SourceFailure.Rollback
        source.updateBundles(setOf(null)).failure() shouldBe SourceFailure.Rollback
        source.updateBundles(setOf(LOW)).failure() shouldBe SourceFailure.Rollback
        source.bundles[domain]?.sequence shouldBe HIGH
    }

    test("a trust domain without a sequence so far takes bundles without one") {
        val source = X509Source()
        source.updateBundles(setOf(null)).failure() shouldBe null
        source.updateBundles(setOf(null)).failure() shouldBe null
        source.updateBundles(setOf(LOW)).failure() shouldBe null
        source.updateBundles(setOf(HIGH)).failure() shouldBe null
        source.updateBundles(setOf(HIGH)).failure() shouldBe null
    }

    test("dropping a trust domain for one update keeps its high-water mark") {
        val source = X509Source()
        source.updateBundles(setOf(HIGH)).failure() shouldBe null
        source.updateBundles(BundleSet.Empty).failure() shouldBe null
        source.updateBundles(BundleSet(listOf(TrustBundle(foreign, sequence = LOW)))).failure() shouldBe null
        source.updateBundles(setOf(LOW)).failure() shouldBe SourceFailure.Rollback
        source.updateBundles(setOf(null)).failure() shouldBe SourceFailure.Rollback
        source.updateBundles(setOf(HIGH)).failure() shouldBe null
    }

    test("beyond the capacity the mark of the trust domain absent longest is forgotten") {
        val capacity = SpiffeLimits.HARD_MAXIMUM_TRUST_DOMAINS
        val source = X509Source(SpiffeLimits(maximumTrustDomains = capacity))
        val many = (0 until capacity).map { number -> TrustBundle(domainNumber(number), sequence = HIGH) }
        source.updateBundles(BundleSet(many)).failure() shouldBe null
        source.updateBundles(setOf(HIGH)).failure() shouldBe null
        val first = BundleSet(listOf(TrustBundle(domainNumber(0), sequence = LOW)))
        val second = BundleSet(listOf(TrustBundle(domainNumber(1), sequence = LOW)))
        source.updateBundles(second).failure() shouldBe SourceFailure.Rollback
        source.updateBundles(first).failure() shouldBe null
    }
})
